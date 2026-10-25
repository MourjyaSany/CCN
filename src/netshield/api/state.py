"""Live simulation session management for the dashboard.

The dashboard needs to *watch* a simulation, not wait for one. This module runs a
simulation on a background thread and publishes a snapshot of its state after
every feature window, guarded by a lock so the HTTP handlers never read a
half-written structure.

Pacing
------
The discrete-event engine completes a 130-second scenario in a few seconds of
wall clock. That is excellent for batch experiments and useless for a live
demonstration, so :class:`LiveMonitor` sleeps at each window boundary to pace
simulated time against wall-clock time by ``speed`` (simulated seconds per real
second). Pacing only ever *delays* the thread - it never alters the simulation,
whose results are identical with or without it.
"""

from __future__ import annotations

import threading
import time
import traceback
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from ..detection.controller import DetectionController
from ..mitigation.engine import MitigationEnforcer, MitigationEngine
from ..mitigation.policy import PolicyConfig
from ..models.base import Detector
from ..utils.logging_utils import get_logger

_LOG = get_logger(__name__)

#: Configuration prefixes the API is willing to override.
#:
#: This allowlist is a safety boundary, not a convenience. The project's
#: guarantee is that the API surface exposes no host, port, interface or
#: real-world target parameter, so it cannot be repurposed into a traffic
#: generator aimed at anything outside this process. Attack parameters and
#: topology shape are simulation-internal and therefore safe to expose;
#: anything else (paths, the database location, the API's own binding, the
#: engine selection) is not.
ALLOWED_OVERRIDE_PREFIXES: tuple[str, ...] = (
    "attack.",
    "network.topology.",
    "mitigation.",
    "detection.",
    "features.",
    "traffic.",
)

#: Individually allowlisted keys that do not fall under a prefix above.
ALLOWED_OVERRIDE_KEYS: frozenset[str] = frozenset(
    {
        "simulation.n_iot_devices",
        "simulation.n_attackers",
        "simulation.duration_s",
        "seed",
    }
)


class OverrideRejected(ValueError):
    """Raised when a requested configuration override is outside the allowlist."""


def sanitise_overrides(overrides: Mapping[str, Any]) -> dict[str, Any]:
    """Validate builder-supplied overrides against the allowlist.

    Args:
        overrides: Dotted-key configuration overrides from an API caller.

    Returns:
        The same mapping, with values rendered for ``Config.with_set``.

    Raises:
        OverrideRejected: If any key is outside
            :data:`ALLOWED_OVERRIDE_PREFIXES` / :data:`ALLOWED_OVERRIDE_KEYS`,
            or if a key attempts path traversal.
    """
    import json as _json

    clean: dict[str, Any] = {}
    for key, value in overrides.items():
        dotted = str(key).strip()
        if not dotted or dotted.startswith(".") or ".." in dotted:
            raise OverrideRejected(f"Malformed override key {key!r}.")
        allowed = dotted in ALLOWED_OVERRIDE_KEYS or any(
            dotted.startswith(prefix) for prefix in ALLOWED_OVERRIDE_PREFIXES
        )
        if not allowed:
            raise OverrideRejected(
                f"Override {dotted!r} is not permitted. The API only accepts "
                f"keys under {list(ALLOWED_OVERRIDE_PREFIXES)} plus "
                f"{sorted(ALLOWED_OVERRIDE_KEYS)}."
            )
        # Lists/dicts/bools round-trip through JSON, which is exactly the
        # literal syntax Config.with_set parses.
        clean[dotted] = (
            _json.dumps(value) if isinstance(value, (list, dict, bool)) else value
        )
    return clean


#: Scenario states surfaced by ``GET /api/network/status``.
STATE_IDLE = "idle"
STATE_RUNNING = "running"
STATE_COMPLETED = "completed"
STATE_STOPPING = "stopping"
STATE_FAILED = "failed"


@dataclass
class SessionSnapshot:
    """An immutable-by-convention view of the running simulation.

    Attributes:
        state: One of the ``STATE_*`` constants.
        scenario: Experiment name being run.
        run_id: Run identifier once the simulation has started.
        engine_label: Provenance of the engine actually in use.
        sim_time_s: Current simulated time.
        duration_s: Total simulated duration.
        started_at: Wall-clock start time (epoch seconds).
        windows: Per-window QoS rows produced so far.
        detections: Detection events produced so far.
        mitigations: Mitigation actions taken so far.
        topology: Serialised topology.
        node_state: Live per-node status for the topology view.
        attack: The attack profile of the running scenario.
        error: Failure message when ``state`` is ``failed``.
        mitigation_enabled: Whether the closed loop is armed.
        detector: Name of the detector driving the loop.
    """

    state: str = STATE_IDLE
    scenario: str = ""
    run_id: str = ""
    engine_label: str = ""
    sim_time_s: float = 0.0
    duration_s: float = 0.0
    started_at: float = 0.0
    windows: list[dict[str, Any]] = field(default_factory=list)
    detections: list[dict[str, Any]] = field(default_factory=list)
    mitigations: list[dict[str, Any]] = field(default_factory=list)
    topology: dict[str, Any] = field(default_factory=dict)
    node_state: list[dict[str, Any]] = field(default_factory=list)
    attack: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    mitigation_enabled: bool = False
    detector: str = ""

    def progress(self) -> float:
        """Return completion in ``[0, 1]``."""
        return min(1.0, self.sim_time_s / self.duration_s) if self.duration_s else 0.0


class LiveMonitor:
    """Window controller that publishes live state and paces the simulation.

    Args:
        session: The owning :class:`SimulationSession`.
        speed: Simulated seconds per wall-clock second. ``0`` disables pacing.
    """

    def __init__(self, session: "SimulationSession", speed: float = 5.0) -> None:
        self.session = session
        self.speed = float(speed)
        self._wall_start = time.perf_counter()

    def on_window(self, engine: Any, window_index: int, t: float) -> None:
        """Publish a snapshot and, if pacing is enabled, wait for wall clock."""
        self.session.publish(engine, t)

        if self.session.stop_requested:
            _LOG.info("Stop requested; halting the simulation at t=%.1fs", t)
            engine.stop()
            return

        if self.speed > 0:
            target = t / self.speed
            elapsed = time.perf_counter() - self._wall_start
            if target > elapsed:
                time.sleep(min(target - elapsed, 5.0))


class SimulationSession:
    """Owns at most one background simulation and its published state.

    Args:
        config_factory: Callable returning ``(config, meta)`` for a scenario name.
        detector_provider: Callable returning ``{name: detector}`` or ``{}``.
        on_complete: Optional callback invoked with the finished result.
    """

    def __init__(
        self,
        config_factory: Callable[[str], tuple[Any, dict[str, Any]]],
        detector_provider: Callable[[], dict[str, Detector]],
        on_complete: Callable[[Any], None] | None = None,
    ) -> None:
        self.config_factory = config_factory
        self.detector_provider = detector_provider
        self.on_complete = on_complete

        self._lock = threading.RLock()
        self._thread: threading.Thread | None = None
        self._snapshot = SessionSnapshot()
        self.stop_requested = False
        self.last_result: Any = None
        self.controller: DetectionController | None = None

    # ------------------------------------------------------------------ #
    @property
    def running(self) -> bool:
        """True while a simulation thread is alive."""
        return self._thread is not None and self._thread.is_alive()

    def snapshot(self) -> SessionSnapshot:
        """Return the current published state (safe to read from any thread)."""
        with self._lock:
            return self._snapshot

    def _update(self, **fields: Any) -> None:
        """Apply field updates to the published snapshot under the lock."""
        with self._lock:
            for key, value in fields.items():
                setattr(self._snapshot, key, value)

    # ------------------------------------------------------------------ #
    def start(
        self,
        scenario: str,
        speed: float = 5.0,
        mitigation: bool | None = None,
        detector_name: str = "graphsage",
        duration_s: float | None = None,
        overrides: Mapping[str, Any] | None = None,
    ) -> SessionSnapshot:
        """Launch a scenario on a background thread.

        Args:
            scenario: Experiment name from ``config/experiments.yaml``.
            speed: Simulated seconds per wall-clock second (0 = as fast as possible).
            mitigation: Force the closed loop on/off; ``None`` uses the scenario.
            detector_name: Detector to drive detection and mitigation.
            duration_s: Optional duration override.
            overrides: Sparse dotted-key configuration overrides from the attack
                builder. Validated against :data:`ALLOWED_OVERRIDE_PREFIXES`
                before use.

        Returns:
            The snapshot immediately after launch.

        Raises:
            RuntimeError: If a simulation is already running.
            ValueError: If an override key is outside the allowlist.
        """
        if self.running:
            raise RuntimeError(
                "A simulation is already running; stop it before starting another."
            )

        config, meta = self.config_factory(scenario)
        if overrides:
            config = config.with_set(
                [f"{key}={value}" for key, value in sanitise_overrides(overrides).items()]
            )
        if duration_s is not None:
            config = config.with_set([f"simulation.duration_s={duration_s}"])
        if mitigation is not None:
            config = config.with_set([f"mitigation.enabled={bool(mitigation)}"])

        self.stop_requested = False
        with self._lock:
            self._snapshot = SessionSnapshot(
                state=STATE_RUNNING,
                scenario=scenario,
                duration_s=float(config.require("simulation.duration_s")),
                started_at=time.time(),
                mitigation_enabled=bool(config.get("mitigation.enabled", False)),
                detector=detector_name,
            )

        self._thread = threading.Thread(
            target=self._run,
            args=(config, meta, scenario, speed, detector_name),
            name=f"netshield-sim-{scenario}",
            daemon=True,
        )
        self._thread.start()
        _LOG.info("Simulation session started: %s (speed x%.1f)", scenario, speed)
        return self.snapshot()

    def stop(self) -> SessionSnapshot:
        """Request that the running simulation stop at the next window boundary."""
        if self.running:
            self.stop_requested = True
            self._update(state=STATE_STOPPING)
            _LOG.info("Stop requested for the running simulation.")
        return self.snapshot()

    def join(self, timeout: float = 120.0) -> None:
        """Block until the background simulation finishes."""
        if self._thread is not None:
            self._thread.join(timeout)

    # ------------------------------------------------------------------ #
    def _run(
        self,
        config: Any,
        meta: dict[str, Any],
        scenario: str,
        speed: float,
        detector_name: str,
    ) -> None:
        """Background thread body: run the simulation and publish its state."""
        from ..simulation.runner import run_simulation  # local import: heavy

        try:
            detectors = self.detector_provider()
            detector = detectors.get(detector_name) or (
                next(iter(detectors.values())) if detectors else None
            )
            mitigation_on = bool(config.get("mitigation.enabled", False))
            trigger = float(
                config.get("detection.mitigation_trigger_probability", 0.80)
            )
            policy = PolicyConfig.from_config(config).validate()
            monitor = LiveMonitor(self, speed=speed)

            def factory(context: Any) -> list[Any]:
                controllers: list[Any] = []
                if detector is not None:
                    mitigation_engine = None
                    if mitigation_on:
                        node_ips = {
                            n.node_id: n.ip for n in context.topology.nodes.values()
                        }
                        mitigation_engine = MitigationEngine(
                            policy, MitigationEnforcer(policy, node_ips),
                            detector_name=detector.name,
                        )
                        mitigation_engine.approval_mode = str(
                            config.get("mitigation.approval_mode", "auto"))
                    controller = DetectionController(
                        context=context, detector=detector,
                        mitigation=mitigation_engine, trigger=trigger,
                    )
                    self.controller = controller
                    controllers.append(controller)
                controllers.append(monitor)
                self._update(
                    topology=context.topology.describe(),
                    run_id=context.run_id,
                )
                return controllers

            result = run_simulation(config, meta, controller_factory=factory)
            self.last_result = result
            self._update(
                state=STATE_COMPLETED,
                run_id=result.run_id,
                engine_label=result.engine_label,
                sim_time_s=float(result.summary.get("duration_s", 0.0)),
                windows=list(result.windows),
                mitigations=list(result.mitigations),
                topology=result.topology,
                attack=dict(result.summary.get("attack", {}) or {}),
            )
            if self.controller is not None:
                self._update(detections=list(self.controller.detection_log))
            if self.on_complete is not None:
                self.on_complete(result)
            _LOG.info("Simulation session finished: %s", result.run_id)

        except Exception as exc:  # noqa: BLE001 - surface the failure to the UI
            _LOG.exception("Simulation session failed")
            self._update(
                state=STATE_FAILED,
                error=f"{type(exc).__name__}: {exc}\n{traceback.format_exc(limit=3)}",
            )
        finally:
            self.controller = self.controller  # keep the final controller for reports

    # ------------------------------------------------------------------ #
    def publish(self, engine: Any, t: float) -> None:
        """Publish a snapshot of the running simulation at time *t*."""
        telemetry = engine.telemetry
        windows = [w.to_row() for w in telemetry.iter_windows()]
        topology = engine.topology

        node_rows: list[dict[str, Any]] = []
        latest: dict[str, dict[str, Any]] = {}
        if self.controller is not None:
            for row in self.controller.detection_log:
                latest[str(row["node"])] = row

        enforcement: dict[str, str] = {}
        if self.controller is not None and self.controller.mitigation is not None:
            for node, state in self.controller.mitigation.enforcer.states.items():
                if state.active:
                    enforcement[node] = state.action.value

        for node in topology.nodes.values():
            detection = latest.get(node.node_id, {})
            node_rows.append({
                "node_id": node.node_id,
                "kind": node.kind.value,
                "ip": node.ip,
                "device_class": node.device_class,
                "tier": node.tier,
                "parent": node.parent,
                "is_attacker": node.is_attacker,
                "tx_packets": node.counters.tx_packets,
                "tx_bytes": node.counters.tx_bytes,
                "probability": float(detection.get("probability", 0.0)),
                "predicted": str(detection.get("predicted", "BENIGN")),
                "packet_rate": float(detection.get("packet_rate", 0.0)),
                "mitigation": enforcement.get(node.node_id, ""),
            })

        with self._lock:
            snapshot = self._snapshot
            snapshot.sim_time_s = float(t)
            snapshot.windows = windows
            snapshot.node_state = node_rows
            snapshot.engine_label = getattr(
                engine, "engine_label", snapshot.engine_label
            )
            if self.controller is not None:
                snapshot.detections = list(self.controller.detection_log)
                snapshot.mitigations = list(self.controller.mitigation_log)
            if not snapshot.topology:
                snapshot.topology = topology.describe()
