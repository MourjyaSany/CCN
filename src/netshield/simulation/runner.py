"""Run orchestration: wire the topology, applications, attackers and telemetry.

:func:`run_simulation` is the single entry point used by dataset generation, the
experiment driver, the fuzzer and the live dashboard. It is deliberately
side-effect free with respect to the filesystem - persistence is an explicit
call to :meth:`SimulationResult.save`.

Closed-loop runs (detection and mitigation *inside* the simulation) are enabled
by passing a ``controller_factory``. The controller is invoked at every feature
window boundary in simulated time, so a decision taken at t=45 s physically
changes packet handling from t=45 s onwards within the very same run.
"""

from __future__ import annotations

import hashlib
import json
import platform
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from ..traffic.applications import Application, build_application
from ..traffic.benign_events import schedule_benign_events
from ..traffic.attacks import (
    AttackProfile,
    Attacker,
    attack_family_counts,
    build_attack_campaign,
)
from ..traffic.server import CloudServer, GatewaySink
from ..utils.config import Config
from ..utils.logging_utils import get_logger
from ..utils.paths import ensure_dir, resolve
from ..utils.seeding import seed_everything
from .engine import SimulationEngine, WindowController
from .ns3_bridge import (
    ENGINE_NS3,
    NS3Availability,
    detect_ns3,
    engine_label,
    resolve_engine,
)
from .tcp import TcpDispatcher, TcpRegistry
from .telemetry import (
    FLOW_CSV_COLUMNS,
    METRIC_CSV_COLUMNS,
    TelemetryCollector,
    write_csv,
)
from .topology import Topology, build_topology

_LOG = get_logger(__name__)

#: Bumped whenever a change alters simulated outcomes for a fixed config
#: (v2: buffered per-packet random draws). Part of every run id.
SIM_VERSION = 2

#: Signature of a factory producing an in-loop controller for a run.
ControllerFactory = Callable[
    ["SimulationContext"], "WindowController | list[WindowController] | None"
]


@dataclass(slots=True)
class SimulationContext:
    """Everything a controller needs to observe and act on a running simulation.

    Attributes:
        config: The merged configuration for this run.
        engine: The live simulation engine.
        topology: The instantiated topology.
        telemetry: The live telemetry collector.
        registry: The shared TCP connection registry.
        server: The cloud server application.
        applications: Legitimate device applications.
        attackers: Attack generators (empty for benign runs).
        run_id: Stable identifier for this run.
    """

    config: Config
    engine: SimulationEngine
    topology: Topology
    telemetry: TelemetryCollector
    registry: TcpRegistry
    server: CloudServer
    applications: list[Application]
    attackers: list[Attacker]
    run_id: str


@dataclass(slots=True)
class SimulationResult:
    """All artefacts produced by one simulation run.

    Attributes:
        run_id: Stable identifier (``<experiment>_seed<seed>_<fingerprint>``).
        engine: Provenance id - :data:`~netshield.simulation.ns3_bridge.ENGINE_NS3`
            or :data:`~netshield.simulation.ns3_bridge.ENGINE_PYTHON`.
        engine_reason: One-line explanation of why that engine was used.
        config: Snapshot of the exact configuration.
        meta: Experiment metadata (name, description, tags).
        flows: IPFIX-style per-window flow records.
        windows: Per-window network QoS metrics.
        nodes: Per-node counters and ground-truth roles.
        links: Per-channel utilisation and loss.
        applications: Per-device service-level KPIs.
        server: Cloud-server application counters.
        attackers: Attack-generator counters.
        topology: Serialised topology description.
        summary: Run-level aggregate summary.
        detections: Detection events produced by an in-loop controller.
        mitigations: Mitigation actions applied during the run.
    """

    run_id: str
    engine: str
    engine_reason: str
    config: dict[str, Any]
    meta: dict[str, Any]
    flows: list[dict[str, Any]]
    windows: list[dict[str, Any]]
    nodes: list[dict[str, Any]]
    links: list[dict[str, Any]]
    applications: list[dict[str, Any]]
    server: dict[str, Any]
    attackers: list[dict[str, Any]]
    topology: dict[str, Any]
    summary: dict[str, Any]
    detections: list[dict[str, Any]] = field(default_factory=list)
    mitigations: list[dict[str, Any]] = field(default_factory=list)

    @property
    def engine_label(self) -> str:
        """Human-readable engine provenance, e.g. ``"NS-3 simulation"``."""
        return engine_label(self.engine)

    def manifest(self) -> dict[str, Any]:
        """Return the JSON manifest describing this run."""
        return {
            "run_id": self.run_id,
            "engine": self.engine,
            "engine_label": self.engine_label,
            "engine_reason": self.engine_reason,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "host": {
                "python": sys.version.split()[0],
                "platform": platform.platform(),
            },
            "meta": self.meta,
            "summary": self.summary,
            "server": self.server,
            "attackers": self.attackers,
            "topology": self.topology,
            "n_flows": len(self.flows),
            "n_windows": len(self.windows),
            "n_detections": len(self.detections),
            "n_mitigations": len(self.mitigations),
        }

    def save(self, directory: str | Path) -> dict[str, Path]:
        """Persist every artefact of this run under *directory*.

        Args:
            directory: Destination directory (created if missing).

        Returns:
            Mapping of artefact name to written path.
        """
        target = ensure_dir(directory)
        written: dict[str, Path] = {}

        written["flows"] = write_csv(self.flows, target / "flows.csv", FLOW_CSV_COLUMNS)
        written["windows"] = write_csv(
            self.windows, target / "window_metrics.csv", METRIC_CSV_COLUMNS
        )
        if self.nodes:
            written["nodes"] = write_csv(
                (dict(row, drop_reasons=json.dumps(row.get("drop_reasons", {})))
                 for row in self.nodes),
                target / "node_counters.csv",
                list(self.nodes[0].keys()),
            )
        if self.links:
            written["links"] = write_csv(
                (dict(row, drop_reasons=json.dumps(row.get("drop_reasons", {})))
                 for row in self.links),
                target / "link_stats.csv",
                list(self.links[0].keys()),
            )
        if self.applications:
            written["applications"] = write_csv(
                self.applications,
                target / "app_kpis.csv",
                list(self.applications[0].keys()),
            )

        for name, payload in (
            ("run", self.manifest()),
            ("config", self.config),
            ("detections", self.detections),
            ("mitigations", self.mitigations),
        ):
            path = target / f"{name}.json"
            path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
            written[name] = path

        _LOG.info("Run '%s' artefacts written to %s", self.run_id, target)
        return written

    @classmethod
    def load(cls, directory: str | Path) -> "SimulationResult":
        """Reconstruct a run from artefacts written by :meth:`save`.

        This is what makes the figures reproducible without re-simulating: the
        evaluation scripts rebuild a run from ``data/experiments/<run_id>/``
        rather than regenerating traffic.

        Args:
            directory: A run artefact directory.

        Returns:
            The reconstructed :class:`SimulationResult`.

        Raises:
            FileNotFoundError: If the directory or its manifest is missing.
        """
        import csv as _csv

        source = resolve(directory)
        manifest_path = source / "run.json"
        if not manifest_path.exists():
            raise FileNotFoundError(f"No run manifest at {manifest_path}")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        def read_rows(name: str) -> list[dict[str, Any]]:
            path = source / name
            if not path.exists():
                return []
            with path.open("r", encoding="utf-8", newline="") as handle:
                return [_coerce_row(row) for row in _csv.DictReader(handle)]

        def read_json(name: str, default: Any) -> Any:
            path = source / name
            if not path.exists():
                return default
            return json.loads(path.read_text(encoding="utf-8"))

        return cls(
            run_id=str(manifest["run_id"]),
            engine=str(manifest["engine"]),
            engine_reason=str(manifest.get("engine_reason", "")),
            config=read_json("config.json", {}),
            meta=dict(manifest.get("meta", {})),
            flows=read_rows("flows.csv"),
            windows=read_rows("window_metrics.csv"),
            nodes=read_rows("node_counters.csv"),
            links=read_rows("link_stats.csv"),
            applications=read_rows("app_kpis.csv"),
            server=dict(manifest.get("server", {})),
            attackers=list(manifest.get("attackers", [])),
            topology=dict(manifest.get("topology", {})),
            summary=dict(manifest.get("summary", {})),
            detections=read_json("detections.json", []),
            mitigations=read_json("mitigations.json", []),
        )


def _coerce_row(row: Mapping[str, str]) -> dict[str, Any]:
    """Convert a CSV row of strings back to numbers where unambiguous.

    CSV has no types, so a reloaded run would otherwise hand strings to code
    expecting floats. Values that are not numeric are left as strings, and
    JSON-encoded cells (drop-reason maps) are decoded.

    Args:
        row: A row from :class:`csv.DictReader`.

    Returns:
        The row with numeric and JSON cells converted.
    """
    out: dict[str, Any] = {}
    for key, value in row.items():
        if value is None or value == "":
            out[key] = value
            continue
        if value.startswith("{") or value.startswith("["):
            try:
                out[key] = json.loads(value)
                continue
            except (ValueError, TypeError):
                pass
        if value in ("True", "False"):
            out[key] = value == "True"
            continue
        try:
            out[key] = int(value)
            continue
        except ValueError:
            pass
        try:
            out[key] = float(value)
            continue
        except ValueError:
            out[key] = value
    return out


def load_run(directory: str | Path) -> SimulationResult:
    """Load a saved run from ``data/experiments/<run_id>/``."""
    return SimulationResult.load(directory)


def discover_runs(root: str | Path) -> list[Path]:
    """Return every run artefact directory beneath *root*, sorted by name."""
    base = resolve(root)
    if not base.is_dir():
        return []
    return sorted(p.parent for p in base.glob("*/run.json"))


def build_run_id(config: Config, meta: Mapping[str, Any] | None = None) -> str:
    """Compose a stable, human-readable identifier for a run.

    Args:
        config: The merged configuration.
        meta: Optional experiment metadata carrying an ``experiment`` name.

    Returns:
        e.g. ``"exp2_udp_flood_seed43_9f2c1a4b7e0d"``.
    """
    name = str((meta or {}).get("experiment", "run"))
    # The simulator version is folded into the hash so that a cached run is
    # only reused when it was produced by the same engine behaviour.
    # The detector running in the loop changes the outcome but is not part of
    # the configuration, so it must be part of the identity too.
    in_loop = str((meta or {}).get("closed_loop") or "")
    key = f"{config.fingerprint()}|sim{SIM_VERSION}" + (f"|loop:{in_loop}" if in_loop else "")
    digest = hashlib.sha1(key.encode()).hexdigest()[:12]
    return f"{name}_seed{int(config.get('seed', 0))}_{digest}"


def _build_applications(
    config: Config,
    engine: SimulationEngine,
    topology: Topology,
    registry: TcpRegistry,
) -> list[Application]:
    """Instantiate one application per endpoint, attackers included.

    Compromised nodes are modelled as previously-benign devices that were
    taken over: they continue to publish telemetry while the botnet code
    floods the target. Their traffic is therefore a *mixture*, which is
    what produces the intermediate SUSPICIOUS ground-truth class.
    """
    traffic_cfg = config.section("traffic")
    seed = int(config.get("seed", 42))
    duration = float(config.require("simulation.duration_s"))
    cloud = topology.nodes[topology.cloud_id]

    applications: list[Application] = []
    for node in topology.endpoints():
        app = build_application(
            device_class=node.device_class,
            engine=engine,
            registry=registry,
            node=node,
            server=cloud,
            traffic_config=traffic_cfg,
            seed=seed,
            stop_time_s=duration,
        )
        applications.append(app)
    return applications


def run_simulation(
    config: Config,
    meta: Mapping[str, Any] | None = None,
    controller_factory: ControllerFactory | None = None,
    trace_packets: bool = False,
    ns3_probe: NS3Availability | None = None,
) -> SimulationResult:
    """Execute one complete simulation and return its artefacts.

    Args:
        config: Merged configuration for the run.
        meta: Experiment metadata (name/description/tags), recorded verbatim.
        controller_factory: Optional factory producing in-loop controllers
            (detection and/or mitigation) invoked at each window boundary.
        trace_packets: Retain a bounded per-packet trace (debug/tests only).
        ns3_probe: Pre-computed NS-3 probe, to avoid re-probing in batch runs.

    Returns:
        A populated :class:`SimulationResult`.

    Raises:
        NS3Unavailable: If ``simulation.engine == "ns3"`` and NS-3 is missing.
    """
    meta = dict(meta or {})
    seed = int(config.get("seed", 42))
    seed_everything(seed)

    engine_id, engine_reason = resolve_engine(
        str(config.get("simulation.engine", "auto")),
        probe=ns3_probe,
    )
    if engine_id == ENGINE_NS3:
        # The NS-3 path is selected only when an actual installation was probed
        # successfully; the C++ model in ns3/ is then the source of truth, and
        # the run is executed there rather than here. Returning early is what
        # keeps the `engine` stamp honest: previously this branch only logged,
        # and the Python engine then produced artefacts labelled "NS-3".
        _LOG.info("Engine resolved to NS-3: %s", engine_reason)
        from .ns3_runner import execute as _ns3_execute  # noqa: PLC0415

        probe = ns3_probe if ns3_probe is not None else detect_ns3()
        return _ns3_execute(
            config=config,
            meta=meta,
            probe=probe,
            engine_reason=engine_reason,
            run_id=build_run_id(config, meta),
            result_class=SimulationResult,
            closed_loop=controller_factory is not None,
        )
    _LOG.info("Engine: Python discrete-event emulation (%s)", engine_reason)

    duration = float(config.require("simulation.duration_s"))
    window_s = float(config.require("features.window_s"))

    topology = build_topology(config)
    telemetry = TelemetryCollector(
        window_s=window_s,
        trace_packets=trace_packets,
        slo_latency_s=float(config.get("evaluation.slo_latency_ms", 50.0)) / 1000.0,
    )
    engine = SimulationEngine(
        topology=topology,
        telemetry=telemetry,
        duration_s=duration,
        seed=seed,
        max_packets=int(config.get("simulation.max_packets", 4_000_000)),
        log_every_s=float(config.get("simulation.log_every_s", 15.0)),
        max_wall_seconds=float(config.get("simulation.max_wall_seconds", 240.0)),
    )

    registry = TcpRegistry()
    cloud_spec = config.get("network.topology.cloud", {}) or {}
    server = CloudServer(
        engine=engine,
        topology=topology,
        registry=registry,
        node=topology.nodes[topology.cloud_id],
        backlog=int(cloud_spec.get("syn_backlog", 256)),
        syn_timeout_s=float(cloud_spec.get("syn_timeout_s", 8.0)),
        worker_slots=int(cloud_spec.get("worker_slots", 64)),
        max_connections=int(cloud_spec.get("max_connections", 512)),
        service_time_s=float(cloud_spec.get("service_time_s", 0.004)),
        seed=seed,
    )
    response_range = config.get("traffic.http_client.response_bytes", [500, 6000])
    server.response_bytes = (int(response_range[0]), int(response_range[1]))
    for gateway in topology.gateways():
        GatewaySink(engine, gateway)

    # Every endpoint needs a protocol demultiplexer, otherwise inbound
    # SYN+ACK / ACK / data segments would arrive at a node with no handler
    # and no handshake could ever complete.
    for endpoint in topology.endpoints():
        TcpDispatcher(engine, registry, endpoint)

    applications = _build_applications(config, engine, topology, registry)
    benign_events = schedule_benign_events(
        engine, applications, config.get("traffic.benign_events", []) or [], seed=seed)
    for app in applications:
        app.start(0.0)

    profile = AttackProfile.from_config(config)
    attackers = build_attack_campaign(engine, topology, registry, profile, seed=seed)
    for attacker in attackers:
        attacker.start()

    run_id = build_run_id(config, meta)
    context = SimulationContext(
        config=config,
        engine=engine,
        topology=topology,
        telemetry=telemetry,
        registry=registry,
        server=server,
        applications=applications,
        attackers=attackers,
        run_id=run_id,
    )

    controllers: list[WindowController] = []
    if controller_factory is not None:
        produced = controller_factory(context)
        if produced is None:
            controllers = []
        elif isinstance(produced, list):
            controllers = produced
        else:
            controllers = [produced]
        for controller in controllers:
            engine.add_controller(controller)

    wall_start = time.perf_counter()
    stats = engine.run()
    wall_elapsed = time.perf_counter() - wall_start

    telemetry.truncate_to(duration)

    detections: list[dict[str, Any]] = []
    mitigations: list[dict[str, Any]] = []
    for controller in controllers:
        detections.extend(getattr(controller, "detection_log", []) or [])
        mitigations.extend(getattr(controller, "mitigation_log", []) or [])

    summary = telemetry.summary()
    summary.update(
        {
            "run_id": run_id,
            "seed": seed,
            "duration_s": duration,
            "window_s": window_s,
            "n_iot_devices": len(topology.legitimate()),
            "n_attackers": len(topology.attackers()),
            "n_routers": int(config.get("network.topology.routers.count", 1)),
            "attack": profile.to_dict(),
            "benign_events": benign_events,
            "attack_families": attack_family_counts(attackers),
            "events_processed": stats.events_processed,
            "packets_generated": stats.packets_generated,
            "packets_delivered": stats.packets_delivered,
            "packets_dropped": stats.packets_dropped,
            "packet_cap_hit": stats.truncated_by_cap,
            "wall_budget_hit": stats.truncated_by_time,
            "completed_fraction": stats.completed_fraction,
            "peak_queue_packets": stats.max_queue_seen,
            "tcp_connections_opened": registry.opened,
            "tcp_connections_failed": registry.failed,
            "wall_seconds": round(wall_elapsed, 3),
            "engine": engine_id,
            "engine_label": engine_label(engine_id),
        }
    )

    result = SimulationResult(
        run_id=run_id,
        engine=engine_id,
        engine_reason=engine_reason,
        config=config.to_dict(),
        meta=meta,
        flows=telemetry.flow_rows(),
        windows=telemetry.metric_rows(),
        nodes=engine.node_report(),
        links=engine.link_report(),
        applications=[app.report() for app in applications],
        server=server.report(),
        attackers=[a.report() for a in attackers],
        topology=topology.describe(),
        summary=summary,
        detections=detections,
        mitigations=mitigations,
    )

    _LOG.info(
        "Run '%s' complete: %d flows across %d windows, attack fraction %.1f%%, "
        "mean latency %.2f ms, loss %.2f%%",
        run_id,
        len(result.flows),
        len(result.windows),
        100.0 * float(summary.get("attack_fraction", 0.0)),
        float(summary.get("mean_latency_ms", 0.0)),
        100.0 * float(summary.get("overall_loss_ratio", 0.0)),
    )
    return result


def run_and_save(
    config: Config,
    output_dir: str | Path,
    meta: Mapping[str, Any] | None = None,
    controller_factory: ControllerFactory | None = None,
    ns3_probe: NS3Availability | None = None,
) -> tuple[SimulationResult, dict[str, Path]]:
    """Run a simulation and immediately persist its artefacts.

    Args:
        config: Merged configuration.
        output_dir: Destination directory for the artefacts.
        meta: Experiment metadata.
        controller_factory: Optional in-loop controller factory.
        ns3_probe: Pre-computed NS-3 probe.

    Returns:
        ``(result, written_paths)``.
    """
    result = run_simulation(
        config, meta=meta, controller_factory=controller_factory, ns3_probe=ns3_probe
    )
    written = result.save(output_dir)
    config.save(resolve(output_dir) / "config_snapshot.yaml")
    return result, written


def probe_once() -> NS3Availability:
    """Probe NS-3 a single time (helper for batch drivers)."""
    return detect_ns3()
