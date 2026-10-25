"""Closed-loop detection and mitigation controller.

This is what makes NetShield-GNN a *system* rather than an offline classifier.
The controller is registered with the simulation engine and invoked at every
feature-window boundary **in simulated time**. On each invocation it:

1. Reads the flow records the gateway exported for the window that just closed.
2. Builds the node-window feature matrix and the window graph - the exact same
   code path used offline, so training and deployment cannot diverge.
3. Scores every node with the trained detector.
4. Hands the scores to the mitigation engine, which installs rate-limit, block
   or isolation rules at the gateway ingress.

Because step 4 mutates the packet filter that the engine consults for every
subsequent packet, the consequences of a decision taken at ``t = 45 s`` are
physically realised from ``t = 45 s`` onwards *within the same simulation*. The
recovery curves in ``results/figures`` are therefore measurements, not
illustrations.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Mapping

import numpy as np
import pandas as pd

from ..features.node_features import CLASS_NAMES, build_node_window_features
from ..graph.builder import build_edge_table
from ..mitigation.engine import MitigationEngine
from ..models.base import DetectionInput, Detector
from ..utils.logging_utils import get_logger

_LOG = get_logger(__name__)


class WindowResultView:
    """A duck-typed :class:`~netshield.simulation.runner.SimulationResult` slice.

    The feature builder and the graph builder both consume a ``SimulationResult``
    interface. Rather than duplicating that logic for the live path, this view
    exposes exactly the attributes they read, backed by a single window's flow
    records. One code path, two call sites - so a feature can never be computed
    one way during training and another way at run time.

    Args:
        run_id: Identifier of the running simulation.
        meta: Experiment metadata.
        engine: Engine provenance id.
        topology: Serialised topology description.
        summary: Minimal summary carrying ``window_s`` and the attack profile.
        flows: Flow-record rows for this window only.
    """

    __slots__ = ("run_id", "meta", "engine", "topology", "summary", "flows")

    def __init__(
        self,
        run_id: str,
        meta: Mapping[str, Any],
        engine: str,
        topology: Mapping[str, Any],
        summary: Mapping[str, Any],
        flows: list[dict[str, Any]],
    ) -> None:
        self.run_id = run_id
        self.meta = dict(meta)
        self.engine = engine
        self.topology = dict(topology)
        self.summary = dict(summary)
        self.flows = flows


@dataclass(slots=True)
class DetectionEvent:
    """One node scored in one window.

    Attributes:
        timestamp: Simulated time the decision was made (window boundary).
        window: Window index.
        node: Node id.
        ip: Node address.
        kind: Node role.
        probability: ``P(SUSPICIOUS) + P(MALICIOUS)``.
        predicted: Predicted class name.
        predicted_index: Predicted class index.
        proba: Full three-class probability vector.
        is_attacker: Ground truth, recorded for offline scoring only.
        packet_rate: The node's observed egress packet rate, for context.
        detector: Detector name.
        inference_ms: Wall-clock inference cost of the whole window.
    """

    timestamp: float
    window: int
    node: str
    ip: str
    kind: str
    probability: float
    predicted: str
    predicted_index: int
    proba: list[float]
    is_attacker: bool
    packet_rate: float
    detector: str
    inference_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON/CSV row."""
        return {
            "timestamp": round(self.timestamp, 4),
            "window": self.window,
            "node": self.node,
            "ip": self.ip,
            "kind": self.kind,
            "probability": round(self.probability, 5),
            "predicted": self.predicted,
            "predicted_index": self.predicted_index,
            "p_benign": round(self.proba[0], 5),
            "p_suspicious": round(self.proba[1], 5),
            "p_malicious": round(self.proba[2], 5),
            "is_attacker": self.is_attacker,
            "packet_rate": round(self.packet_rate, 3),
            "detector": self.detector,
            "inference_ms": round(self.inference_ms, 3),
        }


class DetectionController:
    """Runs a trained detector inside a live simulation, window by window.

    Args:
        context: The :class:`~netshield.simulation.runner.SimulationContext`.
        detector: A fitted detector.
        mitigation: Optional mitigation engine; omit for detect-only runs.
        trigger: Probability at or above which a node is reported as detected.
        alert_only_endpoints: Restrict mitigation to endpoint nodes. Enabled by
            default: throttling one's own gateway would be self-inflicted denial
            of service.
        warmup_windows: Number of initial windows to observe without acting,
            letting periodic applications reach steady state.
    """

    def __init__(
        self,
        context: Any,
        detector: Detector,
        mitigation: MitigationEngine | None = None,
        trigger: float = 0.80,
        alert_only_endpoints: bool = True,
        warmup_windows: int = 1,
    ) -> None:
        self.context = context
        self.detector = detector
        self.mitigation = mitigation
        self.trigger = float(trigger)
        self.alert_only_endpoints = bool(alert_only_endpoints)
        self.warmup_windows = int(warmup_windows)

        self.detection_log: list[dict[str, Any]] = []
        self.mitigation_log: list[dict[str, Any]] = []
        self.window_summaries: list[dict[str, Any]] = []
        self.inference_times_ms: list[float] = []
        self._topology = context.topology.describe()
        self._node_ips = {n.node_id: n.ip for n in context.topology.nodes.values()}
        self._attackers = {n.node_id for n in context.topology.attackers()}
        #: Detectors with memory (GRU, temporal GNN) declare how many windows
        #: they look back over; the controller buffers that many so live
        #: scoring sees the same history as offline scoring.
        self._history_windows = max(1, int(getattr(detector, "history_windows", 1)))
        self._buffer: list[tuple[pd.DataFrame, pd.DataFrame]] = []
        #: Recent windows' evidence, kept for on-demand explanations.
        self.recent: dict[int, tuple[pd.DataFrame, pd.DataFrame]] = {}

        if mitigation is not None:
            context.engine.packet_filter = mitigation.enforcer
            # Arm every gateway the topology nominates, not just the primary:
            # in a multi-gateway fabric a botnet straddles enforcement domains,
            # and filtering at one gateway would leave the other half running.
            points = context.topology.enforcement_nodes or [context.topology.gateway_id]
            context.engine.enforcement_nodes = set(points)
            _LOG.info(
                "Mitigation enforcement armed at %s (trigger p>=%.2f).",
                ", ".join(sorted(points)), self.trigger,
            )

    # ------------------------------------------------------------------ #
    def _window_flows(self, window_index: int) -> list[dict[str, Any]]:
        """Return the flow-record rows exported for *window_index*."""
        telemetry = self.context.telemetry
        window_s = telemetry.window_s
        return [
            record.to_row(window_s)
            for key, record in telemetry.flows.items()
            if key[0] == window_index
        ]

    def _summary_stub(self) -> dict[str, Any]:
        """Return the minimal summary the feature builder reads."""
        from ..traffic.attacks import AttackProfile

        profile = AttackProfile.from_config(self.context.config)
        return {
            "window_s": self.context.telemetry.window_s,
            "attack": profile.to_dict(),
        }

    # ------------------------------------------------------------------ #
    def on_window(self, engine: Any, window_index: int, t: float) -> None:
        """Score the window that just closed and, if armed, mitigate.

        Args:
            engine: The running simulation engine.
            window_index: Index of the completed window.
            t: Current simulated time (the window boundary).
        """
        flows = self._window_flows(window_index)
        if not flows:
            return

        started = time.perf_counter()
        view = WindowResultView(
            run_id=self.context.run_id,
            meta=dict(self.context.config.get("meta", {}) or {}),
            engine=str(self.context.config.get("simulation.engine", "python")),
            topology=self._topology,
            summary=self._summary_stub(),
            flows=flows,
        )

        try:
            features = build_node_window_features(view)
        except ValueError:
            return
        edges = build_edge_table(view)
        self.recent[window_index] = (features, edges)
        for old in [w for w in self.recent if w <= window_index - 30]:
            del self.recent[old]

        if self._history_windows > 1:
            self._buffer.append((features, edges))
            self._buffer = self._buffer[-self._history_windows:]
            history = DetectionInput(
                pd.concat([f for f, _ in self._buffer], ignore_index=True),
                pd.concat([e for _, e in self._buffer], ignore_index=True))
            proba_all = self.detector.predict_proba(history)
            current = (history.features["window"] == features["window"].iloc[0]).to_numpy()
            proba = proba_all[current]
        else:
            data = DetectionInput(features, edges)
            proba = self.detector.predict_proba(data)
        scores = proba[:, 1] + proba[:, 2]
        predictions = proba.argmax(axis=1)
        inference_ms = (time.perf_counter() - started) * 1000.0
        self.inference_times_ms.append(inference_ms)

        events: list[DetectionEvent] = []
        for i, row in enumerate(features.itertuples(index=False)):
            events.append(
                DetectionEvent(
                    timestamp=t,
                    window=window_index,
                    node=str(row.node_id),
                    ip=self._node_ips.get(str(row.node_id), ""),
                    kind=str(row.kind),
                    probability=float(scores[i]),
                    predicted=CLASS_NAMES[int(predictions[i])],
                    predicted_index=int(predictions[i]),
                    proba=[float(v) for v in proba[i]],
                    is_attacker=bool(row.is_attacker),
                    packet_rate=float(row.eg_packet_rate),
                    detector=self.detector.name,
                    inference_ms=inference_ms,
                )
            )
        self.detection_log.extend(event.to_dict() for event in events)

        flagged = [e for e in events if e.probability >= self.trigger]
        self.window_summaries.append({
            "window": window_index,
            "timestamp": round(t, 4),
            "n_scored": len(events),
            "n_flagged": len(flagged),
            "flagged_nodes": [e.node for e in flagged],
            "max_probability": round(max((e.probability for e in events), default=0.0), 5),
            "inference_ms": round(inference_ms, 3),
        })

        if self.mitigation is None or window_index < self.warmup_windows:
            return

        scores_by_node: dict[str, float] = {}
        predicted_by_node: dict[str, str] = {}
        for event in events:
            if self.alert_only_endpoints and event.kind not in ("iot", "attacker"):
                continue
            scores_by_node[event.node] = event.probability
            predicted_by_node[event.node] = event.predicted

        actions = self.mitigation.apply_window(
            window=window_index, t=t, scores=scores_by_node, predicted=predicted_by_node
        )
        self.mitigation_log.extend(action.to_dict() for action in actions)

    # ------------------------------------------------------------------ #
    def report(self) -> dict[str, Any]:
        """Return a JSON-serialisable summary of the controller's activity."""
        detections = pd.DataFrame(self.detection_log)
        flagged_attackers: set[str] = set()
        false_alarms: set[str] = set()
        if not detections.empty:
            hits = detections[detections["probability"] >= self.trigger]
            flagged_attackers = set(hits[hits["is_attacker"]]["node"])
            false_alarms = set(hits[~hits["is_attacker"]]["node"])

        return {
            "detector": self.detector.name,
            "trigger_probability": self.trigger,
            "windows_scored": len(self.window_summaries),
            "n_detection_events": len(self.detection_log),
            "n_mitigation_actions": len(self.mitigation_log),
            "attackers_total": len(self._attackers),
            "attackers_flagged": sorted(flagged_attackers),
            "attackers_missed": sorted(self._attackers - flagged_attackers),
            "false_alarm_nodes": sorted(false_alarms),
            "mean_inference_ms": (
                round(float(np.mean(self.inference_times_ms)), 3)
                if self.inference_times_ms else None
            ),
            "max_inference_ms": (
                round(float(np.max(self.inference_times_ms)), 3)
                if self.inference_times_ms else None
            ),
            "mitigation": self.mitigation.summary() if self.mitigation else None,
        }

    def detection_frame(self) -> pd.DataFrame:
        """Return the detection log as a :class:`pandas.DataFrame`."""
        return pd.DataFrame(self.detection_log)


def first_detection_time(
    detection_log: list[dict[str, Any]], trigger: float
) -> float | None:
    """Return the earliest time an attacker node was flagged.

    Args:
        detection_log: Rows produced by :class:`DetectionController`.
        trigger: Probability threshold.

    Returns:
        The simulated time, or ``None`` if no attacker was ever flagged.
    """
    times = [
        float(row["timestamp"])
        for row in detection_log
        if row.get("is_attacker") and float(row.get("probability", 0.0)) >= trigger
    ]
    return min(times) if times else None
