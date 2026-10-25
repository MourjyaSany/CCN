"""Streaming detection pipeline: collector -> features -> inference -> policy.

Each stage is a small service that reads one bus topic and writes the next,
so in production they run as separate processes (or containers) connected by
Redis Streams and scale independently; in tests and the demo they run in one
process over :class:`~netshield.platform.bus.InMemoryBus`.

=============  =================  =========================================
Service        consumes           produces
=============  =================  =========================================
Collector      IPFIX / flow rows  ``flows``    {window, flows}
Features       ``flows``          ``features`` {window, features, edges}
Inference      ``features``       ``scores``   {window, scores, predicted}
                                  ``alerts``   one per flagged node
Policy         ``scores``         ``actions``  {action, rules}
=============  =================  =========================================

The feature and inference stages reuse exactly the functions the simulator's
in-loop controller uses, so streaming, offline and closed-loop scoring are
one code path.
"""

from __future__ import annotations

import time
from typing import Any, Iterable, Mapping, Sequence

import pandas as pd

from ..detection.controller import WindowResultView
from ..features.node_features import CLASS_NAMES, build_node_window_features
from ..graph.builder import build_edge_table
from ..models.base import DetectionInput, Detector
from .bus import Bus
from .ipfix import Decoder, encode, to_flow_rows


class CollectorService:
    """Receives flow records and publishes them per closed window."""

    def __init__(self, bus: Bus, node_of: Mapping[str, str], window_s: float = 5.0,
                 base_ms: int = 0, metrics: Any = None,
                 node_of_port: Mapping[int, str] | None = None) -> None:
        self.bus, self.node_of, self.window_s, self.base_ms = bus, dict(node_of), window_s, base_ms
        self.node_of_port = dict(node_of_port or {})
        self.decoder = Decoder()
        self.pending: dict[int, list[dict[str, Any]]] = {}
        self.metrics = metrics

    def ingest_ipfix(self, message: bytes) -> int:
        records = self.decoder.decode(message)
        return self.ingest_rows(to_flow_rows(records, self.node_of, self.window_s, self.base_ms,
                                             self.node_of_port))

    def ingest_rows(self, rows: Iterable[Mapping[str, Any]]) -> int:
        n = 0
        for row in rows:
            self.pending.setdefault(int(row["window"]), []).append(dict(row))
            n += 1
        return n

    def flush(self, up_to_window: int | None = None) -> list[int]:
        """Publish every buffered window ``<= up_to_window`` (all when None)."""
        done = sorted(w for w in self.pending if up_to_window is None or w <= up_to_window)
        for w in done:
            self.bus.publish("flows", {"window": w, "flows": self.pending.pop(w)})
            if self.metrics:
                self.metrics.bus_messages.labels("flows").inc()
        return done


class FeatureService:
    """Turns one window of flows into node features and graph edges."""

    def __init__(self, bus: Bus, topology: Mapping[str, Any], window_s: float = 5.0,
                 run_id: str = "live") -> None:
        self.bus, self.topology, self.window_s, self.run_id = bus, dict(topology), window_s, run_id

    def step(self) -> int:
        n = 0
        for msg in self.bus.consume("flows", "features", timeout_s=0.0):
            view = WindowResultView(run_id=self.run_id, meta={"experiment": "stream"},
                                    engine="stream", topology=self.topology,
                                    summary={"window_s": self.window_s,
                                             "attack": {"enabled": False}},
                                    flows=msg["flows"])
            try:
                features = build_node_window_features(view)
            except ValueError:
                continue
            edges = build_edge_table(view)
            self.bus.publish("features", {"window": msg["window"],
                                          "features": features.to_dict("records"),
                                          "edges": edges.to_dict("records")})
            n += 1
        return n


class InferenceService:
    """Scores feature windows; keeps a history buffer for temporal models."""

    def __init__(self, bus: Bus, detector: Detector, trigger: float = 0.8,
                 metrics: Any = None) -> None:
        self.bus, self.detector, self.trigger, self.metrics = bus, detector, trigger, metrics
        self.history = max(1, int(getattr(detector, "history_windows", 1)))
        self.buffer: list[tuple[pd.DataFrame, pd.DataFrame]] = []

    def step(self) -> int:
        n = 0
        for msg in self.bus.consume("features", "inference", timeout_s=0.0):
            features = pd.DataFrame(msg["features"])
            edges = pd.DataFrame(msg["edges"])
            self.buffer = (self.buffer + [(features, edges)])[-self.history:]
            data = DetectionInput(pd.concat([f for f, _ in self.buffer], ignore_index=True),
                                  pd.concat([e for _, e in self.buffer], ignore_index=True))
            t0 = time.perf_counter()
            proba = self.detector.predict_proba(data)
            elapsed = time.perf_counter() - t0
            current = (data.features["window"] == msg["window"]).to_numpy()
            rows = data.features.loc[current]
            p = proba[current]
            hostile = p[:, 1] + p[:, 2]
            scores, predicted = {}, {}
            for node, kind, h, cls, ip in zip(rows["node_id"], rows["kind"], hostile,
                                              p.argmax(1), rows["ip"]):
                if kind not in ("iot", "attacker"):
                    continue
                scores[node] = float(h)
                predicted[node] = CLASS_NAMES[int(cls)]
                if h >= self.trigger:
                    self.bus.publish("alerts", {"window": msg["window"], "node": node, "ip": ip,
                                                "probability": float(h),
                                                "predicted": CLASS_NAMES[int(cls)],
                                                "detector": self.detector.name})
            self.bus.publish("scores", {"window": msg["window"], "scores": scores,
                                        "predicted": predicted,
                                        "inference_ms": round(elapsed * 1000, 3)})
            if self.metrics:
                self.metrics.windows_scored.labels(self.detector.name).inc()
                self.metrics.inference_seconds.labels(self.detector.name).observe(elapsed)
                self.metrics.nodes_flagged.labels(self.detector.name).inc(
                    sum(1 for v in scores.values() if v >= self.trigger))
            n += 1
        return n


class PolicyService:
    """Applies the mitigation ladder and renders data-plane rules."""

    def __init__(self, bus: Bus, engine: Any, window_s: float = 5.0,
                 export_target: str | None = None, ports: Any = None, audit: Any = None,
                 metrics: Any = None) -> None:
        self.bus, self.engine, self.window_s = bus, engine, window_s
        self.export_target, self.ports, self.audit, self.metrics = (export_target, ports,
                                                                    audit, metrics)

    def step(self) -> int:
        from ..mitigation.export import render  # noqa: PLC0415

        n = 0
        for msg in self.bus.consume("scores", "policy", timeout_s=0.0):
            w = int(msg["window"])
            actions = self.engine.apply_window(window=w, t=(w + 1) * self.window_s,
                                               scores=msg["scores"],
                                               predicted=msg.get("predicted"))
            for a in actions:
                rules: list[Any] = []
                if self.export_target and self.ports is not None:
                    try:
                        rules = render([a], self.export_target, self.ports)
                    except KeyError:
                        rules = []
                self.bus.publish("actions", {**a.to_dict(), "rules": rules})
                if self.audit:
                    self.audit.record("system", "system", f"mitigation.{a.action.value}",
                                      a.node, detail={"confidence": a.confidence,
                                                      "window": w, "reason": a.reason})
                if self.metrics:
                    self.metrics.mitigation_actions.labels(a.action.value, "auto").inc()
            n += 1
        return n


class Pipeline:
    """Wires the four services over one bus and pumps them synchronously."""

    def __init__(self, bus: Bus, collector: CollectorService, features: FeatureService,
                 inference: InferenceService, policy: PolicyService | None = None) -> None:
        self.bus, self.collector, self.features = bus, collector, features
        self.inference, self.policy = inference, policy

    def pump(self) -> dict[str, int]:
        out = {"features": self.features.step(), "scores": self.inference.step()}
        if self.policy:
            out["actions"] = self.policy.step()
        return out


def replay_flows_as_ipfix(flow_rows: Sequence[Mapping[str, Any]], window_s: float = 5.0,
                          base_ms: int = 1_700_000_000_000,
                          port_of: Mapping[str, int] | None = None
                          ) -> list[tuple[int, list[bytes]]]:
    """Encode a run's flow rows as IPFIX messages, grouped by window.

    Used to drive the pipeline from a simulator run or a capture exactly as
    an exporter would.
    """
    by_window: dict[int, list[Mapping[str, Any]]] = {}
    for row in flow_rows:
        by_window.setdefault(int(row["window"]), []).append(row)
    out = []
    seq = 0
    for w in sorted(by_window):
        msgs = encode(by_window[w], window_s=window_s, sequence=seq, base_ms=base_ms,
                      port_of=port_of)
        seq += len(by_window[w])
        out.append((w, msgs))
    return out
