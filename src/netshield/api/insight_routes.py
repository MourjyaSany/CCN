"""Read endpoints that power the operations dashboard.

``GET  /api/timeline``              full window series + incident events (live run)
``GET  /api/nodes/{node}/history``  score / rate / action history of one node
``GET  /api/explain/{node}``        why the detector scored this node as it did
``GET  /api/policy``                current approval mode and ladder thresholds
``POST /api/policy``                change the approval mode   (operator)
``GET  /api/replay/runs``           saved runs available for replay
``GET  /api/replay/{run_id}``       one saved run: topology, windows, detections, actions
``GET  /api/research/summary``      every research-protocol table as JSON
"""

from __future__ import annotations

import json
import math
from typing import Any

import pandas as pd
from fastapi import Body, FastAPI, HTTPException, Query

from ..utils.paths import resolve


def _clean(value: Any) -> Any:
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        return None
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_clean(v) for v in value]
    return value


def incident_events(windows: list[dict], detections: list[dict], mitigations: list[dict],
                    attack: dict | None, trigger: float = 0.8) -> list[dict[str, Any]]:
    """Attack start/end, first detection, first mitigation, recovery."""
    events: list[dict[str, Any]] = []
    if attack and attack.get("enabled"):
        events.append({"t": float(attack["start_s"]), "kind": "attack_start",
                       "label": f"{attack.get('type', 'attack')} starts"})
        end = attack.get("end_s", float(attack["start_s"]) + float(attack.get("duration_s", 0)))
        events.append({"t": float(end), "kind": "attack_end", "label": "attack ends"})
    hits = [d for d in detections if float(d.get("probability", 0)) >= trigger
            and str(d.get("is_attacker")).lower() == "true"]
    if hits:
        first = min(hits, key=lambda d: float(d["timestamp"]))
        events.append({"t": float(first["timestamp"]), "kind": "first_detection",
                       "label": f"first bot flagged: {first['node']}"})
    acting = [m for m in mitigations if m.get("action") in ("rate_limit", "block", "isolate")]
    if acting:
        first = min(acting, key=lambda m: float(m["timestamp"]))
        events.append({"t": float(first["timestamp"]), "kind": "first_mitigation",
                       "label": f"{first['action']} on {first['node']}"})
        base = [w.get("clean_availability") for w in windows
                if attack and float(w["t_end"]) <= float(attack.get("start_s", 0))
                and w.get("clean_availability") is not None]
        if base:
            target = 0.95 * (sum(base) / len(base))
            for w in windows:
                if float(w["t_start"]) >= float(first["timestamp"]) and \
                        (w.get("clean_availability") or 0) >= target:
                    events.append({"t": float(w["t_end"]), "kind": "recovered",
                                   "label": "clean availability recovered"})
                    break
    return sorted(events, key=lambda e: e["t"])


def register_insights(app: FastAPI, cfg: Any, session: Any) -> None:
    trigger = float(cfg.get("detection.mitigation_trigger_probability", 0.8))

    def controller() -> Any:
        return getattr(session, "controller", None)

    @app.get("/api/timeline", tags=["live"])
    def timeline() -> dict[str, Any]:
        snap = session.snapshot()
        ctrl = controller()
        windows = list(snap.windows or [])
        detections = list(getattr(ctrl, "detection_log", []) or []) if ctrl else []
        mitigations = list(getattr(ctrl, "mitigation_log", []) or []) if ctrl else []
        attack = None
        try:
            from ..utils.config import experiment_config  # noqa: PLC0415

            if snap.scenario:
                attack = experiment_config(snap.scenario)[0].get("attack", {})
        except Exception:  # noqa: BLE001
            attack = None
        cols = ("window", "t_start", "t_end", "clean_availability", "clean_p50_latency_ms",
                "clean_p99_latency_ms", "clean_jitter_ms", "clean_loss_ratio",
                "throughput_mbps", "offered_mbps", "uplink_utilisation", "attack_offered",
                "legit_offered", "mitigation_drops", "collateral_byte_ratio", "clean_fairness",
                "mitigated_sources", "active_attackers")
        series = [{k: w.get(k) for k in cols if k in w} for w in windows]
        flagged = {}
        for d in detections:
            if float(d.get("probability", 0)) >= trigger:
                flagged.setdefault(int(d["window"]), set()).add(d["node"])
        for row in series:
            row["flagged_nodes"] = len(flagged.get(int(row.get("window", -1)), ()))
        return _clean({"state": snap.state, "scenario": snap.scenario, "run_id": snap.run_id,
                       "sim_time_s": snap.sim_time_s, "duration_s": snap.duration_s,
                       "windows": series, "mitigations": mitigations[-200:],
                       "events": incident_events(windows, detections, mitigations, attack,
                                                 trigger)})

    @app.get("/api/nodes/{node}/history", tags=["live"])
    def node_history(node: str) -> dict[str, Any]:
        ctrl = controller()
        if ctrl is None:
            raise HTTPException(404, "No running session")
        rows = [d for d in ctrl.detection_log if d.get("node") == node]
        actions = [m for m in ctrl.mitigation_log if m.get("node") == node]
        return _clean({"node": node, "history": rows[-120:], "actions": actions})

    @app.get("/api/explain/{node}", tags=["live"])
    def explain_node(node: str, window: int | None = Query(None)) -> dict[str, Any]:
        from ..explain import explain  # noqa: PLC0415
        from ..models.base import DetectionInput  # noqa: PLC0415

        ctrl = controller()
        if ctrl is None or not getattr(ctrl, "recent", None):
            raise HTTPException(404, "No live evidence to explain yet")
        w = window if window is not None else max(ctrl.recent)
        if w not in ctrl.recent:
            raise HTTPException(404, f"Window {w} is no longer buffered")
        features, edges = ctrl.recent[w]
        try:
            out = explain(ctrl.detector, DetectionInput(features, edges), node)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        return _clean({**out, "window": w, "detector": ctrl.detector.name})

    @app.get("/api/policy", tags=["mitigation"])
    def policy() -> dict[str, Any]:
        ctrl = controller()
        engine = getattr(ctrl, "mitigation", None) if ctrl else None
        p = cfg.get("mitigation.policy", {}) or {}
        return {"approval_mode": engine.approval_mode if engine else
                str(cfg.get("mitigation.approval_mode", "auto")),
                "trigger_probability": trigger, **p,
                "rate_limit_pps": cfg.get("mitigation.rate_limit_pps"),
                "escalation_windows": cfg.get("mitigation.escalation_windows"),
                "release_after_clean_windows": cfg.get("mitigation.release_after_clean_windows")}

    @app.post("/api/policy", tags=["mitigation"])
    def set_policy(approval_mode: str = Body(..., embed=True)) -> dict[str, Any]:
        if approval_mode not in ("auto", "hybrid", "manual"):
            raise HTTPException(422, "approval_mode must be auto, hybrid or manual")
        ctrl = controller()
        engine = getattr(ctrl, "mitigation", None) if ctrl else None
        if engine is None:
            raise HTTPException(404, "No running simulation with mitigation armed")
        engine.approval_mode = approval_mode
        return {"approval_mode": approval_mode}

    root = resolve(cfg.get("paths.data_experiments", "data/experiments"))

    @app.get("/api/replay/runs", tags=["results"])
    def replay_runs(limit: int = Query(60, ge=1, le=500),
                    closed_loop_only: bool = Query(False)) -> list[dict[str, Any]]:
        out = []
        for path in sorted(root.glob("*/run.json"), key=lambda p: p.stat().st_mtime,
                           reverse=True):
            try:
                doc = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if closed_loop_only and not doc.get("n_mitigations"):
                continue
            meta = doc.get("meta", {})
            out.append({"run_id": doc["run_id"], "experiment": meta.get("experiment"),
                        "topology": meta.get("topology_family", doc.get("topology", {})
                                             .get("family")),
                        "detector": meta.get("closed_loop"),
                        "n_windows": doc.get("n_windows"),
                        "n_detections": doc.get("n_detections"),
                        "n_mitigations": doc.get("n_mitigations"),
                        "generated_at": doc.get("generated_at")})
            if len(out) >= limit:
                break
        return out

    @app.get("/api/replay/{run_id}", tags=["results"])
    def replay(run_id: str) -> dict[str, Any]:
        from ..simulation.runner import load_run  # noqa: PLC0415

        path = (root / run_id).resolve()
        if root.resolve() not in path.parents or not (path / "run.json").exists():
            raise HTTPException(404, f"Unknown run {run_id!r}")
        r = load_run(path)
        windows = [{k: v for k, v in w.items() if k != "drop_reasons"} for w in r.windows]
        return _clean({"run_id": r.run_id, "meta": r.meta, "topology": r.topology,
                       "windows": windows, "detections": r.detections,
                       "mitigations": r.mitigations, "summary": r.summary,
                       "events": incident_events(r.windows, r.detections, r.mitigations,
                                                 r.summary.get("attack"), trigger)})

    research = resolve("results/research")

    @app.get("/api/research/summary", tags=["results"])
    def research_summary() -> dict[str, Any]:
        tables = {}
        for path in sorted(research.glob("*.csv")):
            try:
                tables[path.stem] = pd.read_csv(path).to_dict("records")
            except Exception:  # noqa: BLE001 - a malformed table must not break the page
                continue
        adv = research / "adversary" / "adversary_summary.csv"
        if adv.exists():
            tables["adversary_summary"] = pd.read_csv(adv).to_dict("records")
        figures = sorted(p.name for p in resolve("results/figures").glob("research_*.png"))
        report = resolve("results/reports/RESEARCH_RESULTS.md")
        return _clean({"tables": tables, "figures": figures,
                       "report_available": report.exists()})
