"""Operational metrics of one closed-loop run: what an operator would measure.

Detection metrics say whether node-windows were labelled correctly. They do
not say how long the network suffered, how many innocent devices were cut
off, or how hard the defence worked the switch. This module turns one run's
window telemetry, detection log, mitigation log and application KPIs into
those numbers.

Definitions (all times in simulated seconds)
--------------------------------------------
``time_to_detect_s``
    Attack start to the decision time of the first window in which any
    ground-truth attacker scored at or above the trigger probability.
``time_to_mitigate_s``
    Attack start to the first rate-limit, block or isolate action.
``time_to_recover_s``
    Attack start to the end of the first window, after mitigation, whose
    clean-device availability is back within ``recover_fraction`` of the
    pre-attack baseline. ``None`` means it never recovered during the attack.
``availability_during_attack``
    Mean clean availability (delivered within the latency SLO / offered)
    over the attack windows.
``collateral_byte_ratio``
    Clean-device bytes dropped by mitigation / clean-device bytes offered,
    over the whole run.
``attack_suppression_ratio``
    Attack packets dropped by mitigation / attack packets offered during the
    attack.
``mitigation_precision`` / ``mitigation_recall``
    Over the set of nodes acted upon, against ground-truth attackers.
``rule_churn_per_min``
    Install + escalate + release actions per simulated minute.
``peak_active_rules``
    Largest number of nodes simultaneously under a rule (the TCAM budget).
``false_alarms_per_node_hour``
    Flagged (score >= trigger) windows of never-compromised endpoints, per
    endpoint-hour of observation.
"""

from __future__ import annotations

import math
from typing import Any, Mapping, Sequence

import numpy as np
import pandas as pd

ACTING_TYPES = {"rate_limit", "block", "isolate"}


def _attack_window(summary: Mapping[str, Any]) -> tuple[float | None, float | None]:
    attack = dict(summary.get("attack", {}) or {})
    if not attack.get("enabled"):
        return None, None
    start = float(attack.get("start_s", 0.0))
    end = float(attack.get("end_s", start + float(attack.get("duration_s", 0.0))))
    return start, end


def _num(frame: pd.DataFrame, column: str) -> pd.Series:
    if column not in frame.columns:
        return pd.Series(dtype=float)
    return pd.to_numeric(frame[column], errors="coerce")


def _peak_active(mitigations: Sequence[Mapping[str, Any]]) -> int:
    active: set[str] = set()
    peak = 0
    for row in sorted(mitigations, key=lambda r: float(r.get("timestamp", 0.0))):
        action = str(row.get("action", ""))
        node = str(row.get("node", ""))
        if action in ACTING_TYPES:
            active.add(node)
        elif action == "release":
            active.discard(node)
        peak = max(peak, len(active))
    return peak


def operational_metrics(
    result: Any,
    trigger: float = 0.80,
    recover_fraction: float = 0.95,
) -> dict[str, Any]:
    """Compute the operator-facing metric bundle for one run.

    Args:
        result: A :class:`~netshield.simulation.runner.SimulationResult` (live
            or loaded from disk).
        trigger: Probability at or above which a node counts as flagged.
        recover_fraction: Fraction of baseline availability that counts as
            recovered.

    Returns:
        A flat mapping; metrics that are undefined for the run are ``None``.
    """
    summary = dict(getattr(result, "summary", {}) or {})
    windows = pd.DataFrame(list(getattr(result, "windows", []) or []))
    detections = pd.DataFrame(list(getattr(result, "detections", []) or []))
    mitigations = list(getattr(result, "mitigations", []) or [])
    apps = pd.DataFrame(list(getattr(result, "applications", []) or []))
    attackers = {str(a.get("node_id", a)) if isinstance(a, Mapping) else str(a)
                 for a in (getattr(result, "attackers", None) or [])}
    if not attackers and not detections.empty and "is_attacker" in detections:
        flags = detections["is_attacker"].astype(str).str.lower() == "true"
        attackers = set(detections.loc[flags, "node"].astype(str))

    start, end = _attack_window(summary)
    duration = float(summary.get("duration_s", 0.0) or 0.0)
    out: dict[str, Any] = {"attack_start_s": start, "attack_end_s": end}

    # ---------------- network QoS by phase ----------------------------------
    if not windows.empty:
        for col in windows.columns:
            if col != "drop_reasons":
                windows[col] = pd.to_numeric(windows[col], errors="coerce")
        pre = windows[windows["t_end"] <= start] if start is not None else windows
        during = (windows[(windows["t_start"] >= start) & (windows["t_end"] <= end)]
                  if start is not None else windows.iloc[0:0])

        def mean_of(frame: pd.DataFrame, col: str) -> float | None:
            series = _num(frame, col).dropna()
            return round(float(series.mean()), 6) if len(series) else None

        for phase, frame in (("baseline", pre), ("attack", during)):
            for col in ("clean_availability", "clean_loss_ratio", "clean_p50_latency_ms",
                        "clean_p95_latency_ms", "clean_p99_latency_ms", "clean_jitter_ms",
                        "clean_fairness", "uplink_utilisation"):
                out[f"{phase}_{col}"] = mean_of(frame, col)
        out["availability_during_attack"] = out.get("attack_clean_availability")

        offered = _num(windows, "clean_offered").sum()
        if "collateral_byte_ratio" in windows.columns:
            # Weighted by clean offered load, so a quiet window does not dominate.
            ratio = _num(windows, "collateral_byte_ratio").fillna(0.0)
            weight = _num(windows, "clean_offered").fillna(0.0)
            out["collateral_byte_ratio"] = (round(float((ratio * weight).sum() / weight.sum()), 6)
                                            if weight.sum() else 0.0)
        out["clean_packets_dropped_by_mitigation"] = int(
            _num(windows, "clean_mitigation_dropped").fillna(0).sum())
        if not during.empty and "attack_suppression_ratio" in during.columns:
            att = _num(during, "attack_offered").fillna(0.0)
            sup = _num(during, "attack_suppression_ratio").fillna(0.0)
            out["attack_suppression_ratio"] = (round(float((sup * att).sum() / att.sum()), 6)
                                               if att.sum() else None)
        out["clean_offered_packets"] = int(offered)
    else:
        pre = during = pd.DataFrame()

    # ---------------- detection timing -------------------------------------
    out["time_to_detect_s"] = None
    if start is not None and not detections.empty:
        det = detections.copy()
        det["probability"] = pd.to_numeric(det["probability"], errors="coerce")
        det["timestamp"] = pd.to_numeric(det["timestamp"], errors="coerce")
        hit = det[(det["node"].astype(str).isin(attackers)) & (det["probability"] >= trigger)
                  & (det["timestamp"] > start)]
        if not hit.empty:
            out["time_to_detect_s"] = round(float(hit["timestamp"].min()) - start, 4)

    # ---------------- false alarms per endpoint-hour -----------------------
    out["false_alarms_per_node_hour"] = None
    if not detections.empty and duration > 0:
        det = detections.copy()
        det["probability"] = pd.to_numeric(det["probability"], errors="coerce")
        endpoints = det[det["kind"].astype(str).isin(["iot", "attacker"])]
        clean = endpoints[~endpoints["node"].astype(str).isin(attackers)]
        n_nodes = clean["node"].nunique()
        if n_nodes:
            flagged = int((clean["probability"] >= trigger).sum())
            out["false_alarms_per_node_hour"] = round(flagged / (n_nodes * duration / 3600.0), 4)
            out["false_alarm_nodes"] = int(clean.loc[clean["probability"] >= trigger,
                                                     "node"].nunique())
        if "inference_ms" in det.columns:
            per_window = pd.to_numeric(det.groupby("window")["inference_ms"].first(),
                                       errors="coerce").dropna()
            if len(per_window):
                out["inference_ms_mean"] = round(float(per_window.mean()), 3)
                out["inference_ms_p95"] = round(float(per_window.quantile(0.95)), 3)

    # ---------------- mitigation -------------------------------------------
    acting = [m for m in mitigations if str(m.get("action")) in ACTING_TYPES]
    out["n_mitigation_actions"] = len(mitigations)
    out["time_to_mitigate_s"] = (
        round(min(float(m["timestamp"]) for m in acting) - start, 4)
        if acting and start is not None else None)
    acted = {str(m["node"]) for m in acting}
    if acted or attackers:
        correct = acted & attackers
        out["mitigation_precision"] = round(len(correct) / len(acted), 5) if acted else None
        out["mitigation_recall"] = (round(len(correct) / len(attackers), 5)
                                    if attackers else None)
        out["wrongly_mitigated_nodes"] = len(acted - attackers)
    out["rule_churn_per_min"] = (round(len(mitigations) / (duration / 60.0), 4)
                                 if duration > 0 else None)
    out["peak_active_rules"] = _peak_active(mitigations)

    # ---------------- recovery ---------------------------------------------
    out["time_to_recover_s"] = None
    base_av = out.get("baseline_clean_availability")
    if acting and start is not None and base_av and not windows.empty:
        first_action = min(float(m["timestamp"]) for m in acting)
        after = windows[(windows["t_start"] >= first_action) & (windows["t_end"] <= end)]
        ok = after[_num(after, "clean_availability") >= recover_fraction * base_av]
        if not ok.empty:
            out["time_to_recover_s"] = round(float(ok["t_end"].iloc[0]) - start, 4)

    # ---------------- application flow completion -------------------------
    if not apps.empty and "fct_p95_ms" in apps.columns:
        for cls in ("http_client", "tcp_uploader"):
            rows = apps[apps["device_class"] == cls]
            p95 = pd.to_numeric(rows["fct_p95_ms"], errors="coerce").dropna()
            out[f"fct_p95_ms_{cls}"] = round(float(p95.median()), 3) if len(p95) else None
        success = pd.to_numeric(apps.get("success_ratio"), errors="coerce").dropna()
        out["app_success_ratio"] = round(float(success.mean()), 5) if len(success) else None
    return {k: (None if isinstance(v, float) and math.isnan(v) else v) for k, v in out.items()}


def aggregate_operational(rows: Sequence[Mapping[str, Any]]) -> pd.DataFrame:
    """Summarise many runs' operational metrics: mean, std, median, n."""
    frame = pd.DataFrame(list(rows))
    numeric = frame.apply(pd.to_numeric, errors="coerce")
    stats = []
    for col in numeric.columns:
        values = numeric[col].dropna()
        if values.empty:
            continue
        stats.append({"metric": col, "n": int(len(values)), "mean": float(values.mean()),
                      "std": float(values.std(ddof=1)) if len(values) > 1 else 0.0,
                      "median": float(values.median()),
                      "p95": float(np.quantile(values, 0.95))})
    return pd.DataFrame(stats)
