"""Adaptive adversary: black-box Bayesian search against a deployed defence.

Threat model
------------
The attacker controls a botnet inside the simulated network and chooses the
attack's parameters: family, per-bot rate, botnet size, packet sizes, on/off
pulsing, rate profile (constant, ramp, sine, step), per-bot jitter,
staggered joins, destination ports and source spoofing. It can observe one
thing about the defence: how much damage each attempt did. That is the
realistic feedback channel - an attacker sees whether the target slowed down,
not the defender's internal scores.

The defence is the full closed loop: detector + mitigation ladder at the
gateway. An attack that is detected gets rate-limited or blocked, so its
damage collapses. The attacker's objective, *damage under defence*, therefore
rewards evasion without having to be told what evasion is.

    damage = 1 - availability_during_attack / baseline_availability

where availability is the share of clean-device packets delivered within
the latency SLO (see :mod:`netshield.simulation.telemetry`).

Search
------
Optuna's TPE sampler proposes batches of attack configurations; each batch
is simulated in parallel worker processes and the results are reported back.
Every trial is also tagged with whether any bot was ever flagged, the attack
volume and the per-bot rate, which is what the stealth frontier is drawn
from.

Metrics
-------
``evasion_success_rate``
    Fraction of trials that violate the SLO (damage >= ``slo_damage``) while
    no bot is ever flagged.
``stealth_frontier``
    For log-spaced attack-volume bins, the largest damage achieved by an
    undetected trial. Its area (trapezoid over log volume) is a single
    scalar of how much harm stays invisible to the detector.
``min_undetected_volume_for_slo``
    Smallest offered attack volume (Mbit/s) at which an undetected trial
    breaks the SLO - the "stealth threshold".
"""

from __future__ import annotations

import json
import math
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any, Mapping, Sequence

import numpy as np
import pandas as pd

from ..utils.logging_utils import get_logger

_LOG = get_logger(__name__)

FAMILIES: tuple[str, ...] = ("udp_flood", "syn_flood", "http_flood", "icmp_flood",
                             "ack_flood", "slowloris")
PORTS: tuple[int, ...] = (80, 443, 1883, 8883, 5683, 22, 9001)
ATTACK_START_S = 30.0
ATTACK_DURATION_S = 40.0
RUN_DURATION_S = 90.0


def suggest_attack(trial: Any) -> dict[str, Any]:
    """Sample one attack configuration from an Optuna trial."""
    family = trial.suggest_categorical("family", list(FAMILIES))
    pps_hi = {"http_flood": 500.0, "slowloris": 40.0}.get(family, 3000.0)
    pps = trial.suggest_float("pps", 5.0, pps_hi, log=True)
    size = trial.suggest_int("packet_bytes", 64, 1400, log=True)
    params = {
        "family": family, "pps": pps,
        "n_attackers": trial.suggest_int("n_attackers", 2, 16),
        "packet_bytes": size,
        "burst": trial.suggest_categorical("burst", [False, True]),
        "on_s": trial.suggest_float("on_s", 0.3, 5.0),
        "off_s": trial.suggest_float("off_s", 0.3, 8.0),
        "profile": trial.suggest_categorical("profile", ["constant", "ramp", "sine", "step"]),
        "jitter": trial.suggest_float("jitter", 0.0, 0.6),
        "stagger_s": trial.suggest_float("stagger_s", 0.0, 15.0),
        "spoof": trial.suggest_categorical("spoof", [False, True]),
        "port": trial.suggest_categorical("port", list(PORTS)),
    }
    if family == "slowloris":
        params["sockets"] = trial.suggest_int("sockets", 5, 60)
    return params


def attack_overrides(params: Mapping[str, Any]) -> dict[str, Any]:
    """Translate a parameter vector into a config override block."""
    family = params["family"]
    size = int(params["packet_bytes"])
    port = int(params["port"])
    ports = [0] if family == "icmp_flood" else [port]
    block: dict[str, Any] = {
        "simulation": {"n_attackers": int(params["n_attackers"]),
                       "duration_s": RUN_DURATION_S},
        "attack": {
            "enabled": True, "type": family, "start_s": ATTACK_START_S,
            "duration_s": ATTACK_DURATION_S, "packets_per_second": float(params["pps"]),
            "packet_bytes": [size, size] if family not in ("syn_flood", "ack_flood")
            else [64, 64],
            "dst_ports": ports,
            "burst": {"enabled": bool(params["burst"]), "on_s": float(params["on_s"]),
                      "off_s": float(params["off_s"])},
            "shape": {"profile": params["profile"]},
            "rate_jitter": [round(1.0 - params["jitter"], 4), round(1.0 + params["jitter"], 4)],
            "stagger_s": float(params["stagger_s"]),
            "spoof_sources": bool(params["spoof"]) and family == "syn_flood",
        },
    }
    if family == "slowloris":
        block["attack"]["slowloris"] = {"sockets": int(params.get("sockets", 40)),
                                        "keepalive_s": 6.0}
        block["attack"]["dst_ports"] = [80 if port not in (80, 443) else port]
    return block


def _evaluate(payload: dict[str, Any]) -> dict[str, Any]:
    """Worker: simulate one attack against one defence and score it."""
    import logging  # noqa: PLC0415

    import torch  # noqa: PLC0415

    torch.set_num_threads(1)
    logging.getLogger("netshield").setLevel(logging.WARNING)
    from ..detection.pipeline import build_controller_factory, load_detectors  # noqa: PLC0415
    from ..evaluation.operational import operational_metrics  # noqa: PLC0415
    from ..simulation.runner import run_simulation  # noqa: PLC0415
    from ..utils.config import experiment_config, load_experiments  # noqa: PLC0415

    params = payload["params"]
    cfg, meta = experiment_config("exp2_udp_flood", load_experiments())
    cfg = cfg.merged(attack_overrides(params), source="adversary")
    sets = ["simulation.engine=python", f"seed={int(payload['seed'])}",
            "simulation.max_wall_seconds=200"]
    detector_name = payload.get("detector")
    factory = None
    if detector_name:
        sets.append("mitigation.enabled=true")
        sets += list(payload.get("policy_overrides", []))
        cfg = cfg.with_set(sets)
        det = load_detectors(payload["models_dir"], [detector_name], required=True)[detector_name]
        if payload.get("conformal"):
            from ..models.calibration import ConformalDetector  # noqa: PLC0415

            det = ConformalDetector.load(Path(payload["models_dir"]) / payload["conformal"])
        factory = build_controller_factory(det, cfg, enable_mitigation=payload.get("mitigate",
                                                                                   True))
    else:
        cfg = cfg.with_set(sets)
    started = time.perf_counter()
    result = run_simulation(cfg, {**meta, "experiment": "adversary"},
                            controller_factory=factory)
    trigger = float(cfg.get("detection.mitigation_trigger_probability", 0.8))
    m = operational_metrics(result, trigger=trigger)
    base = m.get("baseline_clean_availability") or 1.0
    during = m.get("availability_during_attack")
    damage = max(0.0, 1.0 - (during if during is not None else base) / max(1e-9, base))
    windows = pd.DataFrame(result.windows)
    att = windows[(windows["t_start"] >= ATTACK_START_S)
                  & (windows["t_end"] <= ATTACK_START_S + ATTACK_DURATION_S)]
    volume_mbps = float(att["attack_offered"].sum()) if "attack_offered" in att else 0.0
    # attack_offered is a packet count; convert with the configured size.
    size = int(params["packet_bytes"]) if params["family"] not in ("syn_flood", "ack_flood") \
        else 64
    volume_mbps = volume_mbps * size * 8.0 / ATTACK_DURATION_S / 1e6
    det_rows = pd.DataFrame(result.detections)
    bots = {a["node_id"] for a in result.attackers}
    flagged = set()
    max_bot_score = 0.0
    if not det_rows.empty:
        bot_rows = det_rows[det_rows["node"].isin(bots)]
        flagged = set(bot_rows.loc[bot_rows["probability"] >= trigger, "node"])
        max_bot_score = float(bot_rows["probability"].max()) if len(bot_rows) else 0.0
    return {"params": params, "seed": payload["seed"], "detector": detector_name or "none",
            "damage": round(damage, 6), "availability": during, "baseline_availability": base,
            "bots": len(bots), "bots_flagged": len(flagged),
            "detected": bool(flagged), "max_bot_score": round(max_bot_score, 5),
            "time_to_detect_s": m.get("time_to_detect_s"),
            "wrongly_mitigated": m.get("wrongly_mitigated_nodes"),
            "attack_volume_mbps": round(volume_mbps, 4),
            "wall_s": round(time.perf_counter() - started, 2)}


def run_search(
    detector: str | None,
    models_dir: str,
    n_trials: int = 80,
    batch: int = 11,
    seed: int = 0,
    sampler: str = "tpe",
    conformal: str | None = None,
    policy_overrides: Sequence[str] = (),
    log_path: str | Path | None = None,
) -> pd.DataFrame:
    """Run an adaptive (or random) search for damaging attacks.

    Args:
        detector: Detector driving the defence, or ``None`` for no defence.
        models_dir: Directory holding ``<detector>/`` checkpoints.
        n_trials: Total simulated attacks.
        batch: Trials evaluated in parallel per round.
        seed: Sampler and simulation seed base.
        sampler: ``"tpe"`` (adaptive) or ``"random"`` (control).
        conformal: Optional conformal-wrapper directory name inside *models_dir*.
        policy_overrides: Extra policy settings (for the conformal ladder).
        log_path: Optional JSON-lines file appended with every trial.

    Returns:
        One row per trial.
    """
    import optuna  # noqa: PLC0415

    optuna.logging.set_verbosity(optuna.logging.WARNING)
    smp = (optuna.samplers.TPESampler(seed=seed, n_startup_trials=max(batch, 12),
                                      multivariate=True, constant_liar=True)
           if sampler == "tpe" else optuna.samplers.RandomSampler(seed=seed))
    study = optuna.create_study(direction="maximize", sampler=smp)
    rows: list[dict[str, Any]] = []
    started = time.perf_counter()
    with ProcessPoolExecutor(max_workers=batch) as pool:
        done = 0
        while done < n_trials:
            k = min(batch, n_trials - done)
            trials = [study.ask() for _ in range(k)]
            payloads = [{"params": suggest_attack(t), "seed": 5000 + seed * 1000 + done + i,
                         "detector": detector, "models_dir": models_dir,
                         "conformal": conformal, "policy_overrides": list(policy_overrides)}
                        for i, t in enumerate(trials)]
            for trial, res in zip(trials, pool.map(_evaluate, payloads)):
                study.tell(trial, res["damage"])
                res["trial"] = trial.number
                rows.append(res)
                if log_path:
                    with open(log_path, "a", encoding="utf-8") as fh:
                        fh.write(json.dumps(res, default=str) + "\n")
            done += k
            best = max(r["damage"] for r in rows)
            evaded = sum(1 for r in rows if r["damage"] >= 0.05 and not r["detected"])
            print(f"    {detector or 'none'} [{sampler}] {done:>3}/{n_trials} trials, "
                  f"best damage {best:.3f}, evasive {evaded}, "
                  f"{time.perf_counter() - started:.0f}s", flush=True)
    return pd.DataFrame(rows)


def frontier(trials: pd.DataFrame, bins: Sequence[float] | None = None) -> pd.DataFrame:
    """Best undetected damage per log-spaced attack-volume bin."""
    bins = list(bins or np.logspace(-3, 2, 11))
    t = trials.copy()
    t["bin"] = pd.cut(t["attack_volume_mbps"].clip(lower=bins[0] * 1.0001), bins)
    rows = []
    for interval, g in t.groupby("bin", observed=False):
        und = g[~g["detected"]]
        rows.append({"volume_lo": interval.left, "volume_hi": interval.right,
                     "trials": int(len(g)), "undetected": int(len(und)),
                     "best_undetected_damage": float(und["damage"].max()) if len(und) else 0.0,
                     "best_damage": float(g["damage"].max()) if len(g) else 0.0})
    return pd.DataFrame(rows)


def summarise_search(trials: pd.DataFrame, slo_damage: float = 0.05) -> dict[str, Any]:
    """Scalar adversarial-robustness metrics for one search."""
    evasive = trials[(trials["damage"] >= slo_damage) & (~trials["detected"])]
    fr = frontier(trials)
    centres = np.sqrt(fr["volume_lo"] * fr["volume_hi"])
    area = float(np.trapezoid(np.maximum.accumulate(fr["best_undetected_damage"].to_numpy()),
                              np.log10(centres))) if len(fr) > 1 else 0.0
    return {
        "trials": int(len(trials)),
        "evasion_success_rate": float(len(evasive) / max(1, len(trials))),
        "max_damage": float(trials["damage"].max()),
        "max_undetected_damage": float(trials.loc[~trials["detected"], "damage"].max())
        if (~trials["detected"]).any() else 0.0,
        "mean_damage": float(trials["damage"].mean()),
        "detected_fraction": float(trials["detected"].mean()),
        "min_undetected_volume_for_slo": float(evasive["attack_volume_mbps"].min())
        if len(evasive) else math.nan,
        "frontier_area": area,
        "evasive_families": evasive["params"].map(lambda p: p["family"]).value_counts().to_dict()
        if len(evasive) else {},
    }
