"""Calibration coverage and the downstream report sections (steps 2-4)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Sequence

import numpy as np
import pandas as pd

from .analysis import _fmt, _md_table


def conformal_coverage(out_dir: Path, design: str, variants: Sequence[str],
                       alphas: Sequence[float] = (0.05, 0.01, 0.001)) -> pd.DataFrame:
    """Fit temperature + split-conformal on each fold's validation rows and
    measure, on that fold's test rows, ECE before/after and the realised
    benign false-alarm rate at each nominal alpha."""
    from ..evaluation.statistics import binary_ece  # noqa: PLC0415
    from ..models.calibration import ConformalCalibrator, apply_temperature, fit_temperature

    rows = []
    for v in variants:
        for path in sorted(Path(out_dir).glob(f"{design}__*/{v}.npz")):
            data = np.load(path, allow_pickle=False)
            if "val_proba" not in data or "test_proba" not in data:
                continue
            pv, yv = data["val_proba"].astype(float), data["val_label"].astype(int)
            pt, yt = data["test_proba"].astype(float), data["test_label"].astype(int)
            if len(np.unique(yv)) < 2:
                continue
            t = fit_temperature(pv, yv)
            cal_v, cal_t = apply_temperature(pv, t), apply_temperature(pt, t)
            hv = cal_v[:, 1] + cal_v[:, 2]
            ht = cal_t[:, 1] + cal_t[:, 2]
            pvals = ConformalCalibrator().fit(hv[yv == 0]).p_values(ht)
            benign, hostile = yt == 0, yt > 0
            row = {"design": design, "fold": path.parent.name.split("__", 1)[1], "variant": v,
                   "temperature": t,
                   "ece_before": binary_ece(hostile.astype(int), pt[:, 1] + pt[:, 2]),
                   "ece_after": binary_ece(hostile.astype(int), ht)}
            for a in alphas:
                flag = pvals <= a
                row[f"fpr_at_{a:g}"] = float(flag[benign].mean()) if benign.any() else np.nan
                row[f"recall_at_{a:g}"] = float(flag[hostile].mean()) if hostile.any() else np.nan
            rows.append(row)
    return pd.DataFrame(rows)


def conformal_section(conf: pd.DataFrame, label) -> list[str]:
    if conf is None or conf.empty:
        return []
    agg = conf.groupby(["design", "variant"]).mean(numeric_only=True).reset_index()
    t = pd.DataFrame({
        "Design": agg["design"], "Detector": agg["variant"].map(label),
        "Temperature": agg["temperature"].map(lambda x: f"{x:.2f}"),
        "ECE before": agg["ece_before"].map(lambda x: f"{x:.4f}"),
        "ECE after": agg["ece_after"].map(lambda x: f"{x:.4f}"),
        "FPR @ 0.05": agg["fpr_at_0.05"].map(lambda x: f"{x:.4f}"),
        "FPR @ 0.01": agg["fpr_at_0.01"].map(lambda x: f"{x:.4f}"),
        "FPR @ 0.001": agg["fpr_at_0.001"].map(lambda x: f"{x:.4f}"),
        "Recall @ 0.01": agg["recall_at_0.01"].map(lambda x: f"{x:.3f}")})
    return ["## 6b. Calibration and conformal decisions", "",
            "Temperature scaling and the split-conformal benign test are fitted on each fold's "
            "validation runs and applied to its test runs. *FPR @ alpha* is the realised share of "
            "benign windows flagged. The conformal guarantee says it should not exceed alpha "
            "when test windows resemble calibration windows. Leave-one-topology-out breaks that "
            "assumption on purpose.", "", _md_table(t), ""]


def extra_sections(results_dir: Path, label) -> list[str]:
    """Closed-loop, adversary and real-traffic report sections."""
    lines: list[str] = []
    cl = results_dir / "closed_loop_summary.csv"
    if cl.exists():
        f = pd.read_csv(cl).sort_values("availability_attack", ascending=False)
        stress = f["stress_false_alarm_nodes"] if "stress_false_alarm_nodes" in f else \
            pd.Series([np.nan] * len(f), index=f.index)
        t = pd.DataFrame({
            "Defence": f["detector"].map(label),
            "Availability under attack": f["availability_attack"].map(lambda x: f"{x:.1%}"),
            "Detect (s)": f["ttd_median_s"].map(lambda x: _fmt(x, 1)),
            "Mitigate (s)": f["ttm_median_s"].map(lambda x: _fmt(x, 1)),
            "Recover (s)": f["ttr_median_s"].map(lambda x: _fmt(x, 1)),
            "Recovered runs": f.apply(lambda r: f"{int(r['recovered'])}/{int(r['runs'])}", axis=1),
            "Collateral": f["collateral_byte_ratio"].map(lambda x: f"{x:.2%}"),
            "Rule precision": f["mitigation_precision"].map(lambda x: _fmt(x, 3)),
            "Innocents ruled": f["wrongly_mitigated"].map(lambda x: _fmt(float(x), 0)),
            "Stress false-alarm devices / run": stress.map(lambda x: _fmt(x, 2)),
        })
        lines += ["## 7. Closed loop: each detector in charge of the gateway", "",
                  "Unseen seeds (offsets 10 and 11): seven attack scenarios on four topologies, "
                  "plus the three benign-stress scenarios. Times are medians from attack start. "
                  "Availability is the share of clean-device packets delivered within the 100 ms "
                  "SLO during the attack.", "", _md_table(t), ""]
    adv = results_dir / "adversary" / "adversary_summary.csv"
    if adv.exists():
        f = pd.read_csv(adv)
        t = pd.DataFrame({
            "Search": f["search"], "Attacks": f["trials"],
            "Evasion success": f["evasion_success_rate"].map(lambda x: f"{x:.1%}"),
            "Max damage": f["max_damage"].map(lambda x: f"{x:.1%}"),
            "Max undetected damage": f["max_undetected_damage"].map(lambda x: f"{x:.1%}"),
            "Stealth threshold (Mbit/s)": f["min_undetected_volume_for_slo"].map(
                lambda x: "never" if pd.isna(x) else f"{x:.2f}"),
            "Frontier area": f["frontier_area"].map(lambda x: f"{x:.3f}"),
            "Evasive families": f["evasive_families"]})
        lines += ["## 8. Adaptive adversary", "",
                  "Bayesian (TPE) search over attack family, rate, botnet size, packet size, "
                  "pulsing, rate profile, jitter, stagger, port and spoofing, against each "
                  "closed-loop defence. *Evasive* means the attack broke the SLO (damage >= 5%) "
                  "while no bot was ever flagged.", "", _md_table(t), ""]
        rs = results_dir / "adversary" / "hardening_rescore.csv"
        if rs.exists():
            r = pd.read_csv(rs)
            g = r.groupby("model").agg(detected=("detected", "mean"), damage=("damage", "mean"))
            lines += ["**Adversarial hardening.** The 12 most harmful attacks found against "
                      "GraphSAGE were re-run on fresh seeds against both models:", "",
                      _md_table(pd.DataFrame({
                          "Model": g.index,
                          "Attacks detected": g["detected"].map(lambda x: f"{x:.0%}"),
                          "Mean damage": g["damage"].map(lambda x: f"{x:.1%}")})), ""]
        cc = results_dir / "adversary" / "hardening_clean_cost.json"
        if cc.exists():
            c = json.loads(cc.read_text(encoding="utf-8"))
            lines += [f"Cost on clean validation runs: macro-F1 {c['base']['macro_f1']:.4f} "
                      f"before, {c['hardened']['macro_f1']:.4f} after; false-positive rate "
                      f"{c['base']['false_positive_rate']:.4f} before, "
                      f"{c['hardened']['false_positive_rate']:.4f} after.", ""]
    rd = results_dir / "real_data.csv"
    if rd.exists():
        f = pd.read_csv(rd)
        piv = f.pivot_table(index="detector", columns="capture", values="windows_with_flag",
                            aggfunc="first")
        benign_col = [c for c in piv.columns if "enign" in c]
        piv = piv[benign_col + [c for c in piv.columns if c not in benign_col]]
        piv = piv.apply(lambda col: col.map(lambda x: f"{x:.0%}"))
        piv.index = [label(i) for i in piv.index]
        lines += ["## 9. Real traffic: CICIoT2023 captures", "",
                  "Models trained only in simulation. The first 300 MB of each capture was "
                  "replayed through the simulator's telemetry and feature code. Labels exist "
                  "per file, not per host, so cells show the share of 5-second windows with at "
                  "least one flagged host. The benign column is a false-alarm rate; the attack "
                  "columns are detection rates.", "",
                  _md_table(piv.reset_index().rename(columns={"index": "Detector"})), ""]
    return lines
