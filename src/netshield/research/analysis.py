"""Turn protocol predictions into tables, significance tests, figures and a report.

Every number in the generated report is computed here from the saved
``.npz`` predictions, so the report can be regenerated at any time and an
examiner can trace each figure back to rows.
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import numpy as np
import pandas as pd

from ..evaluation.statistics import (
    cluster_bootstrap_ci,
    extended_metrics,
    fast_macro_f1,
    holm_correction,
    metric_fn,
    paired_bootstrap_diff,
    wilcoxon_signed_rank,
)
from .protocol import load_predictions, node_level_detection

#: Metrics given a run-level bootstrap CI in the headline table.
CI_METRICS: tuple[str, ...] = ("macro_f1", "mcc", "hostile_pr_auc", "tpr_at_fpr_0.01",
                               "false_positive_rate", "hostile_ece")

PRETTY: dict[str, str] = {
    "macro_f1": "Macro-F1", "mcc": "MCC", "hostile_pr_auc": "PR-AUC (hostile)",
    "tpr_at_fpr_0.01": "Recall @ 1% FPR", "tpr_at_fpr_0.001": "Recall @ 0.1% FPR",
    "false_positive_rate": "FPR", "hostile_ece": "ECE (hostile)", "attack_recall": "Attack recall",
    "brier": "Brier", "f1_suspicious": "F1 suspicious",
}


def _proba(frame: pd.DataFrame) -> np.ndarray:
    return frame[["p0", "p1", "p2"]].to_numpy(float)


def _fmt(v: Any, digits: int = 4) -> str:
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return "–"
    return f"{v:.{digits}f}"


def _ci(c: Mapping[str, float], digits: int = 4) -> str:
    return f"{_fmt(c['point'], digits)} [{_fmt(c['lo'], digits)}, {_fmt(c['hi'], digits)}]"


def _md_table(frame: pd.DataFrame) -> str:
    cols = list(frame.columns)
    lines = ["| " + " | ".join(str(c) for c in cols) + " |",
             "|" + "|".join("---" if i == 0 else "---:" for i in range(len(cols))) + "|"]
    for _, row in frame.iterrows():
        lines.append("| " + " | ".join(str(row[c]) for c in cols) + " |")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# designs
# --------------------------------------------------------------------------- #
def analyse_seed_cv(out_dir: Path, variants: Sequence[str], runs: pd.DataFrame,
                    reference: str = "graphsage", n_boot: int = 1000,
                    trigger: float = 0.8) -> dict[str, Any]:
    """Pooled out-of-fold metrics with CIs, paired tests and per-cell analysis."""
    preds = {v: load_predictions(out_dir, "seed_cv", v) for v in variants}
    preds = {v: p for v, p in preds.items() if p is not None}
    if not preds:
        return {}
    # Every variant scores the same test rows in the same order within each
    # fold, so align by position and verify the keys rather than merging
    # (node-window keys are not unique in every corpus).
    key = ["fold", "run_id", "window", "node_id"]
    ref_name = max(preds, key=lambda v: len(preds[v]))
    base = preds[ref_name][key + ["label", "kind", "is_attacker"]].reset_index(drop=True)
    aligned = {}
    for v, p in preds.items():
        p = p.reset_index(drop=True)
        if len(p) != len(base) or not (p[key].to_numpy() == base[key].to_numpy()).all():
            print(f"  skipping {v}: its folds do not cover the reference rows yet")
            continue
        aligned[v] = base.assign(p0=p["p0"], p1=p["p1"], p2=p["p2"])
    y = base["label"].to_numpy(int)
    groups = base["run_id"].to_numpy(str)

    headline, ci_table = [], {}
    for v, frame in aligned.items():
        proba = _proba(frame)
        point = extended_metrics(y, proba)
        cis = {m: cluster_bootstrap_ci(metric_fn(m, y, proba), groups, n_boot, seed=1)
               for m in CI_METRICS}
        ci_table[v] = cis
        headline.append({"variant": v, **point,
                         **{f"{m}_lo": cis[m]["lo"] for m in CI_METRICS},
                         **{f"{m}_hi": cis[m]["hi"] for m in CI_METRICS}})
    headline_df = pd.DataFrame(headline)

    # Paired run-level bootstrap: reference vs every other variant.
    comparisons, pvals = [], {}
    if reference in aligned:
        ref_p = _proba(aligned[reference])
        for v, frame in aligned.items():
            if v == reference:
                continue
            for m in ("macro_f1", "hostile_pr_auc"):
                d = paired_bootstrap_diff(metric_fn(m, y, ref_p), metric_fn(m, y, _proba(frame)),
                                          groups, n_boot, seed=2)
                tag = f"{reference} vs {v} [{m}]"
                pvals[tag] = d["p_value"]
                comparisons.append({"comparison": tag, "metric": m, "other": v, **d})
    holm = holm_correction(pvals)
    for row in comparisons:
        row.update({"p_holm": holm[row["comparison"]]["p_holm"],
                    "significant": holm[row["comparison"]]["reject"]})
    comparisons_df = pd.DataFrame(comparisons)

    # Per (scenario, topology) cell macro-F1 -> Wilcoxon across cells.
    cells = base.merge(runs[["run_id", "scenario", "topology_family"]], on="run_id")
    cell_rows = []
    for v, frame in aligned.items():
        pred = _proba(frame).argmax(1)
        for (sc, topo), idx in cells.groupby(["scenario", "topology_family"]).groups.items():
            idx = np.asarray(list(idx))
            cell_rows.append({"variant": v, "scenario": sc, "topology": topo,
                              "macro_f1": fast_macro_f1(y[idx], pred[idx])})
    cell_df = pd.DataFrame(cell_rows)
    wilcox, wp = [], {}
    if reference in aligned:
        piv = cell_df.pivot_table(index=["scenario", "topology"], columns="variant",
                                  values="macro_f1")
        for v in aligned:
            if v == reference:
                continue
            w = wilcoxon_signed_rank(piv[reference], piv[v])
            wp[v] = w["p_value"]
            wins = int((piv[reference] > piv[v] + 1e-9).sum())
            losses = int((piv[reference] < piv[v] - 1e-9).sum())
            wilcox.append({"other": v, **w, "cells_won": wins, "cells_lost": losses,
                           "cells_tied": int(len(piv) - wins - losses)})
        wh = holm_correction(wp)
        for row in wilcox:
            row["p_holm"] = wh[row["other"]]["p_holm"]
            row["significant"] = wh[row["other"]]["reject"]

    # Node-level detection per scenario.
    node_rows = []
    for v, frame in aligned.items():
        nl = node_level_detection(frame.assign(fold=frame["fold"]), trigger)
        nl = nl.merge(runs[["run_id", "scenario"]], on="run_id")
        agg = nl.groupby("scenario")[["bots", "bots_found", "false_alarm_nodes"]].sum()
        agg["runs"] = nl.groupby("scenario").size()
        agg["variant"] = v
        node_rows.append(agg.reset_index())
    node_df = pd.concat(node_rows, ignore_index=True) if node_rows else pd.DataFrame()
    return {"headline": headline_df, "ci": ci_table, "comparisons": comparisons_df,
            "cells": cell_df, "wilcoxon": pd.DataFrame(wilcox), "node_level": node_df,
            "n_rows": int(len(y)), "n_runs": int(len(np.unique(groups)))}


def analyse_holdout(out_dir: Path, design: str, variants: Sequence[str],
                    trigger: float = 0.8) -> pd.DataFrame:
    """Per-fold metrics for ``loto`` / ``loafo`` designs."""
    rows = []
    for v in variants:
        pred = load_predictions(out_dir, design, v)
        if pred is None:
            continue
        for fold, g in pred.groupby("fold"):
            m = extended_metrics(g["label"].to_numpy(int), _proba(g))
            nl = node_level_detection(g, trigger)
            rows.append({"design": design, "fold": fold, "variant": v,
                         "macro_f1": m["macro_f1"], "mcc": m["mcc"],
                         "hostile_pr_auc": m["hostile_pr_auc"],
                         "attack_recall": m["attack_recall"],
                         "false_positive_rate": m["false_positive_rate"],
                         "tpr_at_fpr_0.01": m["tpr_at_fpr_0.01"],
                         "bots": int(nl["bots"].sum()), "bots_found": int(nl["bots_found"].sum()),
                         "false_alarm_nodes": int(nl["false_alarm_nodes"].sum()),
                         "runs": int(len(nl))})
    return pd.DataFrame(rows)


def analyse_stress(out_dir: Path, variants: Sequence[str], runs: pd.DataFrame,
                   trigger: float = 0.8, window_s: float = 5.0) -> pd.DataFrame:
    """False alarms on benign-stress runs, averaged over the seed-CV models."""
    rows = []
    for v in variants:
        pred = load_predictions(out_dir, "seed_cv", v, split="stress")
        if pred is None:
            continue
        pred = pred.merge(runs[["run_id", "scenario"]], on="run_id")
        pred["hostile"] = pred["p1"] + pred["p2"]
        ep = pred[pred["kind"].isin(["iot", "attacker"])]
        for sc, g in ep.groupby("scenario"):
            flagged = g["hostile"] >= trigger
            node_hours = g.groupby(["fold", "run_id"])["node_id"].nunique().sum() * \
                (g.groupby(["fold", "run_id"])["window"].nunique().mean() * window_s / 3600.0)
            per_run = g[flagged].groupby(["fold", "run_id"])["node_id"].nunique()
            n_models_runs = g.groupby(["fold", "run_id"]).ngroups
            rows.append({"variant": v, "scenario": sc,
                         "window_fpr": float(flagged.mean()),
                         "false_alarm_nodes_per_run": float(per_run.sum() / n_models_runs),
                         "false_alarms_per_node_hour": float(flagged.sum() / node_hours)
                         if node_hours else float("nan"),
                         "runs_x_models": int(n_models_runs)})
    return pd.DataFrame(rows)


# --------------------------------------------------------------------------- #
# figures
# --------------------------------------------------------------------------- #
def make_figures(results: Mapping[str, Any], fig_dir: Path) -> list[Path]:
    """Forest plot, LOTO heatmap, LOAFO bars and reliability diagram."""
    import matplotlib  # noqa: PLC0415

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt  # noqa: PLC0415

    from ..evaluation.figures import DETECTOR_COLOURS, DETECTOR_LABELS  # noqa: PLC0415

    fig_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    seed = results.get("seed_cv") or {}

    if seed:
        head = seed["headline"].sort_values("macro_f1")
        fig, axes = plt.subplots(1, 3, figsize=(13, 0.45 * len(head) + 1.6), sharey=True)
        for ax, metric in zip(axes, ("macro_f1", "hostile_pr_auc", "tpr_at_fpr_0.01")):
            for i, (_, r) in enumerate(head.iterrows()):
                c = DETECTOR_COLOURS.get(r["variant"], "#555555")
                ax.errorbar(r[metric], i, xerr=[[r[metric] - r[f"{metric}_lo"]],
                                                 [r[f"{metric}_hi"] - r[metric]]],
                            fmt="o", color=c, capsize=3)
            ax.set_title(PRETTY.get(metric, metric))
            ax.grid(axis="x", alpha=0.3)
        axes[0].set_yticks(range(len(head)))
        axes[0].set_yticklabels([DETECTOR_LABELS.get(v, v) for v in head["variant"]])
        fig.suptitle("Leave-one-seed-out CV: point estimate and 95% run-level bootstrap CI")
        fig.tight_layout()
        path = fig_dir / "research_forest.png"
        fig.savefig(path, dpi=140)
        plt.close(fig)
        written.append(path)

    for design, title, fname in (("loto", "Leave-one-topology-out macro-F1", "research_loto.png"),
                                 ("loafo", "Leave-one-attack-family-out: hostile PR-AUC",
                                  "research_loafo.png")):
        frame = results.get(design)
        if frame is None or frame.empty:
            continue
        metric = "macro_f1" if design == "loto" else "hostile_pr_auc"
        piv = frame.pivot_table(index="variant", columns="fold", values=metric)
        fig, ax = plt.subplots(figsize=(1.3 * piv.shape[1] + 3, 0.5 * piv.shape[0] + 1.5))
        im = ax.imshow(piv.to_numpy(), cmap="viridis", vmin=np.nanmin(piv.to_numpy()), vmax=1.0)
        ax.set_xticks(range(piv.shape[1]))
        ax.set_xticklabels(piv.columns, rotation=30, ha="right")
        ax.set_yticks(range(piv.shape[0]))
        ax.set_yticklabels([DETECTOR_LABELS.get(v, v) for v in piv.index])
        for i in range(piv.shape[0]):
            for j in range(piv.shape[1]):
                val = piv.to_numpy()[i, j]
                if not np.isnan(val):
                    ax.text(j, i, f"{val:.2f}", ha="center", va="center",
                            color="white" if val < 0.75 else "black", fontsize=8)
        fig.colorbar(im, ax=ax, shrink=0.8)
        ax.set_title(title)
        fig.tight_layout()
        path = fig_dir / fname
        fig.savefig(path, dpi=140)
        plt.close(fig)
        written.append(path)

    rel = results.get("reliability")
    if rel:
        fig, ax = plt.subplots(figsize=(5.2, 5))
        ax.plot([0, 1], [0, 1], "--", color="#999999", lw=1)
        for v, (conf, acc) in rel.items():
            ax.plot(conf, acc, "o-", color=DETECTOR_COLOURS.get(v, "#555"), ms=4,
                    label=DETECTOR_LABELS.get(v, v))
        ax.set_xlabel("Predicted P(hostile)")
        ax.set_ylabel("Observed hostile fraction")
        ax.set_title("Reliability of the hostile score")
        ax.legend(fontsize=8)
        fig.tight_layout()
        path = fig_dir / "research_reliability.png"
        fig.savefig(path, dpi=140)
        plt.close(fig)
        written.append(path)
    return written


def reliability_curves(out_dir: Path, variants: Iterable[str], bins: int = 10
                       ) -> dict[str, tuple[list[float], list[float]]]:
    """Binned (confidence, observed frequency) of the hostile score, seed CV."""
    out = {}
    for v in variants:
        pred = load_predictions(out_dir, "seed_cv", v)
        if pred is None:
            continue
        score = (pred["p1"] + pred["p2"]).to_numpy()
        y = (pred["label"] > 0).to_numpy(float)
        edges = np.linspace(0, 1, bins + 1)
        idx = np.clip(np.digitize(score, edges) - 1, 0, bins - 1)
        conf, acc = [], []
        for b in range(bins):
            m = idx == b
            if m.sum() >= 20:
                conf.append(float(score[m].mean()))
                acc.append(float(y[m].mean()))
        out[v] = (conf, acc)
    return out


# --------------------------------------------------------------------------- #
# report
# --------------------------------------------------------------------------- #
def write_report(results: Mapping[str, Any], path: Path, meta: Mapping[str, Any]) -> Path:
    """Write the Markdown research report."""
    from ..evaluation.figures import DETECTOR_LABELS  # noqa: PLC0415

    def label(v: str) -> str:
        return DETECTOR_LABELS.get(v, v)

    lines = ["# NetShield-GNN research protocol results", "",
             "Auto-generated by `scripts/research_protocol.py analyse`. Every number is "
             "recomputed from the saved out-of-fold predictions under "
             f"`{meta.get('out_dir')}`.", ""]
    lines += ["## Corpus", "", f"- Runs: {meta.get('n_runs')} "
              f"({meta.get('n_core_runs')} attack/benign, {meta.get('n_stress_runs')} benign-stress)",
              f"- Node-window rows: {meta.get('n_rows'):,}",
              f"- Topologies: {', '.join(meta.get('topologies', []))}",
              f"- Scenarios: {', '.join(meta.get('scenarios', []))}",
              f"- Seeds per cell: {meta.get('seeds')}", ""]

    seed = results.get("seed_cv") or {}
    if seed:
        lines += ["## 1. Leave-one-seed-out cross-validation", "",
                  f"Pooled out-of-fold predictions over {seed['n_runs']} runs and "
                  f"{seed['n_rows']:,} node-windows. Brackets are 95% confidence intervals "
                  "from a cluster bootstrap that resamples whole runs.", ""]
        head = seed["headline"].sort_values("macro_f1", ascending=False)
        rows = []
        for _, r in head.iterrows():
            cis = seed["ci"][r["variant"]]
            rows.append({"Detector": label(r["variant"]),
                         "Macro-F1": _ci(cis["macro_f1"]), "MCC": _ci(cis["mcc"]),
                         "PR-AUC (hostile)": _ci(cis["hostile_pr_auc"]),
                         "Recall @ 1% FPR": _ci(cis["tpr_at_fpr_0.01"]),
                         "FPR": _ci(cis["false_positive_rate"]),
                         "ECE": _ci(cis["hostile_ece"]),
                         "F1 suspicious": _fmt(r["f1_suspicious"])})
        lines += [_md_table(pd.DataFrame(rows)), ""]
        comp = seed["comparisons"]
        if not comp.empty:
            lines += ["### Paired comparisons against GraphSAGE", "",
                      "Difference = GraphSAGE minus the other detector, on the same "
                      "resampled runs. p-values are Holm-corrected across every "
                      "comparison in this table.", ""]
            show = comp.assign(**{
                "Comparison": comp["other"].map(label),
                "Metric": comp["metric"].map(lambda m: PRETTY.get(m, m)),
                "Difference [95% CI]": comp.apply(lambda r: f"{r['diff']:+.4f} "
                                                  f"[{r['lo']:+.4f}, {r['hi']:+.4f}]", axis=1),
                "p (Holm)": comp["p_holm"].map(lambda p: f"{p:.4f}"),
                "Significant": comp["significant"].map({True: "yes", False: "no"})})
            lines += [_md_table(show[["Comparison", "Metric", "Difference [95% CI]",
                                      "p (Holm)", "Significant"]]), ""]
        wil = seed["wilcoxon"]
        if not wil.empty:
            lines += ["### Across scenario-topology cells", "",
                      "Wilcoxon signed-rank test on per-cell macro-F1, GraphSAGE against "
                      "each detector, Holm-corrected.", ""]
            show = wil.assign(Other=wil["other"].map(label),
                              **{"Won/Tied/Lost": wil.apply(
                                  lambda r: f"{r['cells_won']}/{r['cells_tied']}/{r['cells_lost']}",
                                  axis=1),
                                 "Median diff": wil["median_diff"].map(lambda x: f"{x:+.4f}"),
                                 "p (Holm)": wil["p_holm"].map(lambda p: f"{p:.4f}")})
            lines += [_md_table(show[["Other", "Won/Tied/Lost", "Median diff", "p (Holm)"]]), ""]
        nl = seed["node_level"]
        if not nl.empty:
            lines += ["### Bots found and innocent devices flagged, per scenario", "",
                      "Summed over all runs of each scenario (every topology and seed). "
                      "Each cell reads `bots found / bots`, then innocent endpoints flagged "
                      "in brackets.", ""]
            nl = nl.assign(cell=nl.apply(lambda r: f"{int(r['bots_found'])}/{int(r['bots'])} "
                                         f"({int(r['false_alarm_nodes'])})", axis=1))
            piv = nl.pivot_table(index="scenario", columns="variant", values="cell",
                                 aggfunc="first")
            piv = piv[[c for c in head["variant"] if c in piv.columns]]
            piv.columns = [label(c) for c in piv.columns]
            lines += [_md_table(piv.reset_index().rename(columns={"scenario": "Scenario"})), ""]

    for design, title, metric_cols in (
            ("loto", "## 2. Leave-one-topology-out", ["macro_f1", "attack_recall",
                                                      "false_positive_rate"]),
            ("loafo", "## 3. Leave-one-attack-family-out", ["hostile_pr_auc", "attack_recall",
                                                            "false_positive_rate"])):
        frame = results.get(design)
        if frame is None or frame.empty:
            continue
        lines += [title, ""]
        if design == "loto":
            lines += ["Each column is a topology family the models never saw in training. "
                      "Cells are macro-F1.", ""]
        else:
            lines += ["Each column is an attack family the models never saw in training. "
                      "Cells are PR-AUC of the hostile score, then bots found in brackets.", ""]
        val = "macro_f1" if design == "loto" else "hostile_pr_auc"
        cell = frame.assign(cell=frame.apply(
            lambda r: f"{r[val]:.3f}" + ("" if design == "loto"
                                         else f" ({r['bots_found']}/{r['bots']})"), axis=1))
        piv = cell.pivot_table(index="variant", columns="fold", values="cell", aggfunc="first")
        means = frame.groupby("variant")[metric_cols].mean()
        piv["Mean " + PRETTY.get(val, val)] = means[val].map(lambda x: f"{x:.3f}")
        piv["Mean FPR"] = means["false_positive_rate"].map(lambda x: f"{x:.4f}")
        piv = piv.loc[means[val].sort_values(ascending=False).index]
        piv.index = [label(v) for v in piv.index]
        lines += [_md_table(piv.reset_index().rename(columns={"index": "Detector"})), ""]

    stress = results.get("stress")
    if stress is not None and not stress.empty:
        lines += ["## 4. Benign stress: false alarms with no attack present", "",
                  "Every flag on these runs is a false alarm. Values average all four "
                  "seed-CV models over every stress run. Lower is better.", ""]
        stress = stress.assign(cell=stress.apply(
            lambda r: f"{r['false_alarm_nodes_per_run']:.1f} / {r['window_fpr']:.4f}", axis=1))
        piv = stress.pivot_table(index="variant", columns="scenario", values="cell",
                                 aggfunc="first")
        order = stress.groupby("variant")["window_fpr"].mean().sort_values().index
        piv = piv.loc[order]
        piv.index = [label(v) for v in piv.index]
        lines += ["Cells read: innocent devices flagged per run / window-level FPR.", "",
                  _md_table(piv.reset_index().rename(columns={"index": "Detector"})), ""]

    abl = results.get("ablation")
    if abl is not None and not abl.empty:
        lines += ["## 5. GraphSAGE ablations", "",
                  "Same leave-one-seed-out folds. Difference is relative to the full model.", "",
                  _md_table(abl), ""]

    timing = results.get("timing")
    if timing is not None and not timing.empty:
        lines += ["## 6. Training and inference cost", "", _md_table(timing), ""]

    from .report_extras import conformal_section, extra_sections  # noqa: PLC0415

    lines += conformal_section(results.get("conformal"), label)
    lines += extra_sections(Path("results/research"), label)

    figs = results.get("figures", [])
    if figs:
        lines += ["## Figures", ""] + [f"![{Path(f).stem}](../figures/{Path(f).name})"
                                       for f in figs] + [""]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    return path
