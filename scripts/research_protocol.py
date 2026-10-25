#!/usr/bin/env python3
"""Run and analyse the research evaluation protocol.

    python scripts/research_protocol.py run --designs seed_cv loto loafo
    python scripts/research_protocol.py run --designs seed_cv --ablations
    python scripts/research_protocol.py analyse

``run`` trains every detector on every fold of the requested designs and saves
out-of-fold probabilities under ``results/research/predictions``. It is
resumable: finished (fold, detector) jobs are skipped.

``analyse`` computes the run-level bootstrap CIs, Holm-corrected paired tests,
per-cell Wilcoxon tests, hold-out tables, benign-stress false alarms and
ablations, renders the figures and writes ``results/reports/RESEARCH_RESULTS.md``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from _bootstrap import banner, common_parser, ok, setup  # noqa: E402

DEFAULT_VARIANTS = ["threshold", "autoencoder", "random_forest", "lightgbm", "gru_seq",
                    "gat", "egraphsage", "graphsage"]


def ablation_variants():
    from netshield.research.protocol import FEATURE_GROUPS, Variant  # noqa: PLC0415

    out = [Variant("graphsage", "abl_no_edges", graph_options={"edge_types": []}),
           Variant("graphsage", "abl_physical_only", graph_options={"edge_types": ["physical"]}),
           Variant("graphsage", "abl_comm_only", graph_options={"edge_types": ["communication"]}),
           Variant("graphsage", "abl_one_layer", hyper={"num_layers": 1})]
    for group, cols in FEATURE_GROUPS.items():
        out.append(Variant("graphsage", f"abl_drop_{group}", drop_features=list(cols)))
    return out


def cmd_run(args, config) -> int:
    from netshield.research.protocol import (  # noqa: PLC0415
        Variant,
        load_research_corpus,
        loafo_folds,
        loto_folds,
        run_protocol,
        seed_cv_folds,
    )

    _, _, runs = load_research_corpus(args.corpus)
    builders = {"seed_cv": seed_cv_folds, "loto": loto_folds, "loafo": loafo_folds}
    overrides = list(args.overrides or [])
    for design in args.designs:
        folds = builders[design](runs)
        names = args.variants or DEFAULT_VARIANTS
        if design != "seed_cv" and args.holdout_variants:
            names = args.holdout_variants
        variants = [Variant(v) for v in names]
        if args.only_ablations and design == "seed_cv":
            variants = []
        banner(f"{design}: {len(folds)} folds x {len(variants)} variants")
        for f in folds:
            print(f"  fold {f.name:<14} train {len(f.train):>3} val {len(f.val):>3} "
                  f"test {len(f.test):>3} stress {len(f.stress):>3} runs", flush=True)
        if variants:
            run_protocol(args.corpus, folds, variants, args.out, workers=args.workers,
                         threads_per_worker=args.threads, config_overrides=overrides,
                         save_models=args.save_models)
        if args.ablations and design == "seed_cv":
            abl_folds = folds[: args.ablation_folds] if args.ablation_folds else folds
            banner(f"ablations: {len(abl_folds)} folds x {len(ablation_variants())} variants")
            run_protocol(args.corpus, abl_folds, ablation_variants(), args.out,
                         workers=args.workers, threads_per_worker=args.threads,
                         config_overrides=overrides)
    return 0


def cmd_analyse(args, config) -> int:
    import pandas as pd  # noqa: PLC0415

    from netshield.research.analysis import (  # noqa: PLC0415
        analyse_holdout,
        analyse_seed_cv,
        analyse_stress,
        make_figures,
        reliability_curves,
        write_report,
    )
    from netshield.research.protocol import load_predictions, load_research_corpus  # noqa: PLC0415
    from netshield.evaluation.statistics import extended_metrics  # noqa: PLC0415

    corpus, _, runs = load_research_corpus(args.corpus)
    out = Path(args.out)
    variants = args.variants or DEFAULT_VARIANTS
    trigger = float(config.get("detection.mitigation_trigger_probability", 0.8))
    results = {}
    banner("Analysing seed CV")
    results["seed_cv"] = analyse_seed_cv(out, variants, runs, n_boot=args.boot, trigger=trigger)
    banner("Analysing hold-out designs and stress")
    results["loto"] = analyse_holdout(out, "loto", variants, trigger)
    results["loafo"] = analyse_holdout(out, "loafo", variants, trigger)
    results["stress"] = analyse_stress(out, variants, runs, trigger,
                                       float(config.get("features.window_s", 5.0)))
    from netshield.research.report_extras import conformal_coverage  # noqa: PLC0415

    cal_variants = [v for v in ("random_forest", "lightgbm", "graphsage", "temporal_gnn",
                                "egraphsage") if v in variants]
    results["conformal"] = pd.concat([conformal_coverage(out, d, cal_variants)
                                      for d in ("seed_cv", "loto")], ignore_index=True)
    results["reliability"] = reliability_curves(out, [v for v in ("graphsage", "lightgbm",
                                                                 "random_forest", "gat")
                                                      if v in variants])

    # Ablations relative to the full GraphSAGE.
    abl_rows = []
    full = load_predictions(out, "seed_cv", "graphsage")
    if full is not None:
        base = extended_metrics(full["label"].to_numpy(int), full[["p0", "p1", "p2"]].to_numpy())
        for path in sorted({p.stem for p in out.glob("seed_cv__*/abl_*.npz")}):
            pred = load_predictions(out, "seed_cv", path)
            m = extended_metrics(pred["label"].to_numpy(int), pred[["p0", "p1", "p2"]].to_numpy())
            slow = pred.merge(runs[["run_id", "scenario"]], on="run_id")
            slow = slow[slow["scenario"] == "exp17_slowloris"]
            slow_m = (extended_metrics(slow["label"].to_numpy(int),
                                       slow[["p0", "p1", "p2"]].to_numpy())
                      if len(slow) else {"macro_f1": float("nan")})
            abl_rows.append({"Variant": path.replace("abl_", ""),
                             "Macro-F1": f"{m['macro_f1']:.4f}",
                             "Δ Macro-F1": f"{m['macro_f1'] - base['macro_f1']:+.4f}",
                             "PR-AUC": f"{m['hostile_pr_auc']:.4f}",
                             "Δ PR-AUC": f"{m['hostile_pr_auc'] - base['hostile_pr_auc']:+.4f}",
                             "Slowloris macro-F1": f"{slow_m['macro_f1']:.4f}"})
        if abl_rows:
            slow = full.merge(runs[["run_id", "scenario"]], on="run_id")
            slow = slow[slow["scenario"] == "exp17_slowloris"]
            sm = extended_metrics(slow["label"].to_numpy(int), slow[["p0", "p1", "p2"]].to_numpy())
            abl_rows.insert(0, {"Variant": "full model", "Macro-F1": f"{base['macro_f1']:.4f}",
                                "Δ Macro-F1": "–", "PR-AUC": f"{base['hostile_pr_auc']:.4f}",
                                "Δ PR-AUC": "–", "Slowloris macro-F1": f"{sm['macro_f1']:.4f}"})
    results["ablation"] = pd.DataFrame(abl_rows)

    metas = [json.loads(p.read_text(encoding="utf-8"))
             for p in out.glob("seed_cv__*/*.json")]
    if metas:
        jm = pd.DataFrame(metas)
        jm = jm[jm["variant"].isin(variants)]
        t = jm.groupby("variant").agg(fit_s=("fit_s", "mean"),
                                      infer=("test_infer_us_per_row", "mean"),
                                      rows=("n_train_rows", "mean")).reset_index()
        t = t.sort_values("fit_s")
        from netshield.evaluation.figures import DETECTOR_LABELS  # noqa: PLC0415
        results["timing"] = pd.DataFrame({
            "Detector": t["variant"].map(lambda v: DETECTOR_LABELS.get(v, v)),
            "Mean fit time (s)": t["fit_s"].map(lambda x: f"{x:.1f}"),
            "Inference (µs per node-window)": t["infer"].map(lambda x: f"{x:.1f}"),
            "Training rows": t["rows"].map(lambda x: f"{x:,.0f}")})

    results["figures"] = [str(p) for p in make_figures(results, Path("results/figures"))]

    # Persist machine-readable tables.
    tables = Path("results/research")
    tables.mkdir(parents=True, exist_ok=True)
    seed = results["seed_cv"]
    if seed:
        seed["headline"].to_csv(tables / "seed_cv_headline.csv", index=False)
        seed["comparisons"].to_csv(tables / "seed_cv_comparisons.csv", index=False)
        seed["cells"].to_csv(tables / "seed_cv_cells.csv", index=False)
        seed["wilcoxon"].to_csv(tables / "seed_cv_wilcoxon.csv", index=False)
        seed["node_level"].to_csv(tables / "seed_cv_node_level.csv", index=False)
    for name in ("loto", "loafo", "stress", "ablation", "conformal"):
        frame = results.get(name)
        if frame is not None and not frame.empty:
            frame.to_csv(tables / f"{name}.csv", index=False)

    meta = {"out_dir": str(out).replace("\\", "/"), "n_runs": int(runs["run_id"].nunique()),
            "n_core_runs": int((runs["family"] != "benign_stress").sum()),
            "n_stress_runs": int((runs["family"] == "benign_stress").sum()),
            "n_rows": int(len(corpus)),
            "topologies": sorted(runs["topology_family"].unique()),
            "scenarios": sorted(runs["scenario"].unique()),
            "seeds": int(runs["seed_offset"].nunique())}
    path = write_report(results, Path("results/reports/RESEARCH_RESULTS.md"), meta)
    ok(f"report -> {path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = common_parser("Research evaluation protocol.")
    parser.add_argument("command", choices=["run", "analyse"])
    parser.add_argument("--corpus", default="data/research")
    parser.add_argument("--out", default="results/research/predictions")
    parser.add_argument("--designs", nargs="*", default=["seed_cv", "loto", "loafo"])
    parser.add_argument("--variants", nargs="*", default=None)
    parser.add_argument("--ablations", action="store_true")
    parser.add_argument("--only-ablations", action="store_true")
    parser.add_argument("--ablation-folds", type=int, default=0,
                        help="Run ablations on only the first N seed-CV folds (0 = all).")
    parser.add_argument("--holdout-variants", nargs="*", default=None,
                        help="Detectors for the loto/loafo designs (default: same as --variants).")
    parser.add_argument("--workers", type=int, default=5)
    parser.add_argument("--threads", type=int, default=2)
    parser.add_argument("--boot", type=int, default=1000)
    parser.add_argument("--save-models", action="store_true")
    args = parser.parse_args(argv)
    config = setup(args, "research_protocol")
    return cmd_run(args, config) if args.command == "run" else cmd_analyse(args, config)


if __name__ == "__main__":
    sys.exit(main())
