#!/usr/bin/env python3
"""Evaluate the trained detectors and generate every result artefact.

Produces
--------
``results/metrics/*.json``   full metric bundles, per-experiment breakdowns,
                             detection-latency reports
``results/figures/*.png``    confusion matrices, ROC/PR curves, detector
                             comparison, per-scenario F1, feature importance,
                             GNN training curves, a window-graph visualisation
``results/reports/RESULTS.md`` the auto-generated results document

The split is recreated with the same seed used during training, so the test rows
scored here are exactly the rows the models never saw.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from _bootstrap import banner, common_parser, ok, setup, warn  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    """Run the evaluation and write every artefact.

    Args:
        argv: Command-line arguments.

    Returns:
        Process exit status.
    """
    parser = common_parser("Evaluate the trained detectors and build the report.")
    parser.add_argument("--dataset", default="data/processed/dataset.csv")
    parser.add_argument("--edges", default="data/processed/edges.csv")
    parser.add_argument("--models-dir", default="models")
    parser.add_argument("--figures-dir", default="results/figures")
    parser.add_argument("--metrics-dir", default="results/metrics")
    parser.add_argument("--reports-dir", default="results/reports")
    parser.add_argument("--no-figures", action="store_true",
                        help="Compute metrics without rendering figures.")
    args = parser.parse_args(argv)

    config = setup(args, "evaluate")

    import pandas as pd  # noqa: PLC0415

    from netshield.database.store import NetShieldDB  # noqa: PLC0415
    from netshield.detection.pipeline import PipelineError, load_detectors  # noqa: PLC0415
    from netshield.evaluation import figures as fig  # noqa: PLC0415
    from netshield.evaluation import reports as rep  # noqa: PLC0415
    from netshield.evaluation.metrics import (  # noqa: PLC0415
        compute_metrics,
        detection_latency,
        per_experiment_metrics,
        subset_metrics,
    )
    from netshield.features.dataset import (  # noqa: PLC0415
        DatasetError,
        dataset_report,
        load_dataset,
        split_by_run,
    )
    from netshield.features.node_features import CLASS_NAMES  # noqa: PLC0415
    from netshield.models.base import DetectionInput  # noqa: PLC0415
    from netshield.models.graphsage import BACKEND, GraphSAGEDetector  # noqa: PLC0415
    from netshield.simulation.ns3_bridge import detect_ns3, engine_label  # noqa: PLC0415
    from netshield.utils.paths import ensure_dir, resolve  # noqa: PLC0415

    banner("NetShield-GNN :: evaluation")

    try:
        corpus = load_dataset(args.dataset)
        edges = pd.read_csv(resolve(args.edges))
    except (FileNotFoundError, DatasetError) as exc:
        print(f"\n  {exc}\n")
        return 1

    try:
        detectors = load_detectors(args.models_dir)
    except PipelineError as exc:
        print(f"\n  {exc}\n")
        return 1

    split = split_by_run(
        corpus,
        test_size=float(config.get("evaluation.test_size", 0.25)),
        val_size=float(config.get("evaluation.val_size", 0.15)),
        seed=int(config.get("seed", 42)),
    )
    test_in = DetectionInput(split.test, edges)
    y_true = test_in.labels
    trigger = float(config.get("detection.mitigation_trigger_probability", 0.80))
    window_s = float(config.get("features.window_s", 5.0))

    figures_dir = ensure_dir(args.figures_dir)
    metrics_dir = ensure_dir(args.metrics_dir)
    reports_dir = ensure_dir(args.reports_dir)

    bundles: list[Any] = []
    endpoint_bundles: list[Any] = []
    latency: dict[str, Any] = {}
    per_experiment: list[dict[str, Any]] = []
    predictions: dict[str, Any] = {}

    endpoint_mask = split.test["is_endpoint"].to_numpy(dtype=float) > 0.5

    for name, detector in detectors.items():
        banner(f"scoring: {name}")
        proba = detector.predict_proba(test_in)
        pred = proba.argmax(axis=1)
        scores = proba[:, 1] + proba[:, 2]
        predictions[name] = {"pred": pred, "scores": scores}

        bundle = compute_metrics(y_true, pred, scores, detector=name, split="test")
        bundles.append(bundle)
        head = bundle.headline()
        print(f"  accuracy={head['accuracy']}  macro-F1={head['macro_f1']}  "
              f"attack recall={head['attack_recall']}  FPR={head['fpr']}")

        endpoint = subset_metrics(split.test, pred, scores, endpoint_mask,
                                  detector=name, split="test-endpoints")
        if endpoint is not None:
            endpoint_bundles.append(endpoint)

        latency[name] = detection_latency(split.test, scores, trigger=trigger,
                                          window_s=window_s)
        lat = latency[name]
        print(f"  detection latency: mean={lat['mean_latency_s']}s over "
              f"{lat['n_detected']}/{lat['n_runs_with_attack']} attacked runs")

        per_experiment.extend(
            per_experiment_metrics(split.test, pred, scores, detector=name)
        )

        rep.write_json(bundle.to_dict(), metrics_dir / f"metrics_{name}.json")
        rep.write_json(lat, metrics_dir / f"latency_{name}.json")

    comparison = pd.DataFrame([b.headline() for b in bundles]).sort_values(
        "macro_f1", ascending=False
    )
    rep.write_csv(comparison, metrics_dir / "detector_comparison.csv")
    rep.write_csv(pd.DataFrame(per_experiment),
                  metrics_dir / "per_experiment_metrics.csv")
    banner("Detector comparison (test split)")
    print(comparison.to_string(index=False))

    training_reports: dict[str, Any] = {}
    training_path = resolve(args.models_dir) / "training_reports.json"
    if training_path.exists():
        training_reports = json.loads(training_path.read_text(encoding="utf-8"))

    produced: list[Any] = []
    if not args.no_figures:
        banner("Rendering figures")
        note = (
            f"NetShield-GNN | engine: {corpus['engine'].iloc[0] if 'engine' in corpus else 'n/a'}"
            f" | {len(split.test):,} test node-windows"
        )
        try:
            produced.append(fig.plot_confusion_matrices(
                bundles, figures_dir / "confusion_matrix.png", note))
            produced.append(fig.plot_roc_curves(
                bundles, figures_dir / "roc_curve.png", note))
            produced.append(fig.plot_pr_curves(
                bundles, figures_dir / "precision_recall_curve.png", note))
            produced.append(fig.plot_detector_comparison(
                bundles, figures_dir / "detector_comparison.png", note))
            produced.append(fig.plot_per_experiment_f1(
                per_experiment, figures_dir / "per_experiment_f1.png", note))
            produced.append(fig.plot_detection_metrics_summary(
                bundles, latency, figures_dir / "detection_metrics.png", note))
        except Exception as exc:  # noqa: BLE001 - a figure must not abort evaluation
            warn(f"figure generation failed: {type(exc).__name__}: {exc}")

        rf_report = training_reports.get("random_forest", {})
        importances = (rf_report.get("extra", {}) or {}).get("feature_importances", {})
        if importances:
            produced.append(fig.plot_feature_importance(
                importances, figures_dir / "feature_importance.png", note=note))

        sage_report = training_reports.get("graphsage", {})
        history = sage_report.get("history") or {}
        if history:
            produced.append(fig.plot_training_history(
                history, figures_dir / "training_history.png", note=note))

        sage = detectors.get("graphsage")
        if isinstance(sage, GraphSAGEDetector):
            try:
                graphs = sage._build(test_in)  # noqa: SLF001 - internal by design
                attacked = [g for g in graphs if int((g.y > 0).sum()) > 0]
                chosen = attacked[len(attacked) // 2] if attacked else (
                    graphs[len(graphs) // 2] if graphs else None
                )
                if chosen is not None:
                    produced.append(fig.plot_window_graph(
                        chosen, figures_dir / "graph_visualization.png", note))
            except Exception as exc:  # noqa: BLE001
                warn(f"graph visualisation failed: {type(exc).__name__}: {exc}")

    probe = detect_ns3()
    # The engine label must describe what actually PRODUCED this corpus, not
    # what happens to be installed on the machine running the evaluation.
    # Deriving it from probe.available was a provenance bug: with NS-3 present
    # but unused, a report over Python-engine data claimed "NS-3 simulation".
    # dataset.csv carries an `engine` column per row, so the corpus states its
    # own provenance and a mixed corpus is reported as mixed rather than hidden.
    engines = sorted(
        {str(e) for e in corpus.get("engine", pd.Series(dtype=str)).dropna().unique()}
    ) if "engine" in corpus.columns else []
    if len(engines) == 1:
        engine_label_text = engine_label(engines[0])
    elif engines:
        engine_label_text = "MIXED: " + ", ".join(engine_label(e) for e in engines)
    else:
        engine_label_text = "unknown (corpus records no engine column)"

    environment = {
        "engine_label": engine_label_text,
        "ns3_available": probe.available,
        "gnn_backend": BACKEND,
        "python": sys.version.split()[0],
    }

    report_path = rep.write_results_report(
        reports_dir / "RESULTS.md",
        bundles=bundles,
        latency=latency,
        per_experiment=per_experiment,
        dataset_report=dataset_report(corpus),
        split_summary=split.summary(),
        training_reports={k: v for k, v in training_reports.items()},
        environment=environment,
        classes=list(CLASS_NAMES),
        figures=rep.collect_figure_names(figures_dir),
        endpoint_bundles=endpoint_bundles,
    )
    ok(f"results report -> {report_path}")

    try:
        db = NetShieldDB(config.path("database"))
        for bundle in bundles:
            db.store_evaluation(bundle.detector, "test", bundle.to_dict())
        for bundle in endpoint_bundles:
            db.store_evaluation(bundle.detector, "test-endpoints", bundle.to_dict())
        ok(f"evaluations persisted -> {db.path}")
    except Exception as exc:  # noqa: BLE001 - the DB is a convenience, not a gate
        warn(f"could not persist evaluations: {type(exc).__name__}: {exc}")

    fig.save_figure_index(produced, metrics_dir / "figure_index.json")
    banner("Evaluation complete")
    print(f"  metrics : {metrics_dir}")
    print(f"  figures : {figures_dir}  ({sum(1 for p in produced if p)} rendered)")
    print(f"  report  : {report_path}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
