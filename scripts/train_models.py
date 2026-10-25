#!/usr/bin/env python3
"""Train the three detectors on the generated corpus.

All three detectors see the *same* rows, the *same* 46 features and the *same*
grouped train/validation/test split, so the comparison in the report is a
controlled experiment rather than three independently tuned pipelines.

Checkpoints are written to ``models/<detector>/`` together with the fitted
feature scaler and a manifest recording the feature column order, so a model can
never be loaded against a mismatched feature set.
"""

from __future__ import annotations

import json
import sys
import time
from typing import Any

from _bootstrap import banner, common_parser, ok, setup, warn  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    """Train and persist every detector.

    Args:
        argv: Command-line arguments.

    Returns:
        Process exit status.
    """
    parser = common_parser("Train the threshold, Random Forest and GraphSAGE detectors.")
    parser.add_argument("--dataset", default="data/processed/dataset.csv",
                        help="Corpus produced by scripts/generate_dataset.py.")
    parser.add_argument("--edges", default="data/processed/edges.csv",
                        help="Edge table produced alongside the corpus.")
    parser.add_argument("--models-dir", default="models",
                        help="Where checkpoints are written.")
    parser.add_argument("--detectors", nargs="*",
                        default=["threshold", "random_forest", "graphsage"],
                        help="Subset of detectors to train.")
    parser.add_argument("--epochs", type=int, default=None,
                        help="Override the GraphSAGE epoch budget.")
    args = parser.parse_args(argv)

    config = setup(args, "train_models")

    import pandas as pd  # noqa: PLC0415

    from netshield.features.dataset import (  # noqa: PLC0415
        DatasetError,
        load_dataset,
        split_by_run,
    )
    from netshield.models.base import DetectionInput  # noqa: PLC0415
    from netshield.models.baselines import (  # noqa: PLC0415
        AutoencoderDetector,
        GRUSequenceDetector,
        LightGBMDetector,
    )
    from netshield.models.graphsage import (  # noqa: PLC0415
        BACKEND,
        EGraphSAGEDetector,
        GATDetector,
        GraphSAGEDetector,
    )
    from netshield.models.random_forest import RandomForestDetector  # noqa: PLC0415
    from netshield.models.threshold import ThresholdDetector  # noqa: PLC0415
    from netshield.utils.paths import ensure_dir, resolve  # noqa: PLC0415

    banner("NetShield-GNN :: training")

    try:
        corpus = load_dataset(args.dataset)
    except (FileNotFoundError, DatasetError) as exc:
        print(f"\n  {exc}\n")
        return 1

    edges_path = resolve(args.edges)
    if not edges_path.exists():
        print(f"\n  Edge table not found: {edges_path}\n"
              "  Run 'python scripts/generate_dataset.py' first.\n")
        return 1
    edges = pd.read_csv(edges_path)

    split = split_by_run(
        corpus,
        test_size=float(config.get("evaluation.test_size", 0.25)),
        val_size=float(config.get("evaluation.val_size", 0.15)),
        seed=int(config.get("seed", 42)),
    )
    summary = split.summary()
    print(f"  corpus     : {len(corpus):,} rows, {corpus['run_id'].nunique()} runs")
    for name in ("train", "val", "test"):
        block = summary[name]
        print(f"  {name:<10} : {block['rows']:>6,} rows / {block['runs']:>2} runs  "
              f"{block['classes']}")
    print(f"  GNN backend: {BACKEND}")

    train_in = DetectionInput(split.train, edges)
    val_in = DetectionInput(split.val, edges)

    if split.train["label"].nunique() < 2:
        print("\n  The training split contains a single class; the corpus is too "
              "small or too uniform to train on. Regenerate it with more "
              "scenarios.\n")
        return 1

    factories = {
        "threshold": lambda: ThresholdDetector.from_config(config),
        "random_forest": lambda: RandomForestDetector.from_config(config),
        "graphsage": lambda: GraphSAGEDetector.from_config(config),
        "lightgbm": lambda: LightGBMDetector.from_config(config),
        "gru_seq": lambda: GRUSequenceDetector.from_config(config),
        "autoencoder": lambda: AutoencoderDetector.from_config(config),
        "gat": lambda: GATDetector.from_config(config),
        "egraphsage": lambda: EGraphSAGEDetector.from_config(config),
    }

    models_dir = ensure_dir(args.models_dir)
    reports: dict[str, Any] = {}
    started = time.perf_counter()

    for name in args.detectors:
        factory = factories.get(name)
        if factory is None:
            warn(f"unknown detector '{name}'; skipped")
            continue

        banner(f"training: {name}")
        detector = factory()
        if name in ("graphsage", "gat", "egraphsage") and args.epochs is not None:
            detector.hyper["epochs"] = int(args.epochs)

        try:
            report = detector.fit(train_in, val_in)
        except Exception as exc:  # noqa: BLE001 - report loudly, keep going
            warn(f"training '{name}' failed: {type(exc).__name__}: {exc}")
            reports[name] = {"detector": name, "error": f"{type(exc).__name__}: {exc}"}
            continue

        path = detector.save(models_dir / name)
        reports[name] = report.to_dict()
        ok(f"{name}: fitted in {report.duration_s:.2f}s -> {path}")

    split_path = models_dir / "split.json"
    split_path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    ok(f"split manifest -> {split_path}")

    reports_path = models_dir / "training_reports.json"
    reports_path.write_text(json.dumps(reports, indent=2, default=str), encoding="utf-8")
    ok(f"training reports -> {reports_path}")

    banner("Training complete")
    print(f"  total wall clock: {time.perf_counter() - started:.1f}s")
    print(f"  checkpoints     : {models_dir}")
    errors = [n for n, r in reports.items() if "error" in r]
    if errors:
        print(f"\n  {len(errors)} detector(s) failed to train: {errors}\n")
        return 1
    print("\n  Next: python scripts/evaluate.py\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
