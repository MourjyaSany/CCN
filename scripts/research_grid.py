#!/usr/bin/env python3
"""Run the research simulation grid in parallel and assemble its corpus.

Grid: 7 attack/benign scenarios x 7 topology families x N seeds, the
tree-only rate-shaping scenarios, and the benign-stress scenarios on every
topology. Each run is cached under ``data/experiments/<run_id>`` so the grid
is resumable.

Outputs (default ``data/research/``):
    dataset.csv   node-window features + labels for every run
    edges.csv     window graph edge table
    runs.csv      one row per run: scenario, topology, family, seed, wall time

Example:
    python scripts/research_grid.py --seeds 3 --workers 11
    python scripts/research_grid.py --seeds 2 --window 2.0 --out data/research_w2
"""

from __future__ import annotations

import sys
import time

from _bootstrap import banner, common_parser, ok, setup  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = common_parser("Run the research grid and build its corpus.")
    parser.add_argument("--seeds", type=int, default=3)
    parser.add_argument("--stress-seeds", type=int, default=2)
    parser.add_argument("--workers", type=int, default=None)
    parser.add_argument("--topologies", nargs="*", default=None)
    parser.add_argument("--scenarios", nargs="*", default=None)
    parser.add_argument("--window", type=float, default=None,
                        help="Feature window length (re-simulates; for the window sweep).")
    parser.add_argument("--no-extras", action="store_true",
                        help="Skip tree-only and benign-stress scenarios.")
    parser.add_argument("--out", default="data/research")
    parser.add_argument("--no-reuse", action="store_true")
    args = parser.parse_args(argv)
    config = setup(args, "research_grid")

    import pandas as pd  # noqa: PLC0415

    from netshield.features.dataset import build_dataset, save_dataset  # noqa: PLC0415
    from netshield.graph.builder import edge_table_from_results  # noqa: PLC0415
    from netshield.research.grid import TOPOLOGY_SOURCES, research_grid, run_grid  # noqa: PLC0415
    from netshield.simulation.runner import load_run  # noqa: PLC0415
    from netshield.utils.paths import ensure_dir  # noqa: PLC0415

    overrides = [f"features.window_s={args.window}"] if args.window else []
    kwargs = {"seeds": args.seeds, "stress_seeds": args.stress_seeds,
              "topologies": args.topologies or list(TOPOLOGY_SOURCES),
              "extra_overrides": overrides}
    if args.scenarios:
        kwargs["scenarios"] = args.scenarios
    if args.no_extras:
        kwargs["tree_only"] = ()
        kwargs["stress"] = ()
    specs = research_grid(**kwargs)

    out = ensure_dir(args.out)
    banner(f"Research grid: {len(specs)} runs")
    started = time.perf_counter()
    records = run_grid(specs, workers=args.workers, reuse=not args.no_reuse,
                       manifest=out / "grid_manifest.json")

    banner("Assembling corpus")
    cfg = config.with_set(overrides) if overrides else config
    results = [load_run(r["dir"]) for r in records]
    corpus = build_dataset(results, cfg)
    edges = edge_table_from_results(results)
    runs = pd.DataFrame([{k: r[k] for k in ("run_id", "scenario", "topology_family", "family",
                                            "seed", "seed_offset", "group", "wall_s")}
                         for r in records])
    save_dataset(corpus, out / "dataset.csv")
    edges.to_csv(out / "edges.csv", index=False)
    runs.to_csv(out / "runs.csv", index=False)
    ok(f"corpus: {len(corpus):,} rows, {corpus['run_id'].nunique()} runs -> {out}")
    print("  classes:", corpus["label_name"].value_counts().to_dict())
    print(f"  total wall clock: {time.perf_counter() - started:.0f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
