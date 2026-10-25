#!/usr/bin/env python3
"""Generate the labelled node-window corpus by running simulations.

The corpus is built from the scenarios declared in ``config/experiments.yaml``
under ``dataset_corpus``: each base scenario is replayed with several seeds, and
a fuzzing campaign appends attack-parameter combinations that no human chose.
The held-out generalisation scenario (``exp7_unseen``) is deliberately excluded -
it is only ever scored, never fitted.

Outputs
-------
``data/experiments/<run_id>/``   full artefacts of every run (flows, metrics,
                                 link stats, per-device KPIs, config snapshot)
``data/processed/dataset.csv``   the node-window feature matrix with labels
``data/processed/edges.csv``     the per-window graph edge table
``data/processed/dataset_report.json``  corpus statistics
``data/netshield.db``            every run persisted for the dashboard
"""

from __future__ import annotations

import sys
import time
from typing import Any

from _bootstrap import banner, common_parser, ok, setup, warn  # noqa: E402


def _corpus_plan(config: Any, experiments: dict[str, Any], quick: bool) -> list[dict[str, Any]]:
    """Build the list of runs that make up the corpus.

    Args:
        config: The base configuration.
        experiments: Parsed ``config/experiments.yaml``.
        quick: Use a reduced plan (fewer seeds, fewer fuzz cases, shorter runs).

    Returns:
        A list of ``{"kind", "experiment", "seed_offset", "case"}`` descriptors.
    """
    corpus = experiments.get("dataset_corpus", {}) or {}
    base_runs = list(corpus.get("base_runs", []))
    replicates = int(corpus.get("seed_replicates", 2))
    fuzz_runs = int(corpus.get("fuzz_runs", 10))
    if quick:
        replicates = 0
        fuzz_runs = min(3, fuzz_runs)

    plan: list[dict[str, Any]] = []
    for name in base_runs:
        for offset in range(replicates + 1):
            plan.append({"kind": "base", "experiment": name, "seed_offset": offset})
    plan.append({"kind": "fuzz", "campaign": str(corpus.get("fuzz_campaign",
                                                            "corpus_campaign")),
                 "n": fuzz_runs})
    return plan


def main(argv: list[str] | None = None) -> int:
    """Generate the dataset.

    Args:
        argv: Command-line arguments.

    Returns:
        Process exit status.
    """
    parser = common_parser("Generate the labelled node-window corpus.")
    parser.add_argument("--quick", action="store_true",
                        help="Reduced corpus for a fast smoke run.")
    parser.add_argument("--duration", type=float, default=None,
                        help="Override the simulated duration of every corpus run.")
    parser.add_argument("--experiments", nargs="*", default=None,
                        help="Only run these base experiments.")
    parser.add_argument("--no-fuzz", action="store_true",
                        help="Skip the fuzzing portion of the corpus.")
    parser.add_argument("--no-db", action="store_true",
                        help="Do not persist runs to SQLite.")
    parser.add_argument("--reuse", action="store_true",
                        help="Load a run from data/experiments/ when its "
                             "artefacts already exist instead of "
                             "re-simulating it. Run ids are a hash of the "
                             "exact configuration, so a reused run is "
                             "byte-identical to a fresh one.")
    parser.add_argument("--output-dir", default="data/processed",
                        help="Where the corpus CSV files are written.")
    args = parser.parse_args(argv)

    config = setup(args, "generate_dataset")

    from netshield.database.store import NetShieldDB  # noqa: PLC0415
    from netshield.features.dataset import (  # noqa: PLC0415
        build_dataset,
        dataset_report,
        save_dataset,
    )
    from netshield.fuzzing.engine import (  # noqa: PLC0415
        FuzzEngine,
        load_campaign,
        materialise,
        save_cases,
    )
    from netshield.graph.builder import edge_table_from_results  # noqa: PLC0415
    from netshield.simulation.runner import (  # noqa: PLC0415
        build_run_id,
        load_run,
        probe_once,
        run_simulation,
    )
    from netshield.utils.config import (  # noqa: PLC0415
        ConfigError,
        experiment_config,
        load_experiments,
    )
    from netshield.utils.paths import resolve  # noqa: PLC0415

    experiments = load_experiments()
    plan = _corpus_plan(config, experiments, args.quick)
    if args.experiments:
        plan = [p for p in plan
                if p["kind"] != "base" or p["experiment"] in args.experiments]
    if args.no_fuzz:
        plan = [p for p in plan if p["kind"] != "fuzz"]

    duration_override: list[str] = []
    if args.duration is not None:
        duration_override.append(f"simulation.duration_s={args.duration}")
    elif args.quick:
        duration_override.append("simulation.duration_s=45.0")

    banner("NetShield-GNN :: dataset generation")
    ns3 = probe_once()
    print(f"  NS-3 available : {ns3.available}"
          f"{'' if ns3.available else ' (using the Python discrete-event engine)'}")
    print(f"  base runs      : {sum(1 for p in plan if p['kind'] == 'base')}")
    print(f"  fuzz campaigns : {sum(1 for p in plan if p['kind'] == 'fuzz')}")

    results: list[Any] = []
    started = time.perf_counter()
    experiments_root = resolve("data/experiments")
    failures: list[str] = []
    reused = 0

    def simulate_or_reuse(cfg: Any, meta: dict[str, Any], label: str) -> Any:
        """Run a simulation, or load it if its artefacts already exist."""
        nonlocal reused
        run_id = build_run_id(cfg, meta)
        run_dir = experiments_root / run_id
        if args.reuse and (run_dir / "run.json").exists():
            try:
                loaded = load_run(run_dir)
                reused += 1
                ok(f"reused cached run {run_id}")
                return loaded
            except Exception as exc:  # noqa: BLE001 - fall back to re-running
                warn(f"could not reuse {run_id} ({exc}); re-simulating")
        result = run_simulation(cfg, meta, ns3_probe=ns3)
        result.save(experiments_root / result.run_id)
        cfg.save(experiments_root / result.run_id / "config_snapshot.yaml")
        if result.summary.get("wall_budget_hit"):
            warn(f"{label}: wall-clock budget exhausted; the run covers only "
                 f"{result.summary.get('completed_fraction', 0) * 100:.0f}% "
                 "of its configured duration and is labelled truncated.")
        return result

    for item in plan:
        if item["kind"] == "base":
            name = item["experiment"]
            offset = int(item["seed_offset"])
            try:
                cfg, meta = experiment_config(name, experiments)
            except ConfigError as exc:
                warn(f"skipping {name}: {exc}")
                failures.append(name)
                continue
            overrides = list(duration_override)
            if offset:
                overrides.append(f"seed={int(cfg.get('seed', 42)) + offset}")
            if overrides:
                cfg = cfg.with_set(overrides)
            label = f"{name} (seed {cfg.get('seed')})"
            banner(f"run {len(results) + 1}: {label}")
            results.append(simulate_or_reuse(cfg, meta, label))
            continue

        # fuzzing portion
        campaign_name = str(item["campaign"])
        n_cases = int(item["n"])
        if n_cases <= 0:
            continue
        try:
            spec = load_campaign(campaign_name)
        except Exception as exc:  # noqa: BLE001 - report and continue
            warn(f"fuzz campaign '{campaign_name}' unavailable: {exc}")
            continue

        engine = FuzzEngine(spec)
        cases = engine.generate()[:n_cases]
        save_cases(cases, resolve("data/processed") / f"fuzz_{campaign_name}.json")
        base_cfg, base_meta = experiment_config(spec.base, experiments)

        for case in cases:
            try:
                cfg = materialise(case, base_cfg)
            except ConfigError as exc:
                warn(f"fuzz case {case.case_id} produced an invalid configuration "
                     f"and was skipped: {exc}")
                continue
            if duration_override:
                cfg = cfg.with_set(duration_override)
            meta = {
                **base_meta,
                "experiment": f"fuzz_{campaign_name}",
                "description": f"Fuzzed variant {case.case_id} of {spec.base}",
                "tags": ["fuzzing", spec.strategy],
                "fuzz_case": case.case_id,
            }
            banner(f"run {len(results) + 1}: fuzz case {case.case_id}")
            print(f"  overrides: {case.assignments}")
            results.append(simulate_or_reuse(cfg, meta, case.case_id))

    if not results:
        print("\n  No simulation runs completed; nothing to write.\n")
        return 1

    banner("Assembling the corpus")
    corpus = build_dataset(results, config)
    edges = edge_table_from_results(results)

    output_dir = resolve(args.output_dir)
    dataset_path = save_dataset(corpus, output_dir / "dataset.csv")
    edges_path = output_dir / "edges.csv"
    edges.to_csv(edges_path, index=False)
    ok(f"edges  -> {edges_path}  ({len(edges):,} rows)")

    report = dataset_report(corpus)
    report["runs_executed"] = len(results)
    report["runs_reused"] = reused
    report["failures"] = failures
    report["engine"] = results[0].engine_label
    report["wall_seconds"] = round(time.perf_counter() - started, 2)

    import json

    report_path = output_dir / "dataset_report.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    ok(f"report -> {report_path}")

    if not args.no_db:
        banner("Persisting runs to SQLite")
        db = NetShieldDB(config.path("database"))
        for result in results:
            db.store_run(result)
        ok(f"database -> {db.path}")
        print(f"  table counts: {db.table_counts()}")

    banner("Dataset summary")
    print(f"  rows        : {report['rows']:,}")
    print(f"  runs        : {report['runs']}")
    print(f"  scenarios   : {report['experiments']}")
    print(f"  features    : {report['n_features']}")
    print(f"  classes     : {report['classes']}")
    print(f"  engine      : {report['engine']}")
    print(f"  wall clock  : {report['wall_seconds']} s")
    print(f"\n  dataset -> {dataset_path}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
