#!/usr/bin/env python3
"""Run a dynamic fuzzing campaign against the trained detectors.

Two modes:

``--campaign NAME``
    Runs every case a campaign generates, simulates it and scores the detectors
    on the resulting telemetry. Produces the robustness curves that show how
    detection quality varies with attack rate, packet size, burst duty cycle and
    botnet size.

``--campaign evasion_search --adaptive``
    Runs the greedy evasion search: cases are scored by the detector's recall on
    the attacker nodes, and the lowest-scoring parameter vectors are
    preferentially re-mutated. The result is the parameter region where the
    detector is weakest - evidence for the report's Limitations section.

Every case is a configuration override handed to the in-memory simulator. The
fuzzer never touches a network interface.
"""

from __future__ import annotations

import json
import sys
import time
from typing import Any

from _bootstrap import banner, common_parser, ok, setup, warn  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    """Run a fuzzing campaign.

    Args:
        argv: Command-line arguments.

    Returns:
        Process exit status.
    """
    parser = common_parser("Run a dynamic fuzzing campaign.")
    parser.add_argument("--campaign", "-c", default="rate_sweep",
                        help="Campaign name from config/fuzzing.yaml.")
    parser.add_argument("--list", action="store_true",
                        help="List the available campaigns and exit.")
    parser.add_argument("--adaptive", action="store_true",
                        help="Drive the greedy evasion search (adaptive strategy).")
    parser.add_argument("--limit", type=int, default=None,
                        help="Cap the number of cases actually simulated.")
    parser.add_argument("--duration", type=float, default=70.0,
                        help="Simulated duration of each fuzz run.")
    parser.add_argument("--models-dir", default="models")
    parser.add_argument("--detectors", nargs="*", default=None,
                        help="Subset of detectors to score.")
    parser.add_argument("--objective-detector", default="graphsage",
                        help="Detector whose recall the adaptive search minimises.")
    parser.add_argument("--output-dir", default="results/metrics")
    parser.add_argument("--no-figures", action="store_true")
    args = parser.parse_args(argv)

    setup(args, "fuzz")

    import pandas as pd  # noqa: PLC0415

    from netshield.detection.pipeline import (  # noqa: PLC0415
        PipelineError,
        load_detectors,
        score_run,
    )
    from netshield.evaluation import figures as fig  # noqa: PLC0415
    from netshield.fuzzing.engine import (  # noqa: PLC0415
        FuzzEngine,
        campaign_names,
        cases_to_frame,
        load_campaign,
        materialise,
        save_cases,
    )
    from netshield.simulation.runner import probe_once, run_simulation  # noqa: PLC0415
    from netshield.utils.config import ConfigError, experiment_config  # noqa: PLC0415
    from netshield.utils.paths import ensure_dir  # noqa: PLC0415

    if args.list:
        banner("Available fuzzing campaigns")
        for name in campaign_names():
            spec = load_campaign(name)
            engine = FuzzEngine(spec)
            print(f"  {name:<22} {spec.strategy:<10} "
                  f"{engine.planned_case_count():>3} cases  "
                  f"{spec.description.splitlines()[0][:60] if spec.description else ''}")
        return 0

    try:
        spec = load_campaign(args.campaign)
    except Exception as exc:  # noqa: BLE001
        print(f"\n  {exc}\n")
        return 1

    try:
        detectors = load_detectors(args.models_dir, names=args.detectors)
    except PipelineError as exc:
        print(f"\n  {exc}\n")
        return 1

    try:
        base_cfg, base_meta = experiment_config(spec.base)
    except ConfigError as exc:
        print(f"\n  {exc}\n")
        return 1

    banner(f"Fuzzing campaign: {spec.name}")
    print(f"  strategy   : {spec.strategy}")
    print(f"  baseline   : {spec.base}")
    print(f"  seed       : {spec.seed}")
    print(f"  detectors  : {sorted(detectors)}")
    if spec.description:
        print(f"  purpose    : {spec.description.strip().splitlines()[0]}")

    ns3 = probe_once()
    engine = FuzzEngine(spec)
    output_dir = ensure_dir(args.output_dir)
    rows: list[dict[str, Any]] = []
    started = time.perf_counter()

    def evaluate_case(case: Any) -> float:
        """Simulate one case, score every detector, and return the objective.

        Returns:
            The objective detector's recall on the attacker nodes. Lower means
            the case evaded detection more successfully.
        """
        try:
            cfg = materialise(case, base_cfg)
        except ConfigError as exc:
            warn(f"{case.case_id}: invalid configuration, skipped ({exc})")
            return 1.0
        cfg = cfg.with_set([f"simulation.duration_s={args.duration}"])

        meta = {**base_meta, "experiment": f"fuzz_{spec.name}",
                "fuzz_case": case.case_id}
        result = run_simulation(cfg, meta, ns3_probe=ns3)

        objective = 1.0
        for det_name, detector in detectors.items():
            try:
                scored = score_run(result, detector, cfg)
            except Exception as exc:  # noqa: BLE001
                warn(f"{case.case_id}/{det_name}: scoring failed ({exc})")
                continue
            summary = scored["summary"]
            total = max(1, summary["attackers_total"])
            recall = len(summary["attackers_flagged"]) / total
            row = {
                "campaign": spec.name,
                "case_id": case.case_id,
                "detector": det_name,
                "seed": case.seed,
                "generation": case.generation,
                "recall": round(recall, 5),
                "attackers_total": summary["attackers_total"],
                "attackers_flagged": len(summary["attackers_flagged"]),
                "false_alarm_nodes": len(summary["false_alarm_nodes"]),
                "n_flagged_rows": summary["n_flagged"],
                "packets_generated": result.summary.get("packets_generated"),
                "loss_ratio": result.summary.get("overall_loss_ratio"),
                "mean_latency_ms": result.summary.get("mean_latency_ms"),
                "wall_budget_hit": result.summary.get("wall_budget_hit", False),
            }
            for key, value in case.assignments.items():
                row[key] = json.dumps(value) if isinstance(value, list) else value
            rows.append(row)
            if det_name == args.objective_detector:
                objective = recall

        marker = " [TRUNCATED]" if result.summary.get("wall_budget_hit") else ""
        print(f"  {case.case_id}: objective recall = {objective:.3f}{marker}")
        return objective

    if args.adaptive or spec.strategy == "adaptive":
        banner("Adaptive evasion search")
        print(f"  objective: minimise {args.objective_detector} recall on the bots\n")
        cases = engine.run_adaptive(
            evaluate_case, n_samples=args.limit or spec.n_samples
        )
    else:
        cases = engine.generate()
        if args.limit:
            cases = cases[: args.limit]
        banner(f"Simulating {len(cases)} case(s)")
        for case in cases:
            print(f"  {case.case_id}: {case.assignments}")
            evaluate_case(case)

    cases_path = output_dir / f"fuzz_cases_{spec.name}.json"
    save_cases(cases, cases_path)

    if not rows:
        print("\n  No case produced a scored result.\n")
        return 1

    frame = pd.DataFrame(rows)
    results_path = output_dir / f"fuzz_results_{spec.name}.csv"
    frame.to_csv(results_path, index=False)
    ok(f"results -> {results_path}")

    banner("Robustness summary")
    pivot = frame.pivot_table(index="detector", values=["recall", "false_alarm_nodes"],
                              aggfunc="mean").round(4)
    print(pivot.to_string())

    worst = frame.sort_values("recall").head(5)
    print("\n  Weakest parameter combinations "
          f"(lowest {args.objective_detector} recall):")
    for row in worst.itertuples(index=False):
        params = {
            k: getattr(row, k) for k in frame.columns
            if k.startswith(("attack.", "simulation."))
        }
        print(f"    {row.case_id:<22} {row.detector:<14} recall={row.recall:.3f}  {params}")

    if not args.no_figures:
        figures_dir = ensure_dir("results/figures")
        note = f"campaign: {spec.name} ({spec.strategy}, seed {spec.seed})"
        case_frame = cases_to_frame(cases)
        fig.plot_fuzzing_distribution(
            case_frame, figures_dir / f"fuzzing_parameters_{spec.name}.png", note
        )
        swept = [
            c for c in frame.columns
            if c.startswith(("attack.", "simulation."))
            and pd.api.types.is_numeric_dtype(frame[c]) and frame[c].nunique() > 1
        ]
        if swept:
            fig.plot_fuzz_robustness(
                frame, swept[0], figures_dir / f"fuzz_robustness_{spec.name}.png",
                note, title=f"Detector robustness vs {swept[0].split('.')[-1]}",
            )

    print(f"\n  wall clock: {time.perf_counter() - started:.1f}s\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
