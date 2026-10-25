#!/usr/bin/env python3
"""Closed-loop evaluation: every detector drives mitigation inside the simulator.

Detection metrics say whether node-windows were labelled correctly. This
script measures what happens to the *network* when each detector is put in
charge of the gateway: how fast the attack is detected and mitigated, how
much service the clean fleet keeps, how many innocent devices are cut off,
and how hard the defence works the rule table.

Steps
-----
1. Train each detector once on every non-stress run of the research corpus
   (15% of runs held out for early stopping) -> ``results/research/predictions/final__all``.
2. Run a closed-loop grid on **unseen seeds** (offsets 10 and 11): each attack
   scenario on several topologies, plus the benign-stress scenarios, once per
   detector and once with no defence at all.
3. Compute :func:`netshield.evaluation.operational.operational_metrics` per run
   and aggregate per detector.

Outputs: ``results/research/closed_loop_runs.csv`` and
``results/research/closed_loop_summary.csv`` (read by the research report).
"""

from __future__ import annotations

import sys
from pathlib import Path

from _bootstrap import banner, common_parser, ok, setup  # noqa: E402

ATTACKS = ["exp2_udp_flood", "exp3_syn_flood", "exp4_http_flood", "exp15_icmp_flood",
           "exp16_ack_flood", "exp17_slowloris", "exp19_multivector"]
STRESS = ["exp20_flash_crowd", "exp21_firmware_storm", "exp22_reboot_storm"]


def main(argv: list[str] | None = None) -> int:
    parser = common_parser("Closed-loop mitigation evaluation for every detector.")
    parser.add_argument("--corpus", default="data/research")
    parser.add_argument("--models-out", default="results/research/predictions")
    parser.add_argument("--detectors", nargs="*",
                        default=["threshold", "random_forest", "lightgbm", "egraphsage",
                                 "graphsage", "temporal_gnn"])
    parser.add_argument("--conformal", nargs="*", default=["graphsage", "temporal_gnn"],
                        help="Also evaluate conformal-ladder wrappers of these detectors.")
    parser.add_argument("--topologies", nargs="*", default=["tree", "star", "mesh",
                                                            "multi_gateway"])
    parser.add_argument("--seed-offsets", nargs="*", type=int, default=[10, 11])
    parser.add_argument("--workers", type=int, default=11)
    args = parser.parse_args(argv)
    config = setup(args, "closed_loop_eval")

    import pandas as pd  # noqa: PLC0415

    from netshield.evaluation.operational import operational_metrics  # noqa: PLC0415
    from netshield.research.grid import RunSpec, run_grid  # noqa: PLC0415
    from netshield.research.protocol import (  # noqa: PLC0415
        STRESS_FAMILY,
        Fold,
        Variant,
        _val_split,
        load_research_corpus,
        run_protocol,
    )
    from netshield.simulation.runner import load_run  # noqa: PLC0415

    _, _, runs = load_research_corpus(args.corpus)
    core = runs.loc[runs["family"] != STRESS_FAMILY, "run_id"].tolist()
    train, val = _val_split(core, 0.15, seed=99)
    fold = Fold("final", "all", train, val, [])
    banner(f"Training final models on {len(train)} runs ({len(val)} for early stopping)")
    run_protocol(args.corpus, [fold], [Variant(d) for d in args.detectors], args.models_out,
                 workers=min(5, len(args.detectors)), threads_per_worker=2, save_models=True,
                 config_overrides=list(args.overrides or []))
    models_dir = str(Path(args.models_out) / fold.key)

    # Conformal wrappers: temperature + benign calibration on the same
    # early-stopping runs, so no test run ever informs a threshold.
    from netshield.detection.pipeline import load_detectors  # noqa: PLC0415
    from netshield.models.base import DetectionInput  # noqa: PLC0415
    from netshield.models.calibration import ConformalDetector  # noqa: PLC0415

    corpus, edges, _ = load_research_corpus(args.corpus)
    val_in = DetectionInput(corpus[corpus["run_id"].isin(val)].reset_index(drop=True), edges)
    arms = list(args.detectors)
    for name in args.conformal:
        target = Path(models_dir) / f"{name}_conformal"
        if not (target / "conformal.json").exists():
            base = load_detectors(models_dir, [name], required=True)[name]
            ConformalDetector.from_validation(base, val_in).save(target)
        arms.append(f"{name}_conformal")
    del corpus

    specs = []
    for detector in [None, *arms]:
        for scenario in ATTACKS:
            for topo in args.topologies:
                for offset in args.seed_offsets:
                    specs.append(RunSpec(scenario, topo, offset, closed_loop=detector,
                                         models_dir=models_dir, group="closed-loop"))
        for scenario in STRESS:
            for offset in args.seed_offsets:
                specs.append(RunSpec(scenario, "tree", offset, closed_loop=detector,
                                     models_dir=models_dir, group="closed-loop"))
    banner(f"Closed-loop grid: {len(specs)} runs")
    records = run_grid(specs, workers=args.workers,
                       manifest="results/research/closed_loop_manifest.json")

    trigger = float(config.get("detection.mitigation_trigger_probability", 0.8))
    rows = []
    for rec in records:
        result = load_run(rec["dir"])
        m = operational_metrics(result, trigger=trigger)
        rows.append({"detector": rec["closed_loop"] or "no_defence",
                     "scenario": rec["scenario"], "topology": rec["topology_family"],
                     "seed": rec["seed"], "family": rec["family"], **m})
    frame = pd.DataFrame(rows)
    out = Path("results/research")
    out.mkdir(parents=True, exist_ok=True)
    frame.to_csv(out / "closed_loop_runs.csv", index=False)

    attack = frame[frame["family"] != STRESS_FAMILY]
    stress = frame[frame["family"] == STRESS_FAMILY]
    summary = attack.groupby("detector").agg(
        runs=("scenario", "size"),
        detected=("time_to_detect_s", lambda s: int(s.notna().sum())),
        ttd_median_s=("time_to_detect_s", "median"),
        ttm_median_s=("time_to_mitigate_s", "median"),
        ttr_median_s=("time_to_recover_s", "median"),
        recovered=("time_to_recover_s", lambda s: int(s.notna().sum())),
        availability_attack=("availability_during_attack", "mean"),
        p99_attack_ms=("attack_clean_p99_latency_ms", "mean"),
        collateral_byte_ratio=("collateral_byte_ratio", "mean"),
        attack_suppression=("attack_suppression_ratio", "mean"),
        mitigation_precision=("mitigation_precision", "mean"),
        mitigation_recall=("mitigation_recall", "mean"),
        wrongly_mitigated=("wrongly_mitigated_nodes", "sum"),
        peak_rules=("peak_active_rules", "max"),
        churn_per_min=("rule_churn_per_min", "mean"),
        inference_ms=("inference_ms_mean", "mean"),
    )
    if not stress.empty:
        s = stress.groupby("detector").agg(
            stress_false_alarm_nodes=("false_alarm_nodes", "mean"),
            stress_false_alarms_per_node_hour=("false_alarms_per_node_hour", "mean"),
            stress_wrongly_mitigated=("wrongly_mitigated_nodes", "sum"),
            stress_collateral=("collateral_byte_ratio", "mean"),
            stress_availability=("baseline_clean_availability", "mean"))
        summary = summary.join(s, how="left")
    summary.reset_index().to_csv(out / "closed_loop_summary.csv", index=False)
    per_scenario = attack.pivot_table(index="scenario", columns="detector",
                                      values="availability_during_attack", aggfunc="mean")
    per_scenario.to_csv(out / "closed_loop_availability_by_scenario.csv")
    ok(f"closed-loop summary -> {out / 'closed_loop_summary.csv'}")
    with pd.option_context("display.width", 220, "display.max_columns", 30):
        print(summary.round(3).to_string())
    return 0


if __name__ == "__main__":
    sys.exit(main())
