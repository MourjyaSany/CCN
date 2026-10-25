#!/usr/bin/env python3
"""Run the experiment suite (Experiments 1-8) and produce their artefacts.

Experiments 1-7 are *open loop*: the network is simulated, then the trained
detectors score the resulting telemetry offline.

Experiment 8 is *closed loop*: the GraphSAGE detector runs inside the running
simulation and the mitigation engine installs rules at the gateway while the
attack is still in progress. Its recovery numbers are therefore measured
consequences of packets being dropped, not a separate calculation.

Each experiment writes:

``data/experiments/<run_id>/``          flows, window metrics, link stats, config
``results/figures/<experiment>_*.png``  topology and network-performance figures
``results/reports/<experiment>.md``     a per-experiment report
``results/metrics/experiments_summary.json``  the cross-experiment index
"""

from __future__ import annotations

import json
import sys
import time
from typing import Any

from _bootstrap import banner, common_parser, ok, setup, warn  # noqa: E402

#: Experiments that require a trained detector to be meaningful.
NEEDS_DETECTOR = {"exp7_unseen", "exp8_mitigation"}


def main(argv: list[str] | None = None) -> int:
    """Run one or all experiments.

    Args:
        argv: Command-line arguments.

    Returns:
        Process exit status.
    """
    parser = common_parser("Run the NetShield-GNN experiment suite.")
    parser.add_argument("--experiment", "-e", default=None,
                        help="Run a single experiment by name.")
    parser.add_argument("--all", action="store_true",
                        help="Run every experiment declared in experiments.yaml.")
    parser.add_argument("--list", action="store_true",
                        help="List the available experiments and exit.")
    parser.add_argument("--models-dir", default="models")
    parser.add_argument("--detector", default="graphsage",
                        help="Detector that drives the closed-loop experiment.")
    parser.add_argument("--no-detect", action="store_true",
                        help="Simulate only; skip detection and mitigation.")
    parser.add_argument("--no-figures", action="store_true")
    parser.add_argument("--duration", type=float, default=None,
                        help="Override the simulated duration of every experiment.")
    args = parser.parse_args(argv)

    config = setup(args, "run_experiment")

    import pandas as pd  # noqa: PLC0415

    from netshield.database.store import NetShieldDB  # noqa: PLC0415
    from netshield.detection.pipeline import (  # noqa: PLC0415
        PipelineError,
        build_controller_factory,
        load_detectors,
        recovery_metrics,
        score_run,
    )
    from netshield.evaluation import figures as fig  # noqa: PLC0415
    from netshield.evaluation import reports as rep  # noqa: PLC0415
    from netshield.mitigation.engine import evaluate_mitigation_accuracy  # noqa: PLC0415
    from netshield.mitigation.policy import ActionType, MitigationAction  # noqa: PLC0415
    from netshield.simulation.runner import (  # noqa: PLC0415
        probe_once,
        run_simulation,
    )
    from netshield.utils.config import (  # noqa: PLC0415
        ConfigError,
        experiment_config,
        experiment_names,
        load_experiments,
    )
    from netshield.utils.paths import ensure_dir, resolve  # noqa: PLC0415

    experiments = load_experiments()
    names = experiment_names(experiments)

    if args.list:
        banner("Available experiments")
        for name in names:
            entry = experiments["experiments"][name]
            print(f"  {name:<20} {str(entry.get('description', '')).strip()[:90]}")
        return 0

    if args.experiment:
        selected = [args.experiment]
    elif args.all:
        selected = names
    else:
        parser.error("Specify --experiment NAME, --all, or --list.")
        return 2

    detectors: dict[str, Any] = {}
    if not args.no_detect:
        try:
            detectors = load_detectors(args.models_dir)
        except PipelineError as exc:
            warn(f"{exc}")
            warn("Continuing in simulate-only mode; run "
                 "'python scripts/train_models.py' to enable detection.")

    ns3 = probe_once()
    figures_dir = ensure_dir("results/figures")
    reports_dir = ensure_dir("results/reports")
    metrics_dir = ensure_dir("results/metrics")
    experiments_root = ensure_dir("data/experiments")
    db = NetShieldDB(config.path("database"))

    trigger = float(config.get("detection.mitigation_trigger_probability", 0.80))
    index: list[dict[str, Any]] = []
    started = time.perf_counter()

    for name in selected:
        banner(f"Experiment: {name}")
        try:
            cfg, meta = experiment_config(name, experiments)
        except ConfigError as exc:
            warn(f"{exc}")
            continue
        if args.duration is not None:
            cfg = cfg.with_set([f"simulation.duration_s={args.duration}"])

        print(f"  {str(meta.get('description', '')).strip()}")

        closed_loop = bool(cfg.get("mitigation.enabled", False)) and bool(detectors)
        controller_factory = None
        driver = None
        if closed_loop:
            driver = detectors.get(args.detector) or next(iter(detectors.values()))
            controller_factory = build_controller_factory(driver, cfg,
                                                          enable_mitigation=True)
            print(f"  closed loop: {driver.name} drives mitigation "
                  f"(trigger p>={trigger:.2f})")
        elif cfg.get("mitigation.enabled", False):
            warn("mitigation.enabled is set but no detector is loaded; "
                 "running open loop.")

        result = run_simulation(cfg, meta, controller_factory=controller_factory,
                                ns3_probe=ns3)
        run_dir = experiments_root / result.run_id
        result.save(run_dir)
        cfg.save(run_dir / "config_snapshot.yaml")

        # ---- offline detection for every loaded detector --------------------
        detector_summaries: dict[str, Any] = {}
        detection_rows: list[dict[str, Any]] = []
        timelines: dict[str, pd.DataFrame] = {}
        for det_name, detector in detectors.items():
            try:
                scored = score_run(result, detector, cfg, trigger=trigger)
            except Exception as exc:  # noqa: BLE001
                warn(f"scoring with '{det_name}' failed: {type(exc).__name__}: {exc}")
                continue
            detector_summaries[det_name] = scored["summary"]
            timelines[det_name] = scored["timeline"]
            frame = scored["detections"]
            frame.to_csv(run_dir / f"detections_{det_name}.csv", index=False)
            detection_rows.extend(
                frame.rename(columns={"node_id": "node"})
                .assign(timestamp=frame["t_end"])
                .to_dict("records")
            )
            summary = scored["summary"]
            print(f"  {det_name:<14} flagged {summary['n_flagged']:>4} rows; "
                  f"bots found {len(summary['attackers_flagged'])}"
                  f"/{summary['attackers_total']}; "
                  f"false-alarm nodes {len(summary['false_alarm_nodes'])}")

        # ---- closed-loop specifics -----------------------------------------
        recovery: dict[str, Any] | None = None
        mitigation_summary: dict[str, Any] | None = None
        mitigation_accuracy: dict[str, Any] | None = None
        first_mitigation_s: float | None = None

        if result.mitigations:
            first_mitigation_s = min(float(m["timestamp"]) for m in result.mitigations)
            attack = dict(result.summary.get("attack", {}) or {})
            recovery = recovery_metrics(
                result.windows,
                attack_start_s=float(attack.get("start_s", 0.0)),
                attack_end_s=float(attack.get("end_s", 0.0)),
                first_mitigation_s=first_mitigation_s,
            )
            actions = [
                MitigationAction(
                    timestamp=float(m["timestamp"]), window=int(m["window"]),
                    node=str(m["node"]), ip=str(m.get("ip", "")),
                    action=ActionType(str(m["action"])),
                    confidence=float(m["confidence"]),
                )
                for m in result.mitigations
            ]
            attacker_ids = [n["node_id"] for n in result.topology["nodes"]
                            if n.get("is_attacker")]
            mitigation_accuracy = evaluate_mitigation_accuracy(actions, attacker_ids)
            mitigation_summary = {
                "detector": args.detector,
                "n_actions": len(result.mitigations),
                "actions_by_type": pd.Series(
                    [m["action"] for m in result.mitigations]
                ).value_counts().to_dict(),
                "first_action_s": first_mitigation_s,
                "nodes_affected": sorted({m["node"] for m in result.mitigations}),
                "enforcement": {
                    "packets_dropped": sum(
                        int(w.get("mitigation_drops", 0)) for w in result.windows
                    )
                },
            }
            print(f"  mitigation: {len(result.mitigations)} actions from "
                  f"t={first_mitigation_s:.1f}s; "
                  f"correct {len(mitigation_accuracy['correctly_mitigated'])}"
                  f"/{mitigation_accuracy['attackers_total']}, "
                  f"collateral {mitigation_accuracy['collateral_damage']}")
            if recovery.get("recovery_time_s") is not None:
                print(f"  recovery  : {recovery['recovery_time_s']:.1f}s after the "
                      "first rule was installed")

            pd.DataFrame(result.mitigations).to_csv(
                run_dir / "mitigation_log.csv", index=False
            )

        # ---- figures --------------------------------------------------------
        if not args.no_figures:
            try:
                fig.plot_topology(result, figures_dir / f"{name}_topology.png")
                fig.plot_network_timeseries(
                    result, figures_dir / f"{name}_network.png", first_mitigation_s
                )
                fig.plot_single_metric(
                    result, "throughput_mbps", "Upstream goodput (Mbit/s)",
                    f"Throughput over time - {name}",
                    figures_dir / f"{name}_throughput_vs_time.png",
                    first_mitigation_s,
                )
                fig.plot_single_metric(
                    result, "mean_latency_ms", "End-to-end delay (ms)",
                    f"Latency over time - {name}",
                    figures_dir / f"{name}_latency_vs_time.png",
                    first_mitigation_s,
                    secondary="legit_mean_latency_ms",
                    secondary_label="Legitimate traffic",
                )
                fig.plot_single_metric(
                    result, "loss_ratio", "Packet loss (%)",
                    f"Packet loss over time - {name}",
                    figures_dir / f"{name}_packet_loss_vs_time.png",
                    first_mitigation_s, scale=100.0,
                    secondary="legit_loss_ratio",
                    secondary_label="Legitimate traffic",
                )
                fig.plot_single_metric(
                    result, "pps", "Offered packet rate (pkt/s)",
                    f"Packet rate over time - {name}",
                    figures_dir / f"{name}_packet_rate_vs_time.png",
                    first_mitigation_s,
                )
                if recovery is not None:
                    timeline = timelines.get(args.detector)
                    if timeline is not None and not timeline.empty:
                        timeline = timeline.rename(
                            columns={"max_probability": "max_probability"}
                        )
                    fig.plot_attack_recovery(
                        result, figures_dir / "attack_recovery.png",
                        first_mitigation_s, timeline,
                    )
                    fig.plot_phase_comparison(
                        recovery, figures_dir / "network_phase_comparison.png"
                    )
            except Exception as exc:  # noqa: BLE001
                warn(f"figures for {name} failed: {type(exc).__name__}: {exc}")

        # ---- persistence ----------------------------------------------------
        report_path = rep.write_experiment_report(
            reports_dir / f"{name}.md",
            result,
            detector_summaries,
            recovery=recovery,
            mitigation=mitigation_summary,
            mitigation_accuracy=mitigation_accuracy,
        )
        ok(f"report -> {report_path}")

        try:
            db.store_run(result, detections=detection_rows or None,
                         mitigations=result.mitigations or None, trigger=trigger)
        except Exception as exc:  # noqa: BLE001
            warn(f"could not persist run: {type(exc).__name__}: {exc}")

        index.append({
            "experiment": name,
            "run_id": result.run_id,
            "engine": result.engine_label,
            "description": meta.get("description", ""),
            "tags": meta.get("tags", []),
            "summary": result.summary,
            "detectors": detector_summaries,
            "recovery": recovery,
            "mitigation": mitigation_summary,
            "mitigation_accuracy": mitigation_accuracy,
            "report": str(report_path),
            "run_dir": str(run_dir),
        })

    index_path = resolve(metrics_dir) / "experiments_summary.json"
    index_path.write_text(json.dumps(index, indent=2, default=str), encoding="utf-8")
    ok(f"experiment index -> {index_path}")

    banner("Experiment suite complete")
    print(f"  experiments run : {len(index)}")
    print(f"  wall clock      : {time.perf_counter() - started:.1f}s")
    print("  artefacts       : data/experiments/, results/\n")
    return 0 if index else 1


if __name__ == "__main__":
    sys.exit(main())
