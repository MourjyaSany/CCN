#!/usr/bin/env python3
"""Live presentation demo: normal traffic -> DDoS -> detection -> mitigation -> recovery.

Runs one closed-loop scenario and narrates it in the terminal as simulated time
advances, so an audience can watch the whole defence cycle in about two minutes.
Nothing here is scripted: the narration reports the numbers the simulator is
producing at that instant, and the mitigation actions are the real decisions the
trained detector and the policy engine make.

Usage::

    ./run.sh demo                 # ~2 minutes, paced for a live audience
    python scripts/demo.py --fast # as fast as the machine can go
"""

from __future__ import annotations

import sys
import time
from typing import Any

from _bootstrap import banner, common_parser, setup  # noqa: E402

BAR_WIDTH = 34

# ANSI colours, disabled automatically when stdout is not a terminal.
_TTY = sys.stdout.isatty()
DIM = "\033[2m" if _TTY else ""
BOLD = "\033[1m" if _TTY else ""
RED = "\033[31m" if _TTY else ""
GREEN = "\033[32m" if _TTY else ""
YELLOW = "\033[33m" if _TTY else ""
BLUE = "\033[36m" if _TTY else ""
RESET = "\033[0m" if _TTY else ""


def bar(value: float, maximum: float, width: int = BAR_WIDTH) -> str:
    """Render a proportional text bar."""
    if maximum <= 0:
        return " " * width
    filled = int(round(min(1.0, value / maximum) * width))
    return "#" * filled + "." * (width - filled)


class DemoNarrator:
    """Window controller that prints a live narration of the simulation.

    Args:
        detection_controller: The controller producing detections and mitigation.
        attack_start: Attack start time in simulated seconds.
        attack_end: Attack end time in simulated seconds.
        speed: Simulated seconds per wall-clock second (0 disables pacing).
        peak_pps: Scale used for the traffic bar.
    """

    def __init__(
        self,
        detection_controller: Any,
        attack_start: float,
        attack_end: float,
        speed: float = 1.6,
        peak_pps: float = 9000.0,
    ) -> None:
        self.controller = detection_controller
        self.attack_start = attack_start
        self.attack_end = attack_end
        self.speed = speed
        self.peak_pps = peak_pps
        self.baseline_pps: float | None = None
        self.first_detection: float | None = None
        self.first_mitigation: float | None = None
        self.phase = ""
        self._wall_start = time.perf_counter()

    def on_window(self, engine: Any, window_index: int, t: float) -> None:
        """Print one narration line for the window that just closed."""
        metrics = engine.telemetry.windows.get(window_index)
        if metrics is None:
            return

        # Service level is reported for never-compromised devices: isolating a
        # bot also severs its own legitimate telemetry, which is intended.
        pps = metrics.packets_per_second
        loss = metrics.clean_loss_ratio * 100.0
        latency = metrics.clean_mean_latency_ms or metrics.mean_latency_ms
        util = metrics.uplink_utilisation() * 100.0

        flagged: list[str] = []
        confidence = 0.0
        for row in self.controller.detection_log:
            if int(row["window"]) != window_index:
                continue
            confidence = max(confidence, float(row["probability"]))
            if float(row["probability"]) >= self.controller.trigger:
                flagged.append(str(row["node"]))

        mitigated = [
            row for row in self.controller.mitigation_log
            if int(row["window"]) == window_index
        ]

        if t <= self.attack_start:
            phase, colour = "NORMAL", GREEN
            if self.baseline_pps is None or pps > 0:
                self.baseline_pps = pps if self.baseline_pps is None else (
                    0.7 * self.baseline_pps + 0.3 * pps
                )
        elif t <= self.attack_end:
            phase, colour = ("UNDER ATTACK", RED) if not self.first_mitigation else (
                "MITIGATING", YELLOW
            )
        else:
            phase, colour = "RECOVERING", BLUE

        if flagged and self.first_detection is None:
            self.first_detection = t
        if mitigated and self.first_mitigation is None:
            self.first_mitigation = t

        print(
            f"  {DIM}t={t:6.1f}s{RESET} {colour}{phase:<13}{RESET} "
            f"[{bar(pps, self.peak_pps)}] "
            f"{pps:8.0f} pkt/s  loss {loss:5.1f}%  delay {latency:6.1f} ms  "
            f"uplink {util:5.1f}%  P(hostile) {confidence:.2f}",
            flush=True,
        )

        if phase != self.phase:
            self.phase = phase
            if phase == "UNDER ATTACK":
                print(f"        {RED}>> DDoS traffic detected on the wire: the "
                      f"uplink is saturating.{RESET}", flush=True)
            elif phase == "RECOVERING":
                print(f"        {BLUE}>> Attack window has ended.{RESET}", flush=True)

        if flagged:
            preview = ", ".join(sorted(flagged)[:6])
            more = f" (+{len(flagged) - 6} more)" if len(flagged) > 6 else ""
            print(f"        {YELLOW}>> DETECTION: {len(flagged)} node(s) above "
                  f"trigger p>={self.controller.trigger:.2f}: {preview}{more}{RESET}",
                  flush=True)
        for action in mitigated:
            print(f"        {GREEN}>> MITIGATION: {action['action'].upper()} "
                  f"{action['node']} (p={float(action['confidence']):.3f}) "
                  f"- {action['reason']}{RESET}", flush=True)

        if self.speed > 0:
            target = t / self.speed
            elapsed = time.perf_counter() - self._wall_start
            if target > elapsed:
                time.sleep(min(target - elapsed, 4.0))


def main(argv: list[str] | None = None) -> int:
    """Run the demonstration.

    Args:
        argv: Command-line arguments.

    Returns:
        Process exit status.
    """
    parser = common_parser("Live NetShield-GNN demonstration.")
    parser.add_argument("--scenario", default="exp8_mitigation")
    parser.add_argument("--detector", default="graphsage")
    parser.add_argument("--models-dir", default="models")
    parser.add_argument("--speed", type=float, default=1.6,
                        help="Simulated seconds per wall-clock second.")
    parser.add_argument("--fast", action="store_true",
                        help="Disable pacing and run as fast as possible.")
    parser.add_argument("--duration", type=float, default=110.0,
                        help="Simulated duration of the demonstration.")
    parser.add_argument("--no-mitigation", action="store_true",
                        help="Detect only, to contrast with the mitigated run.")
    args = parser.parse_args(argv)

    setup(args, "demo")

    from netshield.detection.controller import DetectionController  # noqa: PLC0415
    from netshield.detection.pipeline import (  # noqa: PLC0415
        PipelineError,
        load_detectors,
        recovery_metrics,
    )
    from netshield.mitigation.engine import (  # noqa: PLC0415
        MitigationEnforcer,
        MitigationEngine,
        evaluate_mitigation_accuracy,
    )
    from netshield.mitigation.policy import (  # noqa: PLC0415
        ActionType,
        MitigationAction,
        PolicyConfig,
    )
    from netshield.simulation.runner import run_simulation  # noqa: PLC0415
    from netshield.utils.config import ConfigError, experiment_config  # noqa: PLC0415

    banner("NetShield-GNN :: live demonstration")
    print("  Intelligent DDoS detection and automated mitigation")
    print("  for IoT-cloud networks using dynamic fuzzing and Graph Neural Networks")
    print()
    print(f"  {DIM}Every packet below is generated inside an in-memory")
    print(f"  discrete-event network simulator. Nothing leaves this machine.{RESET}")

    try:
        detectors = load_detectors(args.models_dir)
    except PipelineError as exc:
        print(f"\n  {exc}")
        print("\n  Run this first:\n"
              "      python scripts/generate_dataset.py\n"
              "      python scripts/train_models.py\n")
        return 1

    detector = detectors.get(args.detector) or next(iter(detectors.values()))

    try:
        cfg, meta = experiment_config(args.scenario)
    except ConfigError as exc:
        print(f"\n  {exc}\n")
        return 1

    overrides = [f"simulation.duration_s={args.duration}"]
    if args.no_mitigation:
        overrides.append("mitigation.enabled=false")
    else:
        overrides.append("mitigation.enabled=true")
    cfg = cfg.with_set(overrides)

    attack_start = float(cfg.get("attack.start_s", 30.0))
    attack_end = attack_start + float(cfg.get("attack.duration_s", 40.0))
    speed = 0.0 if args.fast else max(0.2, args.speed)

    banner("Scenario")
    print(f"  scenario     : {args.scenario}")
    print(f"  detector     : {detector.display_name}")
    print(f"  devices      : {cfg.get('simulation.n_iot_devices')} legitimate IoT, "
          f"{cfg.get('simulation.n_attackers')} compromised")
    print(f"  attack       : {cfg.get('attack.type')} at "
          f"{cfg.get('attack.packets_per_second')} pkt/s per bot, "
          f"t = {attack_start:.0f}-{attack_end:.0f} s")
    print(f"  mitigation   : {'ENABLED' if cfg.get('mitigation.enabled') else 'disabled'}")
    print(f"  duration     : {args.duration:.0f} simulated seconds"
          f"{'' if speed == 0 else f' (paced at x{speed:.1f} -> about {args.duration / speed:.0f} s)'}")

    policy = PolicyConfig.from_config(cfg).validate()
    trigger = float(cfg.get("detection.mitigation_trigger_probability", 0.80))
    holder: dict[str, Any] = {}

    def factory(context: Any) -> list[Any]:
        """Build the detection controller and the narrator."""
        mitigation_engine = None
        if cfg.get("mitigation.enabled", False):
            node_ips = {n.node_id: n.ip for n in context.topology.nodes.values()}
            mitigation_engine = MitigationEngine(
                policy, MitigationEnforcer(policy, node_ips),
                detector_name=detector.name,
            )
        controller = DetectionController(
            context=context, detector=detector, mitigation=mitigation_engine,
            trigger=trigger,
        )
        peak = max(2000.0, float(cfg.get("attack.packets_per_second", 1500.0))
                   * float(cfg.get("simulation.n_attackers", 6)) * 1.15)
        narrator = DemoNarrator(controller, attack_start, attack_end, speed, peak)
        holder["controller"] = controller
        holder["narrator"] = narrator
        return [controller, narrator]

    banner("Live network")
    print(f"  {DIM}phase          traffic{'':<28} rate      legit-loss  delay"
          f"      uplink   confidence{RESET}")

    started = time.perf_counter()
    result = run_simulation(cfg, meta, controller_factory=factory)
    wall = time.perf_counter() - started

    controller = holder.get("controller")
    narrator = holder.get("narrator")

    banner("What happened")
    summary = result.summary
    windows = result.windows

    pre = [w for w in windows if w["t_end"] <= attack_start]
    during = [w for w in windows
              if w["t_start"] >= attack_start and w["t_end"] <= attack_end]

    def mean(rows: list[dict[str, Any]], key: str, scale: float = 1.0) -> float:
        return (sum(float(r[key]) for r in rows) / len(rows) * scale) if rows else 0.0

    print(f"  Packets simulated      : {summary['packets_generated']:,} "
          f"({summary['events_processed']:,} discrete events in {wall:.1f} s wall clock)")
    print(f"  Engine                 : {result.engine_label}")
    print()
    print(f"  {'':22} {'NORMAL':>12} {'UNDER ATTACK':>14}")
    print(f"  {'offered packets/s':22} {mean(pre, 'pps'):>12.0f} "
          f"{mean(during, 'pps'):>14.0f}")
    print(f"  {'clean loss %':22} {mean(pre, 'clean_loss_ratio', 100):>12.2f} "
          f"{mean(during, 'clean_loss_ratio', 100):>14.2f}")
    print(f"  {'clean delay ms':22} {mean(pre, 'clean_mean_latency_ms'):>12.1f} "
          f"{mean(during, 'clean_mean_latency_ms'):>14.1f}")
    print(f"  {'uplink utilisation %':22} {mean(pre, 'uplink_utilisation', 100):>12.1f} "
          f"{mean(during, 'uplink_utilisation', 100):>14.1f}")

    if narrator is not None and narrator.first_detection is not None:
        print()
        print(f"  Attack began           : t = {attack_start:.1f} s")
        print(f"  First detection        : t = {narrator.first_detection:.1f} s "
              f"({GREEN}{narrator.first_detection - attack_start:.1f} s "
              f"detection latency{RESET})")
        if narrator.first_mitigation is not None:
            print(f"  First mitigation       : t = {narrator.first_mitigation:.1f} s "
                  f"({GREEN}{narrator.first_mitigation - attack_start:.1f} s "
                  f"after the attack started{RESET})")

    if result.mitigations:
        first_mitigation = min(float(m["timestamp"]) for m in result.mitigations)
        recovery = recovery_metrics(windows, attack_start, attack_end, first_mitigation)
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
        accuracy = evaluate_mitigation_accuracy(actions, attacker_ids)

        banner("Mitigation outcome")
        print(f"  Rules installed        : {len(result.mitigations)} "
              f"across {len(accuracy['correctly_mitigated']) + accuracy['collateral_damage']} "
              f"node(s)")
        print(f"  Bots correctly stopped : "
              f"{len(accuracy['correctly_mitigated'])}/{accuracy['attackers_total']} "
              f"(recall {accuracy['recall']:.2f})")
        print(f"  Legitimate devices hit : {accuracy['collateral_damage']} "
              f"(precision {accuracy['precision']:.2f})")

        after = recovery.get("after_mitigation") or {}
        baseline = recovery.get("baseline") or {}
        # The unmitigated slice is the windows in which the attack was running
        # but no rule had been installed yet, so the comparison isolates the
        # effect of the defence at a constant offered attack load.
        unmitigated = [w for w in windows
                       if attack_start <= w["t_start"] and w["t_end"] <= first_mitigation]
        if after and baseline:
            print()
            print(f"  {'':22} {'NORMAL':>12} {'UNMITIGATED':>14} "
                  f"{'MITIGATED':>18}")
            print(f"  {'clean loss %':22} "
                  f"{baseline.get('clean_loss_ratio', 0) * 100:>12.2f} "
                  f"{mean(unmitigated, 'clean_loss_ratio', 100):>14.2f} "
                  f"{after.get('clean_loss_ratio', 0) * 100:>18.2f}")
            print(f"  {'clean delay ms':22} "
                  f"{baseline.get('clean_mean_latency_ms', 0):>12.1f} "
                  f"{mean(unmitigated, 'clean_mean_latency_ms'):>14.1f} "
                  f"{after.get('clean_mean_latency_ms', 0):>18.1f}")
            print(f"  {'clean goodput pkt/s':22} "
                  f"{baseline.get('clean_throughput_pps', 0):>12.1f} "
                  f"{mean(unmitigated, 'clean_throughput_pps'):>14.1f} "
                  f"{after.get('clean_throughput_pps', 0):>18.1f}")
        if recovery.get("recovery_time_s") is not None:
            print(f"\n  {GREEN}{BOLD}Recovery: legitimate packet loss returned to "
                  f"baseline {recovery['recovery_time_s']:.1f} s after the first "
                  f"rule was installed.{RESET}")
    elif not args.no_mitigation:
        print(f"\n  {YELLOW}No mitigation rule was installed: no node reached the "
              f"trigger probability of {trigger:.2f}.{RESET}")

    if controller is not None:
        report = controller.report()
        print()
        print(f"  Detector inference cost: {report['mean_inference_ms']:.1f} ms mean "
              f"per 5-second window ({report['max_inference_ms']:.1f} ms worst case)")
        print(f"  Bots flagged           : {len(report['attackers_flagged'])}"
              f"/{report['attackers_total']}")
        print(f"  Nodes falsely flagged  : {len(report['false_alarm_nodes'])}")

    banner("Demonstration complete")
    print(f"  Full artefacts     : data/experiments/{result.run_id}/")
    print("  Dashboard          : ./run.sh dashboard  ->  http://127.0.0.1:8000")
    print("  Full experiments   : python scripts/run_experiment.py --all")
    print("  Results report     : results/reports/RESULTS.md\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
