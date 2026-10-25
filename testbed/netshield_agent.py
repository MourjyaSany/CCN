#!/usr/bin/env python3
"""NetShield agent: score 5-second captures and push rules to Open vSwitch.

    python3 testbed/netshield_agent.py --capture-dir /tmp/netshield/capture \
        --port-map /tmp/netshield/port_map.json --model graphsage [--dry-run]

Loop: wait for each rotated capture file to close, ingest it with
``netshield.realnet.pcap_ingest`` (the simulator's own telemetry and feature
code), score it with the trained detector (with a history buffer for
temporal models), feed the scores to the same ``MitigationEngine`` policy as
the simulator, and render every new action as ``ovs-ofctl`` commands via
``netshield.mitigation.export``. ``--dry-run`` prints the commands instead
of executing them.

``process_window`` is importable and pure apart from the optional command
execution, so the loop can be replayed offline against any capture.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


class Agent:
    """Stateful scorer + policy engine + rule renderer."""

    def __init__(self, detector: Any, port_map: dict[str, dict], config: Any,
                 dry_run: bool = True) -> None:
        from netshield.mitigation.engine import MitigationEnforcer, MitigationEngine  # noqa
        from netshield.mitigation.export import PortMap  # noqa: PLC0415
        from netshield.mitigation.policy import PolicyConfig  # noqa: PLC0415

        self.detector = detector
        self.dry_run = dry_run
        self.window = 0
        self.history = max(1, int(getattr(detector, "history_windows", 1)))
        self.buffer: list = []
        policy = PolicyConfig.from_config(config).validate()
        # Map capture node ids (h-<ip>) to testbed hosts and switch ports.
        self.node_for_ip = {v["ip"]: name for name, v in port_map.items()}
        nodes = {f"h-{v['ip']}": v for v in port_map.values()}
        self.ports = PortMap(ports={n: v["port"] for n, v in nodes.items()},
                             bridges={n: v["bridge"] for n, v in nodes.items()})
        self.engine = MitigationEngine(policy, MitigationEnforcer(policy, {}),
                                       detector_name=detector.name)
        self.trigger = float(config.get("detection.mitigation_trigger_probability", 0.8))
        self.log: list[dict] = []

    def process_window(self, capture: Path) -> list[str]:
        """Score one capture file and return the rule commands it produced."""
        import pandas as pd  # noqa: PLC0415

        from netshield.features.node_features import build_node_window_features  # noqa
        from netshield.graph.builder import build_edge_table  # noqa: PLC0415
        from netshield.mitigation.export import render  # noqa: PLC0415
        from netshield.models.base import DetectionInput  # noqa: PLC0415
        from netshield.realnet.pcap_ingest import ingest_pcap  # noqa: PLC0415

        view = ingest_pcap(capture, window_s=5.0, max_packets=None, run_id="live")
        if not view.flows:
            self.window += 1
            return []
        features = build_node_window_features(view)
        edges = build_edge_table(view)
        features["window"] = self.window
        edges["window"] = self.window
        self.buffer = (self.buffer + [(features, edges)])[-self.history:]
        data = DetectionInput(pd.concat([f for f, _ in self.buffer], ignore_index=True),
                              pd.concat([e for _, e in self.buffer], ignore_index=True))
        proba = self.detector.predict_proba(data)
        current = (data.features["window"] == self.window).to_numpy()
        frame = data.features.loc[current, ["node_id", "kind"]].copy()
        frame["p"] = proba[current, 1] + proba[current, 2]
        frame["pred"] = proba[current].argmax(1)
        endpoints = frame[frame["kind"] == "iot"]
        scores = dict(zip(endpoints["node_id"], endpoints["p"]))
        names = ("BENIGN", "SUSPICIOUS", "MALICIOUS")
        predicted = {n: names[int(c)] for n, c in zip(endpoints["node_id"], endpoints["pred"])}
        actions = self.engine.apply_window(window=self.window, t=self.window * 5.0,
                                           scores=scores, predicted=predicted)
        mapped = [a for a in actions if a.node in self.ports.ports]
        commands = render(mapped, "openflow", self.ports)
        for a in mapped:
            self.log.append({**a.to_dict(), "host": self.node_for_ip.get(a.node[2:], "")})
        if not self.dry_run:
            for cmd in commands:
                subprocess.run(cmd, shell=True, check=False)
        self.window += 1
        return commands


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--capture-dir", required=True)
    ap.add_argument("--port-map", required=True)
    ap.add_argument("--model", default="graphsage")
    ap.add_argument("--models-dir", default=str(ROOT / "results/research/predictions/final__all"))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--once", action="store_true", help="Process existing files and exit.")
    args = ap.parse_args()

    from netshield.detection.pipeline import load_detectors  # noqa: PLC0415
    from netshield.utils.config import load_config  # noqa: PLC0415

    config = load_config()
    detector = load_detectors(args.models_dir, [args.model], required=True)[args.model]
    agent = Agent(detector, json.loads(Path(args.port_map).read_text()), config, args.dry_run)
    seen: set[Path] = set()
    capture = Path(args.capture_dir)
    while True:
        files = sorted(capture.glob("win-*.pcap"))
        # The newest file is still being written by tcpdump; skip it.
        ready = files if args.once else files[:-1]
        for path in ready:
            if path in seen:
                continue
            seen.add(path)
            for cmd in agent.process_window(path):
                print(("DRY " if args.dry_run else "") + cmd, flush=True)
        if args.once:
            break
        time.sleep(1.0)
    Path(capture.parent / "agent_actions.json").write_text(json.dumps(agent.log, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
