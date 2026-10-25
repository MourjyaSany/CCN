"""Tests for real-capture ingestion, rule export and the testbed agent."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest

dpkt = pytest.importorskip("dpkt")

from netshield.mitigation.export import PortMap, render, to_nftables, to_openflow, to_p4runtime  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def _ip(a: str) -> bytes:
    return bytes(int(x) for x in a.split("."))


def write_pcap(path: Path, flood_pps: int = 0, seconds: float = 5.0, t0: float = 1000.0) -> Path:
    """Write a synthetic capture: 6 quiet devices, optionally one UDP flooder."""
    with path.open("wb") as fh:
        w = dpkt.pcap.Writer(fh)
        events = []
        for d in range(6):
            for k in range(int(seconds / 0.5)):
                events.append((t0 + k * 0.5 + d * 0.01, f"192.168.1.{10 + d}", 8883, "tcp"))
        for k in range(int(flood_pps * seconds)):
            events.append((t0 + k / max(1, flood_pps), "192.168.1.99", 5683, "udp"))
        for ts, src, dport, kind in sorted(events):
            if kind == "tcp":
                l4 = dpkt.tcp.TCP(sport=40000, dport=dport, flags=dpkt.tcp.TH_ACK
                                  | dpkt.tcp.TH_PUSH, data=b"m" * 100)
                proto = dpkt.ip.IP_PROTO_TCP
            else:
                l4 = dpkt.udp.UDP(sport=50000, dport=dport, data=b"\x00" * 480)
                l4.ulen = len(l4)
                proto = dpkt.ip.IP_PROTO_UDP
            ip = dpkt.ip.IP(src=_ip(src), dst=_ip("10.0.0.1"), p=proto, data=l4)
            ip.len = len(ip)
            eth = dpkt.ethernet.Ethernet(src=b"\x02" * 6, dst=b"\x04" * 6,
                                         type=dpkt.ethernet.ETH_TYPE_IP, data=ip)
            w.writepkt(bytes(eth), ts=ts)
    return path


class TestPcapIngest:
    def test_ingest_produces_training_schema(self, tmp_path: Path) -> None:
        from netshield.features.node_features import NODE_FEATURE_COLUMNS, build_node_window_features
        from netshield.realnet.pcap_ingest import ingest_pcap

        view = ingest_pcap(write_pcap(tmp_path / "a.pcap", flood_pps=400, seconds=10.0))
        assert view.summary["hosts"] == 8   # 7 devices + the private 10.0.0.1 server
        feats = build_node_window_features(view)
        assert set(NODE_FEATURE_COLUMNS) <= set(feats.columns)
        flooder = feats[feats["node_id"] == "h-192.168.1.99"]
        quiet = feats[feats["node_id"] == "h-192.168.1.10"]
        assert flooder["eg_packet_rate"].mean() > 20 * quiet["eg_packet_rate"].mean()
        assert (feats["label"] == 0).all() and not feats["is_attacker"].any()

    def test_truncated_capture_is_read_up_to_the_cut(self, tmp_path: Path) -> None:
        from netshield.realnet.pcap_ingest import ingest_pcap

        full = write_pcap(tmp_path / "full.pcap", flood_pps=200, seconds=10.0)
        cut = tmp_path / "cut.pcap"
        data = full.read_bytes()
        cut.write_bytes(data[: len(data) // 2 + 7])          # mid-record cut
        assert 0 < ingest_pcap(cut).summary["packets"] < ingest_pcap(full).summary["packets"]

    def test_ingest_module_never_imports_socket(self) -> None:
        text = (ROOT / "src/netshield/realnet/pcap_ingest.py").read_text(encoding="utf-8")
        assert "import socket" not in text


class TestExport:
    ports = PortMap(ports={"h-a": 3}, interfaces={"h-a": "eth3"}, bridges={"h-a": "r1"})

    def test_openflow_rules(self) -> None:
        rl = to_openflow({"node": "h-a", "action": "rate_limit"}, self.ports)
        assert "add-meter r1 meter=1003" in rl[0] and "actions=meter:1003,NORMAL" in rl[1]
        blk = to_openflow({"node": "h-a", "action": "block"}, self.ports)
        assert blk[0].endswith("in_port=3,actions=drop")
        rel = to_openflow({"node": "h-a", "action": "release"}, self.ports)
        assert "del-flows r1" in rel[0] and "del-meter r1 meter=1003" in rel[1]

    def test_nft_and_p4(self) -> None:
        assert 'iifname "eth3" drop' in to_nftables({"node": "h-a", "action": "block"},
                                                    self.ports)[-1]
        entry = to_p4runtime({"node": "h-a", "action": "rate_limit"}, self.ports)[0]
        assert entry["match"]["standard_metadata.ingress_port"] == 3
        assert entry["action"] == "MyIngress.meter_and_forward"

    def test_escalation_replaces_previous_rule(self) -> None:
        cmds = render([{"node": "h-a", "action": "rate_limit"},
                       {"node": "h-a", "action": "block"}], "openflow", self.ports)
        kinds = [c.split()[3] for c in cmds]
        assert kinds == ["add-meter", "add-flow", "del-flows", "del-meter", "add-flow"]

    def test_unknown_node_raises(self) -> None:
        with pytest.raises(KeyError):
            to_openflow({"node": "h-zzz", "action": "block"}, self.ports)


class TestAgentReplay:
    def test_agent_flags_and_rules_the_flooder(self, tmp_path: Path, base_config: Any) -> None:
        import pandas as pd

        from netshield.features.node_features import build_node_window_features
        from netshield.graph.builder import build_edge_table
        from netshield.models.base import DetectionInput
        from netshield.models.random_forest import RandomForestDetector
        from netshield.realnet.pcap_ingest import ingest_pcap

        # Train a tiny model on synthetic captures: the flooder is the attacker.
        frames, edges = [], []
        for i, pps in enumerate((0, 300, 600, 0, 900)):
            view = ingest_pcap(write_pcap(tmp_path / f"t{i}.pcap", pps, 10.0), run_id=f"t{i}")
            f = build_node_window_features(view)
            bad = f["node_id"] == "h-192.168.1.99"
            f.loc[bad, "label"] = 2
            frames.append(f)
            edges.append(build_edge_table(view))
        train = DetectionInput(pd.concat(frames, ignore_index=True),
                               pd.concat(edges, ignore_index=True))
        det = RandomForestDetector.from_config(base_config)
        det.params["n_estimators"] = 30
        det.fit(train, train)

        spec = importlib.util.spec_from_file_location("agent", ROOT / "testbed/netshield_agent.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        pmap = {f"iot{d}": {"ip": f"192.168.1.{10 + d}", "bridge": "r0", "port": d + 1,
                            "bot": False} for d in range(6)}
        pmap["atk0"] = {"ip": "192.168.1.99", "bridge": "r2", "port": 7, "bot": True}
        agent = mod.Agent(det, pmap, base_config, dry_run=True)
        commands = []
        for w in range(4):
            commands += agent.process_window(write_pcap(tmp_path / f"live{w}.pcap", 800,
                                                        5.0, t0=2000.0 + 5 * w))
        assert commands, "agent issued no rules for an obvious flooder"
        assert all(" r2 " in c for c in commands if "add-flow" in c or "add-meter" in c)
        assert {a["host"] for a in agent.log} == {"atk0"}
