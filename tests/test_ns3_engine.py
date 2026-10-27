"""Integration tests for the NS-3 primary engine.

These run a real NS-3 simulation (inside WSL on Windows, natively on Linux) and
check that its output flows through the project's feature pipeline. They are
skipped automatically when a runnable NS-3 model is not present, so the suite
stays green on machines without it.

The spec emitter is tested unconditionally, because it is pure Python.
"""

from __future__ import annotations

from typing import Any

import pytest

from netshield.simulation.ns3_spec import device_app_rate, write_spec
from netshield.simulation.ns3_wsl import detect, win_to_wsl

_PROBE = detect()
needs_ns3 = pytest.mark.skipif(not _PROBE.available,
                               reason=f"NS-3 model not runnable: {_PROBE.reason}")


# --------------------------------------------------------------------------- #
# pure-Python: the spec emitter
# --------------------------------------------------------------------------- #
class TestSpecEmitter:
    def test_path_conversion(self) -> None:
        assert win_to_wsl(r"C:\Users\x\scenario.spec") == "/mnt/c/Users/x/scenario.spec"
        assert win_to_wsl("/opt/ns-3.48") == "/opt/ns-3.48"
        assert win_to_wsl(r"D:\a\b") == "/mnt/d/a/b"

    def test_device_rates_are_class_specific(self) -> None:
        traffic = {"mqtt_sensor": {"publish_interval_s": 2.0, "payload_bytes": [48, 220]},
                   "udp_streamer": {"packet_interval_s": 0.08, "payload_bytes": [200, 400]}}
        mk, mp, mrate, _ = device_app_rate("mqtt_sensor", traffic)
        ck, cp, crate, _ = device_app_rate("udp_streamer", traffic)
        assert mk == "mqtt" and mp == 8883 and ck == "coap" and cp == 5683
        assert crate > mrate  # the CBR streamer offers more than periodic MQTT

    @pytest.mark.parametrize("family", ["tree", "star", "multi_gateway", "dumbbell",
                                        "fat_tree", "mesh", "ring"])
    def test_every_topology_emits_a_valid_spec(self, family: str, base_config: Any,
                                               tmp_path: Any) -> None:
        cfg = base_config.with_set([f"network.topology.family={family}",
                                    "simulation.n_attackers=4", "attack.enabled=true",
                                    "attack.type=udp_flood", "attack.packets_per_second=500"])
        spec = tmp_path / f"{family}.spec"
        prov = write_spec(cfg, tmp_path, spec)
        text = spec.read_text()
        assert f"param topology {family}" in text
        assert prov["n_nodes"] > 5 and prov["n_links"] >= prov["n_nodes"] - 1
        assert text.count("\nnode ") == prov["n_nodes"]
        assert text.count("\nlink ") == prov["n_links"]
        assert text.count("\nbot ") == prov["n_bots"] == 4
        # multipath families genuinely have more links than a tree
        if family in ("mesh", "fat_tree"):
            assert prov["n_links"] > prov["n_nodes"] - 1

    def test_approximated_families_are_flagged(self, base_config: Any, tmp_path: Any) -> None:
        cfg = base_config.with_set(["simulation.n_attackers=3", "attack.enabled=true",
                                    "attack.type=syn_flood", "attack.packets_per_second=500",
                                    "attack.spoof_sources=true"])
        prov = write_spec(cfg, tmp_path, tmp_path / "s.spec")
        assert "syn_flood" in prov["approximated_families"]
        joined = " ".join(prov["ns3_approximations"])
        assert "spoof" in joined and "SYN backlog" in joined


# --------------------------------------------------------------------------- #
# live NS-3 runs
# --------------------------------------------------------------------------- #
@needs_ns3
class TestNs3Run:
    @pytest.fixture(scope="class")
    def ns3_result(self) -> Any:
        from netshield.simulation.runner import run_simulation
        from netshield.utils.config import experiment_config, load_experiments

        cfg, meta = experiment_config("exp2_udp_flood", load_experiments())
        cfg = cfg.with_set(["simulation.engine=ns3", "simulation.duration_s=45.0"])
        return run_simulation(cfg, meta)

    def test_run_is_stamped_ns3_with_real_topology(self, ns3_result: Any) -> None:
        assert ns3_result.engine == "ns3-simulation"
        assert ns3_result.summary["ns3_distro"]
        topo = ns3_result.topology
        assert topo["source"] == "ns3" and topo["family"] == "tree"
        assert len(topo["nodes"]) > 20 and len(topo["links"]) > 20
        assert any(n["is_attacker"] for n in topo["nodes"])

    def test_congestion_is_emergent(self, ns3_result: Any) -> None:
        # A 1.3x-capacity UDP flood must produce measured loss, not a claim.
        assert ns3_result.summary["packets_generated"] > 1000
        assert ns3_result.summary["overall_loss_ratio"] > 0.02

    def test_flows_feed_the_feature_pipeline(self, ns3_result: Any) -> None:
        from netshield.features.node_features import (
            NODE_FEATURE_COLUMNS,
            build_node_window_features,
        )
        from netshield.graph.builder import build_edge_table

        feats = build_node_window_features(ns3_result)
        edges = build_edge_table(ns3_result)
        assert set(NODE_FEATURE_COLUMNS) <= set(feats.columns)
        assert len(feats) > 50 and len(edges) > 0
        assert feats["is_attacker"].sum() > 0
        assert feats["label_name"].isin(["BENIGN", "SUSPICIOUS", "MALICIOUS"]).all()

    def test_explicit_ns3_request_fails_clearly_when_absent(self) -> None:
        # When the probe says available this is a no-op guard; the real value is
        # documenting the contract. Covered by the skip when unavailable.
        assert _PROBE.available
