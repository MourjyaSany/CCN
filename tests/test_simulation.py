"""Network-simulation behaviour.

These tests assert *networking* properties, not just that the code runs:
routing is a tree, queues are finite, latency is the sum of the physical delays
on the path, congestion causes loss, and a SYN flood exhausts a finite backlog
while consuming almost no bandwidth.
"""

from __future__ import annotations

from typing import Any

import pytest

from netshield.simulation.packet import (
    IPV4_HEADER,
    MSS,
    Protocol,
    TCPFlag,
    wire_size,
)
from netshield.simulation.topology import (
    NodeKind,
    build_topology,
    layout_positions,
    spoofed_ip_pool,
)
from netshield.utils.config import Config


class TestPacketPrimitives:
    """Header accounting and flag handling."""

    def test_wire_size_includes_every_header_layer(self) -> None:
        payload = 500
        tcp = wire_size(payload, Protocol.TCP)
        udp = wire_size(payload, Protocol.UDP)
        assert tcp > payload + IPV4_HEADER
        assert tcp - udp == 12, "TCP header is 12 bytes larger than UDP's"

    def test_wire_size_respects_the_minimum_ethernet_frame(self) -> None:
        assert wire_size(0, Protocol.UDP) == 64
        assert wire_size(1, Protocol.TCP) >= 64

    def test_mss_matches_a_1500_byte_mtu(self) -> None:
        assert MSS == 1460

    def test_protocol_names_round_trip(self) -> None:
        assert Protocol.name(Protocol.TCP) == "TCP"
        assert Protocol.from_name("udp") == Protocol.UDP
        with pytest.raises(ValueError, match="Unknown protocol"):
            Protocol.from_name("carrier-pigeon")

    def test_tcp_flag_description(self) -> None:
        assert TCPFlag.describe(int(TCPFlag.SYN | TCPFlag.ACK)) == "SYN|ACK"
        assert TCPFlag.describe(0) == "-"


class TestTopology:
    """The tiered topology and its routing table."""

    def test_tiers_are_wired_in_the_documented_order(self, attack_config: Config) -> None:
        topo = build_topology(attack_config)
        kinds = {n.kind for n in topo.nodes.values()}
        assert kinds == {NodeKind.IOT, NodeKind.ATTACKER, NodeKind.ROUTER,
                         NodeKind.GATEWAY, NodeKind.CLOUD}
        cloud = topo.nodes[topo.cloud_id]
        gateway = topo.nodes[topo.gateway_id]
        assert cloud.tier == 0 and gateway.tier == 1
        assert gateway.parent == cloud.node_id

    def test_every_endpoint_routes_to_the_cloud_through_the_gateway(
        self, attack_config: Config
    ) -> None:
        topo = build_topology(attack_config)
        for node in topo.endpoints():
            path = topo.path(node.node_id, topo.cloud_id)
            assert path[0] == node.node_id
            assert path[-1] == topo.cloud_id
            assert topo.gateway_id in path, "the gateway must be the choke point"
            assert len(path) == 4, "device -> router -> gateway -> cloud"

    def test_links_are_full_duplex_with_independent_queues(
        self, attack_config: Config
    ) -> None:
        topo = build_topology(attack_config)
        up = topo.channel(topo.gateway_id, topo.cloud_id)
        down = topo.channel(topo.cloud_id, topo.gateway_id)
        assert up is not down
        assert up.queue is not down.queue
        assert up.bandwidth_bps == down.bandwidth_bps

    def test_serialisation_time_follows_bandwidth(self, attack_config: Config) -> None:
        topo = build_topology(attack_config)
        channel = topo.uplink_channel()
        # 1250 bytes = 10 000 bits; at 20 Mbps that is 0.5 ms.
        assert channel.service_time(1250) == pytest.approx(
            10000 / channel.bandwidth_bps, rel=1e-9
        )

    def test_ip_addresses_are_unique(self, attack_config: Config) -> None:
        topo = build_topology(attack_config)
        ips = [n.ip for n in topo.nodes.values()]
        assert len(ips) == len(set(ips))

    def test_attackers_also_carry_a_legitimate_device_class(
        self, attack_config: Config
    ) -> None:
        # Compromised nodes keep doing their day job; that is what makes the
        # detection problem three-class rather than a trivial on/off split.
        topo = build_topology(attack_config)
        for node in topo.attackers():
            assert node.device_class, "an attacker must still have a device class"

    def test_topology_is_deterministic_for_a_fixed_seed(
        self, attack_config: Config
    ) -> None:
        a = build_topology(attack_config)
        b = build_topology(attack_config)
        assert [n.to_dict() for n in a.nodes.values()] == \
               [n.to_dict() for n in b.nodes.values()]

    def test_spoof_pool_never_collides_with_a_real_node(
        self, attack_config: Config
    ) -> None:
        topo = build_topology(attack_config)
        pool = spoofed_ip_pool(48, seed=1)
        assert len(set(pool)) == 48
        assert not (set(pool) & set(topo.ip_to_node))

    def test_layout_positions_cover_every_node(self, attack_config: Config) -> None:
        topo = build_topology(attack_config)
        positions = layout_positions(topo)
        assert set(positions) == set(topo.nodes)


class TestBenignRun:
    """A network with no attacker must behave like a healthy network."""

    def test_run_produces_windows_and_flows(self, benign_result: Any) -> None:
        assert benign_result.windows, "no window metrics produced"
        assert benign_result.flows, "no flow records exported"
        assert benign_result.summary["packets_generated"] > 0

    def test_no_attack_traffic_is_generated(self, benign_result: Any) -> None:
        assert benign_result.summary["attack_packets"] == 0
        assert all(w["attack_offered"] == 0 for w in benign_result.windows)

    def test_loss_is_negligible_without_congestion(self, benign_result: Any) -> None:
        assert benign_result.summary["overall_loss_ratio"] < 0.02

    def test_latency_matches_the_physical_path_delay(self, benign_result: Any) -> None:
        # One-way propagation is 1.5 (access) + 3.0 (aggregation) + 12.0 (uplink)
        # = 16.5 ms, plus serialisation and queueing. Anything far from that
        # means the store-and-forward model is wrong.
        mean_latency = benign_result.summary["mean_latency_ms"]
        assert 16.5 <= mean_latency < 60.0, f"implausible latency {mean_latency} ms"

    def test_tcp_handshakes_complete(self, benign_result: Any) -> None:
        assert benign_result.server["handshakes_completed"] > 0, (
            "no TCP connection was established; the protocol stack is broken"
        )
        assert benign_result.server["syn_rejected"] == 0

    def test_legitimate_devices_deliver_their_messages(self, benign_result: Any) -> None:
        attempted = sum(a["messages_attempted"] for a in benign_result.applications)
        sent = sum(a["messages_sent"] for a in benign_result.applications)
        assert attempted > 0
        assert sent / attempted > 0.85

    def test_uplink_is_far_from_saturated(self, benign_result: Any) -> None:
        assert max(w["uplink_utilisation"] for w in benign_result.windows) < 0.5

    def test_every_device_class_is_represented(self, benign_result: Any) -> None:
        classes = {a["device_class"] for a in benign_result.applications}
        assert len(classes) >= 3


class TestVolumetricAttack:
    """A UDP flood must physically congest the bottleneck link."""

    def test_attack_traffic_dominates(self, attack_result: Any) -> None:
        assert attack_result.summary["attack_fraction"] > 0.5

    def test_uplink_saturates_during_the_attack(self, attack_result: Any) -> None:
        attack = attack_result.summary["attack"]
        during = [w for w in attack_result.windows
                  if attack["start_s"] <= w["t_start"] < attack["end_s"]]
        assert during, "no window falls inside the attack interval"
        assert max(w["uplink_utilisation"] for w in during) > 0.9

    def test_congestion_causes_drop_tail_loss(self, attack_result: Any) -> None:
        attack = attack_result.summary["attack"]
        during = [w for w in attack_result.windows
                  if attack["start_s"] <= w["t_start"] < attack["end_s"]]
        assert max(w["loss_ratio"] for w in during) > 0.05
        assert sum(w["congestion_drops"] for w in during) > 0

    def test_latency_rises_under_congestion(self, attack_result: Any) -> None:
        attack = attack_result.summary["attack"]
        before = [w for w in attack_result.windows if w["t_end"] <= attack["start_s"]]
        during = [w for w in attack_result.windows
                  if attack["start_s"] <= w["t_start"] < attack["end_s"]]
        baseline = sum(w["mean_latency_ms"] for w in before) / len(before)
        peak = max(w["mean_latency_ms"] for w in during)
        assert peak > baseline * 1.5, "queueing delay did not increase under load"

    def test_legitimate_traffic_suffers_collateral_damage(
        self, attack_result: Any
    ) -> None:
        attack = attack_result.summary["attack"]
        during = [w for w in attack_result.windows
                  if attack["start_s"] <= w["t_start"] < attack["end_s"]]
        assert max(w["legit_loss_ratio"] for w in during) > 0.0

    def test_network_recovers_after_the_attack_stops(self, attack_result: Any) -> None:
        attack = attack_result.summary["attack"]
        after = [w for w in attack_result.windows if w["t_start"] >= attack["end_s"]]
        if not after:
            pytest.skip("scenario ends with the attack; nothing to measure")
        assert after[-1]["loss_ratio"] < 0.02
        assert after[-1]["uplink_utilisation"] < 0.5

    def test_throughput_never_exceeds_link_capacity(self, attack_result: Any) -> None:
        capacity_mbps = float(
            attack_result.config["network"]["topology"]["gateway"]["uplink"]
            ["bandwidth_bps"]
        ) / 1e6
        for window in attack_result.windows:
            assert window["throughput_mbps"] <= capacity_mbps * 1.02, (
                "delivered goodput exceeded the physical link capacity"
            )


class TestSynFlood:
    """A SYN flood is a state-exhaustion attack, not a bandwidth attack."""

    def test_backlog_is_exhausted(self, syn_flood_result: Any) -> None:
        server = syn_flood_result.server
        assert server["syn_received"] > server["backlog_capacity"]
        assert server["syn_rejected"] > 0, "the finite backlog never filled"

    def test_half_open_table_is_capped_at_the_backlog(self, syn_flood_result: Any) -> None:
        server = syn_flood_result.server
        assert server["half_open_peak"] <= server["backlog_capacity"]

    def test_spoofed_sources_produce_backscatter(self, syn_flood_result: Any) -> None:
        # SYN+ACKs addressed to spoofed sources cannot be routed; they consume
        # downstream bandwidth and are accounted, not silently discarded.
        assert syn_flood_result.server["unroutable_synacks"] > 0

    def test_bandwidth_cost_is_low_relative_to_a_volumetric_flood(
        self, syn_flood_result: Any, attack_result: Any
    ) -> None:
        syn_peak = max(w["uplink_utilisation"] for w in syn_flood_result.windows)
        udp_peak = max(w["uplink_utilisation"] for w in attack_result.windows)
        assert syn_peak < udp_peak, (
            "a minimum-size SYN flood must use less bandwidth than a 512-byte "
            "UDP flood at a comparable packet rate"
        )


class TestReproducibility:
    """Identical configuration and seed must give identical telemetry."""

    def test_same_seed_gives_identical_results(self, benign_config: Config) -> None:
        from netshield.simulation.runner import run_simulation

        a = run_simulation(benign_config, {"experiment": "repro"})
        b = run_simulation(benign_config, {"experiment": "repro"})
        assert a.run_id == b.run_id
        assert a.summary["packets_generated"] == b.summary["packets_generated"]
        assert a.summary["packets_dropped"] == b.summary["packets_dropped"]
        assert a.flows == b.flows

    def test_different_seed_gives_different_telemetry(self, benign_config: Config) -> None:
        from netshield.simulation.runner import run_simulation

        a = run_simulation(benign_config, {"experiment": "repro"})
        b = run_simulation(benign_config.with_set(["seed=98765"]),
                           {"experiment": "repro"})
        assert a.summary["packets_generated"] != b.summary["packets_generated"]


class TestSaveLoadRoundTrip:
    """Runs must reload from disk so figures never require re-simulation."""

    def test_round_trip_preserves_the_run(self, benign_result: Any, tmp_path: Any) -> None:
        from netshield.simulation.runner import SimulationResult

        benign_result.save(tmp_path / benign_result.run_id)
        restored = SimulationResult.load(tmp_path / benign_result.run_id)
        assert restored.run_id == benign_result.run_id
        assert restored.engine == benign_result.engine
        assert len(restored.windows) == len(benign_result.windows)
        assert len(restored.flows) == len(benign_result.flows)
        assert restored.topology["n_nodes"] == benign_result.topology["n_nodes"]
        assert isinstance(restored.windows[0]["throughput_mbps"], float)
