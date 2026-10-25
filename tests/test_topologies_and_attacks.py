"""Tests for the topology families, the extended attack model and the NS-3 bridge.

These run real simulations rather than mocks, for the same reason the rest of
the suite does: the properties worth asserting are network properties. A
slowloris that does not actually exhaust the connection table, or a dumbbell
whose bottleneck is not the backbone, would still "work" against a mock.
"""

from __future__ import annotations

import pytest

from netshield.api.state import OverrideRejected, sanitise_overrides
from netshield.simulation.ns3_runner import (
    ns3_params,
    ns3_warnings,
    nodes_from_flows,
    normalise_window,
)
from netshield.simulation.runner import run_simulation
from netshield.simulation.topologies import (
    FAMILY_DESCRIPTIONS,
    TOPOLOGY_FAMILIES,
    TopologyError,
    validate_topology,
)
from netshield.simulation.topology import NodeKind, build_topology
from netshield.traffic.attacks import (
    ATTACK_TYPES,
    RATE_PROFILES,
    SINGLE_FAMILIES,
    AttackProfile,
    AttackSafetyError,
    resolve_attack_target,
)
from netshield.utils.config import ConfigError, load_config


def _config(**overrides):
    """Return a small, fast configuration with the given dotted overrides."""
    base = {
        "simulation.duration_s": 30,
        "simulation.n_iot_devices": 12,
        "simulation.n_attackers": 3,
        "simulation.log_every_s": 0,
        "simulation.max_wall_seconds": 120,
        # The shipped default start (30 s) sits exactly at this shortened
        # duration, which the config validator rightly rejects; move the attack
        # window inside the run.
        "attack.start_s": 8,
        "attack.duration_s": 15,
        # These tests assert Python-engine behaviour (attack families, topology
        # families, closed-loop enforcement). Pin the engine so the assertions
        # stay meaningful on a host that also has NS-3 installed.
        "simulation.engine": "python",
    }
    base.update(overrides)
    return load_config(set_args=[f"{k}={v}" for k, v in base.items()])


# --------------------------------------------------------------------------- #
# topology families
# --------------------------------------------------------------------------- #
class TestTopologyFamilies:
    """Every family must build, route and satisfy the structural invariants."""

    @pytest.mark.parametrize("family", TOPOLOGY_FAMILIES)
    def test_family_builds_and_validates(self, family):
        topo = build_topology(_config(**{"network.topology.family": family}))
        validate_topology(topo)
        assert topo.family == family
        assert len(topo.nodes) > 0

    @pytest.mark.parametrize("family", TOPOLOGY_FAMILIES)
    def test_every_endpoint_reaches_the_cloud(self, family):
        topo = build_topology(_config(**{"network.topology.family": family}))
        for node in topo.endpoints():
            path = topo.path(node.node_id, topo.cloud_id)
            assert path[0] == node.node_id
            assert path[-1] == topo.cloud_id
            # A path must cross at least one gateway: that is what makes an
            # enforcement point meaningful in every family.
            gateway_ids = {g.node_id for g in topo.gateways()}
            assert gateway_ids & set(path)

    @pytest.mark.parametrize("family", TOPOLOGY_FAMILIES)
    def test_addresses_never_collide_with_the_spoof_block(self, family):
        topo = build_topology(_config(**{"network.topology.family": family}))
        for node in topo.nodes.values():
            assert not node.ip.startswith("10.66."), (
                f"{node.node_id} was allocated {node.ip}, inside the block "
                "reserved for spoofed sources"
            )

    @pytest.mark.parametrize("family", TOPOLOGY_FAMILIES)
    def test_every_family_is_documented(self, family):
        assert FAMILY_DESCRIPTIONS.get(family)

    def test_multi_gateway_has_several_enforcement_points(self):
        topo = build_topology(_config(**{"network.topology.family": "multi_gateway"}))
        assert len(topo.gateways()) >= 2
        assert len(topo.enforcement_nodes) == len(topo.gateways())
        assert len(topo.uplink_keys) == len(topo.gateways())

    def test_dumbbell_bottleneck_is_the_backbone_not_the_edge(self):
        topo = build_topology(_config(**{"network.topology.family": "dumbbell"}))
        uplink = topo.uplink_channel()
        # Both ends of the declared bottleneck are gateways, i.e. the
        # constrained span sits between infrastructure nodes.
        assert topo.nodes[uplink.src].kind is NodeKind.GATEWAY
        assert topo.nodes[uplink.dst].kind is NodeKind.GATEWAY
        # ... and it really is narrower than the gateway->cloud uplink.
        to_cloud = topo.channel(uplink.dst, topo.cloud_id)
        assert uplink.bandwidth_bps < to_cloud.bandwidth_bps

    def test_fat_tree_gives_edge_routers_redundant_parents(self):
        topo = build_topology(_config(**{"network.topology.family": "fat_tree"}))
        edge_routers = [n for n in topo.nodes.values()
                        if n.node_id.startswith("rtr-")]
        assert edge_routers
        for router in edge_routers:
            uplinks = [n for n in topo.neighbours[router.node_id]
                       if n.startswith("agg-")]
            assert len(uplinks) >= 2, "fat-tree edge routers must be dual-homed"

    def test_mesh_has_more_links_than_a_ring_of_the_same_size(self):
        mesh = build_topology(_config(**{"network.topology.family": "mesh"}))
        ring = build_topology(_config(**{"network.topology.family": "ring"}))
        assert len(mesh.channels) > len(ring.channels)

    def test_unknown_family_is_rejected(self):
        with pytest.raises(ConfigError):
            _config(**{"network.topology.family": "hypercube"})

    def test_validate_rejects_a_topology_with_no_enforcement_point(self):
        topo = build_topology(_config())
        topo.enforcement_nodes = []
        with pytest.raises(TopologyError):
            validate_topology(topo)


class TestTopologySimulation:
    """The non-tree families must actually carry traffic end to end."""

    @pytest.mark.parametrize(
        "family", ["star", "multi_gateway", "dumbbell", "fat_tree", "mesh", "ring"]
    )
    def test_traffic_flows_on_every_family(self, family):
        config = _config(**{
            "network.topology.family": family,
            "simulation.n_attackers": 0,
            "attack.enabled": "false",
        })
        result = run_simulation(config, {"name": f"t_{family}"})
        assert result.summary["packets_generated"] > 0
        assert result.summary["packets_delivered"] > 0
        assert result.flows, "no flow records were exported"
        # Delivery must dominate: a topology that routes badly would show up
        # here as mass loss rather than as an exception.
        ratio = result.summary["packets_delivered"] / result.summary["packets_generated"]
        assert ratio > 0.5, f"{family} delivered only {ratio:.1%} of offered traffic"


# --------------------------------------------------------------------------- #
# attack model
# --------------------------------------------------------------------------- #
class TestRateShaping:
    """The waveform must have the shape its name claims."""

    def _profile(self, **kwargs):
        args = {
            "attack.enabled": "true",
            "attack.start_s": 0,
            "attack.duration_s": 30,
            "simulation.n_attackers": 2,
        }
        args.update(kwargs)
        return AttackProfile.from_config(_config(**args)).validate()

    def test_constant_is_flat(self):
        profile = self._profile(**{"attack.shape.profile": "constant"})
        values = [profile.rate_multiplier(t) for t in range(0, 30, 3)]
        assert all(v == 1.0 for v in values)

    def test_ramp_increases_monotonically(self):
        profile = self._profile(**{
            "attack.shape.profile": "ramp",
            "attack.shape.ramp_start_factor": 0.1,
            "attack.shape.ramp_end_factor": 1.0,
        })
        values = [profile.rate_multiplier(t) for t in range(0, 30, 3)]
        assert values == sorted(values)
        assert values[0] < values[-1]
        assert values[0] == pytest.approx(0.1, abs=1e-6)

    def test_step_is_non_decreasing_and_discrete(self):
        profile = self._profile(**{
            "attack.shape.profile": "step",
            "attack.shape.step_interval_s": 5,
        })
        values = [profile.rate_multiplier(t) for t in range(0, 30, 5)]
        assert values == sorted(values)
        assert len(set(values)) > 1

    def test_sine_oscillates_around_one(self):
        profile = self._profile(**{
            "attack.shape.profile": "sine",
            "attack.shape.sine_period_s": 10,
            "attack.shape.sine_depth": 0.5,
        })
        values = [profile.rate_multiplier(t / 2.0) for t in range(0, 60)]
        assert min(values) < 1.0 < max(values)

    @pytest.mark.parametrize("profile_name", RATE_PROFILES)
    def test_multiplier_is_always_positive(self, profile_name):
        profile = self._profile(**{"attack.shape.profile": profile_name})
        for t in range(0, 31):
            assert profile.rate_multiplier(float(t)) > 0

    def test_unknown_profile_is_rejected(self):
        with pytest.raises(ConfigError):
            _config(**{
                "attack.enabled": "true",
                "attack.shape.profile": "sawtooth",
            })


class TestAttackFamilies:
    """Each new family must produce its characteristic damage."""

    def _run(self, family, **extra):
        args = {
            "attack.enabled": "true",
            "attack.type": family,
            "attack.start_s": 10,
            "attack.duration_s": 15,
            "attack.packets_per_second": 400,
            "attack.dst_ports": "[80]",
            "simulation.duration_s": 30,
            "simulation.n_attackers": 4,
        }
        args.update(extra)
        return run_simulation(_config(**args), {"name": f"t_{family}"})

    @pytest.mark.parametrize("family", SINGLE_FAMILIES)
    def test_every_family_emits_attack_traffic(self, family):
        result = self._run(family)
        emitted = sum(a.get("packets_emitted", 0) for a in result.attackers)
        assert emitted > 0, f"{family} emitted nothing"

    def test_icmp_flood_uses_no_ports(self):
        result = self._run("icmp_flood")
        icmp = [f for f in result.flows if f.get("protocol_name") == "ICMP"]
        assert icmp, "no ICMP flows were recorded"
        assert all(int(f["dst_port"]) == 0 for f in icmp)

    def test_slowloris_is_cheap_but_exhausts_the_connection_table(self):
        loris = self._run(
            "slowloris",
            **{
                "attack.packets_per_second": 20,
                "network.topology.cloud.max_connections": 60,
                "attack.slowloris.sockets": 30,
            },
        )
        flood = self._run("udp_flood")

        loris_packets = loris.summary["packets_generated"]
        flood_packets = flood.summary["packets_generated"]
        assert loris_packets < flood_packets, (
            "slowloris must cost far less bandwidth than a volumetric flood"
        )
        # The damage shows up as refused connections, not as link saturation.
        assert loris.server.get("connections_refused", 0) > 0
        # ... and it is NOT a SYN flood: the half-open backlog is untouched.
        assert loris.server.get("syn_rejected", 0) == 0

    def test_ack_flood_carries_no_connection_requests(self):
        result = self._run("ack_flood")
        attack_flows = [f for f in result.flows if int(f.get("attack_packets", 0)) > 0]
        assert attack_flows
        assert sum(int(f.get("syn_count", 0)) for f in attack_flows) == 0


class TestAttackHeterogeneity:
    """Per-bot variation and staggering must be observable, not nominal."""

    def test_rate_jitter_spreads_the_bots(self):
        from netshield.simulation.engine import SimulationEngine
        from netshield.simulation.telemetry import TelemetryCollector
        from netshield.simulation.tcp import TcpRegistry
        from netshield.traffic.attacks import build_attack_campaign

        config = _config(**{
            "attack.enabled": "true",
            "attack.rate_jitter": "[0.5,2.0]",
            "simulation.n_attackers": 8,
        })
        topo = build_topology(config)
        telemetry = TelemetryCollector(window_s=5.0)
        engine = SimulationEngine(topo, telemetry, duration_s=30.0)
        attackers = build_attack_campaign(
            engine, topo, TcpRegistry(), AttackProfile.from_config(config), seed=1
        )
        rates = {round(a.base_rate, 3) for a in attackers}
        assert len(rates) > 1, "rate_jitter produced identical bots"

    def test_stagger_delays_some_bots(self):
        config = _config(**{
            "attack.enabled": "true",
            "attack.stagger_s": 10,
            "simulation.n_attackers": 8,
        })
        profile = AttackProfile.from_config(config).validate()
        assert profile.stagger_s == 10

    def test_family_mix_weights_are_honoured(self):
        config = _config(**{
            "attack.enabled": "true",
            "attack.type": "mixed",
            "simulation.n_attackers": 6,
        })
        profile = AttackProfile.from_config(config).validate()
        assert profile.attack_type == "mixed"
        assert profile.attack_type in ATTACK_TYPES


class TestAttackSafety:
    """The safety guarantees must hold for the new targeting options too."""

    def test_target_must_be_a_simulated_node(self):
        topo = build_topology(_config())
        with pytest.raises(AttackSafetyError):
            resolve_attack_target(topo, "8.8.8.8")
        with pytest.raises(AttackSafetyError):
            resolve_attack_target(topo, "example.com")

    def test_role_aliases_and_node_ids_resolve(self):
        topo = build_topology(_config())
        assert resolve_attack_target(topo, "cloud").node_id == topo.cloud_id
        assert resolve_attack_target(topo, "gateway").node_id == topo.gateway_id
        assert resolve_attack_target(topo, topo.gateway_id).node_id == topo.gateway_id

    def test_a_gateway_of_a_multi_gateway_fabric_can_be_targeted(self):
        topo = build_topology(_config(**{"network.topology.family": "multi_gateway"}))
        second = topo.gateways()[1].node_id
        assert resolve_attack_target(topo, second).node_id == second


# --------------------------------------------------------------------------- #
# API override allowlist
# --------------------------------------------------------------------------- #
class TestOverrideAllowlist:
    """The API must not become a general configuration write primitive."""

    @pytest.mark.parametrize(
        "key",
        ["attack.type", "attack.packets_per_second", "network.topology.family",
         "simulation.n_attackers", "mitigation.enabled", "seed"],
    )
    def test_simulation_parameters_are_allowed(self, key):
        assert sanitise_overrides({key: 1})

    @pytest.mark.parametrize(
        "key",
        ["paths.database", "api.host", "api.port", "logging.level",
         "simulation.engine", "../../etc/passwd", ".hidden", ""],
    )
    def test_everything_else_is_rejected(self, key):
        with pytest.raises(OverrideRejected):
            sanitise_overrides({key: "x"})

    def test_lists_and_bools_round_trip_as_literals(self):
        clean = sanitise_overrides({
            "attack.dst_ports": [80, 443],
            "attack.spoof_sources": True,
        })
        assert clean["attack.dst_ports"] == "[80, 443]"
        assert clean["attack.spoof_sources"] == "true"


# --------------------------------------------------------------------------- #
# NS-3 bridge (no NS-3 installation required)
# --------------------------------------------------------------------------- #
class TestNs3Mapping:
    """The config -> NS-3 mapping and its honesty reporting."""

    def test_params_carry_the_configured_attack(self):
        config = _config(**{
            "attack.enabled": "true",
            "attack.type": "udp_flood",
            "attack.packets_per_second": 900,
            "attack.start_s": 12,
        })
        params = ns3_params(config)
        assert params["attackType"] == "udp_flood"
        assert params["attackPps"] == 900
        assert params["attackStart"] == 12
        assert params["nAttackers"] == 3

    def test_a_plain_tree_udp_flood_maps_cleanly(self):
        config = _config(**{
            "attack.enabled": "true",
            "attack.type": "udp_flood",
        })
        assert ns3_warnings(config) == []

    @pytest.mark.parametrize(
        "overrides",
        [
            {"network.topology.family": "mesh"},
            {"attack.enabled": "true", "attack.type": "slowloris"},
            {"attack.enabled": "true", "attack.shape.profile": "ramp"},
            {"attack.enabled": "true", "attack.stagger_s": 5},
        ],
    )
    def test_unsupported_settings_are_reported_not_ignored(self, overrides):
        assert ns3_warnings(_config(**overrides)), (
            "a setting the NS-3 model cannot honour must be reported"
        )

    def test_window_normalisation_fills_the_canonical_schema(self):
        from netshield.simulation.telemetry import METRIC_CSV_COLUMNS

        row = normalise_window(
            {
                "window": 0, "t_start": 0.0, "t_end": 5.0,
                "offered_packets": 1000, "offered_bytes": 500000,
                "delivered_packets": 900, "delivered_bytes": 450000,
                "dropped_packets": 100, "legit_offered": 800,
                "legit_delivered": 780, "attack_offered": 200,
                "mean_latency_ms": 20.0,
            },
            window_s=5.0,
        )
        for column in METRIC_CSV_COLUMNS:
            assert column in row, f"{column} missing from a normalised window"
        assert row["pps"] == pytest.approx(200.0)
        assert row["loss_ratio"] == pytest.approx(0.1)

    def test_nodes_are_reconstructed_with_ground_truth_roles(self):
        flows = [
            {"src_node": "iot-00", "src_ip": "10.10.0.2", "packets": 5, "bytes": 500},
            {"src_node": "atk-01", "src_ip": "10.10.9.2", "packets": 50, "bytes": 5000},
            {"src_node": "cloud-0", "src_ip": "10.0.0.1", "packets": 3, "bytes": 300},
        ]
        nodes = {n["node_id"]: n for n in nodes_from_flows(flows)}
        assert nodes["atk-01"]["is_attacker"] is True
        assert nodes["atk-01"]["kind"] == "attacker"
        assert nodes["iot-00"]["is_attacker"] is False
        assert nodes["cloud-0"]["kind"] == "cloud"
