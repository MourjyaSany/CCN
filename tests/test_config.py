"""Configuration loading, merging, overriding and validation."""

from __future__ import annotations

import pytest

from netshield.utils.config import (
    Config,
    ConfigError,
    deep_merge,
    experiment_config,
    experiment_names,
    flatten,
    get_path,
    load_config,
    load_experiments,
    load_fuzzing_config,
    parse_scalar,
    set_path,
    validate,
)


class TestDeepMerge:
    """Merging semantics that the whole layered-config design relies on."""

    def test_merges_nested_mappings_key_by_key(self) -> None:
        base = {"a": {"x": 1, "y": 2}, "b": 3}
        override = {"a": {"y": 20, "z": 30}}
        assert deep_merge(base, override) == {"a": {"x": 1, "y": 20, "z": 30}, "b": 3}

    def test_replaces_lists_wholesale_rather_than_concatenating(self) -> None:
        # An experiment that declares dst_ports: [80] means exactly [80].
        merged = deep_merge({"ports": [1, 2, 3]}, {"ports": [80]})
        assert merged["ports"] == [80]

    def test_does_not_mutate_its_inputs(self) -> None:
        base = {"a": {"x": 1}}
        override = {"a": {"x": 2}}
        deep_merge(base, override)
        assert base == {"a": {"x": 1}}
        assert override == {"a": {"x": 2}}


class TestDottedAccess:
    """Dotted key access, assignment and flattening."""

    def test_get_path_returns_default_for_missing_levels(self) -> None:
        assert get_path({"a": {"b": 1}}, "a.b") == 1
        assert get_path({"a": {"b": 1}}, "a.c", "fallback") == "fallback"
        assert get_path({"a": 1}, "a.b.c", None) is None

    def test_set_path_creates_intermediate_levels(self) -> None:
        data: dict = {}
        set_path(data, "a.b.c", 7)
        assert data == {"a": {"b": {"c": 7}}}

    def test_flatten_round_trips_nesting(self) -> None:
        assert flatten({"a": {"b": 1}, "c": 2}) == {"a.b": 1, "c": 2}

    @pytest.mark.parametrize(
        ("text", "expected"),
        [("3", 3), ("3.5", 3.5), ("true", True), ("false", False),
         ("[1, 2]", [1, 2]), ("hello", "hello")],
    )
    def test_parse_scalar_uses_yaml_rules(self, text: str, expected: object) -> None:
        assert parse_scalar(text) == expected


class TestLoading:
    """Loading the real configuration files that ship with the project."""

    def test_default_config_loads_and_validates(self, base_config: Config) -> None:
        assert base_config.get("project.name") == "NetShield-GNN"
        assert base_config.get("simulation.duration_s") > 0
        assert base_config.get("network.topology.gateway.uplink.bandwidth_bps") > 0

    def test_network_file_is_merged_under_the_network_key(self, base_config: Config) -> None:
        assert "topology" in base_config.section("network")
        assert base_config.get("network.topology.routers.count") >= 1

    def test_cli_overrides_take_precedence(self) -> None:
        cfg = load_config(set_args=["simulation.duration_s=42.0", "seed=7"])
        assert cfg.get("simulation.duration_s") == 42.0
        assert cfg.get("seed") == 7

    def test_malformed_override_is_rejected(self, base_config: Config) -> None:
        with pytest.raises(ConfigError, match="key=value"):
            base_config.with_set(["not_an_assignment"])

    def test_require_raises_for_missing_key(self, base_config: Config) -> None:
        with pytest.raises(ConfigError, match="missing"):
            base_config.require("no.such.key")

    def test_fingerprint_is_stable_and_config_sensitive(self) -> None:
        a = load_config()
        b = load_config()
        c = load_config(set_args=["seed=999"])
        assert a.fingerprint() == b.fingerprint()
        assert a.fingerprint() != c.fingerprint()

    def test_paths_resolve_to_absolute_locations(self, base_config: Config) -> None:
        assert base_config.path("models").is_absolute()
        assert base_config.path("database").name.endswith(".db")


class TestExperiments:
    """Every declared experiment must load and validate."""

    def test_all_declared_experiments_are_valid(self) -> None:
        doc = load_experiments()
        names = experiment_names(doc)
        assert len(names) >= 8, "the project promises Experiments 1-8"
        for name in names:
            cfg, meta = experiment_config(name, doc)
            validate(cfg)
            assert meta["experiment"] == name
            assert meta["description"], f"{name} has no description"

    def test_experiment_overrides_are_applied(self) -> None:
        cfg, _ = experiment_config("exp2_udp_flood")
        assert cfg.get("attack.enabled") is True
        assert cfg.get("attack.type") == "udp_flood"
        assert cfg.get("simulation.n_attackers") >= 1

    def test_holdout_experiment_is_marked(self) -> None:
        _, meta = experiment_config("exp7_unseen")
        assert meta["holdout"] is True, (
            "exp7 must be flagged as held out so dataset generation excludes it"
        )

    def test_dataset_corpus_excludes_the_holdout_experiment(self) -> None:
        doc = load_experiments()
        corpus = doc["dataset_corpus"]["base_runs"]
        assert "exp7_unseen" not in corpus

    def test_fuzzing_campaigns_are_declared(self) -> None:
        doc = load_fuzzing_config()
        assert doc["campaigns"], "config/fuzzing.yaml declares no campaigns"


class TestValidation:
    """Invariants that must fail loudly rather than produce a silly simulation."""

    @pytest.mark.parametrize(
        ("override", "message"),
        [
            (["simulation.duration_s=-1"], "positive"),
            (["simulation.n_iot_devices=0"], ">= 1"),
            (["network.topology.routers.count=0"], ">= 1"),
            (["simulation.engine=quantum"], "auto|ns3|python"),
            (["features.window_s=10000"], "exceeds"),
            (["features.label_suspicious_threshold=0.9",
              "features.label_malicious_threshold=0.5"], "suspicious < malicious"),
            (["detection.mitigation_trigger_probability=1.5"], "in \\(0, 1\\]"),
        ],
    )
    def test_invalid_configurations_are_rejected(
        self, override: list[str], message: str
    ) -> None:
        with pytest.raises(ConfigError, match=message):
            load_config(set_args=override)

    @pytest.mark.parametrize(
        ("override", "message"),
        [
            (["attack.enabled=true", "simulation.n_attackers=0"], "n_attackers is 0"),
            (["attack.enabled=true", "simulation.n_attackers=2",
              "attack.type=teleport"], "attack.type must be"),
            (["attack.enabled=true", "simulation.n_attackers=2",
              "attack.packets_per_second=0"], "must be > 0"),
            (["attack.enabled=true", "simulation.n_attackers=2",
              "attack.packet_bytes=[900, 100]"], "lo <= hi"),
            (["attack.enabled=true", "simulation.n_attackers=2",
              "attack.start_s=10000"], "never fire"),
            (["attack.enabled=true", "simulation.n_attackers=2",
              "attack.dst_ports=[70000]"], "Invalid destination port"),
        ],
    )
    def test_invalid_attack_configurations_are_rejected(
        self, override: list[str], message: str
    ) -> None:
        with pytest.raises(ConfigError, match=message):
            load_config(set_args=override)

    def test_valid_attack_configuration_passes(self) -> None:
        cfg = load_config(set_args=[
            "attack.enabled=true", "simulation.n_attackers=3",
            "attack.type=syn_flood", "attack.packets_per_second=500",
            "attack.packet_bytes=[64, 64]", "attack.dst_ports=[80, 443]",
        ])
        assert validate(cfg) is cfg
