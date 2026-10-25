"""Feature extraction, dataset assembly and graph construction.

The most important test in this file is
:meth:`TestLabelLeakage.test_feature_columns_contain_no_ground_truth` - if that
ever fails, every accuracy number the project reports is meaningless.
"""

from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd
import pytest

from netshield.features.dataset import (
    DatasetError,
    FeatureScaler,
    class_weights,
    dataset_report,
    split_by_run,
)
from netshield.features.flow_features import (
    FLOW_FEATURE_GLOSSARY,
    FlowSchemaError,
    add_derived_flow_features,
    flow_summary,
    top_talkers,
    validate_flow_frame,
)
from netshield.features.node_features import (
    FORBIDDEN_FEATURE_COLUMNS,
    NODE_FEATURE_COLUMNS,
    LeakageError,
    assert_no_leakage,
    build_node_window_features,
    class_distribution,
    feature_matrix,
    label_from_severity,
    label_vector,
    transit_nodes,
)
from netshield.graph.builder import (
    EDGE_COLUMNS,
    GraphBuildError,
    build_edge_table,
    build_graphs,
    build_window_graph,
    graph_statistics,
    to_networkx,
    to_pyg_data,
)
from netshield.traffic.attacks import AttackProfile, attack_duty


class TestLabelLeakage:
    """Ground truth must never reach a model."""

    def test_feature_columns_contain_no_ground_truth(self) -> None:
        assert_no_leakage(NODE_FEATURE_COLUMNS)
        assert not (set(NODE_FEATURE_COLUMNS) & FORBIDDEN_FEATURE_COLUMNS)

    def test_leakage_is_detected_when_it_happens(self) -> None:
        with pytest.raises(LeakageError, match="leak"):
            assert_no_leakage([*NODE_FEATURE_COLUMNS, "attack_ratio"])

    def test_app_tag_is_not_a_feature(self) -> None:
        # The app tag literally contains the string "attack_udp".
        assert "app" not in NODE_FEATURE_COLUMNS
        assert "app" in FORBIDDEN_FEATURE_COLUMNS


class TestAttackDuty:
    """Analytic ground-truth timing, including pulsing attacks."""

    def test_duty_outside_the_attack_is_zero(self) -> None:
        profile = AttackProfile(True, "udp_flood", 30.0, 30.0, 1000.0, (512, 512), (80,))
        assert attack_duty(profile, 20.0, 25.0) == 0.0
        assert attack_duty(profile, 65.0, 70.0) == 0.0

    def test_duty_inside_a_continuous_attack_is_one(self) -> None:
        profile = AttackProfile(True, "udp_flood", 30.0, 30.0, 1000.0, (512, 512), (80,))
        assert attack_duty(profile, 35.0, 40.0) == 1.0

    def test_partial_window_gives_a_partial_duty(self) -> None:
        profile = AttackProfile(True, "udp_flood", 30.0, 30.0, 1000.0, (512, 512), (80,))
        assert attack_duty(profile, 28.0, 33.0) == pytest.approx(0.6)

    def test_pulsing_attack_duty_matches_the_duty_cycle(self) -> None:
        profile = AttackProfile(True, "udp_flood", 30.0, 30.0, 1000.0, (512, 512), (80,),
                                burst_enabled=True, burst_on_s=2.5, burst_off_s=2.5)
        assert attack_duty(profile, 30.0, 40.0) == pytest.approx(0.5, abs=1e-6)

    def test_duty_is_always_bounded(self) -> None:
        profile = AttackProfile(True, "udp_flood", 5.0, 100.0, 1000.0, (64, 64), (80,),
                                burst_enabled=True, burst_on_s=0.3, burst_off_s=0.7)
        for start in np.arange(0.0, 60.0, 1.7):
            value = attack_duty(profile, float(start), float(start) + 5.0)
            assert 0.0 <= value <= 1.0

    @pytest.mark.parametrize(
        ("severity", "expected"),
        [(0.0, 0), (0.05, 0), (0.12, 1), (0.4, 1), (0.55, 2), (1.0, 2)],
    )
    def test_severity_maps_to_the_documented_classes(
        self, severity: float, expected: int
    ) -> None:
        assert label_from_severity(severity) == expected


class TestFlowFeatures:
    """The exported flow schema and its derived columns."""

    def test_exported_flows_validate(self, attack_result: Any) -> None:
        frame = pd.DataFrame(attack_result.flows)
        assert validate_flow_frame(frame) is frame

    def test_invalid_flow_frames_are_rejected(self, attack_result: Any) -> None:
        frame = pd.DataFrame(attack_result.flows).copy()
        frame.loc[frame.index[0], "attack_packets"] = frame["packets"].iloc[0] + 1
        with pytest.raises(FlowSchemaError, match="attack_packets > packets"):
            validate_flow_frame(frame)

    def test_derived_columns_are_added(self, attack_result: Any) -> None:
        frame = add_derived_flow_features(pd.DataFrame(attack_result.flows))
        for column in ("bits_per_packet", "packet_size_cv", "iat_cv", "syn_ratio",
                       "handshake_completion", "is_tcp", "is_udp"):
            assert column in frame.columns
        assert frame["bits_per_packet"].min() >= 0

    def test_glossary_documents_every_required_column(self) -> None:
        assert "attack_packets" in FLOW_FEATURE_GLOSSARY
        assert "GROUND TRUTH" in FLOW_FEATURE_GLOSSARY["attack_packets"]

    def test_summary_and_top_talkers(self, attack_result: Any) -> None:
        frame = pd.DataFrame(attack_result.flows)
        summary = flow_summary(frame)
        assert summary["n_flows"] == len(frame)
        assert 0.0 <= summary["attack_fraction"] <= 1.0
        talkers = top_talkers(frame, n=5)
        assert len(talkers) <= 5
        assert talkers["bytes"].is_monotonic_decreasing


class TestNodeFeatures:
    """The node-window feature matrix."""

    def test_shape_and_columns(self, attack_result: Any) -> None:
        frame = build_node_window_features(attack_result)
        assert not frame.empty
        for column in NODE_FEATURE_COLUMNS:
            assert column in frame.columns
        assert frame[list(NODE_FEATURE_COLUMNS)].isna().sum().sum() == 0

    def test_infrastructure_nodes_are_present(self, attack_result: Any) -> None:
        frame = build_node_window_features(attack_result)
        kinds = set(frame["kind"])
        assert {"router", "gateway", "cloud"} <= kinds, (
            "routers and the gateway must appear so the graph has aggregation points"
        )

    def test_attackers_are_labelled_during_the_attack_only(
        self, attack_result: Any
    ) -> None:
        frame = build_node_window_features(attack_result)
        attack = attack_result.summary["attack"]
        bots = frame[frame["is_attacker"]]
        before = bots[bots["t_end"] <= attack["start_s"]]
        during = bots[(bots["t_start"] >= attack["start_s"])
                      & (bots["t_end"] <= attack["end_s"])]
        assert (before["label"] == 0).all(), "an idle bot must be labelled BENIGN"
        assert (during["label"] == 2).any(), "no bot was labelled MALICIOUS"

    def test_legitimate_devices_are_never_labelled_hostile(
        self, attack_result: Any
    ) -> None:
        frame = build_node_window_features(attack_result)
        legit = frame[~frame["is_attacker"]]
        assert (legit["label"] == 0).all()

    def test_benign_run_has_only_benign_labels(self, benign_result: Any) -> None:
        frame = build_node_window_features(benign_result)
        assert set(frame["label"]) == {0}
        assert class_distribution(frame) == {"BENIGN": len(frame)}

    def test_attacker_packet_rate_exceeds_its_own_idle_rate(
        self, attack_result: Any
    ) -> None:
        frame = build_node_window_features(attack_result)
        attack = attack_result.summary["attack"]
        bots = frame[frame["is_attacker"]]
        idle = bots[bots["t_end"] <= attack["start_s"]]["eg_packet_rate"].mean()
        active = bots[(bots["t_start"] >= attack["start_s"])
                      & (bots["t_end"] <= attack["end_s"])]["eg_packet_rate"].mean()
        assert active > idle * 5

    def test_syn_features_discriminate_a_syn_flood(self, syn_flood_result: Any) -> None:
        frame = build_node_window_features(syn_flood_result)
        attack = syn_flood_result.summary["attack"]
        during = frame[(frame["t_start"] >= attack["start_s"])
                       & (frame["t_end"] <= attack["end_s"])]
        bots = during[during["is_attacker"]]
        legit = during[(~during["is_attacker"]) & (during["is_endpoint"] > 0.5)]
        assert bots["eg_syn_rate"].mean() > legit["eg_syn_rate"].mean() * 10

    def test_spoofing_shows_up_as_source_address_entropy(
        self, syn_flood_result: Any
    ) -> None:
        frame = build_node_window_features(syn_flood_result)
        attack = syn_flood_result.summary["attack"]
        during = frame[(frame["t_start"] >= attack["start_s"])
                       & (frame["t_end"] <= attack["end_s"])]
        bots = during[during["is_attacker"]]
        if not syn_flood_result.summary["attack"].get("spoof_sources"):
            pytest.skip("this scenario does not spoof source addresses")
        assert bots["eg_unique_src_ips"].max() > 1

    def test_matrix_and_labels_are_aligned(self, attack_result: Any) -> None:
        frame = build_node_window_features(attack_result)
        matrix = feature_matrix(frame)
        labels = label_vector(frame)
        assert matrix.shape == (len(frame), len(NODE_FEATURE_COLUMNS))
        assert labels.shape == (len(frame),)
        assert matrix.dtype == np.float32

    def test_empty_run_is_reported_not_silently_accepted(self, attack_result: Any) -> None:
        class Empty:
            run_id = "empty"
            flows: list = []
            summary = {"window_s": 5.0, "attack": {}}
            topology = attack_result.topology
            meta: dict = {}
            engine = "python-des-emulation"

        with pytest.raises(ValueError, match="no flow records"):
            build_node_window_features(Empty())


class TestTransitAttribution:
    """Router/gateway rows come from the flows they forward."""

    def test_transit_nodes_on_a_tree_path(self, attack_result: Any) -> None:
        parents = {n["node_id"]: n.get("parent") for n in attack_result.topology["nodes"]}
        endpoint = next(n["node_id"] for n in attack_result.topology["nodes"]
                        if n["kind"] in ("iot", "attacker"))
        cloud = attack_result.topology["cloud"]
        transit = transit_nodes(endpoint, cloud, parents)
        assert len(transit) == 2, "router and gateway"
        assert any(t.startswith("rtr-") for t in transit)
        assert any(t.startswith("gw-") for t in transit)

    def test_no_transit_between_a_node_and_itself(self, attack_result: Any) -> None:
        parents = {n["node_id"]: n.get("parent") for n in attack_result.topology["nodes"]}
        assert transit_nodes("gw-0", "gw-0", parents) == []

    def test_gateway_load_is_at_least_the_busiest_router(self, attack_result: Any) -> None:
        frame = build_node_window_features(attack_result)
        for window, group in frame.groupby("window"):
            gateway = group[group["kind"] == "gateway"]["eg_packets"]
            routers = group[group["kind"] == "router"]["eg_packets"]
            if gateway.empty or routers.empty:
                continue
            assert gateway.iloc[0] >= routers.max(), (
                f"window {window}: the gateway must carry at least as much as "
                "any single router beneath it"
            )


class TestDatasetAssembly:
    """Corpus construction, scaling and grouped splitting."""

    def test_corpus_contains_every_run(self, corpus: Any) -> None:
        assert corpus["run_id"].nunique() == 3
        assert len(corpus) > 0

    def test_report_is_consistent(self, corpus: Any) -> None:
        report = dataset_report(corpus)
        assert report["rows"] == len(corpus)
        assert report["n_features"] == len(NODE_FEATURE_COLUMNS)
        assert sum(report["classes"].values()) == len(corpus)

    def test_split_never_shares_a_run_between_partitions(self, corpus: Any) -> None:
        split = split_by_run(corpus, test_size=0.34, val_size=0.33, seed=1)
        train = set(split.train["run_id"])
        val = set(split.val["run_id"])
        test = set(split.test["run_id"])
        assert not (train & val) and not (train & test) and not (val & test)
        assert train and test

    def test_split_rejects_a_corpus_that_is_too_small(self) -> None:
        frame = pd.DataFrame({"run_id": ["a", "a"], "experiment": ["x", "x"],
                              "label": [0, 0]})
        with pytest.raises(DatasetError, match="at least 3"):
            split_by_run(frame)

    def test_scaler_round_trips_through_json(self, corpus: Any, tmp_path: Any) -> None:
        scaler = FeatureScaler.fit(corpus)
        path = scaler.save(tmp_path / "scaler.json")
        restored = FeatureScaler.load(path)
        assert np.allclose(scaler.transform(corpus), restored.transform(corpus))

    def test_scaler_standardises_the_training_data(self, corpus: Any) -> None:
        scaler = FeatureScaler.fit(corpus)
        matrix = scaler.transform(corpus)
        assert np.isfinite(matrix).all()
        assert abs(float(matrix.mean())) < 0.2

    def test_scaler_rejects_a_frame_with_missing_columns(self, corpus: Any) -> None:
        scaler = FeatureScaler.fit(corpus)
        with pytest.raises(DatasetError, match="missing feature columns"):
            scaler.transform(corpus.drop(columns=["eg_packets"]))

    def test_class_weights_are_inverse_frequency(self) -> None:
        weights = class_weights(np.array([0] * 90 + [1] * 5 + [2] * 5))
        assert weights[0] < weights[1]
        assert weights.shape == (3,)
        assert float(weights.mean()) == pytest.approx(1.0, abs=1e-5)

    def test_class_weights_handle_an_absent_class(self) -> None:
        weights = class_weights(np.array([0, 0, 2, 2]))
        assert np.isfinite(weights).all()


class TestGraphConstruction:
    """Window graphs and their conversions."""

    def test_edge_table_has_both_edge_families(self, attack_result: Any) -> None:
        edges = build_edge_table(attack_result)
        assert list(edges.columns) == list(EDGE_COLUMNS)
        assert set(edges["edge_type"]) == {"physical", "communication"}

    def test_graphs_are_built_per_window(self, attack_result: Any) -> None:
        frame = build_node_window_features(attack_result)
        edges = build_edge_table(attack_result)
        scaler = FeatureScaler.fit(frame)
        graphs = build_graphs(frame, edges, scaler)
        assert len(graphs) == frame["window"].nunique()
        for graph in graphs:
            assert graph.n_nodes > 0
            assert graph.n_edges > 0
            assert graph.x.shape == (graph.n_nodes, len(NODE_FEATURE_COLUMNS))
            assert graph.y.shape == (graph.n_nodes,)

    def test_edges_never_point_outside_the_node_set(self, attack_result: Any) -> None:
        frame = build_node_window_features(attack_result)
        edges = build_edge_table(attack_result)
        scaler = FeatureScaler.fit(frame)
        for graph in build_graphs(frame, edges, scaler):
            assert graph.edge_index.min() >= 0
            assert graph.edge_index.max() < graph.n_nodes

    def test_self_loops_and_reverse_edges_are_present(self, attack_result: Any) -> None:
        frame = build_node_window_features(attack_result)
        edges = build_edge_table(attack_result)
        scaler = FeatureScaler.fit(frame)
        graph = build_graphs(frame, edges, scaler)[0]
        src, dst = graph.edge_index
        assert (src == dst).any(), "self-loops were requested but are absent"
        pairs = set(zip(src.tolist(), dst.tolist()))
        off_diagonal = [(a, b) for a, b in pairs if a != b]
        assert any((b, a) in pairs for a, b in off_diagonal), "no reverse edge found"

    def test_graph_is_connected_through_the_hierarchy(self, attack_result: Any) -> None:
        import networkx as nx

        frame = build_node_window_features(attack_result)
        edges = build_edge_table(attack_result)
        scaler = FeatureScaler.fit(frame)
        graph = build_graphs(frame, edges, scaler)[0]
        nx_graph = to_networkx(graph).to_undirected()
        assert nx.number_connected_components(nx_graph) == 1, (
            "message passing cannot reach every node in a disconnected graph"
        )

    def test_empty_feature_frame_is_rejected(self) -> None:
        with pytest.raises(GraphBuildError, match="empty"):
            build_window_graph(pd.DataFrame(), pd.DataFrame(), np.zeros((0, 1)))

    def test_pyg_conversion(self, attack_result: Any) -> None:
        pytest.importorskip("torch_geometric")
        frame = build_node_window_features(attack_result)
        edges = build_edge_table(attack_result)
        scaler = FeatureScaler.fit(frame)
        graph = build_graphs(frame, edges, scaler)[0]
        data = to_pyg_data(graph)
        assert data.x.shape[0] == graph.n_nodes
        assert data.edge_index.shape == (2, graph.n_edges)

    def test_statistics_are_consistent(self, attack_result: Any) -> None:
        frame = build_node_window_features(attack_result)
        edges = build_edge_table(attack_result)
        scaler = FeatureScaler.fit(frame)
        graphs = build_graphs(frame, edges, scaler)
        stats = graph_statistics(graphs)
        assert stats["n_graphs"] == len(graphs)
        assert stats["total_nodes"] == sum(g.n_nodes for g in graphs)
        assert sum(stats["classes"].values()) == stats["total_nodes"]
