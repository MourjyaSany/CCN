"""Detector behaviour, checkpointing, metrics and the fuzzing engine."""

from __future__ import annotations

from typing import Any

import numpy as np
import pytest

from netshield.evaluation.metrics import (
    comparison_table,
    compute_metrics,
    detection_latency,
    per_experiment_metrics,
    subset_metrics,
)
from netshield.features.dataset import split_by_run
from netshield.features.node_features import CLASS_NAMES
from netshield.fuzzing.engine import (
    STRATEGIES,
    CampaignSpec,
    FuzzEngine,
    FuzzError,
    campaign_names,
    cases_to_frame,
    load_campaign,
    materialise,
    save_cases,
    load_cases,
)
from netshield.fuzzing.space import (
    SpaceError,
    grid_points,
    grid_size,
    mutate_point,
    sample_point,
    validate_space,
)
from netshield.models.base import DetectionInput, DetectorError
from netshield.models.graphsage import BACKEND, GraphSAGEDetector, MeanSAGEConv
from netshield.models.random_forest import RandomForestDetector
from netshield.models.threshold import ThresholdDetector
from netshield.utils.config import Config, experiment_config


@pytest.fixture(scope="module")
def split(corpus: Any):
    """A grouped train/val/test split over the fixture corpus."""
    return split_by_run(corpus, test_size=0.34, val_size=0.33, seed=3)


@pytest.fixture(scope="module")
def inputs(split: Any, corpus_edges: Any):
    """Train/val/test detector inputs."""
    return (
        DetectionInput(split.train, corpus_edges),
        DetectionInput(split.val, corpus_edges),
        DetectionInput(split.test, corpus_edges),
    )


class TestThresholdDetector:
    """The rule-based baseline."""

    def test_is_usable_without_training(self, detection_input: Any) -> None:
        detector = ThresholdDetector()
        assert detector.fitted
        proba = detector.predict_proba(detection_input)
        assert proba.shape == (detection_input.n_rows, 3)
        assert np.allclose(proba.sum(axis=1), 1.0)

    def test_calibration_only_moves_the_volume_rules(self, inputs: Any) -> None:
        train, _, _ = inputs
        detector = ThresholdDetector(auto_calibrate=True)
        before_ratio = detector.thresholds["syn_ratio"]
        detector.fit(train)
        # A bounded ratio rule must not be calibrated above 1.0, which would
        # silently disable it.
        assert detector.thresholds["syn_ratio"] == before_ratio
        assert detector.thresholds["syn_ratio"] <= 1.0

    def test_infrastructure_nodes_are_not_scored(self, detection_input: Any) -> None:
        detector = ThresholdDetector(endpoints_only=True)
        scores = detector.rule_scores(detection_input.features)
        infra = detection_input.features["is_endpoint"] <= 0.5
        assert (scores.loc[infra.to_numpy(), "score"] == 0.0).all()

    def test_flags_a_high_rate_flood(self, attack_result: Any, corpus_edges: Any) -> None:
        from netshield.features.node_features import build_node_window_features

        frame = build_node_window_features(attack_result)
        detector = ThresholdDetector()
        scores = detector.attack_probability(DetectionInput(frame, corpus_edges))
        attack = attack_result.summary["attack"]
        during = ((frame["t_start"] >= attack["start_s"])
                  & (frame["t_end"] <= attack["end_s"])
                  & frame["is_attacker"]).to_numpy()
        assert scores[during].max() > 0.5

    def test_explain_names_the_rule_that_fired(self, detection_input: Any) -> None:
        detector = ThresholdDetector()
        explanation = detector.explain(detection_input.features, 0)
        assert explanation["rule"] in detector.thresholds
        assert "value" in explanation and "limit" in explanation

    def test_round_trip(self, tmp_path: Any, detection_input: Any) -> None:
        detector = ThresholdDetector()
        detector.thresholds["packet_rate_pps"] = 321.0
        detector.save(tmp_path / "threshold")
        restored = ThresholdDetector.load(tmp_path / "threshold")
        assert restored.thresholds["packet_rate_pps"] == 321.0
        assert np.allclose(detector.predict_proba(detection_input),
                           restored.predict_proba(detection_input))

    def test_missing_checkpoint_is_reported(self, tmp_path: Any) -> None:
        with pytest.raises(FileNotFoundError):
            ThresholdDetector.load(tmp_path / "nope")


class TestRandomForestDetector:
    """The tabular baseline."""

    def test_fit_predict_shapes(self, inputs: Any) -> None:
        train, val, test = inputs
        detector = RandomForestDetector(n_estimators=40, n_jobs=1)
        report = detector.fit(train, val)
        assert report.trained
        assert report.extra["top_features"]
        proba = detector.predict_proba(test)
        assert proba.shape == (test.n_rows, 3)
        assert np.allclose(proba.sum(axis=1), 1.0, atol=1e-6)

    def test_predict_before_fit_is_refused(self, inputs: Any) -> None:
        _, _, test = inputs
        with pytest.raises(DetectorError, match="must be fitted"):
            RandomForestDetector().predict(test)

    def test_probabilities_cover_all_three_classes(self, inputs: Any) -> None:
        # sklearn only emits columns for classes seen in training; the detector
        # must expand them back to the full three-class layout.
        train, val, test = inputs
        detector = RandomForestDetector(n_estimators=30, n_jobs=1)
        detector.fit(train, val)
        assert detector.predict_proba(test).shape[1] == len(CLASS_NAMES)

    def test_round_trip(self, inputs: Any, tmp_path: Any) -> None:
        train, val, test = inputs
        detector = RandomForestDetector(n_estimators=30, n_jobs=1)
        detector.fit(train, val)
        detector.save(tmp_path / "rf")
        restored = RandomForestDetector.load(tmp_path / "rf")
        assert np.allclose(detector.predict_proba(test), restored.predict_proba(test))

    def test_feature_importances_are_ranked(self, inputs: Any) -> None:
        train, val, _ = inputs
        detector = RandomForestDetector(n_estimators=30, n_jobs=1)
        detector.fit(train, val)
        frame = detector.feature_importance_frame()
        assert frame["importance"].is_monotonic_decreasing
        assert float(frame["importance"].sum()) == pytest.approx(1.0, abs=1e-6)


class TestGraphSAGEDetector:
    """The proposed graph model."""

    def test_backend_is_reported(self) -> None:
        assert BACKEND in ("torch-geometric", "pure-torch-fallback")

    def test_fallback_layer_matches_mean_aggregation(self) -> None:
        import torch

        layer = MeanSAGEConv(3, 2)
        with torch.no_grad():
            layer.lin_self.weight.zero_()
            layer.lin_self.bias.zero_()
            layer.lin_neigh.weight.copy_(torch.eye(2, 3))
        x = torch.tensor([[1.0, 0.0, 0.0], [3.0, 0.0, 0.0], [5.0, 0.0, 0.0]])
        # Node 2 receives messages from nodes 0 and 1: mean of 1 and 3 is 2.
        edge_index = torch.tensor([[0, 1], [2, 2]])
        out = layer(x, edge_index)
        assert float(out[2, 0]) == pytest.approx(2.0, abs=1e-6)
        assert float(out[0, 0]) == pytest.approx(0.0, abs=1e-6)

    def test_fit_and_predict(self, inputs: Any) -> None:
        train, val, test = inputs
        detector = GraphSAGEDetector(epochs=12, patience=12, hidden_channels=16)
        report = detector.fit(train, val)
        assert report.trained
        assert report.epochs > 0
        assert report.extra["n_parameters"] > 0
        proba = detector.predict_proba(test)
        assert proba.shape == (test.n_rows, 3)
        assert np.allclose(proba.sum(axis=1), 1.0, atol=1e-5)

    def test_predictions_are_row_aligned_with_the_input(self, inputs: Any) -> None:
        train, val, test = inputs
        detector = GraphSAGEDetector(epochs=8, patience=8, hidden_channels=16)
        detector.fit(train, val)
        proba = detector.predict_proba(test)
        # A uniform row means the scatter-back failed for that sample.
        uniform = np.isclose(proba, 1 / 3).all(axis=1)
        assert uniform.sum() == 0, f"{uniform.sum()} rows were never scored"

    def test_round_trip(self, inputs: Any, tmp_path: Any) -> None:
        train, val, test = inputs
        detector = GraphSAGEDetector(epochs=8, patience=8, hidden_channels=16)
        detector.fit(train, val)
        detector.save(tmp_path / "sage")
        restored = GraphSAGEDetector.load(tmp_path / "sage")
        assert np.allclose(detector.predict_proba(test), restored.predict_proba(test),
                           atol=1e-5)

    def test_training_is_deterministic_for_a_fixed_seed(self, inputs: Any) -> None:
        train, val, test = inputs
        a = GraphSAGEDetector(epochs=6, patience=6, hidden_channels=16, seed=11)
        b = GraphSAGEDetector(epochs=6, patience=6, hidden_channels=16, seed=11)
        a.fit(train, val)
        b.fit(train, val)
        assert np.allclose(a.predict_proba(test), b.predict_proba(test), atol=1e-5)

    def test_embeddings_are_returned_with_metadata(self, inputs: Any) -> None:
        train, val, test = inputs
        detector = GraphSAGEDetector(epochs=6, patience=6, hidden_channels=16)
        detector.fit(train, val)
        vectors, meta = detector.embeddings(test)
        assert vectors.shape[0] == len(meta)
        assert set(["run_id", "window", "node_id", "label"]) <= set(meta.columns)


class TestMetrics:
    """Metric computation, including the network-specific ones."""

    def test_perfect_predictions(self) -> None:
        y = np.array([0, 0, 1, 2, 2])
        metrics = compute_metrics(y, y, np.array([0.0, 0.0, 0.9, 1.0, 1.0]))
        assert metrics.accuracy == 1.0
        assert metrics.macro_f1 == 1.0
        assert metrics.binary["false_positive_rate"] == 0.0

    def test_confusion_matrix_is_three_by_three(self) -> None:
        metrics = compute_metrics(np.array([0, 1]), np.array([0, 0]))
        assert len(metrics.confusion) == 3
        assert all(len(row) == 3 for row in metrics.confusion)

    def test_false_positive_rate_is_computed_over_benign_rows(self) -> None:
        y_true = np.array([0, 0, 0, 0, 2])
        y_pred = np.array([0, 2, 0, 0, 2])
        metrics = compute_metrics(y_true, y_pred)
        assert metrics.binary["false_positives"] == 1
        assert metrics.binary["false_positive_rate"] == pytest.approx(0.25)

    def test_single_class_split_yields_nan_auc_not_a_crash(self) -> None:
        metrics = compute_metrics(np.zeros(5, int), np.zeros(5, int), np.zeros(5))
        assert np.isnan(metrics.binary["roc_auc"])
        assert metrics.roc == {}

    def test_mismatched_lengths_are_rejected(self) -> None:
        with pytest.raises(ValueError, match="same length"):
            compute_metrics(np.zeros(3, int), np.zeros(4, int))

    def test_empty_split_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            compute_metrics(np.zeros(0, int), np.zeros(0, int))

    def test_detection_latency_is_at_least_one_window(self, attack_result: Any) -> None:
        from netshield.features.node_features import build_node_window_features

        frame = build_node_window_features(attack_result)
        # An oracle scorer: perfect knowledge, so latency is purely structural.
        scores = frame["severity"].to_numpy()
        report = detection_latency(frame, scores, trigger=0.5, window_s=5.0)
        assert report["n_runs_with_attack"] == 1
        assert report["mean_latency_s"] is not None
        assert report["mean_latency_s"] >= 5.0, (
            "a windowed detector cannot decide faster than one window"
        )

    def test_undetected_attack_is_reported_not_averaged_away(
        self, attack_result: Any
    ) -> None:
        from netshield.features.node_features import build_node_window_features

        frame = build_node_window_features(attack_result)
        report = detection_latency(frame, np.zeros(len(frame)), trigger=0.9)
        assert report["n_missed"] == 1
        assert report["mean_latency_s"] is None

    def test_subset_metrics_respects_the_mask(self, attack_result: Any) -> None:
        from netshield.features.node_features import build_node_window_features

        frame = build_node_window_features(attack_result)
        pred = frame["label"].to_numpy()
        scores = frame["severity"].to_numpy()
        mask = (frame["is_endpoint"] > 0.5).to_numpy()
        bundle = subset_metrics(frame, pred, scores, mask, "oracle", "endpoints")
        assert bundle is not None
        assert bundle.n_samples == int(mask.sum())
        assert subset_metrics(frame, pred, scores, np.zeros(len(frame), bool),
                              "oracle", "none") is None

    def test_per_experiment_and_comparison_tables(self, attack_result: Any) -> None:
        from netshield.features.node_features import build_node_window_features

        frame = build_node_window_features(attack_result)
        pred = frame["label"].to_numpy()
        rows = per_experiment_metrics(frame, pred, frame["severity"].to_numpy(), "oracle")
        assert rows and rows[0]["detector"] == "oracle"
        table = comparison_table([compute_metrics(frame["label"].to_numpy(), pred)])
        assert "macro_f1" in table.columns


class TestFuzzingSpace:
    """Parameter-space declaration and sampling."""

    def test_valid_declarations_pass(self) -> None:
        space = {
            "a": [1, 2, 3],
            "b": {"uniform": [0.0, 1.0]},
            "c": {"loguniform": [1.0, 100.0]},
            "d": {"int_uniform": [1, 5]},
            "e": {"pair_uniform": [10, 20]},
            "f": {"choice": ["x", "y"]},
            "g": {"subset": [1, 2, 3, 4], "size": [1, 2]},
        }
        assert validate_space(space) is space

    @pytest.mark.parametrize(
        ("space", "message"),
        [
            ({}, "empty"),
            ({"a": []}, "empty"),
            ({"a": 5}, "expected a list"),
            ({"a": {"uniform": [1.0]}}, "\\[lo, hi\\] pair"),
            ({"a": {"uniform": [5.0, 1.0]}}, "hi < lo"),
            ({"a": {"loguniform": [0.0, 1.0]}}, "lo > 0"),
            ({"a": {"choice": []}}, "non-empty list"),
            ({"a": {"subset": [1, 2], "size": [1, 9]}}, "outside"),
            ({"a": {"uniform": [0, 1], "choice": [1]}}, "exactly one"),
        ],
    )
    def test_malformed_declarations_are_rejected(self, space: dict, message: str) -> None:
        with pytest.raises(SpaceError, match=message):
            validate_space(space)

    def test_sampling_respects_declared_bounds(self) -> None:
        rng = np.random.default_rng(0)
        space = {"r": {"loguniform": [10.0, 1000.0]},
                 "n": {"int_uniform": [2, 8]},
                 "p": {"pair_uniform": [64, 1400]}}
        for _ in range(80):
            point = sample_point(space, rng)
            assert 10.0 <= point["r"] <= 1000.0
            assert 2 <= point["n"] <= 8
            assert 64 <= point["p"][0] <= point["p"][1] <= 1400

    def test_grid_enumerates_the_full_product(self) -> None:
        space = {"a": [1, 2], "b": [10, 20, 30]}
        points = list(grid_points(space))
        assert len(points) == grid_size(space) == 6
        assert len({tuple(sorted(p.items())) for p in points}) == 6

    def test_grid_requires_explicit_lists(self) -> None:
        with pytest.raises(SpaceError, match="explicit value lists"):
            list(grid_points({"a": {"uniform": [0, 1]}}))

    def test_mutation_always_changes_something(self) -> None:
        rng = np.random.default_rng(5)
        space = {"r": {"uniform": [1.0, 100.0]}, "n": {"int_uniform": [1, 10]}}
        base = sample_point(space, rng)
        for _ in range(30):
            child = mutate_point(base, space, rng, mutation_rate=0.0)
            assert child != base, "mutation must guarantee at least one change"

    def test_mutation_stays_within_bounds(self) -> None:
        rng = np.random.default_rng(6)
        space = {"r": {"uniform": [1.0, 10.0]}}
        point = {"r": 9.9}
        for _ in range(60):
            point = mutate_point(point, space, rng, mutation_rate=1.0, scale=0.9)
            assert 1.0 <= point["r"] <= 10.0


class TestFuzzingEngine:
    """Campaign generation, reproducibility and materialisation."""

    def test_declared_campaigns_all_load(self) -> None:
        names = campaign_names()
        assert names
        for name in names:
            spec = load_campaign(name)
            assert spec.strategy in STRATEGIES
            assert FuzzEngine(spec).planned_case_count() > 0

    def test_generation_is_reproducible(self) -> None:
        for name in ("rate_sweep", "random_broad", "mutation_walk"):
            spec = load_campaign(name)
            first = [c.assignments for c in FuzzEngine(spec).generate()]
            second = [c.assignments for c in FuzzEngine(load_campaign(name)).generate()]
            assert first == second, f"campaign '{name}' is not reproducible"

    def test_case_seeds_are_distinct(self) -> None:
        cases = FuzzEngine(load_campaign("random_broad")).generate()
        assert len({c.seed for c in cases}) == len(cases)

    def test_grid_sweep_covers_every_declared_value(self) -> None:
        spec = load_campaign("rate_sweep")
        cases = FuzzEngine(spec).generate()
        produced = {c.assignments["attack.packets_per_second"] for c in cases}
        assert produced == set(spec.space["attack.packets_per_second"])

    def test_unknown_campaign_is_reported(self) -> None:
        with pytest.raises(FuzzError, match="Unknown fuzzing campaign"):
            load_campaign("no_such_campaign")

    def test_unknown_strategy_is_rejected(self) -> None:
        with pytest.raises(FuzzError, match="unknown strategy"):
            CampaignSpec.from_mapping("bad", {"strategy": "telepathy",
                                              "space": {"a": [1]}})

    def test_materialised_case_is_a_valid_configuration(self) -> None:
        spec = load_campaign("corpus_campaign")
        base, _ = experiment_config(spec.base)
        for case in FuzzEngine(spec).generate():
            cfg = materialise(case, base)
            assert isinstance(cfg, Config)
            assert cfg.get("seed") == case.seed
            for key, value in case.assignments.items():
                assert cfg.get(key) == value

    def test_adaptive_search_prefers_low_scoring_regions(self) -> None:
        spec = load_campaign("evasion_search")
        engine = FuzzEngine(spec)

        def objective(case: Any) -> float:
            # Lower rate evades better; the search should drift downwards.
            return min(1.0, float(case.assignments["attack.packets_per_second"]) / 2000.0)

        cases = engine.run_adaptive(objective, n_samples=10)
        assert len(cases) == 10
        assert all(c.score is not None for c in cases)
        assert cases[0].score <= cases[-1].score, "results must be sorted by score"
        assert any(c.parent for c in cases), "no mutation descended from a parent"

    def test_cases_round_trip_through_json(self, tmp_path: Any) -> None:
        cases = FuzzEngine(load_campaign("rate_sweep")).generate()
        path = save_cases(cases, tmp_path / "cases.json")
        restored = load_cases(path)
        assert [c.assignments for c in restored] == [c.assignments for c in cases]
        assert [c.seed for c in restored] == [c.seed for c in cases]

    def test_cases_tabulate_for_plotting(self) -> None:
        frame = cases_to_frame(FuzzEngine(load_campaign("rate_sweep")).generate())
        assert "case_id" in frame.columns
        assert "attack.packets_per_second" in frame.columns
