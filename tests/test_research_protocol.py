"""Tests for the research-protocol additions.

Covers the statistical helpers, the new QoS telemetry, the benign-stress
events, the operational metrics, the extra baselines and the fold designs.
"""

from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd
import pytest
from sklearn.metrics import f1_score

from netshield.evaluation.operational import operational_metrics
from netshield.evaluation.statistics import (
    binary_ece,
    cluster_bootstrap_ci,
    extended_metrics,
    fast_macro_f1,
    holm_correction,
    mcnemar_test,
    metric_fn,
    paired_bootstrap_diff,
    tpr_at_fpr,
    wilcoxon_signed_rank,
)
from netshield.simulation.telemetry import _reservoir_slot, jain_index
from netshield.research.protocol import (
    STRESS_FAMILY,
    loafo_folds,
    loto_folds,
    seed_cv_folds,
)


# --------------------------------------------------------------------------- #
# statistics
# --------------------------------------------------------------------------- #
class TestStatistics:
    def test_fast_macro_f1_matches_sklearn(self) -> None:
        rng = np.random.default_rng(3)
        y = rng.integers(0, 3, 2000)
        p = np.where(rng.random(2000) < 0.6, y, rng.integers(0, 3, 2000))
        assert fast_macro_f1(y, p) == pytest.approx(
            f1_score(y, p, labels=[0, 1, 2], average="macro", zero_division=0))

    def test_perfect_detector_metrics(self) -> None:
        y = np.array([0] * 50 + [1] * 10 + [2] * 40)
        proba = np.eye(3)[y]
        m = extended_metrics(y, proba)
        assert m["macro_f1"] == pytest.approx(1.0)
        assert m["mcc"] == pytest.approx(1.0)
        assert m["false_positive_rate"] == 0.0
        assert m["tpr_at_fpr_0.01"] == pytest.approx(1.0)
        assert m["ece"] == pytest.approx(0.0, abs=1e-9)

    def test_tpr_at_fpr_respects_budget(self) -> None:
        y = np.array([0] * 100 + [1] * 100)
        scores = np.concatenate([np.linspace(0, 0.9, 100), np.linspace(0.5, 1.0, 100)])
        assert 0.0 < tpr_at_fpr(y, scores, 0.01) < tpr_at_fpr(y, scores, 0.5) <= 1.0

    def test_binary_ece_of_calibrated_scores_is_small(self) -> None:
        rng = np.random.default_rng(0)
        s = rng.random(20000)
        y = (rng.random(20000) < s).astype(int)
        assert binary_ece(y, s) < 0.02
        assert binary_ece(y, np.clip(s * 0.3, 0, 1)) > 0.2

    def test_cluster_bootstrap_ci_brackets_point(self) -> None:
        rng = np.random.default_rng(1)
        groups = np.repeat(np.arange(20), 50).astype(str)
        y = rng.integers(0, 3, len(groups))
        proba = np.eye(3)[np.where(rng.random(len(y)) < 0.8, y, 0)]
        ci = cluster_bootstrap_ci(metric_fn("macro_f1", y, proba), groups, 300, seed=0)
        assert ci["lo"] <= ci["point"] <= ci["hi"]
        assert ci["n_clusters"] == 20

    def test_paired_diff_detects_a_real_gap(self) -> None:
        rng = np.random.default_rng(2)
        groups = np.repeat(np.arange(30), 40).astype(str)
        y = rng.integers(0, 3, len(groups))
        good = np.eye(3)[np.where(rng.random(len(y)) < 0.95, y, 0)]
        bad = np.eye(3)[np.where(rng.random(len(y)) < 0.5, y, 0)]
        d = paired_bootstrap_diff(metric_fn("macro_f1", y, good),
                                  metric_fn("macro_f1", y, bad), groups, 300)
        assert d["diff"] > 0 and d["lo"] > 0 and d["p_value"] < 0.01

    def test_mcnemar_and_wilcoxon(self) -> None:
        y = np.zeros(100, dtype=int)
        a = np.zeros(100, dtype=int)
        b = np.ones(100, dtype=int)
        assert mcnemar_test(y, a, b)["p_value"] < 1e-6
        assert mcnemar_test(y, a, a)["p_value"] == 1.0
        w = wilcoxon_signed_rank([0.9] * 10 + [0.95] * 5, [0.8] * 10 + [0.7] * 5)
        assert w["p_value"] < 0.01 and w["median_diff"] > 0

    def test_holm_is_monotone_and_controls(self) -> None:
        out = holm_correction({"a": 0.001, "b": 0.02, "c": 0.06}, alpha=0.05)
        assert out["a"]["reject"] and out["b"]["reject"] and not out["c"]["reject"]
        assert out["b"]["p_holm"] == pytest.approx(0.04)
        assert out["a"]["p_holm"] <= out["b"]["p_holm"] <= out["c"]["p_holm"]


# --------------------------------------------------------------------------- #
# telemetry additions
# --------------------------------------------------------------------------- #
class TestTelemetryAdditions:
    def test_jain_index_bounds(self) -> None:
        assert jain_index([1, 1, 1, 1]) == pytest.approx(1.0)
        assert jain_index([1, 0, 0, 0]) == pytest.approx(0.25)
        assert jain_index([]) == 1.0

    def test_reservoir_slot_in_range(self) -> None:
        for seen in (1, 2, 17, 4001, 99999):
            assert 0 <= _reservoir_slot(seen) < seen

    def test_new_window_columns_present(self, benign_result: Any) -> None:
        frame = pd.DataFrame(benign_result.windows)
        for col in ("clean_p99_latency_ms", "clean_jitter_ms", "clean_availability",
                    "clean_fairness", "collateral_byte_ratio", "delivery_ratio_mqtt"):
            assert col in frame.columns
        assert frame["clean_availability"].between(0, 1).all()
        assert (frame["clean_p99_latency_ms"] >= frame["clean_p50_latency_ms"]).all()
        assert (frame["collateral_byte_ratio"] == 0).all()  # no mitigation armed

    def test_attack_degrades_availability(self, benign_result: Any, attack_result: Any) -> None:
        benign = pd.DataFrame(benign_result.windows)["clean_availability"].mean()
        attack = pd.DataFrame(attack_result.windows)
        start = attack_result.summary["attack"]["start_s"]
        during = attack[attack["t_start"] >= start]["clean_availability"].mean()
        assert during < benign

    def test_upload_completion_times_recorded(self, benign_result: Any) -> None:
        apps = pd.DataFrame(benign_result.applications)
        assert "fct_p95_ms" in apps.columns
        uploaders = apps[apps["device_class"] == "tcp_uploader"]
        assert (uploaders["completed"].astype(int) >= 0).all()


# --------------------------------------------------------------------------- #
# benign stress events
# --------------------------------------------------------------------------- #
class TestBenignEvents:
    @pytest.mark.parametrize("event", [
        {"type": "flash_crowd", "start_s": 8.0, "duration_s": 10.0, "rate_multiplier": 20.0},
        {"type": "firmware_storm", "start_s": 8.0},
        {"type": "reboot_storm", "start_s": 8.0},
    ])
    def test_event_runs_and_stays_benign(self, benign_config: Any, event: dict) -> None:
        from netshield.simulation.runner import run_simulation

        cfg = benign_config.merged({"traffic": {"benign_events": [event]}})
        result = run_simulation(cfg, {"experiment": "stress_test"})
        assert result.summary["benign_events"][0]["type"] == event["type"]
        assert result.summary["attack_packets"] == 0

    def test_flash_crowd_raises_offered_load(self, benign_config: Any) -> None:
        from netshield.simulation.runner import run_simulation

        cfg = benign_config.merged({"traffic": {"benign_events": [
            {"type": "flash_crowd", "start_s": 10.0, "duration_s": 15.0,
             "rate_multiplier": 25.0}]}})
        surged = pd.DataFrame(run_simulation(cfg, {"experiment": "fc"}).windows)
        calm = pd.DataFrame(run_simulation(benign_config, {"experiment": "calm"}).windows)
        late = lambda f: f[f["t_start"] >= 15.0]["offered_packets"].sum()  # noqa: E731
        assert late(surged) > 1.3 * late(calm)

    def test_unknown_event_rejected(self, benign_config: Any) -> None:
        from netshield.simulation.runner import run_simulation

        cfg = benign_config.merged({"traffic": {"benign_events": [{"type": "nope"}]}})
        with pytest.raises(ValueError):
            run_simulation(cfg, {"experiment": "bad"})


# --------------------------------------------------------------------------- #
# operational metrics
# --------------------------------------------------------------------------- #
class TestOperationalMetrics:
    def test_attack_run_metrics(self, attack_result: Any) -> None:
        m = operational_metrics(attack_result)
        assert m["attack_start_s"] is not None
        assert m["availability_during_attack"] <= m["baseline_clean_availability"]
        assert m["time_to_mitigate_s"] is None  # open loop: no rules
        assert m["peak_active_rules"] == 0

    def test_benign_run_has_no_attack_window(self, benign_result: Any) -> None:
        m = operational_metrics(benign_result)
        assert m["attack_start_s"] is None and m["time_to_detect_s"] is None


# --------------------------------------------------------------------------- #
# baselines
# --------------------------------------------------------------------------- #
class TestNewBaselines:
    @pytest.mark.parametrize("name", ["lightgbm", "gru_seq", "autoencoder", "gat",
                                      "egraphsage"])
    def test_fit_predict_save_load(self, name: str, detection_input: Any, base_config: Any,
                                   tmp_path: Any) -> None:
        from netshield.detection.pipeline import DETECTOR_CLASSES

        det = DETECTOR_CLASSES[name].from_config(base_config)
        if hasattr(det, "hyper"):
            for key, value in (("epochs", 3), ("patience", 2)):
                if key in det.hyper:
                    det.hyper[key] = value
        det.fit(detection_input, detection_input)
        proba = det.predict_proba(detection_input)
        assert proba.shape == (detection_input.n_rows, 3)
        assert np.allclose(proba.sum(axis=1), 1.0, atol=1e-5)
        det.save(tmp_path / name)
        again = type(det).load(tmp_path / name)
        assert np.allclose(again.predict_proba(detection_input), proba, atol=1e-5)

    def test_sequence_builder_is_causal(self) -> None:
        from netshield.models.baselines import build_sequences

        frame = pd.DataFrame({"run_id": ["r"] * 4, "node_id": ["a", "a", "b", "a"],
                              "window": [0, 1, 0, 2]})
        x = np.array([[1.0], [2.0], [9.0], [3.0]])
        seq = build_sequences(frame, x, 3)
        assert seq[3, :, 0].tolist() == [1.0, 2.0, 3.0]   # a@2 sees a@0, a@1
        assert seq[0, :, 0].tolist() == [0.0, 0.0, 1.0]   # a@0 has no history
        assert seq[2, :, 0].tolist() == [0.0, 0.0, 9.0]   # b never sees a

    def test_edge_type_ablation_keeps_only_self_loops(self, detection_input: Any,
                                                      base_config: Any) -> None:
        from netshield.features.dataset import FeatureScaler
        from netshield.graph.builder import build_graphs

        scaler = FeatureScaler.fit(detection_input.features)
        graphs = build_graphs(detection_input.features, detection_input.edges, scaler,
                              edge_types=[])
        g = graphs[0]
        assert (g.edge_index[0] == g.edge_index[1]).all()
        assert g.edge_attr.shape == (g.n_edges, 6)


# --------------------------------------------------------------------------- #
# fold designs
# --------------------------------------------------------------------------- #
def _runs() -> pd.DataFrame:
    rows = []
    for fam, sc in (("benign", "exp1_normal"), ("udp_flood", "exp2_udp_flood"),
                    ("slowloris", "exp17_slowloris"), ("mixed", "exp19_multivector")):
        for topo in ("tree", "star", "ring"):
            for s in range(3):
                rows.append({"run_id": f"{sc}-{topo}-{s}", "scenario": sc, "family": fam,
                             "topology_family": topo, "seed_offset": s})
    rows.append({"run_id": "stress-1", "scenario": "exp20_flash_crowd",
                 "family": STRESS_FAMILY, "topology_family": "tree", "seed_offset": 0})
    return pd.DataFrame(rows)


class TestFolds:
    def test_seed_cv_tests_every_run_once(self) -> None:
        runs = _runs()
        folds = seed_cv_folds(runs)
        tested = [r for f in folds for r in f.test]
        core = runs[runs["family"] != STRESS_FAMILY]["run_id"]
        assert sorted(tested) == sorted(core)
        for f in folds:
            assert not set(f.train) & set(f.test) and not set(f.val) & set(f.test)
            assert "stress-1" in f.stress and "stress-1" not in f.train

    def test_loto_holds_out_whole_topology(self) -> None:
        runs = _runs().set_index("run_id")
        for f in loto_folds(runs.reset_index()):
            assert set(runs.loc[f.test, "topology_family"]) == {f.name}
            assert f.name not in set(runs.loc[f.train + f.val, "topology_family"])

    def test_loafo_excludes_family_and_mixed(self) -> None:
        runs = _runs().set_index("run_id")
        folds = loafo_folds(runs.reset_index())
        assert {f.name for f in folds} == {"udp_flood", "slowloris"}
        for f in folds:
            seen = set(runs.loc[f.train + f.val, "family"])
            assert f.name not in seen and "mixed" not in seen


# --------------------------------------------------------------------------- #
# step 2: calibration, conformal ladder, temporal GNN
# --------------------------------------------------------------------------- #
class TestCalibration:
    def test_temperature_fixes_overconfidence_without_changing_argmax(self) -> None:
        from netshield.models.calibration import apply_temperature, fit_temperature

        rng = np.random.default_rng(5)
        y = rng.integers(0, 3, 3000)
        logits = np.eye(3)[y] * 2.0 + rng.normal(0, 1.2, (3000, 3))
        sharp = np.exp(logits * 4)
        sharp /= sharp.sum(1, keepdims=True)
        t = fit_temperature(sharp, y)
        assert t > 1.5
        cal = apply_temperature(sharp, t)
        assert (cal.argmax(1) == sharp.argmax(1)).all()
        from netshield.evaluation.statistics import expected_calibration_error as ece
        assert ece(y, cal) < ece(y, sharp)

    def test_conformal_bounds_benign_false_alarms(self) -> None:
        from netshield.models.calibration import ConformalCalibrator

        rng = np.random.default_rng(6)
        cal = ConformalCalibrator().fit(rng.beta(2, 8, 4000))
        fresh = rng.beta(2, 8, 20000)
        for alpha in (0.05, 0.01):
            fpr = (cal.p_values(fresh) <= alpha).mean()
            assert fpr <= alpha * 1.25 + 0.002
            assert fresh[fresh >= cal.threshold(alpha)].size / fresh.size <= alpha * 1.25 + 0.002

    def test_conformal_detector_wraps_any_base(self, detection_input: Any,
                                               base_config: Any, tmp_path: Any) -> None:
        from netshield.models.calibration import ConformalDetector
        from netshield.models.random_forest import RandomForestDetector

        base = RandomForestDetector.from_config(base_config)
        base.params["n_estimators"] = 20
        base.fit(detection_input, detection_input)
        det = ConformalDetector.from_validation(base, detection_input)
        proba = det.predict_proba(detection_input)
        assert np.allclose(proba.sum(1), 1.0)
        det.save(tmp_path / "conf")
        again = ConformalDetector.load(tmp_path / "conf")
        assert np.allclose(again.predict_proba(detection_input), proba)


class TestTemporalGNN:
    def test_fit_predict_and_history_index(self, detection_input: Any, base_config: Any,
                                           tmp_path: Any) -> None:
        from netshield.models.temporal_gnn import TemporalGNNDetector, _RunBatch

        det = TemporalGNNDetector.from_config(base_config)
        det.hyper.update({"epochs": 2, "patience": 1, "seq_len": 3})
        det.fit(detection_input, detection_input)
        proba = det.predict_proba(detection_input)
        assert proba.shape == (detection_input.n_rows, 3)
        assert np.allclose(proba.sum(1), 1.0, atol=1e-5)
        det.save(tmp_path / "tgnn")
        again = TemporalGNNDetector.load(tmp_path / "tgnn")
        assert np.allclose(again.predict_proba(detection_input), proba, atol=1e-5)

        run = det._runs(detection_input)[0]
        assert isinstance(run, _RunBatch)
        # Every history entry points strictly backwards (causality) or is -1.
        rows = np.arange(run.history.shape[0])[:, None]
        assert ((run.history == -1) | (run.history <= rows)).all()
        assert (run.history[:, -1] == np.arange(run.history.shape[0])).all()

    def test_controller_buffers_history_for_temporal_models(self, base_config: Any,
                                                            detection_input: Any) -> None:
        from netshield.detection.pipeline import build_controller_factory
        from netshield.models.baselines import GRUSequenceDetector
        from netshield.simulation.runner import run_simulation

        det = GRUSequenceDetector.from_config(base_config)
        det.hyper.update({"epochs": 1, "seq_len": 3})
        det.fit(detection_input, detection_input)
        cfg = base_config.with_set(["simulation.duration_s=20.0"])
        result = run_simulation(cfg, {"experiment": "buffer"},
                                controller_factory=build_controller_factory(
                                    det, cfg, enable_mitigation=False))
        assert result.detections, "controller produced no detections"


class TestExplanations:
    def test_integrated_gradients_completeness(self, detection_input: Any,
                                               base_config: Any) -> None:
        from netshield.explain import explain
        from netshield.models.graphsage import GraphSAGEDetector

        det = GraphSAGEDetector.from_config(base_config)
        det.hyper.update({"epochs": 4, "patience": 3})
        det.fit(detection_input, detection_input)
        f = detection_input.features
        key = f[f["is_attacker"]].iloc[0]
        one = detection_input.subset(((f["run_id"] == key["run_id"])
                                      & (f["window"] == key["window"])).to_numpy())
        out = explain(det, one, key["node_id"])
        assert out["method"] == "integrated_gradients"
        assert abs(out["completeness_gap"]) < 0.05
        assert out["features"] and out["feature_groups"]

    def test_occlusion_for_tabular(self, detection_input: Any, base_config: Any) -> None:
        from netshield.explain import explain
        from netshield.models.random_forest import RandomForestDetector

        det = RandomForestDetector.from_config(base_config)
        det.params["n_estimators"] = 20
        det.fit(detection_input, detection_input)
        f = detection_input.features
        key = f.iloc[0]
        one = detection_input.subset(((f["run_id"] == key["run_id"])
                                      & (f["window"] == key["window"])).to_numpy())
        out = explain(det, one, key["node_id"])
        assert out["method"] == "occlusion" and len(out["feature_groups"]) == 8


def test_closed_loop_detector_is_part_of_run_identity() -> None:
    """Regression: two defences on the same scenario must never share a cached run."""
    from netshield.research.grid import RunSpec, build_config
    from netshield.simulation.runner import build_run_id

    ids = {d: build_run_id(*build_config(RunSpec("exp2_udp_flood", "tree", 10, closed_loop=d)))
           for d in ("graphsage", "lightgbm", None)}
    assert len(set(ids.values())) == 3
