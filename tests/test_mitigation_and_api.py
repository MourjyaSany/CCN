"""Mitigation policy and enforcement, the database, and the REST API."""

from __future__ import annotations

import json
from typing import Any

import numpy as np
import pytest

from netshield.mitigation.engine import (
    MitigationEnforcer,
    MitigationEngine,
    evaluate_mitigation_accuracy,
)
from netshield.mitigation.policy import (
    ActionType,
    MitigationAction,
    NodeState,
    PolicyConfig,
    decide,
)
from netshield.simulation.packet import Packet, Protocol


def make_packet(src: str = "atk-00", size: int = 512) -> Packet:
    """Build a minimal packet for enforcement tests."""
    return Packet(
        pid=1, t_gen=0.0, src=src, dst="cloud-0", src_ip="10.10.9.2",
        dst_ip="10.0.0.1", sport=40000, dport=8883, protocol=Protocol.UDP, size=size,
    )


@pytest.fixture()
def policy() -> PolicyConfig:
    """A validated default policy."""
    return PolicyConfig().validate()


class TestPolicy:
    """The graduated response ladder."""

    def test_default_policy_is_monotone(self, policy: PolicyConfig) -> None:
        assert (policy.rate_limit_probability
                <= policy.block_probability
                <= policy.isolate_probability)

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"rate_limit_probability": 0.9, "block_probability": 0.5},
            {"block_probability": 0.99, "isolate_probability": 0.6},
            {"escalation_windows": 0},
            {"release_after_clean_windows": 0},
            {"rate_limit_pps": 0.0},
        ],
    )
    def test_incoherent_policies_are_rejected(self, kwargs: dict) -> None:
        with pytest.raises(ValueError):
            PolicyConfig(**kwargs).validate()

    def test_below_trigger_does_nothing(self, policy: PolicyConfig) -> None:
        action, _ = decide(0.1, NodeState("iot-00"), policy)
        assert action is ActionType.NONE

    def test_moderate_confidence_rate_limits(self, policy: PolicyConfig) -> None:
        action, reason = decide(0.82, NodeState("atk-00"), policy)
        assert action is ActionType.RATE_LIMIT
        assert "throttling" in reason

    def test_high_confidence_blocks(self, policy: PolicyConfig) -> None:
        action, _ = decide(0.90, NodeState("atk-00"), policy)
        assert action is ActionType.BLOCK

    def test_isolation_requires_persistence_not_just_confidence(
        self, policy: PolicyConfig
    ) -> None:
        # One very confident window is not enough; that is the whole point of
        # requiring repeated evidence before the most destructive action.
        first_hit = NodeState("atk-00", consecutive_hits=1)
        action, _ = decide(0.99, first_hit, policy)
        assert action is ActionType.BLOCK

        persistent = NodeState("atk-00", consecutive_hits=policy.escalation_windows)
        action, _ = decide(0.99, persistent, policy)
        assert action is ActionType.ISOLATE

    def test_release_requires_enough_clean_windows(self, policy: PolicyConfig) -> None:
        state = NodeState("atk-00", action=ActionType.BLOCK, clean_windows=1)
        action, _ = decide(0.05, state, policy)
        assert action is ActionType.NONE

        state.clean_windows = policy.release_after_clean_windows
        action, reason = decide(0.05, state, policy)
        assert action is ActionType.RELEASE
        assert "clean windows" in reason

    def test_severity_ordering(self) -> None:
        assert ActionType.ISOLATE.severity > ActionType.BLOCK.severity
        assert ActionType.BLOCK.severity > ActionType.RATE_LIMIT.severity


class TestEnforcer:
    """Data-plane enforcement at the gateway ingress."""

    def test_unknown_source_passes(self, policy: PolicyConfig) -> None:
        enforcer = MitigationEnforcer(policy)
        assert enforcer.inspect(make_packet(), 1.0) is None

    def test_block_drops_everything_from_that_source(self, policy: PolicyConfig) -> None:
        enforcer = MitigationEnforcer(policy)
        enforcer.install("atk-00", ActionType.BLOCK, 1.0, 0.95)
        assert enforcer.inspect(make_packet("atk-00"), 1.1) == "mitigation_block"
        assert enforcer.inspect(make_packet("iot-01"), 1.1) is None

    def test_isolation_uses_its_own_drop_reason(self, policy: PolicyConfig) -> None:
        enforcer = MitigationEnforcer(policy)
        enforcer.install("atk-00", ActionType.ISOLATE, 1.0, 0.99)
        assert enforcer.inspect(make_packet("atk-00"), 1.1) == "mitigation_isolate"

    def test_rate_limit_enforces_the_configured_rate(self) -> None:
        policy = PolicyConfig(rate_limit_pps=10.0, rate_limit_burst=5).validate()
        enforcer = MitigationEnforcer(policy)
        enforcer.install("atk-00", ActionType.RATE_LIMIT, 0.0, 0.7)

        # One second of traffic at 100 pps against a 10 pps bucket with burst 5:
        # roughly 5 + 10 = 15 packets should pass, the rest should be shed.
        passed = sum(
            1 for i in range(100)
            if enforcer.inspect(make_packet("atk-00"), i * 0.01) is None
        )
        assert 8 <= passed <= 22, f"token bucket let {passed} packets through"
        assert enforcer.drops["mitigation_ratelimit"] == 100 - passed

    def test_rate_limit_bucket_refills_over_time(self) -> None:
        policy = PolicyConfig(rate_limit_pps=10.0, rate_limit_burst=2).validate()
        enforcer = MitigationEnforcer(policy)
        enforcer.install("atk-00", ActionType.RATE_LIMIT, 0.0, 0.7)
        for _ in range(5):
            enforcer.inspect(make_packet("atk-00"), 0.0)
        assert enforcer.inspect(make_packet("atk-00"), 0.0) == "mitigation_ratelimit"
        # After a full second the bucket has refilled.
        assert enforcer.inspect(make_packet("atk-00"), 1.0) is None

    def test_release_restores_forwarding(self, policy: PolicyConfig) -> None:
        enforcer = MitigationEnforcer(policy)
        enforcer.install("atk-00", ActionType.BLOCK, 1.0, 0.95)
        enforcer.release("atk-00", 2.0)
        assert enforcer.inspect(make_packet("atk-00"), 2.1) is None
        assert enforcer.active_sources() == []

    def test_enforcement_keys_on_node_not_spoofable_ip(self, policy: PolicyConfig) -> None:
        enforcer = MitigationEnforcer(policy)
        enforcer.install("atk-00", ActionType.BLOCK, 1.0, 0.95)
        spoofed = make_packet("atk-00")
        spoofed.src_ip = "10.66.13.7"  # forged address
        assert enforcer.inspect(spoofed, 1.1) == "mitigation_block", (
            "spoofing the source address must not defeat ingress-port enforcement"
        )

    def test_report_counts_drops(self, policy: PolicyConfig) -> None:
        enforcer = MitigationEnforcer(policy, {"atk-00": "10.10.9.2"})
        enforcer.install("atk-00", ActionType.BLOCK, 1.0, 0.95)
        for _ in range(7):
            enforcer.inspect(make_packet("atk-00"), 1.1)
        report = enforcer.report()
        assert report["packets_dropped"] == 7
        assert "atk-00" in report["active_rules"]


class TestMitigationEngine:
    """The control plane that turns detections into rules."""

    def test_confident_detection_installs_a_rule(self, policy: PolicyConfig) -> None:
        engine = MitigationEngine(policy, MitigationEnforcer(policy), "graphsage")
        actions = engine.apply_window(0, 10.0, {"atk-00": 0.97})
        assert actions and actions[0].action is ActionType.BLOCK
        assert engine.first_action_time == 10.0

    def test_benign_scores_install_nothing(self, policy: PolicyConfig) -> None:
        engine = MitigationEngine(policy, MitigationEnforcer(policy))
        assert engine.apply_window(0, 10.0, {"iot-00": 0.02, "iot-01": 0.1}) == []

    def test_rules_never_de_escalate_mid_incident(self, policy: PolicyConfig) -> None:
        engine = MitigationEngine(policy, MitigationEnforcer(policy))
        engine.apply_window(0, 10.0, {"atk-00": 0.95})   # BLOCK
        engine.apply_window(1, 15.0, {"atk-00": 0.83})   # would be RATE_LIMIT
        assert engine.enforcer.states["atk-00"].action is ActionType.BLOCK

    def test_escalation_to_isolation_after_repeated_windows(
        self, policy: PolicyConfig
    ) -> None:
        engine = MitigationEngine(policy, MitigationEnforcer(policy))
        for window in range(4):
            engine.apply_window(window, 10.0 + 5 * window, {"atk-00": 0.99})
        assert engine.enforcer.states["atk-00"].action is ActionType.ISOLATE

    def test_release_after_the_attack_stops(self, policy: PolicyConfig) -> None:
        engine = MitigationEngine(policy, MitigationEnforcer(policy))
        engine.apply_window(0, 10.0, {"atk-00": 0.95})
        for window in range(1, 1 + policy.release_after_clean_windows):
            engine.apply_window(window, 10.0 + 5 * window, {"atk-00": 0.01})
        assert engine.enforcer.states["atk-00"].action is ActionType.NONE
        assert any(a.action is ActionType.RELEASE for a in engine.log)

    def test_log_round_trips_to_csv(self, policy: PolicyConfig, tmp_path: Any) -> None:
        engine = MitigationEngine(policy, MitigationEnforcer(policy))
        engine.apply_window(0, 10.0, {"atk-00": 0.95})
        path = engine.save_log(tmp_path / "mitigation.csv")
        assert path.exists()
        assert "atk-00" in path.read_text(encoding="utf-8")

    def test_summary_is_json_serialisable(self, policy: PolicyConfig) -> None:
        engine = MitigationEngine(policy, MitigationEnforcer(policy))
        engine.apply_window(0, 10.0, {"atk-00": 0.95})
        json.dumps(engine.summary())

    def test_accuracy_scoring_separates_bots_from_collateral(self) -> None:
        actions = [
            MitigationAction(1.0, 0, "atk-00", "", ActionType.BLOCK, 0.9),
            MitigationAction(1.0, 0, "iot-03", "", ActionType.BLOCK, 0.9),
        ]
        result = evaluate_mitigation_accuracy(actions, ["atk-00", "atk-01"])
        assert result["correctly_mitigated"] == ["atk-00"]
        assert result["wrongly_mitigated"] == ["iot-03"]
        assert result["missed_attackers"] == ["atk-01"]
        assert result["precision"] == pytest.approx(0.5)
        assert result["recall"] == pytest.approx(0.5)
        assert result["collateral_damage"] == 1


class TestClosedLoop:
    """Mitigation must physically change the running simulation."""

    def test_mitigation_drops_packets_inside_the_run(self, attack_config: Any) -> None:
        from netshield.detection.controller import DetectionController
        from netshield.mitigation.policy import PolicyConfig as PC
        from netshield.models.base import Detector
        from netshield.simulation.runner import run_simulation

        class OracleDetector(Detector):
            """A perfect detector, so the test isolates the mitigation path."""

            name = "oracle"
            display_name = "Oracle"

            def __init__(self) -> None:
                super().__init__()
                self.fitted = True

            def fit(self, train: Any, val: Any = None) -> Any:  # pragma: no cover
                raise NotImplementedError

            def predict_proba(self, data: Any) -> np.ndarray:
                out = np.zeros((len(data.features), 3))
                hostile = data.features["is_attacker"].to_numpy(dtype=bool)
                active = data.features["attack_duty"].to_numpy(dtype=float) > 0
                flag = hostile & active
                out[flag, 2] = 1.0
                out[~flag, 0] = 1.0
                return out

            def save(self, directory: Any) -> Any:  # pragma: no cover
                raise NotImplementedError

            @classmethod
            def load(cls, directory: Any) -> Any:  # pragma: no cover
                raise NotImplementedError

        policy = PC.from_config(attack_config).validate()
        holder: dict[str, Any] = {}

        def factory(context: Any) -> Any:
            enforcer = MitigationEnforcer(
                policy, {n.node_id: n.ip for n in context.topology.nodes.values()}
            )
            engine = MitigationEngine(policy, enforcer, "oracle")
            controller = DetectionController(context, OracleDetector(), engine,
                                             trigger=0.8, warmup_windows=0)
            holder["controller"] = controller
            return controller

        mitigated = run_simulation(
            attack_config.with_set(["mitigation.enabled=true"]),
            {"experiment": "closed_loop"},
            controller_factory=factory,
        )

        assert mitigated.mitigations, "no mitigation rule was installed"
        total_mitigation_drops = sum(
            int(w.get("mitigation_drops", 0)) for w in mitigated.windows
        )
        assert total_mitigation_drops > 0, (
            "rules were installed but no packet was actually dropped, so the "
            "enforcement point is not wired into the data path"
        )

        # And the attack must be measurably blunted relative to the open loop.
        baseline = run_simulation(attack_config, {"experiment": "open_loop"})
        attack = baseline.summary["attack"]

        def attack_delivered(result: Any) -> int:
            return sum(w["attack_delivered"] for w in result.windows
                       if attack["start_s"] <= w["t_start"] < attack["end_s"])

        assert attack_delivered(mitigated) < attack_delivered(baseline), (
            "mitigation did not reduce the volume of attack traffic reaching "
            "the cloud"
        )


class TestDatabase:
    """SQLite persistence."""

    def test_schema_is_created(self, tmp_path: Any) -> None:
        from netshield.database.store import init_database

        db = init_database(tmp_path / "test.db")
        counts = db.table_counts()
        assert set(counts) >= {"experiments", "devices", "traffic_flows", "metrics",
                               "detections", "alerts", "mitigation_actions"}
        assert all(v == 0 for v in counts.values())

    def test_store_and_read_back_a_run(self, tmp_path: Any, attack_result: Any) -> None:
        from netshield.database.store import NetShieldDB

        db = NetShieldDB(tmp_path / "test.db")
        run_id = db.store_run(attack_result)
        assert db.get_run(run_id) is not None
        assert db.latest_run_id() == run_id
        assert len(db.devices(run_id)) == attack_result.topology["n_nodes"]
        assert len(db.metrics(run_id)) == len(attack_result.windows)
        assert db.top_talkers(run_id)[0]["bytes"] > 0

    def test_storing_twice_replaces_rather_than_duplicates(
        self, tmp_path: Any, attack_result: Any
    ) -> None:
        from netshield.database.store import NetShieldDB

        db = NetShieldDB(tmp_path / "test.db")
        db.store_run(attack_result)
        first = db.table_counts()
        db.store_run(attack_result)
        assert db.table_counts() == first

    def test_detections_become_alerts_above_the_trigger(
        self, tmp_path: Any, attack_result: Any
    ) -> None:
        from netshield.database.store import NetShieldDB

        db = NetShieldDB(tmp_path / "test.db")
        rows = [
            {"detector": "graphsage", "window": 0, "timestamp": 5.0, "node": "atk-00",
             "ip": "10.10.9.2", "kind": "attacker", "probability": 0.97,
             "predicted": "MALICIOUS", "p_malicious": 0.97, "packet_rate": 900.0},
            {"detector": "graphsage", "window": 0, "timestamp": 5.0, "node": "iot-00",
             "ip": "10.10.0.2", "kind": "iot", "probability": 0.02,
             "predicted": "BENIGN", "p_benign": 0.98, "packet_rate": 3.0},
        ]
        db.store_run(attack_result, detections=rows, trigger=0.8)
        alerts = db.alerts(attack_result.run_id)
        assert len(alerts) == 1
        assert alerts[0]["node_id"] == "atk-00"
        assert len(db.detections(attack_result.run_id)) == 2

    def test_cascade_delete(self, tmp_path: Any, attack_result: Any) -> None:
        from netshield.database.store import NetShieldDB

        db = NetShieldDB(tmp_path / "test.db")
        db.store_run(attack_result)
        db.delete_run(attack_result.run_id)
        counts = db.table_counts()
        assert counts["experiments"] == 0
        assert counts["devices"] == 0
        assert counts["metrics"] == 0

    def test_missing_database_is_reported(self, tmp_path: Any) -> None:
        from netshield.database.store import DatabaseError, NetShieldDB

        with pytest.raises(DatabaseError, match="not found"):
            NetShieldDB(tmp_path / "absent.db", create=False)


class TestAPI:
    """The REST API contract."""

    @pytest.fixture(scope="class")
    def client(self):
        """A FastAPI test client over a temporary database."""
        pytest.importorskip("httpx")
        from fastapi.testclient import TestClient

        from netshield.api.app import create_app
        from netshield.utils.config import load_config

        import tempfile

        tmp = tempfile.mkdtemp()
        config = load_config(set_args=[f"paths.database={tmp}/api-test.db"])
        return TestClient(create_app(config))

    def test_health(self, client: Any) -> None:
        payload = client.get("/api/health").json()
        assert payload["status"] == "ok"
        assert "engine" in payload
        assert isinstance(payload["ns3_available"], bool)
        assert payload["gnn_backend"]

    def test_openapi_document_is_generated(self, client: Any) -> None:
        spec = client.get("/openapi.json").json()
        assert spec["info"]["title"] == "NetShield-GNN API"
        for path in ("/api/health", "/api/network/status", "/api/network/topology",
                     "/api/traffic/current", "/api/alerts", "/api/metrics",
                     "/api/mitigation", "/api/simulation/start",
                     "/api/simulation/stop", "/api/experiment/run", "/api/results"):
            assert path in spec["paths"], f"{path} is missing from the OpenAPI document"

    def test_scenarios_are_listed(self, client: Any) -> None:
        scenarios = client.get("/api/scenarios").json()
        assert len(scenarios) >= 8
        names = {s["name"] for s in scenarios}
        assert "exp1_normal" in names and "exp8_mitigation" in names

    def test_idle_status_endpoints(self, client: Any) -> None:
        assert client.get("/api/simulation/status").json()["state"] == "idle"
        status = client.get("/api/network/status").json()
        assert status["n_devices"] == 0
        assert client.get("/api/network/topology").json()["nodes"] == []
        assert client.get("/api/alerts").json() == []
        assert client.get("/api/mitigation").json() == []
        assert client.get("/api/metrics").json()["windows"] == []

    def test_unknown_scenario_is_rejected(self, client: Any) -> None:
        response = client.post("/api/simulation/start", json={"scenario": "nope"})
        assert response.status_code == 404
        assert "Unknown scenario" in response.json()["detail"]

    def test_results_reports_absence_honestly(self, client: Any) -> None:
        payload = client.get("/api/results").json()
        assert isinstance(payload["available"], bool)
        if not payload["available"]:
            assert "evaluate" in payload["message"]

    def test_figure_path_traversal_is_blocked(self, client: Any) -> None:
        assert client.get("/api/figures/..%2F..%2Fsecret.png").status_code in (400, 404)

    def test_dashboard_is_served(self, client: Any) -> None:
        response = client.get("/")
        assert response.status_code == 200
        assert "NetShield-GNN" in response.text

    def test_stop_when_idle_is_harmless(self, client: Any) -> None:
        assert client.post("/api/simulation/stop").status_code == 200
