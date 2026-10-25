"""Tests for the production-platform layer (step 5)."""

from __future__ import annotations

import json
from typing import Any

import numpy as np
import pytest
from fastapi.testclient import TestClient
from hypothesis import given, settings
from hypothesis import strategies as st

from netshield.platform.audit import AuditLog
from netshield.platform.bus import InMemoryBus
from netshield.platform.interop import technique_for, to_cef, to_stix_bundle
from netshield.platform.ipfix import Decoder, encode, to_flow_rows
from netshield.platform.security import (
    AuthError,
    TokenService,
    UserStore,
    hash_password,
    required_role,
    verify_password,
)


# --------------------------------------------------------------------------- #
# security
# --------------------------------------------------------------------------- #
class TestSecurity:
    def test_password_hash_roundtrip(self) -> None:
        h = hash_password("s3cret", iterations=1000)
        assert verify_password("s3cret", h) and not verify_password("wrong", h)
        assert h != hash_password("s3cret", iterations=1000)        # salted

    def test_tokens(self) -> None:
        store = UserStore.from_sources(None, {"NETSHIELD_DEV_USERS": "ana:operator:pw"},
                                       iterations=1000)
        svc = TokenService(secret="k" * 40, ttl_s=60)
        claims = svc.verify(svc.issue(store.authenticate("ana", "pw"))["access_token"])
        assert claims["sub"] == "ana" and claims["role"] == "operator"
        with pytest.raises(AuthError):
            store.authenticate("ana", "nope")
        with pytest.raises(AuthError):
            TokenService(secret="x" * 40).verify(svc.issue(store.users["ana"])["access_token"])
        expired = TokenService(secret="k" * 40, ttl_s=-10)
        with pytest.raises(AuthError):
            svc.verify(expired.issue(store.users["ana"])["access_token"])

    def test_access_rules(self) -> None:
        assert required_role("GET", "/api/network/status") == "viewer"
        assert required_role("POST", "/api/simulation/start") == "operator"
        assert required_role("GET", "/api/audit") == "admin"
        assert required_role("POST", "/api/auth/token") == ""
        assert required_role("GET", "/") == ""


class TestAudit:
    def test_chain_detects_tampering(self) -> None:
        log = AuditLog(":memory:")
        for i in range(5):
            log.record("ana", "operator", "mitigation.approve", f"iot-{i}", detail={"i": i})
        assert log.verify_chain()
        log._conn.execute("UPDATE audit_log SET target='iot-x' WHERE id=3")
        assert not log.verify_chain()


# --------------------------------------------------------------------------- #
# interop
# --------------------------------------------------------------------------- #
class TestInterop:
    alert = {"node": "atk-00", "ip": "10.0.3.40", "probability": 0.97, "timestamp": 45.0,
             "attack_family": "syn_flood", "detector": "graphsage"}

    def test_attack_mapping(self) -> None:
        assert technique_for("udp_flood")[0] == "T1498.001"
        assert technique_for("slowloris")[0] == "T1499.002"
        assert technique_for("weird")[0] == "T1498"

    def test_stix_bundle_is_well_formed(self) -> None:
        bundle = to_stix_bundle([self.alert, {**self.alert, "node": "atk-01"}], run_id="r1")
        types = [o["type"] for o in bundle["objects"]]
        assert bundle["type"] == "bundle" and types.count("sighting") == 2
        assert types.count("attack-pattern") == 1
        ids = {o["id"] for o in bundle["objects"]}
        for o in bundle["objects"]:
            for ref in o.get("observed_data_refs", []) + [o.get("sighting_of_ref")]:
                assert ref is None or ref in ids
            assert o.get("spec_version", "2.1") == "2.1"

    def test_cef_escaping(self) -> None:
        line = to_cef({**self.alert, "node": "a=b|c"})
        assert line.startswith("CEF:0|NetShield|NetShield-GNN|")
        assert "shost=a\\=b|c" in line and "cs1=T1499.001" in line
        assert line.split("|")[6] == "10"


# --------------------------------------------------------------------------- #
# IPFIX
# --------------------------------------------------------------------------- #
class TestIPFIX:
    def test_roundtrip_preserves_feature_fields(self, attack_result: Any) -> None:
        rows = [r for r in attack_result.flows if r["window"] == 3][:60]
        nodes = {n["ip"]: n["node_id"] for n in attack_result.topology["nodes"]}
        dec = Decoder()
        decoded = [r for m in encode(rows, base_ms=10_000, port_of={}) for r in dec.decode(m)]
        back = to_flow_rows(decoded, nodes, base_ms=10_000)
        assert len(back) == len(rows)
        for a, b in zip(rows, back):
            assert b["window"] == a["window"] and b["packets"] == a["packets"]
            assert b["bytes"] == a["bytes"] and b["syn_count"] == a["syn_count"]
            assert b["mean_iat"] == pytest.approx(a["mean_iat"])

    def test_ingress_port_beats_spoofed_source(self) -> None:
        row = {"window": 0, "t_start": 0.0, "src_node": "atk-00", "src_ip": "10.66.1.2",
               "dst_ip": "10.0.0.1", "packets": 5, "bytes": 320, "protocol": 6}
        dec = Decoder()
        rec = dec.decode(encode([row], base_ms=0, port_of={"atk-00": 17})[0])
        assert to_flow_rows(rec, {}, node_of_port={17: "atk-00"})[0]["src_node"] == "atk-00"
        assert to_flow_rows(rec, {})[0]["src_node"] == "cloud-0"

    @settings(max_examples=40, deadline=None)
    @given(st.lists(st.fixed_dictionaries({
        "packets": st.integers(1, 10**6), "bytes": st.integers(64, 10**9),
        "src_port": st.integers(0, 65535), "dst_port": st.integers(0, 65535),
        "protocol": st.sampled_from([1, 6, 17]),
        "mean_iat": st.floats(0, 5, allow_nan=False)}), min_size=1, max_size=90))
    def test_roundtrip_property(self, rows: list[dict]) -> None:
        rows = [{**r, "window": 0, "t_start": 0.0, "src_ip": "10.0.3.10",
                 "dst_ip": "10.0.0.1"} for r in rows]
        dec = Decoder()
        out = [r for m in encode(rows, base_ms=0) for r in dec.decode(m)]
        assert [r["packets"] for r in out] == [r["packets"] for r in rows]
        assert [r["dst_port"] for r in out] == [r["dst_port"] for r in rows]


# --------------------------------------------------------------------------- #
# streaming pipeline end to end
# --------------------------------------------------------------------------- #
class TestStreamingPipeline:
    def test_pipeline_matches_offline_scoring(self, attack_result: Any, detection_input: Any,
                                              base_config: Any) -> None:
        from netshield.detection.pipeline import prepare_input
        from netshield.mitigation.engine import MitigationEnforcer, MitigationEngine
        from netshield.mitigation.policy import PolicyConfig
        from netshield.models.random_forest import RandomForestDetector
        from netshield.platform.pipeline import (
            CollectorService, FeatureService, InferenceService, Pipeline, PolicyService,
            replay_flows_as_ipfix)

        det = RandomForestDetector.from_config(base_config)
        det.params["n_estimators"] = 40
        det.fit(detection_input, detection_input)
        bus = InMemoryBus()
        nodes = {n["ip"]: n["node_id"] for n in attack_result.topology["nodes"]}
        ports = {n["node_id"]: i + 1 for i, n in enumerate(attack_result.topology["nodes"])}
        policy = PolicyConfig.from_config(base_config).validate()
        pipe = Pipeline(
            bus, CollectorService(bus, nodes, base_ms=1_700_000_000_000,
                                  node_of_port={v: k for k, v in ports.items()}),
            FeatureService(bus, attack_result.topology, run_id=attack_result.run_id),
            InferenceService(bus, det, trigger=0.8),
            PolicyService(bus, MitigationEngine(policy, MitigationEnforcer(policy, {}))))
        for window, messages in replay_flows_as_ipfix(attack_result.flows, port_of=ports):
            for m in messages:
                pipe.collector.ingest_ipfix(m)
            pipe.collector.flush(window)
            pipe.pump()
        scores = {m["window"]: m["scores"] for m in bus.drain("scores", "test")}
        offline = prepare_input(attack_result, base_config)
        proba = det.predict_proba(offline)
        frame = offline.features.assign(h=proba[:, 1] + proba[:, 2])
        frame = frame[frame["kind"].isin(["iot", "attacker"])]
        diffs = [abs(scores[w][n] - h) for w, n, h in zip(frame["window"], frame["node_id"],
                                                          frame["h"])
                 if w in scores and n in scores[w]]
        assert len(diffs) > 0.9 * len(frame)
        assert np.median(diffs) < 0.05
        attackers = {a["node_id"] for a in attack_result.attackers}
        alerted = {a["node"] for a in bus.drain("alerts", "test")}
        assert alerted & attackers


# --------------------------------------------------------------------------- #
# API: auth, approvals, streams, metrics
# --------------------------------------------------------------------------- #
@pytest.fixture()
def secured_client(base_config: Any, monkeypatch: Any) -> TestClient:
    from netshield.api.app import create_app

    monkeypatch.setenv("NETSHIELD_DEV_USERS", "vic:viewer:pw1,olga:operator:pw2,adam:admin:pw3")
    cfg = base_config.merged({"api": {"auth": {"enabled": True, "pbkdf2_iterations": 1000},
                                      "audit_db": ":memory:"}})
    return TestClient(create_app(cfg))


def _token(client: TestClient, user: str, pw: str) -> dict[str, str]:
    r = client.post("/api/auth/token", data={"username": user, "password": pw})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


class TestSecuredAPI:
    def test_rbac(self, secured_client: TestClient) -> None:
        c = secured_client
        assert c.get("/api/network/status").status_code == 401
        assert c.get("/api/health").status_code == 200
        viewer, oper, admin = (_token(c, "vic", "pw1"), _token(c, "olga", "pw2"),
                               _token(c, "adam", "pw3"))
        assert c.get("/api/network/status", headers=viewer).status_code == 200
        assert c.post("/api/simulation/stop", headers=viewer).status_code == 403
        assert c.post("/api/simulation/stop", headers=oper).status_code == 200
        assert c.get("/api/audit", headers=oper).status_code == 403
        audit = c.get("/api/audit", headers=admin).json()
        assert audit["chain_valid"]
        actions = {e["action"] for e in audit["entries"]}
        assert "auth.login" in actions and any("simulation/stop" in a for a in actions)
        assert c.post("/api/auth/token", data={"username": "vic", "password": "x"}
                      ).status_code == 401

    def test_metrics_endpoint(self, secured_client: TestClient) -> None:
        body = secured_client.get("/metrics").text
        assert "netshield_inference_seconds" in body and "netshield_auth_failures_total" in body


class TestApprovalsAndStreams:
    def test_hybrid_mode_queues_blocks_and_approval_installs(self, base_config: Any,
                                                              detection_input: Any) -> None:
        from netshield.mitigation.engine import MitigationEnforcer, MitigationEngine
        from netshield.mitigation.policy import ActionType, PolicyConfig

        policy = PolicyConfig.from_config(base_config).validate()
        eng = MitigationEngine(policy, MitigationEnforcer(policy, {}))
        eng.approval_mode = "hybrid"
        eng.apply_window(1, 5.0, {"atk-00": 0.99, "iot-01": 0.82})
        assert eng.enforcer.state_for("iot-01").action is ActionType.RATE_LIMIT   # auto
        assert not eng.enforcer.state_for("atk-00").active                     # queued
        pending = [p for p in eng.pending if p["status"] == "pending"]
        assert pending and pending[0]["node"] == "atk-00"
        entry = eng.approve(pending[0]["id"], 7.0, "olga")
        assert eng.enforcer.state_for("atk-00").active and "olga" in entry.reason
        with pytest.raises(ValueError):
            eng.approve(pending[0]["id"], 8.0, "olga")
        eng.rollback("atk-00", 9.0, "olga")
        assert not eng.enforcer.state_for("atk-00").active

    def test_sse_and_websocket(self, base_config: Any) -> None:
        from netshield.api.app import create_app

        client = TestClient(create_app(base_config.merged({"api": {"audit_db": ":memory:"}})))
        with client.stream("GET", "/api/stream?interval_s=0.2&max_events=2") as r:
            events = [line for line in r.iter_lines() if line.startswith("data:")]
        assert len(events) == 2 and json.loads(events[0][5:])["state"]
        with client.websocket_connect("/ws/live?interval_s=0.2&max_events=2") as ws:
            assert "sim_time_s" in json.loads(ws.receive_text())

    def test_alert_export_formats(self, base_config: Any) -> None:
        from netshield.api.app import create_app

        client = TestClient(create_app(base_config.merged({"api": {"audit_db": ":memory:"}})))
        stix = client.get("/api/alerts/export?fmt=stix")
        assert stix.status_code == 200 and stix.json()["type"] == "bundle"
        assert client.get("/api/alerts/export?fmt=cef").status_code == 200
        assert client.get("/api/alerts/export?fmt=xml").status_code == 422


# --------------------------------------------------------------------------- #
# ONNX
# --------------------------------------------------------------------------- #
class TestOnnx:
    def test_graphsage_onnx_equivalence(self, detection_input: Any, base_config: Any,
                                        tmp_path: Any) -> None:
        from netshield.models.graphsage import GraphSAGEDetector
        from netshield.platform.onnx_export import OnnxGraphSAGE, export_graphsage

        det = GraphSAGEDetector.from_config(base_config)
        det.hyper.update({"epochs": 3, "patience": 2})
        det.fit(detection_input, detection_input)
        report = export_graphsage(det, detection_input, tmp_path / "g.onnx")
        assert report["onnx_max_abs_err"] < 1e-4
        served = OnnxGraphSAGE(tmp_path / "g.onnx", det)
        assert np.abs(served.predict_proba(detection_input)
                      - det.predict_proba(detection_input)).max() < 1e-4


class TestInsightRoutes:
    def test_idle_and_replay_endpoints(self, base_config: Any, attack_result: Any,
                                       tmp_path: Any) -> None:
        from netshield.api.app import create_app
        from netshield.api.insight_routes import incident_events

        attack_result.save(tmp_path / attack_result.run_id)
        cfg = base_config.merged({"api": {"audit_db": ":memory:"},
                                  "paths": {"data_experiments": str(tmp_path)}})
        client = TestClient(create_app(cfg))
        assert client.get("/api/timeline").json()["windows"] == []
        assert client.get("/api/explain/iot-00").status_code == 404
        assert client.get("/api/policy").json()["approval_mode"] == "auto"
        runs = client.get("/api/replay/runs").json()
        assert runs and runs[0]["run_id"] == attack_result.run_id
        body = client.get(f"/api/replay/{attack_result.run_id}").json()
        assert body["windows"] and body["topology"]["nodes"]
        assert any(e["kind"] == "attack_start" for e in body["events"])
        assert client.get("/api/replay/..%2F..%2Fetc").status_code == 404
        assert "tables" in client.get("/api/research/summary").json()
        ev = incident_events(attack_result.windows, [], [], attack_result.summary["attack"])
        assert [e["kind"] for e in ev] == ["attack_start", "attack_end"]
