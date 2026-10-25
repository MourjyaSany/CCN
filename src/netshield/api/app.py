"""FastAPI application: REST API and the served dashboard.

Interactive OpenAPI documentation is generated automatically at ``/docs``
(Swagger UI) and ``/redoc``. The bundled dashboard is served at ``/``.

The API is read-mostly. The two state-changing endpoints
(``/api/simulation/start`` and ``/api/simulation/stop``) drive an in-process
simulation and cannot touch anything outside this process - there is no host
networking, no shelling out, and no path by which a request can cause traffic to
leave the machine.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from ..detection.pipeline import PipelineError, load_detectors
from ..models.base import Detector
from ..simulation.ns3_bridge import detect_ns3, engine_label, resolve_engine
from ..utils.config import Config, experiment_config, load_config, load_experiments
from ..utils.logging_utils import get_logger, setup_logging
from ..utils.paths import repo_root, resolve
from .schemas import (
    Alert,
    AttackFamilyInfo,
    CustomAttackRequest,
    ExperimentRequest,
    FigureInfo,
    HealthResponse,
    MetricsResponse,
    MitigationRecord,
    NetworkStatus,
    ResultsResponse,
    ScenarioInfo,
    SimulationStatus,
    StartSimulationRequest,
    TopologyFamilyInfo,
    TopologyResponse,
    TrafficSnapshot,
)
from .state import OverrideRejected, SimulationSession

_LOG = get_logger(__name__)

STATIC_DIR = Path(__file__).parent / "static"

API_DESCRIPTION = """
REST API for **NetShield-GNN**, an academic IoT-cloud DDoS detection and
mitigation simulator.

* Every attack is generated **inside an in-memory discrete-event simulator**.
  No endpoint can cause a packet to leave this machine.
* `/api/simulation/start` runs a scenario on a background thread and streams its
  state through the read endpoints below.
* Figures, metrics and reports are produced by the command-line scripts
  (`scripts/run_experiment.py`, `scripts/evaluate.py`) and surfaced read-only by
  `/api/results`.
"""


def _load_detectors_safe(models_dir: Path) -> dict[str, Detector]:
    """Load detectors, returning an empty mapping when none are trained yet."""
    try:
        from ..detection.pipeline import ALL_DETECTORS, DETECTOR_CLASSES  # noqa: PLC0415

        present = [n for n in (*ALL_DETECTORS, *DETECTOR_CLASSES)
                   if (Path(models_dir) / n / "manifest.json").exists()]
        names = list(dict.fromkeys(present)) or None
        return load_detectors(models_dir, names)
    except PipelineError as exc:
        _LOG.warning("No trained detectors available: %s", exc)
        return {}


def create_app(config: Config | None = None) -> FastAPI:
    """Build the FastAPI application.

    Args:
        config: Pre-loaded configuration; loaded from disk when omitted.

    Returns:
        The configured :class:`fastapi.FastAPI` instance.
    """
    cfg = config or load_config()
    setup_logging(level=str(cfg.get("logging.level", "INFO")))

    app = FastAPI(
        title="NetShield-GNN API",
        description=API_DESCRIPTION,
        version=str(cfg.get("project.version", "1.0.0")),
        docs_url="/docs",
        redoc_url="/redoc",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(cfg.get("api.cors_origins", ["*"])) or ["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    models_dir = resolve(cfg.get("paths.models", "models"))
    detectors: dict[str, Detector] = _load_detectors_safe(models_dir)
    experiments_doc = load_experiments()

    def config_factory(scenario: str) -> tuple[Config, dict[str, Any]]:
        """Return the configuration for a named scenario."""
        return experiment_config(scenario, experiments_doc)

    def detector_provider() -> dict[str, Detector]:
        """Return the loaded detectors, retrying the load if none are present."""
        nonlocal detectors
        if not detectors:
            detectors = _load_detectors_safe(models_dir)
        return detectors

    def persist(result: Any) -> None:
        """Persist a completed run to SQLite."""
        try:
            from ..database.store import NetShieldDB  # noqa: PLC0415

            db = NetShieldDB(cfg.path("database"))
            controller = session.controller
            db.store_run(
                result,
                detections=(controller.detection_log if controller else None),
                mitigations=result.mitigations or None,
                trigger=float(cfg.get("detection.mitigation_trigger_probability", 0.8)),
            )
        except Exception as exc:  # noqa: BLE001 - persistence must not break the run
            _LOG.warning("Could not persist run: %s", exc)

    session = SimulationSession(config_factory, detector_provider, on_complete=persist)
    app.state.config = cfg
    app.state.session = session

    # ------------------------------------------------------------------ #
    # health & metadata
    # ------------------------------------------------------------------ #
    @app.get("/api/health", response_model=HealthResponse, tags=["system"])
    def health() -> HealthResponse:
        """Report liveness and which optional capabilities are present."""
        from ..models.graphsage import BACKEND  # noqa: PLC0415

        probe = detect_ns3()
        engine_id, _ = resolve_engine(str(cfg.get("simulation.engine", "auto")), probe)
        dataset = resolve(cfg.get("paths.data_processed", "data/processed")) / "dataset.csv"
        return HealthResponse(
            status="ok",
            version=str(cfg.get("project.version", "1.0.0")),
            engine=engine_label(engine_id),
            ns3_available=probe.available,
            gnn_backend=BACKEND,
            detectors_loaded=sorted(detector_provider().keys()),
            database=str(cfg.path("database")),
            dataset_available=dataset.exists(),
        )

    scenario_cache: list[ScenarioInfo] = []

    @app.get("/api/scenarios", response_model=list[ScenarioInfo], tags=["system"])
    def scenarios() -> list[ScenarioInfo]:
        """List every runnable scenario declared in ``config/experiments.yaml``."""
        if scenario_cache:
            return scenario_cache
        out: list[ScenarioInfo] = scenario_cache
        for name in (experiments_doc.get("experiments") or {}):
            scenario_cfg, meta = experiment_config(name, experiments_doc)
            attack = scenario_cfg.get("attack", {}) or {}
            out.append(ScenarioInfo(
                name=name,
                description=str(meta.get("description", "")),
                tags=list(meta.get("tags", [])),
                n_iot_devices=int(scenario_cfg.get("simulation.n_iot_devices", 0)),
                n_attackers=int(scenario_cfg.get("simulation.n_attackers", 0)),
                duration_s=float(scenario_cfg.get("simulation.duration_s", 0.0)),
                attack_type=str(attack.get("type", "")) if attack.get("enabled") else "",
                attack_start_s=float(attack["start_s"]) if attack.get("enabled") else None,
                attack_duration_s=(
                    float(attack["duration_s"]) if attack.get("enabled") else None
                ),
                mitigation_enabled=bool(scenario_cfg.get("mitigation.enabled", False)),
                holdout=bool(meta.get("holdout", False)),
            ))
        return out

    @app.get("/api/environment", tags=["system"])
    def environment() -> dict[str, Any]:
        """Return the full environment probe used to label results."""
        from ..simulation.ns3_bridge import environment_report  # noqa: PLC0415

        return environment_report()

    # ------------------------------------------------------------------ #
    # simulation control
    # ------------------------------------------------------------------ #
    @app.post("/api/simulation/start", response_model=SimulationStatus,
              tags=["simulation"])
    def start_simulation(request: StartSimulationRequest) -> SimulationStatus:
        """Start a scenario on a background thread.

        Raises:
            HTTPException: 409 if a simulation is already running, 404 if the
                scenario name is unknown.
        """
        known = set((experiments_doc.get("experiments") or {}).keys())
        if request.scenario not in known:
            raise HTTPException(
                status_code=404,
                detail=f"Unknown scenario '{request.scenario}'. "
                       f"Available: {sorted(known)}",
            )
        try:
            snapshot = session.start(
                scenario=request.scenario,
                speed=request.speed,
                mitigation=request.mitigation,
                detector_name=request.detector,
                duration_s=request.duration_s,
                overrides=request.overrides,
            )
        except OverrideRejected as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return _status_model(snapshot)

    @app.post("/api/simulation/stop", response_model=SimulationStatus,
              tags=["simulation"])
    def stop_simulation() -> SimulationStatus:
        """Ask the running simulation to stop at the next window boundary."""
        return _status_model(session.stop())

    @app.get("/api/simulation/status", response_model=SimulationStatus,
             tags=["simulation"])
    def simulation_status() -> SimulationStatus:
        """Return the live session state."""
        return _status_model(session.snapshot())

    def _status_model(snapshot: Any) -> SimulationStatus:
        """Convert a session snapshot into the response model."""
        return SimulationStatus(
            state=snapshot.state,
            scenario=snapshot.scenario,
            run_id=snapshot.run_id,
            engine_label=snapshot.engine_label,
            sim_time_s=round(snapshot.sim_time_s, 3),
            duration_s=snapshot.duration_s,
            progress=round(snapshot.progress(), 4),
            mitigation_enabled=snapshot.mitigation_enabled,
            detector=snapshot.detector,
            error=snapshot.error,
        )

    # ------------------------------------------------------------------ #
    # live network views
    # ------------------------------------------------------------------ #
    @app.get("/api/network/status", response_model=NetworkStatus, tags=["network"])
    def network_status() -> NetworkStatus:
        """Aggregate live status: devices, traffic, threats and mitigation."""
        snapshot = session.snapshot()
        latest = snapshot.windows[-1] if snapshot.windows else {}
        nodes = snapshot.node_state

        suspicious = sum(1 for n in nodes if n.get("predicted") == "SUSPICIOUS")
        malicious = sum(1 for n in nodes if n.get("predicted") == "MALICIOUS")
        mitigated = sum(1 for n in nodes if n.get("mitigation"))
        attack = snapshot.attack or {}
        active = bool(
            attack.get("enabled")
            and float(attack.get("start_s", 0)) <= snapshot.sim_time_s
            < float(attack.get("end_s", 0))
        )

        return NetworkStatus(
            state=snapshot.state,
            scenario=snapshot.scenario,
            run_id=snapshot.run_id,
            engine_label=snapshot.engine_label,
            sim_time_s=round(snapshot.sim_time_s, 2),
            duration_s=snapshot.duration_s,
            progress=round(snapshot.progress(), 4),
            n_devices=sum(1 for n in nodes if n.get("kind") in ("iot", "attacker")),
            n_routers=sum(1 for n in nodes if n.get("kind") == "router"),
            n_suspicious=suspicious,
            n_malicious=malicious,
            n_mitigated=mitigated,
            active_attack=active,
            attack_type=str(attack.get("type", "")) if attack.get("enabled") else "",
            packets_per_second=float(latest.get("pps", 0.0)),
            throughput_mbps=float(latest.get("throughput_mbps", 0.0)),
            latency_ms=float(latest.get("mean_latency_ms", 0.0)),
            clean_latency_ms=float(
                latest.get("clean_mean_latency_ms",
                           latest.get("legit_mean_latency_ms", 0.0))
            ),
            packet_loss=float(latest.get("loss_ratio", 0.0)),
            clean_packet_loss=float(
                latest.get("clean_loss_ratio",
                           latest.get("legit_loss_ratio", 0.0))
            ),
            uplink_utilisation=float(latest.get("uplink_utilisation", 0.0)),
            max_confidence=max((float(n.get("probability", 0.0)) for n in nodes),
                               default=0.0),
            detector=snapshot.detector,
        )

    @app.get("/api/network/topology", response_model=TopologyResponse, tags=["network"])
    def topology() -> TopologyResponse:
        """Return the topology with live per-node classification and mitigation."""
        snapshot = session.snapshot()
        topo = snapshot.topology or {}
        by_id = {n["node_id"]: n for n in snapshot.node_state}

        nodes = []
        for node in topo.get("nodes", []):
            live = by_id.get(node["node_id"], {})
            nodes.append({
                "node_id": node["node_id"],
                "kind": node["kind"],
                "ip": node.get("ip", ""),
                "device_class": node.get("device_class", ""),
                "tier": int(node.get("tier", 3)),
                "parent": node.get("parent"),
                "is_attacker": bool(node.get("is_attacker", False)),
                "probability": float(live.get("probability", 0.0)),
                "predicted": str(live.get("predicted", "BENIGN")),
                "packet_rate": float(live.get("packet_rate", 0.0)),
                "mitigation": str(live.get("mitigation", "")),
            })

        return TopologyResponse(
            name=str(topo.get("name", "")),
            run_id=snapshot.run_id,
            n_nodes=len(nodes),
            n_links=len(topo.get("links", [])),
            nodes=nodes,
            links=topo.get("links", []),
        )

    @app.get("/api/traffic/current", response_model=TrafficSnapshot, tags=["network"])
    def current_traffic() -> TrafficSnapshot:
        """Return the most recent completed window plus the top talkers."""
        snapshot = session.snapshot()
        latest = snapshot.windows[-1] if snapshot.windows else {}
        talkers = sorted(
            snapshot.node_state,
            key=lambda n: float(n.get("packet_rate", 0.0)),
            reverse=True,
        )[:10]
        return TrafficSnapshot(
            window=int(latest.get("window", 0)),
            t_start=float(latest.get("t_start", 0.0)),
            t_end=float(latest.get("t_end", 0.0)),
            packets_per_second=float(latest.get("pps", 0.0)),
            throughput_mbps=float(latest.get("throughput_mbps", 0.0)),
            offered_mbps=float(latest.get("offered_mbps", 0.0)),
            delivered_packets=int(latest.get("delivered_packets", 0)),
            dropped_packets=int(latest.get("dropped_packets", 0)),
            loss_ratio=float(latest.get("loss_ratio", 0.0)),
            mean_latency_ms=float(latest.get("mean_latency_ms", 0.0)),
            uplink_utilisation=float(latest.get("uplink_utilisation", 0.0)),
            top_talkers=[
                {
                    "node_id": n["node_id"],
                    "kind": n["kind"],
                    "packet_rate": round(float(n.get("packet_rate", 0.0)), 2),
                    "probability": round(float(n.get("probability", 0.0)), 4),
                    "predicted": n.get("predicted", "BENIGN"),
                    "mitigation": n.get("mitigation", ""),
                }
                for n in talkers
            ],
        )

    @app.get("/api/alerts", response_model=list[Alert], tags=["detection"])
    def alerts(
        limit: int = Query(default=100, ge=1, le=1000),
        min_confidence: float = Query(default=None, ge=0.0, le=1.0),
    ) -> list[Alert]:
        """Return detections above the mitigation trigger, newest first."""
        snapshot = session.snapshot()
        threshold = (
            min_confidence if min_confidence is not None
            else float(cfg.get("detection.mitigation_trigger_probability", 0.8))
        )
        rows = [
            row for row in snapshot.detections
            if float(row.get("probability", 0.0)) >= threshold
        ]
        rows.sort(key=lambda r: (-float(r.get("timestamp", 0.0)),
                                 -float(r.get("probability", 0.0))))
        return [
            Alert(
                timestamp=float(r["timestamp"]),
                window=int(r["window"]),
                node_id=str(r["node"]),
                ip=str(r.get("ip", "")),
                severity=str(r.get("predicted", "SUSPICIOUS")),
                confidence=float(r["probability"]),
                detector=str(r.get("detector", "")),
                packet_rate=float(r.get("packet_rate", 0.0)),
                message=(
                    f"{r['node']} classified {r.get('predicted', '?')} "
                    f"(p={float(r['probability']):.2f}) at "
                    f"t={float(r['timestamp']):.1f}s, "
                    f"{float(r.get('packet_rate', 0.0)):.0f} pkt/s"
                ),
            )
            for r in rows[:limit]
        ]

    @app.get("/api/detections", tags=["detection"])
    def detections(
        window: int = Query(default=None, ge=0),
        limit: int = Query(default=500, ge=1, le=5000),
    ) -> list[dict[str, Any]]:
        """Return raw per-node detection rows, optionally for one window."""
        rows = session.snapshot().detections
        if window is not None:
            rows = [r for r in rows if int(r.get("window", -1)) == window]
        return rows[-limit:]

    @app.get("/api/mitigation", response_model=list[MitigationRecord],
             tags=["mitigation"])
    def mitigation(limit: int = Query(default=100, ge=1, le=1000)
                   ) -> list[MitigationRecord]:
        """Return the mitigation action log, newest first."""
        rows = list(session.snapshot().mitigations)
        rows.sort(key=lambda r: -float(r.get("timestamp", 0.0)))
        return [
            MitigationRecord(
                timestamp=float(r["timestamp"]),
                window=int(r["window"]),
                node=str(r["node"]),
                ip=str(r.get("ip", "")),
                action=str(r["action"]),
                confidence=float(r["confidence"]),
                detector=str(r.get("detector", "")),
                reason=str(r.get("reason", "")),
                result=dict(r.get("result", {})),
            )
            for r in rows[:limit]
        ]

    @app.get("/api/metrics", response_model=MetricsResponse, tags=["network"])
    def metrics() -> MetricsResponse:
        """Return the full per-window QoS series for the current run."""
        snapshot = session.snapshot()
        first = None
        if snapshot.mitigations:
            first = min(float(m["timestamp"]) for m in snapshot.mitigations)
        return MetricsResponse(
            run_id=snapshot.run_id,
            engine_label=snapshot.engine_label,
            window_s=float(cfg.get("features.window_s", 5.0)),
            attack=snapshot.attack,
            first_mitigation_s=first,
            windows=snapshot.windows,
        )

    # ------------------------------------------------------------------ #
    # experiments & results
    # ------------------------------------------------------------------ #
    @app.post("/api/experiment/run", tags=["experiments"])
    def run_experiment(request: ExperimentRequest) -> dict[str, Any]:
        """Run one experiment to completion as fast as possible.

        This is the batch path: it starts the same background session used by
        the live view but with pacing disabled.

        Raises:
            HTTPException: 409 if a simulation is already running.
        """
        known = set((experiments_doc.get("experiments") or {}).keys())
        if request.experiment not in known:
            raise HTTPException(status_code=404,
                                detail=f"Unknown experiment '{request.experiment}'.")
        try:
            session.start(scenario=request.experiment, speed=0.0,
                          detector_name=request.detector,
                          duration_s=request.duration_s)
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {
            "started": True,
            "experiment": request.experiment,
            "note": "Poll /api/simulation/status until state is 'completed'.",
        }

    @app.get("/api/results", response_model=ResultsResponse, tags=["results"])
    def results() -> ResultsResponse:
        """Return stored evaluation results and the artefacts on disk."""
        metrics_dir = resolve(cfg.get("paths.metrics", "results/metrics"))
        figures_dir = resolve(cfg.get("paths.figures", "results/figures"))
        reports_dir = resolve(cfg.get("paths.reports", "results/reports"))
        processed = resolve(cfg.get("paths.data_processed", "data/processed"))

        comparison_path = metrics_dir / "detector_comparison.csv"
        if not comparison_path.exists():
            return ResultsResponse(
                available=False,
                message="No evaluation results yet. Run 'python scripts/evaluate.py' "
                        "(or './run.sh all') to generate them.",
                figures=sorted(p.name for p in figures_dir.glob("*.png")),
            )

        import pandas as pd  # noqa: PLC0415

        comparison = pd.read_csv(comparison_path).to_dict("records")
        per_experiment_path = metrics_dir / "per_experiment_metrics.csv"
        per_experiment = (
            pd.read_csv(per_experiment_path).to_dict("records")
            if per_experiment_path.exists() else []
        )
        dataset_report_path = processed / "dataset_report.json"
        dataset = (
            json.loads(dataset_report_path.read_text(encoding="utf-8"))
            if dataset_report_path.exists() else {}
        )
        return ResultsResponse(
            available=True,
            detectors=comparison,
            per_experiment=per_experiment,
            figures=sorted(p.name for p in figures_dir.glob("*.png")),
            reports=sorted(p.name for p in reports_dir.glob("*.md")),
            dataset=dataset,
            message="",
        )

    @app.get("/api/runs", tags=["results"])
    def runs(limit: int = Query(default=25, ge=1, le=200)) -> list[dict[str, Any]]:
        """List the runs persisted in the database."""
        try:
            from ..database.store import NetShieldDB  # noqa: PLC0415

            return NetShieldDB(cfg.path("database"), create=False).list_runs(limit)
        except Exception as exc:  # noqa: BLE001
            _LOG.warning("Could not list runs: %s", exc)
            return []

    @app.get("/api/figures/{name}", tags=["results"])
    def figure(name: str) -> FileResponse:
        """Serve a generated figure by filename.

        Raises:
            HTTPException: 400 for a path-traversal attempt, 404 if absent.
        """
        if "/" in name or "\\" in name or ".." in name:
            raise HTTPException(status_code=400, detail="Invalid figure name.")
        path = resolve(cfg.get("paths.figures", "results/figures")) / name
        if not path.exists():
            raise HTTPException(status_code=404, detail=f"No figure named '{name}'.")
        return FileResponse(path)

    # ------------------------------------------------------------------ #
    # catalogue: what the simulator can be asked to do
    # ------------------------------------------------------------------ #
    @app.get("/api/topologies", response_model=list[TopologyFamilyInfo],
             tags=["catalogue"])
    def topologies() -> list[TopologyFamilyInfo]:
        """List the available topology families and their tunables."""
        from ..simulation.topologies import FAMILY_DESCRIPTIONS, TOPOLOGY_FAMILIES

        spec = cfg.get("network.topology", {}) or {}
        out: list[TopologyFamilyInfo] = []
        for name in TOPOLOGY_FAMILIES:
            params = spec.get(name, {}) if isinstance(spec.get(name), dict) else {}
            out.append(
                TopologyFamilyInfo(
                    name=name,
                    description=FAMILY_DESCRIPTIONS.get(name, ""),
                    parameters=dict(params),
                )
            )
        return out

    @app.get("/api/attacks", response_model=list[AttackFamilyInfo], tags=["catalogue"])
    def attacks() -> list[AttackFamilyInfo]:
        """List the available attack families."""
        from ..traffic.attacks import ATTACK_TYPES, FAMILY_DESCRIPTIONS as ATTACK_DESC

        layers = {
            "udp_flood": "volumetric",
            "icmp_flood": "volumetric",
            "syn_flood": "protocol",
            "ack_flood": "protocol",
            "http_flood": "application",
            "slowloris": "application",
            "mixed": "mixed",
        }
        return [
            AttackFamilyInfo(
                name=name,
                description=ATTACK_DESC.get(name, ""),
                layer=layers.get(name, "unknown"),
            )
            for name in ATTACK_TYPES
        ]

    @app.get("/api/attacks/schema", tags=["catalogue"])
    def attack_schema() -> dict[str, Any]:
        """Return the attack-builder form schema and current defaults.

        The dashboard renders its builder from this, so a new attack knob
        appears in the UI as soon as it exists in the configuration - the form
        is never hard-coded against a stale copy of the schema.
        """
        from ..simulation.topologies import TOPOLOGY_FAMILIES
        from ..traffic.attacks import ATTACK_TYPES, RATE_PROFILES
        from .state import ALLOWED_OVERRIDE_KEYS, ALLOWED_OVERRIDE_PREFIXES

        return {
            "attack_types": list(ATTACK_TYPES),
            "rate_profiles": list(RATE_PROFILES),
            "topology_families": list(TOPOLOGY_FAMILIES),
            "defaults": cfg.get("attack", {}) or {},
            "allowed_override_prefixes": list(ALLOWED_OVERRIDE_PREFIXES),
            "allowed_override_keys": sorted(ALLOWED_OVERRIDE_KEYS),
            "limits": {
                "packets_per_second": {"min": 1, "max": 20000},
                "n_attackers": {"min": 0, "max": 64},
                "n_iot_devices": {"min": 1, "max": 128},
                "duration_s": {"min": 10, "max": 300},
            },
        }

    @app.post("/api/attack/preview", tags=["catalogue"])
    def attack_preview(request: CustomAttackRequest) -> dict[str, Any]:
        """Validate a builder configuration without running it.

        Merges the overrides onto the chosen base scenario and resolves the
        attack profile, returning either the resolved profile or the exact
        validation error. This is what lets the dashboard tell the user their
        configuration is wrong *before* they wait for a simulation.
        """
        from ..traffic.attacks import AttackProfile
        from .state import sanitise_overrides

        try:
            clean = sanitise_overrides(request.overrides)
        except OverrideRejected as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        try:
            config, meta = config_factory(request.scenario)
        except Exception as exc:  # noqa: BLE001 - surfaced as a 404
            raise HTTPException(status_code=404, detail=str(exc)) from exc

        try:
            merged = config.with_set([f"{k}={v}" for k, v in clean.items()])
            profile = AttackProfile.from_config(merged).validate()
        except Exception as exc:  # noqa: BLE001 - the point is to report it
            return {
                "valid": False,
                "error": f"{type(exc).__name__}: {exc}",
                "overrides": clean,
            }

        n_attackers = int(merged.get("simulation.n_attackers", 0))
        aggregate = profile.packets_per_second * n_attackers
        return {
            "valid": True,
            "profile": profile.to_dict(),
            "topology_family": merged.get("network.topology.family", "tree"),
            "n_attackers": n_attackers,
            "n_iot_devices": int(merged.get("simulation.n_iot_devices", 0)),
            "duration_s": float(merged.get("simulation.duration_s", 0.0)),
            "aggregate_pps": aggregate,
            "estimated_packets": int(aggregate * profile.duration_s),
            "overrides": clean,
        }

    @app.get("/api/figures", response_model=list[FigureInfo], tags=["results"])
    def figures() -> list[FigureInfo]:
        """List every generated figure with its fetch URL."""
        directory = resolve(cfg.get("paths.figures", "results/figures"))
        if not directory.is_dir():
            return []
        out: list[FigureInfo] = []
        for path in sorted(directory.glob("*.png")):
            stem = path.stem
            experiment = stem.split("_")[0] if stem.startswith("exp") else ""
            out.append(
                FigureInfo(
                    name=path.name,
                    url=f"/api/figures/{path.name}",
                    size_bytes=path.stat().st_size,
                    experiment=experiment,
                )
            )
        return out

    @app.get("/api/reports", tags=["results"])
    def reports() -> list[dict[str, Any]]:
        """List the generated markdown reports."""
        directory = resolve(cfg.get("paths.reports", "results/reports"))
        if not directory.is_dir():
            return []
        return [
            {"name": p.name, "size_bytes": p.stat().st_size,
             "url": f"/api/reports/{p.name}"}
            for p in sorted(directory.glob("*.md"))
        ]

    @app.get("/api/reports/{name}", tags=["results"])
    def report(name: str) -> dict[str, Any]:
        """Return one markdown report as text.

        Raises:
            HTTPException: 400 for a path-traversal attempt, 404 if absent.
        """
        if "/" in name or "\\" in name or ".." in name:
            raise HTTPException(status_code=400, detail="Invalid report name.")
        path = resolve(cfg.get("paths.reports", "results/reports")) / name
        if not path.exists():
            raise HTTPException(status_code=404, detail=f"No report named '{name}'.")
        return {"name": name, "markdown": path.read_text(encoding="utf-8")}

    @app.get("/api/models", tags=["results"])
    def models() -> list[dict[str, Any]]:
        """Return the manifest of every trained detector on disk."""
        directory = resolve(cfg.get("paths.models", "models"))
        if not directory.is_dir():
            return []
        out: list[dict[str, Any]] = []
        for manifest in sorted(directory.glob("*/manifest.json")):
            try:
                data = json.loads(manifest.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            data["loaded"] = data.get("detector", "") in detectors
            out.append(data)
        return out

    # ------------------------------------------------------------------ #
    # dashboard
    # ------------------------------------------------------------------ #
    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    frontend_dist = repo_root() / "frontend" / "dist"
    if frontend_dist.is_dir():
        app.mount("/app/assets", StaticFiles(directory=str(frontend_dist / "assets"),
                                             check_dir=False), name="frontend-assets")

        @app.get("/app", include_in_schema=False)
        @app.get("/app/{path:path}", include_in_schema=False)
        def console(path: str = "") -> FileResponse:
            """Serve the console; unknown paths fall back to index.html (SPA routing)."""
            target = (frontend_dist / path).resolve()
            if path and frontend_dist.resolve() in target.parents and target.is_file():
                return FileResponse(target)
            return FileResponse(frontend_dist / "index.html")

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def dashboard() -> Any:
        """Serve the operations console (or the bundled fallback dashboard)."""
        if (frontend_dist / "index.html").exists():
            return RedirectResponse("/app/")
        return legacy_dashboard()

    @app.get("/legacy", response_class=HTMLResponse, include_in_schema=False)
    def legacy_dashboard() -> HTMLResponse:
        """Serve the original dependency-free dashboard."""
        index = STATIC_DIR / "index.html"
        if index.exists():
            return HTMLResponse(index.read_text(encoding="utf-8"))
        return HTMLResponse(
            "<h1>NetShield-GNN</h1><p>Dashboard assets are missing. "
            "The API is available at <a href='/docs'>/docs</a>.</p>",
            status_code=200,
        )

    @app.exception_handler(404)
    async def not_found(_request: Any, exc: Any) -> JSONResponse:  # noqa: ANN401
        """Return a helpful JSON body for unknown routes."""
        return JSONResponse(
            status_code=404,
            content={
                "detail": getattr(exc, "detail", "Not found"),
                "hint": "Interactive API documentation is at /docs",
            },
        )

    _LOG.info(
        "NetShield-GNN API ready (detectors: %s)",
        sorted(detectors) or "none trained yet",
    )
    from .platform_routes import register_platform  # noqa: PLC0415

    register_platform(app, cfg, session)
    from .insight_routes import register_insights  # noqa: PLC0415

    register_insights(app, cfg, session)
    return app


app = None  # populated by main() / uvicorn factory


def get_app() -> FastAPI:
    """Uvicorn application factory (``uvicorn netshield.api.app:get_app``)."""
    return create_app()
