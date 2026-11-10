"""API endpoints for the NS-3 engine and the NetAnim visualizer.

These let the console run a scenario in real NS-3 and open the result in the
NS-3 animator (a desktop window). They are local-only actions: launching
NetAnim opens a GUI on the machine the server runs on.

``GET  /api/ns3/status``            WSL / NS-3 / NetAnim availability
``POST /api/ns3/animate``           run a scenario in NS-3, keep a NetAnim trace
``POST /api/ns3/animate/start``     start a run with live progress
``GET  /api/ns3/animate/jobs/{id}`` poll progress and final result
``POST /api/ns3/netanim/open``      open a saved run's trace in NetAnim
``GET  /api/ns3/runs``              NS-3 runs that have a NetAnim trace
"""

from __future__ import annotations

import json
import threading
import uuid
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, HTTPException, Query

from ..utils.logging_utils import get_logger
from ..utils.paths import resolve

_LOG = get_logger(__name__)
_NS3_JOBS: dict[str, dict[str, Any]] = {}
_NS3_JOBS_LOCK = threading.Lock()


def _result_payload(result: Any) -> dict[str, Any]:
    summary = result.summary
    return {
        "run_id": result.run_id,
        "engine": result.engine,
        "topology": result.topology["family"],
        "n_nodes": len(result.topology["nodes"]),
        "n_links": len(result.topology["links"]),
        "packets_generated": summary.get("packets_generated"),
        "loss_ratio": summary.get("overall_loss_ratio"),
        "clean_delivered_ratio": summary.get("clean_delivered_ratio"),
        "attack_reached_cloud": summary.get("attack_reached_cloud"),
        "attack_offered_total": summary.get("attack_offered_total"),
        "attack_blocked_pct": summary.get("attack_blocked_pct"),
        "attack_reached_pct": summary.get("attack_reached_pct"),
        "gateway_blocked_packets": summary.get("gateway_blocked_packets", 0),
        "gateway_blocked_attack_packets": summary.get("gateway_blocked_attack_packets", 0),
        "gateway_blocked_legit_packets": summary.get("gateway_blocked_legit_packets", 0),
        "anim_available": bool(summary.get("ns3_anim_file")),
        "mitigated": bool(summary.get("ns3_mitigated")),
        "approximations": summary.get("ns3_approximations", []),
    }


def _run_ns3_job(
    job_id: str,
    config: Any,
    meta: Any,
    exp_root: Path,
    mitigate: bool,
) -> None:
    from ..simulation.ns3_run import run_and_save_animated  # noqa: PLC0415
    from ..simulation.ns3_wsl import NS3Unavailable  # noqa: PLC0415

    def update_progress(progress: dict[str, Any]) -> None:
        with _NS3_JOBS_LOCK:
            job = _NS3_JOBS.get(job_id)
            if job is not None:
                job["progress"] = progress

    with _NS3_JOBS_LOCK:
        _NS3_JOBS[job_id]["status"] = "running"
    try:
        result = run_and_save_animated(
            config, meta, exp_root, mitigate=mitigate,
            progress_callback=update_progress,
        )
        payload = _result_payload(result)
        with _NS3_JOBS_LOCK:
            job = _NS3_JOBS[job_id]
            job["result"] = payload
            job["progress"] = {
                **job["progress"],
                "gateway_blocked_packets": payload["gateway_blocked_packets"],
                "gateway_blocked_attack_packets": payload["gateway_blocked_attack_packets"],
                "gateway_blocked_legit_packets": payload["gateway_blocked_legit_packets"],
                "gateway_blocked_pps": 0.0,
                "sim_time_s": job["progress"]["duration_s"],
            }
            job["status"] = "completed"
    except NS3Unavailable as exc:
        with _NS3_JOBS_LOCK:
            _NS3_JOBS[job_id]["status"] = "failed"
            _NS3_JOBS[job_id]["error"] = f"NS-3 unavailable: {exc}"
    except Exception as exc:  # noqa: BLE001
        _LOG.exception("NS-3 animation job %s failed", job_id)
        with _NS3_JOBS_LOCK:
            _NS3_JOBS[job_id]["status"] = "failed"
            _NS3_JOBS[job_id]["error"] = f"NS-3 run failed: {exc}"


def _register_ns3_animation_job_routes(
    app: FastAPI,
    experiments_doc: Any,
    exp_root: Path,
) -> None:
    @app.post("/api/ns3/animate/start", tags=["ns3"])
    def ns3_animate_start(
        scenario: str = Body(..., embed=True),
        duration_s: float = Body(25.0, embed=True),
        overrides: dict[str, Any] | None = Body(None, embed=True),
        mitigate: bool = Body(False, embed=True),
    ) -> dict[str, str]:
        """Start an animated NS-3 run and return its polling job id."""
        known = set((experiments_doc.get("experiments") or {}).keys())
        if scenario not in known:
            raise HTTPException(404, f"Unknown scenario '{scenario}'.")
        from ..utils.config import experiment_config  # noqa: PLC0415

        config, meta = experiment_config(scenario, experiments_doc)
        overrides_set = [f"{key}={value}" for key, value in (overrides or {}).items()]
        config = config.with_set(
            [f"simulation.duration_s={max(5.0, min(60.0, float(duration_s)))}"]
            + overrides_set)
        with _NS3_JOBS_LOCK:
            if any(job["status"] in {"queued", "running"} for job in _NS3_JOBS.values()):
                raise HTTPException(409, "An NS-3 animation is already running.")
            job_id = uuid.uuid4().hex
            _NS3_JOBS[job_id] = {
                "job_id": job_id,
                "status": "queued",
                "progress": {
                    "sim_time_s": 0.0,
                    "duration_s": float(config.require("simulation.duration_s")),
                    "gateway_blocked_packets": 0,
                    "gateway_blocked_attack_packets": 0,
                    "gateway_blocked_legit_packets": 0,
                    "gateway_blocked_pps": 0.0,
                },
                "result": None,
                "error": None,
            }
        threading.Thread(
            target=_run_ns3_job,
            args=(job_id, config, meta, exp_root, mitigate),
            name=f"ns3-animation-{job_id}",
            daemon=True,
        ).start()
        return {"job_id": job_id}

    @app.get("/api/ns3/animate/jobs/{job_id}", tags=["ns3"])
    def ns3_animate_job(job_id: str) -> dict[str, Any]:
        """Return live progress or the final result for an NS-3 animation job."""
        with _NS3_JOBS_LOCK:
            job = _NS3_JOBS.get(job_id)
            if job is None:
                raise HTTPException(404, "Unknown NS-3 animation job.")
            return dict(job)


def register_ns3(app: FastAPI, cfg: Any, experiments_doc: Any) -> None:
    """Attach the NS-3 / NetAnim routes to *app*."""
    exp_root = resolve(cfg.get("paths.data_experiments", "data/experiments"))
    _register_ns3_animation_job_routes(app, experiments_doc, exp_root)

    @app.get("/api/ns3/status", tags=["ns3"])
    def ns3_status() -> dict[str, Any]:
        from ..simulation.ns3_wsl import environment_report  # noqa: PLC0415

        return environment_report()

    @app.post("/api/ns3/animate", tags=["ns3"])
    def ns3_animate(
        scenario: str = Body(..., embed=True),
        duration_s: float = Body(25.0, embed=True),
        overrides: dict[str, Any] | None = Body(None, embed=True),
        mitigate: bool = Body(False, embed=True),
    ) -> dict[str, Any]:
        """Run a scenario in real NS-3 and keep a NetAnim trace of it.

        With ``mitigate=false`` the run is open-loop: the flood runs to
        completion (good for seeing the raw attack). With ``mitigate=true`` the
        NS-3 model installs a reactive rate-based policer at the gateway, so the
        flood is throttled and then cut off inside the run and in NetAnim. The
        duration is capped so the animation stays watchable; pass overrides for
        the topology family, attack type, attacker count, rate, etc.
        """
        known = set((experiments_doc.get("experiments") or {}).keys())
        if scenario not in known:
            raise HTTPException(404, f"Unknown scenario '{scenario}'.")
        from ..simulation.ns3_run import run_and_save_animated  # noqa: PLC0415
        from ..simulation.ns3_wsl import NS3Unavailable  # noqa: PLC0415
        from ..utils.config import experiment_config  # noqa: PLC0415

        config, meta = experiment_config(scenario, experiments_doc)
        sets = [f"simulation.duration_s={max(5.0, min(60.0, float(duration_s)))}"]
        for key, value in (overrides or {}).items():
            sets.append(f"{key}={value}")
        config = config.with_set(sets)
        try:
            result = run_and_save_animated(config, meta, exp_root, mitigate=mitigate)
        except NS3Unavailable as exc:
            raise HTTPException(503, f"NS-3 unavailable: {exc}") from exc
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(500, f"NS-3 run failed: {exc}") from exc
        return _result_payload(result)

    @app.post("/api/ns3/netanim/open", tags=["ns3"])
    def netanim_open(run_id: str = Body(..., embed=True)) -> dict[str, Any]:
        """Open a saved run's NetAnim trace in the NS-3 animator window."""
        from ..simulation.ns3_wsl import launch_netanim  # noqa: PLC0415

        run_dir = (exp_root / run_id).resolve()
        if exp_root.resolve() not in run_dir.parents:
            raise HTTPException(400, "Invalid run id.")
        trace = run_dir / "netanim.xml"
        if not trace.exists():
            raise HTTPException(404, "This run has no NetAnim trace. Run it via "
                                "/api/ns3/animate first.")
        out = launch_netanim(trace)
        if not out.get("launched"):
            raise HTTPException(503, f"Could not open NetAnim: {out.get('reason')}")
        return {"opened": True, "run_id": run_id, "pid": out.get("pid")}

    @app.get("/api/ns3/runs", tags=["ns3"])
    def ns3_runs(limit: int = Query(40, ge=1, le=200)) -> list[dict[str, Any]]:
        """List NS-3 runs that have a NetAnim trace available."""
        out: list[dict[str, Any]] = []
        for trace in sorted(exp_root.glob("*/netanim.xml"),
                            key=lambda p: p.stat().st_mtime, reverse=True):
            run_dir = trace.parent
            doc = {}
            try:
                doc = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                pass
            meta = doc.get("meta", {})
            summ = doc.get("summary", {})
            out.append({
                "run_id": run_dir.name,
                "experiment": meta.get("experiment"),
                "topology": summ.get("ns3_spec", {}).get("n_nodes") and
                doc.get("topology", {}).get("family"),
                "engine": doc.get("engine"),
                "packets": summ.get("packets_generated"),
                "mitigated": bool(summ.get("ns3_mitigated")),
                "attack_blocked_pct": summ.get("attack_blocked_pct"),
                "generated_at": doc.get("generated_at"),
            })
            if len(out) >= limit:
                break
        return out
