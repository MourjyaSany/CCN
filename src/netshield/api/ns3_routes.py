"""API endpoints for the NS-3 engine and the NetAnim visualizer.

These let the console run a scenario in real NS-3 and open the result in the
NS-3 animator (a desktop window). They are local-only actions: launching
NetAnim opens a GUI on the machine the server runs on.

``GET  /api/ns3/status``            WSL / NS-3 / NetAnim availability
``POST /api/ns3/animate``           run a scenario in NS-3, keep a NetAnim trace
``POST /api/ns3/netanim/open``      open a saved run's trace in NetAnim
``GET  /api/ns3/runs``              NS-3 runs that have a NetAnim trace
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import Body, FastAPI, HTTPException, Query

from ..utils.logging_utils import get_logger
from ..utils.paths import resolve

_LOG = get_logger(__name__)


def register_ns3(app: FastAPI, cfg: Any, experiments_doc: Any) -> None:
    """Attach the NS-3 / NetAnim routes to *app*."""
    exp_root = resolve(cfg.get("paths.data_experiments", "data/experiments"))

    @app.get("/api/ns3/status", tags=["ns3"])
    def ns3_status() -> dict[str, Any]:
        from ..simulation.ns3_wsl import environment_report  # noqa: PLC0415

        return environment_report()

    @app.post("/api/ns3/animate", tags=["ns3"])
    def ns3_animate(
        scenario: str = Body(..., embed=True),
        duration_s: float = Body(25.0, embed=True),
        overrides: dict[str, Any] | None = Body(None, embed=True),
    ) -> dict[str, Any]:
        """Run a scenario in real NS-3 and keep a NetAnim trace of it.

        The run is open-loop (NS-3 does not enforce mitigation). The duration
        is capped so the animation stays watchable; pass overrides for the
        topology family, attacker count, rate, etc.
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
            result = run_and_save_animated(config, meta, exp_root)
        except NS3Unavailable as exc:
            raise HTTPException(503, f"NS-3 unavailable: {exc}") from exc
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(500, f"NS-3 run failed: {exc}") from exc
        s = result.summary
        return {
            "run_id": result.run_id,
            "engine": result.engine,
            "topology": result.topology["family"],
            "n_nodes": len(result.topology["nodes"]),
            "n_links": len(result.topology["links"]),
            "packets_generated": s.get("packets_generated"),
            "loss_ratio": s.get("overall_loss_ratio"),
            "anim_available": bool(s.get("ns3_anim_file")),
            "approximations": s.get("ns3_approximations", []),
        }

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
                "generated_at": doc.get("generated_at"),
            })
            if len(out) >= limit:
                break
        return out
