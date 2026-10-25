"""Platform endpoints: auth, RBAC, approvals, live streaming, metrics, export, audit.

Registered by :func:`netshield.api.app.create_app` after the core routes.

Security model
--------------
When ``api.auth.enabled`` is true (or ``NETSHIELD_AUTH=1``), a middleware
requires a bearer token on every ``/api`` and ``/ws`` request except login,
health and metrics, and enforces the minimum role from
:data:`netshield.platform.security.ACCESS_RULES`. Every state-changing
request and every authorisation failure is written to the audit trail.

Endpoints
---------
``POST /api/auth/token``              OAuth2 password grant -> JWT
``GET  /api/auth/me``                 current identity
``GET  /api/approvals``               queued mitigation actions
``POST /api/approvals/{id}/approve``  install a queued action   (operator)
``POST /api/approvals/{id}/reject``   discard a queued action   (operator)
``POST /api/mitigation/{node}/rollback``  release a live rule  (operator)
``GET  /api/stream``                  Server-Sent Events of the live snapshot
``WS   /ws/live``                     WebSocket of the live snapshot
``GET  /metrics``                     Prometheus exposition
``GET  /api/alerts/export``           STIX 2.1 bundle or CEF lines
``GET  /api/audit``                   audit trail                (admin)
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Any

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request, WebSocket
from fastapi.responses import JSONResponse, Response, StreamingResponse
from starlette.websockets import WebSocketDisconnect

from ..platform.audit import AuditLog
from ..platform.interop import export_alerts
from ..platform.metrics import NetShieldMetrics
from ..platform.security import (
    AuthError,
    TokenService,
    UserStore,
    required_role,
    role_rank,
)
from ..utils.paths import resolve

_PUBLIC = {"", None}


def _snapshot_payload(session: Any) -> dict[str, Any]:
    snap = session.snapshot()
    windows = list(snap.windows or [])
    latest = windows[-1] if windows else {}
    controller = getattr(session, "controller", None)
    engine = getattr(controller, "mitigation", None) if controller else None
    detections = list(getattr(controller, "detection_log", []) or [])[-200:] if controller else []
    return {
        "state": snap.state, "scenario": snap.scenario, "run_id": snap.run_id,
        "sim_time_s": round(float(snap.sim_time_s or 0.0), 3),
        "duration_s": snap.duration_s, "progress": round(snap.progress(), 4),
        "detector": snap.detector, "mitigation_enabled": snap.mitigation_enabled,
        "latest_window": {k: latest.get(k) for k in (
            "window", "t_start", "clean_availability", "clean_p99_latency_ms",
            "clean_jitter_ms", "throughput_mbps", "uplink_utilisation", "attack_offered",
            "mitigation_drops", "collateral_byte_ratio") if k in latest},
        "recent_detections": [d for d in detections if float(d.get("probability", 0)) >= 0.5],
        "pending_approvals": [p for p in (engine.pending if engine else [])
                              if p["status"] == "pending"],
        "ts": time.time(),
    }


def register_platform(app: FastAPI, cfg: Any, session: Any) -> None:
    """Attach the platform layer to *app*."""
    auth_enabled = bool(cfg.get("api.auth.enabled", False)) or os.environ.get(
        "NETSHIELD_AUTH", "") == "1"
    users = UserStore.from_sources(resolve(cfg.get("api.auth.users_file", "config/users.yaml")),
                                   iterations=int(cfg.get("api.auth.pbkdf2_iterations",
                                                          600_000)))
    tokens = TokenService(ttl_s=int(cfg.get("api.auth.token_ttl_s", 3600)))
    audit_path = cfg.get("api.audit_db", "data/audit.db")
    audit = AuditLog(":memory:" if audit_path == ":memory:" else resolve(audit_path))
    metrics = NetShieldMetrics()
    app.state.audit, app.state.metrics, app.state.tokens = audit, metrics, tokens
    app.state.users, app.state.auth_enabled = users, auth_enabled

    # ------------------------------------------------------------------ #
    @app.middleware("http")
    async def security_and_metrics(request: Request, call_next: Any) -> Response:
        started = time.perf_counter()
        method, path = request.method, request.url.path
        identity = {"sub": "anonymous", "role": "admin" if not auth_enabled else ""}
        need = required_role(method, path)
        if auth_enabled and need and method != "OPTIONS":
            header = request.headers.get("authorization", "")
            if not header.lower().startswith("bearer "):
                metrics.auth_failures.labels("missing_token").inc()
                return JSONResponse({"detail": "Not authenticated"}, status_code=401,
                                    headers={"WWW-Authenticate": "Bearer"})
            try:
                identity = tokens.verify(header.split(" ", 1)[1])
            except AuthError as exc:
                metrics.auth_failures.labels("bad_token").inc()
                return JSONResponse({"detail": str(exc)}, status_code=401,
                                    headers={"WWW-Authenticate": "Bearer"})
            if role_rank(identity["role"]) < role_rank(need):
                metrics.auth_failures.labels("forbidden").inc()
                audit.record(identity["sub"], identity["role"], f"{method} {path}",
                             outcome="forbidden", detail={"required": need})
                return JSONResponse({"detail": f"Requires role '{need}'"}, status_code=403)
        request.state.identity = identity
        response = await call_next(request)
        route = request.scope.get("route")
        template = getattr(route, "path", path)
        metrics.http_requests.labels(method, template, str(response.status_code)).inc()
        metrics.http_seconds.labels(method, template).observe(time.perf_counter() - started)
        if method in ("POST", "PUT", "DELETE", "PATCH") and path != "/api/auth/token":
            audit.record(identity["sub"], identity.get("role", ""), f"{method} {template}",
                         target=path, outcome=str(response.status_code))
        return response

    def identity(request: Request) -> dict[str, Any]:
        return getattr(request.state, "identity", {"sub": "anonymous", "role": "admin"})

    def engine_or_404() -> Any:
        controller = getattr(session, "controller", None)
        engine = getattr(controller, "mitigation", None) if controller else None
        if engine is None:
            raise HTTPException(404, "No running simulation with mitigation armed")
        return engine

    # ------------------------------------------------------------------ #
    @app.post("/api/auth/token", tags=["auth"])
    def login(username: str = Form(...), password: str = Form(...)) -> dict[str, Any]:
        """OAuth2 password grant. Returns a bearer JWT."""
        try:
            user = users.authenticate(username, password)
        except AuthError:
            metrics.auth_failures.labels("bad_credentials").inc()
            audit.record(username, "", "auth.login", outcome="denied")
            raise HTTPException(401, "Invalid username or password",
                                headers={"WWW-Authenticate": "Bearer"}) from None
        audit.record(user.username, user.role, "auth.login")
        return tokens.issue(user)

    @app.get("/api/auth/me", tags=["auth"])
    def me(who: dict = Depends(identity)) -> dict[str, Any]:
        return {"username": who["sub"], "role": who.get("role"), "auth_enabled": auth_enabled}

    # ------------------------------------------------------------------ #
    @app.get("/api/approvals", tags=["mitigation"])
    def approvals(status: str = Query("pending")) -> list[dict[str, Any]]:
        controller = getattr(session, "controller", None)
        engine = getattr(controller, "mitigation", None) if controller else None
        items = list(engine.pending) if engine else []
        metrics.pending_approvals.set(sum(1 for i in items if i["status"] == "pending"))
        return [i for i in items if status == "all" or i["status"] == status]

    @app.post("/api/approvals/{approval_id}/approve", tags=["mitigation"])
    def approve(approval_id: int, who: dict = Depends(identity)) -> dict[str, Any]:
        engine = engine_or_404()
        try:
            entry = engine.approve(approval_id, float(session.snapshot().sim_time_s or 0.0),
                                   who["sub"])
        except (KeyError, ValueError) as exc:
            raise HTTPException(409 if isinstance(exc, ValueError) else 404, str(exc)) from exc
        metrics.mitigation_actions.labels(entry.action.value, "approved").inc()
        audit.record(who["sub"], who.get("role", ""), "mitigation.approve", entry.node,
                     detail=entry.to_dict())
        return entry.to_dict()

    @app.post("/api/approvals/{approval_id}/reject", tags=["mitigation"])
    def reject(approval_id: int, who: dict = Depends(identity)) -> dict[str, Any]:
        engine = engine_or_404()
        try:
            item = engine.reject(approval_id, float(session.snapshot().sim_time_s or 0.0),
                                 who["sub"])
        except (KeyError, ValueError) as exc:
            raise HTTPException(409 if isinstance(exc, ValueError) else 404, str(exc)) from exc
        audit.record(who["sub"], who.get("role", ""), "mitigation.reject", item["node"],
                     detail=item)
        return item

    @app.post("/api/mitigation/{node}/rollback", tags=["mitigation"])
    def rollback(node: str, who: dict = Depends(identity)) -> dict[str, Any]:
        engine = engine_or_404()
        try:
            entry = engine.rollback(node, float(session.snapshot().sim_time_s or 0.0), who["sub"])
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        metrics.mitigation_actions.labels("release", "rollback").inc()
        audit.record(who["sub"], who.get("role", ""), "mitigation.rollback", node,
                     detail=entry.to_dict())
        return entry.to_dict()

    # ------------------------------------------------------------------ #
    @app.get("/api/stream", tags=["live"])
    async def stream(request: Request, interval_s: float = Query(1.0, ge=0.2, le=10.0),
                     max_events: int = Query(0, ge=0)) -> StreamingResponse:
        """Server-Sent Events: one ``snapshot`` event per interval."""
        async def events():
            sent = 0
            while not await request.is_disconnected():
                payload = _snapshot_payload(session)
                metrics.observe_snapshot(session.snapshot())
                yield f"event: snapshot\ndata: {json.dumps(payload, default=str)}\n\n"
                sent += 1
                if max_events and sent >= max_events:
                    return
                await asyncio.sleep(interval_s)
        return StreamingResponse(events(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache"})

    @app.websocket("/ws/live")
    async def live(ws: WebSocket) -> None:
        """WebSocket push of the live snapshot (token via ``?token=`` when auth is on)."""
        if auth_enabled:
            try:
                tokens.verify(ws.query_params.get("token", ""))
            except AuthError:
                await ws.close(code=4401)
                return
        await ws.accept()
        interval = float(ws.query_params.get("interval_s", 1.0))
        limit = int(ws.query_params.get("max_events", 0))
        sent = 0
        try:
            while True:
                await ws.send_text(json.dumps(_snapshot_payload(session), default=str))
                sent += 1
                if limit and sent >= limit:
                    await ws.close()
                    return
                await asyncio.sleep(max(0.2, interval))
        except WebSocketDisconnect:
            return

    @app.get("/metrics", include_in_schema=False)
    def prometheus() -> Response:
        metrics.observe_snapshot(session.snapshot())
        body, content_type = metrics.render()
        return Response(body, media_type=content_type)

    # ------------------------------------------------------------------ #
    @app.get("/api/alerts/export", tags=["detection"])
    def alerts_export(fmt: str = Query("stix", pattern="^(stix|cef)$"),
                      min_probability: float = Query(0.8, ge=0, le=1)) -> Response:
        """Export current-run alerts for a SIEM (STIX 2.1 or ArcSight CEF)."""
        controller = getattr(session, "controller", None)
        log = list(getattr(controller, "detection_log", []) or []) if controller else []
        snap = session.snapshot()
        family = ""
        try:
            from ..utils.config import experiment_config  # noqa: PLC0415

            scen_cfg, _ = experiment_config(snap.scenario) if snap.scenario else (None, None)
            family = str(scen_cfg.get("attack.type", "")) if scen_cfg else ""
        except Exception:  # noqa: BLE001
            family = ""
        alerts = [{**d, "attack_family": family} for d in log
                  if float(d.get("probability", 0)) >= min_probability]
        body = export_alerts(alerts, fmt, run_id=snap.run_id or "")
        media = "application/stix+json;version=2.1" if fmt == "stix" else "text/plain"
        return Response(body, media_type=media)

    @app.get("/api/audit", tags=["system"])
    def audit_log(limit: int = Query(200, ge=1, le=5000)) -> dict[str, Any]:
        return {"chain_valid": audit.verify_chain(), "entries": audit.entries(limit)}
