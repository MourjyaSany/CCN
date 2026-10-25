"""Entry point for running one pipeline stage as a standalone service.

    python -m netshield.platform.service collector --listen 0.0.0.0:4739
    python -m netshield.platform.service features
    python -m netshield.platform.service inference --models models/final --detector graphsage
    python -m netshield.platform.service policy --export openflow

Services talk over the bus named by ``NETSHIELD_BUS`` (``redis://...``) and
expose Prometheus metrics on ``--metrics-port`` (default 9101). The asset
inventory (address -> node, ingress port -> node, topology) is read from
``--inventory`` (JSON, written by the deployment or the testbed).

The collector is the only component that opens a network socket, and it
only *receives* IPFIX datagrams; nothing in the platform transmits traffic.
"""

from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path


def _inventory(path: str) -> dict:
    if path and Path(path).exists():
        return json.loads(Path(path).read_text(encoding="utf-8"))
    return {"node_of": {}, "node_of_port": {}, "topology": {"nodes": [], "links": []}}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("role", choices=["collector", "features", "inference", "policy"])
    ap.add_argument("--bus", default=os.environ.get("NETSHIELD_BUS", "memory://"))
    ap.add_argument("--inventory", default="config/inventory.json")
    ap.add_argument("--listen", default="0.0.0.0:4739")
    ap.add_argument("--models", default="models/final")
    ap.add_argument("--detector", default="graphsage")
    ap.add_argument("--export", default="openflow")
    ap.add_argument("--window-s", type=float, default=5.0)
    ap.add_argument("--metrics-port", type=int, default=9101)
    args = ap.parse_args()

    from prometheus_client import start_http_server  # noqa: PLC0415

    from .bus import make_bus  # noqa: PLC0415
    from .metrics import NetShieldMetrics  # noqa: PLC0415
    from .pipeline import CollectorService, FeatureService, InferenceService, PolicyService

    metrics = NetShieldMetrics()
    start_http_server(args.metrics_port, registry=metrics.registry)
    bus = make_bus(args.bus)
    inv = _inventory(args.inventory)

    if args.role == "collector":
        import socket  # noqa: PLC0415 - receive-only IPFIX listener

        host, port = args.listen.rsplit(":", 1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((host, int(port)))
        sock.settimeout(1.0)
        base_ms = int(time.time() * 1000)
        svc = CollectorService(bus, inv["node_of"], args.window_s, base_ms, metrics,
                               {int(k): v for k, v in inv.get("node_of_port", {}).items()})
        while True:
            try:
                data, _ = sock.recvfrom(65535)
                svc.ingest_ipfix(data)
            except TimeoutError:
                pass
            now_window = int((time.time() * 1000 - base_ms) / 1000 // args.window_s)
            svc.flush(now_window - 1)          # publish windows that have closed

    if args.role == "features":
        svc = FeatureService(bus, inv["topology"], args.window_s)
    elif args.role == "inference":
        from ..detection.pipeline import load_detectors  # noqa: PLC0415

        det = load_detectors(args.models, [args.detector], required=True)[args.detector]
        svc = InferenceService(bus, det, metrics=metrics)
    else:
        from ..mitigation.engine import MitigationEnforcer, MitigationEngine  # noqa: PLC0415
        from ..mitigation.export import PortMap  # noqa: PLC0415
        from ..mitigation.policy import PolicyConfig  # noqa: PLC0415
        from ..utils.config import load_config  # noqa: PLC0415

        policy = PolicyConfig.from_config(load_config()).validate()
        ports = PortMap(ports={v: int(k) for k, v in inv.get("node_of_port", {}).items()})
        svc = PolicyService(bus, MitigationEngine(policy, MitigationEnforcer(policy, {})),
                            args.window_s, args.export, ports, metrics=metrics)
    while True:
        if svc.step() == 0:
            time.sleep(0.2)


if __name__ == "__main__":
    raise SystemExit(main())
