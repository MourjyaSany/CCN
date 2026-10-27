"""Assemble a SimulationResult from a real NS-3 run (the primary engine).

This is the NS-3 execution path. It builds the exact topology the scenario
calls for, writes it as an NS-3 spec, runs the NS-3 model inside WSL, and reads
back the flow and window telemetry the model exported in the project's own
schema. Because the spec is generated from the real topology, the result
carries the genuine node and link graph, so feature extraction, graph
construction and the detectors run on NS-3 output exactly as they do on the
Python engine's.
"""

from __future__ import annotations

import csv
import json
import tempfile
from pathlib import Path
from typing import Any, Mapping

from ..traffic.attacks import AttackProfile
from ..utils.config import Config
from ..utils.logging_utils import get_logger
from .ns3_spec import write_spec
from .ns3_wsl import ENGINE_NS3, WSLNs3, run_model, win_to_wsl

_LOG = get_logger(__name__)


def _read_csv(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        return [_coerce(row) for row in csv.DictReader(handle)]


def _coerce(row: Mapping[str, str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in row.items():
        if not isinstance(value, str):
            out[key] = value
            continue
        text = value.strip()
        try:
            out[key] = int(text)
            continue
        except ValueError:
            pass
        try:
            out[key] = float(text)
        except ValueError:
            out[key] = value
    return out


def _window_rows(rows: list[dict[str, Any]], window_s: float) -> list[dict[str, Any]]:
    """Map NS-3 window rows onto the project's window-metric schema.

    Only the quantities NS-3 measures are filled; the rest are set to 0 to
    satisfy the fixed column set, and their names are surfaced in the run
    summary so a reader can tell a measured zero from an unmeasured one.
    """
    from .telemetry import METRIC_CSV_COLUMNS  # noqa: PLC0415

    out: list[dict[str, Any]] = []
    for r in rows:
        offered = float(r.get("offered_packets", 0) or 0)
        delivered_bytes = float(r.get("delivered_bytes", 0) or 0)
        dropped = float(r.get("dropped_packets", 0) or 0)
        legit_off = float(r.get("legit_offered", 0) or 0)
        legit_del = float(r.get("legit_delivered", 0) or 0)
        span = max(1e-9, window_s)
        w = dict(r)
        w["pps"] = round(offered / span, 3)
        w["throughput_bps"] = round(delivered_bytes * 8.0 / span, 3)
        w["throughput_mbps"] = round(delivered_bytes * 8.0 / span / 1e6, 5)
        w["offered_mbps"] = round(float(r.get("offered_bytes", 0) or 0) * 8.0 / span / 1e6, 5)
        w["loss_ratio"] = round(dropped / offered, 5) if offered else 0.0
        clean_loss = round(max(0.0, legit_off - legit_del) / legit_off, 5) if legit_off else 0.0
        w["legit_loss_ratio"] = clean_loss
        w["clean_loss_ratio"] = clean_loss
        w["clean_offered"] = legit_off
        w["clean_delivered"] = legit_del
        w["clean_throughput_pps"] = round(legit_del / span, 3)
        w["legit_throughput_pps"] = round(legit_del / span, 3)
        w["clean_mean_latency_ms"] = r.get("legit_mean_latency_ms", 0.0)
        w["clean_p95_latency_ms"] = r.get("clean_p95_latency_ms", 0.0)
        w["clean_p99_latency_ms"] = r.get("clean_p99_latency_ms", 0.0)
        w["attack_offered"] = float(r.get("attack_offered", 0) or 0)
        w["delivered_packets_up"] = float(r.get("delivered_packets", 0) or 0)
        w["delivered_bytes_up"] = delivered_bytes
        w.pop("packet_loss_ratio", None)
        for col in METRIC_CSV_COLUMNS:
            w.setdefault(col, 0)
        out.append(w)
    return out


def _node_rows(topology: Mapping[str, Any], flows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Per-node table from the real topology, with tx counters from the flows."""
    tx: dict[str, dict[str, int]] = {}
    for row in flows:
        nid = str(row.get("src_node", ""))
        if not nid:
            continue
        acc = tx.setdefault(nid, {"tx_packets": 0, "tx_bytes": 0, "dropped_packets": 0})
        acc["tx_packets"] += int(row.get("packets", 0) or 0)
        acc["tx_bytes"] += int(row.get("bytes", 0) or 0)
        acc["dropped_packets"] += int(row.get("dropped", 0) or 0)
    rows = []
    for n in topology.get("nodes", []):
        acc = tx.get(n["node_id"], {})
        rows.append({
            "node_id": n["node_id"], "kind": n["kind"], "ip": n.get("ip", ""),
            "device_class": n.get("device_class", ""),
            "is_attacker": bool(n.get("is_attacker", False)),
            "tx_packets": acc.get("tx_packets", 0), "tx_bytes": acc.get("tx_bytes", 0),
            "rx_packets": 0, "rx_bytes": 0,
            "dropped_packets": acc.get("dropped_packets", 0), "drop_reasons": {},
        })
    return rows


def execute(
    config: Config,
    meta: Mapping[str, Any],
    probe: WSLNs3,
    engine_reason: str,
    run_id: str,
    result_class: Any,
    closed_loop: bool = False,
) -> Any:
    """Run the scenario in NS-3 and return a populated result.

    Args:
        config: The merged configuration.
        meta: Experiment metadata.
        probe: A successful WSL/NS-3 probe.
        engine_reason: Provenance string stamped onto the artefacts.
        run_id: Identifier for this run.
        result_class: The ``SimulationResult`` class (passed in to avoid a
            circular import with :mod:`netshield.simulation.runner`).
        closed_loop: Whether the caller asked for in-loop mitigation. The NS-3
            model runs open-loop, so this is recorded as an approximation.

    Returns:
        A result bundle stamped with :data:`ENGINE_NS3`.
    """
    from .topology import build_topology  # noqa: PLC0415

    topo = build_topology(config)
    window_s = float(config.require("features.window_s"))
    duration = float(config.require("simulation.duration_s"))

    with tempfile.TemporaryDirectory(prefix="netshield-ns3-") as tmp:
        out_dir = Path(tmp)
        spec_path = out_dir / "scenario.spec"
        # The NS-3 model (running in WSL) must write to the WSL view of the
        # output directory; Python then reads the same files from the Windows
        # path. On a native Linux host the two paths coincide.
        prov = write_spec(config, win_to_wsl(out_dir), spec_path)
        proc = run_model(spec_path)
        flows = _read_csv(out_dir / "ns3_flows.csv")
        windows = _window_rows(_read_csv(out_dir / "ns3_windows.csv"), window_s)
        ns3_meta = {}
        meta_path = out_dir / "ns3_run.json"
        if meta_path.exists():
            ns3_meta = json.loads(meta_path.read_text(encoding="utf-8"))

    approximations = list(prov.get("ns3_approximations", []))
    if closed_loop:
        approximations.append(
            "closed-loop mitigation is not enforced inside the NS-3 model; this "
            "run is open-loop and reports no mitigations")
    for note in approximations:
        _LOG.info("NS-3 engine: %s.", note)

    profile = AttackProfile.from_config(config)
    offered = int(ns3_meta.get("packets_offered", 0))
    dropped = int(ns3_meta.get("packets_dropped", 0))
    topo_desc = topo.describe()
    topo_desc["source"] = "ns3"
    summary = {
        "run_id": run_id,
        "engine": ENGINE_NS3,
        "ns3_version": probe.version,
        "ns3_distro": probe.distro,
        "duration_s": duration,
        "window_s": window_s,
        "n_iot_devices": int(config.get("simulation.n_iot_devices", 0)),
        "n_attackers": int(config.get("simulation.n_attackers", 0)),
        "n_flows": len(flows),
        "n_windows": len(windows),
        "packets_generated": offered,
        "packets_delivered": int(ns3_meta.get("packets_delivered", 0)),
        "packets_dropped": dropped,
        "overall_loss_ratio": round(dropped / offered, 6) if offered else 0.0,
        "attack": profile.to_dict(),
        "attack_families": {profile.attack_type: len(topo.attackers())} if profile.enabled
        else {},
        "ns3_approximations": approximations,
        "ns3_spec": {k: v for k, v in prov.items() if k != "node_index"},
        "wall_seconds": proc.get("wall_s"),
    }
    return result_class(
        run_id=run_id,
        engine=ENGINE_NS3,
        engine_reason=engine_reason,
        config=config.to_dict(),
        meta=dict(meta),
        flows=flows,
        windows=windows,
        nodes=_node_rows(topo_desc, flows),
        links=[],
        applications=[],
        server={},
        attackers=[{"node_id": n.node_id, "family": profile.attack_type}
                   for n in topo.attackers()],
        topology=topo_desc,
        summary=summary,
    )
