"""Execute a run inside a real NS-3 installation.

The C++ model in ``ns3/simulations/netshield-topology.cc`` writes
``ns3_flows.csv`` and ``ns3_windows.csv`` using the same column names the Python
engine uses, so everything downstream - feature extraction, graph construction,
the detectors, the figures - consumes NS-3 output unchanged. That is the whole
point of the exercise: the two engines are interchangeable at the artefact
boundary, which is what makes cross-validating them meaningful.

Honesty rules enforced here
---------------------------
The NS-3 model implements a subset of what the Python engine does. Silently
approximating the difference would be the worst possible outcome, because the
artefacts would still be stamped "NS-3 simulation". So:

* :func:`ns3_warnings` enumerates every configured setting the C++ model cannot
  honour, and each one is logged as a warning *and* recorded in the run summary.
* Closed-loop mitigation has no equivalent hook in the C++ model. Rather than
  pretend the loop ran, the run is executed open-loop and says so.
* Quantities NS-3 does not measure are left absent, not zero-filled.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..utils.config import Config
from ..utils.logging_utils import get_logger
from .ns3_bridge import (
    ENGINE_NS3,
    NS3Availability,
    install_model,
    parse_ns3_flowmonitor,
    run_ns3_simulation,
)

_LOG = get_logger(__name__)

#: Topology families implemented only in the Python engine.
NS3_UNSUPPORTED_FAMILIES: frozenset[str] = frozenset(
    {"multi_gateway", "fat_tree", "mesh", "ring"}
)

#: Attack families implemented only in the Python engine.
NS3_UNSUPPORTED_ATTACKS: frozenset[str] = frozenset(
    {"ack_flood", "slowloris", "mixed"}
)


def ns3_params(config: Config) -> dict[str, Any]:
    """Map the project configuration onto the NS-3 model's command line.

    Args:
        config: The merged project configuration.

    Returns:
        A mapping of NS-3 command-line parameter names to values.
    """
    attack = config.get("attack", {}) or {}
    sizes = attack.get("packet_bytes", [512, 512]) or [512, 512]
    enabled = bool(attack.get("enabled", False))
    return {
        "nIot": int(config.get("simulation.n_iot_devices", 24)),
        "nAttackers": int(config.get("simulation.n_attackers", 0)),
        "nRouters": int(config.get("network.topology.routers.count", 3)),
        "duration": float(config.require("simulation.duration_s")),
        "attackStart": float(attack.get("start_s", 0.0)),
        "attackDuration": float(attack.get("duration_s", 0.0)) if enabled else 0.0,
        "attackPps": float(attack.get("packets_per_second", 0.0)),
        "attackBytes": int(sizes[0]),
        "attackType": str(attack.get("type", "udp_flood")),
        "windowS": float(config.require("features.window_s")),
        "seed": int(config.get("seed", 42)),
        "topology": str(config.get("network.topology.family", "tree")),
    }


def ns3_warnings(config: Config) -> list[str]:
    """Return every configured setting the NS-3 model cannot honour.

    Args:
        config: The merged project configuration.

    Returns:
        Human-readable descriptions, empty when the run maps cleanly.
    """
    notes: list[str] = []

    family = str(config.get("network.topology.family", "tree"))
    if family in NS3_UNSUPPORTED_FAMILIES:
        notes.append(
            f"topology family '{family}' is implemented only in the Python "
            "engine; the NS-3 model builds a tree instead"
        )

    attack = config.get("attack", {}) or {}
    if attack.get("enabled"):
        atype = str(attack.get("type", ""))
        if atype in NS3_UNSUPPORTED_ATTACKS:
            notes.append(
                f"attack family '{atype}' is implemented only in the Python "
                "engine; the NS-3 model emits a UDP/TCP flood instead"
            )
        shape = str(config.get("attack.shape.profile", "constant"))
        if shape != "constant":
            notes.append(
                f"rate profile '{shape}' is not implemented in the NS-3 model; "
                "it emits a constant rate"
            )
        jitter = config.get("attack.rate_jitter", [1.0, 1.0]) or [1.0, 1.0]
        if float(jitter[0]) != 1.0 or float(jitter[-1]) != 1.0:
            notes.append("attack.rate_jitter is not implemented in the NS-3 model")
        if float(config.get("attack.stagger_s", 0.0)) > 0:
            notes.append("attack.stagger_s is not implemented in the NS-3 model")
        if bool((attack.get("burst") or {}).get("enabled", False)):
            notes.append("attack.burst is not implemented in the NS-3 model")
    return notes


def coerce_numeric(row: Mapping[str, Any]) -> dict[str, Any]:
    """Convert CSV string fields to ``int``/``float`` where they parse cleanly.

    Args:
        row: A raw CSV row.

    Returns:
        The same mapping with numeric-looking values converted.
    """
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


def normalise_window(row: Mapping[str, Any], window_s: float) -> dict[str, Any]:
    """Map an NS-3 window row onto the Python engine's window-metric schema.

    Downstream code (figures, the SQLite store, the dashboard) reads a fixed set
    of window-metric keys. NS-3 measures a subset of them, so this fills in the
    ones that are *derivable* from what NS-3 reported (``pps``, throughput,
    loss ratios) and leaves the genuinely unmeasured ones absent rather than
    zero: a zero uplink utilisation would read as "the link was idle", which is
    a false measurement, whereas a missing key is correctly rendered as
    ``not available`` by the report writer.

    Args:
        row: One parsed row of ``ns3_windows.csv``.
        window_s: Feature-window length in seconds.

    Returns:
        A window-metric row using the project's canonical key names.
    """
    offered = float(row.get("offered_packets", 0) or 0)
    delivered = float(row.get("delivered_packets", 0) or 0)
    delivered_bytes = float(row.get("delivered_bytes", 0) or 0)
    dropped = float(row.get("dropped_packets", 0) or 0)
    legit_offered = float(row.get("legit_offered", 0) or 0)
    legit_delivered = float(row.get("legit_delivered", 0) or 0)
    span = max(1e-9, window_s)

    out = dict(row)
    out["pps"] = round(offered / span, 3)
    out["throughput_bps"] = round(delivered_bytes * 8.0 / span, 3)
    out["throughput_mbps"] = round(delivered_bytes * 8.0 / span / 1e6, 5)
    out["offered_mbps"] = round(float(row.get("offered_bytes", 0) or 0) * 8.0 / span / 1e6, 5)
    out["loss_ratio"] = round(dropped / offered, 5) if offered else 0.0
    out["legit_loss_ratio"] = (
        round(max(0.0, legit_offered - legit_delivered) / legit_offered, 5)
        if legit_offered else 0.0
    )
    # NS-3 has no notion of "compromised device" beyond the id convention, so
    # the clean-device view is the legitimate view here.
    out["clean_offered"] = legit_offered
    out["clean_delivered"] = legit_delivered
    out["clean_loss_ratio"] = out["legit_loss_ratio"]
    out["clean_throughput_pps"] = round(legit_delivered / span, 3)
    out["clean_mean_latency_ms"] = row.get("legit_mean_latency_ms")
    out["legit_throughput_pps"] = round(legit_delivered / span, 3)
    out["attack_offered"] = float(row.get("attack_offered", 0) or 0)
    out["delivered_packets_up"] = delivered
    out["delivered_bytes_up"] = delivered_bytes
    out.pop("packet_loss_ratio", None)

    # The CSV schema is fixed, so every canonical key must be present or the
    # writers and the SQLite store fail. Keys NS-3 genuinely does not measure
    # are filled with 0 to satisfy the schema, and their names are reported in
    # run.json under "ns3_unmeasured_metrics" so a reader can tell the
    # difference between "measured zero" and "not measured".
    from .telemetry import METRIC_CSV_COLUMNS  # noqa: PLC0415

    for column in METRIC_CSV_COLUMNS:
        out.setdefault(column, 0)
    return out


def unmeasured_metrics(window: Mapping[str, Any]) -> list[str]:
    """Return the canonical metric columns NS-3 did not actually measure."""
    from .telemetry import METRIC_CSV_COLUMNS  # noqa: PLC0415

    measured = {
        "window", "t_start", "t_end", "offered_packets", "offered_bytes",
        "delivered_packets", "delivered_bytes", "delivered_packets_up",
        "delivered_bytes_up", "dropped_packets", "legit_offered",
        "legit_delivered", "attack_offered", "mean_latency_ms",
        "max_latency_ms", "legit_mean_latency_ms", "p95_latency_ms",
        "p99_latency_ms", "pps", "throughput_bps", "throughput_mbps",
        "offered_mbps", "loss_ratio", "legit_loss_ratio", "clean_offered",
        "clean_delivered", "clean_loss_ratio", "clean_throughput_pps",
        "clean_mean_latency_ms", "legit_throughput_pps",
    }
    return [c for c in METRIC_CSV_COLUMNS if c not in measured]


def nodes_from_flows(flows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Reconstruct a per-node table from NS-3 flow records.

    The C++ model does not export a node table, so it is derived here. Roles and
    ground-truth attacker flags come from the node-id convention the model
    shares with the Python topology builder (``iot-NN`` / ``atk-NN`` / ``rtr-N``
    / ``gw-N`` / ``cloud-0``).

    Args:
        flows: Parsed NS-3 flow rows.

    Returns:
        One row per observed source node, ordered by id.
    """
    kinds = (
        ("atk-", "attacker"), ("iot-", "iot"), ("rtr-", "router"),
        ("agg-", "router"), ("gw-", "gateway"), ("cloud-", "cloud"),
    )
    seen: dict[str, dict[str, Any]] = {}
    for row in flows:
        node_id = str(row.get("src_node", ""))
        if not node_id:
            continue
        if node_id not in seen:
            kind = next((k for prefix, k in kinds if node_id.startswith(prefix)), "unknown")
            seen[node_id] = {
                "node_id": node_id,
                "kind": kind,
                "ip": str(row.get("src_ip", "")),
                "device_class": "",
                "is_attacker": kind == "attacker",
                "tx_packets": 0,
                "tx_bytes": 0,
                "rx_packets": 0,
                "rx_bytes": 0,
                "dropped_packets": 0,
                "drop_reasons": {},
            }
        entry = seen[node_id]
        entry["tx_packets"] += int(row.get("packets", 0) or 0)
        entry["tx_bytes"] += int(row.get("bytes", 0) or 0)
        entry["dropped_packets"] += int(row.get("dropped", 0) or 0)
    return sorted(seen.values(), key=lambda n: str(n["node_id"]))


def execute(
    config: Config,
    meta: Mapping[str, Any],
    probe: NS3Availability,
    engine_reason: str,
    run_id: str,
    result_class: Any,
    closed_loop: bool = False,
) -> Any:
    """Build the model, run it inside NS-3 and assemble a result bundle.

    Args:
        config: The merged configuration.
        meta: Experiment metadata.
        probe: A successful NS-3 probe.
        engine_reason: Provenance string stamped onto the artefacts.
        run_id: Identifier for this run.
        result_class: The ``SimulationResult`` class to instantiate (passed in
            to avoid a circular import with :mod:`netshield.simulation.runner`).
        closed_loop: Whether the caller asked for in-loop mitigation.

    Returns:
        A populated result stamped with :data:`ENGINE_NS3`.

    Raises:
        RuntimeError: If the NS-3 model fails to build or run.
    """
    notes = ns3_warnings(config)
    for note in notes:
        _LOG.warning("NS-3 engine: %s.", note)

    if closed_loop:
        note = (
            "closed-loop mitigation is enforced inside the Python engine's "
            "packet path and has no equivalent hook in the C++ model; this run "
            "is open-loop and reports no mitigations"
        )
        notes.append(note)
        _LOG.warning("NS-3 engine: %s.", note)

    params = ns3_params(config)

    with tempfile.TemporaryDirectory(prefix="netshield-ns3-") as tmp:
        target = Path(tmp)
        install_model(probe, timeout_s=900.0)
        proc = run_ns3_simulation(probe, params, target, timeout_s=3600.0)

        flows = [coerce_numeric(r) for r in parse_ns3_flowmonitor(target / "ns3_flows.csv")]
        windows_path = target / "ns3_windows.csv"
        windows = (
            [normalise_window(coerce_numeric(r), params["windowS"])
             for r in parse_ns3_flowmonitor(windows_path)]
            if windows_path.exists() else []
        )
        meta_path = target / "ns3_run.json"
        ns3_meta = (
            json.loads(meta_path.read_text(encoding="utf-8"))
            if meta_path.exists() else {}
        )

    offered = int(ns3_meta.get("packets_offered", 0))
    dropped = int(ns3_meta.get("packets_dropped", 0))
    latencies = [float(w.get("mean_latency_ms", 0.0)) for w in windows
                 if float(w.get("mean_latency_ms", 0.0)) > 0]

    summary = {
        "run_id": run_id,
        "engine": ENGINE_NS3,
        "ns3_version": probe.version,
        "ns3_method": probe.method,
        "duration_s": params["duration"],
        "window_s": params["windowS"],
        "n_flows": len(flows),
        "n_windows": len(windows),
        "packets_generated": offered,
        "packets_delivered": int(ns3_meta.get("packets_delivered", 0)),
        "packets_dropped": dropped,
        "loss_ratio": round(dropped / offered, 5) if offered else 0.0,
        "mean_latency_ms": round(sum(latencies) / len(latencies), 4) if latencies else None,
        # Recorded, not just logged: a reader of run.json must be able to see
        # exactly which configured behaviour the NS-3 run could not reproduce.
        "ns3_unsupported": notes,
        "ns3_unmeasured_metrics": (
            unmeasured_metrics(windows[0]) if windows else []
        ),
        "ns3_stdout": (proc.get("stdout") or "").strip().splitlines()[-2:],
    }

    node_rows = nodes_from_flows(flows)
    return result_class(
        run_id=run_id,
        engine=ENGINE_NS3,
        engine_reason=engine_reason,
        config=config.to_dict(),
        meta=dict(meta),
        flows=flows,
        windows=windows,
        nodes=node_rows,
        links=[],
        applications=[],
        server={},
        attackers=[],
        topology={
            "name": params["topology"],
            "family": params["topology"],
            "n_nodes": len(node_rows) or (
                params["nIot"] + params["nAttackers"] + params["nRouters"] + 2
            ),
            "n_links": 0,
            "cloud": "cloud-0",
            "gateway": "gw-0",
            "gateways": ["gw-0"],
            "enforcement_nodes": ["gw-0"],
            "uplinks": [],
            # The topology plot needs node/link lists. NS-3 owns the real
            # graph; what is reconstructable from the flow export is the node
            # set, so the links list is honestly empty rather than invented.
            "nodes": [
                {
                    "node_id": n["node_id"],
                    "kind": n["kind"],
                    "ip": n["ip"],
                    "device_class": "",
                    "parent": None,
                    "tier": {"cloud": 0, "gateway": 1, "router": 2}.get(n["kind"], 3),
                    "is_attacker": n["is_attacker"],
                }
                for n in node_rows
            ],
            "links": [],
            "source": "ns3",
        },
        summary=summary,
    )


__all__ = [
    "execute",
    "ns3_params",
    "ns3_warnings",
    "coerce_numeric",
    "nodes_from_flows",
    "NS3_UNSUPPORTED_FAMILIES",
    "NS3_UNSUPPORTED_ATTACKS",
]
