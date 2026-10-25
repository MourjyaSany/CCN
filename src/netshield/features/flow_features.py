"""Flow-record schema, validation and flow-level derived features.

The engine exports IPFIX/NetFlow-style records: one row per
``(time-window, 5-tuple)``. This module documents that schema, validates it, and
provides the flow-level derived quantities used for exploratory analysis and for
the flow-granularity figures in the report. Node-level modelling features are
built on top of these records by :mod:`netshield.features.node_features`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Final

import numpy as np
import pandas as pd

from ..simulation.packet import Protocol
from ..utils.logging_utils import get_logger
from ..utils.paths import resolve

_LOG = get_logger(__name__)

#: Columns every flow-record frame must contain.
REQUIRED_FLOW_COLUMNS: Final[tuple[str, ...]] = (
    "window", "t_start", "t_end", "src_node", "dst_node", "src_ip", "dst_ip",
    "src_port", "dst_port", "protocol", "packets", "bytes", "duration",
    "packet_rate", "byte_rate", "mean_packet_size", "packet_size_var",
    "mean_iat", "iat_std", "syn_count", "syn_ack_count", "ack_count",
    "fin_count", "rst_count", "psh_count", "attack_packets",
)

#: Human-readable description of each exported flow feature, reproduced in
#: ``docs/methodology.md`` so the report and the code cannot drift apart.
FLOW_FEATURE_GLOSSARY: Final[dict[str, str]] = {
    "src_ip": "Source IPv4 address (spoofed for SYN floods).",
    "dst_ip": "Destination IPv4 address.",
    "src_port": "Source transport port.",
    "dst_port": "Destination transport port.",
    "protocol": "IANA transport protocol number (6=TCP, 17=UDP).",
    "packets": "Packet count observed for this 5-tuple in this window.",
    "bytes": "Total wire bytes (L2 frame size, headers included).",
    "duration": "Time between first and last packet of the flow in the window.",
    "packet_rate": "packets / window_seconds.",
    "byte_rate": "bytes / window_seconds.",
    "mean_packet_size": "Arithmetic mean wire packet size.",
    "packet_size_var": "Population variance of wire packet size.",
    "mean_iat": "Mean packet inter-arrival time.",
    "iat_std": "Standard deviation of inter-arrival time (jitter).",
    "syn_count": "Bare SYN segments: connection attempts.",
    "syn_ack_count": "SYN+ACK segments: accepted connection attempts.",
    "ack_count": "Segments carrying the ACK flag.",
    "fin_count": "FIN segments: graceful teardown.",
    "rst_count": "RST segments: abortive teardown.",
    "psh_count": "PSH segments: application data pushes.",
    "delivered": "Packets of the flow that reached their destination.",
    "dropped": "Packets of the flow discarded anywhere in the network.",
    "retransmits": "TCP retransmissions emitted for this flow.",
    "attack_packets": "GROUND TRUTH ONLY - never used as a model input.",
}


class FlowSchemaError(ValueError):
    """Raised when a flow frame does not match the exported schema."""


def validate_flow_frame(frame: pd.DataFrame) -> pd.DataFrame:
    """Validate a flow-record frame against :data:`REQUIRED_FLOW_COLUMNS`.

    Args:
        frame: Candidate flow frame.

    Returns:
        The same frame (for call chaining).

    Raises:
        FlowSchemaError: If columns are missing or contain impossible values.
    """
    missing = [c for c in REQUIRED_FLOW_COLUMNS if c not in frame.columns]
    if missing:
        raise FlowSchemaError(f"Flow frame is missing required columns: {missing}")
    if frame.empty:
        return frame

    if (frame["packets"] <= 0).any():
        raise FlowSchemaError("Flow frame contains records with packets <= 0.")
    if (frame["bytes"] <= 0).any():
        raise FlowSchemaError("Flow frame contains records with bytes <= 0.")
    if (frame["attack_packets"] > frame["packets"]).any():
        raise FlowSchemaError(
            "Flow frame contains attack_packets > packets, which is impossible."
        )
    bad_ports = frame[(frame["dst_port"] < 0) | (frame["dst_port"] > 65535)]
    if not bad_ports.empty:
        raise FlowSchemaError(f"Flow frame contains {len(bad_ports)} invalid dst_port values.")
    return frame


def load_flows(path: str | Path) -> pd.DataFrame:
    """Load and validate a ``flows.csv`` produced by a simulation run.

    Args:
        path: Path to the CSV file.

    Returns:
        The validated flow frame.

    Raises:
        FileNotFoundError: If the file does not exist.
        FlowSchemaError: If the schema is invalid.
    """
    source = resolve(path)
    if not source.exists():
        raise FileNotFoundError(f"Flow file not found: {source}")
    return validate_flow_frame(pd.read_csv(source))


def add_derived_flow_features(frame: pd.DataFrame) -> pd.DataFrame:
    """Append flow-level derived features used for analysis and figures.

    Added columns:

    ``bits_per_packet``
        Mean wire size in bits - separates minimum-size SYN floods from
        maximum-size volumetric floods.
    ``packet_size_cv``
        Coefficient of variation of packet size. Near zero for machine-generated
        fixed-size floods, high for real application traffic.
    ``iat_cv``
        Coefficient of variation of the inter-arrival time (burstiness).
    ``syn_ratio``
        Bare SYNs as a fraction of all TCP segments in the flow.
    ``handshake_completion``
        ``syn_ack_count / syn_count`` - collapses towards zero during a SYN flood.
    ``is_tcp`` / ``is_udp``
        Protocol indicator columns.

    Args:
        frame: A validated flow frame.

    Returns:
        A copy of *frame* with the derived columns appended.
    """
    out = frame.copy()
    packets = out["packets"].astype(float).replace(0, np.nan)

    out["bits_per_packet"] = (out["bytes"].astype(float) * 8.0 / packets).fillna(0.0)
    std = np.sqrt(out["packet_size_var"].clip(lower=0.0))
    out["packet_size_cv"] = (
        std / out["mean_packet_size"].replace(0, np.nan)
    ).fillna(0.0)
    out["iat_cv"] = (
        out["iat_std"] / out["mean_iat"].replace(0, np.nan)
    ).fillna(0.0)

    tcp_segments = (
        out["syn_count"] + out["syn_ack_count"] + out["ack_count"] + out["rst_count"]
    ).astype(float).replace(0, np.nan)
    out["syn_ratio"] = (out["syn_count"] / tcp_segments).fillna(0.0)
    out["handshake_completion"] = (
        out["syn_ack_count"] / out["syn_count"].replace(0, np.nan)
    ).fillna(0.0)

    out["is_tcp"] = (out["protocol"] == Protocol.TCP).astype(int)
    out["is_udp"] = (out["protocol"] == Protocol.UDP).astype(int)
    return out


def flow_summary(frame: pd.DataFrame) -> dict[str, Any]:
    """Return a compact statistical summary of a flow frame.

    Args:
        frame: A validated flow frame.

    Returns:
        A JSON-serialisable summary used in run reports.
    """
    if frame.empty:
        return {"n_flows": 0}
    attack = frame["attack_packets"].sum()
    packets = frame["packets"].sum()
    return {
        "n_flows": int(len(frame)),
        "n_windows": int(frame["window"].nunique()),
        "total_packets": int(packets),
        "total_bytes": int(frame["bytes"].sum()),
        "attack_packets": int(attack),
        "attack_fraction": round(float(attack) / float(packets), 5) if packets else 0.0,
        "unique_src_ips": int(frame["src_ip"].nunique()),
        "unique_dst_ports": int(frame["dst_port"].nunique()),
        "tcp_flows": int((frame["protocol"] == Protocol.TCP).sum()),
        "udp_flows": int((frame["protocol"] == Protocol.UDP).sum()),
        "mean_packets_per_flow": round(float(frame["packets"].mean()), 3),
        "mean_packet_size": round(float(frame["mean_packet_size"].mean()), 2),
    }


def top_talkers(frame: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    """Return the *n* source nodes with the highest byte volume.

    Args:
        frame: A validated flow frame.
        n: Number of rows to return.

    Returns:
        A frame with ``src_node``, ``packets``, ``bytes`` and ``flows`` columns,
        sorted by bytes descending.
    """
    if frame.empty:
        return pd.DataFrame(columns=["src_node", "packets", "bytes", "flows"])
    grouped = (
        frame.groupby("src_node")
        .agg(packets=("packets", "sum"), bytes=("bytes", "sum"), flows=("packets", "size"))
        .reset_index()
        .sort_values("bytes", ascending=False)
    )
    return grouped.head(n).reset_index(drop=True)
