"""Node-window feature engineering.

Every detector in NetShield-GNN consumes *exactly* the same feature matrix: one
row per ``(run, time-window, node)``. That is a deliberate experimental control.
The threshold baseline, the Random Forest and GraphSAGE all see identical
per-node evidence, so any performance difference is attributable to the model -
and specifically, for GraphSAGE, to the **graph structure** that the other two
cannot exploit.

Label leakage
-------------
Features are derived only from quantities a real edge gateway can observe by
exporting flow records: addresses, ports, protocol numbers, packet and byte
counts, packet sizes, inter-arrival times and TCP flags. The simulator's
ground-truth fields (``attack_packets``, ``attack_type``, the ``app`` tag, which
literally contains the string ``attack_udp``) are used **only** to build labels
and are never exposed as model inputs. :func:`assert_no_leakage` enforces this
and is exercised by the test suite.

Ground-truth labelling
----------------------
A node's severity in a window combines *composition* and *temporal coverage*::

    attack_ratio = attack_packets / total_packets          (how much of what it
                                                            sent was hostile)
    duty         = active_attack_seconds / window_seconds   (how much of the
                                                            window it attacked)
    severity     = attack_ratio * duty

with ``severity >= 0.55`` giving MALICIOUS and ``severity >= 0.12`` giving
SUSPICIOUS. Both terms are required: a node that floods at full rate for only
half a second of a five-second window is genuinely *suspicious*, not fully
malicious, and a pulsing attacker legitimately sits in the middle class. This is
what produces a non-degenerate three-class problem rather than a trivial binary
one.
"""

from __future__ import annotations

import math
from typing import Any, Iterable, Mapping, Sequence

import numpy as np
import pandas as pd

from ..simulation.packet import Protocol
from ..traffic.attacks import AttackProfile, attack_duty
from ..utils.logging_utils import get_logger

_LOG = get_logger(__name__)

#: Ordered class names; the index is the integer label.
CLASS_NAMES: tuple[str, str, str] = ("BENIGN", "SUSPICIOUS", "MALICIOUS")
CLASS_TO_INDEX: dict[str, int] = {name: i for i, name in enumerate(CLASS_NAMES)}

#: Well-known service ports, used for an *observable* service-mix feature.
SERVICE_PORTS: dict[str, frozenset[int]] = {
    "mqtt": frozenset({1883, 8883}),
    "http": frozenset({80, 443, 8080, 8443}),
    "coap": frozenset({5683, 5684}),
}

#: Columns that are model inputs. Order is contractual: models persist it.
NODE_FEATURE_COLUMNS: tuple[str, ...] = (
    # --- egress volume -----------------------------------------------------
    "eg_packets",
    "eg_bytes",
    "eg_packet_rate",
    "eg_byte_rate",
    "eg_flow_count",
    "eg_packets_per_flow",
    "eg_bytes_per_flow",
    # --- egress packet-size distribution -----------------------------------
    "eg_mean_packet_size",
    "eg_packet_size_std",
    "eg_min_packet_size",
    "eg_max_packet_size",
    # --- egress timing -----------------------------------------------------
    "eg_mean_iat",
    "eg_iat_std",
    "eg_burstiness",
    "eg_mean_flow_duration",
    # --- egress addressing / fan-out ---------------------------------------
    "eg_unique_dst_nodes",
    "eg_unique_dst_ports",
    "eg_unique_src_ports",
    "eg_unique_src_ips",
    "eg_dst_port_entropy",
    # --- egress protocol / service mix --------------------------------------
    "eg_tcp_fraction",
    "eg_udp_fraction",
    "eg_svc_mqtt_fraction",
    "eg_svc_http_fraction",
    "eg_svc_coap_fraction",
    "eg_svc_other_fraction",
    # --- egress TCP flag profile --------------------------------------------
    "eg_syn_count",
    "eg_syn_rate",
    "eg_syn_ack_count",
    "eg_ack_count",
    "eg_fin_count",
    "eg_rst_count",
    "eg_psh_count",
    "eg_syn_ratio",
    "eg_syn_to_ack_ratio",
    "eg_connection_attempts",
    # --- ingress ------------------------------------------------------------
    "in_packets",
    "in_bytes",
    "in_packet_rate",
    "in_flow_count",
    "in_unique_src_nodes",
    "in_unique_src_ips",
    "in_out_packet_ratio",
    # --- structural ---------------------------------------------------------
    "tier",
    "degree",
    "is_endpoint",
)

#: Non-feature bookkeeping columns carried alongside the matrix.
META_COLUMNS: tuple[str, ...] = (
    "run_id", "experiment", "window", "t_start", "t_end", "node_id", "kind",
    "device_class", "ip",
)

#: Ground-truth columns. Never fed to a model.
LABEL_COLUMNS: tuple[str, ...] = (
    "attack_packets", "attack_ratio", "attack_duty", "severity",
    "label", "label_name", "is_attacker",
)

#: Simulator-internal columns that must never appear as features.
FORBIDDEN_FEATURE_COLUMNS: frozenset[str] = frozenset(
    {"attack_packets", "attack_ratio", "attack_duty", "severity", "label",
     "label_name", "is_attacker", "attack_type", "app"}
)


class LeakageError(AssertionError):
    """Raised when a ground-truth column is found in the model input matrix."""


def assert_no_leakage(columns: Iterable[str]) -> None:
    """Verify that no ground-truth column is being used as a model input.

    Args:
        columns: The feature column names about to be handed to a model.

    Raises:
        LeakageError: If any forbidden column is present.
    """
    offenders = sorted(set(columns) & FORBIDDEN_FEATURE_COLUMNS)
    if offenders:
        raise LeakageError(
            "Ground-truth columns would leak into the model input: "
            f"{offenders}. Features must be derived only from observable "
            "flow-record fields."
        )


def label_from_severity(
    severity: float,
    malicious_threshold: float = 0.55,
    suspicious_threshold: float = 0.12,
) -> int:
    """Map a severity score onto the three-class label index.

    Args:
        severity: ``attack_ratio * duty`` in ``[0, 1]``.
        malicious_threshold: Lower bound of the MALICIOUS class.
        suspicious_threshold: Lower bound of the SUSPICIOUS class.

    Returns:
        ``0`` (BENIGN), ``1`` (SUSPICIOUS) or ``2`` (MALICIOUS).
    """
    if severity >= malicious_threshold:
        return 2
    if severity >= suspicious_threshold:
        return 1
    return 0


def _shannon_entropy(counts: Sequence[float]) -> float:
    """Return the Shannon entropy (bits) of a non-negative count vector."""
    total = float(sum(counts))
    if total <= 0:
        return 0.0
    entropy = 0.0
    for value in counts:
        if value <= 0:
            continue
        p = value / total
        entropy -= p * math.log2(p)
    return entropy


def _service_of(port: int) -> str:
    """Classify a destination port into an observable service bucket."""
    for name, ports in SERVICE_PORTS.items():
        if port in ports:
            return name
    return "other"


def _safe_div(numerator: pd.Series, denominator: pd.Series) -> pd.Series:
    """Element-wise division that yields 0 where the denominator is 0."""
    denom = denominator.replace(0, np.nan)
    return (numerator / denom).fillna(0.0)


def _egress_aggregate(flows: pd.DataFrame, window_s: float) -> pd.DataFrame:
    """Aggregate flow records into per-(window, source node) egress features."""
    if flows.empty:
        return pd.DataFrame()

    frame = flows.copy()
    frame["_size_sq_sum"] = frame["packets"] * (
        frame["packet_size_var"] + frame["mean_packet_size"] ** 2
    )
    frame["_iat_n"] = (frame["packets"] - 1).clip(lower=0)
    frame["_iat_sum"] = frame["mean_iat"] * frame["_iat_n"]
    frame["_iat_sq_sum"] = frame["_iat_n"] * (
        frame["iat_std"] ** 2 + frame["mean_iat"] ** 2
    )
    frame["_service"] = frame["dst_port"].map(_service_of)
    frame["_tcp_packets"] = np.where(frame["protocol"] == Protocol.TCP, frame["packets"], 0)
    frame["_udp_packets"] = np.where(frame["protocol"] == Protocol.UDP, frame["packets"], 0)
    for service in ("mqtt", "http", "coap", "other"):
        frame[f"_svc_{service}"] = np.where(
            frame["_service"] == service, frame["packets"], 0
        )

    grouped = frame.groupby(["window", "src_node"], sort=False)
    agg = grouped.agg(
        eg_packets=("packets", "sum"),
        eg_bytes=("bytes", "sum"),
        eg_flow_count=("packets", "size"),
        _size_sum=("bytes", "sum"),
        _size_sq_sum=("_size_sq_sum", "sum"),
        eg_min_packet_size=("min_packet_size", "min"),
        eg_max_packet_size=("max_packet_size", "max"),
        _iat_n=("_iat_n", "sum"),
        _iat_sum=("_iat_sum", "sum"),
        _iat_sq_sum=("_iat_sq_sum", "sum"),
        eg_mean_flow_duration=("duration", "mean"),
        eg_unique_dst_nodes=("dst_node", "nunique"),
        eg_unique_dst_ports=("dst_port", "nunique"),
        eg_unique_src_ports=("src_port", "nunique"),
        eg_unique_src_ips=("src_ip", "nunique"),
        eg_syn_count=("syn_count", "sum"),
        eg_syn_ack_count=("syn_ack_count", "sum"),
        eg_ack_count=("ack_count", "sum"),
        eg_fin_count=("fin_count", "sum"),
        eg_rst_count=("rst_count", "sum"),
        eg_psh_count=("psh_count", "sum"),
        _tcp_packets=("_tcp_packets", "sum"),
        _udp_packets=("_udp_packets", "sum"),
        _svc_mqtt=("_svc_mqtt", "sum"),
        _svc_http=("_svc_http", "sum"),
        _svc_coap=("_svc_coap", "sum"),
        _svc_other=("_svc_other", "sum"),
        attack_packets=("attack_packets", "sum"),
        diag_delivered=("delivered", "sum"),
        diag_dropped=("dropped", "sum"),
        diag_retransmits=("retransmits", "sum"),
    ).reset_index()

    # Destination-port entropy (packet-weighted), computed per group.
    port_counts = (
        frame.groupby(["window", "src_node", "dst_port"], sort=False)["packets"]
        .sum()
        .reset_index()
    )
    entropy = (
        port_counts.groupby(["window", "src_node"], sort=False)["packets"]
        .apply(lambda s: _shannon_entropy(s.to_numpy()))
        .rename("eg_dst_port_entropy")
        .reset_index()
    )
    agg = agg.merge(entropy, on=["window", "src_node"], how="left")

    packets = agg["eg_packets"].astype(float)
    agg["eg_packet_rate"] = packets / window_s
    agg["eg_byte_rate"] = agg["eg_bytes"].astype(float) / window_s
    agg["eg_packets_per_flow"] = _safe_div(packets, agg["eg_flow_count"])
    agg["eg_bytes_per_flow"] = _safe_div(agg["eg_bytes"].astype(float), agg["eg_flow_count"])
    agg["eg_mean_packet_size"] = _safe_div(agg["_size_sum"].astype(float), packets)
    variance = _safe_div(agg["_size_sq_sum"], packets) - agg["eg_mean_packet_size"] ** 2
    agg["eg_packet_size_std"] = np.sqrt(variance.clip(lower=0.0))
    agg["eg_mean_iat"] = _safe_div(agg["_iat_sum"], agg["_iat_n"])
    iat_var = _safe_div(agg["_iat_sq_sum"], agg["_iat_n"]) - agg["eg_mean_iat"] ** 2
    agg["eg_iat_std"] = np.sqrt(iat_var.clip(lower=0.0))
    agg["eg_burstiness"] = _safe_div(agg["eg_iat_std"], agg["eg_mean_iat"])

    agg["eg_tcp_fraction"] = _safe_div(agg["_tcp_packets"].astype(float), packets)
    agg["eg_udp_fraction"] = _safe_div(agg["_udp_packets"].astype(float), packets)
    for service in ("mqtt", "http", "coap", "other"):
        agg[f"eg_svc_{service}_fraction"] = _safe_div(
            agg[f"_svc_{service}"].astype(float), packets
        )

    agg["eg_syn_rate"] = agg["eg_syn_count"].astype(float) / window_s
    agg["eg_syn_ratio"] = _safe_div(
        agg["eg_syn_count"].astype(float), agg["_tcp_packets"].astype(float)
    )
    agg["eg_syn_to_ack_ratio"] = _safe_div(
        agg["eg_syn_count"].astype(float), agg["eg_ack_count"].astype(float) + 1.0
    )
    agg["eg_connection_attempts"] = agg["eg_syn_count"]

    agg = agg.rename(columns={"src_node": "node_id"})
    return agg.drop(columns=[c for c in agg.columns if c.startswith("_")])


def _ingress_aggregate(flows: pd.DataFrame, window_s: float) -> pd.DataFrame:
    """Aggregate flow records into per-(window, destination node) features."""
    if flows.empty:
        return pd.DataFrame()

    agg = (
        flows.groupby(["window", "dst_node"], sort=False)
        .agg(
            in_packets=("packets", "sum"),
            in_bytes=("bytes", "sum"),
            in_flow_count=("packets", "size"),
            in_unique_src_nodes=("src_node", "nunique"),
            in_unique_src_ips=("src_ip", "nunique"),
        )
        .reset_index()
        .rename(columns={"dst_node": "node_id"})
    )
    agg["in_packet_rate"] = agg["in_packets"].astype(float) / window_s
    return agg


def _parent_map(topology: Mapping[str, Any]) -> dict[str, str | None]:
    """Return ``{node_id: parent_id}`` from a serialised topology."""
    return {n["node_id"]: n.get("parent") for n in topology["nodes"]}


def _ancestors(node_id: str, parents: Mapping[str, str | None]) -> list[str]:
    """Return the chain from *node_id* up to the root, inclusive."""
    chain = [node_id]
    guard = 0
    current = node_id
    while parents.get(current) is not None:
        guard += 1
        if guard > len(parents) + 2:  # pragma: no cover - defensive
            raise ValueError(f"Parent cycle detected above {node_id!r}")
        current = parents[current]  # type: ignore[assignment]
        chain.append(current)
    return chain


def transit_nodes(src: str, dst: str, parents: Mapping[str, str | None]) -> list[str]:
    """Return the intermediate forwarding nodes on the path ``src -> dst``.

    The topology is a tree rooted at the cloud, so the path is
    ``src -> ... -> LCA -> ... -> dst`` and the intermediates are every node on
    it except the two endpoints. These are exactly the routers and gateway whose
    forwarding counters would show the flow.

    Args:
        src: Source node id.
        dst: Destination node id.
        parents: ``{node: parent}`` mapping.

    Returns:
        Intermediate node ids, ordered from the source side to the destination
        side. Empty when the two nodes are directly attached.
    """
    if src == dst:
        return []
    up = _ancestors(src, parents)
    down = _ancestors(dst, parents)
    down_index = {node: i for i, node in enumerate(down)}
    for depth, node in enumerate(up):
        if node in down_index:
            path = up[: depth + 1] + list(reversed(down[: down_index[node]]))
            return path[1:-1]
    return []  # pragma: no cover - disconnected tree


def _transit_aggregate(
    flows: pd.DataFrame, window_s: float, parents: Mapping[str, str | None]
) -> pd.DataFrame:
    """Build feature rows for the routers and gateway that forward each flow.

    Infrastructure nodes never appear as a flow's source or destination, yet the
    graph must contain them: they are the aggregation points where a distributed
    attack becomes visible as fan-in. Their features are the flows they carry -
    precisely what a router's own interface counters would report.

    Args:
        flows: The run's flow records.
        window_s: Feature window length in seconds.
        parents: ``{node: parent}`` mapping from the topology.

    Returns:
        A frame with the same egress/ingress columns as the endpoint rows, keyed
        by ``(window, node_id)`` for infrastructure nodes only.
    """
    if flows.empty:
        return pd.DataFrame()

    pair_cache: dict[tuple[str, str], list[str]] = {}
    for src, dst in flows[["src_node", "dst_node"]].drop_duplicates().itertuples(index=False):
        pair_cache[(src, dst)] = transit_nodes(src, dst, parents)

    frame = flows.copy()
    frame["_transit"] = [
        pair_cache[(s, d)] for s, d in zip(frame["src_node"], frame["dst_node"])
    ]
    frame = frame[frame["_transit"].map(len) > 0]
    if frame.empty:
        return pd.DataFrame()

    frame = frame.explode("_transit", ignore_index=True)
    frame["src_node"] = frame["_transit"]
    egress = _egress_aggregate(frame.drop(columns=["_transit"]), window_s)

    ingress_frame = frame.copy()
    ingress_frame["dst_node"] = ingress_frame["_transit"]
    ingress = _ingress_aggregate(ingress_frame.drop(columns=["_transit"]), window_s)

    merged = egress.merge(ingress, on=["window", "node_id"], how="outer")
    numeric = merged.select_dtypes(include=[np.number]).columns
    merged[numeric] = merged[numeric].fillna(0.0)
    return merged


def build_node_window_features(
    result: Any,
    malicious_threshold: float = 0.55,
    suspicious_threshold: float = 0.12,
) -> pd.DataFrame:
    """Build the node-window feature matrix for one simulation run.

    Args:
        result: A :class:`~netshield.simulation.runner.SimulationResult`.
        malicious_threshold: Severity at or above which a node is MALICIOUS.
        suspicious_threshold: Severity at or above which a node is SUSPICIOUS.

    Returns:
        A :class:`pandas.DataFrame` with :data:`META_COLUMNS`,
        :data:`NODE_FEATURE_COLUMNS`, :data:`LABEL_COLUMNS` and a few ``diag_*``
        diagnostics. One row per observed ``(window, node)`` pair; nodes that
        neither sent nor received anything in a window are omitted, because a
        gateway cannot observe a silent device.

    Raises:
        ValueError: If the run produced no flow records at all.
    """
    flows = pd.DataFrame(result.flows)
    if flows.empty:
        raise ValueError(
            f"Run '{result.run_id}' produced no flow records; nothing to featurise."
        )

    window_s = float(result.summary.get("window_s", 5.0))
    parents = _parent_map(result.topology)

    egress = _egress_aggregate(flows, window_s)
    ingress = _ingress_aggregate(flows, window_s)
    features = egress.merge(ingress, on=["window", "node_id"], how="outer")

    # Routers and the gateway forward every flow but originate none, so they
    # need transit-derived rows or they would be missing from the graph.
    transit = _transit_aggregate(flows, window_s, parents)
    if not transit.empty:
        features = pd.concat([features, transit], ignore_index=True, sort=False)

    numeric = features.select_dtypes(include=[np.number]).columns
    features[numeric] = features[numeric].fillna(0.0)

    features["in_out_packet_ratio"] = _safe_div(
        features["in_packets"].astype(float), features["eg_packets"].astype(float) + 1.0
    )

    # ---- structural attributes from the topology --------------------------
    nodes = {n["node_id"]: n for n in result.topology["nodes"]}
    degree: dict[str, int] = {}
    for link in result.topology["links"]:
        degree[link["source"]] = degree.get(link["source"], 0) + 1
        degree[link["target"]] = degree.get(link["target"], 0) + 1

    features["kind"] = features["node_id"].map(lambda n: nodes.get(n, {}).get("kind", ""))
    features["device_class"] = features["node_id"].map(
        lambda n: nodes.get(n, {}).get("device_class", "")
    )
    features["ip"] = features["node_id"].map(lambda n: nodes.get(n, {}).get("ip", ""))
    features["tier"] = features["node_id"].map(
        lambda n: float(nodes.get(n, {}).get("tier", 3))
    )
    features["degree"] = features["node_id"].map(lambda n: float(degree.get(n, 0)))
    features["is_endpoint"] = features["kind"].isin(("iot", "attacker")).astype(float)
    features["is_attacker"] = features["node_id"].map(
        lambda n: bool(nodes.get(n, {}).get("is_attacker", False))
    )

    # ---- ground truth ------------------------------------------------------
    profile = _profile_from_summary(result.summary.get("attack", {}))
    features["t_start"] = features["window"].astype(float) * window_s
    features["t_end"] = features["t_start"] + window_s
    features["attack_duty"] = [
        attack_duty(profile, float(a), float(b))
        for a, b in zip(features["t_start"], features["t_end"])
    ]
    features.loc[~features["is_attacker"], "attack_duty"] = 0.0
    features["attack_ratio"] = _safe_div(
        features["attack_packets"].astype(float), features["eg_packets"].astype(float)
    )
    features["severity"] = features["attack_ratio"] * features["attack_duty"]
    features["label"] = [
        label_from_severity(s, malicious_threshold, suspicious_threshold)
        for s in features["severity"]
    ]
    features["label_name"] = features["label"].map(lambda i: CLASS_NAMES[int(i)])

    # ---- provenance --------------------------------------------------------
    features["run_id"] = result.run_id
    features["experiment"] = str(result.meta.get("experiment", result.run_id))
    features["engine"] = result.engine

    for column in NODE_FEATURE_COLUMNS:
        if column not in features.columns:
            features[column] = 0.0
    features[list(NODE_FEATURE_COLUMNS)] = (
        features[list(NODE_FEATURE_COLUMNS)].astype(float).replace([np.inf, -np.inf], 0.0)
    )

    ordered = [
        *META_COLUMNS,
        "engine",
        *NODE_FEATURE_COLUMNS,
        *LABEL_COLUMNS,
        *[c for c in features.columns if c.startswith("diag_")],
    ]
    ordered = [c for c in ordered if c in features.columns]
    out = features[ordered].sort_values(["window", "node_id"]).reset_index(drop=True)
    _LOG.debug(
        "Run '%s': %d node-window samples, class counts %s",
        result.run_id,
        len(out),
        out["label_name"].value_counts().to_dict(),
    )
    return out


def _profile_from_summary(attack: Mapping[str, Any]) -> AttackProfile:
    """Reconstruct an :class:`AttackProfile` from a serialised run summary."""
    burst = attack.get("burst", {}) or {}
    sizes = attack.get("packet_bytes", [64, 64]) or [64, 64]
    return AttackProfile(
        enabled=bool(attack.get("enabled", False)),
        attack_type=str(attack.get("type", "udp_flood")),
        start_s=float(attack.get("start_s", 0.0)),
        duration_s=float(attack.get("duration_s", 0.0)),
        packets_per_second=float(attack.get("packets_per_second", 0.0)),
        packet_bytes=(int(sizes[0]), int(sizes[1])),
        dst_ports=tuple(int(p) for p in (attack.get("dst_ports", [0]) or [0])),
        target=str(attack.get("target", "cloud")),
        burst_enabled=bool(burst.get("enabled", False)),
        burst_on_s=float(burst.get("on_s", 2.0)),
        burst_off_s=float(burst.get("off_s", 3.0)),
        spoof_sources=bool(attack.get("spoof_sources", False)),
        spoof_pool=int(attack.get("spoof_pool", 64)),
    )


def feature_matrix(frame: pd.DataFrame) -> np.ndarray:
    """Extract the ordered float feature matrix from a feature frame.

    Args:
        frame: A frame produced by :func:`build_node_window_features`.

    Returns:
        A ``(n_samples, n_features)`` float32 array in :data:`NODE_FEATURE_COLUMNS`
        order.

    Raises:
        LeakageError: If a ground-truth column has crept into the feature list.
        KeyError: If a declared feature column is missing from *frame*.
    """
    assert_no_leakage(NODE_FEATURE_COLUMNS)
    missing = [c for c in NODE_FEATURE_COLUMNS if c not in frame.columns]
    if missing:
        raise KeyError(f"Feature frame is missing columns: {missing}")
    return frame[list(NODE_FEATURE_COLUMNS)].to_numpy(dtype=np.float32)


def label_vector(frame: pd.DataFrame) -> np.ndarray:
    """Extract the integer label vector from a feature frame."""
    if "label" not in frame.columns:
        raise KeyError("Feature frame has no 'label' column.")
    return frame["label"].to_numpy(dtype=np.int64)


def class_distribution(frame: pd.DataFrame) -> dict[str, int]:
    """Return the label histogram as ``{class_name: count}``."""
    counts = frame["label"].value_counts().to_dict()
    return {CLASS_NAMES[int(k)]: int(v) for k, v in sorted(counts.items())}
