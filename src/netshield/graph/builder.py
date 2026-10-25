"""Graph construction: turn a time window of network telemetry into a graph.

Why a graph at all
------------------
A tabular detector scores each device in isolation. That is exactly the wrong
inductive bias for DDoS, whose defining property is *distribution*: no single
node in a 12-bot low-and-slow attack looks anomalous on its own, but the
aggregation points above them do, and the bots share a destination, a port set
and a timing signature. Those are relations, not attributes.

Graph definition (one graph per ``(run, time window)``)
-------------------------------------------------------
**Nodes** - every entity observed in the window: IoT devices, compromised
devices, access routers, the edge gateway and the cloud server. Node features
are the 46-dimensional vector from :mod:`netshield.features.node_features`.

**Edges** - two families, distinguished by an edge-type attribute:

``physical``
    The wired/wireless topology: device-router, router-gateway,
    gateway-cloud. These carry the *aggregation hierarchy*. Two rounds of
    message passing therefore let a device's embedding see its router's
    aggregate load, and the router's embedding see the gateway's - which is how
    the model learns "this device is quiet, but everything under my router is
    collectively hammering the uplink".

``communication``
    Observed traffic relations ``src_node -> dst_node`` extracted from the flow
    records, weighted by volume. These connect every talker to the cloud server,
    so two hops relate any pair of devices that share a destination.

Edges are made bidirectional by default so information propagates both up and
down the hierarchy during aggregation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

import numpy as np
import pandas as pd

from ..features.node_features import CLASS_NAMES, NODE_FEATURE_COLUMNS
from ..utils.logging_utils import get_logger

_LOG = get_logger(__name__)

#: Edge type identifiers, also used as the integer edge-type feature.
EDGE_TYPES: tuple[str, ...] = ("physical", "communication")
EDGE_TYPE_INDEX: dict[str, int] = {name: i for i, name in enumerate(EDGE_TYPES)}

#: Columns of the persisted edge table.
EDGE_COLUMNS: tuple[str, ...] = (
    "run_id", "window", "src", "dst", "edge_type", "packets", "bytes",
    "mean_packet_size", "flows",
)


#: Width of :attr:`WindowGraph.edge_attr`.
EDGE_ATTR_DIM: int = 6


class GraphBuildError(ValueError):
    """Raised when a window graph cannot be constructed."""


@dataclass(slots=True)
class WindowGraph:
    """One time window represented as an attributed graph.

    Attributes:
        run_id: Originating simulation run.
        experiment: Experiment name.
        window: Window index.
        t_start: Window start time in simulated seconds.
        node_ids: Node identifiers, index-aligned with ``x`` and ``y``.
        x: ``(n_nodes, n_features)`` float32 node feature matrix.
        y: ``(n_nodes,)`` int64 ground-truth labels.
        edge_index: ``(2, n_edges)`` int64 COO connectivity.
        edge_weight: ``(n_edges,)`` float32 edge weights.
        edge_type: ``(n_edges,)`` int64 edge-type ids.
        kinds: Node role strings, index-aligned.
        is_attacker: Ground-truth attacker flags, index-aligned.
    """

    run_id: str
    experiment: str
    window: int
    t_start: float
    node_ids: list[str]
    x: np.ndarray
    y: np.ndarray
    edge_index: np.ndarray
    edge_weight: np.ndarray
    edge_type: np.ndarray
    kinds: list[str] = field(default_factory=list)
    is_attacker: np.ndarray = field(default_factory=lambda: np.zeros(0, dtype=bool))
    #: ``(n_edges, EDGE_ATTR_DIM)`` float32 edge attributes: log packets, log
    #: bytes, log mean packet size, log flows, physical flag, communication flag.
    edge_attr: np.ndarray = field(
        default_factory=lambda: np.zeros((0, EDGE_ATTR_DIM), dtype=np.float32))

    @property
    def n_nodes(self) -> int:
        """Number of nodes in this window graph."""
        return len(self.node_ids)

    @property
    def n_edges(self) -> int:
        """Number of directed edges in this window graph."""
        return int(self.edge_index.shape[1])

    def summary(self) -> dict[str, Any]:
        """Return a compact JSON-serialisable description."""
        counts = np.bincount(self.y, minlength=len(CLASS_NAMES))
        return {
            "run_id": self.run_id,
            "experiment": self.experiment,
            "window": self.window,
            "t_start": self.t_start,
            "n_nodes": self.n_nodes,
            "n_edges": self.n_edges,
            "classes": {CLASS_NAMES[i]: int(c) for i, c in enumerate(counts)},
        }


# --------------------------------------------------------------------------- #
# edge extraction
# --------------------------------------------------------------------------- #
def build_edge_table(result: Any) -> pd.DataFrame:
    """Extract the per-window edge table for one simulation run.

    Args:
        result: A :class:`~netshield.simulation.runner.SimulationResult`.

    Returns:
        A frame with :data:`EDGE_COLUMNS`. Communication edges are aggregated
        per ``(window, src_node, dst_node)``; physical edges are emitted once per
        window so a window graph is self-contained.
    """
    flows = pd.DataFrame(result.flows)
    windows = sorted(flows["window"].unique()) if not flows.empty else []

    rows: list[dict[str, Any]] = []

    if not flows.empty:
        comm = (
            flows.groupby(["window", "src_node", "dst_node"], sort=False)
            .agg(packets=("packets", "sum"), bytes=("bytes", "sum"),
                 flows=("packets", "size"))
            .reset_index()
        )
        comm["mean_packet_size"] = (
            comm["bytes"] / comm["packets"].replace(0, np.nan)
        ).fillna(0.0)
        for row in comm.itertuples(index=False):
            rows.append({
                "run_id": result.run_id,
                "window": int(row.window),
                "src": row.src_node,
                "dst": row.dst_node,
                "edge_type": "communication",
                "packets": int(row.packets),
                "bytes": int(row.bytes),
                "mean_packet_size": round(float(row.mean_packet_size), 3),
                "flows": int(row.flows),
            })

    physical = [(link["source"], link["target"]) for link in result.topology["links"]]
    for window in windows:
        for src, dst in physical:
            rows.append({
                "run_id": result.run_id,
                "window": int(window),
                "src": src,
                "dst": dst,
                "edge_type": "physical",
                "packets": 0,
                "bytes": 0,
                "mean_packet_size": 0.0,
                "flows": 0,
            })

    return pd.DataFrame(rows, columns=list(EDGE_COLUMNS))


# --------------------------------------------------------------------------- #
# graph assembly
# --------------------------------------------------------------------------- #
def _edge_weight(
    packets: float, byte_count: float, mode: str
) -> float:
    """Compute an edge weight from traffic volume.

    Args:
        packets: Packet count carried by the edge.
        byte_count: Byte count carried by the edge.
        mode: ``"packets"``, ``"bytes"`` or ``"log_packets"``.

    Returns:
        The weight. ``log_packets`` is the default because raw packet counts
        span four orders of magnitude between idle sensors and a flood, which
        would otherwise let a single edge dominate every aggregation.
    """
    if mode == "bytes":
        return float(byte_count)
    if mode == "packets":
        return float(packets)
    return float(np.log1p(max(0.0, packets)))


def build_window_graph(
    features: pd.DataFrame,
    edges: pd.DataFrame,
    x: np.ndarray,
    add_reverse_edges: bool = True,
    self_loops: bool = True,
    edge_weight_mode: str = "log_packets",
    edge_types: Sequence[str] | None = None,
) -> WindowGraph:
    """Assemble a single window graph.

    Args:
        features: Feature rows for exactly one ``(run_id, window)``.
        edges: Edge rows for the same ``(run_id, window)``.
        x: Pre-scaled node feature matrix, row-aligned with *features*.
        add_reverse_edges: Emit both directions of every edge.
        self_loops: Add a self-loop to every node so a node's own features
            survive mean aggregation.
        edge_weight_mode: See :func:`_edge_weight`.
        edge_types: Keep only these edge families (``"physical"``,
            ``"communication"``). ``None`` keeps both. Self-loops are always
            kept, so an empty list yields a graph-free (per-node) model - the
            ablation that isolates what message passing contributes.

    Returns:
        The assembled :class:`WindowGraph`.

    Raises:
        GraphBuildError: If *features* is empty or spans multiple windows.
    """
    if features.empty:
        raise GraphBuildError("Cannot build a graph from an empty feature frame.")
    if features["window"].nunique() != 1 or features["run_id"].nunique() != 1:
        raise GraphBuildError(
            "build_window_graph expects rows from exactly one (run_id, window)."
        )

    node_ids = list(features["node_id"])
    index = {node: i for i, node in enumerate(node_ids)}

    src_list: list[int] = []
    dst_list: list[int] = []
    weight_list: list[float] = []
    type_list: list[int] = []
    attr_list: list[list[float]] = []
    allowed = None if edge_types is None else {EDGE_TYPE_INDEX[t] for t in edge_types}

    seen: set[tuple[int, int, int]] = set()

    def add(u: int, v: int, weight: float, etype: int, attr: list[float]) -> None:
        key = (u, v, etype)
        if key in seen:
            return
        seen.add(key)
        src_list.append(u)
        dst_list.append(v)
        weight_list.append(weight)
        type_list.append(etype)
        attr_list.append(attr)

    for row in edges.itertuples(index=False):
        u = index.get(row.src)
        v = index.get(row.dst)
        if u is None or v is None:
            # An edge endpoint that produced no observable traffic this window.
            continue
        etype = EDGE_TYPE_INDEX.get(str(row.edge_type), 1)
        if allowed is not None and etype not in allowed:
            continue
        weight = (
            1.0 if etype == EDGE_TYPE_INDEX["physical"]
            else _edge_weight(float(row.packets), float(row.bytes), edge_weight_mode)
        )
        physical = etype == EDGE_TYPE_INDEX["physical"]
        attr = [
            float(np.log1p(max(0.0, float(row.packets)))),
            float(np.log1p(max(0.0, float(row.bytes)))) / 4.0,
            float(np.log1p(max(0.0, float(getattr(row, "mean_packet_size", 0.0) or 0.0)))) / 2.0,
            float(np.log1p(max(0.0, float(getattr(row, "flows", 0.0) or 0.0)))),
            1.0 if physical else 0.0,
            0.0 if physical else 1.0,
        ]
        add(u, v, weight, etype, attr)
        if add_reverse_edges:
            add(v, u, weight, etype, attr)

    if self_loops:
        for i in range(len(node_ids)):
            add(i, i, 1.0, EDGE_TYPE_INDEX["physical"], [0.0, 0.0, 0.0, 0.0, 1.0, 0.0])

    if not src_list:
        raise GraphBuildError(
            f"Window {features['window'].iloc[0]} of run "
            f"{features['run_id'].iloc[0]} produced a graph with no edges."
        )

    return WindowGraph(
        run_id=str(features["run_id"].iloc[0]),
        experiment=str(features["experiment"].iloc[0]),
        window=int(features["window"].iloc[0]),
        t_start=float(features["t_start"].iloc[0]),
        node_ids=node_ids,
        x=np.asarray(x, dtype=np.float32),
        y=features["label"].to_numpy(dtype=np.int64),
        edge_index=np.asarray([src_list, dst_list], dtype=np.int64),
        edge_weight=np.asarray(weight_list, dtype=np.float32),
        edge_type=np.asarray(type_list, dtype=np.int64),
        kinds=list(features["kind"]),
        is_attacker=features["is_attacker"].to_numpy(dtype=bool),
        edge_attr=np.asarray(attr_list, dtype=np.float32).reshape(-1, EDGE_ATTR_DIM),
    )


def build_graphs(
    features: pd.DataFrame,
    edges: pd.DataFrame,
    scaler: Any,
    add_reverse_edges: bool = True,
    self_loops: bool = True,
    edge_weight_mode: str = "log_packets",
    edge_types: Sequence[str] | None = None,
) -> list[WindowGraph]:
    """Build one graph per ``(run_id, window)`` present in *features*.

    Args:
        features: Node-window feature frame, possibly spanning many runs.
        edges: Edge table covering the same runs and windows.
        scaler: A fitted :class:`~netshield.features.dataset.FeatureScaler`.
        add_reverse_edges: Emit both directions of every edge.
        self_loops: Add self-loops.
        edge_weight_mode: Edge weighting mode.

    Returns:
        The window graphs, ordered by ``(run_id, window)``.
    """
    graphs: list[WindowGraph] = []
    edge_groups = {key: group for key, group in edges.groupby(["run_id", "window"])} \
        if not edges.empty else {}

    skipped = 0
    for (run_id, window), group in features.groupby(["run_id", "window"], sort=True):
        group = group.reset_index(drop=True)
        window_edges = edge_groups.get(
            (run_id, window), pd.DataFrame(columns=list(EDGE_COLUMNS))
        )
        matrix = scaler.transform(group)
        try:
            graphs.append(
                build_window_graph(
                    group, window_edges, matrix,
                    add_reverse_edges=add_reverse_edges,
                    self_loops=self_loops,
                    edge_weight_mode=edge_weight_mode,
                    edge_types=edge_types,
                )
            )
        except GraphBuildError as exc:
            skipped += 1
            _LOG.debug("Skipping window graph: %s", exc)

    if skipped:
        _LOG.warning("Skipped %d window(s) that produced no usable graph.", skipped)
    _LOG.info(
        "Built %d window graphs (mean %.1f nodes, %.1f edges).",
        len(graphs),
        float(np.mean([g.n_nodes for g in graphs])) if graphs else 0.0,
        float(np.mean([g.n_edges for g in graphs])) if graphs else 0.0,
    )
    return graphs


# --------------------------------------------------------------------------- #
# exports
# --------------------------------------------------------------------------- #
def to_pyg_data(graph: WindowGraph) -> Any:
    """Convert a :class:`WindowGraph` into a PyTorch Geometric ``Data`` object.

    Args:
        graph: The window graph.

    Returns:
        A ``torch_geometric.data.Data`` carrying ``x``, ``edge_index``,
        ``edge_weight``, ``edge_type`` and ``y``.

    Raises:
        ImportError: If PyTorch Geometric is not installed.
    """
    import torch
    from torch_geometric.data import Data

    data = Data(
        x=torch.from_numpy(graph.x),
        edge_index=torch.from_numpy(graph.edge_index),
        y=torch.from_numpy(graph.y),
    )
    data.edge_weight = torch.from_numpy(graph.edge_weight)
    data.edge_type = torch.from_numpy(graph.edge_type)
    data.run_id = graph.run_id
    data.window = graph.window
    data.node_ids = graph.node_ids
    return data


def to_networkx(graph: WindowGraph, include_features: bool = True) -> Any:
    """Convert a :class:`WindowGraph` into a :class:`networkx.DiGraph`.

    Args:
        graph: The window graph.
        include_features: Attach the (scaled) feature vector to each node.

    Returns:
        A directed NetworkX graph with node and edge attributes, used for the
        topology and graph-structure figures.
    """
    import networkx as nx

    nx_graph = nx.DiGraph()
    for i, node_id in enumerate(graph.node_ids):
        attrs: dict[str, Any] = {
            "label": int(graph.y[i]),
            "label_name": CLASS_NAMES[int(graph.y[i])],
            "kind": graph.kinds[i] if i < len(graph.kinds) else "",
            "is_attacker": bool(graph.is_attacker[i]) if len(graph.is_attacker) else False,
        }
        if include_features:
            attrs["features"] = graph.x[i].tolist()
        nx_graph.add_node(node_id, **attrs)

    for k in range(graph.n_edges):
        u = graph.node_ids[int(graph.edge_index[0, k])]
        v = graph.node_ids[int(graph.edge_index[1, k])]
        if u == v:
            continue
        nx_graph.add_edge(
            u, v,
            weight=float(graph.edge_weight[k]),
            edge_type=EDGE_TYPES[int(graph.edge_type[k])],
        )
    return nx_graph


def graphs_to_tensors(graphs: Sequence[WindowGraph]) -> tuple[np.ndarray, np.ndarray]:
    """Stack every graph's node features and labels into flat arrays.

    Useful for the tabular baselines, which must see exactly the same rows the
    GNN sees so that the comparison is controlled.

    Args:
        graphs: The window graphs.

    Returns:
        ``(X, y)`` with ``X`` of shape ``(total_nodes, n_features)``.
    """
    if not graphs:
        return np.zeros((0, len(NODE_FEATURE_COLUMNS)), np.float32), np.zeros(0, np.int64)
    return (
        np.concatenate([g.x for g in graphs], axis=0),
        np.concatenate([g.y for g in graphs], axis=0),
    )


def graph_statistics(graphs: Iterable[WindowGraph]) -> dict[str, Any]:
    """Return aggregate statistics over a collection of window graphs."""
    graphs = list(graphs)
    if not graphs:
        return {"n_graphs": 0}
    nodes = np.array([g.n_nodes for g in graphs])
    edges = np.array([g.n_edges for g in graphs])
    labels = np.concatenate([g.y for g in graphs])
    counts = np.bincount(labels, minlength=len(CLASS_NAMES))
    return {
        "n_graphs": len(graphs),
        "total_nodes": int(nodes.sum()),
        "total_edges": int(edges.sum()),
        "mean_nodes": round(float(nodes.mean()), 2),
        "mean_edges": round(float(edges.mean()), 2),
        "min_nodes": int(nodes.min()),
        "max_nodes": int(nodes.max()),
        "classes": {CLASS_NAMES[i]: int(c) for i, c in enumerate(counts)},
    }


def edge_table_from_results(results: Iterable[Any]) -> pd.DataFrame:
    """Concatenate edge tables for many runs."""
    frames = [build_edge_table(result) for result in results]
    frames = [f for f in frames if not f.empty]
    if not frames:
        return pd.DataFrame(columns=list(EDGE_COLUMNS))
    return pd.concat(frames, ignore_index=True)
