"""Export GraphSAGE detectors to ONNX and serve them with ONNX Runtime.

PyTorch Geometric's ``SAGEConv`` relies on scatter kernels that do not export
reliably, so the trained weights are first copied into the mathematically
identical pure-PyTorch :class:`~netshield.models.graphsage.MeanSAGEConv`
(``lin_r -> lin_self`` with ``lin_l``'s bias, ``lin_l -> lin_neigh``). The
copy is verified numerically before export, and the exported graph is
verified against PyTorch after export, so a served model can never silently
diverge from the trained one.

The ONNX graph takes ``x`` (n_nodes, n_features), ``adj`` (n_nodes, n_nodes)
and returns class probabilities (n_nodes, 3); node and edge counts are
dynamic axes, so one file serves any topology size.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

from ..features.node_features import CLASS_NAMES
from ..models.base import DetectionInput
from ..models.graphsage import GraphSAGEDetector, MeanSAGEConv, _collate


class _ExportNet(nn.Module):
    def __init__(self, convs: list[MeanSAGEConv], norms: nn.ModuleList, head: nn.Linear) -> None:
        super().__init__()
        self.convs = nn.ModuleList(convs)
        self.norms = norms
        self.head = head

    def forward(self, x: torch.Tensor, adj: torch.Tensor) -> torch.Tensor:
        # adj is the row-normalised in-neighbour matrix: (adj @ x)[v] is the
        # mean of v's in-neighbours, exactly SAGEConv's mean aggregation.
        for conv, norm in zip(self.convs, self.norms):
            x = F.relu(norm(conv.lin_self(x) + conv.lin_neigh(adj @ x)))
        return F.softmax(self.head(x), dim=1)


def mean_adjacency(edge_index: np.ndarray, n_nodes: int) -> np.ndarray:
    """Row-normalised dense in-neighbour matrix (duplicates counted, like PyG)."""
    adj = np.zeros((n_nodes, n_nodes), dtype=np.float32)
    np.add.at(adj, (edge_index[1], edge_index[0]), 1.0)
    deg = adj.sum(axis=1, keepdims=True)
    return np.divide(adj, deg, out=np.zeros_like(adj), where=deg > 0)


def _to_mean_convs(detector: GraphSAGEDetector) -> list[MeanSAGEConv]:
    out = []
    for conv in detector.model.convs:
        if isinstance(conv, MeanSAGEConv):
            out.append(conv)
            continue
        lin_l, lin_r = conv.lin_l, conv.lin_r            # PyG SAGEConv
        out_ch, in_ch = lin_r.weight.shape
        mean = MeanSAGEConv(int(in_ch), int(out_ch))
        with torch.no_grad():
            mean.lin_self.weight.copy_(lin_r.weight)
            mean.lin_self.bias.copy_(lin_l.bias)
            mean.lin_neigh.weight.copy_(lin_l.weight)
        out.append(mean)
    return out


def export_graphsage(detector: GraphSAGEDetector, data: DetectionInput, path: str | Path,
                     opset: int = 17, atol: float = 1e-4) -> dict[str, Any]:
    """Export a fitted mean-aggregation GraphSAGE detector to ONNX.

    Args:
        detector: Fitted detector with ``arch == "sage"`` and mean aggregation.
        data: Sample evidence used for tracing and for the equivalence checks.
        path: Destination ``.onnx`` file (a sidecar ``.json`` holds the scaler
            and graph options).
        opset: ONNX opset.
        atol: Maximum allowed absolute probability difference.

    Returns:
        Export report with the measured max deviations and ORT latency.
    """
    if detector.hyper.get("arch", "sage") != "sage" or detector.hyper.get("aggr") != "mean":
        raise ValueError("ONNX export supports mean-aggregation GraphSAGE only.")
    detector.model.eval()
    net = _ExportNet(_to_mean_convs(detector), detector.model.norms, detector.model.head).eval()
    graphs = detector._build(data)
    x, ei, _, ea = _collate(graphs[: min(8, len(graphs))], torch.device("cpu"))
    adj = torch.from_numpy(mean_adjacency(ei.numpy(), x.shape[0]))
    with torch.no_grad():
        ref = F.softmax(detector.model(x, ei, ea), dim=1).numpy()
        copy = net(x, adj).numpy()
    copy_err = float(np.abs(ref - copy).max())
    if copy_err > atol:
        raise RuntimeError(f"Weight copy diverges from the trained model by {copy_err:.2e}")

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    torch.onnx.export(net, (x, adj), str(path), input_names=["x", "adj"],
                      output_names=["proba"], opset_version=opset, dynamo=False,
                      dynamic_axes={"x": {0: "nodes"}, "adj": {0: "nodes", 1: "nodes2"},
                                    "proba": {0: "nodes"}})
    import onnxruntime as ort  # noqa: PLC0415

    sess = ort.InferenceSession(str(path), providers=["CPUExecutionProvider"])
    feeds = {"x": x.numpy(), "adj": adj.numpy()}
    out = sess.run(None, feeds)[0]
    onnx_err = float(np.abs(out - ref).max())
    if onnx_err > atol:
        raise RuntimeError(f"ONNX output diverges from PyTorch by {onnx_err:.2e}")
    t0 = time.perf_counter()
    for _ in range(50):
        sess.run(None, feeds)
    ort_ms = (time.perf_counter() - t0) / 50 * 1000
    t0 = time.perf_counter()
    with torch.no_grad():
        for _ in range(50):
            detector.model(x, ei, ea)
    torch_ms = (time.perf_counter() - t0) / 50 * 1000
    sidecar = {"scaler": json.loads(json.dumps(detector.scaler.to_dict()))
               if hasattr(detector.scaler, "to_dict") else None,
               "graph_options": detector.graph_options,
               "feature_columns": detector.feature_columns, "classes": list(CLASS_NAMES)}
    path.with_suffix(".json").write_text(json.dumps(sidecar, indent=2, default=str),
                                         encoding="utf-8")
    return {"path": str(path), "nodes": int(x.shape[0]), "edges": int(ei.shape[1]),
            "weight_copy_max_abs_err": copy_err, "onnx_max_abs_err": onnx_err,
            "onnxruntime_ms_per_batch": round(ort_ms, 3),
            "torch_ms_per_batch": round(torch_ms, 3), "opset": opset,
            "bytes": path.stat().st_size}


class OnnxGraphSAGE:
    """ONNX Runtime-backed scorer with the detector's ``predict_proba`` contract."""

    def __init__(self, onnx_path: str | Path, detector: GraphSAGEDetector) -> None:
        import onnxruntime as ort  # noqa: PLC0415

        self.session = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
        self.detector = detector           # scaler + graph builder only
        self.name = f"{detector.name}_onnx"
        self.feature_columns = detector.feature_columns

    def predict_proba(self, data: DetectionInput) -> np.ndarray:
        n = len(data.features)
        out = np.full((n, len(CLASS_NAMES)), 1.0 / len(CLASS_NAMES))
        pos = {k: i for i, k in enumerate(zip(data.features["run_id"], data.features["window"],
                                              data.features["node_id"]))}
        for g in self.detector._build(data):
            proba = self.session.run(None, {"x": g.x.astype(np.float32),
                                            "adj": mean_adjacency(g.edge_index, g.n_nodes)})[0]
            for local, node in enumerate(g.node_ids):
                i = pos.get((g.run_id, g.window, node))
                if i is not None:
                    out[i] = proba[local]
        return out
