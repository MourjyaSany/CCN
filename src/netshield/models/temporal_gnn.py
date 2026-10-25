"""Temporal GNN: GraphSAGE per window, then a GRU over each node's history.

Motivation
----------
GraphSAGE classifies every window independently, which throws away exactly
the evidence that identifies a pulsing or slowly ramping attacker: a node
that has been "a bit odd" for six consecutive windows is far more suspicious
than one that was odd once. The Random Forest has the same blindness, and the
GRU baseline has history but no neighbours. This model has both.

Architecture
------------
For window *t* the spatial encoder (the same message-passing stack as
GraphSAGE) produces an embedding ``h_v^t`` for every node. The temporal
encoder then runs a GRU over that node's last ``K`` embeddings::

    s_v^t = GRU(h_v^{t-K+1}, ..., h_v^t)
    z_v^t = W_out [ h_v^t || s_v^t ]

The model is **causal**: only windows ``<= t`` are used, so it can run inside
the closed loop with a ``K``-window buffer.

Efficiency
----------
All windows of a run are encoded in one batched pass (a disconnected union of
window graphs). A precomputed ``(n_rows, K)`` gather index then pulls each
node's history out of that embedding matrix, so sequence assembly costs one
tensor gather instead of a Python loop per node.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Sequence

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.metrics import f1_score

from ..features.dataset import FeatureScaler, class_weights
from ..features.node_features import CLASS_NAMES
from ..graph.builder import WindowGraph
from ..utils.logging_utils import get_logger
from ..utils.paths import ensure_dir, resolve
from ..utils.seeding import seed_everything
from .base import DetectionInput, DetectorError, TrainingReport
from .graphsage import GraphSAGEDetector, GraphSAGENet, _collate

_LOG = get_logger(__name__)
N_CLASSES = len(CLASS_NAMES)


class TemporalGNNNet(nn.Module):
    """Spatial GraphSAGE encoder + GRU temporal encoder + linear head."""

    def __init__(self, in_channels: int, hidden: int, num_layers: int, dropout: float,
                 aggr: str, arch: str, heads: int) -> None:
        super().__init__()
        self.spatial = GraphSAGENet(in_channels, hidden, N_CLASSES, num_layers, dropout,
                                    aggr, arch, heads)
        self.gru = nn.GRU(hidden, hidden, batch_first=True)
        self.dropout = float(dropout)
        self.head = nn.Linear(2 * hidden, N_CLASSES)

    def encode(self, x: torch.Tensor, edge_index: torch.Tensor,
               edge_attr: torch.Tensor) -> torch.Tensor:
        h = x
        for conv, norm in zip(self.spatial.convs, self.spatial.norms):
            h = F.relu(norm(self.spatial._conv(conv, h, edge_index, edge_attr)))
            h = F.dropout(h, p=self.dropout, training=self.training)
        return h

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor, edge_attr: torch.Tensor,
                history: torch.Tensor) -> torch.Tensor:
        """Return logits for every node-window in the batch.

        Args:
            history: ``(n_nodes, K)`` long tensor; entry ``[i, j]`` is the row
                of node *i*'s embedding ``K-1-j`` windows earlier, or ``-1``.
        """
        h = self.encode(x, edge_index, edge_attr)
        padded = torch.cat([torch.zeros(1, h.size(1), dtype=h.dtype, device=h.device), h])
        seq = padded[history + 1]                      # -1 -> zero row
        _, state = self.gru(seq)
        return self.head(torch.cat([h, state[-1]], dim=1))


class _RunBatch:
    """All window graphs of one run plus the history gather index."""

    __slots__ = ("graphs", "history", "keys")

    def __init__(self, graphs: list[WindowGraph], seq_len: int) -> None:
        self.graphs = sorted(graphs, key=lambda g: g.window)
        rows: dict[tuple[int, str], int] = {}
        keys: list[tuple[str, int, str]] = []
        offset = 0
        for g in self.graphs:
            for i, node in enumerate(g.node_ids):
                rows[(g.window, node)] = offset + i
                keys.append((g.run_id, g.window, node))
            offset += g.n_nodes
        history = np.full((offset, seq_len), -1, dtype=np.int64)
        windows = sorted({g.window for g in self.graphs})
        index_of = {w: k for k, w in enumerate(windows)}
        for (window, node), row in rows.items():
            pos = index_of[window]
            for lag in range(seq_len):
                if pos - lag < 0:
                    break
                prev = rows.get((windows[pos - lag], node))
                if prev is not None:
                    history[row, seq_len - 1 - lag] = prev
        self.history = history
        self.keys = keys


def _batch_runs(batches: Sequence[_RunBatch], device: torch.device):
    graphs = [g for b in batches for g in b.graphs]
    x, edge_index, y, edge_attr = _collate(graphs, device)
    histories, offset = [], 0
    for b in batches:
        h = b.history.copy()
        h[h >= 0] += offset
        histories.append(h)
        offset += b.history.shape[0]
    history = torch.from_numpy(np.concatenate(histories)).to(device)
    return x, edge_index, y, edge_attr, history


class TemporalGNNDetector(GraphSAGEDetector):
    """Spatio-temporal detector (GraphSAGE + GRU), causal over ``seq_len`` windows."""

    name = "temporal_gnn"
    display_name = "Temporal GNN (GraphSAGE + GRU)"
    default_arch = "sage"

    def __init__(self, *args: Any, seq_len: int = 6, runs_per_batch: int = 2,
                 **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.hyper["seq_len"] = int(seq_len)
        self.hyper["runs_per_batch"] = int(runs_per_batch)

    @classmethod
    def from_config(cls, config: Any) -> "TemporalGNNDetector":
        det = super().from_config(config)
        section = config.get("detection.temporal_gnn", {}) or {}
        det.hyper["seq_len"] = int(section.get("seq_len", 6))
        det.hyper["runs_per_batch"] = int(section.get("runs_per_batch", 2))
        det.hyper["epochs"] = int(section.get("epochs", 120))
        det.hyper["patience"] = int(section.get("patience", 20))
        return det

    @property
    def history_windows(self) -> int:
        """Windows of history the closed-loop controller must buffer."""
        return int(self.hyper["seq_len"])

    def _new_net(self, in_channels: int) -> TemporalGNNNet:  # type: ignore[override]
        return TemporalGNNNet(in_channels, self.hyper["hidden_channels"],
                              self.hyper["num_layers"], self.hyper["dropout"],
                              self.hyper["aggr"], self.hyper.get("arch", "sage"),
                              int(self.hyper.get("heads", 4))).to(self.device)

    def _runs(self, data: DetectionInput) -> list[_RunBatch]:
        graphs = self._build(data)
        by_run: dict[str, list[WindowGraph]] = {}
        for g in graphs:
            by_run.setdefault(g.run_id, []).append(g)
        return [_RunBatch(gs, self.hyper["seq_len"]) for _, gs in sorted(by_run.items())]

    @torch.no_grad()
    def _predict_runs(self, runs: Sequence[_RunBatch]) -> tuple[np.ndarray, list, np.ndarray]:
        self.model.eval()
        probs, keys, ys = [], [], []
        for start in range(0, len(runs), 4):
            chunk = runs[start:start + 4]
            x, ei, y, ea, hist = _batch_runs(chunk, self.device)
            probs.append(F.softmax(self.model(x, ei, ea, hist), dim=1).cpu().numpy())
            ys.append(y.cpu().numpy())
            for b in chunk:
                keys.extend(b.keys)
        if not probs:
            return np.zeros((0, N_CLASSES)), [], np.zeros(0, dtype=int)
        return np.concatenate(probs), keys, np.concatenate(ys)

    def fit(self, train: DetectionInput, val: DetectionInput | None = None) -> TrainingReport:
        """Train end-to-end with weighted cross-entropy; early-stop on val macro-F1."""
        started = time.perf_counter()
        seed_everything(self.hyper["seed"])
        self._check_columns(train.features)
        self.scaler = FeatureScaler.fit(train.features, self.feature_columns)
        train_runs = self._runs(train)
        if not train_runs:
            raise DetectorError("Training split produced no window graphs.")
        val_runs = self._runs(val) if val is not None and val.n_rows else []
        in_channels = train_runs[0].graphs[0].x.shape[1]
        self.model = self._new_net(in_channels)
        y_all = np.concatenate([g.y for b in train_runs for g in b.graphs])
        weights = torch.from_numpy(class_weights(y_all, N_CLASSES)).float().to(self.device)
        criterion = nn.CrossEntropyLoss(weight=weights)
        optimiser = torch.optim.Adam(self.model.parameters(), lr=self.hyper["lr"],
                                     weight_decay=self.hyper["weight_decay"])
        rng = np.random.default_rng(self.hyper["seed"])
        best, best_state, best_epoch, stale = -1.0, None, 0, 0
        history: dict[str, list[float]] = {"loss": [], "val_f1": []}
        per = max(1, self.hyper["runs_per_batch"])
        for epoch in range(1, self.hyper["epochs"] + 1):
            self.model.train()
            order = rng.permutation(len(train_runs))
            total, steps = 0.0, 0
            for start in range(0, len(order), per):
                chunk = [train_runs[i] for i in order[start:start + per]]
                x, ei, y, ea, hist = _batch_runs(chunk, self.device)
                optimiser.zero_grad(set_to_none=True)
                loss = criterion(self.model(x, ei, ea, hist), y)
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), 5.0)
                optimiser.step()
                total += float(loss.item())
                steps += 1
            history["loss"].append(round(total / max(1, steps), 6))
            if val_runs:
                p, _, yv = self._predict_runs(val_runs)
                f1 = float(f1_score(yv, p.argmax(1), average="macro", zero_division=0))
            else:
                f1 = -history["loss"][-1]
            history["val_f1"].append(round(f1, 6))
            if f1 > best + 1e-5:
                best, best_epoch, stale = f1, epoch, 0
                best_state = {k: v.detach().clone() for k, v in self.model.state_dict().items()}
            else:
                stale += 1
                if stale >= self.hyper["patience"]:
                    break
            if epoch % 10 == 0 or epoch == 1:
                _LOG.info("  temporal epoch %3d loss=%.4f val_F1=%.4f", epoch,
                          history["loss"][-1], f1)
        if best_state is not None:
            self.model.load_state_dict(best_state)
        self.fitted = True
        return TrainingReport(detector=self.name, epochs=len(history["loss"]),
                              best_epoch=best_epoch, history=history,
                              duration_s=time.perf_counter() - started,
                              extra={"hyperparameters": dict(self.hyper),
                                     "best_val_macro_f1": round(best, 5),
                                     "n_parameters": int(sum(p.numel() for p in
                                                             self.model.parameters()))})

    @torch.no_grad()
    def predict_proba(self, data: DetectionInput) -> np.ndarray:
        """Return probabilities row-aligned with ``data.features``.

        History is drawn only from windows present in *data*. In the closed
        loop the controller supplies the buffered recent windows, so live and
        offline scoring follow the same code path.
        """
        self._require_fitted()
        self._check_columns(data.features)
        n = len(data.features)
        out = np.full((n, N_CLASSES), 1.0 / N_CLASSES)
        position = {key: i for i, key in enumerate(zip(data.features["run_id"],
                                                       data.features["window"],
                                                       data.features["node_id"]))}
        probs, keys, _ = self._predict_runs(self._runs(data))
        for row, key in enumerate(keys):
            i = position.get(key)
            if i is not None:
                out[i] = probs[row]
        return out

    def save(self, directory: str | Path) -> Path:
        """Persist weights, scaler and hyper-parameters."""
        self._require_fitted()
        target = ensure_dir(directory)
        torch.save(self.model.state_dict(), target / "temporal_gnn.pt")
        self.scaler.save(target / "scaler.json")
        (target / "hyperparameters.json").write_text(json.dumps(
            {"hyper": self.hyper, "graph_options": self.graph_options,
             "in_channels": len(self.feature_columns), "backend": self.backend}, indent=2),
            encoding="utf-8")
        self.write_manifest(target, {"kind": self.name, "trainable": True,
                                     "seq_len": self.hyper["seq_len"]})
        return target

    @classmethod
    def load(cls, directory: str | Path) -> "TemporalGNNDetector":
        """Restore a saved temporal GNN."""
        source = resolve(directory)
        payload = json.loads((source / "hyperparameters.json").read_text(encoding="utf-8"))
        hyper = dict(payload["hyper"])
        seq_len = hyper.pop("seq_len", 6)
        runs_per_batch = hyper.pop("runs_per_batch", 2)
        detector = cls(seq_len=seq_len, runs_per_batch=runs_per_batch, **hyper)
        detector.graph_options = dict(payload.get("graph_options", {}))
        detector.scaler = FeatureScaler.load(source / "scaler.json")
        detector.feature_columns = list(cls.read_manifest(source)["feature_columns"])
        detector.model = detector._new_net(int(payload["in_channels"]))
        detector.model.load_state_dict(torch.load(source / "temporal_gnn.pt",
                                                  map_location=detector.device))
        detector.model.eval()
        detector.fitted = True
        return detector
