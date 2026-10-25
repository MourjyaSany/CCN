"""GraphSAGE node classifier (the proposed model).

Architecture
------------
Two ``SAGEConv`` layers with mean aggregation, followed by a linear read-out::

    h_v^{(0)} = x_v
    h_v^{(k)} = ReLU( W_self^{(k)} h_v^{(k-1)}
                      + W_nbr^{(k)} * MEAN_{u in N(v)} h_u^{(k-1)} )
    z_v       = W_out h_v^{(K)}

Two layers is a deliberate choice, not a default: it is exactly the receptive
field needed for this topology. One hop lets a device see its access router;
two hops let it see the gateway and, through the communication edges to the
cloud, every other talker in the window. That is precisely the evidence a
distributed low-and-slow attack hides in - each bot is individually
unremarkable, but their shared aggregation point is not.

Because the aggregator is *inductive* (it learns a function of a neighbourhood
rather than an embedding per node id), the trained model transfers to graphs
with different node counts. This is essential here: experiments vary the fleet
from 24 to 38 nodes, and the held-out generalisation run has an attacker count
never seen in training.

Implementation
--------------
PyTorch Geometric's ``SAGEConv`` is used when available. If it is not installed,
:class:`MeanSAGEConv` provides an equivalent pure-PyTorch mean-aggregation layer
built on ``index_add_``, so the project remains runnable and the architecture
remains conceptually identical. The active backend is recorded in the
checkpoint manifest and printed in every training log, so results are never
ambiguous about which path produced them.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Sequence

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.metrics import f1_score

from ..features.dataset import FeatureScaler, class_weights
from ..features.node_features import CLASS_NAMES
from ..graph.builder import EDGE_ATTR_DIM, WindowGraph, build_graphs
from ..utils.logging_utils import get_logger
from ..utils.paths import ensure_dir, resolve
from ..utils.seeding import seed_everything
from .base import Detector, DetectionInput, DetectorError, TrainingReport

_LOG = get_logger(__name__)

try:  # pragma: no cover - exercised implicitly by whichever backend is present
    from torch_geometric.nn import GATv2Conv as _PyGGATv2Conv
    from torch_geometric.nn import SAGEConv as _PyGSAGEConv

    PYG_AVAILABLE = True
    BACKEND = "torch-geometric"
except ImportError:  # pragma: no cover
    _PyGSAGEConv = None  # type: ignore[assignment]
    _PyGGATv2Conv = None  # type: ignore[assignment]
    PYG_AVAILABLE = False
    BACKEND = "pure-torch-fallback"


class MeanSAGEConv(nn.Module):
    """Pure-PyTorch GraphSAGE convolution with mean neighbourhood aggregation.

    Mathematically equivalent to ``torch_geometric.nn.SAGEConv(aggr="mean")``:
    a separate linear transform for the node's own representation and for the
    mean of its in-neighbours, summed.

    Args:
        in_channels: Input feature dimension.
        out_channels: Output feature dimension.
    """

    def __init__(self, in_channels: int, out_channels: int) -> None:
        super().__init__()
        self.lin_self = nn.Linear(in_channels, out_channels, bias=True)
        self.lin_neigh = nn.Linear(in_channels, out_channels, bias=False)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        """Aggregate neighbour features and combine with the node's own.

        Args:
            x: ``(n_nodes, in_channels)`` node features.
            edge_index: ``(2, n_edges)`` COO connectivity; messages flow from
                ``edge_index[0]`` to ``edge_index[1]``.

        Returns:
            ``(n_nodes, out_channels)`` updated representations.
        """
        source, target = edge_index[0], edge_index[1]
        gathered = x.index_select(0, source)

        summed = torch.zeros(x.size(0), x.size(1), dtype=x.dtype, device=x.device)
        summed.index_add_(0, target, gathered)

        counts = torch.zeros(x.size(0), 1, dtype=x.dtype, device=x.device)
        counts.index_add_(0, target, torch.ones_like(gathered[:, :1]))
        mean = summed / counts.clamp(min=1.0)

        return self.lin_self(x) + self.lin_neigh(mean)


class EdgeSAGEConv(nn.Module):
    """E-GraphSAGE convolution: messages carry edge (flow) attributes.

    Following Lo et al., "E-GraphSAGE: A Graph Neural Network based Intrusion
    Detection System for IoT" (NOMS 2022), each message is a learned function
    of the neighbour's representation concatenated with the attributes of the
    edge it travels along, so traffic volume on a link informs aggregation
    instead of being reduced to a scalar weight::

        m_uv = W_msg [h_u || e_uv],   h_v' = W_self h_v + MEAN_u m_uv

    Args:
        in_channels: Input node feature dimension.
        out_channels: Output dimension.
        edge_dim: Edge attribute dimension.
    """

    def __init__(self, in_channels: int, out_channels: int, edge_dim: int) -> None:
        super().__init__()
        self.lin_self = nn.Linear(in_channels, out_channels, bias=True)
        self.lin_msg = nn.Linear(in_channels + edge_dim, out_channels, bias=False)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor,
                edge_attr: torch.Tensor) -> torch.Tensor:
        source, target = edge_index[0], edge_index[1]
        messages = self.lin_msg(torch.cat([x.index_select(0, source), edge_attr], dim=1))
        summed = torch.zeros(x.size(0), messages.size(1), dtype=x.dtype, device=x.device)
        summed.index_add_(0, target, messages)
        counts = torch.zeros(x.size(0), 1, dtype=x.dtype, device=x.device)
        counts.index_add_(0, target, torch.ones_like(messages[:, :1]))
        return self.lin_self(x) + summed / counts.clamp(min=1.0)


#: Supported message-passing architectures.
ARCHITECTURES: tuple[str, ...] = ("sage", "gat", "edge_sage")


def _make_conv(in_channels: int, out_channels: int, aggr: str,
               arch: str = "sage", heads: int = 4) -> nn.Module:
    """Return a convolution layer for *arch*.

    ``sage`` uses PyG's ``SAGEConv`` (or the pure-torch equivalent); ``gat``
    uses ``GATv2Conv`` with edge attributes and concatenated heads whose total
    width equals *out_channels*; ``edge_sage`` is :class:`EdgeSAGEConv`.
    """
    if arch == "gat":
        if not PYG_AVAILABLE or _PyGGATv2Conv is None:
            raise DetectorError("The GAT baseline requires torch-geometric.")
        if out_channels % heads:
            raise DetectorError("hidden_channels must be divisible by the GAT head count.")
        return _PyGGATv2Conv(in_channels, out_channels // heads, heads=heads,
                             edge_dim=EDGE_ATTR_DIM, add_self_loops=False)
    if arch == "edge_sage":
        return EdgeSAGEConv(in_channels, out_channels, EDGE_ATTR_DIM)
    if PYG_AVAILABLE and _PyGSAGEConv is not None:
        return _PyGSAGEConv(in_channels, out_channels, aggr=aggr)
    return MeanSAGEConv(in_channels, out_channels)


class GraphSAGENet(nn.Module):
    """Stacked GraphSAGE encoder with a linear classification head.

    Args:
        in_channels: Node feature dimension.
        hidden_channels: Width of the hidden representations.
        num_classes: Number of output classes.
        num_layers: Number of message-passing rounds (>= 1).
        dropout: Dropout probability applied between layers.
        aggr: Neighbour aggregation ("mean", "max", "sum" - PyG backend only).
    """

    def __init__(
        self,
        in_channels: int,
        hidden_channels: int = 64,
        num_classes: int = 3,
        num_layers: int = 2,
        dropout: float = 0.3,
        aggr: str = "mean",
        arch: str = "sage",
        heads: int = 4,
    ) -> None:
        super().__init__()
        if num_layers < 1:
            raise ValueError("GraphSAGE needs at least one message-passing layer.")
        if arch not in ARCHITECTURES:
            raise ValueError(f"Unknown GNN architecture {arch!r}; known: {ARCHITECTURES}")
        self.arch = arch
        self.dropout = float(dropout)
        self.convs = nn.ModuleList()
        self.norms = nn.ModuleList()

        dims = [in_channels] + [hidden_channels] * num_layers
        for i in range(num_layers):
            self.convs.append(_make_conv(dims[i], dims[i + 1], aggr, arch, heads))
            self.norms.append(nn.LayerNorm(dims[i + 1]))
        self.head = nn.Linear(hidden_channels, num_classes)

    def _conv(self, conv: nn.Module, x: torch.Tensor, edge_index: torch.Tensor,
              edge_attr: torch.Tensor | None) -> torch.Tensor:
        if self.arch in ("gat", "edge_sage"):
            if edge_attr is None:
                raise DetectorError(f"Architecture '{self.arch}' needs edge attributes.")
            return conv(x, edge_index, edge_attr)
        return conv(x, edge_index)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor,
                edge_attr: torch.Tensor | None = None) -> torch.Tensor:
        """Return per-node class logits.

        Args:
            x: ``(n_nodes, in_channels)`` node features.
            edge_index: ``(2, n_edges)`` COO connectivity.

        Returns:
            ``(n_nodes, num_classes)`` logits.
        """
        for conv, norm in zip(self.convs, self.norms):
            x = self._conv(conv, x, edge_index, edge_attr)
            x = norm(x)
            x = F.relu(x)
            x = F.dropout(x, p=self.dropout, training=self.training)
        return self.head(x)

    def embed(self, x: torch.Tensor, edge_index: torch.Tensor,
              edge_attr: torch.Tensor | None = None) -> torch.Tensor:
        """Return the final hidden representation (for embedding visualisation)."""
        for conv, norm in zip(self.convs, self.norms):
            x = F.relu(norm(self._conv(conv, x, edge_index, edge_attr)))
        return x


def _collate(graphs: Sequence[WindowGraph], device: torch.device
             ) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
    """Merge several window graphs into one disconnected batch graph.

    Node indices are offset per graph so the batched ``edge_index`` never links
    two different windows - message passing therefore stays strictly within a
    window, which is required for the temporal semantics to hold.

    Args:
        graphs: Window graphs to batch.
        device: Target torch device.

    Returns:
        ``(x, edge_index, y, edge_attr)`` tensors for the batch.
    """
    xs: list[np.ndarray] = []
    ys: list[np.ndarray] = []
    edges: list[np.ndarray] = []
    attrs: list[np.ndarray] = []
    offset = 0
    for graph in graphs:
        xs.append(graph.x)
        ys.append(graph.y)
        edges.append(graph.edge_index + offset)
        attr = graph.edge_attr
        if attr.shape[0] != graph.n_edges:
            attr = np.zeros((graph.n_edges, EDGE_ATTR_DIM), dtype=np.float32)
        attrs.append(attr)
        offset += graph.n_nodes

    x = torch.from_numpy(np.concatenate(xs, axis=0)).to(device)
    y = torch.from_numpy(np.concatenate(ys, axis=0)).to(device)
    edge_index = torch.from_numpy(np.concatenate(edges, axis=1)).to(device)
    edge_attr = torch.from_numpy(np.concatenate(attrs, axis=0)).to(device)
    return x, edge_index, y, edge_attr


class GraphSAGEDetector(Detector):
    """The proposed graph-based DDoS detector.

    Args:
        hidden_channels: Hidden width.
        num_layers: Message-passing depth.
        dropout: Dropout probability.
        aggr: Neighbour aggregator.
        lr: Adam learning rate.
        weight_decay: L2 regularisation.
        epochs: Maximum training epochs.
        patience: Early-stopping patience in epochs, on validation macro-F1.
        batch_graphs: Number of window graphs per optimisation step.
        class_weighting: Use inverse-frequency weighted cross-entropy.
        seed: Deterministic seed.
        graph_options: Options forwarded to the graph builder.
    """

    name = "graphsage"
    display_name = "GraphSAGE (proposed)"
    uses_graph = True
    default_arch = "sage"

    def __init__(
        self,
        hidden_channels: int = 64,
        num_layers: int = 2,
        dropout: float = 0.3,
        aggr: str = "mean",
        lr: float = 0.008,
        weight_decay: float = 5e-4,
        epochs: int = 220,
        patience: int = 40,
        batch_graphs: int = 16,
        class_weighting: bool = True,
        seed: int = 42,
        graph_options: dict[str, Any] | None = None,
        arch: str | None = None,
        heads: int = 4,
    ) -> None:
        super().__init__()
        self.hyper: dict[str, Any] = {
            "arch": str(arch or self.default_arch),
            "heads": int(heads),
            "hidden_channels": int(hidden_channels),
            "num_layers": int(num_layers),
            "dropout": float(dropout),
            "aggr": str(aggr),
            "lr": float(lr),
            "weight_decay": float(weight_decay),
            "epochs": int(epochs),
            "patience": int(patience),
            "batch_graphs": int(batch_graphs),
            "class_weighting": bool(class_weighting),
            "seed": int(seed),
        }
        self.graph_options: dict[str, Any] = {
            "add_reverse_edges": True,
            "self_loops": True,
            "edge_weight_mode": "log_packets",
            **(graph_options or {}),
        }
        self.model: GraphSAGENet | None = None
        self.scaler: FeatureScaler | None = None
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.backend = BACKEND

    @classmethod
    def from_config(cls, config: Any) -> "GraphSAGEDetector":
        """Build a detector from ``detection.<name>`` and ``graph`` sections.

        Variants without their own section inherit ``detection.graphsage``, so
        every GNN baseline shares the same budget unless deliberately changed.
        """
        section = dict(config.get("detection.graphsage", {}) or {})
        section.update(config.get(f"detection.{cls.name}", {}) or {})
        graph_cfg = config.get("graph", {}) or {}
        return cls(
            hidden_channels=int(section.get("hidden_channels", 64)),
            num_layers=int(section.get("num_layers", 2)),
            dropout=float(section.get("dropout", 0.3)),
            aggr=str(section.get("aggr", "mean")),
            lr=float(section.get("lr", 0.008)),
            weight_decay=float(section.get("weight_decay", 5e-4)),
            epochs=int(section.get("epochs", 220)),
            patience=int(section.get("patience", 40)),
            batch_graphs=int(section.get("batch_graphs", 16)),
            class_weighting=bool(section.get("class_weighting", True)),
            seed=int(config.get("seed", 42)),
            heads=int(section.get("heads", 4)),
            graph_options={
                "add_reverse_edges": bool(graph_cfg.get("add_reverse_edges", True)),
                "self_loops": bool(graph_cfg.get("self_loops", True)),
                "edge_weight_mode": str(graph_cfg.get("edge_weight", "log_packets")),
            },
        )

    def _new_net(self, in_channels: int) -> GraphSAGENet:
        """Instantiate the network described by ``self.hyper``."""
        return GraphSAGENet(
            in_channels=in_channels,
            hidden_channels=self.hyper["hidden_channels"],
            num_classes=len(CLASS_NAMES),
            num_layers=self.hyper["num_layers"],
            dropout=self.hyper["dropout"],
            aggr=self.hyper["aggr"],
            arch=self.hyper.get("arch", "sage"),
            heads=int(self.hyper.get("heads", 4)),
        ).to(self.device)

    # ------------------------------------------------------------------ #
    def _build(self, data: DetectionInput) -> list[WindowGraph]:
        """Build window graphs for *data* using the fitted scaler."""
        if self.scaler is None:
            raise DetectorError("GraphSAGE needs a fitted scaler before building graphs.")
        return build_graphs(data.features, data.edges, self.scaler, **self.graph_options)

    # ------------------------------------------------------------------ #
    def fit(
        self, train: DetectionInput, val: DetectionInput | None = None
    ) -> TrainingReport:
        """Train the GNN with early stopping on validation macro-F1.

        Args:
            train: Training evidence (features + edges).
            val: Validation evidence; when omitted, the final epoch is kept and
                a warning is logged, because there is then no honest way to
                select a checkpoint.

        Returns:
            A :class:`TrainingReport` with the full loss/F1 history.

        Raises:
            DetectorError: If the training split yields no usable graphs.
        """
        started = time.perf_counter()
        seed_everything(self.hyper["seed"])
        self._check_columns(train.features)

        self.scaler = FeatureScaler.fit(train.features, self.feature_columns)
        train_graphs = self._build(train)
        if not train_graphs:
            raise DetectorError("Training split produced no window graphs.")
        val_graphs = self._build(val) if (val is not None and val.n_rows) else []

        in_channels = train_graphs[0].x.shape[1]
        self.model = self._new_net(in_channels)

        y_all = np.concatenate([g.y for g in train_graphs])
        weights = (
            torch.from_numpy(class_weights(y_all, len(CLASS_NAMES))).to(self.device)
            if self.hyper["class_weighting"] else None
        )
        criterion = nn.CrossEntropyLoss(weight=weights)
        optimiser = torch.optim.Adam(
            self.model.parameters(),
            lr=self.hyper["lr"],
            weight_decay=self.hyper["weight_decay"],
        )

        history: dict[str, list[float]] = {"loss": [], "train_f1": [], "val_f1": []}
        best_f1 = -1.0
        best_epoch = 0
        best_state: dict[str, torch.Tensor] | None = None
        stale = 0
        batch_size = max(1, self.hyper["batch_graphs"])
        rng = np.random.default_rng(self.hyper["seed"])

        _LOG.info(
            "Training GraphSAGE [%s] on %d graphs (%d val), %d features, "
            "%d layers x %d units, device=%s",
            self.backend, len(train_graphs), len(val_graphs), in_channels,
            self.hyper["num_layers"], self.hyper["hidden_channels"], self.device,
        )

        for epoch in range(1, self.hyper["epochs"] + 1):
            self.model.train()
            order = rng.permutation(len(train_graphs))
            epoch_loss = 0.0
            batches = 0
            train_pred: list[np.ndarray] = []
            train_true: list[np.ndarray] = []

            for start in range(0, len(order), batch_size):
                chunk = [train_graphs[i] for i in order[start:start + batch_size]]
                x, edge_index, y, edge_attr = _collate(chunk, self.device)
                optimiser.zero_grad(set_to_none=True)
                logits = self.model(x, edge_index, edge_attr)
                loss = criterion(logits, y)
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), 5.0)
                optimiser.step()
                epoch_loss += float(loss.item())
                batches += 1
                train_pred.append(logits.argmax(dim=1).detach().cpu().numpy())
                train_true.append(y.detach().cpu().numpy())

            mean_loss = epoch_loss / max(1, batches)
            train_f1 = float(
                f1_score(np.concatenate(train_true), np.concatenate(train_pred),
                         average="macro", zero_division=0)
            )
            val_f1 = float("nan")
            if val_graphs:
                val_f1 = self._score_graphs(val_graphs)

            history["loss"].append(round(mean_loss, 6))
            history["train_f1"].append(round(train_f1, 6))
            history["val_f1"].append(None if np.isnan(val_f1) else round(val_f1, 6))

            monitored = train_f1 if np.isnan(val_f1) else val_f1
            if monitored > best_f1 + 1e-5:
                best_f1 = monitored
                best_epoch = epoch
                best_state = {
                    k: v.detach().clone() for k, v in self.model.state_dict().items()
                }
                stale = 0
            else:
                stale += 1

            if epoch % 20 == 0 or epoch == 1:
                _LOG.info(
                    "  epoch %3d/%d  loss=%.4f  train_F1=%.4f  val_F1=%s",
                    epoch, self.hyper["epochs"], mean_loss, train_f1,
                    "n/a" if np.isnan(val_f1) else f"{val_f1:.4f}",
                )
            if stale >= self.hyper["patience"]:
                _LOG.info("  early stop at epoch %d (best epoch %d, F1=%.4f)",
                          epoch, best_epoch, best_f1)
                break

        if best_state is not None:
            self.model.load_state_dict(best_state)
        if not val_graphs:
            _LOG.warning(
                "No validation split was supplied; the checkpoint was selected on "
                "training macro-F1, which risks over-fitting."
            )
        self.fitted = True

        return TrainingReport(
            detector=self.name,
            trained=True,
            epochs=len(history["loss"]),
            best_epoch=best_epoch,
            history=history,
            duration_s=time.perf_counter() - started,
            extra={
                "backend": self.backend,
                "device": str(self.device),
                "hyperparameters": dict(self.hyper),
                "graph_options": dict(self.graph_options),
                "in_channels": int(in_channels),
                "n_train_graphs": len(train_graphs),
                "n_val_graphs": len(val_graphs),
                "n_parameters": int(sum(p.numel() for p in self.model.parameters())),
                "best_monitored_f1": round(best_f1, 5),
                "class_weights": class_weights(y_all, len(CLASS_NAMES)).tolist(),
            },
        )

    # ------------------------------------------------------------------ #
    @torch.no_grad()
    def _score_graphs(self, graphs: Sequence[WindowGraph]) -> float:
        """Return macro-F1 over a set of graphs."""
        if self.model is None:
            raise DetectorError("No model to score with.")
        self.model.eval()
        preds: list[np.ndarray] = []
        trues: list[np.ndarray] = []
        batch_size = max(1, self.hyper["batch_graphs"])
        for start in range(0, len(graphs), batch_size):
            chunk = list(graphs[start:start + batch_size])
            x, edge_index, y, edge_attr = _collate(chunk, self.device)
            logits = self.model(x, edge_index, edge_attr)
            preds.append(logits.argmax(dim=1).cpu().numpy())
            trues.append(y.cpu().numpy())
        return float(
            f1_score(np.concatenate(trues), np.concatenate(preds),
                     average="macro", zero_division=0)
        )

    @torch.no_grad()
    def predict_proba(self, data: DetectionInput) -> np.ndarray:
        """Return class probabilities row-aligned with ``data.features``.

        Graphs are built per ``(run_id, window)``, scored, and their per-node
        outputs are scattered back onto the original row order via the
        ``(run_id, window, node_id)`` key. Any row whose window produced no
        graph receives the uniform prior and is counted in a warning rather than
        silently dropped.
        """
        self._require_fitted()
        if self.model is None:  # pragma: no cover - defensive
            raise DetectorError("GraphSAGE is marked fitted but has no model.")
        self._check_columns(data.features)

        n_rows = len(data.features)
        output = np.full((n_rows, len(CLASS_NAMES)), 1.0 / len(CLASS_NAMES))
        position = {
            (run, window, node): i
            for i, (run, window, node) in enumerate(
                zip(data.features["run_id"], data.features["window"],
                    data.features["node_id"])
            )
        }

        graphs = self._build(data)
        self.model.eval()
        covered = 0
        batch_size = max(1, self.hyper["batch_graphs"])
        for start in range(0, len(graphs), batch_size):
            chunk = list(graphs[start:start + batch_size])
            x, edge_index, _, edge_attr = _collate(chunk, self.device)
            probs = F.softmax(self.model(x, edge_index, edge_attr), dim=1).cpu().numpy()
            offset = 0
            for graph in chunk:
                for local, node_id in enumerate(graph.node_ids):
                    key = (graph.run_id, graph.window, node_id)
                    index = position.get(key)
                    if index is not None:
                        output[index] = probs[offset + local]
                        covered += 1
                offset += graph.n_nodes

        if covered < n_rows:
            _LOG.warning(
                "GraphSAGE scored %d/%d rows; %d rows had no window graph and "
                "received the uniform prior.", covered, n_rows, n_rows - covered,
            )
        return output

    @torch.no_grad()
    def embeddings(self, data: DetectionInput) -> tuple[np.ndarray, pd.DataFrame]:
        """Return final-layer node embeddings and their metadata.

        Args:
            data: Evidence to embed.

        Returns:
            ``(embeddings, metadata)`` where metadata carries ``run_id``,
            ``window``, ``node_id``, ``kind`` and ``label``.
        """
        self._require_fitted()
        if self.model is None:  # pragma: no cover - defensive
            raise DetectorError("GraphSAGE has no model.")
        self.model.eval()
        graphs = self._build(data)
        vectors: list[np.ndarray] = []
        rows: list[dict[str, Any]] = []
        for graph in graphs:
            x, edge_index, _, edge_attr = _collate([graph], self.device)
            vectors.append(self.model.embed(x, edge_index, edge_attr).cpu().numpy())
            for i, node_id in enumerate(graph.node_ids):
                rows.append({
                    "run_id": graph.run_id,
                    "window": graph.window,
                    "node_id": node_id,
                    "kind": graph.kinds[i] if i < len(graph.kinds) else "",
                    "label": int(graph.y[i]),
                    "label_name": CLASS_NAMES[int(graph.y[i])],
                })
        if not vectors:
            return np.zeros((0, self.hyper["hidden_channels"]), np.float32), pd.DataFrame()
        return np.concatenate(vectors, axis=0), pd.DataFrame(rows)

    # ------------------------------------------------------------------ #
    def save(self, directory: str | Path) -> Path:
        """Persist weights, scaler, hyper-parameters and manifest."""
        self._require_fitted()
        if self.model is None or self.scaler is None:  # pragma: no cover
            raise DetectorError("Nothing to save: model or scaler is missing.")
        target = ensure_dir(directory)
        torch.save(self.model.state_dict(), target / "graphsage.pt")
        # feature_columns may be an ablation subset; persist what was used.
        self.scaler.save(target / "scaler.json")
        (target / "hyperparameters.json").write_text(
            json.dumps(
                {
                    "hyper": self.hyper,
                    "graph_options": self.graph_options,
                    "in_channels": int(len(self.feature_columns)),
                    "backend": self.backend,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        self.write_manifest(target, {"kind": self.name, "arch": self.hyper.get("arch"),
                                     "backend": self.backend, "trainable": True})
        _LOG.info("%s saved -> %s", self.display_name, target)
        return target

    @classmethod
    def load(cls, directory: str | Path) -> "GraphSAGEDetector":
        """Restore a GraphSAGE detector from disk.

        Raises:
            FileNotFoundError: If the checkpoint is missing.
        """
        source = resolve(directory)
        weights_path = source / "graphsage.pt"
        if not weights_path.exists():
            raise FileNotFoundError(f"No GraphSAGE checkpoint at {weights_path}")

        payload = json.loads((source / "hyperparameters.json").read_text(encoding="utf-8"))
        detector = cls(**{k: v for k, v in payload["hyper"].items()})
        detector.graph_options = dict(payload.get("graph_options", {}))
        detector.scaler = FeatureScaler.load(source / "scaler.json")
        manifest = cls.read_manifest(source)
        detector.feature_columns = list(manifest.get("feature_columns",
                                                     detector.feature_columns))

        in_channels = int(payload.get("in_channels", len(detector.feature_columns)))
        detector.model = detector._new_net(in_channels)
        detector.model.load_state_dict(
            torch.load(weights_path, map_location=detector.device)
        )
        detector.model.eval()
        detector.fitted = True
        if payload.get("backend") and payload["backend"] != BACKEND:
            _LOG.warning(
                "Checkpoint was trained with backend '%s' but '%s' is active. "
                "The layers are mathematically equivalent, but state-dict keys "
                "may differ across backends.", payload["backend"], BACKEND,
            )
        return detector


class GATDetector(GraphSAGEDetector):
    """Graph attention baseline (GATv2 with edge attributes).

    Attention lets a node weight its neighbours unequally, which is the
    natural competitor to mean aggregation when a few loud neighbours sit
    among many quiet ones.
    """

    name = "gat"
    display_name = "GATv2 (baseline)"
    default_arch = "gat"


class EGraphSAGEDetector(GraphSAGEDetector):
    """E-GraphSAGE baseline: flow attributes enter every message."""

    name = "egraphsage"
    display_name = "E-GraphSAGE (baseline)"
    default_arch = "edge_sage"
