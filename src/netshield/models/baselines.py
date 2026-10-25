"""Additional baselines that a reviewer expects next to GraphSAGE.

The original comparison pitted the GNN against a threshold rule and a Random
Forest. That is not enough to support a claim that *graph structure* is what
helps, because a stronger tabular learner, a temporal learner or an
unsupervised detector might close the gap on its own. This module adds:

``lightgbm``
    Gradient-boosted trees (LightGBM). The strongest conventional tabular
    learner on intrusion-detection benchmarks; if GraphSAGE only beats the
    Random Forest but not this, the advantage is about model capacity rather
    than about graphs.
``gru_seq``
    A GRU over each node's own last ``K`` feature windows. It sees *history*
    but no *neighbours*, so it separates the temporal contribution from the
    relational one. It is causal - only past windows are used - so it is
    deployable in the closed loop.
``autoencoder``
    A one-class (benign-only) autoencoder scored by reconstruction error. It
    never sees an attack label, so it is the honest baseline for unseen
    (zero-day) attack families.

All three implement :class:`~netshield.models.base.Detector`, consume the
same scaled 46-feature rows and return probabilities row-aligned with the
input, so every metric is computed over identical samples.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.metrics import f1_score

from ..features.dataset import FeatureScaler, class_weights
from ..features.node_features import CLASS_NAMES
from ..utils.logging_utils import get_logger
from ..utils.paths import ensure_dir, resolve
from ..utils.seeding import seed_everything
from .base import Detector, DetectionInput, DetectorError, TrainingReport

_LOG = get_logger(__name__)

N_CLASSES = len(CLASS_NAMES)


def _expand_proba(raw: np.ndarray, classes: np.ndarray) -> np.ndarray:
    """Map a model's per-seen-class probabilities onto the 3-class layout."""
    full = np.zeros((raw.shape[0], N_CLASSES), dtype=np.float64)
    for column, class_index in enumerate(classes):
        full[:, int(class_index)] = raw[:, column]
    return full


# =========================================================================== #
# LightGBM
# =========================================================================== #
class LightGBMDetector(Detector):
    """Gradient-boosted decision trees over node-window features.

    Args:
        n_estimators: Maximum boosting rounds (early-stopped on validation).
        learning_rate: Shrinkage.
        num_leaves: Leaves per tree.
        min_child_samples: Minimum rows per leaf.
        subsample: Row subsampling per round.
        colsample_bytree: Feature subsampling per tree.
        seed: Deterministic seed.
    """

    name = "lightgbm"
    display_name = "LightGBM"
    uses_graph = False

    def __init__(
        self,
        n_estimators: int = 600,
        learning_rate: float = 0.05,
        num_leaves: int = 31,
        min_child_samples: int = 10,
        subsample: float = 0.8,
        colsample_bytree: float = 0.8,
        seed: int = 42,
    ) -> None:
        super().__init__()
        self.params: dict[str, Any] = {
            "n_estimators": int(n_estimators),
            "learning_rate": float(learning_rate),
            "num_leaves": int(num_leaves),
            "min_child_samples": int(min_child_samples),
            "subsample": float(subsample),
            "subsample_freq": 1,
            "colsample_bytree": float(colsample_bytree),
            "class_weight": "balanced",
            "random_state": int(seed),
            "n_jobs": -1,
            "verbose": -1,
        }
        self.model: Any = None
        self.scaler: FeatureScaler | None = None
        self._classes: np.ndarray | None = None

    @classmethod
    def from_config(cls, config: Any) -> "LightGBMDetector":
        """Build from ``detection.lightgbm``."""
        section = config.get("detection.lightgbm", {}) or {}
        return cls(
            n_estimators=int(section.get("n_estimators", 600)),
            learning_rate=float(section.get("learning_rate", 0.05)),
            num_leaves=int(section.get("num_leaves", 31)),
            min_child_samples=int(section.get("min_child_samples", 10)),
            subsample=float(section.get("subsample", 0.8)),
            colsample_bytree=float(section.get("colsample_bytree", 0.8)),
            seed=int(config.get("seed", 42)),
        )

    def fit(self, train: DetectionInput, val: DetectionInput | None = None) -> TrainingReport:
        """Fit with early stopping on validation multi-class log-loss."""
        import lightgbm as lgb  # noqa: PLC0415 - optional dependency

        started = time.perf_counter()
        self._check_columns(train.features)
        self.scaler = FeatureScaler.fit(train.features, self.feature_columns)
        x_train = self.scaler.transform(train.features)
        y_train = train.labels
        self.model = lgb.LGBMClassifier(**self.params)
        fit_kwargs: dict[str, Any] = {}
        has_val = val is not None and val.n_rows and len(np.unique(val.labels)) > 1
        if has_val:
            fit_kwargs = {
                "eval_X": (self.scaler.transform(val.features),),
                "eval_y": (val.labels,),
                "callbacks": [lgb.early_stopping(50, verbose=False)],
            }
        self.model.fit(x_train, y_train, **fit_kwargs)
        self._classes = self.model.classes_
        self.fitted = True
        val_f1 = (float(f1_score(val.labels, self.predict(val), average="macro",
                                 zero_division=0)) if has_val else float("nan"))
        importances = sorted(zip(self.feature_columns,
                                 self.model.feature_importances_.tolist()),
                             key=lambda kv: kv[1], reverse=True)
        return TrainingReport(
            detector=self.name, epochs=int(self.model.best_iteration_ or
                                           self.params["n_estimators"]),
            best_epoch=int(self.model.best_iteration_ or 0),
            duration_s=time.perf_counter() - started,
            extra={"params": dict(self.params),
                   "val_macro_f1": None if np.isnan(val_f1) else round(val_f1, 5),
                   "top_features": [{"feature": k, "importance": int(v)}
                                    for k, v in importances[:10]]},
        )

    def predict_proba(self, data: DetectionInput) -> np.ndarray:
        """Return 3-class probabilities aligned with ``data.features``."""
        self._require_fitted()
        self._check_columns(data.features)
        raw = self.model.predict_proba(self.scaler.transform(data.features))
        return _expand_proba(raw, self._classes)

    def save(self, directory: str | Path) -> Path:
        """Persist booster, scaler and manifest."""
        self._require_fitted()
        target = ensure_dir(directory)
        joblib.dump(self.model, target / "model.joblib")
        self.scaler.save(target / "scaler.json")
        (target / "params.json").write_text(json.dumps(self.params, indent=2), encoding="utf-8")
        self.write_manifest(target, {"kind": self.name, "trainable": True})
        return target

    @classmethod
    def load(cls, directory: str | Path) -> "LightGBMDetector":
        """Restore a saved LightGBM detector."""
        source = resolve(directory)
        detector = cls()
        detector.params = json.loads((source / "params.json").read_text(encoding="utf-8"))
        detector.model = joblib.load(source / "model.joblib")
        detector.scaler = FeatureScaler.load(source / "scaler.json")
        detector._classes = detector.model.classes_
        detector.feature_columns = list(cls.read_manifest(source)["feature_columns"])
        detector.fitted = True
        return detector


# =========================================================================== #
# shared torch helpers
# =========================================================================== #
def build_sequences(frame: pd.DataFrame, x: np.ndarray, length: int) -> np.ndarray:
    """Stack each row with its node's previous ``length - 1`` windows.

    Rows are grouped by ``(run_id, node_id)`` and ordered by ``window``. The
    returned tensor has the current window in the last time step and zero
    padding where a node has less history. Only *past* windows are used, so
    the model is causal and can run online.

    Args:
        frame: Feature rows carrying ``run_id``, ``node_id`` and ``window``.
        x: Scaled feature matrix row-aligned with *frame*.
        length: Sequence length ``K`` (>= 1).

    Returns:
        ``(n_rows, length, n_features)`` float32 array, row-aligned with *frame*.
    """
    n, d = x.shape
    out = np.zeros((n, length, d), dtype=np.float32)
    keys = frame["run_id"].astype(str) + "|" + frame["node_id"].astype(str)
    order = np.lexsort((frame["window"].to_numpy(), keys.to_numpy()))
    sorted_keys = keys.to_numpy()[order]
    for lag in range(length):
        if lag == 0:
            out[order, length - 1] = x[order]
            continue
        same = np.zeros(n, dtype=bool)
        same[lag:] = sorted_keys[lag:] == sorted_keys[:-lag]
        rows = order[same]
        prev = order[np.nonzero(same)[0] - lag]
        out[rows, length - 1 - lag] = x[prev]
    return out


class _TorchDetector(Detector):
    """Common fit/predict/save plumbing for the small torch baselines."""

    weights_file = "model.pt"

    def __init__(self, seed: int = 42) -> None:
        super().__init__()
        self.hyper: dict[str, Any] = {"seed": int(seed)}
        self.model: nn.Module | None = None
        self.scaler: FeatureScaler | None = None
        self.device = torch.device("cpu")

    # subclasses implement these three
    def _new_net(self, in_features: int) -> nn.Module:  # pragma: no cover
        raise NotImplementedError

    def _inputs(self, data: DetectionInput) -> np.ndarray:  # pragma: no cover
        raise NotImplementedError

    def save(self, directory: str | Path) -> Path:
        """Persist weights, scaler, hyper-parameters and manifest."""
        self._require_fitted()
        target = ensure_dir(directory)
        torch.save(self.model.state_dict(), target / self.weights_file)
        self.scaler.save(target / "scaler.json")
        (target / "hyperparameters.json").write_text(
            json.dumps({"hyper": self.hyper, "extra": self._extra_state()}, indent=2),
            encoding="utf-8")
        self.write_manifest(target, {"kind": self.name, "trainable": True})
        return target

    def _extra_state(self) -> dict[str, Any]:
        return {}

    def _restore_extra(self, extra: dict[str, Any]) -> None:
        return None

    @classmethod
    def load(cls, directory: str | Path) -> "_TorchDetector":
        """Restore a saved detector."""
        source = resolve(directory)
        payload = json.loads((source / "hyperparameters.json").read_text(encoding="utf-8"))
        detector = cls(**payload["hyper"])
        detector.scaler = FeatureScaler.load(source / "scaler.json")
        detector.feature_columns = list(cls.read_manifest(source)["feature_columns"])
        detector._restore_extra(payload.get("extra", {}))
        detector.model = detector._new_net(len(detector.feature_columns))
        detector.model.load_state_dict(torch.load(source / cls.weights_file,
                                                  map_location="cpu"))
        detector.model.eval()
        detector.fitted = True
        return detector


# =========================================================================== #
# GRU over a node's own history
# =========================================================================== #
class _GRUNet(nn.Module):
    def __init__(self, in_features: int, hidden: int, dropout: float) -> None:
        super().__init__()
        self.gru = nn.GRU(in_features, hidden, batch_first=True)
        self.drop = nn.Dropout(dropout)
        self.head = nn.Linear(hidden, N_CLASSES)

    def forward(self, seq: torch.Tensor) -> torch.Tensor:
        _, h = self.gru(seq)
        return self.head(self.drop(h[-1]))


class GRUSequenceDetector(_TorchDetector):
    """Causal GRU over each node's last ``K`` windows (no neighbours).

    Args:
        seq_len: Number of windows in each sequence, current included.
        hidden: GRU hidden width.
        dropout: Dropout before the read-out.
        lr: Adam learning rate.
        epochs: Maximum epochs.
        patience: Early-stopping patience on validation macro-F1.
        batch_size: Rows per optimisation step.
        seed: Deterministic seed.
    """

    name = "gru_seq"
    display_name = "GRU sequence (baseline)"
    uses_graph = False

    def __init__(self, seq_len: int = 6, hidden: int = 64, dropout: float = 0.2,
                 lr: float = 0.003, epochs: int = 60, patience: int = 10,
                 batch_size: int = 256, seed: int = 42) -> None:
        super().__init__(seed)
        self.hyper.update({"seq_len": int(seq_len), "hidden": int(hidden),
                           "dropout": float(dropout), "lr": float(lr),
                           "epochs": int(epochs), "patience": int(patience),
                           "batch_size": int(batch_size)})

    @classmethod
    def from_config(cls, config: Any) -> "GRUSequenceDetector":
        """Build from ``detection.gru_seq``."""
        section = config.get("detection.gru_seq", {}) or {}
        return cls(seed=int(config.get("seed", 42)),
                   **{k: section[k] for k in ("seq_len", "hidden", "dropout", "lr",
                                              "epochs", "patience", "batch_size")
                      if k in section})

    @property
    def history_windows(self) -> int:
        """Windows of history the closed-loop controller must buffer."""
        return int(self.hyper["seq_len"])

    def _new_net(self, in_features: int) -> nn.Module:
        return _GRUNet(in_features, self.hyper["hidden"], self.hyper["dropout"])

    def _inputs(self, data: DetectionInput) -> np.ndarray:
        return build_sequences(data.features, self.scaler.transform(data.features),
                               self.hyper["seq_len"])

    @torch.no_grad()
    def _proba_from(self, inputs: np.ndarray) -> np.ndarray:
        self.model.eval()
        out = []
        for start in range(0, len(inputs), 2048):
            batch = torch.from_numpy(inputs[start:start + 2048])
            out.append(F.softmax(self.model(batch), dim=1).numpy())
        return np.concatenate(out) if out else np.zeros((0, N_CLASSES))

    def fit(self, train: DetectionInput, val: DetectionInput | None = None) -> TrainingReport:
        """Train with weighted cross-entropy and early stopping."""
        started = time.perf_counter()
        seed_everything(self.hyper["seed"])
        self._check_columns(train.features)
        self.scaler = FeatureScaler.fit(train.features, self.feature_columns)
        x_tr = self._inputs(train)
        y_tr = np.array(train.labels, copy=True)
        x_va = self._inputs(val) if val is not None and val.n_rows else None
        y_va = val.labels if x_va is not None else None
        self.model = self._new_net(x_tr.shape[2])
        weights = torch.from_numpy(class_weights(y_tr, N_CLASSES)).float()
        criterion = nn.CrossEntropyLoss(weight=weights)
        optimiser = torch.optim.Adam(self.model.parameters(), lr=self.hyper["lr"],
                                     weight_decay=1e-4)
        rng = np.random.default_rng(self.hyper["seed"])
        best, best_state, best_epoch, stale = -1.0, None, 0, 0
        history: dict[str, list[float]] = {"loss": [], "val_f1": []}
        xt, yt = torch.from_numpy(x_tr), torch.from_numpy(y_tr)
        for epoch in range(1, self.hyper["epochs"] + 1):
            self.model.train()
            order = rng.permutation(len(x_tr))
            total = 0.0
            for start in range(0, len(order), self.hyper["batch_size"]):
                idx = torch.from_numpy(order[start:start + self.hyper["batch_size"]])
                optimiser.zero_grad(set_to_none=True)
                loss = criterion(self.model(xt[idx]), yt[idx])
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), 5.0)
                optimiser.step()
                total += float(loss.item()) * len(idx)
            history["loss"].append(round(total / len(x_tr), 6))
            if x_va is not None:
                f1 = float(f1_score(y_va, self._proba_from(x_va).argmax(1),
                                    average="macro", zero_division=0))
            else:
                f1 = -history["loss"][-1]
            history["val_f1"].append(round(f1, 6))
            if f1 > best + 1e-5:
                best, best_epoch, stale = f1, epoch, 0
                best_state = {k: v.clone() for k, v in self.model.state_dict().items()}
            else:
                stale += 1
                if stale >= self.hyper["patience"]:
                    break
        if best_state is not None:
            self.model.load_state_dict(best_state)
        self.fitted = True
        return TrainingReport(detector=self.name, epochs=len(history["loss"]),
                              best_epoch=best_epoch, history=history,
                              duration_s=time.perf_counter() - started,
                              extra={"hyper": dict(self.hyper),
                                     "best_val_macro_f1": round(best, 5)})

    def predict_proba(self, data: DetectionInput) -> np.ndarray:
        """Return 3-class probabilities aligned with ``data.features``."""
        self._require_fitted()
        self._check_columns(data.features)
        return self._proba_from(self._inputs(data)).astype(np.float64)


# =========================================================================== #
# One-class autoencoder
# =========================================================================== #
class _AENet(nn.Module):
    def __init__(self, in_features: int, bottleneck: int) -> None:
        super().__init__()
        hidden = max(bottleneck * 2, 24)
        self.encoder = nn.Sequential(nn.Linear(in_features, hidden), nn.ReLU(),
                                     nn.Linear(hidden, bottleneck), nn.ReLU())
        self.decoder = nn.Sequential(nn.Linear(bottleneck, hidden), nn.ReLU(),
                                     nn.Linear(hidden, in_features))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(x))


class AutoencoderDetector(_TorchDetector):
    """Benign-only autoencoder; anomaly score is reconstruction error.

    Labels are used for exactly one thing: selecting the BENIGN training rows.
    The decision scale is set from the benign validation error distribution
    (its ``quantile``-th percentile), never from attack examples, so the model
    is a genuine zero-day baseline.

    The anomaly ratio ``s = error / threshold`` is mapped to probabilities with
    ``P(hostile) = sigmoid(k log s)`` and the hostile mass is split towards
    MALICIOUS as ``s`` exceeds ``malicious_ratio``.

    Args:
        bottleneck: Latent width.
        lr: Adam learning rate.
        epochs: Training epochs.
        batch_size: Rows per step.
        quantile: Benign error percentile that defines ``s = 1``.
        malicious_ratio: Anomaly ratio at which hostile mass is half MALICIOUS.
        seed: Deterministic seed.
    """

    name = "autoencoder"
    display_name = "Autoencoder (unsupervised)"
    uses_graph = False

    def __init__(self, bottleneck: int = 10, lr: float = 0.002, epochs: int = 60,
                 batch_size: int = 256, quantile: float = 99.0,
                 malicious_ratio: float = 4.0, seed: int = 42) -> None:
        super().__init__(seed)
        self.hyper.update({"bottleneck": int(bottleneck), "lr": float(lr),
                           "epochs": int(epochs), "batch_size": int(batch_size),
                           "quantile": float(quantile),
                           "malicious_ratio": float(malicious_ratio)})
        self.threshold: float = 1.0

    @classmethod
    def from_config(cls, config: Any) -> "AutoencoderDetector":
        """Build from ``detection.autoencoder``."""
        section = config.get("detection.autoencoder", {}) or {}
        return cls(seed=int(config.get("seed", 42)),
                   **{k: section[k] for k in ("bottleneck", "lr", "epochs", "batch_size",
                                              "quantile", "malicious_ratio")
                      if k in section})

    def _new_net(self, in_features: int) -> nn.Module:
        return _AENet(in_features, self.hyper["bottleneck"])

    def _inputs(self, data: DetectionInput) -> np.ndarray:
        # Clip so one extreme flood row cannot dominate the squared error.
        return np.clip(self.scaler.transform(data.features), -8.0, 8.0).astype(np.float32)

    def _extra_state(self) -> dict[str, Any]:
        return {"threshold": self.threshold}

    def _restore_extra(self, extra: dict[str, Any]) -> None:
        self.threshold = float(extra.get("threshold", 1.0))

    @torch.no_grad()
    def reconstruction_error(self, data: DetectionInput) -> np.ndarray:
        """Per-row mean squared reconstruction error."""
        self.model.eval()
        x = torch.from_numpy(self._inputs(data))
        return ((self.model(x) - x) ** 2).mean(dim=1).numpy().astype(np.float64)

    def fit(self, train: DetectionInput, val: DetectionInput | None = None) -> TrainingReport:
        """Fit on BENIGN rows only; calibrate the scale on benign validation rows."""
        started = time.perf_counter()
        seed_everything(self.hyper["seed"])
        self._check_columns(train.features)
        benign_mask = train.labels == 0
        if not benign_mask.any():
            raise DetectorError("The autoencoder needs BENIGN training rows.")
        benign = train.subset(benign_mask)
        self.scaler = FeatureScaler.fit(benign.features, self.feature_columns)
        x = torch.from_numpy(self._inputs(benign))
        self.model = self._new_net(x.shape[1])
        optimiser = torch.optim.Adam(self.model.parameters(), lr=self.hyper["lr"])
        rng = np.random.default_rng(self.hyper["seed"])
        history: dict[str, list[float]] = {"loss": []}
        for _ in range(self.hyper["epochs"]):
            self.model.train()
            order = rng.permutation(len(x))
            total = 0.0
            for start in range(0, len(order), self.hyper["batch_size"]):
                idx = torch.from_numpy(order[start:start + self.hyper["batch_size"]])
                optimiser.zero_grad(set_to_none=True)
                loss = F.mse_loss(self.model(x[idx]), x[idx])
                loss.backward()
                optimiser.step()
                total += float(loss.item()) * len(idx)
            history["loss"].append(round(total / len(x), 6))
        self.fitted = True
        calib = benign
        if val is not None and val.n_rows and (val.labels == 0).any():
            calib = val.subset(val.labels == 0)
        errors = self.reconstruction_error(calib)
        self.threshold = float(max(1e-9, np.percentile(errors, self.hyper["quantile"])))
        return TrainingReport(detector=self.name, epochs=self.hyper["epochs"],
                              best_epoch=self.hyper["epochs"], history=history,
                              duration_s=time.perf_counter() - started,
                              extra={"hyper": dict(self.hyper),
                                     "threshold": self.threshold,
                                     "n_benign_train_rows": int(benign_mask.sum())})

    def predict_proba(self, data: DetectionInput) -> np.ndarray:
        """Map anomaly ratios onto BENIGN / SUSPICIOUS / MALICIOUS probabilities."""
        self._require_fitted()
        self._check_columns(data.features)
        ratio = np.maximum(self.reconstruction_error(data) / self.threshold, 1e-9)
        hostile = 1.0 / (1.0 + np.exp(-4.0 * np.log(ratio)))
        malicious_share = 1.0 / (1.0 + np.exp(
            -4.0 * np.log(ratio / self.hyper["malicious_ratio"])))
        p_mal = hostile * malicious_share
        return np.stack([1.0 - hostile, hostile - p_mal, p_mal], axis=1)
