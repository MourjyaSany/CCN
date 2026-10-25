"""Common detector interface.

All three detectors - the threshold baseline, the Random Forest and GraphSAGE -
implement the same contract so the evaluation harness can treat them
interchangeably and so the comparison in the report is genuinely controlled:

* They receive the *same* :class:`DetectionInput` (identical node-window feature
  rows; the graph model additionally receives the edge table).
* They return a probability matrix **row-aligned with**
  ``DetectionInput.features``, so every metric is computed over exactly the same
  samples.
* They persist everything needed for inference - including the fitted feature
  scaler and the contractual feature column order - so a checkpoint can never be
  loaded against a mismatched feature set.
"""

from __future__ import annotations

import abc
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import numpy as np
import pandas as pd

from ..features.node_features import CLASS_NAMES, NODE_FEATURE_COLUMNS
from ..utils.logging_utils import get_logger
from ..utils.paths import ensure_dir, resolve

_LOG = get_logger(__name__)

N_CLASSES: int = len(CLASS_NAMES)


class DetectorError(RuntimeError):
    """Raised when a detector is used incorrectly (e.g. predict before fit)."""


@dataclass(slots=True)
class DetectionInput:
    """The evidence handed to a detector.

    Attributes:
        features: Node-window feature rows. Row order defines output order.
        edges: Edge table covering the same ``(run_id, window)`` pairs. Ignored
            by the tabular detectors; required by the graph detector.
    """

    features: pd.DataFrame
    edges: pd.DataFrame

    def __post_init__(self) -> None:
        if self.features is None:
            raise DetectorError("DetectionInput.features must not be None.")

    @property
    def labels(self) -> np.ndarray:
        """Ground-truth label vector, when present."""
        if "label" not in self.features.columns:
            raise DetectorError("DetectionInput has no 'label' column.")
        return self.features["label"].to_numpy(dtype=np.int64)

    @property
    def n_rows(self) -> int:
        """Number of feature rows."""
        return len(self.features)

    def subset(self, mask: np.ndarray) -> "DetectionInput":
        """Return a row-filtered view sharing the same edge table."""
        return DetectionInput(self.features[mask].reset_index(drop=True), self.edges)


@dataclass(slots=True)
class TrainingReport:
    """Outcome of fitting a detector.

    Attributes:
        detector: Detector name.
        trained: False for rule-based detectors that need no fitting.
        epochs: Number of epochs actually run (0 for non-iterative models).
        best_epoch: Epoch selected by early stopping.
        history: Per-epoch metric traces.
        duration_s: Wall-clock fitting time.
        extra: Detector-specific diagnostics (feature importances, class weights).
    """

    detector: str
    trained: bool = True
    epochs: int = 0
    best_epoch: int = 0
    history: dict[str, list[float]] | None = None
    duration_s: float = 0.0
    extra: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view."""
        return {
            "detector": self.detector,
            "trained": self.trained,
            "epochs": self.epochs,
            "best_epoch": self.best_epoch,
            "history": self.history or {},
            "duration_s": round(self.duration_s, 3),
            "extra": self.extra or {},
        }


class Detector(abc.ABC):
    """Abstract base class for every NetShield-GNN detector.

    Attributes:
        name: Short identifier used in filenames, figures and result tables.
        display_name: Human-readable name used in report tables.
        uses_graph: Whether the detector consumes the edge table.
    """

    name: str = "detector"
    display_name: str = "Detector"
    uses_graph: bool = False

    def __init__(self) -> None:
        self.fitted: bool = False
        self.feature_columns: list[str] = list(NODE_FEATURE_COLUMNS)

    # ------------------------------------------------------------------ #
    @abc.abstractmethod
    def fit(
        self, train: DetectionInput, val: DetectionInput | None = None
    ) -> TrainingReport:
        """Fit the detector.

        Args:
            train: Training evidence.
            val: Optional validation evidence for early stopping.

        Returns:
            A :class:`TrainingReport`.
        """

    @abc.abstractmethod
    def predict_proba(self, data: DetectionInput) -> np.ndarray:
        """Return class probabilities row-aligned with ``data.features``.

        Args:
            data: The evidence to score.

        Returns:
            A ``(n_rows, 3)`` float array whose rows sum to 1.
        """

    def predict(self, data: DetectionInput) -> np.ndarray:
        """Return hard class predictions (argmax of :meth:`predict_proba`)."""
        return self.predict_proba(data).argmax(axis=1).astype(np.int64)

    def attack_probability(self, data: DetectionInput) -> np.ndarray:
        """Return ``P(SUSPICIOUS) + P(MALICIOUS)`` - the "is this hostile" score.

        This is the scalar the mitigation engine thresholds and the score used
        for ROC/PR analysis, because the operational question is binary even
        though the model is three-class.
        """
        proba = self.predict_proba(data)
        return proba[:, 1] + proba[:, 2]

    # ------------------------------------------------------------------ #
    @abc.abstractmethod
    def save(self, directory: str | Path) -> Path:
        """Persist the detector to *directory* and return the directory path."""

    @classmethod
    @abc.abstractmethod
    def load(cls, directory: str | Path) -> "Detector":
        """Restore a detector previously written by :meth:`save`."""

    # ------------------------------------------------------------------ #
    def _require_fitted(self) -> None:
        """Raise if the detector has not been fitted yet."""
        if not self.fitted:
            raise DetectorError(
                f"Detector '{self.name}' must be fitted (or loaded) before use."
            )

    def _check_columns(self, frame: pd.DataFrame) -> None:
        """Verify the input frame carries the contractual feature columns."""
        missing = [c for c in self.feature_columns if c not in frame.columns]
        if missing:
            raise DetectorError(
                f"Detector '{self.name}' requires feature columns that are "
                f"missing from the input: {missing[:8]}"
            )

    def write_manifest(self, directory: str | Path, payload: Mapping[str, Any]) -> Path:
        """Write ``manifest.json`` describing a persisted detector."""
        target = ensure_dir(directory)
        manifest = {
            "detector": self.name,
            "display_name": self.display_name,
            "uses_graph": self.uses_graph,
            "classes": list(CLASS_NAMES),
            "feature_columns": self.feature_columns,
            **dict(payload),
        }
        path = target / "manifest.json"
        path.write_text(json.dumps(manifest, indent=2, default=str), encoding="utf-8")
        return path

    @staticmethod
    def read_manifest(directory: str | Path) -> dict[str, Any]:
        """Read ``manifest.json`` from a persisted detector directory.

        Raises:
            FileNotFoundError: If the manifest is absent.
        """
        path = resolve(directory) / "manifest.json"
        if not path.exists():
            raise FileNotFoundError(f"No detector manifest at {path}")
        return json.loads(path.read_text(encoding="utf-8"))

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        state = "fitted" if self.fitted else "unfitted"
        return f"<{type(self).__name__} name={self.name!r} {state}>"


def normalise_rows(matrix: np.ndarray) -> np.ndarray:
    """Normalise a non-negative score matrix into per-row probabilities.

    Args:
        matrix: A ``(n, k)`` non-negative array.

    Returns:
        A ``(n, k)`` array whose rows sum to 1. All-zero rows become uniform.
    """
    out = np.clip(np.asarray(matrix, dtype=np.float64), 0.0, None)
    totals = out.sum(axis=1, keepdims=True)
    uniform = np.full_like(out, 1.0 / out.shape[1])
    return np.where(totals > 0, out / np.where(totals > 0, totals, 1.0), uniform)
