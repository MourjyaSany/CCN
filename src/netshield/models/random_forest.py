"""Random-Forest detector (Baseline B).

A strong, conventional tabular baseline: it sees the identical 46-dimensional
node-window feature vector that GraphSAGE sees, but each sample is independent.
Any gap between this model and GraphSAGE is therefore attributable to the graph
structure and not to feature engineering, class balancing or scaling - all of
which are held constant.

Class imbalance is handled with ``class_weight="balanced"`` (inverse frequency),
which matches the weighted cross-entropy used by the GNN.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score

from ..features.dataset import FeatureScaler
from ..features.node_features import CLASS_NAMES
from ..utils.logging_utils import get_logger
from ..utils.paths import ensure_dir, resolve
from .base import Detector, DetectionInput, TrainingReport

_LOG = get_logger(__name__)


class RandomForestDetector(Detector):
    """Random-Forest classifier over node-window features.

    Args:
        n_estimators: Number of trees.
        max_depth: Maximum tree depth (``None`` for unlimited).
        min_samples_leaf: Minimum samples in a leaf.
        class_weight: Passed straight to scikit-learn.
        n_jobs: Parallelism; ``-1`` uses every core.
        seed: Deterministic seed for the forest.
    """

    name = "random_forest"
    display_name = "Random Forest"
    uses_graph = False

    def __init__(
        self,
        n_estimators: int = 300,
        max_depth: int | None = 14,
        min_samples_leaf: int = 2,
        class_weight: str | None = "balanced",
        n_jobs: int = -1,
        seed: int = 42,
    ) -> None:
        super().__init__()
        self.params: dict[str, Any] = {
            "n_estimators": int(n_estimators),
            "max_depth": None if max_depth in (None, 0) else int(max_depth),
            "min_samples_leaf": int(min_samples_leaf),
            "class_weight": class_weight,
            "n_jobs": int(n_jobs),
            "random_state": int(seed),
        }
        self.model: RandomForestClassifier | None = None
        self.scaler: FeatureScaler | None = None
        self._classes: np.ndarray | None = None

    @classmethod
    def from_config(cls, config: Any) -> "RandomForestDetector":
        """Build a detector from the ``detection.random_forest`` config section."""
        section = config.get("detection.random_forest", {}) or {}
        return cls(
            n_estimators=int(section.get("n_estimators", 300)),
            max_depth=section.get("max_depth", 14),
            min_samples_leaf=int(section.get("min_samples_leaf", 2)),
            class_weight=section.get("class_weight", "balanced"),
            n_jobs=int(section.get("n_jobs", -1)),
            seed=int(config.get("seed", 42)),
        )

    # ------------------------------------------------------------------ #
    def fit(
        self, train: DetectionInput, val: DetectionInput | None = None
    ) -> TrainingReport:
        """Fit the forest on the training split.

        The feature scaler is fitted on training rows only. Trees are invariant
        to monotone rescaling, so scaling does not change the forest - it is
        applied purely so every detector consumes byte-identical inputs.

        Args:
            train: Training evidence.
            val: Optional validation evidence, used only to report macro-F1.

        Returns:
            A :class:`TrainingReport` including out-of-bag-free validation
            macro-F1 and the ten most important features.
        """
        started = time.perf_counter()
        self._check_columns(train.features)

        self.scaler = FeatureScaler.fit(train.features, self.feature_columns)
        x_train = self.scaler.transform(train.features)
        y_train = train.labels

        if len(np.unique(y_train)) < 2:
            raise ValueError(
                "Random Forest requires at least two classes in the training "
                f"split; found only {np.unique(y_train).tolist()}."
            )

        self.model = RandomForestClassifier(**self.params)
        self.model.fit(x_train, y_train)
        self._classes = self.model.classes_
        self.fitted = True

        train_f1 = float(
            f1_score(y_train, self.model.predict(x_train), average="macro",
                     zero_division=0)
        )
        val_f1 = float("nan")
        if val is not None and val.n_rows:
            val_f1 = float(
                f1_score(val.labels, self.predict(val), average="macro", zero_division=0)
            )

        importances = sorted(
            zip(self.feature_columns, self.model.feature_importances_.tolist()),
            key=lambda item: item[1],
            reverse=True,
        )
        _LOG.info(
            "Random Forest fitted: %d trees, train macro-F1=%.4f, val macro-F1=%.4f",
            self.params["n_estimators"], train_f1, val_f1,
        )
        return TrainingReport(
            detector=self.name,
            trained=True,
            epochs=1,
            best_epoch=1,
            duration_s=time.perf_counter() - started,
            extra={
                "params": {k: v for k, v in self.params.items()},
                "train_macro_f1": round(train_f1, 5),
                "val_macro_f1": None if np.isnan(val_f1) else round(val_f1, 5),
                "n_train_rows": int(len(y_train)),
                "class_counts": {
                    CLASS_NAMES[int(c)]: int(n)
                    for c, n in zip(*np.unique(y_train, return_counts=True))
                },
                "top_features": [
                    {"feature": name, "importance": round(value, 6)}
                    for name, value in importances[:10]
                ],
                "feature_importances": {
                    name: round(value, 8) for name, value in importances
                },
            },
        )

    # ------------------------------------------------------------------ #
    def predict_proba(self, data: DetectionInput) -> np.ndarray:
        """Return class probabilities aligned with ``data.features``.

        scikit-learn only emits columns for classes seen in training, so the
        output is expanded back to the full three-class layout - otherwise a
        corpus without SUSPICIOUS samples would silently shift the column
        meanings.
        """
        self._require_fitted()
        if self.model is None or self.scaler is None:  # pragma: no cover - defensive
            raise RuntimeError("Random Forest is marked fitted but has no model.")
        self._check_columns(data.features)

        raw = self.model.predict_proba(self.scaler.transform(data.features))
        full = np.zeros((raw.shape[0], len(CLASS_NAMES)), dtype=np.float64)
        classes = self._classes if self._classes is not None else self.model.classes_
        for column, class_index in enumerate(classes):
            full[:, int(class_index)] = raw[:, column]
        return full

    # ------------------------------------------------------------------ #
    def save(self, directory: str | Path) -> Path:
        """Persist the forest, the scaler and the manifest."""
        self._require_fitted()
        target = ensure_dir(directory)
        joblib.dump(self.model, target / "model.joblib")
        if self.scaler is not None:
            self.scaler.save(target / "scaler.json")
        (target / "params.json").write_text(
            json.dumps(
                {
                    "params": self.params,
                    "classes": [int(c) for c in np.atleast_1d(self._classes)]
                    if self._classes is not None else [],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        self.write_manifest(target, {"kind": "sklearn-random-forest",
                                     "trainable": True})
        _LOG.info("Random Forest saved -> %s", target)
        return target

    @classmethod
    def load(cls, directory: str | Path) -> "RandomForestDetector":
        """Restore a Random Forest detector from disk.

        Raises:
            FileNotFoundError: If any checkpoint component is missing.
        """
        source = resolve(directory)
        model_path = source / "model.joblib"
        if not model_path.exists():
            raise FileNotFoundError(f"No Random Forest checkpoint at {model_path}")

        payload = json.loads((source / "params.json").read_text(encoding="utf-8"))
        detector = cls()
        detector.params = payload["params"]
        detector.model = joblib.load(model_path)
        detector.scaler = FeatureScaler.load(source / "scaler.json")
        stored = payload.get("classes")
        detector._classes = (
            np.asarray(stored) if stored else np.asarray(detector.model.classes_)
        )
        manifest = cls.read_manifest(source)
        detector.feature_columns = list(manifest.get("feature_columns",
                                                     detector.feature_columns))
        detector.fitted = True
        return detector

    # ------------------------------------------------------------------ #
    def feature_importance_frame(self) -> pd.DataFrame:
        """Return feature importances as a sorted frame.

        Raises:
            RuntimeError: If the detector has not been fitted.
        """
        self._require_fitted()
        if self.model is None:  # pragma: no cover - defensive
            raise RuntimeError("Random Forest has no fitted model.")
        return (
            pd.DataFrame(
                {"feature": self.feature_columns,
                 "importance": self.model.feature_importances_}
            )
            .sort_values("importance", ascending=False)
            .reset_index(drop=True)
        )
