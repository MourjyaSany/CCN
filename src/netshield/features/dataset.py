"""Dataset assembly: many runs -> one labelled, split, normalised corpus.

Split policy
------------
Splits are made **by run, never by row**. Two windows from the same simulation
share device identities, RNG streams and attack parameters; putting one in train
and the other in test would leak. ``GroupShuffleSplit``-style grouping on
``run_id`` is therefore mandatory, and the held-out generalisation experiment
(``exp7_unseen``) is excluded from the corpus entirely - it is only ever scored,
never fitted.

Normalisation
-------------
Traffic features span many orders of magnitude (0.4 pps to 5 700 pps), so a
``log1p`` transform is applied to the heavy-tailed count/rate columns before
standardisation. Both the column list and the fitted statistics are persisted
with the model so inference reproduces training exactly.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

import numpy as np
import pandas as pd

from ..utils.logging_utils import get_logger
from ..utils.paths import ensure_parent, resolve
from ..utils.seeding import rng_for
from .node_features import (
    CLASS_NAMES,
    LABEL_COLUMNS,
    META_COLUMNS,
    NODE_FEATURE_COLUMNS,
    assert_no_leakage,
    build_node_window_features,
)

_LOG = get_logger(__name__)

#: Heavy-tailed columns that receive a ``log1p`` transform before scaling.
LOG_SCALE_COLUMNS: frozenset[str] = frozenset(
    {
        "eg_packets", "eg_bytes", "eg_packet_rate", "eg_byte_rate",
        "eg_flow_count", "eg_packets_per_flow", "eg_bytes_per_flow",
        "eg_packet_size_std", "eg_max_packet_size", "eg_min_packet_size",
        "eg_mean_packet_size", "eg_syn_count", "eg_syn_rate",
        "eg_syn_ack_count", "eg_ack_count", "eg_fin_count", "eg_rst_count",
        "eg_psh_count", "eg_connection_attempts", "eg_unique_dst_nodes",
        "eg_unique_dst_ports", "eg_unique_src_ports", "eg_unique_src_ips",
        "in_packets", "in_bytes", "in_packet_rate", "in_flow_count",
        "in_unique_src_nodes", "in_unique_src_ips", "degree",
    }
)


class DatasetError(ValueError):
    """Raised when a dataset cannot be assembled or is internally inconsistent."""


@dataclass(slots=True)
class FeatureScaler:
    """Log-then-standardise scaler persisted alongside every trained model.

    Attributes:
        columns: Feature column order the scaler was fitted on.
        log_columns: Subset receiving a ``log1p`` transform first.
        mean: Per-column mean after the log transform.
        std: Per-column standard deviation after the log transform.
    """

    columns: list[str]
    log_columns: list[str]
    mean: list[float] = field(default_factory=list)
    std: list[float] = field(default_factory=list)

    @classmethod
    def fit(cls, frame: pd.DataFrame, columns: Sequence[str] | None = None) -> "FeatureScaler":
        """Fit the scaler on a feature frame.

        Args:
            frame: Training rows only - never the validation or test split.
            columns: Feature order; defaults to :data:`NODE_FEATURE_COLUMNS`.

        Returns:
            The fitted scaler.
        """
        cols = list(columns or NODE_FEATURE_COLUMNS)
        assert_no_leakage(cols)
        log_cols = [c for c in cols if c in LOG_SCALE_COLUMNS]
        values = cls._pre_transform(frame[cols].to_numpy(dtype=np.float64), cols, log_cols)
        mean = values.mean(axis=0)
        std = values.std(axis=0)
        std[std < 1e-8] = 1.0  # constant columns pass through unchanged
        return cls(cols, log_cols, mean.tolist(), std.tolist())

    @staticmethod
    def _pre_transform(
        values: np.ndarray, columns: Sequence[str], log_columns: Sequence[str]
    ) -> np.ndarray:
        """Apply the ``log1p`` transform to the heavy-tailed columns."""
        out = np.array(values, dtype=np.float64, copy=True)
        index = {c: i for i, c in enumerate(columns)}
        for name in log_columns:
            i = index[name]
            out[:, i] = np.log1p(np.clip(out[:, i], 0.0, None))
        return out

    def transform(self, frame: pd.DataFrame) -> np.ndarray:
        """Transform a feature frame into a standardised float32 matrix.

        Args:
            frame: Any frame containing :attr:`columns`.

        Returns:
            A ``(n_rows, n_features)`` float32 array.

        Raises:
            DatasetError: If required columns are missing.
        """
        missing = [c for c in self.columns if c not in frame.columns]
        if missing:
            raise DatasetError(f"Cannot transform: missing feature columns {missing}")
        values = self._pre_transform(
            frame[self.columns].to_numpy(dtype=np.float64), self.columns, self.log_columns
        )
        scaled = (values - np.asarray(self.mean)) / np.asarray(self.std)
        return np.nan_to_num(scaled, nan=0.0, posinf=0.0, neginf=0.0).astype(np.float32)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view of the fitted scaler."""
        return {
            "columns": self.columns,
            "log_columns": self.log_columns,
            "mean": self.mean,
            "std": self.std,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FeatureScaler":
        """Rebuild a scaler from :meth:`to_dict` output."""
        return cls(
            columns=list(data["columns"]),
            log_columns=list(data["log_columns"]),
            mean=list(data["mean"]),
            std=list(data["std"]),
        )

    def save(self, path: str | Path) -> Path:
        """Write the scaler to *path* as JSON."""
        target = ensure_parent(path)
        target.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        return target

    @classmethod
    def load(cls, path: str | Path) -> "FeatureScaler":
        """Read a scaler previously written by :meth:`save`."""
        source = resolve(path)
        if not source.exists():
            raise FileNotFoundError(f"Scaler file not found: {source}")
        return cls.from_dict(json.loads(source.read_text(encoding="utf-8")))


@dataclass(slots=True)
class DatasetSplit:
    """Train / validation / test partition of a node-window corpus.

    Attributes:
        train: Training rows.
        val: Validation rows (early stopping, threshold selection).
        test: Test rows (reported metrics).
        groups: The ``run_id`` values assigned to each split.
    """

    train: pd.DataFrame
    val: pd.DataFrame
    test: pd.DataFrame
    groups: dict[str, list[str]]

    def summary(self) -> dict[str, Any]:
        """Return per-split row counts and class distributions."""
        def describe(frame: pd.DataFrame) -> dict[str, Any]:
            counts = frame["label"].value_counts().to_dict()
            return {
                "rows": int(len(frame)),
                "runs": int(frame["run_id"].nunique()) if len(frame) else 0,
                "classes": {CLASS_NAMES[int(k)]: int(v) for k, v in sorted(counts.items())},
            }

        return {
            "train": describe(self.train),
            "val": describe(self.val),
            "test": describe(self.test),
            "group_assignment": self.groups,
        }


def build_dataset(results: Iterable[Any], config: Any) -> pd.DataFrame:
    """Featurise a collection of simulation runs into one corpus.

    Args:
        results: Iterable of :class:`~netshield.simulation.runner.SimulationResult`.
        config: Configuration providing the label thresholds.

    Returns:
        The concatenated node-window feature frame.

    Raises:
        DatasetError: If no run produced any usable rows.
    """
    malicious = float(config.get("features.label_malicious_threshold", 0.55))
    suspicious = float(config.get("features.label_suspicious_threshold", 0.12))

    frames: list[pd.DataFrame] = []
    for result in results:
        try:
            frames.append(
                build_node_window_features(
                    result,
                    malicious_threshold=malicious,
                    suspicious_threshold=suspicious,
                )
            )
        except ValueError as exc:
            _LOG.warning("Skipping run '%s': %s", getattr(result, "run_id", "?"), exc)

    if not frames:
        raise DatasetError("No simulation run produced usable feature rows.")

    corpus = pd.concat(frames, ignore_index=True)
    _LOG.info(
        "Dataset assembled: %d rows from %d runs; classes %s",
        len(corpus),
        corpus["run_id"].nunique(),
        {CLASS_NAMES[int(k)]: int(v) for k, v in
         sorted(corpus["label"].value_counts().to_dict().items())},
    )
    return corpus


def split_by_run(
    corpus: pd.DataFrame,
    test_size: float = 0.25,
    val_size: float = 0.15,
    seed: int = 42,
) -> DatasetSplit:
    """Partition a corpus into train/val/test, grouping by ``run_id``.

    Runs are shuffled deterministically and allocated whole, so no simulation
    contributes rows to more than one split. Allocation is stratified by
    *experiment family* where possible, so each split sees benign, volumetric,
    protocol and application attacks.

    Args:
        corpus: The assembled feature frame.
        test_size: Fraction of runs reserved for testing.
        val_size: Fraction of runs reserved for validation.
        seed: Deterministic shuffling seed.

    Returns:
        The :class:`DatasetSplit`.

    Raises:
        DatasetError: If the corpus contains too few runs to split.
    """
    runs = sorted(corpus["run_id"].unique())
    if len(runs) < 3:
        raise DatasetError(
            f"Need at least 3 distinct runs to build a grouped split, got {len(runs)}."
        )

    experiment_of = (
        corpus.groupby("run_id")["experiment"].first().to_dict()
    )
    families: dict[str, list[str]] = {}
    for run in runs:
        families.setdefault(str(experiment_of.get(run, "unknown")), []).append(run)

    rng = rng_for(seed, "dataset_split")
    targets = {
        "train": max(0.0, 1.0 - test_size - val_size),
        "val": max(0.0, val_size),
        "test": max(0.0, test_size),
    }
    assigned: dict[str, list[str]] = {"train": [], "val": [], "test": []}

    # Greedy largest-deficit allocation. Iterating family by family spreads every
    # experiment across all three splits, while the deficit rule keeps the global
    # proportions close to the requested fractions even when families are tiny.
    total = 0
    for family in sorted(families):
        members = list(families[family])
        rng.shuffle(members)
        for run in members:
            total += 1
            choice = max(
                targets,
                key=lambda name: targets[name] * total - len(assigned[name]),
            )
            assigned[choice].append(run)

    train_runs = assigned["train"]
    val_runs = assigned["val"]
    test_runs = assigned["test"]

    # A split must never be empty, and training must never be starved.
    for name in ("test", "val"):
        if not assigned[name] and len(train_runs) > 2:
            moved = train_runs.pop()
            assigned[name].append(moved)
            _LOG.warning("Split '%s' was empty; moved run '%s' out of train.", name, moved)
    train_runs = assigned["train"]
    val_runs = assigned["val"]
    test_runs = assigned["test"]

    if not train_runs:
        raise DatasetError("Grouped split produced an empty training set.")
    if not val_runs:
        # Borrow one training run rather than validating on the test set.
        val_runs = [train_runs.pop()]
        _LOG.warning("Validation split was empty; borrowed run '%s' from train.", val_runs[0])

    split = DatasetSplit(
        train=corpus[corpus["run_id"].isin(train_runs)].reset_index(drop=True),
        val=corpus[corpus["run_id"].isin(val_runs)].reset_index(drop=True),
        test=corpus[corpus["run_id"].isin(test_runs)].reset_index(drop=True),
        groups={"train": sorted(train_runs), "val": sorted(val_runs), "test": sorted(test_runs)},
    )
    _LOG.info(
        "Split by run: train=%d rows/%d runs, val=%d/%d, test=%d/%d",
        len(split.train), len(train_runs),
        len(split.val), len(val_runs),
        len(split.test), len(test_runs),
    )
    return split


def class_weights(labels: np.ndarray, n_classes: int = 3) -> np.ndarray:
    """Compute inverse-frequency class weights for imbalanced training.

    Args:
        labels: Integer label vector.
        n_classes: Number of classes.

    Returns:
        A ``(n_classes,)`` float32 weight vector normalised to mean 1. Classes
        absent from *labels* receive weight 1.0.
    """
    counts = np.bincount(labels.astype(int), minlength=n_classes).astype(np.float64)
    weights = np.ones(n_classes, dtype=np.float64)
    present = counts > 0
    weights[present] = counts[present].sum() / (present.sum() * counts[present])
    weights /= weights.mean()
    return weights.astype(np.float32)


def save_dataset(corpus: pd.DataFrame, path: str | Path) -> Path:
    """Write a corpus to CSV, creating parent directories as needed."""
    target = ensure_parent(path)
    corpus.to_csv(target, index=False)
    _LOG.info("Dataset written: %s (%d rows, %d columns)", target, len(corpus), corpus.shape[1])
    return target


def load_dataset(path: str | Path) -> pd.DataFrame:
    """Read a corpus previously written by :func:`save_dataset`.

    Args:
        path: CSV path.

    Returns:
        The loaded frame.

    Raises:
        FileNotFoundError: If the dataset does not exist.
        DatasetError: If required columns are absent.
    """
    source = resolve(path)
    if not source.exists():
        raise FileNotFoundError(
            f"Dataset not found: {source}. Run 'python scripts/generate_dataset.py' first."
        )
    frame = pd.read_csv(source)
    required = [*META_COLUMNS, *NODE_FEATURE_COLUMNS, *LABEL_COLUMNS]
    missing = [c for c in required if c not in frame.columns]
    if missing:
        raise DatasetError(f"Dataset at {source} is missing columns: {missing[:10]}")
    return frame


def dataset_report(corpus: pd.DataFrame) -> dict[str, Any]:
    """Return a JSON-serialisable description of a corpus.

    Args:
        corpus: The assembled feature frame.

    Returns:
        Row/run/class counts plus per-experiment breakdown.
    """
    per_experiment = (
        corpus.groupby("experiment")
        .agg(rows=("label", "size"), runs=("run_id", "nunique"))
        .to_dict("index")
    )
    for experiment, group in corpus.groupby("experiment"):
        counts = group["label"].value_counts().to_dict()
        per_experiment[experiment]["classes"] = {
            CLASS_NAMES[int(k)]: int(v) for k, v in sorted(counts.items())
        }
    counts = corpus["label"].value_counts().to_dict()
    return {
        "rows": int(len(corpus)),
        "runs": int(corpus["run_id"].nunique()),
        "experiments": int(corpus["experiment"].nunique()),
        "n_features": len(NODE_FEATURE_COLUMNS),
        "classes": {CLASS_NAMES[int(k)]: int(v) for k, v in sorted(counts.items())},
        "engines": corpus["engine"].value_counts().to_dict() if "engine" in corpus else {},
        "per_experiment": per_experiment,
    }
