"""Detection metrics, including the network-specific ones.

Beyond the usual classification scores this module computes the two numbers a
network operator actually cares about:

**False-positive rate.** On a 24-device fleet producing ~250 node-windows per
minute, a 1% FPR is an alert every 25 seconds. FPR is therefore reported
explicitly rather than hidden inside "accuracy".

**Detection latency.** Measured in *simulated seconds* between the moment the
attack starts and the end of the first feature window in which the detector
raises the attacking node above the mitigation trigger probability. Because
detection can only happen on window boundaries, the floor is one window length
(5 s by default) - a real, reportable property of the design, not an artefact.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    matthews_corrcoef,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)

from ..features.node_features import CLASS_NAMES
from ..utils.logging_utils import get_logger

_LOG = get_logger(__name__)

#: Rows whose true label is SUSPICIOUS or MALICIOUS count as "hostile" for the
#: binary operational view.
HOSTILE_CLASSES: tuple[int, ...] = (1, 2)


@dataclass(slots=True)
class DetectionMetrics:
    """Complete metric bundle for one detector on one evaluation split.

    Attributes:
        detector: Detector name.
        split: Split label, e.g. ``"test"`` or an experiment name.
        n_samples: Number of scored rows.
        accuracy: Overall multi-class accuracy.
        balanced_accuracy: Mean per-class recall.
        macro_precision: Unweighted mean precision.
        macro_recall: Unweighted mean recall.
        macro_f1: Unweighted mean F1.
        weighted_f1: Support-weighted F1.
        mcc: Matthews correlation coefficient.
        per_class: Per-class precision/recall/F1/support.
        confusion: 3x3 confusion matrix as nested lists.
        binary: Binary (benign vs hostile) operational metrics.
        roc: ROC curve points for the binary view.
        pr: Precision-recall curve points for the binary view.
        extra: Anything else worth recording.
    """

    detector: str
    split: str
    n_samples: int
    accuracy: float
    balanced_accuracy: float
    macro_precision: float
    macro_recall: float
    macro_f1: float
    weighted_f1: float
    mcc: float
    per_class: dict[str, dict[str, float]]
    confusion: list[list[int]]
    binary: dict[str, float]
    roc: dict[str, list[float]] = field(default_factory=dict)
    pr: dict[str, list[float]] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view."""
        return {
            "detector": self.detector,
            "split": self.split,
            "n_samples": self.n_samples,
            "accuracy": self.accuracy,
            "balanced_accuracy": self.balanced_accuracy,
            "macro_precision": self.macro_precision,
            "macro_recall": self.macro_recall,
            "macro_f1": self.macro_f1,
            "weighted_f1": self.weighted_f1,
            "mcc": self.mcc,
            "per_class": self.per_class,
            "confusion_matrix": self.confusion,
            "classes": list(CLASS_NAMES),
            "binary": self.binary,
            "roc": self.roc,
            "pr": self.pr,
            "extra": self.extra,
        }

    def headline(self) -> dict[str, Any]:
        """Return the compact row used in comparison tables."""
        return {
            "detector": self.detector,
            "split": self.split,
            "n_samples": self.n_samples,
            "accuracy": round(self.accuracy, 4),
            "macro_f1": round(self.macro_f1, 4),
            "macro_precision": round(self.macro_precision, 4),
            "macro_recall": round(self.macro_recall, 4),
            "attack_precision": round(self.binary.get("precision", 0.0), 4),
            "attack_recall": round(self.binary.get("recall", 0.0), 4),
            "attack_f1": round(self.binary.get("f1", 0.0), 4),
            "fpr": round(self.binary.get("false_positive_rate", 0.0), 5),
            "roc_auc": round(self.binary.get("roc_auc", float("nan")), 4),
            "pr_auc": round(self.binary.get("pr_auc", float("nan")), 4),
        }


def _safe_roc_auc(y_true: np.ndarray, scores: np.ndarray) -> float:
    """ROC AUC that returns NaN instead of raising on a single-class split."""
    if len(np.unique(y_true)) < 2:
        return float("nan")
    return float(roc_auc_score(y_true, scores))


def compute_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    attack_scores: np.ndarray | None = None,
    detector: str = "detector",
    split: str = "test",
    curve_points: int = 200,
    extra: Mapping[str, Any] | None = None,
) -> DetectionMetrics:
    """Compute the full metric bundle.

    Args:
        y_true: Integer ground-truth labels.
        y_pred: Integer predictions.
        attack_scores: ``P(hostile)`` per row, used for ROC/PR. Derived from the
            hard predictions when omitted (which makes the curves coarse but
            still honest).
        detector: Detector name for labelling.
        split: Split label.
        curve_points: Maximum number of points retained per curve.
        extra: Extra diagnostics to attach.

    Returns:
        The populated :class:`DetectionMetrics`.

    Raises:
        ValueError: If the label and prediction arrays differ in length.
    """
    y_true = np.asarray(y_true, dtype=int)
    y_pred = np.asarray(y_pred, dtype=int)
    if y_true.shape != y_pred.shape:
        raise ValueError(
            f"y_true and y_pred must be the same length, got {y_true.shape} "
            f"and {y_pred.shape}."
        )
    if y_true.size == 0:
        raise ValueError("Cannot compute metrics on an empty split.")

    labels = list(range(len(CLASS_NAMES)))
    matrix = confusion_matrix(y_true, y_pred, labels=labels)

    precision = precision_score(y_true, y_pred, labels=labels, average=None,
                                zero_division=0)
    recall = recall_score(y_true, y_pred, labels=labels, average=None, zero_division=0)
    f1 = f1_score(y_true, y_pred, labels=labels, average=None, zero_division=0)
    support = np.bincount(y_true, minlength=len(CLASS_NAMES))

    per_class = {
        CLASS_NAMES[i]: {
            "precision": round(float(precision[i]), 5),
            "recall": round(float(recall[i]), 5),
            "f1": round(float(f1[i]), 5),
            "support": int(support[i]),
        }
        for i in labels
    }

    # ---- binary (operational) view ----------------------------------------
    true_hostile = np.isin(y_true, HOSTILE_CLASSES).astype(int)
    pred_hostile = np.isin(y_pred, HOSTILE_CLASSES).astype(int)
    scores = (
        np.asarray(attack_scores, dtype=float)
        if attack_scores is not None
        else pred_hostile.astype(float)
    )

    tp = int(((true_hostile == 1) & (pred_hostile == 1)).sum())
    fp = int(((true_hostile == 0) & (pred_hostile == 1)).sum())
    fn = int(((true_hostile == 1) & (pred_hostile == 0)).sum())
    tn = int(((true_hostile == 0) & (pred_hostile == 0)).sum())

    binary = {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "precision": round(tp / (tp + fp), 5) if (tp + fp) else 0.0,
        "recall": round(tp / (tp + fn), 5) if (tp + fn) else 0.0,
        "false_positive_rate": round(fp / (fp + tn), 6) if (fp + tn) else 0.0,
        "false_negative_rate": round(fn / (fn + tp), 6) if (fn + tp) else 0.0,
        "specificity": round(tn / (tn + fp), 5) if (tn + fp) else 0.0,
        "roc_auc": _safe_roc_auc(true_hostile, scores),
        "pr_auc": (
            round(float(average_precision_score(true_hostile, scores)), 5)
            if len(np.unique(true_hostile)) > 1 else float("nan")
        ),
    }
    denominator = 2 * tp + fp + fn
    binary["f1"] = round(2 * tp / denominator, 5) if denominator else 0.0

    roc_points: dict[str, list[float]] = {}
    pr_points: dict[str, list[float]] = {}
    if len(np.unique(true_hostile)) > 1:
        fpr, tpr, _ = roc_curve(true_hostile, scores)
        prec_curve, rec_curve, _ = precision_recall_curve(true_hostile, scores)
        roc_points = {
            "fpr": _thin(fpr, curve_points),
            "tpr": _thin(tpr, curve_points),
        }
        pr_points = {
            "precision": _thin(prec_curve, curve_points),
            "recall": _thin(rec_curve, curve_points),
        }

    return DetectionMetrics(
        detector=detector,
        split=split,
        n_samples=int(y_true.size),
        accuracy=round(float(accuracy_score(y_true, y_pred)), 5),
        balanced_accuracy=round(float(balanced_accuracy_score(y_true, y_pred)), 5),
        macro_precision=round(
            float(precision_score(y_true, y_pred, average="macro", zero_division=0)), 5),
        macro_recall=round(
            float(recall_score(y_true, y_pred, average="macro", zero_division=0)), 5),
        macro_f1=round(float(f1_score(y_true, y_pred, average="macro", zero_division=0)), 5),
        weighted_f1=round(
            float(f1_score(y_true, y_pred, average="weighted", zero_division=0)), 5),
        mcc=round(float(matthews_corrcoef(y_true, y_pred)), 5)
        if len(np.unique(y_true)) > 1 else 0.0,
        per_class=per_class,
        confusion=matrix.tolist(),
        binary=binary,
        roc=roc_points,
        pr=pr_points,
        extra=dict(extra or {}),
    )


def _thin(values: np.ndarray, limit: int) -> list[float]:
    """Sub-sample a curve to at most *limit* points, keeping the endpoints."""
    array = np.asarray(values, dtype=float)
    if array.size <= limit:
        return [round(float(v), 6) for v in array]
    idx = np.unique(np.linspace(0, array.size - 1, limit).astype(int))
    return [round(float(array[i]), 6) for i in idx]


def detection_latency(
    frame: pd.DataFrame,
    attack_scores: np.ndarray,
    trigger: float = 0.8,
    window_s: float = 5.0,
) -> dict[str, Any]:
    """Measure how long each attack ran before the detector flagged it.

    For every run containing attackers, the first feature window in which any
    ground-truth attacker node is scored at or above *trigger* is located. The
    latency is the time from the attack's start to the **end** of that window,
    because a windowed detector cannot decide before the window closes.

    Args:
        frame: Feature rows including ``run_id``, ``t_start``, ``t_end``,
            ``is_attacker`` and ``attack_duty``.
        attack_scores: ``P(hostile)`` per row, aligned with *frame*.
        trigger: Probability at or above which a node counts as detected.
        window_s: Feature window length in seconds.

    Returns:
        A mapping with ``per_run`` details plus aggregate statistics. Runs whose
        attack is never detected are reported as ``detected: false`` and are
        excluded from the mean, with their count surfaced as ``n_missed``.
    """
    work = frame.copy()
    work["_score"] = np.asarray(attack_scores, dtype=float)

    per_run: list[dict[str, Any]] = []
    for run_id, group in work.groupby("run_id", sort=True):
        attacking = group[(group["is_attacker"]) & (group["attack_duty"] > 0.0)]
        if attacking.empty:
            continue
        attack_start = float(attacking["t_start"].min())
        detected = attacking[attacking["_score"] >= trigger]
        if detected.empty:
            per_run.append({
                "run_id": str(run_id),
                "experiment": str(group["experiment"].iloc[0]),
                "attack_start_s": attack_start,
                "detected": False,
                "latency_s": None,
            })
            continue
        first_end = float(detected["t_end"].min())
        per_run.append({
            "run_id": str(run_id),
            "experiment": str(group["experiment"].iloc[0]),
            "attack_start_s": attack_start,
            "first_detection_s": first_end,
            "detected": True,
            "latency_s": round(max(0.0, first_end - attack_start), 4),
        })

    latencies = [r["latency_s"] for r in per_run if r["detected"]]
    return {
        "trigger_probability": trigger,
        "window_s": window_s,
        "n_runs_with_attack": len(per_run),
        "n_detected": len(latencies),
        "n_missed": len(per_run) - len(latencies),
        "mean_latency_s": round(float(np.mean(latencies)), 4) if latencies else None,
        "median_latency_s": round(float(np.median(latencies)), 4) if latencies else None,
        "min_latency_s": round(float(np.min(latencies)), 4) if latencies else None,
        "max_latency_s": round(float(np.max(latencies)), 4) if latencies else None,
        "per_run": per_run,
    }


def per_experiment_metrics(
    frame: pd.DataFrame,
    y_pred: np.ndarray,
    attack_scores: np.ndarray,
    detector: str,
) -> list[dict[str, Any]]:
    """Compute headline metrics separately for each experiment.

    Args:
        frame: Feature rows with ``experiment`` and ``label`` columns.
        y_pred: Predictions aligned with *frame*.
        attack_scores: ``P(hostile)`` aligned with *frame*.
        detector: Detector name.

    Returns:
        One headline dict per experiment, sorted by experiment name.
    """
    rows: list[dict[str, Any]] = []
    y_pred = np.asarray(y_pred)
    attack_scores = np.asarray(attack_scores)
    for experiment, group in frame.groupby("experiment", sort=True):
        mask = frame["experiment"].to_numpy() == experiment
        try:
            metrics = compute_metrics(
                group["label"].to_numpy(dtype=int),
                y_pred[mask],
                attack_scores[mask],
                detector=detector,
                split=str(experiment),
            )
        except ValueError:  # pragma: no cover - empty group
            continue
        rows.append(metrics.headline())
    return rows


def comparison_table(bundles: Sequence[DetectionMetrics]) -> pd.DataFrame:
    """Build the detector comparison table used in the report.

    Args:
        bundles: Metric bundles, one per detector.

    Returns:
        A frame sorted by macro-F1 descending.
    """
    if not bundles:
        return pd.DataFrame()
    frame = pd.DataFrame([b.headline() for b in bundles])
    return frame.sort_values("macro_f1", ascending=False).reset_index(drop=True)


def subset_metrics(
    frame: pd.DataFrame,
    y_pred: np.ndarray,
    attack_scores: np.ndarray,
    mask: np.ndarray,
    detector: str,
    split: str,
) -> DetectionMetrics | None:
    """Compute metrics restricted to a boolean row mask.

    Used to report endpoint-only metrics alongside all-node metrics, since
    infrastructure nodes are trivially benign and would otherwise inflate
    accuracy.

    Args:
        frame: The full feature frame.
        y_pred: Predictions aligned with *frame*.
        attack_scores: Hostile probabilities aligned with *frame*.
        mask: Boolean selector.
        detector: Detector name.
        split: Split label.

    Returns:
        The metric bundle, or ``None`` when the mask selects nothing.
    """
    mask = np.asarray(mask, dtype=bool)
    if not mask.any():
        return None
    return compute_metrics(
        frame.loc[mask, "label"].to_numpy(dtype=int),
        np.asarray(y_pred)[mask],
        np.asarray(attack_scores)[mask],
        detector=detector,
        split=split,
    )
