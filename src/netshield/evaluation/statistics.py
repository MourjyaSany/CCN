"""Statistical protocol: extended metrics, run-level CIs and significance tests.

Why run-level resampling
------------------------
Node-windows from the same simulation run are strongly correlated: they share
a seed, a botnet and a congestion episode. Bootstrapping over *windows* would
treat 3,000 correlated rows as 3,000 independent observations and produce
confidence intervals that are far too narrow. Every interval here therefore
resamples whole **runs** (a cluster bootstrap), which is the unit that was
actually randomised.

Contents
--------
* :func:`extended_metrics` - MCC, per-class PR-AUC, detection rate at fixed
  false-alarm rates, expected calibration error and Brier score.
* :func:`cluster_bootstrap_ci` - percentile CI for any metric, resampling runs.
* :func:`paired_bootstrap_diff` - CI and p-value for a metric *difference*
  between two detectors scored on the same rows.
* :func:`mcnemar_test` - exact/continuity-corrected McNemar on paired errors.
* :func:`wilcoxon_signed_rank` - paired test across seeds or scenarios.
* :func:`holm_correction` - family-wise error control for many comparisons.
"""

from __future__ import annotations

import math
from typing import Any, Callable, Mapping, Sequence

import numpy as np
from scipy import stats as sstats
from sklearn.metrics import (
    average_precision_score,
    f1_score,
    matthews_corrcoef,
    roc_auc_score,
    roc_curve,
)

from ..features.node_features import CLASS_NAMES

N_CLASSES = len(CLASS_NAMES)

#: False-alarm rates at which detection rate is reported.
FPR_TARGETS: tuple[float, ...] = (0.001, 0.01, 0.05)


# --------------------------------------------------------------------------- #
# point metrics
# --------------------------------------------------------------------------- #
def hostile_score(proba: np.ndarray) -> np.ndarray:
    """``P(SUSPICIOUS) + P(MALICIOUS)`` - the binary 'is this hostile' score."""
    proba = np.asarray(proba, dtype=float)
    return proba[:, 1] + proba[:, 2]


def tpr_at_fpr(y_binary: np.ndarray, scores: np.ndarray, target: float) -> float:
    """Highest detection rate achievable with false-positive rate <= *target*.

    Returns ``nan`` when the rows contain only one class.
    """
    y_binary = np.asarray(y_binary, dtype=int)
    if y_binary.min() == y_binary.max():
        return float("nan")
    fpr, tpr, _ = roc_curve(y_binary, scores)
    ok = fpr <= target + 1e-12
    return float(tpr[ok].max()) if ok.any() else 0.0


def expected_calibration_error(
    y_true: np.ndarray, proba: np.ndarray, n_bins: int = 15
) -> float:
    """Top-label expected calibration error (Guo et al., 2017).

    Rows are binned by their maximum predicted probability; ECE is the
    row-weighted mean gap between confidence and accuracy across bins.
    """
    proba = np.asarray(proba, dtype=float)
    conf = proba.max(axis=1)
    correct = (proba.argmax(axis=1) == np.asarray(y_true)).astype(float)
    edges = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    for lo, hi in zip(edges[:-1], edges[1:]):
        mask = (conf > lo) & (conf <= hi)
        if mask.any():
            ece += mask.mean() * abs(correct[mask].mean() - conf[mask].mean())
    return float(ece)


def binary_ece(y_binary: np.ndarray, scores: np.ndarray, n_bins: int = 15) -> float:
    """Calibration error of the hostile score - the number the policy thresholds."""
    y_binary = np.asarray(y_binary, dtype=float)
    scores = np.clip(np.asarray(scores, dtype=float), 0.0, 1.0)
    edges = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    for i, (lo, hi) in enumerate(zip(edges[:-1], edges[1:])):
        mask = (scores >= lo) & ((scores < hi) if i < n_bins - 1 else (scores <= hi))
        if mask.any():
            ece += mask.mean() * abs(y_binary[mask].mean() - scores[mask].mean())
    return float(ece)


def multiclass_brier(y_true: np.ndarray, proba: np.ndarray) -> float:
    """Mean squared error between the probability vector and the one-hot label."""
    proba = np.asarray(proba, dtype=float)
    onehot = np.eye(proba.shape[1])[np.asarray(y_true, dtype=int)]
    return float(((proba - onehot) ** 2).sum(axis=1).mean())


def extended_metrics(y_true: np.ndarray, proba: np.ndarray) -> dict[str, Any]:
    """Compute the research metric bundle for one detector on one split.

    Args:
        y_true: Integer labels (0 BENIGN, 1 SUSPICIOUS, 2 MALICIOUS).
        proba: ``(n, 3)`` class probabilities.

    Returns:
        A flat mapping of metric name to value. Undefined metrics are ``nan``.
    """
    y_true = np.asarray(y_true, dtype=int)
    proba = np.asarray(proba, dtype=float)
    pred = proba.argmax(axis=1)
    y_bin = (y_true > 0).astype(int)
    score = hostile_score(proba)
    out: dict[str, Any] = {
        "n": int(len(y_true)),
        "accuracy": float((pred == y_true).mean()),
        "macro_f1": float(f1_score(y_true, pred, labels=list(range(N_CLASSES)),
                                   average="macro", zero_division=0)),
        "mcc": float(matthews_corrcoef(y_true, pred)) if len(np.unique(y_true)) > 1
        else float("nan"),
        "ece": expected_calibration_error(y_true, proba),
        "hostile_ece": binary_ece(y_bin, score),
        "brier": multiclass_brier(y_true, proba),
    }
    for k, name in enumerate(CLASS_NAMES):
        y_k = (y_true == k).astype(int)
        out[f"f1_{name.lower()}"] = float(f1_score(y_true == k, pred == k, zero_division=0))
        out[f"pr_auc_{name.lower()}"] = (
            float(average_precision_score(y_k, proba[:, k])) if 0 < y_k.sum() < len(y_k)
            else float("nan"))
    has_both = 0 < y_bin.sum() < len(y_bin)
    out["hostile_roc_auc"] = float(roc_auc_score(y_bin, score)) if has_both else float("nan")
    out["hostile_pr_auc"] = (float(average_precision_score(y_bin, score)) if has_both
                             else float("nan"))
    hostile_pred = pred > 0
    negatives = max(1, int((y_bin == 0).sum()))
    out["false_positive_rate"] = float((hostile_pred & (y_bin == 0)).sum() / negatives)
    out["attack_recall"] = (float((hostile_pred & (y_bin == 1)).sum() / y_bin.sum())
                            if y_bin.sum() else float("nan"))
    for target in FPR_TARGETS:
        out[f"tpr_at_fpr_{target:g}"] = tpr_at_fpr(y_bin, score, target)
    return out


# --------------------------------------------------------------------------- #
# cluster bootstrap
# --------------------------------------------------------------------------- #
def _cluster_index(groups: np.ndarray) -> tuple[np.ndarray, list[np.ndarray]]:
    uniq, inverse = np.unique(np.asarray(groups).astype(str), return_inverse=True)
    members = [np.nonzero(inverse == g)[0] for g in range(len(uniq))]
    return uniq, members


def cluster_bootstrap_ci(
    metric: Callable[[np.ndarray], float],
    groups: np.ndarray,
    n_resamples: int = 2000,
    level: float = 0.95,
    seed: int = 0,
) -> dict[str, float]:
    """Percentile confidence interval for ``metric(row_index)``, resampling groups.

    Args:
        metric: Function of a row-index array returning a scalar.
        groups: Cluster id per row (normally ``run_id``).
        n_resamples: Bootstrap replicates.
        level: Two-sided coverage.
        seed: RNG seed.

    Returns:
        ``{"point", "lo", "hi", "se", "n_clusters"}``.
    """
    _, members = _cluster_index(groups)
    rng = np.random.default_rng(seed)
    all_rows = np.concatenate(members) if members else np.zeros(0, dtype=int)
    point = float(metric(all_rows))
    reps = []
    for _ in range(int(n_resamples)):
        pick = rng.integers(0, len(members), len(members))
        rows = np.concatenate([members[i] for i in pick])
        value = metric(rows)
        if value is not None and not math.isnan(value):
            reps.append(value)
    if not reps:
        return {"point": point, "lo": float("nan"), "hi": float("nan"),
                "se": float("nan"), "n_clusters": len(members)}
    alpha = (1.0 - level) / 2.0
    arr = np.asarray(reps)
    return {"point": point, "lo": float(np.quantile(arr, alpha)),
            "hi": float(np.quantile(arr, 1.0 - alpha)), "se": float(arr.std(ddof=1)),
            "n_clusters": len(members)}


def paired_bootstrap_diff(
    metric_a: Callable[[np.ndarray], float],
    metric_b: Callable[[np.ndarray], float],
    groups: np.ndarray,
    n_resamples: int = 2000,
    level: float = 0.95,
    seed: int = 0,
) -> dict[str, float]:
    """CI and two-sided bootstrap p-value for ``metric_a - metric_b``.

    Both metrics are evaluated on the *same* resampled runs, so the
    comparison is paired and the shared run-to-run variance cancels.
    """
    _, members = _cluster_index(groups)
    rng = np.random.default_rng(seed)
    rows_all = np.concatenate(members)
    point = float(metric_a(rows_all) - metric_b(rows_all))
    diffs = []
    for _ in range(int(n_resamples)):
        pick = rng.integers(0, len(members), len(members))
        rows = np.concatenate([members[i] for i in pick])
        d = metric_a(rows) - metric_b(rows)
        if not math.isnan(d):
            diffs.append(d)
    arr = np.asarray(diffs)
    alpha = (1.0 - level) / 2.0
    # Two-sided p: how often the resampled difference falls on the other side of 0.
    p = 2.0 * min((arr <= 0).mean(), (arr >= 0).mean()) if len(arr) else float("nan")
    return {"diff": point, "lo": float(np.quantile(arr, alpha)) if len(arr) else float("nan"),
            "hi": float(np.quantile(arr, 1 - alpha)) if len(arr) else float("nan"),
            "p_value": float(min(1.0, p))}


# --------------------------------------------------------------------------- #
# hypothesis tests
# --------------------------------------------------------------------------- #
def mcnemar_test(y_true: np.ndarray, pred_a: np.ndarray, pred_b: np.ndarray) -> dict[str, Any]:
    """McNemar's test on the rows where exactly one detector is correct.

    Uses the exact binomial test when the discordant count is below 25 and the
    continuity-corrected chi-square otherwise.

    Caveat: McNemar assumes independent rows. Node-windows within a run are
    not independent, so treat this as a descriptive check and rely on the
    run-level :func:`paired_bootstrap_diff` for inference.
    """
    y_true = np.asarray(y_true)
    a_ok = np.asarray(pred_a) == y_true
    b_ok = np.asarray(pred_b) == y_true
    b = int((a_ok & ~b_ok).sum())   # A right, B wrong
    c = int((~a_ok & b_ok).sum())   # A wrong, B right
    n = b + c
    if n == 0:
        return {"a_only_correct": b, "b_only_correct": c, "statistic": 0.0,
                "p_value": 1.0, "method": "none"}
    if n < 25:
        p = float(sstats.binomtest(b, n, 0.5).pvalue)
        return {"a_only_correct": b, "b_only_correct": c, "statistic": float(b),
                "p_value": p, "method": "exact-binomial"}
    stat = (abs(b - c) - 1.0) ** 2 / n
    return {"a_only_correct": b, "b_only_correct": c, "statistic": float(stat),
            "p_value": float(sstats.chi2.sf(stat, 1)), "method": "chi2-cc"}


def wilcoxon_signed_rank(a: Sequence[float], b: Sequence[float]) -> dict[str, Any]:
    """Paired Wilcoxon signed-rank test of ``a`` vs ``b`` (e.g. per-seed scores)."""
    a = np.asarray(a, dtype=float)
    b = np.asarray(b, dtype=float)
    mask = ~(np.isnan(a) | np.isnan(b))
    a, b = a[mask], b[mask]
    if len(a) < 2 or np.allclose(a, b):
        return {"n": int(len(a)), "statistic": float("nan"), "p_value": 1.0,
                "median_diff": float(np.median(a - b)) if len(a) else float("nan")}
    res = sstats.wilcoxon(a, b, zero_method="zsplit")
    return {"n": int(len(a)), "statistic": float(res.statistic),
            "p_value": float(res.pvalue), "median_diff": float(np.median(a - b))}


def holm_correction(p_values: Mapping[str, float], alpha: float = 0.05) -> dict[str, dict]:
    """Holm-Bonferroni step-down adjustment.

    Returns, per hypothesis, the adjusted p-value and whether it is rejected
    at family-wise level *alpha*.
    """
    items = sorted(((k, float(v)) for k, v in p_values.items() if not math.isnan(v)),
                   key=lambda kv: kv[1])
    m = len(items)
    out: dict[str, dict] = {}
    running = 0.0
    still_rejecting = True
    for i, (key, p) in enumerate(items):
        adjusted = min(1.0, max(running, (m - i) * p))
        running = adjusted
        reject = still_rejecting and adjusted <= alpha
        if not reject:
            still_rejecting = False
        out[key] = {"p_value": p, "p_holm": adjusted, "reject": bool(reject)}
    for key, v in p_values.items():
        if key not in out:
            out[key] = {"p_value": float(v), "p_holm": float("nan"), "reject": False}
    return out


def fast_macro_f1(y_true: np.ndarray, y_pred: np.ndarray, k: int = N_CLASSES) -> float:
    """Macro-F1 from a bincount confusion matrix (identical to scikit-learn's
    ``average="macro", zero_division=0`` over a fixed label set, ~50x faster)."""
    cm = np.bincount(np.asarray(y_true) * k + np.asarray(y_pred), minlength=k * k).reshape(k, k)
    tp = np.diag(cm).astype(float)
    denom = cm.sum(0) + cm.sum(1)
    f1 = np.divide(2 * tp, denom, out=np.zeros(k), where=denom > 0)
    return float(f1.mean())


# --------------------------------------------------------------------------- #
# convenience: metric closures over row subsets
# --------------------------------------------------------------------------- #
def metric_fn(name: str, y_true: np.ndarray, proba: np.ndarray) -> Callable[[np.ndarray], float]:
    """Return ``f(rows) -> metric`` for use with the bootstrap helpers."""
    y_true = np.asarray(y_true, dtype=int)
    proba = np.asarray(proba, dtype=float)
    pred = proba.argmax(axis=1)

    def f(rows: np.ndarray) -> float:
        if len(rows) == 0:
            return float("nan")
        yt, pr = y_true[rows], proba[rows]
        if name == "macro_f1":
            return fast_macro_f1(yt, pred[rows])
        if name == "mcc":
            return float(matthews_corrcoef(yt, pr.argmax(1))) if len(np.unique(yt)) > 1 \
                else float("nan")
        if name == "hostile_pr_auc":
            yb = (yt > 0).astype(int)
            return float(average_precision_score(yb, hostile_score(pr))) \
                if 0 < yb.sum() < len(yb) else float("nan")
        if name == "false_positive_rate":
            neg = yt == 0
            return float((pr[neg].argmax(1) > 0).mean()) if neg.any() else float("nan")
        if name == "attack_recall":
            pos = yt > 0
            return float((pr[pos].argmax(1) > 0).mean()) if pos.any() else float("nan")
        if name.startswith("tpr_at_fpr_"):
            return tpr_at_fpr((yt > 0).astype(int), hostile_score(pr),
                              float(name.rsplit("_", 1)[1]))
        if name == "hostile_ece":
            return binary_ece((yt > 0).astype(int), hostile_score(pr))
        raise KeyError(f"Unknown bootstrap metric {name!r}")

    return f
