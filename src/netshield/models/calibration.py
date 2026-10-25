"""Calibrated and conformal decisions for the mitigation ladder.

The policy acts at fixed probabilities (rate-limit at 0.60, block at 0.85,
isolate at 0.95). Those numbers only mean something if the detector's
probabilities are calibrated, and even a calibrated probability says nothing
about how often an innocent device will be blocked. This module provides both:

Temperature scaling (Guo et al., 2017)
    One scalar ``T`` fitted on validation rows by minimising negative
    log-likelihood: ``p_cal ∝ p^(1/T)``. It never changes the argmax, so
    accuracy and macro-F1 are untouched; only confidence is corrected.

Split-conformal benign test (Vovk et al.; Angelopoulos & Bates, 2021)
    The hostile scores of BENIGN validation rows form a calibration set. For
    a new row with score ``s`` the conformal p-value is
    ``p = (1 + #{calibration scores >= s}) / (n + 1)``. Acting only when
    ``p <= alpha`` bounds the false-alarm rate on benign rows by ``alpha``,
    provided test benign rows are exchangeable with the calibration rows.
    Each rung of the ladder gets its own ``alpha``, which turns the policy
    into a statement of the form "an innocent device is blocked in at most
    1% of windows".

:class:`ConformalDetector` wraps any trained detector. Its hostile mass is
``1 - p_conformal``, so the unmodified policy engine can use it by setting
the rung probabilities to ``1 - alpha`` (0.95, 0.99, 0.999).

Caveat, stated in the report: exchangeability holds within a design whose
calibration and test runs come from the same scenario distribution. Under a
topology or attack-family shift it does not, and the measured false-alarm
rate is reported next to the nominal one precisely to show that.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
from scipy.optimize import minimize_scalar

from ..utils.paths import ensure_dir, resolve
from .base import DetectionInput, Detector, TrainingReport

#: Default per-rung false-alarm budgets: rate-limit, block, isolate.
LADDER_ALPHAS: tuple[float, float, float] = (0.05, 0.01, 0.001)


def apply_temperature(proba: np.ndarray, temperature: float) -> np.ndarray:
    """Return ``softmax(log p / T)`` row-wise."""
    logp = np.log(np.clip(np.asarray(proba, dtype=float), 1e-12, 1.0)) / float(temperature)
    logp -= logp.max(axis=1, keepdims=True)
    out = np.exp(logp)
    return out / out.sum(axis=1, keepdims=True)


def fit_temperature(proba: np.ndarray, labels: np.ndarray) -> float:
    """Fit the NLL-optimal temperature on validation rows (bounded to [0.05, 20])."""
    labels = np.asarray(labels, dtype=int)

    def nll(log_t: float) -> float:
        p = apply_temperature(proba, float(np.exp(log_t)))
        return float(-np.log(np.clip(p[np.arange(len(labels)), labels], 1e-12, 1)).mean())

    res = minimize_scalar(nll, bounds=(np.log(0.05), np.log(20.0)), method="bounded")
    return float(np.exp(res.x))


class ConformalCalibrator:
    """Split-conformal p-values for 'this row is benign'."""

    def __init__(self, scores: np.ndarray | None = None) -> None:
        self.scores = np.sort(np.asarray(scores if scores is not None else [], dtype=float))

    def fit(self, benign_scores: np.ndarray) -> "ConformalCalibrator":
        self.scores = np.sort(np.asarray(benign_scores, dtype=float))
        return self

    def p_values(self, scores: np.ndarray) -> np.ndarray:
        """Conformal p-value per score; small means 'unlike any benign row'."""
        n = len(self.scores)
        if n == 0:
            return np.ones(len(scores))
        at_least = n - np.searchsorted(self.scores, np.asarray(scores, dtype=float), side="left")
        return (1.0 + at_least) / (n + 1.0)

    def threshold(self, alpha: float) -> float:
        """Smallest score whose p-value is <= alpha (the rung's score cut)."""
        n = len(self.scores)
        k = int(np.ceil((1.0 - alpha) * (n + 1))) - 1
        return float(self.scores[min(max(k, 0), n - 1)]) if n else 1.0


class ConformalDetector(Detector):
    """Temperature-scaled, conformally calibrated wrapper around a trained detector.

    Args:
        base: A fitted detector.
        temperature: Temperature applied to the base probabilities.
        calibrator: Conformal calibrator over benign hostile scores.
    """

    name = "conformal"
    display_name = "Conformal wrapper"

    def __init__(self, base: Detector, temperature: float = 1.0,
                 calibrator: ConformalCalibrator | None = None) -> None:
        super().__init__()
        self.base = base
        self.uses_graph = base.uses_graph
        self.feature_columns = list(base.feature_columns)
        self.temperature = float(temperature)
        self.calibrator = calibrator or ConformalCalibrator()
        self.fitted = base.fitted
        self.name = f"{base.name}_conformal"

    @property
    def history_windows(self) -> int:
        return int(getattr(self.base, "history_windows", 1))

    @classmethod
    def from_validation(cls, base: Detector, val: DetectionInput) -> "ConformalDetector":
        """Fit temperature and conformal set on validation evidence."""
        proba = base.predict_proba(val)
        labels = val.labels
        temperature = fit_temperature(proba, labels)
        cal = apply_temperature(proba, temperature)
        benign = labels == 0
        calibrator = ConformalCalibrator().fit(cal[benign, 1] + cal[benign, 2])
        return cls(base, temperature, calibrator)

    def fit(self, train: DetectionInput, val: DetectionInput | None = None) -> TrainingReport:
        """Fit the base detector on *train*, then calibrate on *val*."""
        report = self.base.fit(train, val)
        if val is None or not val.n_rows:
            raise ValueError("Conformal calibration needs validation rows.")
        fitted = ConformalDetector.from_validation(self.base, val)
        self.temperature, self.calibrator, self.fitted = (fitted.temperature,
                                                          fitted.calibrator, True)
        report.extra = {**(report.extra or {}), "temperature": self.temperature,
                        "n_calibration": int(len(self.calibrator.scores))}
        return report

    def calibrated_proba(self, data: DetectionInput) -> np.ndarray:
        """Temperature-scaled base probabilities."""
        return apply_temperature(self.base.predict_proba(data), self.temperature)

    def predict_proba(self, data: DetectionInput) -> np.ndarray:
        """Hostile mass = ``1 - p_conformal``, split by the calibrated class ratio."""
        cal = self.calibrated_proba(data)
        hostile = cal[:, 1] + cal[:, 2]
        p_val = self.calibrator.p_values(hostile)
        mass = 1.0 - p_val
        share = np.divide(cal[:, 2], hostile, out=np.full(len(hostile), 0.5), where=hostile > 0)
        return np.stack([p_val, mass * (1.0 - share), mass * share], axis=1)

    def save(self, directory: str | Path) -> Path:
        target = ensure_dir(directory)
        self.base.save(target / "base")
        np.save(target / "calibration_scores.npy", self.calibrator.scores)
        (target / "conformal.json").write_text(json.dumps(
            {"base": self.base.name, "temperature": self.temperature,
             "n_calibration": int(len(self.calibrator.scores))}, indent=2), encoding="utf-8")
        self.write_manifest(target, {"kind": "conformal", "base": self.base.name})
        return target

    @classmethod
    def load(cls, directory: str | Path) -> "ConformalDetector":
        from ..detection.pipeline import DETECTOR_CLASSES  # noqa: PLC0415

        source = resolve(directory)
        meta = json.loads((source / "conformal.json").read_text(encoding="utf-8"))
        base = DETECTOR_CLASSES[meta["base"]].load(source / "base")
        cal = ConformalCalibrator(np.load(source / "calibration_scores.npy"))
        return cls(base, float(meta["temperature"]), cal)


def conformal_policy_overrides(alphas: tuple[float, float, float] = LADDER_ALPHAS
                               ) -> list[str]:
    """Config assignments that make the policy rungs mean per-rung FPR budgets."""
    a_rate, a_block, a_iso = alphas
    return [f"mitigation.policy.rate_limit_probability={1 - a_rate}",
            f"mitigation.policy.block_probability={1 - a_block}",
            f"mitigation.policy.isolate_probability={1 - a_iso}",
            f"detection.mitigation_trigger_probability={1 - a_rate}"]
