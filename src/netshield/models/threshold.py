"""Rule-based threshold detector (Baseline A).

This is the control condition: the static, hand-tuned rule set that most
production IoT gateways still ship with. It fires when any single per-node
counter crosses a configured limit:

.. math::

   s(v) = \\max\\Big(
       \\frac{r_{pkt}(v)}{\\tau_{pkt}},\\;
       \\frac{r_{byte}(v)}{\\tau_{byte}},\\;
       \\frac{|D_{port}(v)|}{\\tau_{port}},\\;
       \\frac{\\rho_{SYN}(v)}{\\tau_{SYN}}
   \\Big)

with :math:`s \\ge 1` giving MALICIOUS and :math:`s \\ge \\alpha` (default
``\\alpha = 0.45``) giving SUSPICIOUS.

Two design decisions matter for a fair comparison:

1. **It is applied only to endpoints.** Scoring the gateway - which legitimately
   forwards the sum of every device's traffic - would trivially and unfairly
   flag it. Excluding infrastructure is what a real deployment does.
2. **Thresholds may be auto-calibrated** from benign training data (see
   :meth:`ThresholdDetector.fit`), so the baseline is tuned rather than
   strawmanned. The calibration puts each threshold at a high percentile of the
   benign distribution, which is exactly how an operator would set it.

Its expected failure mode is the distributed low-and-slow attack, where every
individual bot stays below every threshold.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Mapping

import numpy as np
import pandas as pd

from ..utils.logging_utils import get_logger
from ..utils.paths import ensure_dir, resolve
from .base import Detector, DetectionInput, TrainingReport, normalise_rows

_LOG = get_logger(__name__)

#: Feature columns the rules read, mapped to their threshold config keys.
RULE_FEATURES: dict[str, str] = {
    "eg_packet_rate": "packet_rate_pps",
    "eg_byte_rate": "byte_rate_bps",
    "eg_unique_dst_ports": "unique_dst_ports",
    "eg_syn_ratio": "syn_ratio",
}

#: Rules whose limit is a *rate or count* and therefore network-specific.
#: Bounded ratio rules (syn_ratio in [0, 1]) are protocol-semantic and are
#: deliberately NOT calibrated: fitting them to benign data would push the
#: limit above 1.0 and silently disable the rule.
CALIBRATABLE_RULES: frozenset[str] = frozenset(
    {"packet_rate_pps", "byte_rate_bps", "unique_dst_ports"}
)

#: Percentile of the benign training distribution used when auto-calibrating.
CALIBRATION_PERCENTILE: float = 99.0
#: Safety factor applied on top of the calibration percentile.
CALIBRATION_MARGIN: float = 1.25


class ThresholdDetector(Detector):
    """Static rule-based anomaly detector.

    Args:
        thresholds: Mapping of threshold name to limit; defaults come from
            ``detection.threshold`` in the configuration.
        suspicious_scale: Fraction of the malicious limit at which a node is
            escalated to SUSPICIOUS.
        endpoints_only: Score only endpoint nodes (recommended and default).
        auto_calibrate: Re-derive thresholds from benign training rows in
            :meth:`fit`.
    """

    name = "threshold"
    display_name = "Threshold baseline"
    uses_graph = False

    def __init__(
        self,
        thresholds: Mapping[str, float] | None = None,
        suspicious_scale: float = 0.45,
        endpoints_only: bool = True,
        auto_calibrate: bool = True,
    ) -> None:
        super().__init__()
        self.thresholds: dict[str, float] = {
            "packet_rate_pps": 220.0,
            "byte_rate_bps": 900000.0,
            "unique_dst_ports": 12.0,
            "syn_ratio": 0.55,
        }
        if thresholds:
            self.thresholds.update({k: float(v) for k, v in thresholds.items()
                                    if k in self.thresholds})
        self.suspicious_scale = float(suspicious_scale)
        self.endpoints_only = bool(endpoints_only)
        self.auto_calibrate = bool(auto_calibrate)
        self.calibrated_from: str = "config"
        # Rule-based: usable immediately, no training required.
        self.fitted = True

    # ------------------------------------------------------------------ #
    @classmethod
    def from_config(cls, config: Any) -> "ThresholdDetector":
        """Build a detector from the ``detection.threshold`` config section."""
        section = config.get("detection.threshold", {}) or {}
        return cls(
            thresholds={
                "packet_rate_pps": section.get("packet_rate_pps", 220.0),
                "byte_rate_bps": section.get("byte_rate_bps", 900000.0),
                "unique_dst_ports": section.get("unique_dst_ports", 12.0),
                "syn_ratio": section.get("syn_ratio", 0.55),
            },
            suspicious_scale=float(section.get("suspicious_scale", 0.45)),
            auto_calibrate=bool(section.get("auto_calibrate", True)),
        )

    # ------------------------------------------------------------------ #
    def fit(
        self, train: DetectionInput, val: DetectionInput | None = None
    ) -> TrainingReport:
        """Optionally calibrate thresholds from benign endpoint traffic.

        No model is learned. When ``auto_calibrate`` is enabled, each threshold
        is set to ``CALIBRATION_MARGIN`` times the 99th percentile of the benign
        endpoint distribution, but never below the configured floor - so the
        baseline is tuned to the network it is deployed on rather than left at
        an arbitrary default.

        Args:
            train: Training evidence (only BENIGN endpoint rows are used).
            val: Unused; accepted for interface compatibility.

        Returns:
            A :class:`TrainingReport` recording the resulting thresholds.
        """
        started = time.perf_counter()
        self._check_columns(train.features)

        if self.auto_calibrate:
            frame = train.features
            benign = frame[(frame["label"] == 0) & (frame["is_endpoint"] > 0.5)]
            if len(benign) >= 30:
                calibrated: dict[str, float] = {}
                for column, key in RULE_FEATURES.items():
                    if key not in CALIBRATABLE_RULES:
                        continue
                    percentile = float(
                        np.percentile(benign[column].to_numpy(dtype=float),
                                      CALIBRATION_PERCENTILE)
                    )
                    calibrated[key] = max(
                        self.thresholds[key], percentile * CALIBRATION_MARGIN
                    )
                self.thresholds.update(calibrated)
                self.calibrated_from = (
                    f"{len(benign)} benign endpoint rows @ p{CALIBRATION_PERCENTILE:.0f}"
                )
                _LOG.info("Threshold baseline calibrated: %s", self.thresholds)
            else:
                _LOG.warning(
                    "Only %d benign endpoint rows available; keeping configured "
                    "thresholds without calibration.", len(benign),
                )

        return TrainingReport(
            detector=self.name,
            trained=False,
            duration_s=time.perf_counter() - started,
            extra={
                "thresholds": dict(self.thresholds),
                "suspicious_scale": self.suspicious_scale,
                "endpoints_only": self.endpoints_only,
                "calibrated_from": self.calibrated_from,
            },
        )

    # ------------------------------------------------------------------ #
    def rule_scores(self, frame: pd.DataFrame) -> pd.DataFrame:
        """Return the per-rule normalised scores for every row.

        Args:
            frame: A node-window feature frame.

        Returns:
            A frame with one column per rule plus a ``score`` column holding the
            row-wise maximum. Useful for explaining *why* the baseline fired.
        """
        self._check_columns(frame)
        scores = pd.DataFrame(index=frame.index)
        for column, key in RULE_FEATURES.items():
            limit = max(1e-9, float(self.thresholds[key]))
            scores[key] = frame[column].to_numpy(dtype=float) / limit
        scores["score"] = scores.max(axis=1)
        if self.endpoints_only:
            scores.loc[frame["is_endpoint"].to_numpy(dtype=float) <= 0.5, :] = 0.0
        return scores

    def predict_proba(self, data: DetectionInput) -> np.ndarray:
        """Score rows and convert the rule score into pseudo-probabilities.

        The score is mapped monotonically onto the three classes so that ROC and
        PR curves are meaningful for the baseline too: ``score`` well below the
        suspicious scale concentrates mass on BENIGN, ``score >= 1`` concentrates
        it on MALICIOUS, and the region between interpolates.
        """
        self._require_fitted()
        score = self.rule_scores(data.features)["score"].to_numpy(dtype=float)

        benign = np.clip(1.0 - score / max(1e-9, self.suspicious_scale), 0.0, 1.0)
        malicious = np.clip((score - self.suspicious_scale)
                            / max(1e-9, 1.0 - self.suspicious_scale), 0.0, 1.0)
        # Saturate well above the limit so a 10x flood is not merely "1.0".
        malicious = np.where(score >= 1.0, np.clip(0.9 + 0.1 * np.tanh(score - 1.0),
                                                   0.0, 1.0), malicious)
        suspicious = np.clip(1.0 - benign - malicious, 0.0, 1.0)
        stacked = np.stack([benign, suspicious, malicious], axis=1)
        return normalise_rows(stacked)

    # ------------------------------------------------------------------ #
    def save(self, directory: str | Path) -> Path:
        """Persist the calibrated thresholds."""
        target = ensure_dir(directory)
        (target / "thresholds.json").write_text(
            json.dumps(
                {
                    "thresholds": self.thresholds,
                    "suspicious_scale": self.suspicious_scale,
                    "endpoints_only": self.endpoints_only,
                    "auto_calibrate": self.auto_calibrate,
                    "calibrated_from": self.calibrated_from,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        self.write_manifest(target, {"kind": "rule-based", "trainable": False})
        _LOG.info("Threshold detector saved -> %s", target)
        return target

    @classmethod
    def load(cls, directory: str | Path) -> "ThresholdDetector":
        """Restore a threshold detector from disk.

        Raises:
            FileNotFoundError: If the checkpoint is missing.
        """
        source = resolve(directory)
        path = source / "thresholds.json"
        if not path.exists():
            raise FileNotFoundError(f"No threshold checkpoint at {path}")
        payload = json.loads(path.read_text(encoding="utf-8"))
        detector = cls(
            thresholds=payload.get("thresholds"),
            suspicious_scale=float(payload.get("suspicious_scale", 0.45)),
            endpoints_only=bool(payload.get("endpoints_only", True)),
            auto_calibrate=bool(payload.get("auto_calibrate", True)),
        )
        detector.calibrated_from = str(payload.get("calibrated_from", "checkpoint"))
        manifest_path = source / "manifest.json"
        if manifest_path.exists():
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            detector.feature_columns = list(manifest.get("feature_columns",
                                                         detector.feature_columns))
        return detector

    def explain(self, frame: pd.DataFrame, row: int) -> dict[str, Any]:
        """Explain a single decision by naming the rule that fired hardest.

        Args:
            frame: The feature frame.
            row: Positional row index.

        Returns:
            A mapping with the winning rule, its value, its limit and the score.
        """
        scores = self.rule_scores(frame)
        record = scores.iloc[row]
        rule_only = record.drop(labels=["score"])
        winner = str(rule_only.idxmax())
        column = next(c for c, k in RULE_FEATURES.items() if k == winner)
        return {
            "rule": winner,
            "feature": column,
            "value": float(frame.iloc[row][column]),
            "limit": float(self.thresholds[winner]),
            "score": float(record["score"]),
        }
