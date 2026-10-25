"""Detection pipeline: loading trained detectors and scoring runs.

Two entry points:

:func:`load_detectors`
    Restores the trained detectors from ``models/`` and reports honestly which
    ones were found, so a missing checkpoint produces a clear message rather
    than a silent skip.

:func:`score_run`
    Scores one simulation run offline, producing per-node-window detections plus
    the recovery-relevant timeline. This is the path used by
    ``scripts/run_experiment.py`` for the detect-only experiments; the
    closed-loop experiment uses :mod:`netshield.detection.controller` instead.

:func:`build_controller_factory`
    Wires a trained detector and a mitigation engine into the callback signature
    the simulation runner expects, so closed-loop runs are a one-line change.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

import pandas as pd

from ..features.node_features import CLASS_NAMES, build_node_window_features
from ..graph.builder import build_edge_table
from ..mitigation.engine import MitigationEnforcer, MitigationEngine
from ..mitigation.policy import PolicyConfig
from ..models.base import DetectionInput, Detector
from ..models.baselines import AutoencoderDetector, GRUSequenceDetector, LightGBMDetector
from ..models.graphsage import EGraphSAGEDetector, GATDetector, GraphSAGEDetector
from ..models.temporal_gnn import TemporalGNNDetector
from ..models.random_forest import RandomForestDetector
from ..models.threshold import ThresholdDetector
from ..utils.logging_utils import get_logger
from ..utils.paths import resolve
from .controller import DetectionController

_LOG = get_logger(__name__)

#: Detector registry: name -> class.
DETECTOR_CLASSES: dict[str, type[Detector]] = {
    ThresholdDetector.name: ThresholdDetector,
    RandomForestDetector.name: RandomForestDetector,
    GraphSAGEDetector.name: GraphSAGEDetector,
    LightGBMDetector.name: LightGBMDetector,
    GRUSequenceDetector.name: GRUSequenceDetector,
    AutoencoderDetector.name: AutoencoderDetector,
    GATDetector.name: GATDetector,
    EGraphSAGEDetector.name: EGraphSAGEDetector,
    TemporalGNNDetector.name: TemporalGNNDetector,
}

#: Every detector the research protocol compares, weakest-first.
ALL_DETECTORS: tuple[str, ...] = (
    "threshold", "autoencoder", "random_forest", "lightgbm", "gru_seq",
    "gat", "egraphsage", "graphsage",
)

#: Default order used in reports and figures (weakest baseline first).
DETECTOR_ORDER: tuple[str, ...] = ("threshold", "random_forest", "graphsage")


class PipelineError(RuntimeError):
    """Raised when the detection pipeline cannot be assembled."""


def detector_directory(models_root: str | Path, name: str) -> Path:
    """Return the checkpoint directory for a named detector."""
    return resolve(models_root) / name


def load_detectors(
    models_root: str | Path,
    names: Sequence[str] | None = None,
    required: bool = False,
) -> dict[str, Detector]:
    """Load trained detectors from ``models/``.

    Args:
        models_root: Directory holding one sub-directory per detector.
        names: Detector names to load; defaults to :data:`DETECTOR_ORDER`.
        required: Raise if a checkpoint is missing instead of skipping it.

    Returns:
        ``{name: detector}`` for every checkpoint successfully loaded.

    Raises:
        PipelineError: If *required* is set and a checkpoint is missing, or if
            no detector at all could be loaded.
    """
    wanted = list(names or DETECTOR_ORDER)
    loaded: dict[str, Detector] = {}
    missing: list[str] = []

    for name in wanted:
        cls = DETECTOR_CLASSES.get(name)
        if cls is None:
            raise PipelineError(
                f"Unknown detector '{name}'. Known: {sorted(DETECTOR_CLASSES)}"
            )
        directory = detector_directory(models_root, name)
        try:
            loaded[name] = cls.load(directory)
            _LOG.info("Loaded detector '%s' from %s", name, directory)
        except FileNotFoundError as exc:
            missing.append(name)
            _LOG.warning("Detector '%s' not available: %s", name, exc)

    if missing and required:
        raise PipelineError(
            f"Missing trained detectors: {missing}. "
            "Run 'python scripts/train_models.py' first."
        )
    if not loaded:
        raise PipelineError(
            f"No trained detectors found under {resolve(models_root)}. "
            "Run 'python scripts/train_models.py' first."
        )
    return loaded


def prepare_input(result: Any, config: Any) -> DetectionInput:
    """Featurise one simulation run into detector input.

    Args:
        result: A :class:`~netshield.simulation.runner.SimulationResult`.
        config: Configuration supplying the label thresholds.

    Returns:
        The :class:`~netshield.models.base.DetectionInput` for the whole run.
    """
    features = build_node_window_features(
        result,
        malicious_threshold=float(config.get("features.label_malicious_threshold", 0.55)),
        suspicious_threshold=float(
            config.get("features.label_suspicious_threshold", 0.12)
        ),
    )
    return DetectionInput(features, build_edge_table(result))


def score_run(
    result: Any,
    detector: Detector,
    config: Any,
    trigger: float | None = None,
) -> dict[str, Any]:
    """Score one run offline and return detections plus a timeline.

    Args:
        result: The simulation run to score.
        detector: A fitted detector.
        config: Configuration (label thresholds, trigger probability).
        trigger: Override the mitigation trigger probability.

    Returns:
        A mapping with ``detections`` (a frame), ``timeline`` (per-window
        aggregates) and ``summary``.
    """
    threshold = float(
        trigger
        if trigger is not None
        else config.get("detection.mitigation_trigger_probability", 0.80)
    )
    data = prepare_input(result, config)
    proba = detector.predict_proba(data)
    scores = proba[:, 1] + proba[:, 2]
    predictions = proba.argmax(axis=1)

    detections = data.features[
        ["run_id", "experiment", "window", "t_start", "t_end", "node_id", "kind",
         "ip", "eg_packet_rate", "label", "label_name", "is_attacker"]
    ].copy()
    detections["detector"] = detector.name
    detections["probability"] = scores
    detections["predicted_index"] = predictions
    detections["predicted"] = [CLASS_NAMES[int(p)] for p in predictions]
    detections["p_benign"] = proba[:, 0]
    detections["p_suspicious"] = proba[:, 1]
    detections["p_malicious"] = proba[:, 2]
    detections["flagged"] = detections["probability"] >= threshold

    timeline = (
        detections.groupby(["window", "t_start", "t_end"], as_index=False)
        .agg(
            n_nodes=("node_id", "size"),
            n_flagged=("flagged", "sum"),
            n_attackers=("is_attacker", "sum"),
            max_probability=("probability", "max"),
            mean_probability=("probability", "mean"),
        )
        .sort_values("window")
        .reset_index(drop=True)
    )

    attackers = set(detections.loc[detections["is_attacker"], "node_id"])
    flagged_attackers = set(
        detections.loc[detections["flagged"] & detections["is_attacker"], "node_id"]
    )
    false_alarms = set(
        detections.loc[detections["flagged"] & ~detections["is_attacker"], "node_id"]
    )

    return {
        "detections": detections,
        "timeline": timeline,
        "summary": {
            "run_id": result.run_id,
            "experiment": str(result.meta.get("experiment", result.run_id)),
            "detector": detector.name,
            "trigger_probability": threshold,
            "n_rows": int(len(detections)),
            "n_flagged": int(detections["flagged"].sum()),
            "attackers_total": len(attackers),
            "attackers_flagged": sorted(flagged_attackers),
            "attackers_missed": sorted(attackers - flagged_attackers),
            "false_alarm_nodes": sorted(false_alarms),
        },
    }


def build_controller_factory(
    detector: Detector,
    config: Any,
    enable_mitigation: bool = True,
) -> Callable[[Any], DetectionController]:
    """Return a controller factory for :func:`netshield.simulation.runner.run_simulation`.

    Args:
        detector: A fitted detector to run in the loop.
        config: Configuration providing policy thresholds.
        enable_mitigation: Arm the mitigation engine. When False the controller
            observes and logs but installs no rules, which is how the
            "detection only" arm of Experiment 8 is produced.

    Returns:
        A callable taking the simulation context and returning the controller.
    """
    trigger = float(config.get("detection.mitigation_trigger_probability", 0.80))
    policy = PolicyConfig.from_config(config).validate()

    def factory(context: Any) -> DetectionController:
        mitigation: MitigationEngine | None = None
        if enable_mitigation:
            node_ips = {n.node_id: n.ip for n in context.topology.nodes.values()}
            enforcer = MitigationEnforcer(policy, node_ips)
            mitigation = MitigationEngine(policy, enforcer, detector_name=detector.name)
            mitigation.approval_mode = str(config.get("mitigation.approval_mode", "auto"))
        return DetectionController(
            context=context,
            detector=detector,
            mitigation=mitigation,
            trigger=trigger,
            warmup_windows=int(config.get("detection.warmup_windows", 1)),
        )

    return factory


def recovery_metrics(
    windows: Sequence[Mapping[str, Any]],
    attack_start_s: float,
    attack_end_s: float,
    first_mitigation_s: float | None,
) -> dict[str, Any]:
    """Quantify how well the network recovered after mitigation.

    The three phases are made **disjoint** so the comparison means something:

    ``baseline``
        windows entirely before the attack;
    ``under_attack``
        attack running, no mitigation rule installed yet;
    ``after_mitigation``
        attack *still running*, mitigation now active.

    Comparing the last two isolates the effect of the defence, because the
    offered attack load is identical across them. A fourth ``post_attack``
    block covers the windows after the attack stops.

    Recovery is measured on ``clean_loss_ratio`` - the loss experienced by
    devices that were never compromised. Using ``legit_loss_ratio`` would be
    misleading: isolating a bot also severs that bot's own legitimate
    telemetry, which counts as legitimate loss but is an intended consequence
    of the defence rather than a failure of it.

    Args:
        windows: Per-window metric rows from the run.
        attack_start_s: Attack start time.
        attack_end_s: Attack end time.
        first_mitigation_s: Time the first rule was installed, or ``None``.

    Returns:
        Baseline / under-attack / post-mitigation aggregates and the measured
        recovery time.
    """
    frame = pd.DataFrame(list(windows))
    if frame.empty:
        return {"available": False, "reason": "no window metrics"}

    pre = frame[frame["t_end"] <= attack_start_s]
    boundary = attack_end_s if first_mitigation_s is None else first_mitigation_s
    during = frame[
        (frame["t_start"] >= attack_start_s) & (frame["t_end"] <= boundary)
    ]
    if first_mitigation_s is None:
        post = frame.iloc[0:0]
    else:
        post = frame[
            (frame["t_start"] >= first_mitigation_s)
            & (frame["t_end"] <= attack_end_s)
        ]
    post_attack = frame[frame["t_start"] >= attack_end_s]

    def block(section: pd.DataFrame) -> dict[str, Any]:
        if section.empty:
            return {}
        return {
            "windows": int(len(section)),
            "throughput_mbps": round(float(section["throughput_mbps"].mean()), 5),
            "legit_throughput_pps": round(
                float(section["legit_throughput_pps"].mean()), 3),
            "mean_latency_ms": round(float(section["mean_latency_ms"].mean()), 4),
            "legit_mean_latency_ms": round(
                float(section["legit_mean_latency_ms"].mean()), 4),
            "loss_ratio": round(float(section["loss_ratio"].mean()), 6),
            "legit_loss_ratio": round(float(section["legit_loss_ratio"].mean()), 6),
            "clean_loss_ratio": round(float(
                section.get("clean_loss_ratio", section["legit_loss_ratio"]).mean()), 6),
            "clean_throughput_pps": round(float(
                section.get("clean_throughput_pps",
                            section["legit_throughput_pps"]).mean()), 3),
            "clean_mean_latency_ms": round(float(
                section.get("clean_mean_latency_ms",
                            section["legit_mean_latency_ms"]).mean()), 4),
            "uplink_utilisation": round(float(section["uplink_utilisation"].mean()), 5),
        }

    baseline = block(pre)
    recovery_time: float | None = None
    metric = ("clean_loss_ratio" if "clean_loss_ratio" in frame.columns
              else "legit_loss_ratio")
    if baseline and first_mitigation_s is not None and not post.empty:
        target = float(baseline.get(metric, baseline["legit_loss_ratio"])) * 1.25 + 0.01
        recovered = post[post[metric] <= target]
        if not recovered.empty:
            recovery_time = round(
                float(recovered["t_end"].iloc[0]) - first_mitigation_s, 4
            )

    return {
        "available": True,
        "attack_start_s": attack_start_s,
        "attack_end_s": attack_end_s,
        "first_mitigation_s": first_mitigation_s,
        "baseline": baseline,
        "under_attack": block(during),
        "after_mitigation": block(post),
        "post_attack": block(post_attack),
        "recovery_time_s": recovery_time,
        "recovery_metric": metric,
        "recovery_definition": (
            "first window after the first mitigation action in which the "
            "packet-loss ratio of never-compromised devices returns to within "
            "25% (+1pp) of the pre-attack mean; phases are disjoint, so "
            "'under attack' means 'attack running, not yet mitigated'"
        ),
    }


def summarise_detector_outputs(
    outputs: Mapping[str, Mapping[str, Any]]
) -> pd.DataFrame:
    """Build a tidy comparison frame from several :func:`score_run` results."""
    rows: list[dict[str, Any]] = []
    for name, payload in outputs.items():
        summary = dict(payload.get("summary", {}))
        rows.append({
            "detector": name,
            "n_rows": summary.get("n_rows", 0),
            "n_flagged": summary.get("n_flagged", 0),
            "attackers_total": summary.get("attackers_total", 0),
            "attackers_flagged": len(summary.get("attackers_flagged", [])),
            "attackers_missed": len(summary.get("attackers_missed", [])),
            "false_alarm_nodes": len(summary.get("false_alarm_nodes", [])),
        })
    return pd.DataFrame(rows)
