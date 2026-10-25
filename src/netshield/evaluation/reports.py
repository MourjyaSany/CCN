"""Machine- and human-readable result reports.

Every number written by this module comes from an evaluation that ran. Where a
quantity could not be computed - because a split contained a single class, an
attack was never detected, or a dependency was unavailable - the report says so
explicitly with a ``not available`` marker and a reason. Nothing is imputed.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import pandas as pd

from ..utils.logging_utils import get_logger
from ..utils.paths import ensure_dir, ensure_parent

_LOG = get_logger(__name__)

NA = "not available"


def _fmt(value: Any, digits: int = 4, suffix: str = "") -> str:
    """Format a number for a Markdown table, or ``not available``."""
    if value is None:
        return NA
    if isinstance(value, float):
        if value != value:  # NaN
            return NA
        return f"{value:.{digits}f}{suffix}"
    return f"{value}{suffix}"


def _count(value: Any) -> str:
    """Format an integer count with thousands separators, or ``not available``.

    The NS-3 engine measures a different set of quantities from the Python one
    (there are no "discrete events processed" in an NS-3 run, for instance), so
    a report must be able to render a missing counter rather than crash on
    ``None``.
    """
    if value is None:
        return NA
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return str(value)


def write_json(payload: Any, path: str | Path) -> Path:
    """Write *payload* as pretty-printed JSON."""
    target = ensure_parent(path)
    target.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    _LOG.info("report -> %s", target)
    return target


def write_csv(frame: pd.DataFrame, path: str | Path) -> Path:
    """Write a frame to CSV."""
    target = ensure_parent(path)
    frame.to_csv(target, index=False)
    _LOG.info("table -> %s", target)
    return target


def comparison_markdown(
    bundles: Sequence[Any],
    latency: Mapping[str, Mapping[str, Any]],
    title: str = "Detector comparison",
) -> str:
    """Render the headline detector comparison as a Markdown table.

    Args:
        bundles: Metric bundles, one per detector.
        latency: ``{detector: latency_report}``.
        title: Section heading.

    Returns:
        A Markdown fragment.
    """
    lines = [
        f"### {title}",
        "",
        "| Detector | Accuracy | Macro-F1 | Attack precision | Attack recall | "
        "Attack F1 | FPR | ROC-AUC | Mean detection latency |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for bundle in bundles:
        report = latency.get(bundle.detector, {})
        mean_latency = report.get("mean_latency_s")
        missed = report.get("n_missed", 0)
        latency_cell = (
            f"{mean_latency:.1f} s" if mean_latency is not None else NA
        )
        if missed:
            latency_cell += f" ({missed} run(s) missed)"
        lines.append(
            f"| {bundle.detector} "
            f"| {_fmt(bundle.accuracy)} "
            f"| {_fmt(bundle.macro_f1)} "
            f"| {_fmt(bundle.binary.get('precision'))} "
            f"| {_fmt(bundle.binary.get('recall'))} "
            f"| {_fmt(bundle.binary.get('f1'))} "
            f"| {_fmt(bundle.binary.get('false_positive_rate'), 5)} "
            f"| {_fmt(bundle.binary.get('roc_auc'))} "
            f"| {latency_cell} |"
        )
    return "\n".join(lines)


def per_class_markdown(bundle: Any) -> str:
    """Render one detector's per-class precision/recall/F1 as Markdown."""
    lines = [
        f"#### {bundle.detector} - per-class results ({bundle.split})",
        "",
        "| Class | Precision | Recall | F1 | Support |",
        "|---|---:|---:|---:|---:|",
    ]
    for name, values in bundle.per_class.items():
        lines.append(
            f"| {name} | {_fmt(values['precision'])} | {_fmt(values['recall'])} "
            f"| {_fmt(values['f1'])} | {values['support']} |"
        )
    return "\n".join(lines)


def confusion_markdown(bundle: Any, classes: Sequence[str]) -> str:
    """Render a confusion matrix as a Markdown table."""
    header = "| True \\ Predicted | " + " | ".join(classes) + " |"
    sep = "|---|" + "---:|" * len(classes)
    lines = [f"#### {bundle.detector} - confusion matrix", "", header, sep]
    for i, row in enumerate(bundle.confusion):
        lines.append(f"| **{classes[i]}** | " + " | ".join(str(v) for v in row) + " |")
    return "\n".join(lines)


def experiment_markdown(rows: Sequence[Mapping[str, Any]]) -> str:
    """Render per-experiment results as a Markdown table."""
    if not rows:
        return "_No per-experiment results were produced._"
    lines = [
        "| Experiment | Detector | Samples | Macro-F1 | Attack recall | "
        "Attack precision | FPR |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row.get('split', '?')} | {row.get('detector', '?')} "
            f"| {row.get('n_samples', 0)} | {_fmt(row.get('macro_f1'))} "
            f"| {_fmt(row.get('attack_recall'))} "
            f"| {_fmt(row.get('attack_precision'))} "
            f"| {_fmt(row.get('fpr'), 5)} |"
        )
    return "\n".join(lines)


def network_phase_markdown(recovery: Mapping[str, Any]) -> str:
    """Render the NORMAL / UNDER ATTACK / AFTER MITIGATION comparison."""
    if not recovery.get("available"):
        return f"_Network phase comparison {NA}: {recovery.get('reason', 'no data')}._"

    rows = [
        ("Normal (pre-attack)", recovery.get("baseline") or {}),
        ("Under attack (not yet mitigated)", recovery.get("under_attack") or {}),
        ("After mitigation (attack still running)",
         recovery.get("after_mitigation") or {}),
        ("Post-attack", recovery.get("post_attack") or {}),
    ]
    lines = [
        "Phases are disjoint. 'Under attack' covers the windows in which the "
        "attack was running but no mitigation rule had been installed yet, so "
        "comparing it with the next row isolates the effect of the defence at a "
        "constant offered attack load.",
        "",
        "Loss, latency and goodput are reported for **never-compromised "
        "devices**: isolating a bot also severs that bot's own legitimate "
        "telemetry, which is an intended consequence of the defence rather than "
        "a failure of it.",
        "",
        "| Phase | Windows | Upstream goodput (Mbit/s) | Clean goodput (pkt/s) | "
        "Clean latency (ms) | Clean loss | Uplink utilisation |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for name, block in rows:
        if not block:
            lines.append(f"| {name} | - | {NA} | {NA} | {NA} | {NA} | {NA} |")
            continue
        lines.append(
            f"| {name} | {block.get('windows', 0)} "
            f"| {_fmt(block.get('throughput_mbps'), 4)} "
            f"| {_fmt(block.get('clean_throughput_pps'), 2)} "
            f"| {_fmt(block.get('clean_mean_latency_ms'), 2)} "
            f"| {_fmt(block.get('clean_loss_ratio'), 5)} "
            f"| {_fmt(block.get('uplink_utilisation'), 4)} |"
        )

    recovery_s = recovery.get("recovery_time_s")
    lines.append("")
    lines.append(
        f"- First mitigation action: "
        f"{_fmt(recovery.get('first_mitigation_s'), 1, ' s')}"
    )
    lines.append(
        f"- Recovery time: {_fmt(recovery_s, 1, ' s')}"
        + (f" ({recovery['recovery_definition']})" if recovery_s is not None else "")
    )
    return "\n".join(lines)


def mitigation_markdown(summary: Mapping[str, Any], accuracy: Mapping[str, Any]) -> str:
    """Render the mitigation campaign summary."""
    if not summary:
        return f"_Mitigation summary {NA} (no closed-loop run was executed)._"

    lines = [
        "| Property | Value |",
        "|---|---|",
        f"| Detector driving mitigation | {summary.get('detector', NA)} |",
        f"| Actions installed | {summary.get('n_actions', 0)} |",
        f"| Actions by type | {summary.get('actions_by_type', {})} |",
        f"| First action | {_fmt(summary.get('first_action_s'), 1, ' s')} |",
        f"| Nodes acted upon | {len(summary.get('nodes_affected', []))} |",
        f"| Packets dropped by mitigation | "
        f"{summary.get('enforcement', {}).get('packets_dropped', 0)} |",
        f"| Correctly mitigated bots | {len(accuracy.get('correctly_mitigated', []))} "
        f"/ {accuracy.get('attackers_total', 0)} |",
        f"| Collateral damage (legitimate nodes throttled/blocked) | "
        f"{accuracy.get('collateral_damage', 0)} |",
        f"| Mitigation precision | {_fmt(accuracy.get('precision'))} |",
        f"| Mitigation recall | {_fmt(accuracy.get('recall'))} |",
    ]
    return "\n".join(lines)


def write_results_report(
    path: str | Path,
    bundles: Sequence[Any],
    latency: Mapping[str, Mapping[str, Any]],
    per_experiment: Sequence[Mapping[str, Any]],
    dataset_report: Mapping[str, Any],
    split_summary: Mapping[str, Any],
    training_reports: Mapping[str, Mapping[str, Any]],
    environment: Mapping[str, Any],
    classes: Sequence[str],
    figures: Sequence[str] = (),
    endpoint_bundles: Sequence[Any] = (),
) -> Path:
    """Write ``results/reports/RESULTS.md`` - the auto-generated results file.

    Args:
        path: Destination path.
        bundles: All-node metric bundles.
        latency: Per-detector detection-latency reports.
        per_experiment: Per-experiment headline rows.
        dataset_report: Output of
            :func:`netshield.features.dataset.dataset_report`.
        split_summary: Output of
            :meth:`netshield.features.dataset.DatasetSplit.summary`.
        training_reports: ``{detector: training_report_dict}``.
        environment: Environment probe (engine provenance, versions).
        classes: Class names in label order.
        figures: Filenames of the figures produced.
        endpoint_bundles: Optional endpoint-only metric bundles.

    Returns:
        The written path.
    """
    target = ensure_parent(path)
    engine_label = environment.get("engine_label", NA)
    generated = datetime.now(timezone.utc).isoformat(timespec="seconds")

    sections: list[str] = [
        "# NetShield-GNN - Experimental Results",
        "",
        "> **Auto-generated.** Every figure in this file was produced by",
        "> `python scripts/evaluate.py` from artefacts that a simulation run",
        "> actually wrote. Quantities that could not be computed are marked",
        f"> `{NA}` together with the reason; none are imputed.",
        "",
        f"- Generated: `{generated}`",
        f"- Simulation engine: **{engine_label}**",
        f"- NS-3 available on this host: "
        f"**{environment.get('ns3_available', False)}**",
        f"- GraphSAGE backend: **{environment.get('gnn_backend', NA)}**",
        f"- Python: `{environment.get('python', NA)}`",
        "",
        "## 1. Dataset",
        "",
        f"- Node-window samples: **{dataset_report.get('rows', 0)}**",
        f"- Simulation runs: **{dataset_report.get('runs', 0)}**",
        f"- Distinct scenarios: **{dataset_report.get('experiments', 0)}**",
        f"- Features per node-window: **{dataset_report.get('n_features', 0)}**",
        f"- Class distribution: `{dataset_report.get('classes', {})}`",
        "",
        "### Split (grouped by run, so no simulation spans two splits)",
        "",
        "| Split | Rows | Runs | Classes |",
        "|---|---:|---:|---|",
    ]
    for name in ("train", "val", "test"):
        block = split_summary.get(name, {}) or {}
        sections.append(
            f"| {name} | {block.get('rows', 0)} | {block.get('runs', 0)} "
            f"| `{block.get('classes', {})}` |"
        )

    sections += ["", "## 2. Detector comparison (test split, all nodes)", ""]
    sections.append(comparison_markdown(bundles, latency, title="Headline results"))

    if endpoint_bundles:
        sections += [
            "",
            "### Endpoint-only view",
            "",
            "Infrastructure nodes (routers, gateway, cloud) are benign by",
            "construction in this threat model, so they inflate accuracy. The",
            "table below restricts every metric to IoT and compromised devices -",
            "the population a real detector is graded on.",
            "",
        ]
        sections.append(comparison_markdown(endpoint_bundles, latency,
                                            title="Endpoint nodes only"))

    sections += ["", "## 3. Per-class results", ""]
    for bundle in bundles:
        sections += [per_class_markdown(bundle), "",
                     confusion_markdown(bundle, classes), ""]

    sections += ["", "## 4. Per-scenario results", "",
                 experiment_markdown(per_experiment), ""]

    sections += ["", "## 5. Training", "",
                 "| Detector | Trained | Epochs | Best epoch | Fit time (s) |",
                 "|---|---|---:|---:|---:|"]
    for name, report in training_reports.items():
        sections.append(
            f"| {name} | {report.get('trained', False)} "
            f"| {report.get('epochs', 0)} | {report.get('best_epoch', 0)} "
            f"| {_fmt(report.get('duration_s'), 2)} |"
        )

    if figures:
        sections += ["", "## 6. Figures", ""]
        sections += [f"- `results/figures/{name}`" for name in figures]

    sections += [
        "",
        "---",
        "",
        "### Reproducing these numbers",
        "",
        "```bash",
        "./run.sh setup      # dependency check + directories",
        "./run.sh dataset    # regenerate the labelled corpus from simulation",
        "./run.sh train      # retrain all three detectors",
        "./run.sh evaluate   # regenerate this file and every figure",
        "```",
        "",
        "All randomness is seeded from `seed` in `config/default.yaml` and the",
        "per-experiment overrides in `config/experiments.yaml`; re-running the",
        "commands above on the same commit reproduces these numbers exactly.",
        "",
    ]

    target.write_text("\n".join(sections), encoding="utf-8")
    _LOG.info("Results report -> %s", target)
    return target


def write_experiment_report(
    path: str | Path,
    result: Any,
    detector_summaries: Mapping[str, Mapping[str, Any]],
    recovery: Mapping[str, Any] | None = None,
    mitigation: Mapping[str, Any] | None = None,
    mitigation_accuracy: Mapping[str, Any] | None = None,
) -> Path:
    """Write a per-experiment Markdown report.

    Args:
        path: Destination path.
        result: The simulation run.
        detector_summaries: ``{detector: score_run summary}``.
        recovery: Optional recovery metrics.
        mitigation: Optional mitigation summary.
        mitigation_accuracy: Optional mitigation accuracy scoring.

    Returns:
        The written path.
    """
    target = ensure_parent(path)
    summary = dict(result.summary)
    attack = dict(summary.get("attack", {}) or {})

    lines = [
        f"# {result.meta.get('experiment', result.run_id)}",
        "",
        (result.meta.get("description") or "").strip(),
        "",
        "## Run configuration",
        "",
        "| Property | Value |",
        "|---|---|",
        f"| Run id | `{result.run_id}` |",
        f"| Engine | **{result.engine_label}** |",
        f"| Engine selection | {result.engine_reason} |",
        f"| Seed | {summary.get('seed')} |",
        f"| Duration | {summary.get('duration_s')} s |",
        f"| Feature window | {summary.get('window_s')} s |",
        f"| IoT devices | {summary.get('n_iot_devices')} |",
        f"| Compromised devices | {summary.get('n_attackers')} |",
        f"| Attack | `{attack.get('type', 'none')}` "
        f"{'enabled' if attack.get('enabled') else 'disabled'} |",
        f"| Attack window | {attack.get('start_s')} - {attack.get('end_s')} s |",
        f"| Per-attacker rate | {attack.get('packets_per_second')} pps |",
        "",
        "## Simulated network outcome",
        "",
        "| Measurement | Value |",
        "|---|---|",
        f"| Packets generated | {_count(summary.get('packets_generated'))} |",
        f"| Packets delivered | {_count(summary.get('packets_delivered'))} |",
        f"| Packets dropped | {_count(summary.get('packets_dropped'))} |",
        f"| Overall loss ratio | "
        f"{_fmt(summary.get('overall_loss_ratio', summary.get('loss_ratio')), 5)} |",
        f"| Mean end-to-end latency | {_fmt(summary.get('mean_latency_ms'), 3)} ms |",
        f"| Flow records exported | {_count(summary.get('n_flows'))} |",
        f"| Feature windows | {summary.get('n_windows')} |",
        f"| TCP connections opened / failed | "
        f"{summary.get('tcp_connections_opened')} / "
        f"{summary.get('tcp_connections_failed')} |",
        f"| Discrete events processed | {_count(summary.get('events_processed'))} |",
        f"| Wall-clock time | {_fmt(summary.get('wall_seconds'), 2)} s |",
        "",
        "## Cloud server",
        "",
        "| Counter | Value |",
        "|---|---|",
    ]
    for key, value in (result.server or {}).items():
        lines.append(f"| {key.replace('_', ' ')} | {value} |")

    lines += ["", "## Detection", "",
              "| Detector | Rows scored | Flagged | Bots found | Bots missed | "
              "False-alarm nodes |", "|---|---:|---:|---:|---:|---:|"]
    for name, block in detector_summaries.items():
        lines.append(
            f"| {name} | {block.get('n_rows', 0)} | {block.get('n_flagged', 0)} "
            f"| {len(block.get('attackers_flagged', []))} "
            f"| {len(block.get('attackers_missed', []))} "
            f"| {len(block.get('false_alarm_nodes', []))} |"
        )

    if recovery is not None:
        lines += ["", "## Network performance by phase", "",
                  network_phase_markdown(recovery)]
    if mitigation is not None:
        lines += ["", "## Mitigation", "",
                  mitigation_markdown(mitigation, mitigation_accuracy or {})]

    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    _LOG.info("Experiment report -> %s", target)
    return target


def collect_figure_names(figures_dir: str | Path) -> list[str]:
    """Return the sorted filenames of every figure present on disk."""
    directory = ensure_dir(figures_dir)
    return sorted(p.name for p in directory.glob("*.png"))


def summarise_runs(results: Iterable[Any]) -> pd.DataFrame:
    """Build a tidy overview table of many simulation runs."""
    rows: list[dict[str, Any]] = []
    for result in results:
        summary = dict(result.summary)
        attack = dict(summary.get("attack", {}) or {})
        rows.append({
            "run_id": result.run_id,
            "experiment": result.meta.get("experiment", ""),
            "engine": result.engine_label,
            "seed": summary.get("seed"),
            "duration_s": summary.get("duration_s"),
            "n_iot": summary.get("n_iot_devices"),
            "n_attackers": summary.get("n_attackers"),
            "attack_type": attack.get("type") if attack.get("enabled") else "none",
            "attack_pps": attack.get("packets_per_second") if attack.get("enabled") else 0,
            "packets": summary.get("packets_generated"),
            "loss_ratio": summary.get("overall_loss_ratio"),
            "mean_latency_ms": summary.get("mean_latency_ms"),
            "n_flows": summary.get("n_flows"),
            "n_windows": summary.get("n_windows"),
            "wall_s": summary.get("wall_seconds"),
        })
    return pd.DataFrame(rows)
