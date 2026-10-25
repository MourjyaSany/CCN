"""Figure generation.

Every figure in this module is rendered from data that a simulation or an
evaluation actually produced. There is no placeholder data and no illustrative
mock anywhere: if the input is missing, the function raises or returns ``None``
and the caller reports the gap rather than drawing something plausible.

House style
-----------
* One categorical palette, assigned to detectors in a **fixed order** so a
  detector keeps its colour across every figure in the report.
* **No dual-axis charts.** Where two quantities of different scale need to be
  compared over time (throughput and latency, say), they get stacked panels
  sharing an x-axis, never two y-scales on one plot.
* Recessive grid and axes; the data is the darkest thing on the page.
* The attack interval is shaded, and the first mitigation action is marked, so
  every time-series is readable without the caption.
* Every title carries the engine provenance, so an NS-3 figure and an emulation
  figure can never be confused.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import matplotlib

matplotlib.use("Agg")  # headless: figures are files, never windows

import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from matplotlib.colors import LinearSegmentedColormap  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402

from ..features.node_features import CLASS_NAMES  # noqa: E402
from ..utils.logging_utils import get_logger  # noqa: E402
from ..utils.paths import ensure_dir  # noqa: E402

_LOG = get_logger(__name__)

# --------------------------------------------------------------------------- #
# palette (validated categorical order; slots assigned by role, never cycled)
# --------------------------------------------------------------------------- #
SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_SECONDARY = "#52514e"
INK_MUTED = "#8a8981"
GRID = "#e3e2dd"

CATEGORICAL: tuple[str, ...] = (
    "#2a78d6",  # 1 blue
    "#eb6834",  # 2 orange
    "#1baf7a",  # 3 aqua
    "#eda100",  # 4 yellow
    "#e87ba4",  # 5 magenta
    "#008300",  # 6 green
    "#4a3aa7",  # 7 violet
    "#e34948",  # 8 red
)

#: Detectors keep the same colour in every figure of the report.
DETECTOR_COLOURS: dict[str, str] = {
    "threshold": CATEGORICAL[1],
    "random_forest": CATEGORICAL[2],
    "graphsage": CATEGORICAL[0],
    "lightgbm": CATEGORICAL[3],
    "gru_seq": CATEGORICAL[4],
    "autoencoder": CATEGORICAL[5],
    "gat": CATEGORICAL[6],
    "egraphsage": CATEGORICAL[7],
    "temporal_gnn": "#0b0b0b",
}
DETECTOR_LABELS: dict[str, str] = {
    "threshold": "Threshold baseline",
    "random_forest": "Random Forest",
    "graphsage": "GraphSAGE (proposed)",
    "lightgbm": "LightGBM",
    "gru_seq": "GRU sequence",
    "autoencoder": "Autoencoder (unsupervised)",
    "gat": "GATv2",
    "egraphsage": "E-GraphSAGE",
    "temporal_gnn": "Temporal GNN",
}

#: Node roles keep the same colour in every topology/graph figure.
KIND_COLOURS: dict[str, str] = {
    "iot": CATEGORICAL[0],
    "attacker": CATEGORICAL[7],
    "router": CATEGORICAL[2],
    "gateway": CATEGORICAL[3],
    "cloud": CATEGORICAL[6],
}
CLASS_COLOURS: dict[str, str] = {
    "BENIGN": CATEGORICAL[2],
    "SUSPICIOUS": CATEGORICAL[3],
    "MALICIOUS": CATEGORICAL[7],
}

#: Single-hue sequential ramp for magnitude (confusion matrices, heatmaps).
SEQUENTIAL_BLUE = LinearSegmentedColormap.from_list(
    "netshield_blue",
    ["#fcfcfb", "#cde2fb", "#9ec5f4", "#5598e7", "#2a78d6", "#1c5cab", "#0d366b"],
)

ATTACK_SHADE = "#f2ded6"
MITIGATION_LINE = "#1baf7a"


def apply_style(dpi: int = 140) -> None:
    """Install the project's matplotlib house style."""
    plt.rcParams.update({
        "figure.facecolor": SURFACE,
        "axes.facecolor": SURFACE,
        "savefig.facecolor": SURFACE,
        "figure.dpi": dpi,
        "savefig.dpi": dpi,
        "savefig.bbox": "tight",
        "font.size": 9.5,
        "axes.titlesize": 11,
        "axes.titleweight": "semibold",
        "axes.labelsize": 9.5,
        "axes.labelcolor": INK_SECONDARY,
        "axes.edgecolor": GRID,
        "axes.linewidth": 0.9,
        "axes.grid": True,
        "axes.axisbelow": True,
        "grid.color": GRID,
        "grid.linewidth": 0.7,
        "xtick.color": INK_SECONDARY,
        "ytick.color": INK_SECONDARY,
        "xtick.labelsize": 8.5,
        "ytick.labelsize": 8.5,
        "legend.frameon": False,
        "legend.fontsize": 8.5,
        "lines.linewidth": 2.0,
        "lines.markersize": 5,
        "text.color": INK,
    })


def _finish(fig: plt.Figure, path: str | Path, subtitle: str = "") -> Path:
    """Add provenance, save and close a figure.

    Args:
        fig: The figure to save.
        path: Destination path.
        subtitle: Provenance line placed at the bottom-left of the canvas.

    Returns:
        The written path.
    """
    target = Path(path)
    ensure_dir(target.parent)
    if subtitle:
        fig.text(0.005, 0.005, subtitle, fontsize=7, color=INK_MUTED, ha="left",
                 va="bottom")
    fig.savefig(target)
    plt.close(fig)
    _LOG.info("figure -> %s", target)
    return target


def _despine(ax: plt.Axes) -> None:
    """Remove the top and right spines."""
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)


def _shade_attack(ax: plt.Axes, start: float | None, end: float | None,
                  label: bool = True) -> None:
    """Shade the attack interval on a time-series axis."""
    if start is None or end is None or end <= start:
        return
    ax.axvspan(start, end, color=ATTACK_SHADE, zorder=0,
               label="Attack active" if label else None)


def _mark_mitigation(ax: plt.Axes, t: float | None, label: bool = True) -> None:
    """Draw the first-mitigation marker on a time-series axis."""
    if t is None:
        return
    ax.axvline(t, color=MITIGATION_LINE, linestyle="--", linewidth=1.6,
               label="First mitigation" if label else None, zorder=2)


def engine_note(result: Any) -> str:
    """Return the provenance caption for a run's figures."""
    label = getattr(result, "engine_label", "unknown engine")
    run_id = getattr(result, "run_id", "?")
    return f"Source: {label}  |  run {run_id}"


# --------------------------------------------------------------------------- #
# 1. topology
# --------------------------------------------------------------------------- #
def plot_topology(
    result: Any, path: str | Path, title: str | None = None
) -> Path:
    """Draw the IoT-edge-cloud topology with node roles colour-coded.

    Args:
        result: A simulation result carrying a serialised topology.
        path: Destination path.
        title: Optional title override.

    Returns:
        The written path.
    """
    apply_style()
    topology = result.topology
    nodes = topology["nodes"]
    links = topology["links"]

    tiers: dict[int, list[dict[str, Any]]] = {}
    for node in nodes:
        tiers.setdefault(int(node["tier"]), []).append(node)

    positions: dict[str, tuple[float, float]] = {}
    max_tier = max(tiers) if tiers else 1
    for tier, members in tiers.items():
        members = sorted(members, key=lambda n: n["node_id"])
        y = float(max_tier - tier)
        for i, node in enumerate(members):
            x = (i + 1) / (len(members) + 1)
            positions[node["node_id"]] = (x, y)

    width = max(9.0, 0.42 * max(len(m) for m in tiers.values()))
    fig, ax = plt.subplots(figsize=(width, 5.4))

    for link in links:
        a = positions.get(link["source"])
        b = positions.get(link["target"])
        if a is None or b is None:
            continue
        bandwidth = float(link.get("bandwidth_bps", 1e6))
        ax.plot([a[0], b[0]], [a[1], b[1]],
                color=GRID, linewidth=0.8 + 0.9 * np.log10(max(1.0, bandwidth / 1e6)),
                zorder=1, solid_capstyle="round")

    for node in nodes:
        x, y = positions[node["node_id"]]
        kind = node["kind"]
        size = {"cloud": 320, "gateway": 260, "router": 190}.get(kind, 90)
        ax.scatter([x], [y], s=size, color=KIND_COLOURS.get(kind, INK_MUTED),
                   edgecolor=SURFACE, linewidth=1.6, zorder=3)
        if kind in ("cloud", "gateway", "router"):
            ax.annotate(node["node_id"], (x, y), textcoords="offset points",
                        xytext=(0, 13), ha="center", fontsize=8, color=INK)

    tier_names = {0: "Cloud", 1: "Edge gateway", 2: "Access routers",
                  3: "IoT devices"}
    for tier in tiers:
        ax.annotate(tier_names.get(tier, f"Tier {tier}"), (-0.02, float(max_tier - tier)),
                    ha="right", va="center", fontsize=9, color=INK_SECONDARY,
                    fontweight="semibold")

    handles = [
        Line2D([0], [0], marker="o", linestyle="", markersize=8,
               markerfacecolor=colour, markeredgecolor=SURFACE, label=name.title())
        for name, colour in KIND_COLOURS.items()
    ]
    ax.legend(handles=handles, loc="upper center", bbox_to_anchor=(0.5, -0.02), ncol=5)

    n_attackers = sum(1 for n in nodes if n.get("is_attacker"))
    ax.set_title(
        title
        or f"IoT-edge-cloud topology: {len(nodes)} nodes, {len(links)} links, "
           f"{n_attackers} compromised"
    )
    ax.set_xlim(-0.22, 1.06)
    ax.set_ylim(-0.55, max_tier + 0.45)
    ax.axis("off")
    return _finish(fig, path, engine_note(result))


# --------------------------------------------------------------------------- #
# 2-5. network QoS time series
# --------------------------------------------------------------------------- #
def _attack_bounds(result: Any) -> tuple[float | None, float | None]:
    """Return the attack interval from a run summary, or ``(None, None)``."""
    attack = dict(result.summary.get("attack", {}) or {})
    if not attack.get("enabled"):
        return None, None
    return float(attack.get("start_s", 0.0)), float(attack.get("end_s", 0.0))


def plot_network_timeseries(
    result: Any,
    path: str | Path,
    first_mitigation_s: float | None = None,
) -> Path:
    """Plot throughput, latency, loss and packet rate as stacked panels.

    Four measures with four different units share one x-axis as separate panels
    rather than being crammed onto twin y-axes.

    Args:
        result: The simulation run.
        path: Destination path.
        first_mitigation_s: Time of the first mitigation action, if any.

    Returns:
        The written path.

    Raises:
        ValueError: If the run has no window metrics.
    """
    apply_style()
    frame = pd.DataFrame(result.windows)
    if frame.empty:
        raise ValueError(f"Run '{result.run_id}' has no window metrics to plot.")

    t = frame["t_end"].to_numpy(dtype=float)
    start, end = _attack_bounds(result)

    fig, axes = plt.subplots(4, 1, figsize=(9.5, 9.0), sharex=True)

    window_s = (frame["t_end"] - frame["t_start"]).clip(lower=1e-9)
    axes[0].plot(t, frame["pps"], color=CATEGORICAL[0], label="Offered")
    axes[0].plot(t, frame["delivered_packets"] / window_s, color=CATEGORICAL[2],
                 label="Delivered")
    axes[0].plot(t, frame["dropped_packets"] / window_s, color=CATEGORICAL[7],
                 label="Dropped")
    axes[0].set_ylabel("Packets / s")
    axes[0].set_title("Packet rate: offered, delivered and dropped")

    axes[1].plot(t, frame["throughput_mbps"], color=CATEGORICAL[0],
                 label="Upstream goodput at cloud")
    axes[1].plot(t, frame["offered_mbps"], color=CATEGORICAL[1], linestyle=":",
                 label="Offered load")
    axes[1].set_ylabel("Mbit/s")
    axes[1].set_title("Throughput vs offered load")

    axes[2].plot(t, frame["mean_latency_ms"], color=CATEGORICAL[0], label="All traffic")
    if "legit_mean_latency_ms" in frame:
        axes[2].plot(t, frame["legit_mean_latency_ms"], color=CATEGORICAL[2],
                     label="Legitimate traffic")
    axes[2].plot(t, frame["p95_latency_ms"], color=CATEGORICAL[1], linestyle=":",
                 label="p95")
    axes[2].set_ylabel("End-to-end delay (ms)")
    axes[2].set_title("Latency")

    axes[3].plot(t, 100.0 * frame["loss_ratio"], color=CATEGORICAL[0], label="All traffic")
    axes[3].plot(t, 100.0 * frame["legit_loss_ratio"], color=CATEGORICAL[7],
                 label="Legitimate traffic")
    axes[3].set_ylabel("Packet loss (%)")
    axes[3].set_xlabel("Simulated time (s)")
    axes[3].set_title("Packet loss")

    for i, ax in enumerate(axes):
        _shade_attack(ax, start, end, label=(i == 0))
        _mark_mitigation(ax, first_mitigation_s, label=(i == 0))
        _despine(ax)
        ax.legend(loc="upper left", ncol=2)

    fig.suptitle(
        f"Network performance - {result.meta.get('experiment', result.run_id)}",
        fontsize=13, fontweight="semibold", y=0.995,
    )
    fig.tight_layout(rect=(0, 0.015, 1, 0.985))
    return _finish(fig, path, engine_note(result))


def plot_single_metric(
    result: Any,
    column: str,
    ylabel: str,
    title: str,
    path: str | Path,
    first_mitigation_s: float | None = None,
    scale: float = 1.0,
    secondary: str | None = None,
    secondary_label: str = "",
) -> Path:
    """Plot one window metric over time.

    Args:
        result: The simulation run.
        column: Metric column to plot.
        ylabel: Y-axis label.
        title: Plot title.
        path: Destination path.
        first_mitigation_s: Time of the first mitigation action, if any.
        scale: Multiplier applied to the values (e.g. 100 for percentages).
        secondary: Optional second column on the *same* scale and unit.
        secondary_label: Legend label for the second series.

    Returns:
        The written path.

    Raises:
        KeyError: If *column* is absent from the run's window metrics.
    """
    apply_style()
    frame = pd.DataFrame(result.windows)
    if column not in frame.columns:
        raise KeyError(f"Window metrics have no column '{column}'.")

    t = frame["t_end"].to_numpy(dtype=float)
    start, end = _attack_bounds(result)

    fig, ax = plt.subplots(figsize=(8.6, 3.9))
    _shade_attack(ax, start, end)
    ax.plot(t, frame[column].to_numpy(dtype=float) * scale, color=CATEGORICAL[0],
            marker="o", markersize=4, label=ylabel)
    if secondary and secondary in frame.columns:
        ax.plot(t, frame[secondary].to_numpy(dtype=float) * scale,
                color=CATEGORICAL[7], marker="s", markersize=4,
                label=secondary_label or secondary)
    _mark_mitigation(ax, first_mitigation_s)

    ax.set_xlabel("Simulated time (s)")
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.legend(loc="best")
    _despine(ax)
    fig.tight_layout()
    return _finish(fig, path, engine_note(result))


# --------------------------------------------------------------------------- #
# 6. confusion matrices
# --------------------------------------------------------------------------- #
def plot_confusion_matrices(
    bundles: Sequence[Any], path: str | Path, note: str = ""
) -> Path:
    """Draw one row-normalised confusion matrix per detector.

    Args:
        bundles: :class:`~netshield.evaluation.metrics.DetectionMetrics` list.
        path: Destination path.
        note: Provenance caption.

    Returns:
        The written path.

    Raises:
        ValueError: If no bundles were supplied.
    """
    apply_style()
    if not bundles:
        raise ValueError("No metric bundles supplied for the confusion matrix figure.")

    fig, axes = plt.subplots(1, len(bundles), figsize=(4.3 * len(bundles), 4.1))
    if len(bundles) == 1:
        axes = [axes]

    for ax, bundle in zip(axes, bundles):
        matrix = np.asarray(bundle.confusion, dtype=float)
        totals = matrix.sum(axis=1, keepdims=True)
        normalised = np.divide(matrix, np.where(totals > 0, totals, 1.0))
        ax.imshow(normalised, cmap=SEQUENTIAL_BLUE, vmin=0.0, vmax=1.0)

        for i in range(matrix.shape[0]):
            for j in range(matrix.shape[1]):
                value = normalised[i, j]
                ax.text(j, i, f"{int(matrix[i, j])}\n{value * 100:.0f}%",
                        ha="center", va="center", fontsize=8.5,
                        color=SURFACE if value > 0.55 else INK)

        ax.set_xticks(range(len(CLASS_NAMES)))
        ax.set_yticks(range(len(CLASS_NAMES)))
        ax.set_xticklabels([c[:4].title() for c in CLASS_NAMES])
        ax.set_yticklabels([c[:4].title() for c in CLASS_NAMES])
        ax.set_xlabel("Predicted")
        ax.set_ylabel("True")
        ax.set_title(
            f"{DETECTOR_LABELS.get(bundle.detector, bundle.detector)}\n"
            f"macro-F1 {bundle.macro_f1:.3f}"
        )
        ax.grid(False)

    fig.suptitle("Confusion matrices (counts and row-normalised)",
                 fontsize=12, fontweight="semibold")
    fig.tight_layout(rect=(0, 0.02, 1, 0.96))
    return _finish(fig, path, note)


# --------------------------------------------------------------------------- #
# 7. ROC / PR
# --------------------------------------------------------------------------- #
def plot_roc_curves(
    bundles: Sequence[Any], path: str | Path, note: str = ""
) -> Path | None:
    """Plot binary (benign vs hostile) ROC curves for every detector.

    Args:
        bundles: Metric bundles carrying ``roc`` points.
        path: Destination path.
        note: Provenance caption.

    Returns:
        The written path, or ``None`` when no bundle contained a usable curve
        (which happens when a split has only one class - reported, not faked).
    """
    apply_style()
    usable = [b for b in bundles if b.roc.get("fpr")]
    if not usable:
        _LOG.warning("No ROC curves available (single-class split); figure skipped.")
        return None

    fig, ax = plt.subplots(figsize=(5.6, 5.2))
    ax.plot([0, 1], [0, 1], color=INK_MUTED, linestyle=":", linewidth=1.2,
            label="Chance")
    for bundle in usable:
        auc = bundle.binary.get("roc_auc", float("nan"))
        ax.plot(bundle.roc["fpr"], bundle.roc["tpr"],
                color=DETECTOR_COLOURS.get(bundle.detector, CATEGORICAL[0]),
                label=f"{DETECTOR_LABELS.get(bundle.detector, bundle.detector)} "
                      f"(AUC {auc:.3f})")
    ax.set_xlabel("False-positive rate")
    ax.set_ylabel("True-positive rate")
    ax.set_title("ROC - benign vs hostile node-window")
    ax.set_xlim(-0.02, 1.02)
    ax.set_ylim(-0.02, 1.02)
    ax.legend(loc="lower right")
    _despine(ax)
    fig.tight_layout()
    return _finish(fig, path, note)


def plot_pr_curves(
    bundles: Sequence[Any], path: str | Path, note: str = ""
) -> Path | None:
    """Plot precision-recall curves. Returns ``None`` when unavailable."""
    apply_style()
    usable = [b for b in bundles if b.pr.get("recall")]
    if not usable:
        _LOG.warning("No PR curves available; figure skipped.")
        return None

    fig, ax = plt.subplots(figsize=(5.6, 5.2))
    for bundle in usable:
        auc = bundle.binary.get("pr_auc", float("nan"))
        ax.plot(bundle.pr["recall"], bundle.pr["precision"],
                color=DETECTOR_COLOURS.get(bundle.detector, CATEGORICAL[0]),
                label=f"{DETECTOR_LABELS.get(bundle.detector, bundle.detector)} "
                      f"(AP {auc:.3f})")
    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_title("Precision-recall - hostile node-window")
    ax.set_ylim(-0.02, 1.02)
    ax.legend(loc="lower left")
    _despine(ax)
    fig.tight_layout()
    return _finish(fig, path, note)


# --------------------------------------------------------------------------- #
# 8-9. detector comparison
# --------------------------------------------------------------------------- #
def plot_detector_comparison(
    bundles: Sequence[Any], path: str | Path, note: str = ""
) -> Path:
    """Grouped bars comparing precision, recall, F1, accuracy and FPR.

    FPR is plotted on its own panel because "lower is better" reverses the
    reading direction, and because it lives on a different scale from the rest.

    Args:
        bundles: Metric bundles.
        path: Destination path.
        note: Provenance caption.

    Returns:
        The written path.

    Raises:
        ValueError: If no bundles were supplied.
    """
    apply_style()
    if not bundles:
        raise ValueError("No metric bundles supplied for the comparison figure.")

    metrics = [
        ("Accuracy", lambda b: b.accuracy),
        ("Macro-F1", lambda b: b.macro_f1),
        ("Attack precision", lambda b: b.binary.get("precision", 0.0)),
        ("Attack recall", lambda b: b.binary.get("recall", 0.0)),
        ("Attack F1", lambda b: b.binary.get("f1", 0.0)),
    ]

    fig, (ax, ax_fpr) = plt.subplots(
        1, 2, figsize=(11.5, 4.3), gridspec_kw={"width_ratios": [3, 1]}
    )

    x = np.arange(len(metrics))
    n = len(bundles)
    width = 0.8 / n
    for i, bundle in enumerate(bundles):
        values = [fn(bundle) for _, fn in metrics]
        offset = (i - (n - 1) / 2) * width
        bars = ax.bar(x + offset, values, width * 0.9,
                      color=DETECTOR_COLOURS.get(bundle.detector, CATEGORICAL[i % 8]),
                      label=DETECTOR_LABELS.get(bundle.detector, bundle.detector),
                      edgecolor=SURFACE, linewidth=1.5)
        for bar, value in zip(bars, values):
            ax.annotate(f"{value:.2f}", (bar.get_x() + bar.get_width() / 2, value),
                        textcoords="offset points", xytext=(0, 3), ha="center",
                        fontsize=7.5, color=INK_SECONDARY)

    ax.set_xticks(x)
    ax.set_xticklabels([name for name, _ in metrics])
    ax.set_ylim(0, 1.12)
    ax.set_ylabel("Score (higher is better)")
    ax.set_title("Detection quality")
    ax.legend(loc="lower right", ncol=min(3, n))
    _despine(ax)

    fpr_values = [b.binary.get("false_positive_rate", 0.0) * 100 for b in bundles]
    colours = [DETECTOR_COLOURS.get(b.detector, CATEGORICAL[0]) for b in bundles]
    bars = ax_fpr.bar(range(len(bundles)), fpr_values, 0.6, color=colours,
                      edgecolor=SURFACE, linewidth=1.5)
    for bar, value in zip(bars, fpr_values):
        ax_fpr.annotate(f"{value:.2f}%", (bar.get_x() + bar.get_width() / 2, value),
                        textcoords="offset points", xytext=(0, 3), ha="center",
                        fontsize=8, color=INK_SECONDARY)
    ax_fpr.set_xticks(range(len(bundles)))
    ax_fpr.set_xticklabels(
        [DETECTOR_LABELS.get(b.detector, b.detector).split()[0] for b in bundles],
        rotation=0,
    )
    ax_fpr.set_ylabel("False-positive rate (%)")
    ax_fpr.set_title("False alarms (lower is better)")
    _despine(ax_fpr)

    fig.suptitle("Detector comparison on the held-out test split",
                 fontsize=12.5, fontweight="semibold")
    fig.tight_layout(rect=(0, 0.02, 1, 0.94))
    return _finish(fig, path, note)


def plot_per_experiment_f1(
    rows: Sequence[Mapping[str, Any]], path: str | Path, note: str = ""
) -> Path | None:
    """Grouped bars of macro-F1 per experiment per detector.

    This is the figure that shows *where* each detector wins or loses, which a
    single aggregate score hides.

    Args:
        rows: Per-experiment headline dicts with ``detector``, ``split`` and
            ``macro_f1`` keys.
        path: Destination path.
        note: Provenance caption.

    Returns:
        The written path, or ``None`` when there is nothing to plot.
    """
    apply_style()
    frame = pd.DataFrame(list(rows))
    if frame.empty:
        return None

    experiments = sorted(frame["split"].unique())
    detectors = [d for d in ("threshold", "random_forest", "graphsage")
                 if d in set(frame["detector"])]
    if not detectors:
        detectors = sorted(frame["detector"].unique())

    fig, ax = plt.subplots(figsize=(max(8.0, 1.5 * len(experiments)), 4.4))
    x = np.arange(len(experiments))
    width = 0.8 / len(detectors)

    for i, detector in enumerate(detectors):
        subset = frame[frame["detector"] == detector].set_index("split")
        values = [float(subset["macro_f1"].get(e, np.nan)) for e in experiments]
        offset = (i - (len(detectors) - 1) / 2) * width
        ax.bar(x + offset, values, width * 0.9,
               color=DETECTOR_COLOURS.get(detector, CATEGORICAL[i % 8]),
               label=DETECTOR_LABELS.get(detector, detector),
               edgecolor=SURFACE, linewidth=1.4)

    ax.set_xticks(x)
    ax.set_xticklabels([e.replace("_", "\n", 1) for e in experiments], fontsize=8)
    ax.set_ylabel("Macro-F1")
    ax.set_ylim(0, 1.08)
    ax.set_title("Per-scenario detection quality")
    ax.legend(loc="lower right", ncol=len(detectors))
    _despine(ax)
    fig.tight_layout()
    return _finish(fig, path, note)


# --------------------------------------------------------------------------- #
# 10. attack / mitigation recovery
# --------------------------------------------------------------------------- #
def plot_attack_recovery(
    result: Any,
    path: str | Path,
    first_mitigation_s: float | None,
    detection_timeline: pd.DataFrame | None = None,
    note: str = "",
) -> Path:
    """Show the detect-mitigate-recover cycle on one shared time axis.

    Three stacked panels: legitimate goodput, legitimate packet loss and the
    detector's per-window confidence. Because they share the x-axis, the reader
    can line up "the attack starts", "the detector fires", "the rule is
    installed" and "loss returns to baseline" without a caption.

    Args:
        result: The closed-loop simulation run.
        path: Destination path.
        first_mitigation_s: Time of the first installed rule.
        detection_timeline: Optional frame with ``t_end`` and
            ``max_probability`` columns.
        note: Provenance caption.

    Returns:
        The written path.

    Raises:
        ValueError: If the run has no window metrics.
    """
    apply_style()
    frame = pd.DataFrame(result.windows)
    if frame.empty:
        raise ValueError("Run has no window metrics; cannot draw the recovery figure.")

    t = frame["t_end"].to_numpy(dtype=float)
    start, end = _attack_bounds(result)
    panels = 3 if detection_timeline is not None and not detection_timeline.empty else 2

    fig, axes = plt.subplots(panels, 1, figsize=(9.5, 3.0 * panels), sharex=True)
    axes = np.atleast_1d(axes)

    goodput = ("clean_throughput_pps" if "clean_throughput_pps" in frame
               else "legit_throughput_pps")
    loss = "clean_loss_ratio" if "clean_loss_ratio" in frame else "legit_loss_ratio"

    axes[0].plot(t, frame[goodput], color=CATEGORICAL[2],
                 marker="o", markersize=3.5,
                 label="Delivered pkt/s from never-compromised devices")
    axes[0].set_ylabel("Clean goodput (pkt/s)")
    axes[0].set_title("Service level experienced by uncompromised devices")

    axes[1].plot(t, 100.0 * frame[loss], color=CATEGORICAL[7],
                 marker="o", markersize=3.5, label="Loss, uncompromised devices")
    axes[1].set_ylabel("Clean loss (%)")
    axes[1].set_title("Collateral damage to uncompromised traffic")

    if panels == 3:
        timeline = detection_timeline
        axes[2].plot(timeline["t_end"], timeline["max_probability"],
                     color=CATEGORICAL[0], marker="o", markersize=3.5,
                     label="Max node P(hostile)")
        axes[2].axhline(0.8, color=INK_MUTED, linestyle=":", linewidth=1.2,
                        label="Mitigation trigger")
        axes[2].set_ylim(-0.03, 1.05)
        axes[2].set_ylabel("Detector confidence")
        axes[2].set_title("GNN confidence per window")

    axes[-1].set_xlabel("Simulated time (s)")
    for i, ax in enumerate(axes):
        _shade_attack(ax, start, end, label=(i == 0))
        _mark_mitigation(ax, first_mitigation_s, label=(i == 0))
        _despine(ax)
        ax.legend(loc="best", ncol=2)

    fig.suptitle("Attack, detection, mitigation and recovery",
                 fontsize=12.5, fontweight="semibold")
    fig.tight_layout(rect=(0, 0.015, 1, 0.96))
    return _finish(fig, path, note or engine_note(result))


def plot_phase_comparison(
    recovery: Mapping[str, Any], path: str | Path, note: str = ""
) -> Path | None:
    """Bar chart comparing NORMAL / UNDER ATTACK / AFTER MITIGATION.

    Args:
        recovery: The mapping returned by
            :func:`netshield.detection.pipeline.recovery_metrics`.
        path: Destination path.
        note: Provenance caption.

    Returns:
        The written path, or ``None`` if any phase is missing.
    """
    apply_style()
    phases = [("Normal", recovery.get("baseline")),
              ("Under attack\n(unmitigated)", recovery.get("under_attack")),
              ("Mitigated\n(attack ongoing)", recovery.get("after_mitigation"))]
    if any(not block for _, block in phases):
        _LOG.warning("Phase comparison skipped: a phase has no windows.")
        return None

    measures = [
        ("Clean goodput\n(pkt/s)", "clean_throughput_pps", 1.0),
        ("Clean latency\n(ms)", "clean_mean_latency_ms", 1.0),
        ("Clean loss\n(%)", "clean_loss_ratio", 100.0),
        ("Uplink use\n(%)", "uplink_utilisation", 100.0),
    ]
    colours = [CATEGORICAL[2], CATEGORICAL[7], CATEGORICAL[0]]

    fig, axes = plt.subplots(1, len(measures), figsize=(3.1 * len(measures), 3.9))
    for ax, (label, key, scale) in zip(axes, measures):
        values = [float(block.get(key, 0.0)) * scale for _, block in phases]
        bars = ax.bar(range(3), values, 0.62, color=colours, edgecolor=SURFACE,
                      linewidth=1.5)
        for bar, value in zip(bars, values):
            ax.annotate(f"{value:.3g}", (bar.get_x() + bar.get_width() / 2, value),
                        textcoords="offset points", xytext=(0, 3), ha="center",
                        fontsize=8, color=INK_SECONDARY)
        ax.set_xticks(range(3))
        ax.set_xticklabels([p for p, _ in phases], fontsize=7.8, rotation=18,
                           ha="right")
        ax.set_title(label, fontsize=9.5)
        _despine(ax)

    recovery_s = recovery.get("recovery_time_s")
    suffix = f" - recovery in {recovery_s:.1f} s" if recovery_s is not None else ""
    fig.suptitle(f"Network state by phase{suffix}", fontsize=12.5,
                 fontweight="semibold")
    fig.tight_layout(rect=(0, 0.02, 1, 0.93))
    return _finish(fig, path, note)


# --------------------------------------------------------------------------- #
# 11. graph structure
# --------------------------------------------------------------------------- #
def plot_window_graph(
    graph: Any, path: str | Path, note: str = "", title: str | None = None
) -> Path:
    """Draw one window graph with nodes coloured by ground-truth class.

    Args:
        graph: A :class:`~netshield.graph.builder.WindowGraph`.
        path: Destination path.
        note: Provenance caption.
        title: Optional title override.

    Returns:
        The written path.
    """
    apply_style()
    import networkx as nx

    from ..graph.builder import to_networkx

    nx_graph = to_networkx(graph, include_features=False)
    undirected = nx_graph.to_undirected()
    positions = nx.spring_layout(undirected, seed=7, k=0.9, iterations=200)

    fig, ax = plt.subplots(figsize=(8.4, 6.6))
    for u, v, data in undirected.edges(data=True):
        x1, y1 = positions[u]
        x2, y2 = positions[v]
        physical = data.get("edge_type") == "physical"
        ax.plot([x1, x2], [y1, y2],
                color=GRID if physical else "#cfd8e6",
                linewidth=0.7 if physical else 0.5 + 0.35 * float(data.get("weight", 1.0)),
                linestyle="-" if physical else ":", zorder=1)

    for node, (x, y) in positions.items():
        attrs = nx_graph.nodes[node]
        label_name = attrs.get("label_name", "BENIGN")
        kind = attrs.get("kind", "iot")
        size = {"cloud": 300, "gateway": 250, "router": 180}.get(kind, 85)
        ax.scatter([x], [y], s=size, color=CLASS_COLOURS.get(label_name, CATEGORICAL[2]),
                   edgecolor=SURFACE, linewidth=1.5, zorder=3)
        if kind in ("cloud", "gateway", "router"):
            ax.annotate(node, (x, y), textcoords="offset points", xytext=(0, 12),
                        ha="center", fontsize=7.5, color=INK)

    handles = [Patch(facecolor=colour, edgecolor=SURFACE, label=name)
               for name, colour in CLASS_COLOURS.items()]
    handles += [
        Line2D([0], [0], color=GRID, linestyle="-", label="Physical link"),
        Line2D([0], [0], color="#cfd8e6", linestyle=":", label="Observed communication"),
    ]
    ax.legend(handles=handles, loc="upper center", bbox_to_anchor=(0.5, -0.01), ncol=5)
    ax.set_title(
        title
        or f"Window graph - {graph.experiment}, window {graph.window} "
           f"(t={graph.t_start:.0f}s): {graph.n_nodes} nodes, {graph.n_edges} edges"
    )
    ax.axis("off")
    fig.tight_layout()
    return _finish(fig, path, note)


# --------------------------------------------------------------------------- #
# 12. fuzzing
# --------------------------------------------------------------------------- #
def plot_fuzzing_distribution(
    frame: pd.DataFrame, path: str | Path, note: str = ""
) -> Path | None:
    """Show the parameter distribution explored by a fuzzing campaign.

    Args:
        frame: A frame from :func:`netshield.fuzzing.engine.cases_to_frame`.
        path: Destination path.
        note: Provenance caption.

    Returns:
        The written path, or ``None`` if no numeric parameters were varied.
    """
    apply_style()
    if frame.empty:
        return None

    numeric = [
        c for c in frame.columns
        if c.startswith(("attack.", "simulation."))
        and pd.api.types.is_numeric_dtype(frame[c])
        and frame[c].nunique() > 1
    ]
    if not numeric:
        _LOG.warning("Fuzzing figure skipped: no varying numeric parameters.")
        return None

    numeric = numeric[:6]
    cols = min(3, len(numeric))
    rows = int(np.ceil(len(numeric) / cols))
    fig, axes = plt.subplots(rows, cols, figsize=(4.0 * cols, 3.1 * rows))
    axes = np.atleast_1d(axes).ravel()

    for ax, column in zip(axes, numeric):
        values = frame[column].dropna().to_numpy(dtype=float)
        bins = min(14, max(4, int(np.sqrt(len(values)) * 2)))
        ax.hist(values, bins=bins, color=CATEGORICAL[0], edgecolor=SURFACE,
                linewidth=1.2)
        ax.set_title(column.split(".")[-1].replace("_", " "), fontsize=9.5)
        ax.set_ylabel("Cases")
        _despine(ax)
    for ax in axes[len(numeric):]:
        ax.set_visible(False)

    campaign = frame["campaign"].iloc[0] if "campaign" in frame else "campaign"
    fig.suptitle(f"Fuzzing parameter coverage - {campaign} ({len(frame)} cases)",
                 fontsize=12.5, fontweight="semibold")
    fig.tight_layout(rect=(0, 0.02, 1, 0.94))
    return _finish(fig, path, note)


def plot_fuzz_robustness(
    frame: pd.DataFrame,
    x_column: str,
    path: str | Path,
    note: str = "",
    title: str = "Detector robustness across fuzzed attack parameters",
) -> Path | None:
    """Plot detector recall against a swept fuzzing parameter.

    Args:
        frame: Long-form frame with ``detector``, *x_column* and ``recall``.
        x_column: The swept parameter column.
        path: Destination path.
        note: Provenance caption.
        title: Plot title.

    Returns:
        The written path, or ``None`` if the data is unusable.
    """
    apply_style()
    if frame.empty or x_column not in frame.columns or "recall" not in frame.columns:
        return None

    fig, ax = plt.subplots(figsize=(8.4, 4.3))
    for detector, group in frame.groupby("detector"):
        group = group.sort_values(x_column)
        ax.plot(group[x_column], group["recall"], marker="o",
                color=DETECTOR_COLOURS.get(str(detector), CATEGORICAL[0]),
                label=DETECTOR_LABELS.get(str(detector), str(detector)))
    ax.set_xlabel(x_column.split(".")[-1].replace("_", " "))
    ax.set_ylabel("Attacker recall")
    ax.set_ylim(-0.03, 1.05)
    ax.set_title(title)
    ax.legend(loc="lower right")
    _despine(ax)
    fig.tight_layout()
    return _finish(fig, path, note)


# --------------------------------------------------------------------------- #
# extras: training history, feature importance, detection metrics summary
# --------------------------------------------------------------------------- #
def plot_training_history(
    history: Mapping[str, Sequence[float]], path: str | Path, note: str = ""
) -> Path | None:
    """Plot the GNN's loss and macro-F1 curves as stacked panels."""
    apply_style()
    loss = list(history.get("loss", []))
    if not loss:
        return None

    fig, axes = plt.subplots(2, 1, figsize=(7.8, 5.4), sharex=True)
    epochs = np.arange(1, len(loss) + 1)
    axes[0].plot(epochs, loss, color=CATEGORICAL[0], label="Training loss")
    axes[0].set_ylabel("Cross-entropy")
    axes[0].set_title("GraphSAGE training")

    train_f1 = [v for v in history.get("train_f1", []) if v is not None]
    val_f1 = [v for v in history.get("val_f1", []) if v is not None]
    if train_f1:
        axes[1].plot(np.arange(1, len(train_f1) + 1), train_f1,
                     color=CATEGORICAL[0], label="Train macro-F1")
    if val_f1:
        axes[1].plot(np.arange(1, len(val_f1) + 1), val_f1,
                     color=CATEGORICAL[1], label="Validation macro-F1")
    axes[1].set_ylim(-0.03, 1.05)
    axes[1].set_ylabel("Macro-F1")
    axes[1].set_xlabel("Epoch")

    for ax in axes:
        ax.legend(loc="best")
        _despine(ax)
    fig.tight_layout()
    return _finish(fig, path, note)


def plot_feature_importance(
    importances: Mapping[str, float], path: str | Path, top_n: int = 18, note: str = ""
) -> Path | None:
    """Horizontal bars of the Random Forest's most informative features."""
    apply_style()
    if not importances:
        return None
    ordered = sorted(importances.items(), key=lambda kv: kv[1], reverse=True)[:top_n]
    names = [k for k, _ in ordered][::-1]
    values = [v for _, v in ordered][::-1]

    fig, ax = plt.subplots(figsize=(7.6, 0.32 * len(names) + 1.4))
    ax.barh(names, values, color=CATEGORICAL[2], edgecolor=SURFACE, linewidth=1.2)
    ax.set_xlabel("Gini importance")
    ax.set_title(f"Most informative flow features (Random Forest, top {len(names)})")
    ax.grid(axis="y", visible=False)
    _despine(ax)
    fig.tight_layout()
    return _finish(fig, path, note)


def plot_detection_metrics_summary(
    bundles: Sequence[Any],
    latency: Mapping[str, Mapping[str, Any]],
    path: str | Path,
    note: str = "",
) -> Path:
    """Combine the headline scores and the measured detection latency.

    Args:
        bundles: Metric bundles.
        latency: ``{detector: latency_report}`` from
            :func:`netshield.evaluation.metrics.detection_latency`.
        path: Destination path.
        note: Provenance caption.

    Returns:
        The written path.
    """
    apply_style()
    fig, (ax_scores, ax_latency) = plt.subplots(
        1, 2, figsize=(11.0, 4.2), gridspec_kw={"width_ratios": [2, 1]}
    )

    names = [DETECTOR_LABELS.get(b.detector, b.detector) for b in bundles]
    colours = [DETECTOR_COLOURS.get(b.detector, CATEGORICAL[0]) for b in bundles]
    measures = [("Macro-F1", [b.macro_f1 for b in bundles]),
                ("Attack recall", [b.binary.get("recall", 0.0) for b in bundles]),
                ("Attack precision", [b.binary.get("precision", 0.0) for b in bundles])]

    x = np.arange(len(measures))
    width = 0.8 / max(1, len(bundles))
    for i, (name, colour) in enumerate(zip(names, colours)):
        values = [series[i] for _, series in measures]
        ax_scores.bar(x + (i - (len(bundles) - 1) / 2) * width, values, width * 0.9,
                      color=colour, label=name, edgecolor=SURFACE, linewidth=1.4)
    ax_scores.set_xticks(x)
    ax_scores.set_xticklabels([m for m, _ in measures])
    ax_scores.set_ylim(0, 1.1)
    ax_scores.set_ylabel("Score")
    ax_scores.set_title("Detection quality")
    ax_scores.legend(loc="lower right")
    _despine(ax_scores)

    lat_values: list[float] = []
    lat_names: list[str] = []
    lat_colours: list[str] = []
    for bundle in bundles:
        report = latency.get(bundle.detector, {})
        mean = report.get("mean_latency_s")
        if mean is None:
            continue
        lat_values.append(float(mean))
        lat_names.append(DETECTOR_LABELS.get(bundle.detector, bundle.detector).split()[0])
        lat_colours.append(DETECTOR_COLOURS.get(bundle.detector, CATEGORICAL[0]))

    if lat_values:
        bars = ax_latency.bar(range(len(lat_values)), lat_values, 0.6,
                              color=lat_colours, edgecolor=SURFACE, linewidth=1.4)
        for bar, value in zip(bars, lat_values):
            ax_latency.annotate(f"{value:.1f}s",
                                (bar.get_x() + bar.get_width() / 2, value),
                                textcoords="offset points", xytext=(0, 3),
                                ha="center", fontsize=8, color=INK_SECONDARY)
        ax_latency.set_xticks(range(len(lat_names)))
        ax_latency.set_xticklabels(lat_names)
    else:
        ax_latency.text(0.5, 0.5, "No attack detected\nin the scored split",
                        ha="center", va="center", color=INK_MUTED,
                        transform=ax_latency.transAxes)
    ax_latency.set_ylabel("Mean detection latency (s)")
    ax_latency.set_title("Time to first detection")
    _despine(ax_latency)

    fig.suptitle("Detection performance summary", fontsize=12.5, fontweight="semibold")
    fig.tight_layout(rect=(0, 0.02, 1, 0.93))
    return _finish(fig, path, note)


def save_figure_index(paths: Iterable[Path | None], path: str | Path) -> Path:
    """Write a JSON index of every figure that was actually produced."""
    produced = [str(Path(p).name) for p in paths if p is not None]
    target = Path(path)
    ensure_dir(target.parent)
    target.write_text(json.dumps({"figures": produced}, indent=2), encoding="utf-8")
    return target
