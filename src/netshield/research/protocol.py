"""Evaluation protocol: cross-validation designs, parallel training, analysis.

Designs
-------
``seed_cv`` (primary)
    Leave-one-seed-out cross-validation over the research grid. Fold *k*
    tests on seed offset *k* of **every** (scenario, topology) cell and trains
    on the remaining seeds, so the folds are exactly stratified and every run
    is tested exactly once. Pooled out-of-fold predictions then support a
    run-level cluster bootstrap and paired detector comparisons.
``loto``
    Leave-one-topology-out: train on six topology families, test on the
    seventh. Measures structural generalisation as a number rather than as a
    single anecdotal run.
``loafo``
    Leave-one-attack-family-out: the held-out family (and multi-vector runs
    that contain it) never appear in training. Measures zero-day behaviour.
``stress``
    Benign-stress runs (flash crowd, firmware storm, reboot storm) never enter
    training; every model trained in ``seed_cv`` is scored on them, so any
    flag is a false alarm.

Validation rows for early stopping are always carved out of the *training*
runs of the fold (15% of runs, grouped), never from the test runs.

Every (fold, detector) job writes its test probabilities to an ``.npz`` file,
so analysis can be re-run, extended or audited without retraining.
"""

from __future__ import annotations

import json
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Sequence

import numpy as np
import pandas as pd

from ..features.node_features import NODE_FEATURE_COLUMNS
from ..utils.logging_utils import get_logger

_LOG = get_logger(__name__)

STRESS_FAMILY = "benign_stress"
HELD_OUT_FAMILIES: tuple[str, ...] = ("udp_flood", "syn_flood", "http_flood",
                                      "icmp_flood", "ack_flood", "slowloris")

#: Feature groups for drop-one-group ablations (mirrors node_features.py).
FEATURE_GROUPS: dict[str, tuple[str, ...]] = {
    "egress_volume": NODE_FEATURE_COLUMNS[0:7],
    "packet_size": NODE_FEATURE_COLUMNS[7:11],
    "timing": NODE_FEATURE_COLUMNS[11:15],
    "addressing": NODE_FEATURE_COLUMNS[15:20],
    "protocol_mix": NODE_FEATURE_COLUMNS[20:26],
    "tcp_flags": NODE_FEATURE_COLUMNS[26:36],
    "ingress": NODE_FEATURE_COLUMNS[36:43],
    "structural": NODE_FEATURE_COLUMNS[43:46],
}


@dataclass(slots=True)
class Fold:
    """One train/validation/test partition of run ids."""

    design: str
    name: str
    train: list[str]
    val: list[str]
    test: list[str]
    stress: list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.design}__{self.name}"


@dataclass(slots=True)
class Variant:
    """A detector configuration to train in every fold.

    Attributes:
        detector: Registry name (``graphsage``, ``lightgbm``, ...).
        label: Unique label in result tables (defaults to *detector*).
        drop_features: Feature columns removed before training (ablation).
        graph_options: Overrides for the GNN graph builder (ablation).
        hyper: Overrides for the detector's hyper-parameters.
    """

    detector: str
    label: str = ""
    drop_features: list[str] = field(default_factory=list)
    graph_options: dict[str, Any] = field(default_factory=dict)
    hyper: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.label:
            self.label = self.detector


# --------------------------------------------------------------------------- #
# corpus
# --------------------------------------------------------------------------- #
def load_research_corpus(directory: str | Path) -> tuple[pd.DataFrame, pd.DataFrame,
                                                         pd.DataFrame]:
    """Load ``dataset.csv``, ``edges.csv`` and ``runs.csv`` from a grid output."""
    from ..features.dataset import load_dataset  # noqa: PLC0415

    root = Path(directory)
    corpus = load_dataset(root / "dataset.csv")
    edges = pd.read_csv(root / "edges.csv")
    runs = pd.read_csv(root / "runs.csv")
    corpus = corpus.merge(runs[["run_id", "topology_family", "family", "seed_offset",
                                "scenario"]], on="run_id", how="left")
    return corpus, edges, runs


def _val_split(train_runs: Sequence[str], fraction: float, seed: int) -> tuple[list[str],
                                                                              list[str]]:
    rng = np.random.default_rng(seed)
    runs = sorted(train_runs)
    n_val = max(1, int(round(fraction * len(runs))))
    pick = set(rng.choice(len(runs), n_val, replace=False).tolist())
    val = [r for i, r in enumerate(runs) if i in pick]
    train = [r for i, r in enumerate(runs) if i not in pick]
    return train, val


def seed_cv_folds(runs: pd.DataFrame, val_fraction: float = 0.15, seed: int = 7) -> list[Fold]:
    """Leave-one-seed-out folds over the non-stress runs."""
    core = runs[runs["family"] != STRESS_FAMILY]
    stress = runs.loc[runs["family"] == STRESS_FAMILY, "run_id"].tolist()
    folds = []
    for k in sorted(core["seed_offset"].unique()):
        test = core.loc[core["seed_offset"] == k, "run_id"].tolist()
        rest = core.loc[core["seed_offset"] != k, "run_id"].tolist()
        train, val = _val_split(rest, val_fraction, seed + int(k))
        folds.append(Fold("seed_cv", f"seed{k}", train, val, test, stress))
    return folds


def loto_folds(runs: pd.DataFrame, val_fraction: float = 0.15, seed: int = 11) -> list[Fold]:
    """Leave-one-topology-out folds (stress runs excluded)."""
    core = runs[runs["family"] != STRESS_FAMILY]
    folds = []
    for i, topo in enumerate(sorted(core["topology_family"].unique())):
        test = core.loc[core["topology_family"] == topo, "run_id"].tolist()
        rest = core.loc[core["topology_family"] != topo, "run_id"].tolist()
        train, val = _val_split(rest, val_fraction, seed + i)
        folds.append(Fold("loto", topo, train, val, test))
    return folds


def loafo_folds(runs: pd.DataFrame, val_fraction: float = 0.15, seed: int = 13) -> list[Fold]:
    """Leave-one-attack-family-out folds.

    The held-out family's runs form the test set. Multi-vector (``mixed``)
    runs are excluded from training in every fold, because they contain
    several families and would leak the held-out one.
    """
    core = runs[runs["family"] != STRESS_FAMILY]
    folds = []
    for i, family in enumerate(HELD_OUT_FAMILIES):
        if family not in set(core["family"]):
            continue
        test = core.loc[core["family"] == family, "run_id"].tolist()
        rest = core.loc[~core["family"].isin([family, "mixed"]), "run_id"].tolist()
        train, val = _val_split(rest, val_fraction, seed + i)
        folds.append(Fold("loafo", family, train, val, test))
    return folds


# --------------------------------------------------------------------------- #
# job execution
# --------------------------------------------------------------------------- #
_STATE: dict[str, Any] = {}


def _init_worker(corpus_dir: str, threads: int) -> None:
    import logging  # noqa: PLC0415

    import torch  # noqa: PLC0415

    torch.set_num_threads(max(1, threads))
    logging.getLogger("netshield").setLevel(logging.WARNING)
    corpus, edges, _ = load_research_corpus(corpus_dir)
    _STATE["corpus"] = corpus
    _STATE["edges"] = edges


def _subset(run_ids: Sequence[str]) -> pd.DataFrame:
    corpus = _STATE["corpus"]
    return corpus[corpus["run_id"].isin(set(run_ids))].reset_index(drop=True)


def _make_detector(variant: Variant, config: Any) -> Any:
    from ..detection.pipeline import DETECTOR_CLASSES  # noqa: PLC0415

    detector = DETECTOR_CLASSES[variant.detector].from_config(config)
    if variant.drop_features:
        detector.feature_columns = [c for c in detector.feature_columns
                                    if c not in set(variant.drop_features)]
    if variant.graph_options and hasattr(detector, "graph_options"):
        detector.graph_options.update(variant.graph_options)
    for key, value in variant.hyper.items():
        if hasattr(detector, "hyper") and key in detector.hyper:
            detector.hyper[key] = value
        elif hasattr(detector, "params") and key in detector.params:
            detector.params[key] = value
    return detector


def _job(fold_payload: dict[str, Any], variant_payload: dict[str, Any], out_dir: str,
         config_overrides: list[str], save_model: bool) -> dict[str, Any]:
    from ..models.base import DetectionInput  # noqa: PLC0415
    from ..utils.config import load_config  # noqa: PLC0415

    fold = Fold(**fold_payload)
    variant = Variant(**variant_payload)
    target = Path(out_dir) / fold.key / f"{variant.label}.npz"
    if target.exists():
        meta = json.loads(target.with_suffix(".json").read_text(encoding="utf-8"))
        return {**meta, "cached": True}
    config = load_config(set_args=config_overrides) if config_overrides else load_config()
    edges = _STATE["edges"]
    detector = _make_detector(variant, config)
    train = DetectionInput(_subset(fold.train), edges)
    val = DetectionInput(_subset(fold.val), edges)
    started = time.perf_counter()
    report = detector.fit(train, val)
    fit_s = time.perf_counter() - started

    payload: dict[str, np.ndarray] = {}
    timing: dict[str, float] = {}
    for split_name, run_ids in (("test", fold.test), ("stress", fold.stress),
                                ("val", fold.val)):
        if not run_ids:
            continue
        frame = _subset(run_ids)
        t0 = time.perf_counter()
        proba = detector.predict_proba(DetectionInput(frame, edges)).astype(np.float32)
        timing[f"{split_name}_infer_us_per_row"] = (
            (time.perf_counter() - t0) * 1e6 / max(1, len(frame)))
        payload[f"{split_name}_proba"] = proba
        payload[f"{split_name}_label"] = frame["label"].to_numpy(np.int8)
        payload[f"{split_name}_run"] = frame["run_id"].to_numpy(str)
        payload[f"{split_name}_window"] = frame["window"].to_numpy(np.int32)
        payload[f"{split_name}_node"] = frame["node_id"].to_numpy(str)
        payload[f"{split_name}_kind"] = frame["kind"].to_numpy(str)
        payload[f"{split_name}_attacker"] = frame["is_attacker"].to_numpy(bool)
    target.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(target, **payload)
    if save_model:
        detector.save(target.parent / variant.label)
    meta = {"fold": fold.key, "design": fold.design, "fold_name": fold.name,
            "variant": variant.label, "detector": variant.detector,
            "fit_s": round(fit_s, 2), "n_train_rows": train.n_rows,
            "epochs": report.epochs, "best_epoch": report.best_epoch, **timing}
    target.with_suffix(".json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return {**meta, "cached": False}


def run_protocol(
    corpus_dir: str | Path,
    folds: Sequence[Fold],
    variants: Sequence[Variant],
    out_dir: str | Path,
    workers: int = 4,
    threads_per_worker: int = 2,
    config_overrides: Sequence[str] = (),
    save_models: bool = False,
) -> list[dict[str, Any]]:
    """Train and score every (fold, variant) pair across worker processes.

    Graph models are submitted first because they are the slowest jobs,
    which keeps the pool busy until the end.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    jobs = [(f, v) for v in variants for f in folds]
    slow = {"graphsage", "gat", "egraphsage", "temporal_gnn", "gru_seq"}
    jobs.sort(key=lambda fv: 0 if fv[1].detector in slow else 1)
    results: list[dict[str, Any]] = []
    started = time.perf_counter()
    with ProcessPoolExecutor(max_workers=workers, initializer=_init_worker,
                             initargs=(str(corpus_dir), threads_per_worker)) as pool:
        futures = {pool.submit(_job, asdict(f), asdict(v), str(out), list(config_overrides),
                               save_models): (f.key, v.label) for f, v in jobs}
        for i, future in enumerate(as_completed(futures), 1):
            key = futures[future]
            try:
                record = future.result()
                results.append(record)
                tag = "cached" if record.get("cached") else f"fit {record['fit_s']:.0f}s"
                print(f"  [{i:>3}/{len(jobs)}] {key[0]:<26} {key[1]:<28} {tag}", flush=True)
            except Exception as exc:  # noqa: BLE001 - one failed job must not kill the run
                print(f"  [{i:>3}/{len(jobs)}] {key} FAILED: {type(exc).__name__}: {exc}",
                      flush=True)
                results.append({"fold": key[0], "variant": key[1], "error": str(exc)})
    print(f"  protocol: {len(jobs)} jobs in {time.perf_counter() - started:.0f}s", flush=True)
    (out / "jobs.json").write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    return results


# --------------------------------------------------------------------------- #
# analysis
# --------------------------------------------------------------------------- #
def load_predictions(out_dir: str | Path, design: str, variant: str,
                     split: str = "test") -> pd.DataFrame | None:
    """Concatenate one variant's predictions across all folds of *design*."""
    frames = []
    for path in sorted(Path(out_dir).glob(f"{design}__*/{variant}.npz")):
        data = np.load(path, allow_pickle=False)
        if f"{split}_proba" not in data:
            continue
        proba = data[f"{split}_proba"].astype(float)
        frames.append(pd.DataFrame({
            "fold": path.parent.name.split("__", 1)[1],
            "run_id": data[f"{split}_run"], "window": data[f"{split}_window"],
            "node_id": data[f"{split}_node"], "kind": data[f"{split}_kind"],
            "is_attacker": data[f"{split}_attacker"], "label": data[f"{split}_label"],
            "p0": proba[:, 0], "p1": proba[:, 1], "p2": proba[:, 2]}))
    return pd.concat(frames, ignore_index=True) if frames else None


def node_level_detection(pred: pd.DataFrame, trigger: float = 0.8) -> pd.DataFrame:
    """Per-run bot detection counts: bots found and innocent endpoints flagged.

    This is the operator's question ("which devices are compromised?"),
    complementary to the window-level metrics.
    """
    pred = pred.copy()
    pred["hostile"] = pred["p1"] + pred["p2"]
    endpoints = pred[pred["kind"].isin(["iot", "attacker"])]
    rows = []
    for (fold, run), g in endpoints.groupby(["fold", "run_id"]):
        flagged = set(g.loc[g["hostile"] >= trigger, "node_id"])
        bots = set(g.loc[g["is_attacker"], "node_id"])
        clean = set(g["node_id"]) - bots
        rows.append({"fold": fold, "run_id": run, "bots": len(bots),
                     "bots_found": len(bots & flagged), "false_alarm_nodes": len(flagged & clean),
                     "clean_nodes": len(clean)})
    return pd.DataFrame(rows)
