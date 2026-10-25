"""Declarative experiment grids executed in parallel.

A grid is a list of :class:`RunSpec` - (scenario, topology family, seed
offset, extra overrides, optional closed-loop detector). Every spec maps to a
deterministic ``run_id`` (a hash of the exact configuration), so a grid can be
interrupted and resumed: completed runs are found on disk and skipped.

Runs execute in separate processes because the discrete-event engine is
pure Python and single-threaded; on a 12-core laptop this is the difference
between an hour and five minutes for the full research grid.
"""

from __future__ import annotations

import json
import os
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from ..utils.logging_utils import get_logger

_LOG = get_logger(__name__)

#: Topology families of the suite and the experiment that defines each one's
#: structural parameters (taken verbatim from ``config/experiments.yaml``).
TOPOLOGY_SOURCES: dict[str, str | None] = {
    "tree": None,
    "star": "exp9_star",
    "multi_gateway": "exp10_multi_gateway",
    "dumbbell": "exp11_dumbbell",
    "fat_tree": "exp12_fat_tree",
    "mesh": "exp13_mesh",
    "ring": "exp14_ring",
}

#: Scenario -> attack family label used by leave-one-family-out CV.
SCENARIO_FAMILY: dict[str, str] = {
    "exp1_normal": "benign",
    "exp2_udp_flood": "udp_flood",
    "exp3_syn_flood": "syn_flood",
    "exp4_http_flood": "http_flood",
    "exp5_distributed": "udp_flood",
    "exp6_fuzzed": "mixed",
    "exp15_icmp_flood": "icmp_flood",
    "exp16_ack_flood": "ack_flood",
    "exp17_slowloris": "slowloris",
    "exp18_ramp": "udp_flood",
    "exp19_multivector": "mixed",
    "exp20_flash_crowd": "benign_stress",
    "exp21_firmware_storm": "benign_stress",
    "exp22_reboot_storm": "benign_stress",
}


@dataclass(slots=True)
class RunSpec:
    """One simulation to execute.

    Attributes:
        scenario: Experiment name in ``config/experiments.yaml``.
        topology: Topology family override, or ``None`` for the scenario's own.
        seed_offset: Added to the scenario seed (0 = the canonical seed).
        overrides: Extra ``key=value`` assignments applied last.
        closed_loop: Detector name to run in the loop with mitigation armed.
        models_dir: Where the closed-loop detector checkpoint lives.
        group: Free-form grid label stored in the run metadata.
    """

    scenario: str
    topology: str | None = None
    seed_offset: int = 0
    overrides: list[str] = field(default_factory=list)
    closed_loop: str | None = None
    models_dir: str = "models"
    group: str = "grid"

    @property
    def family(self) -> str:
        """Attack family of the scenario."""
        return SCENARIO_FAMILY.get(self.scenario, "other")


def topology_override(name: str, experiments: Mapping[str, Any]) -> dict[str, Any]:
    """Return the ``network.topology`` block that selects topology *name*."""
    if name not in TOPOLOGY_SOURCES:
        raise KeyError(f"Unknown topology family {name!r}; known: {sorted(TOPOLOGY_SOURCES)}")
    source = TOPOLOGY_SOURCES[name]
    if source is None:
        return {"family": "tree"}
    entry = (experiments.get("experiments") or {})[source]
    block = dict(((entry.get("config") or {}).get("network") or {}).get("topology") or {})
    block["family"] = name
    return block


def build_config(spec: RunSpec, experiments: Mapping[str, Any] | None = None):
    """Materialise the :class:`Config` and metadata for *spec*."""
    from ..utils.config import experiment_config, load_experiments  # noqa: PLC0415

    doc = experiments if experiments is not None else load_experiments()
    cfg, meta = experiment_config(spec.scenario, doc)
    if spec.topology:
        # Keep scenario-specific topology settings (e.g. the slowloris
        # connection table) and add the family's structural parameters.
        current = dict((cfg.get("network.topology", {}) or {}))
        current.update(topology_override(spec.topology, doc))
        cfg = cfg.merged({"network": {"topology": current}}, source=f"topology:{spec.topology}")
    assignments = ["simulation.engine=python"]
    if spec.seed_offset:
        assignments.append(f"seed={int(cfg.get('seed', 42)) + int(spec.seed_offset)}")
    if spec.closed_loop:
        assignments.append("mitigation.enabled=true")
        if spec.closed_loop.endswith("_conformal"):
            from ..models.calibration import conformal_policy_overrides  # noqa: PLC0415

            assignments += conformal_policy_overrides()
    cfg = cfg.with_set(assignments + list(spec.overrides))
    meta = {
        **meta,
        "topology_family": spec.topology or str(cfg.get("network.topology.family", "tree")),
        "attack_family": spec.family,
        "grid_group": spec.group,
        "seed_offset": int(spec.seed_offset),
        "closed_loop": spec.closed_loop,
        "overrides": list(spec.overrides),
    }
    return cfg, meta


def _execute(spec_payload: dict[str, Any], root: str, reuse: bool) -> dict[str, Any]:
    """Worker entry point: run one spec (or find it on disk) and save it."""
    try:
        import torch  # noqa: PLC0415

        torch.set_num_threads(1)
    except Exception:  # noqa: BLE001 - torch is optional for pure simulation
        pass
    import logging  # noqa: PLC0415

    logging.getLogger("netshield").setLevel(logging.WARNING)

    from ..simulation.runner import build_run_id, run_simulation  # noqa: PLC0415

    spec = RunSpec(**spec_payload)
    cfg, meta = build_config(spec)
    run_id = build_run_id(cfg, meta)
    run_dir = Path(root) / run_id
    base = {"run_id": run_id, "dir": str(run_dir), **asdict(spec),
            "family": spec.family, "topology_family": meta["topology_family"],
            "seed": int(cfg.get("seed", 42))}
    if reuse and (run_dir / "run.json").exists():
        return {**base, "reused": True, "wall_s": 0.0}

    controller_factory = None
    if spec.closed_loop:
        from ..detection.pipeline import build_controller_factory, load_detectors  # noqa: PLC0415

        if spec.closed_loop.endswith("_conformal"):
            from ..models.calibration import ConformalDetector  # noqa: PLC0415

            detector = ConformalDetector.load(Path(spec.models_dir) / spec.closed_loop)
        else:
            detector = load_detectors(spec.models_dir, [spec.closed_loop], required=True)[
                spec.closed_loop]
        controller_factory = build_controller_factory(detector, cfg, enable_mitigation=True)

    started = time.perf_counter()
    result = run_simulation(cfg, meta, controller_factory=controller_factory)
    result.save(run_dir)
    cfg.save(run_dir / "config_snapshot.yaml")
    return {**base, "reused": False, "wall_s": round(time.perf_counter() - started, 2),
            "truncated": bool(result.summary.get("wall_budget_hit"))}


def run_grid(
    specs: Sequence[RunSpec],
    root: str | Path = "data/experiments",
    workers: int | None = None,
    reuse: bool = True,
    manifest: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Execute *specs* across worker processes.

    Args:
        specs: Runs to execute.
        root: Directory that receives one sub-directory per run.
        workers: Process count (default: CPU count - 1).
        reuse: Skip specs whose run directory already exists.
        manifest: Optional JSON path recording every completed spec.

    Returns:
        One record per spec: run id, directory, spec fields, wall time.
    """
    from ..utils.paths import ensure_dir  # noqa: PLC0415

    root_path = ensure_dir(root)
    n_workers = max(1, workers or (os.cpu_count() or 2) - 1)
    records: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    started = time.perf_counter()
    payloads = [asdict(s) for s in specs]
    with ProcessPoolExecutor(max_workers=n_workers) as pool:
        futures = {pool.submit(_execute, p, str(root_path), reuse): p for p in payloads}
        for i, future in enumerate(as_completed(futures), 1):
            payload = futures[future]
            try:
                record = future.result()
                records.append(record)
                status = "reused" if record["reused"] else f"{record['wall_s']:.1f}s"
                print(f"  [{i:>4}/{len(payloads)}] {payload['scenario']:<22} "
                      f"{str(payload['topology'] or '-'):<14} +{payload['seed_offset']:<3} "
                      f"{status}", flush=True)
            except Exception as exc:  # noqa: BLE001 - keep the grid going
                failures.append({**payload, "error": f"{type(exc).__name__}: {exc}"})
                print(f"  [{i:>4}/{len(payloads)}] FAILED {payload}: {exc}", flush=True)
    elapsed = time.perf_counter() - started
    print(f"  grid: {len(records)} ok, {len(failures)} failed, {elapsed:.0f}s wall, "
          f"{n_workers} workers", flush=True)
    if manifest is not None:
        path = Path(manifest)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"records": records, "failures": failures,
                                    "wall_s": round(elapsed, 1)}, indent=2, default=str),
                        encoding="utf-8")
    return records


def research_grid(
    seeds: int = 3,
    topologies: Iterable[str] = tuple(TOPOLOGY_SOURCES),
    scenarios: Iterable[str] = ("exp1_normal", "exp2_udp_flood", "exp3_syn_flood",
                                "exp4_http_flood", "exp15_icmp_flood", "exp16_ack_flood",
                                "exp17_slowloris"),
    tree_only: Iterable[str] = ("exp5_distributed", "exp6_fuzzed", "exp18_ramp",
                                "exp19_multivector"),
    stress: Iterable[str] = ("exp20_flash_crowd", "exp21_firmware_storm",
                             "exp22_reboot_storm"),
    stress_seeds: int = 2,
    extra_overrides: Sequence[str] = (),
    group: str = "research",
) -> list[RunSpec]:
    """The full research grid: family x topology x seed, plus extras.

    * every attack family on every topology, ``seeds`` seeds each;
    * the tree-only rate-shaping scenarios, ``seeds`` seeds each;
    * the benign-stress scenarios on every topology, ``stress_seeds`` each.
    """
    specs: list[RunSpec] = []
    topologies = list(topologies)
    for scenario in scenarios:
        for topo in topologies:
            for s in range(seeds):
                specs.append(RunSpec(scenario, topo, s, list(extra_overrides), group=group))
    for scenario in tree_only:
        for s in range(seeds):
            specs.append(RunSpec(scenario, "tree", s, list(extra_overrides), group=group))
    for scenario in stress:
        for topo in topologies:
            for s in range(stress_seeds):
                specs.append(RunSpec(scenario, topo, s, list(extra_overrides),
                                     group=f"{group}-stress"))
    return specs
