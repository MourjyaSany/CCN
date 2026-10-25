#!/usr/bin/env python3
"""Performance benchmarks with a portable regression check.

    python scripts/benchmark.py --write benchmarks/baseline.json
    python scripts/benchmark.py --compare benchmarks/baseline.json --tolerance 0.25

Each benchmark is timed (best of ``--repeat``) and divided by a fixed
pure-Python calibration loop measured in the same process, so the stored
numbers are *relative* costs that transfer between machines: a CI runner
that is twice as slow overall is not reported as a regression, while a
change that makes the simulator 30% slower relative to the CPU is.

Benchmarks
----------
``sim_events``      events processed per second, 25 s UDP flood
``features``        node-window feature build for that run
``graph_build``     window-graph construction for that run
``rf_infer``        Random Forest inference per node-window
``sage_infer``      GraphSAGE inference per node-window
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from _bootstrap import setup  # noqa: E402


def _calibrate(n: int = 2_000_000) -> float:
    t = time.perf_counter()
    acc = 0
    for i in range(n):
        acc += i & 7
    return time.perf_counter() - t


def _best(fn, repeat: int) -> float:
    best = float("inf")
    for _ in range(repeat):
        t = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - t)
    return best


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repeat", type=int, default=3)
    ap.add_argument("--write", default=None)
    ap.add_argument("--compare", default=None)
    ap.add_argument("--tolerance", type=float, default=0.25)
    ap.add_argument("--set", dest="overrides", action="append", default=[])
    ap.add_argument("--config", default="config/default.yaml")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--log-level", default="WARNING")
    args = ap.parse_args(argv)
    setup(args, "benchmark")

    from netshield.detection.pipeline import prepare_input  # noqa: PLC0415
    from netshield.features.dataset import FeatureScaler  # noqa: PLC0415
    from netshield.graph.builder import build_graphs  # noqa: PLC0415
    from netshield.models.graphsage import GraphSAGEDetector  # noqa: PLC0415
    from netshield.models.random_forest import RandomForestDetector  # noqa: PLC0415
    from netshield.simulation.runner import run_simulation  # noqa: PLC0415
    from netshield.utils.config import experiment_config, load_experiments  # noqa: PLC0415

    cal = min(_calibrate() for _ in range(3))
    cfg, meta = experiment_config("exp2_udp_flood", load_experiments())
    cfg = cfg.with_set(["simulation.duration_s=25.0", "attack.start_s=8.0",
                        "attack.duration_s=12.0", "simulation.engine=python"])
    holder = {}

    def sim():
        holder["r"] = run_simulation(cfg, meta)

    t_sim = _best(sim, args.repeat)
    result = holder["r"]
    events = int(result.summary["events_processed"])
    data = prepare_input(result, cfg)
    t_feat = _best(lambda: prepare_input(result, cfg), args.repeat)
    scaler = FeatureScaler.fit(data.features)
    t_graph = _best(lambda: build_graphs(data.features, data.edges, scaler), args.repeat)
    rf = RandomForestDetector.from_config(cfg)
    rf.params.update({"n_estimators": 100, "n_jobs": 1})
    rf.fit(data, data)
    sage = GraphSAGEDetector.from_config(cfg)
    sage.hyper.update({"epochs": 2, "patience": 1})
    sage.fit(data, data)
    n = data.n_rows
    t_rf = _best(lambda: rf.predict_proba(data), args.repeat) / n
    t_sage = _best(lambda: sage.predict_proba(data), args.repeat) / n

    raw = {"sim_s_per_mevent": t_sim / events * 1e6, "features_s": t_feat,
           "graph_build_s": t_graph, "rf_us_per_row": t_rf * 1e6,
           "sage_us_per_row": t_sage * 1e6}
    rel = {k: v / cal for k, v in raw.items()}
    report = {"calibration_s": cal, "events": events, "rows": n,
              "events_per_s": events / t_sim, "raw": raw, "relative": rel}
    print(json.dumps(report, indent=2))
    if args.write:
        Path(args.write).parent.mkdir(parents=True, exist_ok=True)
        Path(args.write).write_text(json.dumps(report, indent=2), encoding="utf-8")
    if args.compare:
        base = json.loads(Path(args.compare).read_text(encoding="utf-8"))["relative"]
        worse = {k: rel[k] / base[k] - 1.0 for k in rel if k in base}
        failed = {k: v for k, v in worse.items() if v > args.tolerance}
        for k, v in worse.items():
            print(f"  {k:<20} {v:+.1%} {'REGRESSION' if k in failed else 'ok'}")
        return 1 if failed else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
