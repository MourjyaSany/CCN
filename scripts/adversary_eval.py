#!/usr/bin/env python3
"""Step 3: adaptive adversary, stealth frontier and adversarial hardening.

    python scripts/adversary_eval.py search      # adaptive search vs every defence
    python scripts/adversary_eval.py harden      # retrain GraphSAGE on found evasions
    python scripts/adversary_eval.py report      # tables + figures

``search`` runs Optuna TPE against each closed-loop defence (trained final
models from ``closed_loop_eval.py``), plus a random-search control against
GraphSAGE with the same budget and a no-defence reference.

``harden`` takes the most damaging attacks found against GraphSAGE, simulates
each on fresh seeds without any defence, adds those runs to the training set,
retrains GraphSAGE ("graphsage_hardened"), and re-runs the adaptive search
against the hardened model.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from _bootstrap import banner, common_parser, ok, setup  # noqa: E402

OUT = Path("results/research/adversary")
MODELS = "results/research/predictions/final__all"


def cmd_search(args) -> int:

    from netshield.research.adversary import run_search, summarise_search  # noqa: PLC0415

    OUT.mkdir(parents=True, exist_ok=True)
    plans = [(d, "tpe") for d in args.detectors] + [("graphsage", "random"), (None, "tpe")]
    for detector, sampler in plans:
        tag = f"{detector or 'none'}_{sampler}"
        path = OUT / f"trials_{tag}.json"
        if path.exists():
            print(f"  {tag}: cached")
            continue
        banner(f"Adversary vs {detector or 'no defence'} ({sampler}, {args.trials} trials)")
        trials = run_search(detector, args.models, n_trials=args.trials, batch=args.workers,
                            seed=args.seed, sampler=sampler)
        trials.to_json(path, orient="records", indent=1, default_handler=str)
        print("  ", json.dumps(summarise_search(trials), default=str))
    return 0


def cmd_harden(args) -> int:
    import pandas as pd  # noqa: PLC0415

    from netshield.features.dataset import build_dataset  # noqa: PLC0415
    from netshield.graph.builder import edge_table_from_results  # noqa: PLC0415
    from netshield.models.base import DetectionInput  # noqa: PLC0415
    from netshield.models.graphsage import GraphSAGEDetector  # noqa: PLC0415
    from netshield.research.adversary import (  # noqa: PLC0415
        _evaluate,
        attack_overrides,
        run_search,
        summarise_search,
    )
    from netshield.research.protocol import (  # noqa: PLC0415
        STRESS_FAMILY,
        _val_split,
        load_research_corpus,
    )
    from netshield.simulation.runner import run_simulation  # noqa: PLC0415
    from netshield.utils.config import experiment_config, load_config, load_experiments  # noqa: PLC0415

    trials = pd.read_json(OUT / "trials_graphsage_tpe.json")
    # Most damaging attacks the defence did not stop: undetected, or detected
    # but still harmful. These are the gaps the hardened model must close.
    trials["harm"] = trials["damage"] * (1.0 + (~trials["detected"]).astype(float))
    top = trials.sort_values("harm", ascending=False).head(args.top)
    banner(f"Simulating {len(top)} evasive attacks x {args.seeds} seeds (no defence)")
    exp = load_experiments()
    results = []
    for i, (_, row) in enumerate(top.iterrows()):
        for s in range(args.seeds):
            cfg, meta = experiment_config("exp2_udp_flood", exp)
            cfg = cfg.merged(attack_overrides(row["params"]), source="adversarial-train")
            cfg = cfg.with_set(["simulation.engine=python", f"seed={9000 + 10 * i + s}"])
            results.append(run_simulation(cfg, {**meta, "experiment": f"adv_{i}"}))
    adv_corpus = build_dataset(results, load_config())
    adv_edges = edge_table_from_results(results)

    corpus, edges, runs = load_research_corpus(args.corpus)
    core = runs.loc[runs["family"] != STRESS_FAMILY, "run_id"].tolist()
    train_ids, val_ids = _val_split(core, 0.15, seed=99)        # same split as final models
    train = pd.concat([corpus[corpus["run_id"].isin(train_ids)], adv_corpus],
                      ignore_index=True)
    all_edges = pd.concat([edges, adv_edges], ignore_index=True)
    val = corpus[corpus["run_id"].isin(val_ids)].reset_index(drop=True)

    config = load_config(set_args=["detection.graphsage.epochs=120",
                                   "detection.graphsage.patience=20"])
    banner("Retraining GraphSAGE with adversarial runs")
    det = GraphSAGEDetector.from_config(config)
    det.fit(DetectionInput(train, all_edges), DetectionInput(val, all_edges))
    target = Path(args.models) / "graphsage_hardened"
    det.save(target)
    ok(f"hardened model -> {target}")

    # The pipeline loads detectors by class name, so expose the hardened
    # checkpoint as its own models root.
    hardened_root = Path(args.models).parent / "hardened"
    if hardened_root.exists():
        import shutil  # noqa: PLC0415
        shutil.rmtree(hardened_root)
    import shutil  # noqa: PLC0415
    shutil.copytree(target, hardened_root / "graphsage")

    banner("Re-scoring the training evasions on fresh seeds")
    rescore = []
    for name, root in (("graphsage", args.models), ("graphsage_hardened", str(hardened_root))):
        for i, (_, row) in enumerate(top.iterrows()):
            res = _evaluate({"params": row["params"], "seed": 9500 + i, "detector": "graphsage",
                             "models_dir": root})
            rescore.append({"model": name, "attack": i, "damage": res["damage"],
                            "detected": res["detected"], "bots_flagged": res["bots_flagged"],
                            "bots": res["bots"]})
    pd.DataFrame(rescore).to_csv(OUT / "hardening_rescore.csv", index=False)

    banner("Fresh adaptive search against the hardened model")
    trials_h = run_search("graphsage", str(hardened_root), n_trials=args.trials,
                          batch=args.workers, seed=args.seed + 1, sampler="tpe")
    trials_h.to_json(OUT / "trials_graphsage-hardened_tpe.json", orient="records", indent=1,
                     default_handler=str)
    print("  ", json.dumps(summarise_search(trials_h), default=str))

    # Clean-data cost of hardening: score the validation runs with both models.
    from netshield.evaluation.statistics import extended_metrics  # noqa: PLC0415
    from netshield.detection.pipeline import load_detectors  # noqa: PLC0415

    base = load_detectors(args.models, ["graphsage"])["graphsage"]
    vin = DetectionInput(val, all_edges)
    cost = {"base": extended_metrics(vin.labels, base.predict_proba(vin)),
            "hardened": extended_metrics(vin.labels, det.predict_proba(vin))}
    (OUT / "hardening_clean_cost.json").write_text(json.dumps(cost, indent=2), encoding="utf-8")
    return 0


def cmd_report(args) -> int:
    import matplotlib  # noqa: PLC0415

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt  # noqa: PLC0415
    import numpy as np  # noqa: PLC0415
    import pandas as pd  # noqa: PLC0415

    from netshield.evaluation.figures import DETECTOR_COLOURS, DETECTOR_LABELS  # noqa: PLC0415
    from netshield.research.adversary import frontier, summarise_search  # noqa: PLC0415

    rows, frontiers = [], {}
    for path in sorted(OUT.glob("trials_*.json")):
        tag = path.stem.replace("trials_", "")
        trials = pd.read_json(path)
        summ = summarise_search(trials)
        rows.append({"search": tag, **{k: v for k, v in summ.items()
                                       if k != "evasive_families"},
                     "evasive_families": json.dumps(summ["evasive_families"])})
        frontiers[tag] = frontier(trials)
    table = pd.DataFrame(rows)
    table.to_csv(OUT / "adversary_summary.csv", index=False)

    fig, ax = plt.subplots(figsize=(7.5, 4.6))
    for tag, fr in frontiers.items():
        if tag.endswith("_random") or tag.startswith("none"):
            continue
        det = tag.rsplit("_", 1)[0]
        key = det.replace("-hardened", "")
        centres = np.sqrt(fr["volume_lo"] * fr["volume_hi"])
        ax.plot(centres, np.maximum.accumulate(fr["best_undetected_damage"]), "o-", ms=3,
                color=DETECTOR_COLOURS.get(key, "#333"),
                ls="--" if "hardened" in det else "-",
                label=DETECTOR_LABELS.get(key, key) + (" (hardened)" if "hardened" in det else ""))
    ax.axhline(0.05, color="#999", lw=1, ls=":")
    ax.set_xscale("log")
    ax.set_xlabel("Offered attack volume during attack (Mbit/s)")
    ax.set_ylabel("Best damage achieved while undetected")
    ax.set_title("Stealth frontier (dotted line = SLO violation)")
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig("results/figures/research_stealth_frontier.png", dpi=140)
    plt.close(fig)

    curves = {}
    for tag in ("graphsage_tpe", "graphsage_random"):
        p = OUT / f"trials_{tag}.json"
        if p.exists():
            t = pd.read_json(p).sort_values("trial")
            curves[tag] = np.maximum.accumulate(t["damage"].to_numpy())
    if curves:
        fig, ax = plt.subplots(figsize=(6, 4))
        for tag, c in curves.items():
            ax.plot(np.arange(1, len(c) + 1), c, label="adaptive (TPE)" if "tpe" in tag
                    else "random search")
        ax.set_xlabel("Simulated attacks")
        ax.set_ylabel("Best damage so far vs GraphSAGE defence")
        ax.legend()
        fig.tight_layout()
        fig.savefig("results/figures/research_adversary_convergence.png", dpi=140)
        plt.close(fig)
    ok(f"summary -> {OUT / 'adversary_summary.csv'}")
    print(table.drop(columns=["evasive_families"]).round(4).to_string(index=False))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = common_parser("Adaptive adversary evaluation.")
    parser.add_argument("command", choices=["search", "harden", "report"])
    parser.add_argument("--detectors", nargs="*",
                        default=["threshold", "random_forest", "lightgbm", "graphsage",
                                 "temporal_gnn"])
    parser.add_argument("--models", default=MODELS)
    parser.add_argument("--corpus", default="data/research")
    parser.add_argument("--trials", type=int, default=66)
    parser.add_argument("--workers", type=int, default=11)
    parser.add_argument("--top", type=int, default=12)
    parser.add_argument("--seeds", type=int, default=3)
    args = parser.parse_args(argv)
    setup(args, "adversary_eval")
    args.seed = int(args.seed or 0)
    return {"search": cmd_search, "harden": cmd_harden, "report": cmd_report}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
