"""Temporary smoke test: simulate a few runs, build a corpus, train all detectors."""

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


from netshield.evaluation.metrics import comparison_table, compute_metrics, detection_latency  # noqa: E402
from netshield.features.dataset import build_dataset, split_by_run  # noqa: E402
from netshield.graph.builder import edge_table_from_results, graph_statistics  # noqa: E402
from netshield.models.base import DetectionInput  # noqa: E402
from netshield.models.graphsage import BACKEND, GraphSAGEDetector  # noqa: E402
from netshield.models.random_forest import RandomForestDetector  # noqa: E402
from netshield.models.threshold import ThresholdDetector  # noqa: E402
from netshield.simulation.runner import run_simulation  # noqa: E402
from netshield.utils.config import experiment_config, load_config  # noqa: E402
from netshield.utils.logging_utils import setup_logging  # noqa: E402

setup_logging("INFO")

EXPERIMENTS = ["exp1_normal", "exp2_udp_flood", "exp3_syn_flood",
               "exp4_http_flood", "exp5_distributed", "exp6_fuzzed"]
SEEDS = [0, 1]
DURATION = 55.0

started = time.perf_counter()
results = []
for name in EXPERIMENTS:
    for offset in SEEDS:
        cfg, meta = experiment_config(name)
        base_seed = int(cfg.get("seed", 42))
        cfg = cfg.with_set([f"seed={base_seed + offset}",
                            f"simulation.duration_s={DURATION}"])
        print(f"--- {name} seed={base_seed + offset}")
        results.append(run_simulation(cfg, meta))

print(f"\nSimulations done in {time.perf_counter() - started:.1f}s\n")

config = load_config()
corpus = build_dataset(results, config)
edges = edge_table_from_results(results)
print("corpus", corpus.shape, "edges", edges.shape)
print("classes", corpus["label_name"].value_counts().to_dict())

split = split_by_run(corpus, test_size=0.25, val_size=0.20, seed=42)
print("split summary:", split.summary()["train"], split.summary()["val"],
      split.summary()["test"])

train_in = DetectionInput(split.train, edges)
val_in = DetectionInput(split.val, edges)
test_in = DetectionInput(split.test, edges)

detectors = [
    ThresholdDetector.from_config(config),
    RandomForestDetector.from_config(config),
    GraphSAGEDetector.from_config(config),
]
print("GraphSAGE backend:", BACKEND)

bundles = []
for det in detectors:
    print(f"\n=== fitting {det.name}")
    report = det.fit(train_in, val_in)
    pred = det.predict(test_in)
    scores = det.attack_probability(test_in)
    metrics = compute_metrics(test_in.labels, pred, scores, detector=det.name, split="test")
    bundles.append(metrics)
    print(det.name, metrics.headline())
    print("  confusion", metrics.confusion)
    lat = detection_latency(split.test, scores, trigger=0.8, window_s=5.0)
    print("  latency", {k: v for k, v in lat.items() if k != "per_run"})

print("\n=== comparison")
print(comparison_table(bundles).to_string(index=False))

sage = detectors[-1]
graphs = sage._build(train_in)
print("\ngraph stats:", graph_statistics(graphs))
print(f"\nTOTAL {time.perf_counter() - started:.1f}s")
