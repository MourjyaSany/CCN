# NetShield-GNN — Experiment Guide

How every experiment is defined, what it is for, and exactly how to reproduce it.

---

## 1. The experiment matrix

All nineteen experiments are declared in `config/experiments.yaml` as *sparse
overrides* on `config/default.yaml`. Nothing is hard-coded in Python.

### Core suite (1-8): the detector's argument

| # | Name | Attack | Bots | Rate/bot | Purpose |
|---|---|---|---|---|---|
| 1 | `exp1_normal` | none | 0 | — | Baseline operating envelope; the `BENIGN` class |
| 2 | `exp2_udp_flood` | UDP | 4 | 1400 pkt/s, 512 B | Volumetric / bandwidth exhaustion |
| 3 | `exp3_syn_flood` | SYN (spoofed) | 3 | 1800 pkt/s, 60 B | Protocol / state exhaustion |
| 4 | `exp4_http_flood` | HTTP | 4 | 320 req/s | Application-layer |
| 5 | `exp5_distributed` | UDP, CoAP-shaped | **36** | **22 pkt/s** | **Stealthy distributed** |
| 6 | `exp6_fuzzed` | UDP, pulsing | 6 | 2100 pkt/s, 2.5 s on / 3.5 s off | Burst evasion |
| 7 | `exp7_unseen` | mixed | 7 | 640 pkt/s | **Held-out generalisation** |
| 8 | `exp8_mitigation` | UDP | 6 | 1500 pkt/s | **Closed-loop detect → mitigate → recover** |

### Topology suite (9-14): is the advantage structural or an artefact?

Every one of these runs **the same attack as `exp2_udp_flood`** and changes only
the network structure, so any difference in detector or mitigation behaviour is
attributable to the topology and nothing else. The original single-tree suite
could not provide that control.

| # | Name | Family | Bots | What it tests |
|---|---|---|---|---|
| 9 | `exp9_star` | `star` | 4 | No intermediate aggregation — the control condition for "does the hierarchy matter" |
| 10 | `exp10_multi_gateway` | `multi_gateway` | 6 | Botnet straddles three enforcement domains; no gateway sees the whole attack |
| 11 | `exp11_dumbbell` | `dumbbell` | 4 | The node that enforces is not the link that saturates |
| 12 | `exp12_fat_tree` | `fat_tree` | 5 | Redundant paths split the aggregation evidence across two parents |
| 13 | `exp13_mesh` | `mesh` | 5 | Multipath routing spreads the per-link load |
| 14 | `exp14_ring` | `ring` | 4 | Structurally unequal path lengths before any attack |

### Attack suite (15-19): families and rate shaping

| # | Name | Attack | Bots | Rate/bot | What it tests |
|---|---|---|---|---|---|
| 15 | `exp15_icmp_flood` | ICMP | 4 | 1600 pkt/s | No ports at all — port-based rules are blind by construction |
| 16 | `exp16_ack_flood` | ACK | 4 | 2000 pkt/s | Bypasses the SYN backlog; consumes forwarding capacity |
| 17 | `exp17_slowloris` | slowloris | 8 | 12 sockets/s | Exhausts the connection table on an almost idle link |
| 18 | `exp18_ramp` | UDP, ramped | 6 | 1800 pkt/s peak, from 5% | Slow-ramp evasion of a static threshold |
| 19 | `exp19_multivector` | mixed + sine | 10 | 900 pkt/s | Weighted family mix, sinusoidal envelope, per-bot jitter, staggered joins |

Experiments 9-19 are **not** in `dataset_corpus.base_runs`. Like `exp7_unseen`,
they are evaluation-only: no model is fitted on them, so they are additional
out-of-distribution tests rather than more training data. That is deliberate —
adding them to the corpus would make the models better at exactly the scenarios
being used to judge them.

### 1.1 Why Experiment 5 is the important one

Thirty-six compromised nodes each emit ~22 packets/second of CoAP-shaped UDP:
the **same destination port (5683)**, the **same 200–400 byte packet size** and
the **same steady cadence** as a legitimate `udp_streamer` sensor. No single
device is anomalous on its own.

The gateway backhaul is overridden to an NB-IoT/LTE-class **2 Mbit/s** link
rather than the 20 Mbit/s fibre used elsewhere, so the ~800 pkt/s aggregate
genuinely saturates it and causes real service degradation. This is the scenario
that a per-node threshold rule is structurally unable to catch — and measurement
confirms it: the calibrated threshold detector achieves **0.18 recall** here.

### 1.2 Why Experiment 7 is excluded from training

`exp7_unseen` carries `holdout: true` and is absent from
`dataset_corpus.base_runs`. Its parameters — 7 bots, 640 pkt/s, packet sizes
spanning 96–1400 B, destination ports 9001 / 47808 / 5683, a 4.0 s-on /
1.5 s-off pulse, source spoofing, and a 42 s start — lie outside every range the
models were fitted on. It is only ever *scored*, never fitted, which makes it a
genuine generalisation test rather than an interpolation.

---

## 2. Running experiments

```bash
python scripts/run_experiment.py --list                      # what is available
python scripts/run_experiment.py --experiment exp2_udp_flood # one
python scripts/run_experiment.py --all                       # the full suite
python scripts/run_experiment.py --all --duration 60         # shorter runs
python scripts/run_experiment.py -e exp8_mitigation --detector random_forest
```

Or through the wrapper:

```bash
./run.sh experiments
./run.sh simulate exp3_syn_flood
```

### Prerequisites

Experiments 1–6 run without trained models (they simulate and produce network
figures). Experiments 7 and 8 need `models/` populated:

```bash
./run.sh dataset && ./run.sh train
```

If models are missing, `run_experiment.py` warns clearly and continues in
simulate-only mode rather than failing silently.

---

## 3. What each run produces

```
data/experiments/<run_id>/
├── flows.csv              IPFIX-style flow records (one row per window per 5-tuple)
├── window_metrics.csv     per-window QoS: throughput, latency, loss by cause, utilisation
├── node_counters.csv      per-node tx/rx/drop counters
├── link_stats.csv         per-channel utilisation, queue delay, peak queue
├── app_kpis.csv           per-device service-level KPIs (messages sent, connections failed)
├── detections_<det>.csv   per-detector, per-node-window scores
├── mitigation_log.csv     mitigation actions (closed-loop runs only)
├── run.json               manifest: engine provenance, summary, topology
├── config.json            the exact merged configuration
└── config_snapshot.yaml   the same, human-readable

results/figures/<exp>_*.png      topology, network time series
results/reports/<exp>.md         per-experiment report
results/metrics/experiments_summary.json   cross-experiment index
```

`run_id` is `<experiment>_seed<seed>_<blake2b(config)>`, so two runs with the
same id are byte-identical. That is what makes `--reuse` safe.

---

## 4. The dataset corpus

`config/experiments.yaml::dataset_corpus` declares what the training corpus is
built from:

```yaml
dataset_corpus:
  base_runs: [exp1_normal, exp2_udp_flood, exp3_syn_flood,
              exp4_http_flood, exp5_distributed, exp6_fuzzed]
  seed_replicates: 2          # each base run replayed with 3 seeds
  fuzz_runs: 10               # plus 10 fuzzer-generated runs
  fuzz_campaign: corpus_campaign
```

That gives **28 runs → 12,863 node-windows**:

| Scenario | Rows | Runs | Classes |
|---|---:|---:|---|
| `exp1_normal` | 1,061 | 3 | BENIGN 1,061 |
| `exp2_udp_flood` | 1,255 | 3 | BENIGN 1,183 · MALICIOUS 72 |
| `exp3_syn_flood` | 1,226 | 3 | BENIGN 1,172 · MALICIOUS 54 |
| `exp4_http_flood` | 1,231 | 3 | BENIGN 1,159 · MALICIOUS 72 |
| `exp5_distributed` | 2,506 | 3 | BENIGN 1,750 · MALICIOUS 756 |
| `exp6_fuzzed` | 1,296 | 3 | BENIGN 1,152 · **SUSPICIOUS 144** |
| `fuzz_corpus_campaign` | 4,288 | 10 | BENIGN 3,974 · SUSPICIOUS 121 · MALICIOUS 193 |

Note that `exp6_fuzzed` contributes only `SUSPICIOUS` labels: a 2.5 s-on /
3.5 s-off pulse gives a duty cycle of ≈0.42, so severity ≈ 0.41 — squarely in
the middle band. That is the labelling scheme behaving exactly as designed.

```bash
python scripts/generate_dataset.py                 # full corpus, ~6 min
python scripts/generate_dataset.py --quick         # reduced, ~2 min
python scripts/generate_dataset.py --reuse         # skip runs already on disk
python scripts/generate_dataset.py --no-fuzz       # base scenarios only
python scripts/generate_dataset.py --experiments exp1_normal exp2_udp_flood
```

---

## 4b. Running an experiment inside NS-3

Any experiment can be re-run in a real ns-3.44 installation:

```bash
python scripts/run_experiment.py --experiment exp2_udp_flood        --set simulation.engine=ns3
```

The artefacts are stamped `ns3-simulation` and are otherwise schema-identical,
so the feature pipeline, the detectors and the figures consume them unchanged.

Two things to know before quoting NS-3 numbers:

1. **`simulation.engine: auto` does not pick NS-3**, even when it is installed.
   NS-3 implements a subset of the model, and letting `auto` switch per scenario
   would make the corpus a mixture of two simulators. NS-3 is opt-in.
2. **The C++ model cannot honour every setting.** Topology families other than
   `tree`/`star`/`dumbbell`, the `ack_flood`/`slowloris`/`mixed` families, rate
   shaping, per-bot jitter, staggered joins, pulsing and the closed mitigation
   loop are Python-only. Each unsupported setting is logged as a warning and
   recorded in `run.json` under `summary.ns3_unsupported`; nothing is silently
   approximated.

NS-3 is best used as a **cross-validation** of the physical layer, where the two
independent implementations agree closely: a configured 16.5 ms path delay is
measured at ≈17 ms by the Python engine and 17.32 ms by NS-3, and both saturate
the 20 Mbit/s uplink under the same offered load.

## 5. Fuzzing campaigns

Declared in `config/fuzzing.yaml`:

| Campaign | Strategy | Cases | Purpose |
|---|---|---:|---|
| `rate_sweep` | grid | 6 | Packet rate across a decade |
| `packet_size_sweep` | grid | 5 | Minimum-frame to near-MTU |
| `burst_sweep` | grid | 12 | Pulsing duty cycles |
| `botnet_size_sweep` | grid | 4 | Constant volume, varying bot count |
| `random_broad` | random | 24 | Broad randomised exploration |
| `corpus_campaign` | random | 10 | The fuzzed portion of the training corpus |
| `mutation_walk` | mutation | 12 | Seeded walk around a baseline |
| `evasion_search` | adaptive | 12 | **Greedy search for the detector's weakest region** |

```bash
python scripts/fuzz.py --list
python scripts/fuzz.py --campaign rate_sweep
python scripts/fuzz.py --campaign evasion_search --adaptive
python scripts/fuzz.py --campaign random_broad --limit 6 --duration 50
```

Output: `results/metrics/fuzz_results_<campaign>.csv`,
`results/metrics/fuzz_cases_<campaign>.json`, and figures
`fuzzing_parameters_<campaign>.png` / `fuzz_robustness_<campaign>.png`.

### A note on rate ranges

`corpus_campaign` caps `packets_per_second` at 900 rather than 3000. For
`udp_flood` and `syn_flood` that value is literally packets per second, but an
`http_flood` expands each unit into a **complete TCP transaction** (handshake,
request, response, teardown — roughly eight packets). A 10-bot HTTP case at
3000 req/s would therefore offer ~240,000 pkt/s and exhaust the per-run
wall-clock budget. Wider ranges live in `random_broad`, which is used for
robustness analysis rather than corpus construction.

---

## 6. Full reproduction

```bash
./run.sh setup                       # ~10 s
python scripts/generate_dataset.py   # ~6 min  → data/processed/dataset.csv
python scripts/train_models.py       # ~1 min  → models/
python scripts/run_experiment.py --all  # ~5 min → results/reports/exp*.md
python scripts/evaluate.py           # ~1 min  → results/reports/RESULTS.md
pytest                               # ~1 min  → 221 tests
```

Everything is seeded from `seed: 42` in `config/default.yaml` plus the
per-experiment overrides. Re-running on the same commit reproduces the same
numbers.

---

## 7. Defining your own experiment

Add a block to `config/experiments.yaml`:

```yaml
  exp9_my_scenario:
    description: >
      What this scenario tests and why it is interesting.
    tags: ["custom"]
    config:
      seed: 99
      simulation: {n_attackers: 8, duration_s: 90.0}
      network:
        topology:
          gateway:
            uplink: {bandwidth_bps: 5000000}   # constrain the backhaul
      attack:
        enabled: true
        type: "syn_flood"
        start_s: 30.0
        duration_s: 30.0
        packets_per_second: 900.0
        packet_bytes: [64, 64]
        dst_ports: [8883, 443]
        spoof_sources: true
        burst: {enabled: true, on_s: 1.0, off_s: 2.0}
```

Then:

```bash
python scripts/run_experiment.py --experiment exp9_my_scenario
```

The configuration is validated before the simulation starts, so a mistake
(an attack that starts after the run ends, a rate of zero, an invalid port)
produces a precise error message rather than a meaningless run.

To include it in the training corpus, add its name to
`dataset_corpus.base_runs`.

---

## 8. Interpreting the artefacts

**`window_metrics.csv`** — the QoS series. Key columns:

| Column | Meaning |
|---|---|
| `throughput_mbps` | Upstream goodput delivered at the cloud (comparable to link capacity) |
| `offered_mbps` | Offered load — the gap to `throughput_mbps` is what congestion destroyed |
| `mean_latency_ms` / `p95_latency_ms` | End-to-end delay; the rise under attack is queueing delay |
| `loss_ratio` | Overall loss |
| `legit_loss_ratio` | Loss over all non-attack traffic |
| **`clean_loss_ratio`** | **Loss for never-compromised devices** — the service-level number |
| `congestion_drops` / `mitigation_drops` | Damage by the *attack* vs by the *defence* |
| `uplink_utilisation` | Fraction of the window the bottleneck serialiser was busy |
| `syn_rejected` | SYNs refused by a full backlog |

**Why `clean_loss_ratio` exists.** Isolating a bot also severs that bot's own
legitimate telemetry, which counts as `legit_loss` but is an intended
consequence of the defence, not a failure of it. Separating the two populations
is what makes the recovery measurement honest.

**`run.json`** — always check `engine_label` before quoting a number. It reads
either `"NS-3 simulation"` or `"Python discrete-event emulation"`, and it is set
by a real capability probe.
