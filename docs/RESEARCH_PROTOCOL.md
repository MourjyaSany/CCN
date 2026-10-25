# Research protocol

How the version 2.0 numbers are produced, and why each design choice was
made. Every table in [`RESEARCH_RESULTS.md`](../results/reports/RESEARCH_RESULTS.md)
is regenerated from saved predictions by `scripts/research_protocol.py analyse`.

## 1. Corpus: the research grid

`scripts/research_grid.py` runs, in parallel worker processes:

| Block | Scenarios | Topologies | Seeds | Runs |
|---|---|---|---|---|
| Attack families | benign, UDP, SYN, HTTP, ICMP, ACK, slowloris | all 7 | 4 | 196 |
| Rate shaping | distributed, fuzzed, ramp, multi-vector | tree | 4 | 16 |
| Benign stress | flash crowd, firmware storm, reboot storm | all 7 | 3 | 63 |
| **Total** | | | | **275** |

This yields 133,269 labelled node-windows. Runs are cached by a hash of the
exact configuration and the simulator version, so the grid is resumable and
reproducible.

### Benign stress scenarios

These are evaluation-only and contain no attack, so every flag is a false
alarm:

* **Flash crowd:** every HTTP client raises its request rate 20x for 25 s,
  which triples the offered packet rate.
* **Firmware storm:** every bulk uploader starts a 200-400 kB transfer within
  two seconds, twice per run.
* **Reboot storm:** every MQTT sensor drops its session and reconnects within
  one second. This is a burst of SYNs from many sources that looks like a SYN
  flood.

## 2. Metrics

### Detection, per node-window

Macro-F1, per-class F1, Matthews correlation, per-class and hostile PR-AUC,
ROC-AUC, and recall at a fixed false-positive rate (0.1%, 1%, 5%). Calibration
is measured as top-label and hostile-score ECE plus the multi-class Brier
score. The hostile score is P(suspicious) + P(malicious), which is the number
the mitigation policy thresholds.

### Network QoS, per window, measured in the simulator

Measured for devices that were never compromised:

* p50, p95 and p99 one-way latency, from a deterministic reservoir sample;
* RFC 3550 interarrival jitter, kept per flow;
* availability, the share of offered packets delivered within the 100 ms SLO;
* Jain's fairness index over per-device delivery ratios;
* per-application delivery ratio;
* flow completion time for HTTP requests and bulk uploads, timed to the final
  acknowledgement.

### Operational, per closed-loop run

From `evaluation/operational.py`:

* time to detect, time to mitigate and time to recover, all measured from
  attack start;
* collateral byte ratio and attack suppression ratio;
* mitigation precision and recall;
* rule churn per minute and peak active rules;
* false alarms per endpoint-hour and inference latency.

## 3. Evaluation designs

| Design | Folds | Train | Test | Question |
|---|---|---|---|---|
| Leave-one-seed-out | 4 | 3 seeds of every cell | the 4th seed | Overall performance with CIs |
| Leave-one-topology-out | 7 | 6 topologies | the 7th | Does it transfer to an unseen structure? |
| Leave-one-family-out | 6 | all other families, no multi-vector | the held-out family | Does it catch a zero-day family? |
| Benign stress | 4 models | seed-CV training folds | 63 stress runs | Does it cry wolf on legitimate surges? |

Early-stopping validation always uses 15% of the training runs, grouped by
run, and never test runs.

## 4. Statistics

* **Confidence intervals:** a cluster bootstrap that resamples whole runs,
  with 1,000 replicates. Node-windows inside a run share a seed, a botnet and
  a congestion episode, so resampling windows would understate uncertainty.
* **Detector comparisons:** a paired run-level bootstrap of the metric
  difference, where both detectors are scored on the same resampled runs.
  The two-sided p-values are Holm-corrected across every comparison.
* **Across conditions:** a Wilcoxon signed-rank test on per-cell macro-F1,
  where a cell is one scenario on one topology, also Holm-corrected.
* McNemar's test is provided, but it assumes independent rows and is
  descriptive only.

## 5. Detectors

| Detector | Sees neighbours | Sees history | Labels used |
|---|---|---|---|
| Threshold rule | no | no | calibration |
| Autoencoder | no | no | benign rows only |
| Random Forest | no | no | yes |
| LightGBM | no | no | yes |
| GRU sequence | no | 6 windows | yes |
| GATv2 (edge attributes) | 2 hops | no | yes |
| E-GraphSAGE (Lo et al., 2022) | 2 hops, flow attributes in messages | no | yes |
| GraphSAGE | 2 hops | no | yes |
| Temporal GNN (GraphSAGE + GRU) | 2 hops | 6 windows | yes |

GraphSAGE ablations run on two of the four seed folds. They remove the
graph, keep only physical or only communication edges, use one layer, and
drop each of the eight feature groups.

## 6. Calibrated, conformal decisions

`models/calibration.py` applies temperature scaling, fitted by NLL on
validation runs, then a split-conformal test of the hypothesis "this window
is benign". The wrapped detector's hostile mass is 1 - p, so the unchanged
policy engine acts at 0.95, 0.99 and 0.999. Each rung of the ladder then has
a nominal false-alarm budget of 5%, 1% and 0.1%. The guarantee holds when
test benign windows are exchangeable with calibration windows. The
closed-loop and stress results report the measured rate next to the nominal
one.

## 7. Adaptive adversary

`research/adversary.py` runs Optuna TPE as the attacker's black-box
optimiser. It searches attack family, per-bot rate, botnet size, packet size,
pulsing, rate profile, jitter, stagger, port and spoofing, against each
closed-loop defence. Its objective is damage under defence: the relative
drop in clean-device availability during the attack. Detection is not part
of the objective, so evasion emerges on its own.

* **Evasion success rate:** the share of attempts that break the SLO while
  no bot is ever flagged.
* **Stealth frontier:** the best undetected damage per attack-volume bin.
* **Hardening:** the most harmful attacks found against GraphSAGE are
  simulated on fresh seeds and added to training. A new search then runs
  against the hardened model. Its cost on clean validation data is reported
  too.

## 8. Real traffic

`realnet/pcap_ingest.py` replays packet captures through the simulator's own
telemetry collector. The flows then have the training schema, and features
come from the same code. CICIoT2023 publishes labels per file, not per host.
Evaluation is therefore at window level: flags on the benign capture are
false alarms, and on attack captures we report the share of windows with a
flag and the packet share of the flagged hosts. The first 300 MB of seven
captures were used: benign, UDP, SYN, HTTP, ICMP, ACK-fragmentation and
slowloris.

## 9. Reproduce

```bash
python scripts/research_grid.py --seeds 4 --stress-seeds 3 --workers 11
python scripts/research_protocol.py run --ablations --ablation-folds 2 \
    --set detection.graphsage.epochs=120 --set detection.graphsage.patience=20
python scripts/closed_loop_eval.py --set detection.graphsage.epochs=120
python scripts/adversary_eval.py search && python scripts/adversary_eval.py harden
python scripts/adversary_eval.py report
python scripts/real_data_eval.py --captures data/external/ciciot2023/*.pcap
python scripts/research_protocol.py analyse
```

On a 12-core laptop the grid takes about 12 minutes. The full protocol takes
several hours, dominated by GNN training.
