# NetShield-GNN — Technical Project Report

**Intelligent DDoS Detection and Automated Mitigation for IoT–Cloud Networks using Graph Neural Networks and a Closed Simulation Loop**

*Head-to-toe engineering report: what every component is, how it works, how the pieces fit, and the roadmap to a real ESP32 hardware testbed.*

---

## 0. Table of contents

1. Executive summary
2. Problem statement and research contribution
3. System architecture at a glance
4. The simulation engines (NS-3 primary + Python closed-loop)
5. Topology families
6. Attack model and dynamic fuzzing
7. Telemetry, flows and the feature pipeline
8. Graph construction
9. Detectors (the GNN zoo) and calibration
10. The mitigation subsystem
11. The closed loop
12. Backend: API, live session, database, platform services
13. Frontend: the operations console
14. NetAnim visualisation
15. Research and evaluation methodology
16. The real-data path (pcap ingest) and the Mininet testbed
17. End-to-end lifecycle of a single run
18. Reproducibility, build and operations
19. Safety and ethics posture
20. **Roadmap: adding real ESP32 IoT devices**
21. Representative results
22. Limitations and future work
23. Appendix: repository map and key files

---

## 1. Executive summary

NetShield-GNN is a research platform that studies one question end to end:

> *When a botnet of compromised IoT devices floods a cloud service, can a Graph Neural Network find the compromised devices from network behaviour alone, and can an automated policy shut them down fast enough that the healthy devices keep working — and can we **measure** that recovery rather than assume it?*

The platform builds a **real IoT→gateway→cloud network** (seven topology families), floods it with configurable DDoS attacks, extracts per-device/per-window features, scores every device with a trained detector, and — in **closed loop** — installs mitigation rules at the gateway **inside the running simulation**, so throughput recovering and latency falling are *emergent consequences of packets actually being dropped earlier in the path*, never asserted after the fact.

The system ships two simulation engines (a C++ **NS-3** model as the primary packet-level engine and a Python discrete-event engine that hosts the closed loop), seven trained detectors, a full FastAPI backend, a React operations console, **NetAnim** packet-level visualisation, a research harness with proper cross-validation and confidence intervals, and a **real-data path** (`pcap` ingest + a Mininet/OpenFlow testbed agent) that runs the *same* detector and *same* policy on real Linux networking. That real-data path is the foundation for the planned **ESP32 hardware testbed** (Section 20).

---

## 2. Problem statement and research contribution

**Problem.** IoT devices (cameras, sensors, smart plugs) are weakly secured and are routinely conscripted into botnets (Mirai being the canonical example). From a single device's traffic, a flood looks a lot like a busy-but-legitimate device. The *graph* — who talks to whom, how fan-out and timing correlate across neighbours — carries the signal that a per-device threshold misses.

**Contribution.** The project treats detection and mitigation as **one control system**, not two offline classifiers:

- **Graph-based detection.** A GraphSAGE/temporal-GNN detector reasons over the network graph each time window, so a device is judged partly by its neighbourhood, not just its own counters.
- **Closed-loop, in-band mitigation.** The response (rate-limit → block → isolate → release) is enforced on the live packet path. Recovery metrics are *measured*.
- **Statistical honesty.** Detectors are scored with leave-one-seed-out cross-validation across topologies and attack families, with 95% bootstrap confidence intervals — so a claimed improvement is defensible, not a lucky seed.
- **Sim-to-real continuity.** The exact telemetry, feature, detector and policy code runs unchanged on real captures (`pcap`) and on a Mininet/OpenFlow testbed, and is designed to run on real ESP32 hardware.

---

## 3. System architecture at a glance

The platform is a six-stage pipeline with a feedback arc (this is literally what the console home page animates):

```
 ┌───────────┐   ┌───────────┐   ┌────────────┐   ┌─────────────┐
 │ Topology  │──▶│  NS-3 /   │──▶│   Flow     │──▶│    GNN      │
 │ families  │   │  Python   │   │  features  │   │  detector   │
 │ (7)       │   │  engine   │   │ node×window│   │ P(hostile)  │
 └───────────┘   └─────┬─────┘   └────────────┘   └──────┬──────┘
                       ▲                                  │
                       │          ┌─────────────┐         ▼
                       │          │  Visualise  │   ┌─────────────┐
                       └──────────│ NetAnim +   │◀──│ Mitigation  │
       closed-loop enforcement    │ dashboard   │   │ ladder @ GW │
                                  └─────────────┘   └─────────────┘
```

Two things make the architecture unusual:

1. **Two interchangeable engines behind one feature/detector/mitigation stack.** NS-3 is the packet-level ground truth; the Python engine hosts the closed loop. Both emit the *same* flow/window CSV schema, so everything downstream is engine-agnostic.
2. **The feedback arc is real.** Mitigation installed by the controller changes what the engine does in the *next* window, so the metrics are a measurement of a control system, not a scripted animation.

---

## 4. The simulation engines

### 4.1 NS-3 (primary, packet-level)

- **What it is.** The industry-standard [ns-3](https://www.nsnam.org/) discrete-event network simulator (ns-3.48). On Windows it runs inside **WSL2 (Ubuntu-24.04)**, because native-Windows builds of ns-3's shared libraries fail to initialise at load time; on Linux it runs directly.
- **Spec-driven model.** Rather than hard-coding one topology in C++, Python emits a **spec** (a line-oriented description of parameters, nodes, links, cloud/enforcement points, applications, bots and rate step-levels) and a single generic C++ model, `ns3/netshield/netshield-sim.cc`, builds *any* of the seven topologies from that link list. Device and bot traffic is generated with ns-3's **standard application generators** (`OnOffHelper`, `PacketSink`) — all traffic originates from each node's real assigned address; the model never hand-crafts or spoofs packets.
- **Instrumentation.** `ns3/netshield/netshield-trace.h` installs IP-layer trace sinks (send/deliver/drop) and exports `ns3_flows.csv` and `ns3_windows.csv` in **exactly** the project's schema, plus `ns3_run.json`. Rate shaping over time is scheduled as a waveform.
- **Visualisation.** When requested, the model installs a `MobilityHelper` (nodes positioned by tier: cloud at top, gateways/routers in the middle, IoT/attackers at the leaves) and an `AnimationInterface`, writing a `netanim.xml` trace for NetAnim with per-node colours (cloud blue, gateway/router grey, attacker red, IoT green).
- **Invocation.** `src/netshield/simulation/ns3_wsl.py` is the Windows↔WSL bridge (`detect`, `run_model`, `launch_netanim`, `environment_report`). `ns3_run.py` runs a scenario and keeps the trace; `ns3_spec.py` writes the spec. `scripts/setup_ns3.py` reproducibly builds ns-3 + the model + NetAnim from a clean machine.

> **Engineering note (fixed this cycle).** `wsl.exe` expands `$VAR` tokens in its command-line arguments *before* bash runs. The NetAnim launcher used shell variables for the trace path, so they were blanked and NetAnim opened with no file. The bridge now feeds scripts to `bash -l -s` over **stdin**, so variables survive. Separately, upstream NetAnim ignores `argv`; a small source patch (`ns3/netshield/patch_netanim.py`, applied by the setup script) makes it auto-load the trace passed on the command line.

### 4.2 Python discrete-event engine (the closed loop)

- **What it is.** A compact event-driven simulator (`src/netshield/simulation/engine.py`) with a scheduler, channels with queues, per-node applications, and a `PacketFilter` hook at the gateway ingress.
- **Why it exists alongside NS-3.** Closed-loop mitigation must *change the packet path mid-run*. The Python engine exposes a `WindowController` interface invoked at every feature-window boundary; the controller runs detection, decides mitigation, and installs rules into the live `packet_filter`. The NS-3 model runs **open-loop** (it generates traffic but does not enforce mitigation), so any run that carries a controller stays on the Python engine; `ns3`/`wsl` runs are explicitly open-loop.
- **Telemetry.** `telemetry.py` owns per-window `WindowMetrics` (offered/delivered/dropped, latency samples, SLO adherence, clean-vs-attack accounting, collateral) and the flow records that become the feature CSV.

---

## 5. Topology families

Seven families, each changing **one** structural assumption of a baseline hierarchical tree so that detector robustness to *graph* changes (not just traffic changes) can be measured:

| Family | What it varies |
|---|---|
| `tree` | Baseline IoT → gateway → cloud hierarchy |
| `star` | Single hub concentration |
| `mesh` | Dense interconnection (emergent congestion; ~30%+ loss observed) |
| `fat_tree` | Datacentre-style multi-rooted redundancy |
| `dumbbell` | A single shared bottleneck link |
| `ring` | Cyclic forwarding |
| `multi_gateway` | Multiple uplinks / load spreading (near-zero loss observed) |

Because loss and congestion are **emergent** from the built network, the families produce genuinely different stress profiles (verified: `mesh` ~32.7% loss vs `multi_gateway` ~0% under the same offered load).

---

## 6. Attack model and dynamic fuzzing

- **Attack families.** Six configurable DDoS families (e.g. UDP flood, SYN flood, and other volumetric/protocol patterns) with configurable **rate waveforms** (ramp, step, pulse), start time, duration, attacker count and per-bot intensity.
- **Dynamic fuzzing.** A fuzzing engine (`src/netshield/fuzzing/`) perturbs attack parameters to generate campaigns the training corpus never contained, which is how generalisation is stress-tested (the console's **Attack Builder** exposes this to the operator).
- **Ground truth.** The engine knows which nodes are compromised, which is used only for *scoring* detection/mitigation after the fact — never fed to the detector.

---

## 7. Telemetry, flows and the feature pipeline

- **Flows.** Every packet updates a per-(source, window) flow record: packet/byte counts, rates, destinations, protocol mix.
- **Windows.** Time is bucketed into fixed feature windows (`telemetry.window_s`). Each window yields per-node statistics plus network-wide QoS metrics (clean availability, p50/p99 latency, goodput, offered load, SLO adherence, collateral byte ratio).
- **Node features.** `src/netshield/features/node_features.py` turns the flow CSV into the per-node feature vectors the models consume (rates, fan-out, entropy of destinations, burstiness, etc.). **The same feature code runs on simulated flows and on real `pcap` flows**, which is the key to sim-to-real transfer.
- **Schema stability.** Both engines and the real-data path emit the identical `*_flows.csv` / `*_windows.csv` schema, so features, graph building, detection and evaluation never need to know where the data came from.

---

## 8. Graph construction

`src/netshield/graph/` assembles, per window, the graph the GNN reasons over:

- **Nodes** = devices/routers/gateway/cloud, each carrying its feature vector.
- **Edges** = the real links of the active topology (plus any derived communication edges).
- The result is handed to the detectors as a node-feature matrix + adjacency, re-built each window so the detector sees the network *evolve* as the attack unfolds.

---

## 9. Detectors (the GNN zoo) and calibration

Seven detectors ship pre-trained under `models/<name>/` (each with a `manifest.json`), selectable at run time:

| Detector | Type | Role |
|---|---|---|
| `graphsage` | Graph neural network (GraphSAGE) | Primary graph detector |
| `temporal_gnn` | GNN + temporal history buffer | Captures evolution across windows |
| `egraphsage` | Edge-featured GraphSAGE variant | Uses edge attributes |
| `lightgbm` | Gradient-boosted trees | Strong non-graph baseline |
| `random_forest` | Bagged trees | Classical baseline |
| `autoencoder` | Reconstruction/anomaly | Unsupervised baseline |
| `threshold` | Fixed rule | Naive floor / sanity baseline |

- **Common interface.** `src/netshield/models/base.py` defines the contract (`fit`, `score`, `history_windows`, `name`); `graphsage.py`, `temporal_gnn.py`, `random_forest.py`, `threshold.py`, `baselines.py` implement them. The GNNs use **PyTorch Geometric** (`torch-geometric`).
- **Output.** Each detector returns `P(hostile)` per node per window.
- **Calibration & conformal.** `models/calibration.py` calibrates raw scores to probabilities; the research harness can wrap detectors in a **conformal ladder** for distribution-free confidence, evaluated as a first-class variant.
- **Explainability.** `src/netshield/explain.py` surfaces *why* a node was flagged (feature attributions), exposed on the console's node drawer and `/api/explain`.
- **Training.** `scripts/train_models.py` trains all detectors from the generated corpus; the launcher trains them automatically if none are present.

---

## 10. The mitigation subsystem

`src/netshield/mitigation/` is deliberately split into a **data plane** and a **control plane** (mirroring how real firewalls/SDN separate forwarding from policy).

### 10.1 Data plane — `MitigationEnforcer` (engine.py)
Implements the engine's `PacketFilter`. For every packet arriving at the gateway it checks the rule installed for that **ingress node identity** (keyed on the physical port / assigned identity, which address spoofing cannot forge):

- `BLOCK` / `ISOLATE` → drop.
- `RATE_LIMIT` → token-bucket (configurable `rate_limit_pps`, `rate_limit_burst`); forward while tokens remain, else drop.
- Tracks dropped packets/bytes per node and in aggregate, so collateral damage on legitimate traffic is measurable.

### 10.2 Control plane — `MitigationEngine` (engine.py)
Consumes detector scores each window and drives the enforcer via a **response ladder** (`policy.py`, `decide()`):

- Escalation: a node that stays above `trigger_probability` for consecutive windows climbs `MONITOR → RATE_LIMIT → BLOCK → ISOLATE` (thresholds `rate_limit_probability`, `block_probability`, `isolate_probability`, with `escalation_windows`).
- De-escalation never happens *mid-incident*; a node is **released** only after `release_after_clean_windows` consecutive clean windows — so recovery is earned.
- **Approval modes** (human-in-the-loop governance): `auto` (install everything), `hybrid` (auto rate-limits, queue blocks/isolations for an operator), `manual` (queue everything). `approve` / `reject` / `rollback` are operator actions, all logged.
- **Accuracy scoring.** `evaluate_mitigation_accuracy()` scores decisions against ground truth as a *second* classification problem (precision/recall/F1 over nodes acted upon, plus collateral count) — because wrongly isolating a healthy device is far costlier than a missed detection alert.

### 10.3 Rule export — `export.py`
Renders the abstract action log into **real enforcement commands**: `ovs-ofctl` OpenFlow 1.3 meter/drop rules keyed to a `PortMap` (device → bridge → OpenFlow port). This is what lets the *same* policy run on the Mininet testbed and, later, on real hardware.

---

## 11. The closed loop

`src/netshield/detection/controller.py` is the `WindowController` that ties it together each window boundary:

1. Build the window's graph from live telemetry.
2. Score every node with the selected detector (feeding a history buffer for temporal models).
3. Hand scores to the `MitigationEngine`, which installs/releases rules (subject to approval mode).
4. Install the enforcer as the engine's `packet_filter` so rules bite on the *next* window's packets.

Because step 4 changes the packet path, the window after an isolation genuinely carries fewer attack packets — which is why availability climbing back is a measurement. (The engine also records, per window, how many sources are under an active rule, so the "Rules active" telemetry reflects reality.)

---

## 12. Backend: API, live session, database, platform services

- **FastAPI app** (`src/netshield/api/app.py`) serves the REST API, the OpenAPI docs at `/docs`, and the built console at `/app`.
- **Live session** (`api/state.py`) runs a scenario on a background thread with live pacing (`speed` = simulated seconds per wall-clock second; `0` = as fast as possible), exposing `/api/simulation/{start,stop,status}`, `/api/live`, `/api/topology`, `/api/mitigation`, `/api/timeline`, `/api/alerts`, `/api/explain/{node}`, `/api/nodes/{node}/history`.
- **NS-3 routes** (`api/ns3_routes.py`): `/api/ns3/status`, `/api/ns3/animate` (run a scenario in real NS-3, keep a NetAnim trace), `/api/ns3/netanim/open` (launch the animator), `/api/ns3/runs`.
- **Platform services** (`src/netshield/platform/`): an event **bus**, Prometheus-style **metrics** (gauges like `netshield_active_rules`), a tamper-evident **audit** log, **security** (auth/roles), a receive-only **IPFIX** collector (`service.py`), and a **timeseries** store. These make the system look and behave like a real SOC backend.
- **Database** (`src/netshield/database/`): SQLite (`data/netshield.db`) with a schema/store for runs, alerts, mitigation records and audit.

---

## 13. Frontend: the operations console

A React + TypeScript single-page app (Vite, Tailwind, Radix, ECharts, Cytoscape) served at `/app`, styled as a **hybrid ops-dark + editorial** console: a permanent dark command-center chrome (sidebar/topbar) wrapping readable light-or-dark data panels.

Pages: **Home** (an animated, glowing pipeline mindmap of the whole system with clickable stages), **Overview** (live mission control + KPIs), **Live network** (the graph the GNN sees, coloured by `P(hostile)`), **Incident timeline**, **Alerts** (exportable as STIX/CEF), **Mitigations**, **Experiments**, **Research results**, **Replay** (window-by-window forensics), **NS-3 & NetAnim**, **Attack builder**, **Topologies**, **Policy & audit**, **About**. Every page carries a one-line explainer of its role in the pipeline. A command palette (Ctrl-K) jumps anywhere.

---

## 14. NetAnim visualisation

NetAnim is ns-3's Qt packet animator. When a scenario is run via `/api/ns3/animate`, the model writes `netanim.xml`; `/api/ns3/netanim/open` copies it to WSL-local storage and launches NetAnim, which (with our patch) auto-loads and plays it. NetAnim shows the **real network and the real attack packets** traversing the graph.

**In-NS-3 mitigation (visualised and measured).** With `mitigate=true`, the model installs `NetShieldPolicer` — a custom root `QueueDisc` — at the spec's `enforce` (gateway) nodes. It combines two standard mechanisms:

1. **Per-source fair queueing (immediate, no detection delay).** Admitted packets are hashed into 64 per-source buckets served by **Deficit Round Robin**. A flood can only fill *its own* bucket, so it can never consume the whole buffer and push legitimate packets out — protection that applies from the very first packet, before any classification.
2. **Rate-based policing (escalating).** Each source's arrival rate is evaluated every 0.5 s and escalates **watch → rate-limit (token bucket) → block → release-when-quiet**. The trigger (15 pkt/s) sits ~3× above the measured legitimate device rate (~5 pkt/s) and far below any flood; action requires 2 *consecutive* flooding intervals so a transient burst cannot trip it. Dropping is keyed on the real source address — the model never creates or rewrites a packet, preserving the safety posture.

**Metrics are counted exactly, at the victim.** Every cloud-bound packet is classified once at its origin (attack or legitimate) and counted again only if it is actually delivered at the cloud, giving `atk_offered_cloud / atk_delivered_cloud / legit_offered_cloud / legit_delivered_cloud`. Mitigation rate and goodput preservation are direct ratios of these, so both are necessarily within [0, 1]. *(An earlier version inferred attack delivery by subtracting legitimate from **total** delivery; because total delivery also contains TCP ACKs and other return traffic, that could yield nonsensical negative percentages. It was replaced with the direct counters.)*

**Measured results** (28 s run, dumbbell bottleneck, 10 IoT devices, 8 bots):

| attack family | topology | attack blocked | legitimate delivered |
|---|---|---|---|
| udp_flood | dumbbell | 98.6% | 96.2% |
| udp_flood | tree | 97.7% | 96.2% |
| syn_flood | star | 97.7% | 96.2% |
| mixed | multi_gateway | 95.3% | 96.4% |
| slowloris | dumbbell | 93.7% | 96.2% |

All families clear the design targets of ≥92% mitigation and ≥95% goodput preservation.

**Baseline and control runs** (same scenario, udp_flood on dumbbell) isolate what the defence actually buys and what it costs:

| run | attack reaching the cloud | legitimate delivered |
|---|---|---|
| attack, **no defence** | 48,055 | 99.7% |
| attack, **defended** | **3,224** (14.9x fewer) | 96.2% |
| no attack, defence **on** | - | 99.81% |
| no attack, defence **off** | - | 99.81% |

Two things follow. First, the policer is **cost-free when idle**: with no attack, enabling it changes legitimate delivery not at all (99.81% either way), so it introduces no standing penalty. Second, the harm model in this topology is **victim load rather than legitimate packet loss** - the links' default FqCoDel already isolates legitimate flows well, so an undefended flood still leaves legitimate delivery high while hammering the cloud with 48,055 packets. The defence's contribution is removing that load (a 14.9x reduction), at the cost of a ~3 s detection-and-escalation transient during which legitimate delivery dips to 96.2%. Shortening that transient trades directly against false-positive safety, which is why action requires two consecutive flooding intervals.

**Attack-family fidelity.** Every family is reproduced as *offered load* on its characteristic port and packet size; only `udp_flood` is transport-exact and the rest are labelled approximations in the run metadata. They are carried over UDP deliberately: a TCP-carried "flood" is congestion-controlled, so bots back off to a fair share of the bottleneck (measured ~55 pkt/s per bot instead of ~1500) and the attack never becomes volumetric. Worse, once such a source is blocked it stops transmitting, so the attack's own offered load collapses and any within-run ratio becomes meaningless. TCP handshake/congestion semantics and slowloris' held connections are modelled in the Python engine (including the finite SYN backlog), not here.

**What the animation shows.** NetAnim cannot style individual packets - its trace format carries only `fId/tId/uId` and four timestamps per packet, and the API is node- and link-level only - so enforcement is surfaced four ways instead:

* **The enforced link.** The gateway's upstream link is labelled live: `clear` -> `THROTTLING n pkt/s` -> `BLOCKING n pkt/s`, so the hop where traffic is stopped is named on the canvas.
* **Per-node counters.** Each offending node carries its own `Blocked pkts` and `Throttled pkts` counters. In NetAnim these appear under **Stats -> Counter Tables**, selectable by counter name, giving a table of exactly which nodes are being stopped or slowed and by how much (measured run: each of the eight bots ~25,100 blocked and ~2,950 throttled, and no legitimate device appears at all - an independent confirmation of zero false positives).
* **Node state.** Bots recolour **orange `RATE-LIMITED`**, then **black `BLOCKED`**, shrink, and slide into a quarantine row below the topology. The gateway itself turns orange/red while dropping. The **victim is never recoloured**, so colour always denotes an offending or enforcing node.
* **Flow asymmetry.** Blocked bots keep transmitting, so packets continue to arrive at the gateway while none leave it toward the cloud - a packet-level picture of "stopped here" that needs no per-packet styling. This gateway policer is the in-simulation *enforcement mechanism*; the GNN remains the intelligent *detector* in the full closed loop (dashboard).

---

## 15. Research and evaluation methodology

- **`scripts/closed_loop_eval.py`** runs the closed loop for every detector across topologies and seed offsets, optionally wrapping detectors in conformal ladders, and writes predictions and operational metrics.
- **`scripts/research_protocol.py`** orchestrates the full protocol; **`evaluation/`** computes detection metrics, operational metrics (time-to-detect, time-to-mitigate, peak active rules, collateral byte ratio, availability recovery) and figures.
- **Statistical rigour.** Leave-one-seed-out cross-validation over every topology × attack family, with **95% run-level bootstrap confidence intervals**, so model comparisons are statistically defensible. Results render in the console's **Research results** page and in `results/reports/`.

---

## 16. The real-data path and the Mininet testbed

This is the bridge from simulation to hardware, and it already exists.

- **`src/netshield/realnet/pcap_ingest.py`** parses `.pcap`/`.pcapng` with `dpkt`, reconstructs flows, maps IPs to topology nodes, and emits **the exact flow schema the models were trained on**. So a real capture becomes model-ready input with no retraining of the plumbing.
- **`src/netshield/realnet/features.py`** computes the same sliding-window per-source features in real time (a `FlowTracker` with per-source windows).
- **Mininet/OpenFlow testbed** (`testbed/`): runs the **same** closed loop on **real Linux networking** — kernel TCP stacks, Open vSwitch forwarding, `tc` link shaping, real OpenFlow 1.3 meter/drop rules. `testbed/topology.py` builds the emulated network; `testbed/traffic/` has benign IoT device generators, a server, and `lab_flood.py` (a flood generator that **refuses any target outside `10.0.0.0/8`**).
- **`testbed/netshield_agent.py`** is the production-shaped agent: it watches rotating 5-second gateway captures, ingests each with `realnet.pcap_ingest`, scores it with a trained detector (with a history buffer for temporal models), feeds the scores to the **same `MitigationEngine` policy**, and renders new actions as `ovs-ofctl` commands via `mitigation.export` (`--dry-run` prints them instead). `process_window` is pure and importable, so it can be replayed offline against any capture directory.

**The significance:** detection, policy and enforcement are already decoupled from the simulator. Swapping the traffic *source* from Mininet namespaces to real ESP32 hardware is an integration task, not a rewrite.

---

## 17. End-to-end lifecycle of a single run

1. Operator picks scenario/topology/detector/approval-mode (console or API).
2. Python emits the spec; the chosen engine builds the network.
3. Devices generate benign traffic; at the attack's start time, bots begin their waveform flood toward the cloud.
4. Each window: flows → features → graph → detector → `P(hostile)` per node.
5. The controller escalates/installs rules; the enforcer drops/limits offending packets on the next window.
6. Telemetry records availability, latency, goodput, drops, collateral, active rules.
7. As attackers are isolated, clean availability recovers; after clean windows, rules are released.
8. Artefacts persist (DB rows, CSVs, optional NetAnim trace); the console/Replay/Research views read them.

*Representative closed-loop run* (`exp8_mitigation`, GraphSAGE): attack at t=35 s, first detection and first mitigation at t=40 s, escalation block→isolate on 6 bots by t=45 s, clean availability 48% → 100%, collateral 0%, rules released from t=120 s.

---

## 18. Reproducibility, build and operations

- **One-click.** `start.bat` (Windows) / `start.sh` (Unix) / `python launch.py` create `.venv`, install dependencies, find or download a portable Node, build the console, install/train detectors, start the server, and open `/app`. Re-running skips finished steps.
- **CLI.** `run.sh` wraps common tasks (serve, frontend build/dev, experiments). `scripts/` holds focused entry points (`serve.py`, `train_models.py`, `generate_dataset.py`, `closed_loop_eval.py`, `research_protocol.py`, `setup_ns3.py`, …).
- **NS-3 setup.** `scripts/setup_ns3.py` builds ns-3 + the model + NetAnim reproducibly (WSL on Windows, native on Linux), including the NetAnim auto-load patch.
- **Containers.** `Dockerfile` / `docker-compose.yml` / `deploy/` for reproducible deployment.
- **Tests.** `tests/` + `pytest.ini`; the testbed agent is unit-tested offline against real captures.

---

## 19. Safety and ethics posture

- All attack traffic is generated **inside simulators/emulators**. The simulation, feature and model code never opens a socket; the only network code is the **receive-only** IPFIX collector and the Mininet testbed, which **refuses any target outside its emulated `10.0.0.0/8`**.
- The NS-3 model uses only standard application generators from each node's **real assigned address** — no hand-crafted or spoofed packets.
- This posture is a hard design constraint and must be preserved by any future work, including the ESP32 testbed (Section 20), which confines all attack traffic to an isolated lab subnet.

---

## 20. Roadmap: adding real ESP32 IoT devices

**Goal.** Replace emulated hosts with real **ESP32** Wi-Fi microcontrollers so the *same* detector and *same* mitigation policy defend a physical IoT network — closing the sim-to-real loop and letting us compare on-hardware KPIs against the simulator's predictions.

### 20.1 Why ESP32, and why this is low-risk architecturally
The detector, policy and enforcement are already source-agnostic (Section 16). The testbed agent already turns rotating `pcap` captures into OpenFlow rules. ESP32 integration therefore reuses `realnet.pcap_ingest`, the trained models, `MitigationEngine`, and `mitigation.export` **unchanged**; the new work is the physical network, the firmware, and the gateway capture/enforcement plumbing.

### 20.2 Target hardware topology (lab, fully isolated)
```
  [ESP32 #1 sensor] ┐
  [ESP32 #2 sensor] ┤        Wi-Fi          ┌───────────────┐        ┌───────────┐
  [ESP32 #3 sensor] ┼───────────────────────▶│  Gateway/AP   │───────▶│  "Cloud"  │
  [ESP32 #4 BOT*  ] ┤   (isolated SSID,       │ Linux + OVS + │ uplink │  server   │
  [ESP32 #N ...   ] ┘    lab subnet only)     │ hostapd + cap │        │ (Pi/VM)   │
                                              └──────┬────────┘        └───────────┘
                                                     │ runs netshield_agent.py
                                                     ▼ ovs-ofctl meter/drop on access port
```
- **End devices:** ESP32 dev boards. Most run **benign** firmware (periodic MQTT/CoAP telemetry — temperature, humidity, a heartbeat). A minority run **attacker** firmware for experiments.
- **Gateway/AP:** a Raspberry Pi 4 / small Linux box running `hostapd` (Wi-Fi AP) + **Open vSwitch**. It both forwards traffic and is the enforcement point. `tcpdump` rotates 5-second captures of the uplink (identical to the testbed).
- **"Cloud" server:** a second Pi or a VM hosting the MQTT broker / target service.
- **Isolation:** a dedicated SSID/VLAN and subnet (e.g. `10.0.0.0/8`), no route to the internet. Attacker firmware hard-codes the lab target and **refuses any address outside the lab subnet**, mirroring `lab_flood.py`.

### 20.3 Firmware (Arduino / ESP-IDF)
- **Benign device profile.** Connect to the lab AP; publish a small MQTT message every *N* seconds with jitter; occasionally pull a config blob. Parameterised rate so devices map to the simulator's device classes.
- **Attacker profile (lab-only).** On a trigger (physical button / MQTT command from the test controller), emit a bounded UDP or SYN flood **only** toward the configured lab target, at a configurable packet rate and duration — the physical analogue of an `OnOff` bot. A compile-time guard and a runtime subnet check prevent any non-lab target.

### 20.4 Mapping real devices into the graph
- A `port_map.json` (already the agent's input) maps each ESP32's IP/MAC → access bridge → OpenFlow port. Each ESP32 becomes a **graph node**; the gateway is the parent; the cloud is the root — matching the simulated `tree` topology so features and the detector see a familiar structure.
- `realnet.pcap_ingest` turns each capture into the trained flow schema; `realnet.features` can additionally provide a real-time sliding-window view.

### 20.5 The live loop on hardware (reuses existing code)
1. Gateway `tcpdump` writes `capture/win-*.pcap` every 5 s.
2. `testbed/netshield_agent.py` ingests each closed capture → features → trained detector (history buffer for temporal) → `MitigationEngine`.
3. New actions render as `ovs-ofctl` meter/drop rules on the offending ESP32's access port.
4. The agent's action log (`agent_actions.json`) is in NetShield's schema, so the **console, metrics, audit and Research views ingest hardware runs exactly like simulated ones**.

### 20.6 Phased delivery plan
| Phase | Scope | Exit criterion |
|---|---|---|
| **P0 — Bring-up** | 1 benign ESP32 → AP → broker; agent in `--dry-run` | Captures parse; features/scores produced end to end |
| **P1 — Detect** | Add 1 attacker ESP32; agent scores but does not enforce | Bot flagged above trigger during its flood; benign devices stay low |
| **P2 — Enforce** | Enable real OpenFlow drop/meter on the bot's port | Flood traffic drops at the gateway; cloud service recovers |
| **P3 — Scale & topologies** | N≈10–24 ESP32s; vary layout (star via one AP, mesh via ESP-MESH, multi-gateway via two APs) | KPIs produced per topology family |
| **P4 — Sim-to-real validation** | Run the matching scenario in the simulator and on hardware | On-hardware TTD / availability-recovery / collateral compared to simulator's predicted ranges |

### 20.7 Risks and mitigations
- **Domain gap (train on sim, test on real).** Wi-Fi jitter and real stacks differ from the simulator. Mitigate with per-deployment **calibration** (already in `models/calibration.py`), a short **fine-tune** on labelled lab captures, and conformal wrappers for honest uncertainty.
- **Feature parity.** `pcap_ingest` already emits the trained schema; validate feature distributions sim-vs-real and document any gap.
- **Clock/sync & capture gaps.** Use the gateway's monotonic clock for windowing (the agent already windows on capture-file rotation).
- **ESP32 throughput limits.** A single ESP32 cannot match a simulated bot's rate; use several attacker boards or lower the benign baseline so the attack is still detectable and the experiment is meaningful.
- **Safety.** Air-gapped lab subnet, compile-time + runtime target guards, physical kill switch on the AP.

### 20.8 What a successful ESP32 testbed demonstrates
A single artefact where *the identical GNN and policy* defend (a) a packet-level NS-3 simulation, (b) a Mininet/OpenFlow emulation, and (c) a physical ESP32 network — with the same metrics pipeline across all three. That continuity is the headline research result the hardware phase is designed to produce.

---

## 21. Representative results

- **Topology-correct congestion.** Same offered load, different structures: `mesh` ~32.7% loss, `multi_gateway` ~0% — emergent from the built network, not scripted.
- **Closed-loop defence (sample run).** Detection latency ~5 s; clean availability 48% → 100%; collateral damage 0%; full block→isolate→release ladder; six bots isolated and later released.
- **Statistical evaluation.** Detectors compared with leave-one-seed-out CV and 95% bootstrap intervals across topologies and attack families (Research results page / `results/reports/`).

*(Headline per-model accuracy figures come from the research harness; this report documents the methodology rather than freezing numbers that each training run reproduces.)*

---

## 22. Limitations and future work

- **Two enforcement implementations.** The dashboard's closed loop uses the **GNN** to decide and the Python enforcer to act; the NS-3/NetAnim path uses a **rate-based gateway policer** to act so the flood can be visualised being cut off. They are consistent in policy (same ladder) but the NS-3 path does not yet run the GNN inside the simulation. *Future:* a two-pass mode that scores the open-loop NS-3 flows with the GNN and replays its exact decisions as the NS-3 enforcement schedule, so NetAnim shows GNN-driven mitigation.
- **Sim-to-real gap** is expected and is precisely what the ESP32 phase measures and calibrates.
- **ESP32 attack throughput** is modest; experiments size the benign baseline accordingly.
- **Scale.** Current runs are lab-sized (tens of nodes); larger fabrics are future work on the NS-3 side.

---

## 23. Appendix: repository map and key files

```
ns3/netshield/            NS-3 model (netshield-sim.cc, netshield-trace.h, patch_netanim.py)
src/netshield/
  simulation/             engines, telemetry, NS-3 bridge/spec/run, runner
  features/               node_features and the feature pipeline
  graph/                  per-window graph construction
  models/                 detectors (graphsage, temporal_gnn, random_forest, threshold, baselines) + calibration
  detection/              closed-loop controller + pipeline
  mitigation/             enforcer + engine + policy + export (OpenFlow)
  realnet/                pcap_ingest + real-time features (sim-to-real)
  fuzzing/                dynamic attack fuzzing
  evaluation/ research/   metrics, figures, reports, protocol
  platform/               bus, metrics, audit, security, IPFIX collector, timeseries
  api/                    FastAPI app + routes (sim, ns3, insight, platform) + live state
  explain.py              detector explainability
testbed/                  Mininet/OVS testbed + netshield_agent.py (basis for ESP32)
frontend/                 React console (Home pipeline map, pages, ui kit)
models/                   pre-trained detectors (manifest.json each)
scripts/                  launch/serve/train/eval/research/setup_ns3
config/default.yaml       all tunables (simulation, attack, features, graph, detection, mitigation, api)
docs/                     this report + architecture/methodology/research/viva docs
```

---

*Document status: current as of this development cycle (ns-3.48 in WSL, NetAnim auto-load + WSL `$VAR` bridge fixes applied, `mitigated_sources` telemetry wired, console redesigned). The ESP32 phase (Section 20) is a roadmap, not yet built; the real-data path and testbed it depends on are implemented and offline-tested.*
