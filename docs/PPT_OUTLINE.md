# NetShield-GNN — Presentation Outline

**Deck:** "NetShield-GNN: Graph-Neural DDoS Detection and Automated Mitigation for IoT Networks"
**Slides:** 27 (+ 1 backup) · **Target talk time:** 12–15 min · **Audience:** faculty review panel

> **Read this first — honesty note for the hardware slides.**
> Slides 15 (Core Hardware), 19 (Circuit Diagram) and 23 (Hardware Results) describe the
> **ESP32 testbed that is designed but not yet built**. Every number on them is a *target*, not a
> measurement. They are marked `PLANNED` in this outline — keep that word on the actual slide.
> Everything else in this deck is measured from runs in this repository and is reproducible via
> `scripts/research_protocol.py`.
>
> **Where each number comes from:** `results/reports/RESEARCH_RESULTS.md` (detection, closed loop,
> adversary, real captures) and `docs/PROJECT_REPORT_TECHNICAL.md` §14 (NS-3 policer).
> The confusion matrices on Slide 20 were recomputed from the pooled out-of-fold predictions in
> `results/research/predictions/seed_cv__seed{0..3}/`.

---

## Slide 1 — Title

**On slide**
- **NetShield-GNN**
- Graph-Neural DDoS Detection and Automated Mitigation for IoT Networks
- A packet-level NS-3 simulation with a closed detect → decide → enforce loop
- *Your name · Roll no. · Department · Guide's name · Date*

**Visual:** dark slide; the NetAnim topology screenshot (bots in black/orange, gateway red) faded to 25% behind the title.

**Say:** "This project does not stop at detecting a DDoS attack — it closes the loop and actually cuts the flood off inside a real packet-level simulator, and measures what that costs."

---

## Slide 2 — Agenda

**On slide** (two columns, no sentences)

Introduction · Literature Survey · Motivation · Problem Statement · Objectives
Methodology · Block Diagram · Requirements · Circuit Diagram
Confusion Matrix · Results · Future Work · Conclusion · Timeline · References

**Visual:** 15 numbered chips. Highlight the current section on later slides if your template supports it.

---

## Slide 3 — Introduction: Background

**On slide**
- A **DDoS attack** overwhelms a service using many machines at once — the bottleneck is bandwidth and queue space, not a software bug.
- Since **Mirai (2016)**, the machines are **IoT devices**: cameras, sensors, routers — shipped with default credentials, never patched, always online.
- One infected device is harmless. **Thousands acting together** take down the service they were meant to report to.
- Classical defences live at the **network edge** and act on **aggregate volume**. An IoT botnet is the opposite shape: *many* sources, each individually unremarkable.
- Both the attack and the defence are therefore **structural** problems — about *which device talks to whom, how much, and at the same time as whom*.

**Visual:** left half — 1 device → thin arrow → cloud icon (fine). Right half — 40 devices → 40 arrows of *the same thickness* converging on the same cloud, which turns red. Identical arrow weight in both halves is the entire point.

**Say:** "No single arrow is suspicious. The *pattern* of arrows is."

---

## Slide 4 — Introduction: Importance and Real-World Relevance

**On slide**
- **Mirai** reached roughly 600,000 infected IoT hosts and took down Dyn DNS, cutting off a large part of the US internet (Antonakakis et al., USENIX Security 2017).
- IoT deployments are **growing faster than they are being secured** — industrial sensors, smart meters, medical telemetry, campus networks.
- The devices themselves **cannot be fixed**: no CPU budget for a security agent, no update path, 10-year field life.
- So the defence has to sit **in the network**, at the gateway the devices already pass through.
- The gateway is also where the **cost of a mistake** lands: block the wrong device and you have caused the outage yourself.
- Industry reality: mitigation must be **automatic** (humans are too slow at 5-second timescales) *and* **auditable** (someone must be able to ask "why was my sensor cut off?").

**Visual:** three-item strip — "600k devices · Dyn, Oct 2016" / "cannot patch the endpoint" / "defend at the gateway". Three facts, no more.

---

## Slide 5 — Introduction: Overview of the Application Area

**On slide**
- **Domain:** network security for IoT edge networks — the segment between devices and the cloud service they report to.
- **Where this project operates:** the **IoT gateway / access router**, the single point every device's traffic crosses.
- **What it sees:** 5-second windows of flow telemetry — packet and byte rates, packet-size statistics, inter-arrival timing, port fan-out, protocol mix, TCP-flag profile.
- **What it decides:** a per-device label — `BENIGN` / `SUSPICIOUS` / `MALICIOUS`, with a calibrated probability.
- **What it does:** installs a real enforcement rule — **rate-limit → block → isolate** — and **releases** it when the device goes quiet again.
- **Built as:** a **packet-level NS-3 simulation** (C++) of 24–38-node IoT topologies + a Python detection/mitigation stack + a React operations console + **NetAnim** packet visualisation.
- **Validated against:** real public captures (**CICIoT2023**) replayed through the identical feature code.

**Visual:** horizontal band — `IoT devices → Gateway → Cloud service`, with a dashed box round the gateway labelled "telemetry · detector · policy · enforcement".

---

## Slide 6 — Literature Survey (1 of 2): The problem and the detectors

**On slide** — table, 5 rows

| Work | Contribution | Gap this project addresses |
|---|---|---|
| Mirkovic & Reiher, *ACM CCR* 2004 | The canonical taxonomy of DDoS attacks and defences | Classification only; pre-dates learned detection and per-device granularity |
| Zargar, Joshi & Tipper, *IEEE COMST* 2013 | Survey of flooding defences by deployment point | Concludes source-end defence is best but hardest; no per-device mechanism given |
| Antonakakis et al., *USENIX Sec.* 2017 | Measured the Mirai botnet end to end | Measurement, not defence — establishes the threat model we defend against |
| Doshi, Apthorpe & Feamster, *IEEE SafeThings* 2018 | Per-device ML DDoS detection on consumer IoT traffic | Flat per-device feature vectors — **no topology, no history, no enforcement** |
| Meidan et al., *N-BaIoT*, *IEEE Perv. Comp.* 2018 | Deep autoencoders on benign IoT traffic; unsupervised | Anomaly score only, no decision policy. **Reproduced here as our autoencoder baseline** |

**Say:** "The literature establishes the threat and shows that machine learning works on IoT traffic. What it does not do is use the *network structure* — and it stops at the alert."

---

## Slide 7 — Literature Survey (2 of 2): Graphs, enforcement, datasets

**On slide** — table, 5 rows

| Work | Contribution | How we use / extend it |
|---|---|---|
| Hamilton, Ying & Leskovec, *NeurIPS* 2017 | **GraphSAGE** — inductive neighbourhood aggregation | Our proposed detector; inductive, so it transfers to topologies and fleet sizes never trained on |
| Lo et al., *E-GraphSAGE*, *IEEE NOMS* 2022 | GNN intrusion detection with flow features on edges | **Implemented here as a baseline**; we add the closed loop it lacks |
| Shreedhar & Varghese, *IEEE/ACM ToN* 1996 | **Deficit Round Robin** fair queueing | The per-source scheduler inside our NS-3 gateway policer |
| Nichols & Jacobson, *ACM Queue* 2012 / RFC 8290 | CoDel / FQ-CoDel active queue management | The default queue discipline our policer must beat — and our honest control condition |
| Sharafaldin et al., *IEEE ICCST* 2019 (CIC-DDoS2019); Neto et al., *Sensors* 2023 (CICIoT2023) | Realistic labelled DDoS / IoT capture datasets | **CICIoT2023 captures replayed** through our feature code — sim-trained models tested on real traffic |

**Visual:** a tinted bar under the table holding the gap statement:
> **Identified gap:** detection is well studied in isolation. *Detection + calibrated decision + real enforcement + measured collateral damage*, in one packet-level system, is not.

---

## Slide 8 — Motivation: Why This Project Is Required

**On slide**
- An **alert is not a defence.** Published IoT-DDoS work reports F1 scores; the operator still has to act, by hand, in seconds.
- **Nobody reports the cost of acting.** Precision tells you how often a flag was right. It does **not** tell you how many innocent sensors you cut off, or how long the service stayed down.
- **Flat per-device models ignore the one signal that separates a botnet from a busy day:** coordination. Thirty devices behaving oddly *through the same gateway, in the same window* is a different event from thirty devices behaving oddly independently.
- **"Low and slow" attacks defeat volume thresholds entirely** — each bot stays under any sane per-device limit; only the aggregate is abnormal.
- A **flash crowd looks exactly like a flood** to a volume threshold. A defence that cannot tell them apart is a self-inflicted outage.
- Research-grade claims need **research-grade evaluation**: unseen seeds, unseen topologies, unseen attack families, confidence intervals — not one lucky run.

---

## Slide 9 — Motivation: Challenges in the Existing System

**On slide** — "what breaks, and why" (every number measured in this project)

| Existing approach | How it fails |
|---|---|
| **Static volume thresholds** | Measured **21.66% false-positive rate**, precision **0.214** — it flags ~17 innocent devices *per benign run*, including on runs with no attack at all |
| **Flat per-device ML** (RF / GBM) | Strong offline (macro-F1 0.96) but **blind to coordination**; under an adaptive adversary **43.9% of attacks evade** Random Forest |
| **Unsupervised anomaly detection** | Catches volume; misses application-layer slowloris (PR-AUC **0.75**) and alarms on flash crowds |
| **Edge-only / ISP scrubbing** | Acts on aggregate volume far from the source; cannot name *which device* to throttle |
| **Manual response** | The damage is done in the first 5–10 s; a human ticket cycle is minutes |
| **Evaluation practice** | Single split, one topology, no CIs → results do not survive an unseen topology (measured drop to macro-F1 **0.53** on an unseen `tree` layout) |

**Say:** "Every one of those numbers is from this repository — including the embarrassing ones."

---

## Slide 10 — Motivation: Expected Benefits of the Proposed Work

**On slide**
- **Detection that uses structure** — a 2-hop graph neural network sees each device *and its gateway's whole neighbourhood*, so distributed low-rate attacks become visible.
- **Decisions with honest confidence** — temperature scaling + split-conformal testing, so each rung of the response ladder carries a stated false-alarm budget (5% / 1% / 0.1%).
- **Enforcement that actually happens** — rules take effect on the *next* window's packets, so recovery is measured, not asserted.
- **Collateral damage as a first-class metric** — measured **0.00%** with **rule precision 1.000** across 56 closed-loop runs.
- **Availability you can quote** — clean-traffic availability under attack **63.1% → 89.2%**.
- **Adversarially tested** — evasion success **80.3%** undefended → **3.0%** defended → **0.0%** after hardening.
- **Reproducible and auditable** — fixed seeds, saved out-of-fold predictions, tamper-evident audit log, STIX/CEF alert export.
- **A path to hardware** — the identical detector and policy already run on `pcap` captures and on a Mininet/OpenFlow testbed, so the ESP32 phase is integration, not a rewrite.

---

## Slide 11 — Problem Statement

**On slide** — one framed box, then the constraints

> **Given** 5-second windows of flow telemetry from an IoT access network of 24–38 heterogeneous
> devices, **classify every device in every window** as `BENIGN`, `SUSPICIOUS` or `MALICIOUS`, and
> **automatically install, escalate and release** gateway enforcement rules — such that the attack's
> load on the victim is removed while legitimate traffic and innocent devices are preserved.

**Subject to:**
- **No ground truth at run time.** The decision uses only telemetry a real gateway can collect — no simulator internals (enforced in code by a forbidden-feature assertion).
- **Act within one window.** Decisions happen on window boundaries, so 5 s is the detection floor — a design property, not an artefact.
- **False positives are expensive.** Cutting off a healthy sensor is a worse outcome than a few extra seconds of flood.
- **Generalise.** Unseen seeds, unseen topology families, unseen attack families.
- **Stay safe.** No packet is ever forged, crafted or source-spoofed anywhere in the system; filtering keys on each node's real assigned address. Attack traffic exists only as standard generator load inside the simulator, or inside an isolated lab subnet.

**Measurable success targets:** ≥92% of attack load stopped · ≥95% of legitimate traffic delivered · 0% collateral · detection ≤1 window.

---

## Slide 12 — Objectives

**On slide** — numbered, each with its verification criterion

1. **Build a packet-level IoT network simulator** in NS-3 covering 7 topology families (star, tree, mesh, ring, dumbbell, fat-tree, multi-gateway) with realistic device classes (MQTT sensor, HTTP client, TCP uploader, UDP streamer).
   → *Verify:* congestion emerges from structure, not script — mesh ~32.7% loss vs multi-gateway ~0% at identical offered load.
2. **Generate a labelled corpus** of 6 attack families plus benign-stress scenarios (flash crowd, firmware storm, reboot storm).
   → *Verify:* 275 runs, 133,269 node-windows, 7 topologies, 4 seeds per cell.
3. **Engineer a leakage-free 46-feature node-window representation** in 8 groups.
   → *Verify:* automated forbidden-column assertion + per-group ablation.
4. **Train and compare 9 detectors**, from a threshold rule to a temporal GNN.
   → *Verify:* leave-one-seed-out CV with 95% cluster-bootstrap CIs and Holm-corrected paired tests.
5. **Calibrate the probabilities** so thresholds mean something.
   → *Verify:* ECE before/after; realised FPR against nominal α.
6. **Close the loop** — detector → policy ladder → enforcement that changes the packet path.
   → *Verify:* availability, time-to-detect / mitigate / recover, collateral, rule precision.
7. **Mitigate inside NS-3 and visualise it in NetAnim.**
   → *Verify:* 98.6% of attack load stopped at 96.2% goodput; node colours, per-node counters and link labels in the animator.
8. **Attack our own defence** with a Bayesian (TPE) adaptive adversary, then harden.
   → *Verify:* evasion rate before and after.
9. **Test on real traffic** — CICIoT2023 captures through the identical feature code.
10. **Ship an operations console + REST API** so every result above is inspectable, exportable and audited.
11. **Specify the ESP32 hardware testbed** so the same detector and policy can defend a physical network. *(design complete; build pending)*

---

## Slide 13 — Methodology

**On slide** — six numbered stages, left to right

**1 · Simulate**
NS-3 (C++) builds the real topology, installs real applications and carries real packets. Attack traffic is standard `OnOffHelper` generator load from each bot's real address. A Python discrete-event engine hosts the live closed loop.

**2 · Observe**
Every 5 s, per node: egress volume, packet-size distribution, inter-arrival timing, destination fan-out and port entropy, protocol/service mix, TCP-flag profile, ingress counters, structural position → **46 features**.

**3 · Represent as a graph**
Nodes = devices / routers / cloud. Edges = **physical links** + **communication edges** (who actually talked to whom this window). One graph per window.

**4 · Detect**
2-layer GraphSAGE, mean aggregation: `h_v = ReLU(W_self·h_v + W_nbr·MEAN_{u∈N(v)} h_u)`. Two hops is deliberate — hop 1 is the access router, hop 2 is the gateway and every other talker through it. Then temperature scaling + a split-conformal benign test.

**5 · Decide**
A monotone ladder on calibrated confidence: `monitor (p≥0.80) → rate-limit (0.60) → block (0.85) → isolate (0.95, after 2 consecutive flagged windows) → release (after 3 clean windows)`.

**6 · Enforce and measure**
Python path: the policy's packet filter becomes the engine's filter, so rules bite on the next window. NS-3 path: `NetShieldPolicer`, a custom root `QueueDisc` at the gateway = **64-bucket per-source Deficit Round Robin** (works from the first packet, no detection delay) + **token-bucket policing** (escalating). Packets are counted once at origin and once at the victim, so every ratio lies in [0, 1] by construction.

**Visual:** six chevrons. Keep the formula and the ladder as small captions, not body text.

---

## Slide 14 — Block Diagram

**On slide** — redraw this with PowerPoint shapes

```
┌─────────────────────────── SIMULATION LAYER ───────────────────────────┐
│  NS-3 (C++)  ·  7 topologies  ·  24–38 nodes  ·  real packets          │
│  IoT devices ──▶ access routers ──▶ GATEWAY ──▶ cloud service          │
│  benign apps: MQTT / HTTP / bulk TCP / CoAP     bots: OnOff generators │
└───────────────┬──────────────────────────┬─────────────────────────────┘
                │ flow telemetry (5 s)     │ netanim.xml trace
                ▼                          ▼
┌──────────────────────────────┐   ┌────────────────────┐
│  FEATURE LAYER               │   │  NetAnim           │
│  46 features × 8 groups      │   │  node colour/size  │
│  leakage assertion           │   │  per-node counters │
└──────────────┬───────────────┘   │  link labels       │
               ▼                   └────────────────────┘
┌──────────────────────────────┐
│  GRAPH LAYER                 │  physical + communication edges
│  one window graph per 5 s    │  → WindowGraph
└──────────────┬───────────────┘
               ▼
┌──────────────────────────────┐   ┌───────────────────────────────┐
│  DETECTION LAYER             │──▶│  CALIBRATION                  │
│  GraphSAGE (proposed)        │   │  temperature + conformal      │
│  + 8 baselines               │   └───────────────┬───────────────┘
└──────────────────────────────┘                   ▼
                                   ┌───────────────────────────────┐
                                   │  POLICY ENGINE                │
                                   │  monitor→rate-limit→block→    │
                                   │  isolate→release  (+approval) │
                                   └───────────────┬───────────────┘
                                                   ▼
┌───────────────────────────────────────────────────────────────────────┐
│  ENFORCEMENT LAYER                                                    │
│  Python packet filter  ·  NS-3 NetShieldPolicer (DRR + token bucket)  │
│  ·  OpenFlow (ovs-ofctl) on the Mininet / ESP32 testbed               │
└───────────────┬───────────────────────────────────────────────────────┘
                ▼                                   ▲
┌───────────────────────────────┐                   │ CLOSED LOOP:
│  BACKEND  FastAPI + SQLite    │                   │ rules bite on the
│  metrics · audit · IPFIX · bus│───────────────────┘ NEXT window
└───────────────┬───────────────┘
                ▼
┌───────────────────────────────┐
│  CONSOLE  React + TS + Vite   │  live graph · timeline · alerts ·
│  ECharts · Cytoscape          │  mitigations · research results
└───────────────────────────────┘
```

**Say:** "The arrow coming back up is the whole project. Everything above it has been done before; the loop is what makes the numbers on the results slide mean anything."

---

## Slide 15 — Requirements: Core Hardware

> **Mark column B `PLANNED` on the slide.**

**A · Development & simulation machine (actually used)**

| Item | Spec |
|---|---|
| CPU | x86-64, 8 cores — GNN training is CPU-only |
| RAM | 16 GB (8 GB minimum) |
| Storage | ~20 GB (1,211 archived experiment runs + traces + models) |
| OS | Windows 11 + **WSL2 Ubuntu 24.04** (NS-3 builds and runs in WSL) |
| GPU | **Not required** — every model trained on CPU |

**B · ESP32 hardware testbed (`PLANNED`, Phase 8)**

| Item | Qty | Role |
|---|---|---|
| **ESP32 DevKit V1** (ESP-WROOM-32) | 10–24 | IoT end devices; majority benign firmware, minority lab-only attacker firmware |
| **Raspberry Pi 4 (4 GB)** | 1 | Gateway / AP — `hostapd` + **Open vSwitch** + `tcpdump`; runs `netshield_agent.py`; **the enforcement point** |
| **Raspberry Pi 4 or VM** | 1 | "Cloud" server — Mosquitto MQTT broker + HTTP target |
| DHT22 temperature/humidity sensor | 1 per device | Real telemetry payload |
| 10 kΩ and 220 Ω resistors, LED, push button | per device | Sensor pull-up; status LED; attack-trigger button |
| 5 V 3 A supply / powered USB hub | 1–2 | Board power |
| Managed switch or second AP | 1 | Multi-gateway and mesh layouts |

**Isolation (non-negotiable):** dedicated SSID + VLAN, lab subnet `10.0.0.0/8`, **no route to the internet**; attacker firmware carries a compile-time target guard *and* a runtime subnet check; physical kill switch on the AP.

---

## Slide 16 — Requirements: Software Stack

**On slide** — grouped table (versions are what the repository actually pins)

| Layer | Software |
|---|---|
| **Packet simulator** | **ns-3.48** (C++17), built in WSL2 Ubuntu 24.04; **NetAnim** (Qt5), patched to auto-load a trace from `argv[1]` |
| **Language / runtime** | Python ≥ 3.10 (developed on 3.13); CMake + g++ for NS-3 |
| **Scientific core** | NumPy, pandas, SciPy, scikit-learn, joblib |
| **Deep learning** | **PyTorch ≥ 2.0** + **PyTorch Geometric ≥ 2.4** (pure-PyTorch mean-aggregation fallback if PyG is absent — the active backend is recorded in every checkpoint manifest) |
| **Graphs** | NetworkX |
| **Research harness** | LightGBM (baseline), **Optuna** (TPE adaptive adversary), dpkt (offline `pcap` parsing) |
| **Backend** | **FastAPI** + Uvicorn + Pydantic v2; SQLite (`data/netshield.db`); Prometheus client; PyJWT; ONNX + ONNX Runtime; Redis Streams (optional bus) |
| **Frontend** | **React 18.3 + TypeScript 5.6 + Vite 5.4 + Tailwind 3.4**, Radix UI, **ECharts 5.5** (charts), **Cytoscape 3.30** (live network graph), TanStack Query/Table, Zustand |
| **Visualisation** | Matplotlib + seaborn (paper figures), NetAnim (packet animation) |
| **Testing / QA** | pytest, httpx, **Hypothesis** (property-based), Playwright (console E2E), ruff + mypy |
| **Testbed (real networking)** | Mininet + Open vSwitch + `ovs-ofctl`, `hostapd`, `tcpdump` |
| **ESP32 firmware** (`PLANNED`) | Arduino core for ESP32 / ESP-IDF; PubSubClient (MQTT); Mosquitto broker |

**One line to say:** "Deliberately no Python dependency that needs a C++ toolchain — the whole stack installs from wheels on a student laptop. NS-3 is the only compiled component."

---

## Slide 17 — Requirements: AI & Machine Learning

**On slide**

**Learning task.** 3-class node classification, per device, per 5-second window: `BENIGN` / `SUSPICIOUS` / `MALICIOUS`.

**Input — 46 features in 8 groups** (leakage-checked in code):
`egress volume (7)` · `packet-size distribution (4)` · `timing & burstiness (4)` · `addressing / fan-out & port entropy (5)` · `protocol & service mix (6)` · `TCP-flag profile (10)` · `ingress (7)` · `structural: tier, degree, is_endpoint (3)`

**Corpus.** 275 runs · **133,269** node-windows · 7 topologies · 14 scenarios · 4 seeds per cell. Class balance is naturally extreme (benign ≫ malicious ≫ suspicious), handled with inverse-frequency class weights / `class_weight="balanced"`.

**Nine detectors compared**

| Detector | Sees neighbours | Sees history | Supervision |
|---|---|---|---|
| Threshold rule | no | no | calibration only |
| Autoencoder | no | no | benign rows only |
| Random Forest | no | no | labels |
| LightGBM | no | no | labels |
| GRU sequence | no | 6 windows | labels |
| GATv2 (edge attributes) | 2 hops | no | labels |
| E-GraphSAGE | 2 hops + edge features | no | labels |
| **GraphSAGE (proposed)** | **2 hops** | no | labels |
| Temporal GNN (SAGE + GRU) | 2 hops | 6 windows | labels |

**Evaluation protocol — this is as much the contribution as the model is**
- **Leave-one-seed-out CV** — pooled out-of-fold predictions, never in-sample.
- **95% cluster bootstrap** resampling **whole runs** (windows within a run are not independent).
- **Holm-corrected** paired comparisons + per-cell **Wilcoxon** signed-rank tests.
- **Leave-one-topology-out** and **leave-one-attack-family-out** generalisation.
- **Calibration:** ECE, temperature scaling, split-conformal benign test.
- **Closed-loop KPIs** and a **TPE adaptive adversary**.
- **13 ablations** — drop the graph, drop each feature group, one layer, physical-only, comm-only.

---

## Slide 18 — Model Used

**On slide**

**Proposed model — GraphSAGE node classifier**
- 2 × `SAGEConv` (mean aggregation) + linear read-out:
  `h_v^(k) = ReLU( W_self^(k) h_v^(k−1) + W_nbr^(k) · MEAN_{u∈N(v)} h_u^(k−1) )`, then `z_v = W_out h_v^(K)`
- **Why 2 layers, not more:** it is exactly the receptive field this topology needs — hop 1 is the device's access router, hop 2 is the gateway and, through communication edges, every other talker in the window. That is where a distributed low-rate attack is visible.
- **Why inductive:** it learns a *function of a neighbourhood*, not an embedding per node ID — so a model trained on 24 nodes runs on 38, and on topology families it never saw.
- Weighted cross-entropy; early stopping on validation macro-F1; fixed seeds; backend (PyG vs fallback) recorded in the checkpoint manifest.
- **Then:** temperature scaling (T ≈ 1.45) + split-conformal benign test, so the policy ladder can act at 0.95 / 0.99 / 0.999 with a nominal 5% / 1% / 0.1% false-alarm budget.

**Honest headline — the result we did not expect**
> On **pooled offline accuracy, Random Forest wins**: macro-F1 **0.9648** vs GraphSAGE **0.9225** (Holm *p* < 0.001).
> In **closed-loop defence the ordering flips**: availability **89.2%** (GraphSAGE) vs **79.9%** (RF); **56/56** runs recovered vs **48/56**.
> Under an **adaptive adversary**, RF is evaded **43.9%** of the time; GraphSAGE **3.0%**; hardened GraphSAGE **0.0%**.
>
> **Conclusion: offline macro-F1 is the wrong objective.** What matters is whether the loop holds under attack.

**Say this out loud — it is the strongest slide in the deck.** Panels reward a student who reports a result against their own hypothesis.

**Cost:** GraphSAGE 459.5 s to fit, 360 µs per node-window at inference — comfortably real-time at a 5 s window (Random Forest: 8.2 s / 15.7 µs).

---

## Slide 19 — Circuit Diagram

> **Label `PLANNED — ESP32 testbed, Phase 8`.**

**Part A — per-device circuit (one ESP32 sensor node)**

```
                  ESP32 DevKit V1 (ESP-WROOM-32)
                 ┌──────────────────────────────┐
   5 V USB ─────▶│ VIN                      3V3 ├──┬────────────────┐
         GND ───▶│ GND                      GND ├──┴──┐            │
                 │                              │     │        ┌───┴───┐
                 │ GPIO4  ◀── DATA ─────────────┼─────┼────────┤ DHT22 │
                 │                              │     └────────┤ temp/ │
                 │  10 kΩ pull-up: 3V3 ──┬── DATA (GPIO4)      │ hum.  │
                 │                              │              └───────┘
                 │ GPIO2  ──▶ 220 Ω ──▶ LED ──▶ GND    (status: green = benign
                 │                              │       telemetry, red = flooding)
                 │ GPIO0  ──▶ push button ──▶ GND      (attack trigger,
                 │            INPUT_PULLUP      │       lab-only firmware)
                 │                              │
                 │ Wi-Fi (on-module antenna) ───┼──▶ isolated lab SSID
                 └──────────────────────────────┘
```

- **DHT22 on GPIO4** with a **10 kΩ pull-up** to 3V3 — supplies the real MQTT telemetry payload.
- **Status LED on GPIO2** via **220 Ω** — lets the audience see at a glance which board is flooding.
- **Momentary button on GPIO0** (`INPUT_PULLUP`, active-low) — arms the lab-only attack profile; the alternative trigger is an MQTT command from the test controller.
- Power: 5 V USB per board, or a powered hub for the whole fleet.

**Part B — network wiring**

```
 [ESP32 #1 benign] ┐
 [ESP32 #2 benign] ┤      Wi-Fi          ┌──────────────────┐  Ethernet  ┌───────────┐
 [ESP32 #3 benign] ┼────────────────────▶│  GATEWAY / AP    │───────────▶│  "Cloud"  │
 [ESP32 #4 BOT*  ] ┤  isolated SSID,     │  Raspberry Pi 4  │   uplink   │  Pi / VM  │
 [ESP32 #N ...   ] ┘  10.0.0.0/8,        │  hostapd + OVS   │            │  MQTT +   │
                      no internet route  │  tcpdump (5 s)   │            │  HTTP     │
                                         │  netshield_agent │            └───────────┘
                                         └────────┬─────────┘
                                   ovs-ofctl meter / drop on the
                                   offending ESP32's access port
```

**Live loop on hardware — reuses existing code unchanged:**
`tcpdump` rotates a 5 s capture → `realnet.pcap_ingest` → 46 features → trained detector → `MitigationEngine` → `ovs-ofctl` meter/drop. The agent writes `agent_actions.json` in NetShield's own schema, so **the console, metrics and audit ingest hardware runs exactly like simulated ones**.

---

## Slide 20 — Confusion Matrix

**Measured:** pooled out-of-fold predictions, 4 seed folds, **n = 108,494 node-windows**.

**A · GraphSAGE (proposed)** — rows = true, columns = predicted

| | pred BENIGN | pred SUSPICIOUS | pred MALICIOUS | recall |
|---|---:|---:|---:|---:|
| **true BENIGN** (100,984) | **100,229** | 126 | 629 | 99.25% |
| **true SUSPICIOUS** (489) | 7 | **475** | 7 | 97.14% |
| **true MALICIOUS** (7,021) | 0 | 69 | **6,952** | 99.02% |

**B · Binary operational view** (`SUSPICIOUS ∪ MALICIOUS` = hostile)

| Metric | GraphSAGE | Random Forest | Threshold baseline |
|---|---:|---:|---:|
| True positives | 7,503 | 7,479 | 5,945 |
| False positives | 755 | 380 | **21,874** |
| False negatives | **7** | 31 | 1,565 |
| True negatives | 100,229 | 100,604 | 79,110 |
| Precision | 0.9086 | 0.9516 | 0.2137 |
| **Recall** | **0.9991** | 0.9959 | 0.7916 |
| **False-positive rate** | **0.75%** | 0.38% | **21.66%** |
| F1 (hostile) | 0.9517 | 0.9733 | 0.3366 |
| Accuracy | 99.30% | 99.62% | 78.40% |
| Macro-F1 (3-class) | 0.9225 | 0.9648 | 0.4806 |

**Three things to point at**
1. **Only 7 missed hostile windows out of 7,510** — recall 99.91%. **No malicious window was ever called benign** (that cell is exactly **0**).
2. The errors that remain are **BENIGN → MALICIOUS (629)** — caution, not blindness — and they concentrate in the **flash-crowd** stress scenario, which is genuinely ambiguous.
3. The threshold baseline's **21,874 false positives** is the entire argument for this project, in one number.

**Also quote:** recall at a fixed 1% FPR = **0.9997 [0.9988, 1.0000]** · PR-AUC (hostile) = **0.9688** · ECE after calibration = **0.0092**.

**Visual:** render A as a 3×3 heatmap — `evaluation/figures.py::plot_confusion_matrices` already does this. Row-normalise so the diagonal reads 99.25 / 97.14 / 99.02.

---

## Slide 21 — Results: Software (1 of 2) — Detection & generalisation

**Leave-one-seed-out CV** (212 runs, 108,494 node-windows; brackets = 95% cluster-bootstrap CI)

| Detector | Macro-F1 | PR-AUC (hostile) | Recall @ 1% FPR | FPR | ECE |
|---|---:|---:|---:|---:|---:|
| Random Forest | **0.9648** [0.9468, 0.9762] | 0.9972 | 0.9999 | 0.38% | 0.0026 |
| GRU sequence | 0.9622 | **0.9995** | 1.0000 | 0.18% | 0.0018 |
| LightGBM | 0.9595 | 0.9958 | 0.9996 | 0.32% | 0.0036 |
| GATv2 | 0.9315 | 0.9821 | 0.9996 | 0.72% | 0.0067 |
| E-GraphSAGE | 0.9306 | 0.9715 | 1.0000 | 0.76% | 0.0073 |
| **GraphSAGE (proposed)** | 0.9225 [0.8912, 0.9439] | 0.9688 | 0.9997 | 0.75% | 0.0078 |
| Temporal GNN | 0.8484 | 0.9760 | 1.0000 | 0.81% | 0.0080 |
| Autoencoder (unsupervised) | 0.5671 | 0.8790 | 0.7020 | 1.14% | 0.0210 |
| Threshold baseline | 0.4806 | 0.5241 | 0.4973 | **21.66%** | 0.2738 |

**Bots found / innocents flagged.** Every learned detector finds **112/112, 224/224, 144/144 …** bots with **0 innocent devices flagged**, in every scenario. The threshold baseline flags **476–575 innocents per scenario** — including **476 on a run with no attack at all**.

**Generalisation**
- **Leave-one-topology-out:** LightGBM 0.934 mean macro-F1, RF 0.903, GraphSAGE 0.841. Every model collapses on the unseen `tree` family (0.53–0.61) — **reported, not hidden**; that is the honest limit of 7 topology families.
- **Leave-one-attack-family-out:** RF 0.969 mean PR-AUC, LightGBM 0.963, GraphSAGE 0.689 — the GNN extrapolates *worst* to a never-seen family and *best* under adaptive attack.
- **Benign stress (false alarms, no attack present):** RF 0.0 devices/run; GraphSAGE 4.7 on flash crowd; threshold baseline 16.9.
- **Real traffic (CICIoT2023, trained only in simulation):** all GNN variants detect 100% of attack windows across all six DDoS captures. Honest caveat: benign-capture flagging is also high, and labels are per file rather than per host — **a calibration gap we name rather than paper over**.

---

## Slide 22 — Results: Software (2 of 2) — Closed loop, in-sim mitigation, adversary

**A · Closed loop — each detector put in charge of the gateway** (unseen seeds; 56 runs)

| Defence | Availability under attack | Detect | Mitigate | Recover | Recovered | Collateral | Rule precision |
|---|---:|---:|---:|---:|---:|---:|---:|
| **GraphSAGE (proposed)** | **89.2%** | 5.0 s | 5.0 s | 10.0 s | **56/56** | **0.00%** | **1.000** |
| Temporal GNN | 89.5% | 5.0 s | 5.0 s | 10.0 s | 56/56 | 0.00% | 1.000 |
| LightGBM | 86.4% | 5.0 s | 5.0 s | 10.0 s | 54/56 | 0.00% | 0.995 |
| Random Forest | 79.9% | 5.0 s | 5.0 s | 10.0 s | 48/56 | 0.00% | 0.993 |
| Threshold baseline | 87.7% | 5.0 s | — | — | 56/56 | 0.38% | 0.481 |
| **no defence** | **63.1%** | — | — | — | 0/56 | — | — |

→ **+26.1 points of availability, 0% collateral, rule precision 1.000, every run recovered.**

**B · Mitigation inside NS-3 / NetAnim** (28 s run, dumbbell bottleneck, 10 IoT devices, 8 bots)

| Attack family | Topology | Attack load stopped | Legitimate delivered |
|---|---|---:|---:|
| udp_flood | dumbbell | **98.6%** | 96.2% |
| udp_flood | tree | 97.7% | 96.2% |
| syn_flood | star | 97.7% | 96.2% |
| mixed | multi_gateway | 95.3% | 96.4% |
| slowloris | dumbbell | 93.7% | 96.2% |

**All five clear the targets (≥92% stopped / ≥95% delivered).** Baseline and control runs:

| Run | Attack packets reaching the cloud | Legitimate delivered |
|---|---:|---:|
| attack, no defence | 48,055 | 99.7% |
| attack, **defended** | **3,224 — 14.9× fewer** | 96.2% |
| no attack, defence **on** | — | 99.81% |
| no attack, defence **off** | — | 99.81% |

→ **The policer is cost-free when idle** (99.81% either way). The 96.2% is the ~3 s detect-and-escalate transient, which trades directly against false-positive safety — which is why action requires two consecutive flooding intervals.
→ **Zero false positives in enforcement:** only `atk-00…atk-07` were ever throttled or blocked; **no legitimate device ever appears** in NetAnim's per-node counters.

**C · Adaptive adversary** (Optuna/TPE over family, rate, botnet size, packet size, pulsing, jitter, stagger, port)

| Defence | Evasion success | Max undetected damage |
|---|---:|---:|
| none | **80.3%** | 97.2% |
| Random Forest | 43.9% | 97.1% |
| LightGBM | 4.5% | 90.1% |
| GraphSAGE | 3.0% | 7.7% |
| **GraphSAGE, adversarially hardened** | **0.0%** | **3.5%** |

Hardening cost on clean data: macro-F1 **0.8695 → 0.8919**, FPR **0.0143 → 0.0127** — it got *better*, not worse.

**D · What NetAnim shows** — four channels, since the trace format carries no per-packet styling:
bot node **colour** red → orange `RATE-LIMITED` → black `BLOCKED` + shrink + quarantine slide · gateway **colour** grey → orange → red · **per-node counters** `Blocked pkts` / `Throttled pkts` (Stats → Counter Tables) · **link label** `clear → THROTTLING 11,782 pkt/s → BLOCKING 11,832 pkt/s`.

---

## Slide 23 — Results: Hardware

> **Label this slide `PLANNED — not yet measured`. Do not let it read as a result.**

**Status.** The hardware path is **designed and de-risked, not built**. What *is* built and offline-tested is the real-networking path it depends on: `realnet.pcap_ingest` (real `pcap` → the trained feature schema) and `testbed/netshield_agent.py` (captures → detector → `MitigationEngine` → `ovs-ofctl` rules on Mininet/OVS). Swapping the traffic *source* from Mininet namespaces to ESP32 boards is **integration, not a rewrite**.

**Phased plan with exit criteria**

| Phase | Scope | Exit criterion |
|---|---|---|
| **P0 Bring-up** | 1 benign ESP32 → AP → broker; agent in `--dry-run` | Captures parse; features and scores produced end to end |
| **P1 Detect** | + 1 attacker ESP32; score but do not enforce | Bot flagged above trigger during its flood; benign devices stay low |
| **P2 Enforce** | Enable real OpenFlow drop/meter on the bot's port | Flood drops at the gateway; cloud service recovers |
| **P3 Scale** | N ≈ 10–24 boards; star (1 AP), mesh (ESP-MESH), multi-gateway (2 APs) | KPIs produced per topology family |
| **P4 Sim-to-real** | Same scenario in the simulator and on hardware | On-hardware TTD / availability-recovery / collateral compared to the simulator's predicted ranges |

**Expected outcomes — hypotheses to be tested, not claims**
- Detection latency ≈ **one capture window (5 s)** — the agent already windows on capture rotation.
- Collateral **0%** if rule precision transfers; **this is the headline risk.**
- Availability recovery **lower than in simulation** — Wi-Fi jitter and real TCP stacks add variance the model never saw.

**Known risks → mitigation already in the codebase**
- **Domain gap (train on sim, test on real)** → per-deployment temperature scaling (`models/calibration.py`), a short fine-tune on labelled lab captures, conformal wrappers for honest uncertainty.
- **ESP32 throughput is modest** — one board cannot match a simulated bot → use several attacker boards, or lower the benign baseline so the experiment stays meaningful.
- **Clock / capture gaps** → window on the gateway's monotonic clock (already the agent's behaviour).
- **Safety** → air-gapped lab subnet, compile-time *and* runtime target guards, physical kill switch.

---

## Slide 24 — Future Work

**On slide** — ordered by value; each item names the gap it closes

1. **GNN-driven enforcement inside NS-3.** Today the NS-3/NetAnim path enforces with a *rate-based policer* so the flood can be seen being cut off, while the GNN decides in the Python closed loop. **Plan:** a two-pass mode that scores the open-loop NS-3 flows with the GNN and replays its exact decisions as the NS-3 enforcement schedule — so NetAnim shows *GNN-driven* mitigation. **This is the most valuable next step and the deck's main acknowledged limitation.**
2. **Build the ESP32 testbed** (P0 → P4 above) and publish the measured sim-to-real calibration gap.
3. **Fix the unseen-topology collapse** (macro-F1 0.53 on an unseen `tree` family) — more topology families, topology-randomised training, structural augmentation.
4. **Close the real-capture calibration gap** — per-site conformal calibration so CICIoT2023 benign captures stop over-flagging.
5. **Per-packet visualisation.** NetAnim's trace format carries only `fId/tId/uId` plus four timestamps, so individual packets cannot be coloured. **Plan:** a custom WebGL replay in the console driven by the same trace.
6. **Attack-family fidelity.** Only `udp_flood` is transport-exact in NS-3; the rest are documented offered-load approximations, because TCP congestion control defeats offered-load modelling. **Plan:** native TCP-state attack applications, so slowloris' held connections exist in NS-3 as well as in the Python engine.
7. **Online / continual learning** with drift detection, so a deployed gateway adapts without a full retrain.
8. **Explainability for the operator** — per-feature attribution behind every installed rule, so "why was my sensor throttled?" has a one-click answer.
9. **Multi-gateway coordination** — federated detection across gateways that each see only part of the botnet.
10. **Hardware-in-the-loop with a real SDN controller** (ONOS / Ryu) instead of direct `ovs-ofctl`.

---

## Slide 25 — Conclusion

**On slide**

- Built a **complete, closed-loop DDoS defence** for IoT networks — packet-level NS-3 simulation, 46-feature leakage-checked telemetry, a graph neural detector, calibrated decisions, and **enforcement that genuinely changes the packet path**.
- **Detection works:** 99.91% recall on hostile windows — **7 misses in 108,494 node-windows** — at 0.75% FPR, with **zero innocent devices flagged** by any learned detector in any scenario.
- **Mitigation works, and its cost is measured:** **98.6%** of attack load stopped at **96.2%** goodput inside NS-3; availability under attack **63.1% → 89.2%**; **0.00% collateral** at **rule precision 1.000** over 56 runs; attack packets at the victim **48,055 → 3,224**.
- **It survives being attacked:** adaptive-adversary evasion **80.3% → 3.0% → 0.0%** after hardening — and hardening *improved* clean accuracy.
- **The honest finding:** the best offline macro-F1 (Random Forest, 0.9648) is **not** the best defence (availability 79.9% vs 89.2%; evasion 43.9% vs 3.0%). **Offline accuracy is the wrong objective for a system that has to act.** That is the result worth taking away.
- **Limits stated, not hidden:** unseen-topology collapse, non-exact TCP attack families, policer-rather-than-GNN enforcement inside NS-3, and an ESP32 testbed that is designed but unbuilt.
- Everything is **reproducible:** fixed seeds, saved out-of-fold predictions, 1,211 archived runs, an auto-generated results report, and a tamper-evident audit log.

**Closing line:** "The contribution is not another detector with a better F1. It is an honest, end-to-end measurement of what it costs to actually act on one."

---

## Slide 26 — Work Timeline

**On slide** — Gantt-style bars; phases 1–7 complete, 8 planned, 9 in progress

| # | Phase | Weeks | Deliverable | Status |
|---|---|---|---|---|
| 1 | Literature survey & problem scoping | 1–2 | Gap statement, threat model, success targets | ✅ |
| 2 | NS-3 simulator: topologies, device classes, applications | 3–5 | 7 topology families, 24–38 nodes, real packets | ✅ |
| 3 | Attack scenarios & corpus generation | 5–7 | 6 attack families + 3 benign-stress; **275 runs / 133,269 windows** | ✅ |
| 4 | Feature engineering & leakage audit | 7–8 | **46 features in 8 groups** + forbidden-column assertion | ✅ |
| 5 | Detector development & baselines | 8–11 | **9 detectors**; GraphSAGE + 8 baselines; 13 ablations | ✅ |
| 6 | Research protocol: CV, CIs, calibration, generalisation | 11–13 | Leave-one-seed / topology / family-out; bootstrap CIs; Holm tests; conformal | ✅ |
| 7 | Closed loop, NS-3 policer, NetAnim, adversary, console | 13–16 | Availability 89.2%; **98.6% / 96.2%** in-sim; evasion → 0.0%; React console + FastAPI | ✅ |
| 8 | **ESP32 hardware testbed (P0 → P4)** | 17–22 | Physical IoT network defended by the same detector and policy; sim-to-real calibration | ⏳ **planned** |
| 9 | Report, paper draft, viva preparation | 22–24 | Technical + simple reports, this deck, reproducibility pack | 🔄 in progress |

**Visual:** horizontal bars on a week axis — one solid colour for complete, hatched/outline for planned. Legend bottom-right.

---

## Slide 27 — References

**On slide** — IEEE style, two columns, 9–10 pt

1. M. Antonakakis *et al.*, "Understanding the Mirai botnet," in *Proc. 26th USENIX Security Symp.*, 2017.
2. C. Kolias, G. Kambourakis, A. Stavrou and J. Voas, "DDoS in the IoT: Mirai and other botnets," *Computer*, vol. 50, no. 7, 2017.
3. J. Mirkovic and P. Reiher, "A taxonomy of DDoS attack and DDoS defense mechanisms," *ACM SIGCOMM Comput. Commun. Rev.*, vol. 34, no. 2, 2004.
4. S. T. Zargar, J. Joshi and D. Tipper, "A survey of defense mechanisms against distributed denial of service flooding attacks," *IEEE Commun. Surveys Tuts.*, vol. 15, no. 4, 2013.
5. D. Moore, C. Shannon, D. J. Brown, G. M. Voelker and S. Savage, "Inferring internet denial-of-service activity," *ACM Trans. Comput. Syst.*, vol. 24, no. 2, 2006.
6. R. Doshi, N. Apthorpe and N. Feamster, "Machine learning DDoS detection for consumer Internet of Things devices," in *Proc. IEEE Security and Privacy Workshops (SafeThings)*, 2018.
7. Y. Meidan *et al.*, "N-BaIoT: Network-based detection of IoT botnet attacks using deep autoencoders," *IEEE Pervasive Computing*, vol. 17, no. 3, 2018.
8. W. L. Hamilton, R. Ying and J. Leskovec, "Inductive representation learning on large graphs," in *Proc. NeurIPS*, 2017.
9. T. N. Kipf and M. Welling, "Semi-supervised classification with graph convolutional networks," in *Proc. ICLR*, 2017.
10. W. W. Lo, S. Layeghy, M. Sarhan, M. Gallagher and M. Portmann, "E-GraphSAGE: A graph neural network based intrusion detection system for IoT," in *Proc. IEEE/IFIP NOMS*, 2022.
11. M. Fey and J. E. Lenssen, "Fast graph representation learning with PyTorch Geometric," in *ICLR Workshop on Representation Learning on Graphs and Manifolds*, 2019.
12. F. Pedregosa *et al.*, "Scikit-learn: Machine learning in Python," *J. Mach. Learn. Res.*, vol. 12, 2011.
13. G. F. Riley and T. R. Henderson, "The ns-3 network simulator," in *Modeling and Tools for Network Simulation*, Springer, 2010.
14. M. Shreedhar and G. Varghese, "Efficient fair queueing using deficit round robin," *IEEE/ACM Trans. Netw.*, vol. 4, no. 3, 1996.
15. K. Nichols and V. Jacobson, "Controlling queue delay," *ACM Queue*, vol. 10, no. 5, 2012.
16. T. Hoeiland-Joergensen, P. McKenney, D. Taht, J. Gettys and E. Dumazet, "The flow queue CoDel packet scheduler and active queue management algorithm," RFC 8290, 2018.
17. V. Jacobson, "Congestion avoidance and control," in *Proc. ACM SIGCOMM*, 1988.
18. M. Allman, V. Paxson and E. Blanton, "TCP congestion control," RFC 5681, 2009.
19. W. Eddy, "TCP SYN flooding attacks and common mitigations," RFC 4987, 2007.
20. P. Ferguson and D. Senie, "Network ingress filtering: Defeating denial of service attacks which employ IP source address spoofing," RFC 2827 (BCP 38), 2000.
21. B. Claise, B. Trammell and P. Aitken, "Specification of the IP flow information export (IPFIX) protocol," RFC 7011, 2013.
22. I. Sharafaldin, A. H. Lashkari, S. Hakak and A. A. Ghorbani, "Developing realistic distributed denial of service (DDoS) attack dataset and taxonomy," in *Proc. IEEE ICCST*, 2019. (CIC-DDoS2019)
23. E. C. P. Neto *et al.*, "CICIoT2023: A real-time dataset and benchmark for large-scale attacks in IoT environment," *Sensors*, vol. 23, no. 13, 2023.
24. N. Koroniotis, N. Moustafa, E. Sitnikova and B. Turnbull, "Towards the development of realistic botnet dataset in the Internet of Things environment: Bot-IoT," *Future Generation Computer Systems*, vol. 100, 2019.
25. B. Lantz, B. Heller and N. McKeown, "A network in a laptop: Rapid prototyping for software-defined networks," in *Proc. ACM HotNets*, 2010.
26. T. Akiba, S. Sano, T. Yanase, T. Ohta and M. Koyama, "Optuna: A next-generation hyperparameter optimization framework," in *Proc. ACM KDD*, 2019.

---

## Slide 28 (BACKUP) — Anticipated Questions

Keep this slide hidden; pull it up only if asked.

| Likely question | Short answer |
|---|---|
| "Why does your proposed GNN lose on macro-F1?" | It does, by 0.042, and we report it. It wins where it matters: availability (89.2% vs 79.9%), runs recovered (56/56 vs 48/56), evasion (3.0% vs 43.9%). Random Forest's errors are the *expensive* kind under adaptive attack. |
| "Is the attack traffic real?" | Real packets through a real NS-3 stack, generated by standard `OnOffHelper` applications from each node's real assigned address. **Nothing is forged or spoofed anywhere in the system.** |
| "Is the mitigation real or cosmetic?" | A custom root `QueueDisc` in the NS-3 datapath — 64-bucket per-source DRR plus token-bucket policing. Measured 48,055 → 3,224 attack packets at the victim. Control runs prove it is cost-free when idle (99.81% either way). |
| "Why 5-second windows?" | It is the detection floor by design: decisions happen on window boundaries. Shorter windows give noisier features and a worse FPR — a stated trade-off, not an artefact. |
| "Why doesn't NetAnim colour individual packets?" | Its trace format carries only `fId/tId/uId` and four timestamps per packet; there is no per-packet styling API. Enforcement is surfaced four other ways (node colour, node size, per-node counters, link labels). |
| "What is the weakest part?" | Two things: the unseen-`tree`-topology collapse (macro-F1 0.53), and that NS-3 enforcement is the policer rather than the GNN. Both are named in Future Work with a plan. |
| "Hardware?" | Designed and de-risked, not built. The real-networking path it needs — pcap ingest plus the OVS agent — is implemented and offline-tested. |
