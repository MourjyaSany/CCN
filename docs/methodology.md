# NetShield-GNN — Methodology

This document specifies exactly how the network is modelled, how traffic and
attacks are generated, how features are computed, how the graph is built, how
the models are trained, and how mitigation decisions are made. It is the
reference a reader should be able to reproduce the project from.

---

## 1. Network model

### 1.1 Discrete-event formulation

The simulator maintains an event queue `Q` of `(t, seq, callback, payload)`
ordered by simulated time `t`, with `seq` breaking ties so execution is
deterministic. The loop pops the earliest event, advances the clock to its
timestamp, and executes it. Time therefore advances only when something happens.

### 1.2 Link model

Each physical link is instantiated as **two directed channels** (full duplex).
A channel is a single-server queue:

| Quantity | Formula |
|---|---|
| Serialisation (transmission) delay | $D_{tx} = \dfrac{8 \cdot S}{B}$ for a frame of $S$ bytes on a link of $B$ bit/s |
| Propagation delay | $D_{prop}$ — a configured constant per link |
| Queueing delay | $D_{q}$ — **emergent**: the time a packet waits behind others |
| Buffer | Drop-tail FIFO of $K$ packets; arrival at a full buffer is discarded |

End-to-end one-way delay for a packet crossing $H$ hops:

$$D_{e2e} = \sum_{h=1}^{H}\left( \frac{8 S}{B_h} + D_{prop,h} + D_{q,h} \right)$$

Only the first two terms are configured. $D_q$ falls out of the queue dynamics,
which is why latency rises under attack without anyone telling it to.

For the default topology the fixed part is
$1.5 + 3.0 + 12.0 = 16.5$ ms, which matches the ≈17 ms measured on benign runs.

### 1.3 Node processing model

Routers, the gateway and the cloud additionally run a **processing server** with
service rate $\mu = \texttt{forwarding\_pps}$. A packet arriving when the
backlog $\max(0, t_{busy} - t)\cdot\mu$ already exceeds `proc_queue` is dropped
with reason `cpu_overload`.

This second bottleneck is what makes a SYN flood hurt: minimum-size segments
consume almost no bandwidth but the same processing slot as a full-size frame.

### 1.4 Utilisation and loss

$$\rho = \frac{\text{time the serialiser was busy}}{\text{window length}}
\qquad
L = \frac{\text{dropped}}{\text{delivered} + \text{dropped}}$$

Loss is attributed by cause: `queue_overflow`, `cpu_overload`, `random_loss`
(residual wireless bit errors), `no_route`, and the four `mitigation_*` reasons.
This decomposition is what lets the report separate *congestion* damage from
*defence* damage.

---

## 2. Transport model

`simulation/tcp.py` implements a compact but genuine TCP.

**Modelled**

- Three-way handshake (`SYN` → `SYN+ACK` → `ACK`) with SYN retransmission and a
  bounded retry count (4). A connection whose SYNs go unanswered *fails* — the
  mechanism by which a SYN flood denies service to legitimate devices.
- Cumulative acknowledgement with `rcv_next` tracking; a sequence gap produces a
  duplicate ACK.
- Reno congestion control:

  $$
  cwnd \leftarrow
  \begin{cases}
    cwnd + \text{MSS} & cwnd < ssthresh \quad\text{(slow start)}\\[2pt]
    cwnd + \dfrac{\text{MSS}^2}{cwnd} & \text{otherwise (congestion avoidance)}
  \end{cases}
  $$

  On timeout: $ssthresh \leftarrow \max(2\,\text{MSS}, \text{inflight}/2)$,
  $cwnd \leftarrow \text{MSS}$.
- Jacobson/Karels RTO with Karn's algorithm:

  $$SRTT \leftarrow \tfrac{7}{8}SRTT + \tfrac{1}{8}R,\quad
    RTTVAR \leftarrow \tfrac{3}{4}RTTVAR + \tfrac14 |SRTT - R|,$$
  $$RTO \leftarrow \mathrm{clamp}(SRTT + 4\,RTTVAR,\ 0.2\text{ s},\ 8\text{ s})$$

  with exponential backoff on repeated timeouts and RTT samples discarded for
  retransmitted segments.

**Not modelled** (documented simplifications, none of which changes the
qualitative congestion behaviour the experiments depend on): fast
retransmit/fast recovery, SACK, window scaling, Nagle, delayed ACKs, and
receiver-window flow control.

---

## 3. Traffic model

### 3.1 Legitimate IoT devices

| Class | Transport | Port | Shape | Payload |
|---|---|---|---|---|
| `mqtt_sensor` | TCP | 8883 | persistent session, publish every 2 s ±35% | 48–220 B |
| `http_client` | TCP | 80 | short-lived request/response every 6 s ±50% | 180–640 B req, 500–6000 B resp |
| `tcp_uploader` | TCP | 443 | bulk transfer every 20 s ±40% | 20–120 kB |
| `udp_streamer` | UDP | 5683 | constant bitrate, 80 ms ±20% | 200–400 B |

The mix is apportioned by largest-remainder from `traffic.device_mix`, then
shuffled with a derived RNG so class assignment is uncorrelated with node index.
Every class reconnects with exponential backoff `(1, 2, 4, 8, 15) s` after a
failure — this is what turns a SYN flood from an abstract packet count into an
observable **service outage**.

### 3.2 Attack families

| Family | Layer | Mechanism | Signature |
|---|---|---|---|
| `udp_flood` | 3/4 | connectionless datagrams at a fixed rate | uplink saturation, drop-tail loss, queueing delay |
| `syn_flood` | 4 | bare `SYN`s, optionally spoofed | half-open table exhaustion; **low bandwidth** |
| `http_flood` | 7 | complete TCP transactions (handshake → request → response → teardown) | worker-pool exhaustion; each packet is individually plausible |
| `mixed` | — | each bot deterministically assigned one of the above | multi-vector |

**Burst/pulsing shaping.** With `attack.burst.enabled`, an attacker transmits
only while $\bmod(t - t_0,\ T_{on}+T_{off}) < T_{on}$. This defeats moving-average
thresholds and is the mechanism behind Experiment 6.

**Source spoofing.** Addresses are drawn from `10.66.0.0/16`, a block the
topology never assigns, so a spoofed packet can never be confused with a real
device. SYN+ACKs sent to spoofed addresses are routed toward the gateway,
consume real downstream bandwidth, and are accounted as *backscatter* — the cost
a SYN flood imposes on the defender's own link.

### 3.3 Server resource model

The cloud server exhausts three resources in increasing order of subtlety:

1. **Link/forwarding capacity** — handled by the channels and processing servers.
2. **SYN backlog** — a table of 256 half-open entries with an 8 s timeout.
   When full, new `SYN`s are silently discarded and the client eventually fails.
3. **Worker slots** — 64 concurrent request handlers with a 4 ms service time,
   giving ≈250 requests/s of application capacity.

---

## 4. Feature engineering

### 4.1 Flow records

The gateway exports one record per `(5-second window, 5-tuple)`. Second-order
statistics use running sums:

$$\mathrm{Var}(S) = \frac{1}{n}\sum S_i^2 - \left(\frac{1}{n}\sum S_i\right)^2,
\qquad
\sigma_{IAT} = \sqrt{\frac{1}{n}\sum \Delta_i^2 - \bar{\Delta}^2}$$

### 4.2 The 46 node-window features

One row per `(run, window, node)`, grouped as:

- **Egress volume** (7): packets, bytes, packet rate, byte rate, flow count,
  packets/flow, bytes/flow.
- **Packet-size distribution** (4): mean, standard deviation, min, max.
  Machine-generated floods have near-zero size variance.
- **Timing** (4): mean IAT, IAT standard deviation, burstiness
  $CV = \sigma_{IAT}/\bar{IAT}$, mean flow duration.
- **Addressing / fan-out** (5): unique destination nodes, destination ports,
  source ports, **source IPs** (the spoofing signal), and destination-port
  Shannon entropy $H = -\sum p_i \log_2 p_i$.
- **Protocol & service mix** (6): TCP/UDP fractions and MQTT/HTTP/CoAP/other
  fractions derived from destination ports.
- **TCP flag profile** (10): SYN, SYN+ACK, ACK, FIN, RST, PSH counts; SYN rate;
  SYN ratio; **SYN-to-ACK ratio** (the half-open asymmetry); connection attempts.
- **Ingress** (7): packets, bytes, rate, flow count, unique source nodes,
  unique source IPs, in/out ratio.
- **Structural** (3): tier, degree, endpoint indicator.

**Infrastructure attribution.** Routers and the gateway originate no flow, but
they forward every one. `_transit_aggregate` attributes each flow to every node
on its path, so a router's row is the traffic it carries — exactly what its
interface counters would report. Without this the graph would have no
aggregation points and the whole relational argument would collapse.

### 4.3 Label leakage prevention

Features are derived **only** from what a gateway can observe by exporting flow
records. The simulator's ground truth — `attack_packets`, `attack_type`, and the
`app` tag, which literally contains the string `attack_udp` — is used solely to
construct labels. `assert_no_leakage()` enforces this and is called inside
`FeatureScaler.fit`, so no model can be trained on a leaking column;
`tests/test_features_and_graph.py::TestLabelLeakage` locks it down.

### 4.4 Ground-truth labelling

$$
\text{severity} = \underbrace{\frac{\text{attack packets}}{\text{total packets}}}_{\text{composition}}
\times
\underbrace{\frac{\text{active attack seconds}}{\text{window length}}}_{\text{temporal coverage}}
$$

$$
y = \begin{cases}
\texttt{MALICIOUS} & \text{severity} \ge 0.55\\
\texttt{SUSPICIOUS} & 0.12 \le \text{severity} < 0.55\\
\texttt{BENIGN} & \text{otherwise}
\end{cases}
$$

Duty is computed **analytically** from the attack schedule (`attack_duty`), so it
is exact even for pulsing attacks whose cycle is not aligned to the window grid.

---

## 5. Graph representation

One graph per `(run, window)`.

**Nodes** — every entity observed in the window: IoT devices, compromised
devices, access routers, the edge gateway, the cloud server. Node features are
the 46-vector above.

**Edges** — two families with an edge-type attribute:

- `physical` — the wired/wireless topology (device–router, router–gateway,
  gateway–cloud). These carry the **aggregation hierarchy**.
- `communication` — observed `src → dst` traffic relations from the flow records,
  weighted $w = \log(1 + \text{packets})$ so a single flood edge cannot dominate
  aggregation.

Edges are bidirectional and self-loops are added, so a node's own features
survive mean aggregation.

**Why two layers of message passing is the right receptive field.** One hop lets
a device see its access router; two hops let it see the gateway and — through
the communication edges to the cloud — every other talker in that window. That
is precisely the evidence a distributed low-and-slow attack hides in: each bot
is individually unremarkable, but their shared aggregation point is not.

---

## 6. Detectors

### 6.1 Threshold baseline (control condition)

$$s(v) = \max\left(
\frac{r_{pkt}(v)}{\tau_{pkt}},\;
\frac{r_{byte}(v)}{\tau_{byte}},\;
\frac{|D_{port}(v)|}{\tau_{port}},\;
\frac{\rho_{SYN}(v)}{\tau_{SYN}}
\right)$$

with $s \ge 1 \Rightarrow$ `MALICIOUS` and $s \ge 0.45 \Rightarrow$ `SUSPICIOUS`.

Two fairness decisions:

1. It scores **endpoints only**. Flagging the gateway — which legitimately
   forwards the sum of all device traffic — would be a strawman.
2. Volume thresholds are **auto-calibrated** to the 99th percentile of benign
   training traffic × 1.25, which is how an operator would actually tune them.
   The bounded `syn_ratio` rule is deliberately *not* calibrated: fitting it to
   benign data would push the limit above 1.0 and silently disable the rule.

### 6.2 Random Forest baseline

300 trees, max depth 14, minimum leaf 2, `class_weight="balanced"`. It sees the
identical feature matrix; the only thing it lacks is the graph.

### 6.3 GraphSAGE (proposed)

$$h_v^{(0)} = x_v$$
$$h_v^{(k)} = \mathrm{ReLU}\Big(\mathrm{LayerNorm}\big(
W^{(k)}_{\text{self}} h_v^{(k-1)} +
W^{(k)}_{\text{nbr}} \cdot \mathrm{MEAN}_{u \in \mathcal{N}(v)} h_u^{(k-1)}
\big)\Big)$$
$$z_v = W_{\text{out}} h_v^{(K)}, \qquad \hat{y}_v = \mathrm{softmax}(z_v)$$

with $K = 2$, hidden width 64, dropout 0.3, mean aggregation.

- **Inductive by construction.** The aggregator learns a function of a
  neighbourhood, not an embedding per node id, so the trained model transfers to
  graphs with different node counts. This is essential: the experiments vary the
  fleet from 24 to 60 nodes, and the held-out run has an attacker count never
  seen in training.
- **Loss.** Inverse-frequency weighted cross-entropy, matching the Random
  Forest's `class_weight="balanced"`.
- **Optimiser.** Adam, lr 0.008, weight decay 5e-4, gradient-norm clip 5.0.
- **Batching.** Window graphs are merged into one disconnected batch graph with
  node indices offset per graph, so message passing never crosses a window
  boundary.
- **Model selection.** Early stopping on validation macro-F1, patience 40; the
  best-epoch weights are restored before the checkpoint is written.
- **Backend.** PyTorch Geometric's `SAGEConv` when installed, otherwise the
  mathematically equivalent `MeanSAGEConv` built on `index_add_`. The active
  backend is recorded in every log line and checkpoint manifest.

---

## 7. Experimental protocol

**Splitting.** By **run**, never by row — two windows of the same simulation
share device identities and RNG streams. `exp7_unseen` is excluded from the
corpus entirely and is only ever scored.

**Normalisation.** `log1p` on heavy-tailed count/rate columns (they span 0.4 to
5700 pkt/s), then standardisation. The scaler is fitted on **training rows only**
and persisted with each model.

**Metrics.** Multi-class accuracy, balanced accuracy, macro precision/recall/F1,
MCC, and the full 3×3 confusion matrix; plus an operational binary view
(benign vs hostile) giving precision, recall, F1, **false-positive rate**,
ROC-AUC and PR-AUC.

**Detection latency.** Simulated seconds from attack start to the **end** of the
first window in which a ground-truth attacker is scored at or above the trigger.
The floor is one window length (5 s) — a real, reportable property of a windowed
design, not an artefact. Runs where the attack is never detected are reported as
missed, not averaged away.

**Recovery time.** Simulated seconds from the first installed rule to the first
window whose **legitimate** packet-loss ratio returns to within 25% (+1 pp) of
the pre-attack mean. A service-level definition, not an aesthetic one.

---

## 8. Dynamic fuzzing

The fuzzer mutates **attack parameters only** and hands the result to the
in-memory simulator. Four strategies:

| Strategy | Behaviour | Purpose |
|---|---|---|
| `grid` | Exhaustive Cartesian sweep of explicit value lists | 1-D robustness curves |
| `random` | Independent draws from declared distributions | combinations no human would write |
| `mutation` | Seeded random walk, bounded multiplicative delta | locally dense sampling around a baseline |
| `adaptive` | Greedy search minimising detector recall on the bots | finds the weakest parameter region |

The `adaptive` strategy is a coverage-guided fuzzer with "detector weakness"
substituted for code coverage: cases are scored, the lowest-scoring population is
retained, and children are mutated from it. Its output is the evidence for the
Limitations section.

Every campaign is fully determined by `(campaign, seed)`; regeneration is
byte-identical, and `tests/test_models_and_fuzzing.py` asserts it.

---

## 9. Mitigation

### 9.1 Response ladder

| Confidence | Action | Effect |
|---|---|---|
| $p \ge 0.60$ | rate limit | token bucket, 60 pkt/s refill, burst 30 |
| $p \ge 0.85$ | block | all packets from that ingress dropped |
| $p \ge 0.95$ for $N$ consecutive windows | isolate | gateway port isolation |
| $p < 0.80$ for $M$ consecutive windows | release | rule removed |

Rules never de-escalate within an incident; escalation to the most destructive
action requires *persistence*, not just one confident window.

### 9.2 Enforcement

Enforcement runs at the **gateway ingress**, inside the packet path:

```python
def inspect(packet, t) -> str | None:
    state = states.get(packet.src)          # ingress identity, not source IP
    if state is None or not state.active:   return None
    if state.action in (BLOCK, ISOLATE):    return DROP_REASON[state.action]
    if state.action is RATE_LIMIT:
        state.tokens = min(burst, state.tokens + (t - last) * rate)
        if state.tokens >= 1: state.tokens -= 1; return None
        return "mitigation_ratelimit"
```

Because this is consulted for every packet arriving at the gateway, a rule
installed at $t$ changes the physics of the run from $t$ onwards. Recovery is
measured, never asserted.

---

## 10. Reproducibility

Every stochastic subsystem draws from a seed derived from the master seed via
`blake2b(master ‖ label)`, so device 7's traffic RNG is independent of the attack
RNG yet fully determined by `seed`. A run's identity is
`<experiment>_seed<seed>_<blake2b(config)>`; two runs with the same id are
byte-identical, which is what makes `--reuse` safe and is asserted by
`tests/test_simulation.py::TestReproducibility`.

```bash
./run.sh setup && ./run.sh all      # full pipeline, deterministic
```
