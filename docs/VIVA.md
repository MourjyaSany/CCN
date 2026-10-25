# NetShield-GNN — Viva Preparation

Fifty questions with answers, ordered from networking fundamentals to the
specifics of this project. Numbers quoted here come from
`results/reports/RESULTS.md`; if you regenerate the results, re-read that file
before the viva.

**The three sentences to have ready if you are asked only one thing:**

> NetShield-GNN simulates a four-tier IoT–cloud network at packet level, floods
> it with four families of DDoS attack, and detects the attackers with a
> GraphSAGE GNN that classifies every device in every 5-second window. Because
> the detector runs *inside* the running simulation, a mitigation rule installed
> at t = 45 s physically changes what happens to packets from t = 45 s onwards,
> so the recovery curves are measurements rather than claims. The headline
> finding is that a per-node threshold rule catches only 18% of a stealthy
> distributed botnet, while the graph model catches 100% at a 0.4% false-alarm
> rate.

---

## A. Networking fundamentals

**1. What is the difference between TCP and UDP?**

TCP is connection-oriented, reliable and ordered: it establishes state with a
three-way handshake, numbers every byte, retransmits what is not acknowledged,
and adapts its sending rate to congestion. UDP is connectionless and
best-effort: no handshake, no acknowledgement, no retransmission, no congestion
control — just a length and a checksum on top of IP.

In this project both are implemented and both matter. `mqtt_sensor`,
`http_client` and `tcp_uploader` ride TCP; `udp_streamer` uses UDP. The attacks
exploit the *difference*: a UDP flood costs the attacker nothing in state, while
a SYN flood weaponises exactly the state TCP requires the *server* to keep.

**2. Walk me through the TCP three-way handshake, and why it is attackable.**

Client sends `SYN`. Server allocates a half-open connection entry and replies
`SYN+ACK`. Client replies `ACK` and the connection is established.

The asymmetry is the vulnerability: after one small packet from the client, the
*server* must allocate and hold state until the handshake completes or times
out. An attacker who never sends the third packet forces the server to hold
state for nothing. In `traffic/server.py` this is a 256-entry table with an 8 s
timeout; Experiment 3 fills it and legitimate devices then fail to connect.

**3. Explain the OSI model and where this project operates.**

Seven layers: Physical, Data Link, Network, Transport, Session, Presentation,
Application.

| Layer | In this project |
|---|---|
| 1 Physical | Link bandwidth and propagation delay |
| 2 Data Link | Ethernet framing overhead (18 B), drop-tail queues |
| 3 Network | IPv4 addressing, the BFS routing table, forwarding |
| 4 Transport | TCP (handshake, cwnd, RTO) and UDP; ports; SYN backlog |
| 5–6 Session/Presentation | Not separately modelled — normal for IP networks |
| 7 Application | MQTT/HTTP/CoAP behaviour, HTTP flood, worker pool |

Detection operates on layer-3/4 metadata (the flow record), which is precisely
what a real gateway can see without decrypting anything.

**4. How does the TCP/IP model differ from OSI?**

TCP/IP has four layers — Link, Internet, Transport, Application — and collapses
OSI's 5–7 into one. It is descriptive of what was actually built; OSI is
prescriptive. This project maps naturally onto TCP/IP: Link (channels/queues),
Internet (IP + routing), Transport (TCP/UDP), Application (the device models).

**5. What is throughput, and how do you measure it here?**

Throughput is successfully delivered data per unit time. Here it is measured, not
configured: delivered bytes at the cloud × 8 ÷ window length.

Crucially it is measured **directionally**. Counting both directions would let
"throughput" exceed the 20 Mbit/s uplink and look like a bug — so upstream
(delivered at the cloud, having crossed the bottleneck) is separated from
downstream. A test asserts throughput never exceeds link capacity.

**6. What is latency, and what is it made of?**

End-to-end one-way delay:

$$D = \sum_{\text{hops}} \left(\underbrace{\frac{8S}{B}}_{\text{serialisation}} + \underbrace{D_{prop}}_{\text{propagation}} + \underbrace{D_{q}}_{\text{queueing}}\right)$$

In the default topology the fixed part is 1.5 + 3 + 12 = 16.5 ms, and benign
runs measure ≈17 ms — the difference is serialisation and light queueing. Under
a UDP flood it rises to ≈44 ms, and that entire increase is **queueing delay**:
the same packets over the same links, just waiting behind a full buffer.

**7. What causes packet loss in your simulator?**

Five distinct causes, tracked separately: `queue_overflow` (drop-tail buffer
full — the dominant cause under a volumetric flood), `cpu_overload` (node
processing backlog exceeded), `random_loss` (0.05% residual wireless bit
errors), `no_route`, and the four `mitigation_*` reasons. Separating them is
what lets the report distinguish damage done by the *attack* from damage done by
the *defence*.

**8. What is network congestion, and how does TCP respond?**

Congestion is offered load exceeding capacity, so queues fill and packets are
dropped. TCP infers it from loss. The implementation here is Reno: slow start
(`cwnd += MSS` per ACK) until `ssthresh`, then congestion avoidance
(`cwnd += MSS²/cwnd`); on timeout, `ssthresh` halves and `cwnd` collapses to one
segment.

This matters for honesty: legitimate TCP flows *back off* during the flood while
the UDP attackers do not, so the attack's share of the link grows. That is real
network behaviour and the simulator reproduces it rather than assuming it.

**9. Why does a drop-tail queue treat TCP and UDP unfairly?**

Drop-tail discards whatever arrives at a full buffer, with no notion of fairness.
TCP sources interpret the drop as congestion and reduce their rate; UDP sources
ignore it. The well-behaved traffic yields and the misbehaving traffic takes the
capacity — which is exactly why an unmanaged link collapses under a UDP flood,
and why mitigation has to act on identity rather than relying on the transport
protocol to be polite.

**10. What is a gateway, and why is it the right place to defend?**

A gateway joins two networks and forwards between them. Here it aggregates all
three access routers onto the single 20 Mbit/s cloud uplink.

It is the right enforcement point for three reasons: (i) it is the choke point,
so all traffic is visible in one place; (ii) it is upstream of the resource being
protected, so dropping there actually relieves the bottleneck; (iii) it knows the
**ingress port** each frame arrived on, which is an identity a spoofed source
address cannot forge.

**11. How is routing done in your topology?**

The topology is a tree rooted at the cloud, so BFS from every destination yields
a `next_hop[(current, destination)]` table computed once at build time. On a tree
the shortest path is the only path — which is not a simplification but the
property that makes the gateway a genuine single point of aggregation.

**12. What is MTU and why does packet size matter for an attack?**

MTU is the largest frame a link carries — 1500 B here, giving a TCP MSS of 1460 B.

Packet size determines whether an attack is bandwidth-bound or packet-rate-bound.
A 512-byte UDP flood at 1400 pkt/s per bot saturates a 20 Mbit/s link; a
64-byte SYN flood at 1800 pkt/s uses only ≈26% of the same link but exhausts a
state table. This is why `eg_mean_packet_size` and `eg_packet_size_std` are
features: near-zero size variance is a fingerprint of machine-generated traffic.

**13. What is jitter and where does it appear?**

Variation in inter-arrival time. Feature `eg_iat_std`, and `eg_burstiness` is the
coefficient of variation $\sigma_{IAT}/\bar{IAT}$. A CoAP sensor on a fixed
timer has low burstiness; a bursty HTTP client has high burstiness. It is one of
the features that separates a steady flood from human-driven traffic.

---

## B. DDoS and security

**14. What is a DoS attack, and how does DDoS differ?**

DoS exhausts a resource from one source. DDoS does it from many, which changes
the defence problem qualitatively rather than quantitatively: you cannot block
one address, per-source rate limits stay under their thresholds, and the
aggregate only becomes visible where the traffic converges. That is the entire
motivation for a relational detector.

**15. Classify the attacks you implement.**

- **Volumetric** (`udp_flood`) — exhausts bandwidth. Symptom: 100% uplink
  utilisation, ≈20% loss, latency 17 → 44 ms.
- **Protocol / state** (`syn_flood`) — exhausts the connection table.
  Measured: 162,160 SYNs received, 159,722 rejected, backlog pegged at its
  256-entry limit, and legitimate connection failures rise 10×, all at ≈26%
  link utilisation.
- **Application** (`http_flood`) — exhausts worker slots with well-formed
  requests. Every packet is individually plausible.
- **Mixed** — each bot assigned a different family; multi-vector.

**16. Explain a SYN flood precisely.**

The attacker sends `SYN` segments and never completes the handshake, often with
forged source addresses. Each `SYN` costs the attacker ~64 bytes and no state;
it costs the server a backlog entry held for the SYN timeout. When the backlog
fills, legitimate `SYN`s are dropped and real devices cannot connect.

The subtlety this project reproduces: the server dutifully sends `SYN+ACK` to the
forged address, which is unroutable and consumes the defender's *own* downstream
bandwidth. That is **backscatter**, and it is counted
(`unroutable_synacks`) rather than hand-waved.

**17. What is a UDP flood, and why is it so easy?**

Connectionless datagrams at maximum rate. No handshake, no state, and — because
there is no congestion control — no back-off when the network signals distress.
The attacker's cost is one system call per packet.

**18. Why is an HTTP flood harder to detect than a UDP flood?**

Because every individual request is legitimate. It has a real handshake, a
well-formed request and a real response. There is no malformed packet, no odd
port, no protocol violation. Only the *aggregate rate* and the *fan-in pattern*
betray it — which is a relational property, not a per-packet one.

**19. What makes IoT networks especially vulnerable?**

Weak or default credentials, rarely patched firmware, no host-based defences,
and enormous population size. A compromised device also has a plausible cover
story: it keeps doing its normal job. That is why this project models
compromised nodes as still running their legitimate application — it is what
makes the detection problem three-class instead of trivially binary.

**20. What is spoofing and how do you handle it?**

Forging the source IP. It defeats IP-based blocking and misdirects backscatter
onto innocent third parties.

The project handles it two ways. As a *signal*: `eg_unique_src_ips` per node
spikes when one device emits many source addresses. As a *defence*: mitigation
keys on the gateway **ingress identity**, which cannot be forged from the
attacker's side. A test forges the source address on a blocked node's packet and
asserts it is still dropped.

**21. What is a pulsing or burst attack, and why does it work?**

On/off duty-cycled traffic. It defeats moving-average thresholds because the
average stays below the limit while the peaks still cause loss. Experiment 6
uses a 2.5 s on / 3.5 s off cycle, giving a duty of ≈0.42 — which is why those
windows are ground-truth `SUSPICIOUS` rather than `MALICIOUS`.

**22. How do you guarantee this cannot be used to attack a real network?**

Structurally, not by policy:

- No module imports `socket`, `scapy`, or any raw-socket API. Attack "packets"
  are Python objects pushed onto an in-memory heap.
- `Attacker.__init__` raises `AttackSafetyError` unless the target is a node in
  the in-process topology — there is no way to name an external host.
- Spoofed addresses come from `10.66.0.0/16`, which the topology never assigns.
- The REST API has **no host, port or target parameter anywhere**; its only
  state-changing endpoints start and stop an in-process simulation.

---

## C. Simulation

**23. What is network simulation and why not just measure a real network?**

Simulation reproduces protocol behaviour in software so experiments are
repeatable, safe and fully instrumented. You cannot ethically DDoS a real IoT
deployment, you cannot get ground-truth labels from real traffic, and you cannot
re-run yesterday's conditions. Simulation gives all three.

**24. What is NS-3, and did you use it?**

NS-3 is the standard open-source discrete-event network simulator, written in
C++ with a Python binding.

**I did not use it for the reported results, and the project says so
everywhere.** The machine had no C++ toolchain (`g++` and `make` absent), so
NS-3 could not be built. The repository ships a complete NS-3 model
(`ns3/simulations/netshield-topology.cc`) for hosts that do have it, and
`ns3_bridge.resolve_engine` performs a real capability probe. Every artefact is
stamped `"Python discrete-event emulation"` — in `run.json`, in the dataset's
`engine` column, in the caption of every figure, and in the header of
`RESULTS.md`. With `simulation.engine: ns3`, a missing installation is a hard
error, never a silent fallback.

**25. Then why should I believe your numbers?**

Because they are not asserted, they are *derived* from a real queueing model. The
engine is a genuine discrete-event simulator: store-and-forward switching,
finite drop-tail buffers, serialisation delay `8S/B`, propagation delay, and
per-node processing servers. Latency, loss and throughput are emergent.

Three checks you can run: the measured benign latency (≈17 ms) equals the
configured path delay (16.5 ms) plus serialisation; delivered throughput never
exceeds the configured 20 Mbit/s link (asserted by a test); and the SYN flood
uses *less* bandwidth than the UDP flood at a comparable packet rate, exactly as
theory predicts (also asserted by a test).

**26. What is a discrete-event simulator?**

State changes only at discrete instants. A priority queue holds
`(time, callback)` events; the loop pops the earliest, advances the clock to it,
and executes it — which may schedule further events. Time jumps between events
rather than ticking, so an idle network costs nothing to simulate.

**27. Tell me about a bug you found in your own simulator.**

The pulsing-attack scheduler livelocked. During an off-phase the attacker
computes the next burst start as
`start + (floor(elapsed/cycle) + 1) × cycle`. When `elapsed` landed exactly on a
cycle boundary, binary floating point made `floor` return `k-1` while `elapsed`
already equalled `k × cycle`, so "next" evaluated to *exactly now*. Scheduling at
`now` re-entered the same branch and the simulated clock stopped advancing.

It was caught because I had added a wall-clock budget to the engine, which
reported "budget exhausted at simulated t = 42.0 s" — a suspiciously round
number. The fix is two-layered: an epsilon inside the floor, and a hard
forward-progress guarantee (`max(next, t + ε)`) at the call site. There is now a
regression test that probes exact cycle boundaries.

**28. How do you guarantee reproducibility?**

Every subsystem's RNG is derived as `blake2b(master_seed ‖ label)`, so device 7's
traffic stream is independent of the attack stream yet fully determined by one
seed. A run's identity is `<experiment>_seed<seed>_<hash(config)>`. A test runs
the same configuration twice and asserts the flow tables are equal.

---

## D. Features and machine learning

**29. What flow features do you extract, and why those?**

46 per node per 5-second window, in eight groups: egress volume, packet-size
distribution, timing, addressing/fan-out, protocol and service mix, TCP flag
profile, ingress, and structural.

The design principle is that each group targets a specific attack family: size
variance and rate catch volumetric floods; SYN-to-ACK ratio and connection
attempts catch SYN floods; service mix and fan-out catch application floods;
unique source IPs catches spoofing; burstiness catches pulsing.

**30. How do you avoid label leakage?**

Features come only from what a gateway can observe by exporting flow records.
The simulator's ground truth — `attack_packets`, `attack_type`, and the `app`
tag, which literally contains the string `attack_udp` — is used solely to build
labels. `assert_no_leakage()` is called inside `FeatureScaler.fit`, so no model
can be trained on a leaking column, and a dedicated test asserts the feature list
and the forbidden list are disjoint.

If that guard ever failed, every accuracy number in the project would be
meaningless — which is why it is a test and not a comment.

**31. Why three classes rather than benign/malicious?**

Because a bot is not equally malicious in every window. A pulsing attacker
active 42% of a window, or a bot whose attack starts mid-window, is genuinely
*partially* hostile. Severity = composition × temporal coverage captures that,
and it gives the mitigation engine a graduated signal to act on rather than a
binary alarm.

**32. Why did you split by run rather than randomly?**

Two windows from the same simulation share device identities, RNG streams and
attack parameters. A random row split would put nearly identical rows in train
and test and inflate every score. Splits allocate whole runs; `exp7_unseen` is
excluded from the corpus entirely and only ever scored.

**33. How do you handle the class imbalance?**

The corpus is 11,451 benign / 265 suspicious / 1,147 malicious — about 43:1.
Inverse-frequency class weights in the GNN's cross-entropy, matched by
`class_weight="balanced"` in the forest, so the comparison stays controlled. And
the headline metric is **macro**-F1, which weights the rare classes equally;
accuracy alone would be 88% for a model that always says "benign".

---

## E. Graph neural networks

**34. What is a graph neural network?**

A model that computes node representations by repeatedly aggregating information
from neighbours. After $k$ rounds, a node's representation summarises its
$k$-hop neighbourhood. It handles data whose meaning lies in *relations* rather
than in independent feature vectors.

**35. What is GraphSAGE specifically, and why did you choose it?**

GraphSAGE (SAmple and aggreGatE) learns an aggregator *function* rather than one
embedding per node:

$$h_v^{(k)} = \sigma\big(W_{\text{self}} h_v^{(k-1)} + W_{\text{nbr}} \cdot \mathrm{MEAN}_{u \in \mathcal{N}(v)} h_u^{(k-1)}\big)$$

I chose it because it is **inductive**. A transductive method like vanilla GCN
learns node-specific parameters and cannot score a device it never saw. My
experiments vary the fleet from 24 to 60 nodes and the held-out run has an
attacker count never seen in training — a transductive model simply could not be
evaluated on it.

**36. Why a GNN instead of a normal classifier? Be concrete.**

Because DDoS is defined by distribution. In Experiment 5, thirty-six bots each
emit ≈22 pkt/s of CoAP-shaped UDP — the same port, the same 200–400 byte size
and the same cadence as a legitimate sensor. Per-node, they are unremarkable:
the threshold detector catches **18%** of them.

The evidence is relational: their shared access routers and the gateway show a
collective load spike that no individual device explains. Two rounds of message
passing put that context into every device's representation. The routers and the
gateway are first-class nodes in the graph precisely so that this signal exists.

**37. Why exactly two message-passing layers?**

It is the receptive field this topology needs, not a default. One hop reaches a
device's access router; two hops reach the gateway and, through the
communication edges to the cloud, every other talker in that window. A third
layer would add parameters and over-smoothing without reaching anything new on a
four-tier tree.

**38. How do you build the graph, and what are the edges?**

One graph per `(run, 5-second window)`. Nodes are every observed entity. Two edge
families: `physical` (the topology — device–router, router–gateway,
gateway–cloud), which carries the aggregation hierarchy; and `communication`
(observed `src → dst` traffic), weighted `log(1 + packets)` so a single flood
edge cannot dominate mean aggregation. Edges are bidirectional and self-loops
are added so a node's own features survive aggregation.

**39. Your GNN and Random Forest score almost the same. Doesn't that undermine
the thesis?**

It qualifies it, and I report it rather than hiding it. On the test split
GraphSAGE reaches 0.867 macro-F1 against the forest's 0.862 — a real but small
gap. Three honest observations:

1. **Where the gap appears is the interesting part.** On the *fuzzer-generated*
   scenarios — attack parameters no human chose — GraphSAGE scores 0.850 against
   the forest's 0.803. And on the **held-out run** (Experiment 7, whose
   parameters lie outside every training range and on which no model was fitted)
   GraphSAGE finds **7 of 7 bots with zero false alarms**, while the forest finds
   only 5 and the threshold rule flags 21 innocent devices. The advantage is
   specifically about generalisation, which is exactly where an *inductive*
   relational model should win: GraphSAGE learns an aggregation function over
   neighbourhoods, whereas the forest partitions a feature space whose ranges it
   learned from the training data.
2. **The error profiles differ.** GraphSAGE has perfect `MALICIOUS` recall
   (368/368) and higher macro-precision (0.915 vs 0.816); the forest is better
   calibrated on the rare `SUSPICIOUS` class but misclassifies 25 malicious
   windows as merely suspicious. For a mitigation system, missing a bot is worse
   than over-escalating a suspicious one.
3. **Both massively beat the deployed baseline.** The threshold rule scores
   0.407. The practical claim of the project — that learned detection beats
   static rules on IoT DDoS — is strongly supported; the narrower claim that
   graphs beat tabular features is supported only on the generalisation set, and
   I say so.

**40. What would strengthen the graph argument?**

More scenarios where per-node evidence is genuinely insufficient — larger
botnets at lower per-node rates, and attacks whose per-node statistics fall
*inside* the legitimate distribution rather than merely near it. Experiment 5 is
a step in that direction (36 bots at ≈22 pkt/s on a constrained 2 Mbit/s
backhaul); scaling to hundreds of bots is the natural next step and is listed in
Future Work.

---

## F. Fuzzing

**41. What is fuzz testing, and what does it mean here?**

Classically, feeding malformed input to a program to find crashes. Here the
"program under test" is the **detector** and the "input" is the attack's
parameter vector: rate, packet size, burst duty cycle, port set, botnet size,
timing, spoofing. The fuzzer answers the question the report actually needs to
answer: does detection still work when the attacker turns the knobs?

**42. What strategies do you implement?**

Four. `grid` — exhaustive sweep of explicit lists, for 1-D robustness curves.
`random` — independent draws from declared distributions, exploring combinations
no human would write. `mutation` — a seeded random walk around a baseline.
`adaptive` — a greedy search that scores each case by the detector's recall on
the bots and preferentially re-mutates the *worst* cases. That last one is a
coverage-guided fuzzer with "detector weakness" substituted for code coverage,
and its output is the evidence for the Limitations section.

**43. How is fuzzing reproducible if it is random?**

Every campaign is fully determined by `(campaign_name, seed)`. Generators take an
explicit seeded `numpy.random.Generator`; case seeds are derived deterministically
from the campaign seed. A test regenerates three campaigns and asserts the
parameter vectors are identical.

**44. Did fuzzing find anything real?**

Yes, two things. First, it exposed the pulsing-scheduler livelock described in
Q27 — a real bug in my own simulator, found by a parameter combination I would
never have written by hand. Second, it is the reason the corpus contains
attack-parameter combinations outside the hand-written scenarios, which is where
the GNN's advantage over the forest actually shows (0.850 vs 0.803 macro-F1).

---

## G. Evaluation

**45. Define precision, recall and F1 in this context.**

Precision = of the node-windows flagged hostile, the fraction genuinely hostile —
the inverse of nuisance alarms. Recall = of the genuinely hostile node-windows,
the fraction caught — the inverse of missed attacks. F1 is their harmonic mean.

Macro-averaging computes each per class and averages unweighted, so the rare
`SUSPICIOUS` class counts as much as the dominant `BENIGN` one.

**46. Why do you report false-positive rate separately?**

Because it is the number that decides whether a system is deployable. On a
24-device fleet at one 5-second window each, the system produces ~288
node-windows per minute. A 1% FPR is an alert every 20 seconds — an operator
would switch it off within a day. GraphSAGE measures 0.44% and the forest 0.14%;
the threshold baseline measures **22.3%**, which is unusable regardless of its
recall.

**47. How do you measure detection latency, and why is it 5 seconds?**

Simulated seconds from attack start to the **end** of the first window in which
a ground-truth attacker is scored at or above the trigger. It is 5 s because the
feature window is 5 s: a windowed detector cannot decide before the window
closes. That is a real design property, and the honest framing is "detection
latency equals one window" rather than pretending it is instantaneous. Shortening
the window would cut latency at the cost of noisier statistics — a genuine
engineering trade-off, and a good exam question in itself.

**48. How do you measure recovery, and is it real?**

It is real because mitigation runs inside the simulation. Recovery time is the
simulated seconds from the first installed rule to the first window whose
**legitimate** packet-loss ratio returns to within 25% (+1 pp) of the pre-attack
mean. It is a service-level definition: what the surviving devices experience,
not what the aggregate looks like. The alternative — running the simulation, then
computing "what recovery would have been" — would be fiction, and the
architecture deliberately makes that impossible.

---

## H. Mitigation, limitations and future work

**49. Explain your mitigation policy and why it is graduated.**

Confidence bands: ≥0.60 rate-limit (token bucket, 60 pkt/s), ≥0.85 block, ≥0.95
*sustained over consecutive windows* isolate; release after several clean
windows. Rules never de-escalate within an incident.

It is graduated because the cost of error is asymmetric. Blocking a legitimate
temperature sensor is a silent outage nobody notices until the data is missing;
letting one bot through costs a fraction of a link. So the destructive actions
require both high confidence *and* persistence.

**50. What are the main limitations, and what would you do next?**

Five limitations I would raise before an examiner does:

1. **NS-3 was not used for the reported results.** The Python engine is a
   genuine discrete-event simulator and every artefact is labelled, but the
   numbers are not NS-3 numbers.
2. **Ground truth is synthetic.** Labels are exact because I generated the
   attacks. That is the reason the results are trustworthy *and* the reason they
   may be optimistic relative to real traffic, which is messier.
3. **The graph advantage is modest on hand-written scenarios** and appears
   mainly on fuzzer-generated ones (Q39).
4. **TCP is simplified** — no fast retransmit, SACK, or receiver-window flow
   control (documented in `docs/methodology.md`).
5. **No adversary that adapts to the defence.** The fuzzer searches for weak
   parameters, but it does not model an attacker who observes mitigation and
   responds.

Next steps, in priority order: scale to hundreds of bots at per-node rates
strictly inside the legitimate distribution, so the relational argument is tested
where it should matter most; add temporal modelling across windows
(GNN + GRU) so a pulsing attacker's history carries forward; validate against a
public capture such as CIC-DDoS2019 to check the features transfer to real
traffic; and close the adversarial loop by letting the fuzzer see the deployed
detector's decisions.

---

---

## I. NS-3, topologies and the extended attack model

**51. Did you actually use NS-3, or just ship a model file?**

It is built and executed. ns-3.44 is compiled from source (optimized profile)
and `ns3/simulations/netshield-topology.cc` is compiled into it and run.
`python scripts/run_experiment.py -e exp2_udp_flood --set simulation.engine=ns3`
produces artefacts stamped `ns3-simulation`. On this machine NS-3 lives inside
WSL, because NS-3 needs a POSIX C++ toolchain that Windows does not provide, and
`ns3_bridge` drives it there.

**52. If NS-3 is available, why is the default engine still the Python one?**

Because a corpus must come from one simulator. The C++ model implements a
subset: four of the seven topology families are Python-only, three of the six
attack families are Python-only, and rate shaping and the closed mitigation loop
have no NS-3 equivalent. If `auto` picked NS-3 for the scenarios it supports and
Python for the rest, the *training* set would be a mixture of two simulators
while the closed-loop evaluation stayed on one — a train/test mismatch that
would quietly invalidate the whole detector comparison. So `auto` resolves to
the Python reference engine and logs that NS-3 is available and how to opt in.

**53. Then what is NS-3 actually for here?**

Cross-validation of the physical layer by an independent implementation. The
configured one-way path delay is 16.5 ms; the Python engine measures ≈17 ms and
NS-3 measures 17.32 ms. Both saturate the 20 Mbit/s uplink at ~20.6 Mbit/s under
the same offered load, and NS-3 independently reproduces latency climbing to
300–740 ms under a flood and recovering afterwards. Two separately written
simulators agreeing is evidence that the numbers are physics and not an artefact
of one implementation.

**54. Why not use FlowMonitor? It is the standard tool.**

FlowMonitor gives per-flow totals and no TCP flag counts. A FlowMonitor-derived
feature vector would have silent zeros in `syn_count`, `syn_ack_count`,
`ack_count`, `fin_count` and `rst_count` — five of the 46 features — which is an
invisible train/test mismatch, not a visible failure. The model instead taps
`Ipv4L3Protocol`'s `SendOutgoing`, `LocalDeliver` and `Drop`, where the IPv4
header is supplied separately and the transport header can be peeked, so real
flag counts, packet sizes and inter-arrival times are recovered.

**55. Your NS-3 model first reported zero packet loss on a saturated link. What was wrong?**

`InternetStackHelper` installs a traffic-control queue disc in front of every
device, so under congestion the packet is discarded *there*, before it reaches
the device transmit queue. Tracing only `TxQueue` therefore saw nothing. The fix
was to trace `TrafficControlLayer/RootQueueDiscList/*/DropBeforeEnqueue` as
well. The check that it is now right is packet conservation: delivered + dropped
equals offered exactly (100,824 + 25,004 = 125,828).

**56. How is latency measured in the NS-3 model?**

The send time of every packet is recorded against its ns-3 packet UID at
`SendOutgoing` and subtracted at `LocalDeliver`. A UID survives the copies made
during forwarding, so this is a genuine end-to-end delay including queueing —
which is why it rises under congestion. Percentiles come from the retained
per-packet samples using the same nearest-rank rule as the Python engine, so the
two engines' p95 numbers mean the same thing.

**57. Why add six more topologies? Was the tree not enough?**

The tree makes the problem structurally easy in a way that flatters the
detector: one choke point, one aggregation path, one place to enforce. Every
bot's traffic provably crosses the same link. The other families each remove one
of those assumptions — `star` removes intermediate aggregation entirely,
`multi_gateway` splits the botnet across three enforcement domains, `dumbbell`
moves the bottleneck away from the node that enforces, and `fat_tree`/`mesh`
introduce genuinely redundant paths so the aggregation evidence is split. They
run the identical attack, so any behavioural difference is attributable to
structure alone.

**58. What had to change in the engine to support multiple gateways?**

Two assumptions. The enforcement point was a single `enforcement_node`; it is
now a set, and the controller arms every gateway the topology nominates —
otherwise half a straddling botnet would keep running. And the "uplink" was
hard-coded as gateway → cloud; topologies now *declare* their bottleneck in
`uplink_keys`, which is what lets a dumbbell name its backbone span instead.
Utilisation divides by the number of uplinks so it stays a fraction.

**59. What makes slowloris different from the SYN flood you already had?**

They exhaust different resources, and the counters prove it. A SYN flood never
completes a handshake, so it fills the *half-open backlog*. Slowloris completes
handshakes and then stalls, so the backlog is untouched and the *established
connection table* fills instead. Measured over the same window: slowloris
generated 2,925 packets against the UDP flood's 34,157 — an order of magnitude
less traffic — yet drove the connection table to its 120 ceiling and caused 63
refused connections, with `syn_rejected` at exactly zero. Negligible bandwidth,
total denial of service.

**60. Why does an ICMP flood matter if you already model UDP floods?**

Because ICMP has no ports, so it lands somewhere else in feature space entirely.
In the same run the UDP flood produced 1,220 flow records and the ICMP flood
only 212, because flow cardinality collapses when the 5-tuple has no port
component. Port-entropy, service-mix and unique-port features all go to zero
while packet-rate features spike — so a rule keyed on port structure is blind to
it by construction, which is exactly the blind spot worth demonstrating.

**61. What is the point of the rate waveforms?**

The `ramp` is the adversarially interesting one: the attack starts at 5% of its
final rate and climbs, so it crosses any static threshold late — by which time
the queue is already full. It tests whether a learned detector alarms earlier
than a calibrated rule, which is the practical argument for learning at all.
`sine` and `step` vary the load without a clean on/off edge, and per-bot rate
jitter plus staggered join times stop the botnet being a set of identical
emitters sitting on one point in feature space, which is an artificially easy
detection problem.

**62. The dashboard lets a user build a custom attack. Does that not break your safety guarantee?**

No, and the mechanism matters. The builder sends sparse dotted-key config
overrides, and `netshield.api.state.sanitise_overrides` checks each one against
an allowlist before it is applied: only `attack.*`, `network.topology.*`,
`mitigation.*`, `detection.*`, `features.*`, `traffic.*` and a few named
`simulation.*` keys are accepted. `paths.*`, `api.host`, `simulation.engine` and
anything else are rejected with a 400, and a test asserts it. So there is still
no host, port, interface or real-world target parameter in the API surface.
`attack.target` accepts only a role or a node id from the topology this process
just built; `resolve_attack_target` raises `AttackSafetyError` otherwise.

**63. What is the honest weakness of the new experiments?**

They are evaluation-only and single-seed. Experiments 9–19 are deliberately
excluded from the training corpus, which is the right call — including them
would make the models better at the scenarios used to judge them — but it means
each is one run at one seed. They establish that the system *behaves correctly*
across structures and attack families; they are not yet enough to make a
statistical claim about which detector wins on each topology. Repeating them
across seeds is the obvious next step.

---

## Rapid-fire facts

| Question | Answer |
|---|---|
| Nodes in the default topology | 29 (24 IoT + 3 routers + gateway + cloud) |
| Bottleneck link | Gateway → cloud, 20 Mbit/s, 12 ms, 120-packet queue |
| Feature window | 5 s |
| Features per node-window | 46 |
| Classes | BENIGN / SUSPICIOUS / MALICIOUS |
| Corpus | 12,863 node-windows from 28 runs, 7 scenarios |
| GNN size | 2 × SAGEConv, 64 hidden, 14,659 parameters |
| Mitigation enforcement point | Gateway ingress, keyed on port identity |
| Detection latency floor | One feature window (5 s) |
| Most important feature (RF) | `eg_unique_src_ports` |
| Engine used for the results | Python reference engine (NS-3 available, opt-in) |
| NS-3 version | ns-3.44, optimized, built from source |
| Topology families | 7 (tree, star, multi_gateway, dumbbell, fat_tree, mesh, ring) |
| Attack families | 6 + mixed |
| Rate waveforms | constant, ramp, sine, step (x pulsing duty cycle) |
| Experiments | 19 |
| NS-3 vs Python benign latency | 17.32 ms vs ~17 ms (16.5 ms configured) |
