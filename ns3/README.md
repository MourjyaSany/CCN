# NS-3 (primary engine)

The **primary** NS-3 model is in [`ns3/netshield/`](netshield/): a generic,
spec-driven model that builds whatever node-and-link graph the Python side
emits, so all seven topology families are real NS-3 networks. Python drives it
via [`ns3_spec.py`](../src/netshield/simulation/ns3_spec.py) (scenario to spec),
[`ns3_wsl.py`](../src/netshield/simulation/ns3_wsl.py) (run it, in WSL on
Windows) and [`ns3_run.py`](../src/netshield/simulation/ns3_run.py) (assemble
the result). Set it up with `python scripts/setup_ns3.py`.

The older single-file model in [`simulations/`](simulations/) targets ns-3.44
and covers tree/star/dumbbell with built-in traffic generators; it is kept for
reference and cross-checking. The notes below describe that older model.

---

# NS-3 integration

## Status

**NS-3 is built and working, and this model has been compiled and executed
against it.** The project runs on ns-3.44 (built from source, optimized
profile). A run started with `simulation.engine: ns3` really does execute the
C++ model in this directory; its artefacts are stamped
**`ns3-simulation`** / **"NS-3 simulation"** in:

- the `engine` / `engine_label` fields of every `run.json`,
- the `engine` column of `data/processed/dataset.csv`,
- the provenance caption of every figure in `results/figures/`,
- the header of `results/reports/RESULTS.md`.

That labelling is enforced in code by
`netshield.simulation.ns3_bridge.resolve_engine`, which performs a real
capability probe and never guesses. There is no code path that can present
emulated numbers as NS-3 numbers, or NS-3 numbers as emulated ones.

## Contents

| Path | Purpose |
|---|---|
| `simulations/netshield-topology.cc` | The NS-3 model: 4-tier topology, drop-tail queues, legitimate IoT traffic, attack generators, and a per-window flow/metric export matching the Python engine's schema. |
| `scripts/build_ns3.sh` | Copies the model into `$NS3_DIR/scratch`, builds it, and optionally runs it. |

The Python side is split in two:

| Module | Purpose |
|---|---|
| `netshield.simulation.ns3_bridge` | Probing, command construction, invocation, output parsing. |
| `netshield.simulation.ns3_runner` | Config → model parameters, and assembling a `SimulationResult` from the model's CSV output. |

## Installing NS-3

NS-3 needs a POSIX C++ toolchain, so on Windows it lives inside WSL. The bridge
supports both arrangements and probes for them in this order:

1. a native `ns3` CLI (`$NS3_DIR/ns3`, or `ns3` on `PATH`),
2. **a built ns-3 tree inside a WSL distribution**,
3. the ns-3 Python bindings.

```bash
# Linux / macOS / WSL
curl -fL -o ns-allinone-3.44.tar.bz2 \
  https://www.nsnam.org/release/ns-allinone-3.44.tar.bz2
tar xf ns-allinone-3.44.tar.bz2
cd ns-allinone-3.44/ns-3.44
./ns3 configure --build-profile=optimized \
    --enable-modules=core,network,internet,point-to-point,applications,flow-monitor,traffic-control,csma,stats,bridge,wifi,mobility \
    --disable-examples --disable-tests
./ns3 build -j "$(nproc)"
```

`cmake` ≥ 3.13 is required. If you cannot install it system-wide, the official
Linux tarball from Kitware works fine unpacked into `~/tools/cmake` — the
bridge puts `$HOME/tools/cmake/bin` on the PATH it uses.

The probe finds a tree at any of:

```
$HOME/ns3/ns-allinone-*/ns-3.*
$HOME/ns-allinone-*/ns-3.*
/opt/ns3/ns-allinone-*/ns-3.*
```

Override with `NS3_DIR` (native), or `NS3_WSL_DISTRO` / `NS3_WSL_DIR` (WSL).

## Running

```bash
python scripts/check_env.py                     # reports the probe result
python scripts/run_experiment.py --experiment exp2_udp_flood \
       --set simulation.engine=ns3
```

The model is copied into `$NS3_DIR/scratch` and rebuilt automatically before
each run, so editing the `.cc` is all that is needed to change it.

## Engine selection, and why `auto` does not pick NS-3

| `simulation.engine` | Behaviour |
|---|---|
| `python` | Always the Python reference engine. NS-3 is not consulted. |
| `ns3` | Requires NS-3. A missing installation is a hard error (`NS3Unavailable`), never a silent fallback. |
| `auto` (default) | The Python reference engine, **even when NS-3 is installed** — and the log says so, and tells you how to opt in. |

That last row is deliberate and is worth being able to defend:

The Python engine is the reference implementation. All seven topology families,
all six attack families, the rate-shaping waveforms and the closed mitigation
loop exist there; the C++ model implements a subset. If `auto` silently chose
NS-3 for the scenarios NS-3 happens to support and the Python engine for the
rest, **the training corpus would be a mixture of two different simulators**
while the closed-loop evaluation stayed on one of them. That is a train/test
mismatch which would quietly invalidate the detector comparison — the exact
class of error this project is built to avoid. So NS-3 is opt-in, and a corpus
is always single-engine.

## Model fidelity

Both engines agree on the physical layer — the same four tiers, the same link
rates, the same one-way delays, the same drop-tail queue depths, all mirroring
`config/network.yaml`. They differ above it:

| Aspect | Python engine | NS-3 model |
|---|---|---|
| TCP | Simplified Reno in `simulation/tcp.py` (slow start, AIMD, RTO, Karn) | Full ns-3 TCP stack |
| SYN backlog | Explicit finite half-open table with timeout and backscatter | Not modelled; the SYN flood reproduces the packet-rate signature only |
| Connection table | Finite `max_connections`, which slowloris exhausts | Not modelled |
| Application layer | MQTT / HTTP / bulk / CoAP behavioural models with reconnect logic | `OnOffApplication` approximations |
| Topology families | tree, star, multi_gateway, dumbbell, fat_tree, mesh, ring | tree, star, dumbbell |
| Attack families | 6 + mixed | udp_flood, syn_flood, http_flood, icmp_flood |
| Rate shaping | constant, ramp, sine, step; per-bot jitter; staggered joins; pulsing | constant only |
| Closed-loop mitigation | Enforced inside the packet path | Not available |

Anything in that table the C++ model cannot honour is **reported, not silently
approximated**: `ns3_runner.ns3_warnings()` enumerates every such setting, each
one is logged as a warning, and the list is written into `run.json` under
`summary.ns3_unsupported`. Metrics NS-3 does not measure are listed under
`summary.ns3_unmeasured_metrics` so a reader can tell "measured zero" from
"not measured".

## Why the model taps `Ipv4L3Protocol` rather than using FlowMonitor

FlowMonitor aggregates per-flow totals and exposes no TCP flag counts. A
FlowMonitor-derived feature vector would therefore have silent zeros in the
`syn_count` / `syn_ack_count` / `ack_count` / `fin_count` / `rst_count` columns
that the detectors consume — an invisible train/test mismatch.

Instead the model connects to three `Ipv4L3Protocol` trace sources:

| Trace | Used for |
|---|---|
| `SendOutgoing` | Offered load, flow accounting, TCP flags, packet sizes, inter-arrival times |
| `LocalDeliver` | Delivered counters and end-to-end latency |
| `Drop` | Stack-level discards |

At those points the IPv4 header is supplied separately and the transport header
can be peeked, so genuine per-flow flag counts are recovered.

Two subtleties worth knowing, both of which caused silently wrong numbers
before they were fixed:

- **Congestion drops happen in the traffic-control queue disc**, not the device
  transmit queue. `InternetStackHelper` installs a queue disc in front of every
  device, so tracing only `TxQueue` reported *zero* loss on a link that was
  visibly saturated. The model now traces
  `TrafficControlLayer/RootQueueDiscList/*/DropBeforeEnqueue` as well, and
  packet conservation holds exactly: `delivered + dropped == offered`.
- **Latency is measured, not derived.** The send time of every packet is
  recorded against its ns-3 UID and subtracted at delivery, so the reported
  delay includes queueing and rises under congestion.

## Cross-validating the two engines

The two simulators are written independently, so agreement between them is
evidence rather than tautology. On the default topology:

| Quantity | Configured | Python engine | NS-3 |
|---|---:|---:|---:|
| Benign one-way latency | 16.5 ms path delay | ≈17 ms | **17.32 ms** |
| Uplink capacity | 20 Mbit/s | saturates | **20.6 Mbit/s** |

Under a 4-bot, 1400 pkt/s UDP flood NS-3 measures latency rising from 17.4 ms
to 300–740 ms and loss from 0% to ~30%, recovering to 17.4 ms after the attack
stops — the same qualitative behaviour the Python engine produces, from an
independent implementation.
