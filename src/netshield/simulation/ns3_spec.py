"""Emit an NS-3 scenario specification from the project configuration.

NS-3 is the primary engine: the Python side owns the *definition* of a
scenario (the topology, the device fleet, the compromised-device load) and the
C++ model (``ns3/netshield/netshield-sim.cc``) owns the *execution*. This
module is the bridge between them. It builds the exact topology the Python
topology builder would build -- every node, every link, for any of the seven
families -- and writes it, together with per-device application rates and
per-bot attack rates, as a plain-text spec the C++ model reads.

Writing the whole graph as data is what makes NS-3 a faithful network rather
than a few hard-coded shapes: a multi-gateway fabric or a mesh is simply a
different set of ``node``/``link`` lines, and the C++ builds it generically.

Fidelity notes (returned in the provenance dict and recorded in run.json):
  * All traffic is produced by NS-3 application generators sending from each
    node's real address; source spoofing is not reproduced.
  * Volumetric UDP and application-layer HTTP floods are genuine. SYN, ACK,
    ICMP and slowloris are offered-load approximations on the relevant
    transport and port, labelled as such.
  * The cloud is a packet sink; the finite SYN backlog and connection table
    that the Python engine models are not reproduced, so protocol-exhaustion
    effects are approximated by load.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

import numpy as np

from ..utils.config import Config
from .topology import build_topology

#: Attack family -> (uses_tcp, destination port, is_approximation).
ATTACK_MAP: dict[str, tuple[bool, int, bool]] = {
    "udp_flood": (False, 5683, False),
    "http_flood": (True, 80, False),
    "icmp_flood": (False, 5683, True),
    "syn_flood": (True, 8883, True),
    "ack_flood": (True, 80, True),
    "slowloris": (True, 80, True),
}

#: Device class -> (app kind, destination port, interval key, payload key).
DEVICE_MAP: dict[str, tuple[str, int, str, str]] = {
    "mqtt_sensor": ("mqtt", 8883, "publish_interval_s", "payload_bytes"),
    "http_client": ("http", 80, "request_interval_s", "request_bytes"),
    "tcp_uploader": ("bulk", 443, "upload_interval_s", "upload_bytes"),
    "udp_streamer": ("coap", 5683, "packet_interval_s", "payload_bytes"),
}


def _mean(bounds: Any, default: float) -> float:
    try:
        lo, hi = float(bounds[0]), float(bounds[1])
        return (lo + hi) / 2.0
    except (TypeError, ValueError, IndexError):
        return default


def device_app_rate(device_class: str, traffic: Mapping[str, Any]) -> tuple[str, int, float, int]:
    """Return (app kind, port, mean bits/s, representative packet bytes).

    The mean rate is payload per message divided by the message interval, so a
    device offers the same average load to NS-3 as it does to the Python
    engine. Packet size is the device's representative payload, so per-class
    size features still separate the classes.
    """
    kind, port, interval_key, payload_key = DEVICE_MAP.get(
        device_class, ("coap", 5683, "packet_interval_s", "payload_bytes"))
    cfg = traffic.get(device_class, {}) or {}
    interval = float(cfg.get(interval_key, 2.0))
    payload = _mean(cfg.get(payload_key, [128, 128]), 128.0)
    if device_class == "tcp_uploader":
        pkt = int(cfg.get("segment_bytes", 1400))
    else:
        pkt = max(1, int(payload))
    rate_bps = payload * 8.0 / max(1e-6, interval)
    return kind, port, max(1.0, rate_bps), pkt


def write_spec(config: Config, output_dir: str | Path, spec_path: str | Path) -> dict[str, Any]:
    """Write the NS-3 scenario spec and return a provenance dictionary.

    Args:
        config: The merged configuration.
        output_dir: Directory the C++ model writes its CSV/JSON output to.
        spec_path: Where to write the spec file.

    Returns:
        Provenance: node/link counts, the family mapping used and every
        approximation applied, for recording in the run summary.
    """
    topo = build_topology(config)
    traffic = config.section("traffic")
    attack = config.get("attack", {}) or {}
    duration = float(config.require("simulation.duration_s"))
    window_s = float(config.require("features.window_s"))
    seed = int(config.get("seed", 42))

    ids = sorted(topo.nodes)
    index = {nid: i for i, nid in enumerate(ids)}
    lines: list[str] = ["# NetShield-GNN NS-3 scenario spec (generated)"]

    def p(key: str, value: Any) -> None:
        lines.append(f"param {key} {value}")

    p("duration", duration)
    p("window_s", window_s)
    p("seed", seed)
    p("topology", config.get("network.topology.family", "tree"))
    p("output_dir", str(output_dir).replace("\\", "/"))

    # ---- nodes ------------------------------------------------------------
    for nid in ids:
        n = topo.nodes[nid]
        dc = n.device_class or "-"
        lines.append(
            f"node {nid} {n.kind.value} {n.tier} {1 if n.is_attacker else 0} "
            f"{dc} {n.forwarding_pps:.1f} {n.proc_queue}")
    lines.append(f"cloud {index[topo.cloud_id]}")
    enforce = topo.enforcement_nodes or [topo.gateway_id]
    lines.append("enforce " + " ".join(str(index[e]) for e in enforce if e in index))

    # ---- links (each physical link once) ----------------------------------
    seen: set[tuple[int, int]] = set()
    n_links = 0
    for (a, b), ch in topo.channels.items():
        ia, ib = index[a], index[b]
        key = (min(ia, ib), max(ia, ib))
        if key in seen:
            continue
        seen.add(key)
        lines.append(
            f"link {ia} {ib} {ch.bandwidth_bps:.1f} {ch.delay_s:.6f} "
            f"{ch.queue_packets} {ch.loss:.6f}")
        n_links += 1

    # ---- legitimate device applications -----------------------------------
    for n in topo.endpoints():
        kind, port, rate_bps, pkt = device_app_rate(n.device_class, traffic)
        # A single OnOff at the device's mean offered rate; on=1/off=0 keeps a
        # steady class-characteristic load without hand-pacing packets.
        lines.append(
            f"app {index[n.node_id]} {kind} {rate_bps:.1f} {pkt} {port} 1.0 0.0 1.0")

    # ---- attack profile ---------------------------------------------------
    enabled = bool(attack.get("enabled", False))
    family = str(attack.get("type", "udp_flood"))
    sizes = attack.get("packet_bytes", [512, 512]) or [512, 512]
    atk_bytes = int(_mean(sizes, 512.0))
    start = float(attack.get("start_s", 0.0))
    atk_duration = float(attack.get("duration_s", 0.0)) if enabled else 0.0
    shape = config.get("attack.shape", {}) or {}
    burst = attack.get("burst", {}) or {}
    jitter = attack.get("rate_jitter", [1.0, 1.0]) or [1.0, 1.0]
    stagger = float(attack.get("stagger_s", 0.0))

    p("attack_enabled", 1 if enabled else 0)
    p("attack_start", start)
    p("attack_duration", atk_duration)
    p("attack_type", family)
    uses_tcp, atk_port, _ = ATTACK_MAP.get(family, (False, 5683, True))
    p("attack_port", atk_port)
    p("attack_socket", "ns3::TcpSocketFactory" if uses_tcp else "ns3::UdpSocketFactory")
    p("burst", 1 if burst.get("enabled") else 0)
    p("burst_on", float(burst.get("on_s", 2.0)))
    p("burst_off", float(burst.get("off_s", 3.0)))
    p("profile", str(shape.get("profile", "constant")))
    p("ramp_lo", float(shape.get("ramp_start_factor", 0.1)))
    p("ramp_hi", float(shape.get("ramp_end_factor", 1.0)))
    p("sine_period", float(shape.get("sine_period_s", 10.0)))
    p("sine_depth", float(shape.get("sine_depth", 0.5)))
    p("step_interval", float(shape.get("step_interval_s", 5.0)))
    levels = shape.get("step_levels", [0.25, 0.5, 0.75, 1.0]) or [1.0]
    lines.append("steplevels " + " ".join(f"{float(v):.4f}" for v in levels))

    # ---- per-bot load -----------------------------------------------------
    approximated: set[str] = set()
    rng = np.random.default_rng(seed + 9973)
    pps = float(attack.get("packets_per_second", 0.0))
    lo, hi = float(jitter[0]), float(jitter[-1])
    mix = attack.get("family_mix", {}) or {}
    mix_families = sorted(mix) or ["udp_flood", "syn_flood", "http_flood"]
    mix_weights = np.array([float(mix.get(f, 1.0)) for f in mix_families], dtype=float)
    mix_weights = mix_weights / mix_weights.sum() if mix_weights.sum() else None
    bots = topo.attackers()
    for n in bots:
        fam = family
        if family == "mixed":
            fam = str(rng.choice(mix_families, p=mix_weights))
        f_tcp, f_port, f_approx = ATTACK_MAP.get(fam, (False, 5683, True))
        if f_approx:
            approximated.add(fam)
        factor = float(rng.uniform(lo, hi)) if hi > lo else lo
        wire = atk_bytes + (40 if f_tcp else 28)
        # slowloris is defined by held connections, not volume; cap its rate.
        bot_pps = min(pps, 20.0) if fam == "slowloris" else pps
        rate_bps = max(1.0, bot_pps * factor * wire * 8.0)
        join = float(rng.uniform(0.0, stagger)) if stagger > 0 else 0.0
        lines.append(
            f"bot {index[n.node_id]} {fam} {rate_bps:.1f} {atk_bytes} {join:.3f} "
            f"{1 if f_tcp else 0} {f_port}")

    Path(spec_path).write_text("\n".join(lines) + "\n", encoding="utf-8")

    notes: list[str] = []
    if enabled and approximated:
        notes.append(
            "attack families " + ", ".join(sorted(approximated)) +
            " are offered-load approximations in NS-3 (standard application "
            "generators on the relevant transport/port), not protocol-exact")
    if attack.get("spoof_sources"):
        notes.append("source spoofing is not reproduced; all traffic carries "
                     "each node's real address")
    notes.append("the cloud is a packet sink; the finite SYN backlog and "
                 "connection table are not modelled, so protocol-exhaustion "
                 "effects are approximated by load")
    return {
        "n_nodes": len(ids),
        "n_links": n_links,
        "n_bots": len(bots),
        "attack_family": family,
        "approximated_families": sorted(approximated),
        "ns3_approximations": notes,
        "node_index": index,
    }
