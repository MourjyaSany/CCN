"""Telemetry collection: IPFIX-style flow export and per-window QoS metrics.

Storing one row per packet is not viable at DDoS packet rates (a single 90-second
run can exceed a million packets), and it is also not what a real network does.
Production gateways export **flow records**: per-window, per-5-tuple aggregates.
This module implements the same thing.

Two independent streams are produced:

``FlowTable``
    One record per ``(time-window, 5-tuple)``. These become the input to feature
    extraction, the graph builder and the Random-Forest baseline.

``WindowMetrics``
    One record per time window describing the *network's* health: throughput,
    end-to-end latency distribution, packet loss broken down by cause, queue
    occupancy and bandwidth utilisation. These are the QoS numbers plotted in
    ``results/figures`` and are emergent properties of the queueing model - none
    of them is configured anywhere.

An optional bounded per-packet trace is available for debugging and for the
small runs used by the unit tests.
"""

from __future__ import annotations

import csv
import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator

from ..utils.logging_utils import get_logger
from ..utils.paths import ensure_parent
from .packet import (
    CONGESTION_DROP_REASONS,
    MITIGATION_DROP_REASONS,
    Packet,
    Protocol,
    TCPFlag,
)

_LOG = get_logger(__name__)

#: Maximum number of end-to-end latency samples retained per window.
LATENCY_SAMPLE_CAP: int = 4000

#: Default service-level objective for one-way delay of clean device traffic.
#: A packet delivered later than this counts as unavailable service.
DEFAULT_SLO_LATENCY_S: float = 0.100

#: Upstream application tags of the legitimate device classes.
LEGIT_APP_TAGS: tuple[str, ...] = ("mqtt", "http", "bulk", "coap")


def _reservoir_slot(seen: int) -> int:
    """Deterministic reservoir-sampling slot for the *seen*-th sample (1-based).

    Returns an index in ``[0, seen)``. A Knuth multiplicative hash keeps the
    choice reproducible run-to-run, so cached runs stay byte-identical, while
    spreading retained samples across the window instead of keeping only the
    first ``LATENCY_SAMPLE_CAP`` packets.
    """
    return ((seen * 2654435761) & 0xFFFFFFFF) % seen


def jain_index(values: Iterable[float]) -> float:
    """Jain's fairness index ``(sum x)^2 / (n * sum x^2)`` in ``(0, 1]``."""
    xs = [float(v) for v in values]
    if not xs:
        return 1.0
    sq = sum(x * x for x in xs)
    return (sum(xs) ** 2) / (len(xs) * sq) if sq > 0 else 1.0


@dataclass(slots=True)
class FlowRecord:
    """Accumulated statistics for one 5-tuple inside one time window.

    All second-order statistics (variance, jitter) are accumulated with running
    sums so the record stays O(1) in memory regardless of packet count.
    """

    window: int
    t_start: float
    src_node: str
    dst_node: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    app: str = "generic"

    packets: int = 0
    bytes: int = 0
    payload_bytes: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0

    size_sum: float = 0.0
    size_sq_sum: float = 0.0
    size_min: int = 1 << 30
    size_max: int = 0

    iat_sum: float = 0.0
    iat_sq_sum: float = 0.0
    iat_count: int = 0

    syn_count: int = 0
    syn_ack_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0

    delivered: int = 0
    dropped: int = 0
    retransmits: int = 0

    attack_packets: int = 0
    attack_type: str = ""

    def update(self, packet: Packet) -> None:
        """Fold a newly generated packet into this flow record."""
        size = packet.size
        if self.packets == 0:
            self.first_seen = packet.t_gen
        else:
            gap = packet.t_gen - self.last_seen
            if gap >= 0.0:
                self.iat_sum += gap
                self.iat_sq_sum += gap * gap
                self.iat_count += 1
        self.last_seen = packet.t_gen

        self.packets += 1
        self.bytes += size
        self.payload_bytes += packet.payload
        self.size_sum += size
        self.size_sq_sum += float(size) * float(size)
        self.size_min = min(self.size_min, size)
        self.size_max = max(self.size_max, size)
        if packet.retransmit:
            self.retransmits += 1

        if packet.protocol == Protocol.TCP:
            flags = packet.flags
            syn = bool(flags & TCPFlag.SYN)
            ack = bool(flags & TCPFlag.ACK)
            if syn and ack:
                self.syn_ack_count += 1
            elif syn:
                self.syn_count += 1
            if ack:
                self.ack_count += 1
            if flags & TCPFlag.FIN:
                self.fin_count += 1
            if flags & TCPFlag.RST:
                self.rst_count += 1
            if flags & TCPFlag.PSH:
                self.psh_count += 1

        if packet.is_attack:
            self.attack_packets += 1
            if not self.attack_type:
                self.attack_type = packet.attack_type

    # -- derived statistics -------------------------------------------------- #
    @property
    def duration(self) -> float:
        """Observed flow duration inside the window, in seconds."""
        return max(0.0, self.last_seen - self.first_seen)

    @property
    def mean_packet_size(self) -> float:
        """Mean wire packet size in bytes."""
        return self.size_sum / self.packets if self.packets else 0.0

    @property
    def packet_size_variance(self) -> float:
        """Population variance of packet size, in bytes squared."""
        if self.packets < 2:
            return 0.0
        mean = self.mean_packet_size
        var = self.size_sq_sum / self.packets - mean * mean
        return max(0.0, var)

    @property
    def mean_iat(self) -> float:
        """Mean inter-arrival time between packets of this flow, seconds."""
        return self.iat_sum / self.iat_count if self.iat_count else 0.0

    @property
    def iat_std(self) -> float:
        """Standard deviation of the inter-arrival time (jitter), seconds."""
        if self.iat_count < 2:
            return 0.0
        mean = self.mean_iat
        var = self.iat_sq_sum / self.iat_count - mean * mean
        return math.sqrt(max(0.0, var))

    def packet_rate(self, window_s: float) -> float:
        """Packets per second, normalised by the *window* length."""
        return self.packets / window_s if window_s > 0 else 0.0

    def byte_rate(self, window_s: float) -> float:
        """Bytes per second, normalised by the *window* length."""
        return self.bytes / window_s if window_s > 0 else 0.0

    @property
    def attack_ratio(self) -> float:
        """Ground-truth fraction of this flow's packets that are attack traffic."""
        return self.attack_packets / self.packets if self.packets else 0.0

    def to_row(self, window_s: float) -> dict[str, Any]:
        """Flatten the record into a CSV/DataFrame row."""
        return {
            "window": self.window,
            "t_start": round(self.t_start, 4),
            "t_end": round(self.t_start + window_s, 4),
            "src_node": self.src_node,
            "dst_node": self.dst_node,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "protocol_name": Protocol.name(self.protocol),
            "app": self.app,
            "packets": self.packets,
            "bytes": self.bytes,
            "payload_bytes": self.payload_bytes,
            "duration": round(self.duration, 6),
            "packet_rate": round(self.packet_rate(window_s), 4),
            "byte_rate": round(self.byte_rate(window_s), 4),
            "mean_packet_size": round(self.mean_packet_size, 3),
            "packet_size_var": round(self.packet_size_variance, 3),
            "min_packet_size": 0 if self.size_min > (1 << 29) else self.size_min,
            "max_packet_size": self.size_max,
            "mean_iat": round(self.mean_iat, 6),
            "iat_std": round(self.iat_std, 6),
            "syn_count": self.syn_count,
            "syn_ack_count": self.syn_ack_count,
            "ack_count": self.ack_count,
            "fin_count": self.fin_count,
            "rst_count": self.rst_count,
            "psh_count": self.psh_count,
            "delivered": self.delivered,
            "dropped": self.dropped,
            "retransmits": self.retransmits,
            "attack_packets": self.attack_packets,
            "attack_ratio": round(self.attack_ratio, 5),
            "attack_type": self.attack_type,
        }


FLOW_CSV_COLUMNS: tuple[str, ...] = (
    "window", "t_start", "t_end", "src_node", "dst_node", "src_ip", "dst_ip",
    "src_port", "dst_port", "protocol", "protocol_name", "app", "packets",
    "bytes", "payload_bytes", "duration", "packet_rate", "byte_rate",
    "mean_packet_size", "packet_size_var", "min_packet_size", "max_packet_size",
    "mean_iat", "iat_std", "syn_count", "syn_ack_count", "ack_count",
    "fin_count", "rst_count", "psh_count", "delivered", "dropped",
    "retransmits", "attack_packets", "attack_ratio", "attack_type",
)


@dataclass(slots=True)
class WindowMetrics:
    """Network QoS measurements for one time window.

    Every field here is *measured*, never configured: throughput comes from
    bytes that actually reached the cloud, latency from per-packet timestamps,
    and loss from the drop-tail queues and processing servers.
    """

    window: int
    t_start: float
    t_end: float

    offered_packets: int = 0
    offered_bytes: int = 0
    delivered_packets: int = 0
    delivered_bytes: int = 0
    # Directional split: 'upstream' means delivered at the cloud server,
    # i.e. traffic that actually crossed the gateway uplink bottleneck.
    delivered_packets_up: int = 0
    delivered_bytes_up: int = 0
    delivered_bytes_down: int = 0
    dropped_packets: int = 0
    dropped_bytes: int = 0

    legit_offered: int = 0
    legit_delivered: int = 0
    legit_dropped: int = 0
    # 'clean' = traffic originating from devices that were never
    # compromised. Isolating a bot also severs its own legitimate
    # telemetry, so 'legit_*' alone cannot answer the question a network
    # operator actually asks: did the *uninfected* fleet recover?
    clean_offered: int = 0
    clean_delivered: int = 0
    clean_dropped: int = 0
    clean_latency_sum: float = 0.0
    clean_latency_count: int = 0
    attack_offered: int = 0
    attack_delivered: int = 0
    attack_dropped: int = 0

    congestion_drops: int = 0
    mitigation_drops: int = 0
    loss_drops: int = 0
    drop_reasons: dict[str, int] = field(default_factory=dict)

    latency_sum: float = 0.0
    latency_count: int = 0
    latency_max: float = 0.0
    latency_samples: list[float] = field(default_factory=list)
    # Latency restricted to legitimate traffic: the delay a real IoT
    # device experiences, which is what an SLO is written against.
    legit_latency_sum: float = 0.0
    legit_latency_count: int = 0
    legit_latency_samples: list[float] = field(default_factory=list)

    uplink_busy_time: float = 0.0
    uplink_queue_sum: float = 0.0
    uplink_queue_n: int = 0
    uplink_queue_peak: int = 0
    #: Number of bottleneck channels whose busy time is summed into
    #: ``uplink_busy_time``. Utilisation divides by it, so a multi-gateway
    #: fabric reports mean utilisation across its uplinks rather than a
    #: figure that could exceed 100%.
    uplink_count: int = 1

    tcp_connections_opened: int = 0
    tcp_connections_failed: int = 0
    syn_backlog_peak: int = 0
    syn_rejected: int = 0
    unroutable_packets: int = 0
    active_attackers: int = 0
    mitigated_sources: int = 0

    # -- research-grade QoS / mitigation accounting ------------------------- #
    slo_latency_s: float = DEFAULT_SLO_LATENCY_S
    clean_offered_bytes: int = 0
    clean_mitigation_dropped: int = 0
    clean_mitigation_dropped_bytes: int = 0
    attack_mitigation_dropped: int = 0
    clean_within_slo: int = 0
    clean_latency_seen: int = 0
    clean_latency_samples: list[float] = field(default_factory=list)
    clean_jitter_sum: float = 0.0
    clean_jitter_n: int = 0
    clean_dev_offered: dict[str, int] = field(default_factory=dict)
    clean_dev_delivered: dict[str, int] = field(default_factory=dict)
    app_offered: dict[str, int] = field(default_factory=dict)
    app_delivered: dict[str, int] = field(default_factory=dict)

    # -- recording ---------------------------------------------------------- #
    def record_offered(self, packet: Packet) -> None:
        """Count a packet at the moment it is generated."""
        self.offered_packets += 1
        self.offered_bytes += packet.size
        if packet.is_attack:
            self.attack_offered += 1
        else:
            self.legit_offered += 1
        if not packet.from_compromised:
            self.clean_offered += 1
            self.clean_offered_bytes += packet.size
            if not packet.is_attack and not str(packet.app).startswith("srv:"):
                self.clean_dev_offered[packet.src] = (
                    self.clean_dev_offered.get(packet.src, 0) + 1)
        if not packet.is_attack:
            self.app_offered[packet.app] = self.app_offered.get(packet.app, 0) + 1

    def record_delivered(
        self, packet: Packet, latency: float, upstream: bool = True
    ) -> None:
        """Count a delivered packet together with its end-to-end delay.

        Args:
            packet: The delivered packet.
            latency: One-way end-to-end delay in seconds.
            upstream: True when the destination is the cloud server, i.e.
                the packet crossed the gateway uplink bottleneck.
                Downstream traffic (ACKs, HTTP response bodies) is counted
                separately so that measured throughput stays directly
                comparable with the uplink capacity.
        """
        self.delivered_packets += 1
        self.delivered_bytes += packet.size
        if upstream:
            self.delivered_packets_up += 1
            self.delivered_bytes_up += packet.size
        else:
            self.delivered_bytes_down += packet.size
        if packet.is_attack:
            self.attack_delivered += 1
        else:
            self.legit_delivered += 1
            self.legit_latency_sum += latency
            self.legit_latency_count += 1
            if len(self.legit_latency_samples) < LATENCY_SAMPLE_CAP:
                self.legit_latency_samples.append(latency)
            self.app_delivered[packet.app] = self.app_delivered.get(packet.app, 0) + 1
            if not packet.from_compromised:
                self.clean_delivered += 1
                self.clean_latency_sum += latency
                self.clean_latency_count += 1
                if latency <= self.slo_latency_s:
                    self.clean_within_slo += 1
                self.clean_latency_seen += 1
                if len(self.clean_latency_samples) < LATENCY_SAMPLE_CAP:
                    self.clean_latency_samples.append(latency)
                else:
                    slot = _reservoir_slot(self.clean_latency_seen)
                    if slot < LATENCY_SAMPLE_CAP:
                        self.clean_latency_samples[slot] = latency
                if not str(packet.app).startswith("srv:"):
                    self.clean_dev_delivered[packet.src] = (
                        self.clean_dev_delivered.get(packet.src, 0) + 1)
        self.latency_sum += latency
        self.latency_count += 1
        self.latency_max = max(self.latency_max, latency)
        if len(self.latency_samples) < LATENCY_SAMPLE_CAP:
            self.latency_samples.append(latency)

    def record_drop(self, packet: Packet, reason: str) -> None:
        """Count a discarded packet and attribute it to a cause."""
        self.dropped_packets += 1
        self.dropped_bytes += packet.size
        self.drop_reasons[reason] = self.drop_reasons.get(reason, 0) + 1
        if packet.is_attack:
            self.attack_dropped += 1
        else:
            self.legit_dropped += 1
            if not packet.from_compromised:
                self.clean_dropped += 1
        if reason in MITIGATION_DROP_REASONS:
            self.mitigation_drops += 1
            if packet.is_attack:
                self.attack_mitigation_dropped += 1
            elif not packet.from_compromised:
                self.clean_mitigation_dropped += 1
                self.clean_mitigation_dropped_bytes += packet.size
        elif reason in CONGESTION_DROP_REASONS:
            self.congestion_drops += 1
        elif reason == "random_loss":
            self.loss_drops += 1

    # -- derived ------------------------------------------------------------ #
    @property
    def duration(self) -> float:
        """Window length in seconds."""
        return max(1e-9, self.t_end - self.t_start)

    @property
    def throughput_bps(self) -> float:
        """Upstream goodput delivered at the cloud server, in bits/second.

        Directly comparable with the gateway uplink capacity, because
        every byte counted here traversed that link.
        """
        return self.delivered_bytes_up * 8.0 / self.duration

    @property
    def downstream_bps(self) -> float:
        """Goodput delivered back to devices (ACKs, HTTP bodies), bits/s."""
        return self.delivered_bytes_down * 8.0 / self.duration

    @property
    def aggregate_bps(self) -> float:
        """Total delivered goodput in both directions, bits per second."""
        return self.delivered_bytes * 8.0 / self.duration

    @property
    def offered_bps(self) -> float:
        """Offered load, in bits per second."""
        return self.offered_bytes * 8.0 / self.duration

    @property
    def legit_throughput_pps(self) -> float:
        """Delivered *legitimate* packets per second (the metric users feel)."""
        return self.legit_delivered / self.duration

    @property
    def packets_per_second(self) -> float:
        """Offered packet rate."""
        return self.offered_packets / self.duration

    @property
    def loss_ratio(self) -> float:
        """Overall packet loss ratio in [0, 1]."""
        total = self.delivered_packets + self.dropped_packets
        return self.dropped_packets / total if total else 0.0

    @property
    def legit_loss_ratio(self) -> float:
        """Loss ratio over all non-attack traffic, bots' own traffic included."""
        total = self.legit_delivered + self.legit_dropped
        return self.legit_dropped / total if total else 0.0

    @property
    def clean_loss_ratio(self) -> float:
        """Loss ratio for traffic from devices that were never compromised.

        This is the service-level number: it excludes the legitimate
        telemetry of bots, which mitigation deliberately severs, so it
        answers whether the *uninfected* fleet recovered.
        """
        total = self.clean_delivered + self.clean_dropped
        return self.clean_dropped / total if total else 0.0

    @property
    def clean_throughput_pps(self) -> float:
        """Delivered packets per second from uncompromised devices."""
        return self.clean_delivered / self.duration

    @property
    def clean_mean_latency_ms(self) -> float:
        """Mean end-to-end delay for uncompromised devices, milliseconds."""
        if not self.clean_latency_count:
            return 0.0
        return self.clean_latency_sum / self.clean_latency_count * 1000.0

    @property
    def mean_latency_ms(self) -> float:
        """Mean end-to-end one-way delay of delivered packets, milliseconds."""
        return (self.latency_sum / self.latency_count * 1000.0) if self.latency_count else 0.0

    @property
    def max_latency_ms(self) -> float:
        """Worst observed end-to-end delay, milliseconds."""
        return self.latency_max * 1000.0

    @property
    def legit_mean_latency_ms(self) -> float:
        """Mean end-to-end delay of *legitimate* traffic only, in ms."""
        if not self.legit_latency_count:
            return 0.0
        return self.legit_latency_sum / self.legit_latency_count * 1000.0

    def legit_latency_percentile_ms(self, q: float) -> float:
        """Return the *q*-th percentile of legitimate-traffic latency, ms."""
        if not self.legit_latency_samples:
            return 0.0
        ordered = sorted(self.legit_latency_samples)
        idx = min(len(ordered) - 1,
                  max(0, int(round((q / 100.0) * (len(ordered) - 1)))))
        return ordered[idx] * 1000.0

    def latency_percentile_ms(self, q: float) -> float:
        """Return the *q*-th percentile of sampled latency, in milliseconds.

        Args:
            q: Percentile in ``[0, 100]``.
        """
        if not self.latency_samples:
            return 0.0
        ordered = sorted(self.latency_samples)
        idx = min(len(ordered) - 1, max(0, int(round((q / 100.0) * (len(ordered) - 1)))))
        return ordered[idx] * 1000.0

    def uplink_utilisation(self) -> float:
        """Mean fraction of the window the bottleneck serialiser(s) were busy.

        With a single uplink this is exactly its utilisation. With several
        (a multi-gateway fabric) it is the mean across them, because
        ``uplink_busy_time`` sums every uplink's transmit time.
        """
        capacity = self.duration * max(1, self.uplink_count)
        return min(1.0, self.uplink_busy_time / capacity) if capacity > 0 else 0.0

    def clean_latency_percentile_ms(self, q: float) -> float:
        """*q*-th percentile of clean-device one-way delay, in milliseconds."""
        if not self.clean_latency_samples:
            return 0.0
        ordered = sorted(self.clean_latency_samples)
        idx = min(len(ordered) - 1, max(0, int(round((q / 100.0) * (len(ordered) - 1)))))
        return ordered[idx] * 1000.0

    @property
    def clean_jitter_ms(self) -> float:
        """Mean RFC 3550 interarrival jitter over clean flows, milliseconds."""
        return self.clean_jitter_sum / self.clean_jitter_n * 1000.0 if self.clean_jitter_n else 0.0

    @property
    def clean_availability(self) -> float:
        """Share of clean packets delivered within the latency SLO.

        Lost packets and late packets both count as unavailable service, so
        this is the single number an SLA would be written against.
        """
        return self.clean_within_slo / self.clean_offered if self.clean_offered else 1.0

    @property
    def collateral_byte_ratio(self) -> float:
        """Clean-device bytes dropped by mitigation / clean-device bytes offered."""
        if not self.clean_offered_bytes:
            return 0.0
        return self.clean_mitigation_dropped_bytes / self.clean_offered_bytes

    @property
    def attack_suppression_ratio(self) -> float:
        """Attack packets removed by mitigation / attack packets offered."""
        return self.attack_mitigation_dropped / self.attack_offered if self.attack_offered else 0.0

    @property
    def clean_fairness(self) -> float:
        """Jain's index over per-device delivery ratios of clean devices."""
        ratios = [
            self.clean_dev_delivered.get(dev, 0) / offered
            for dev, offered in self.clean_dev_offered.items() if offered > 0
        ]
        return jain_index(ratios)

    def app_delivery_ratio(self, app: str) -> float:
        """Delivered / offered packets for one legitimate application tag."""
        offered = self.app_offered.get(app, 0)
        return self.app_delivered.get(app, 0) / offered if offered else float("nan")

    def mean_uplink_queue(self) -> float:
        """Mean gateway-uplink queue occupancy, in packets."""
        return self.uplink_queue_sum / self.uplink_queue_n if self.uplink_queue_n else 0.0

    def to_row(self) -> dict[str, Any]:
        """Flatten the record into a CSV/DataFrame row."""
        return {
            "window": self.window,
            "t_start": round(self.t_start, 4),
            "t_end": round(self.t_end, 4),
            "offered_packets": self.offered_packets,
            "offered_bytes": self.offered_bytes,
            "delivered_packets": self.delivered_packets,
            "delivered_bytes": self.delivered_bytes,
            "delivered_packets_up": self.delivered_packets_up,
            "delivered_bytes_up": self.delivered_bytes_up,
            "dropped_packets": self.dropped_packets,
            "dropped_bytes": self.dropped_bytes,
            "legit_offered": self.legit_offered,
            "legit_delivered": self.legit_delivered,
            "legit_dropped": self.legit_dropped,
            "attack_offered": self.attack_offered,
            "attack_delivered": self.attack_delivered,
            "attack_dropped": self.attack_dropped,
            "congestion_drops": self.congestion_drops,
            "mitigation_drops": self.mitigation_drops,
            "random_loss_drops": self.loss_drops,
            "pps": round(self.packets_per_second, 3),
            "throughput_bps": round(self.throughput_bps, 2),
            "throughput_mbps": round(self.throughput_bps / 1e6, 5),
            "downstream_mbps": round(self.downstream_bps / 1e6, 5),
            "aggregate_mbps": round(self.aggregate_bps / 1e6, 5),
            "offered_mbps": round(self.offered_bps / 1e6, 5),
            "legit_throughput_pps": round(self.legit_throughput_pps, 3),
            "loss_ratio": round(self.loss_ratio, 6),
            "legit_loss_ratio": round(self.legit_loss_ratio, 6),
            "clean_offered": self.clean_offered,
            "clean_delivered": self.clean_delivered,
            "clean_dropped": self.clean_dropped,
            "clean_loss_ratio": round(self.clean_loss_ratio, 6),
            "clean_throughput_pps": round(self.clean_throughput_pps, 3),
            "clean_mean_latency_ms": round(self.clean_mean_latency_ms, 4),
            "mean_latency_ms": round(self.mean_latency_ms, 4),
            "legit_mean_latency_ms": round(self.legit_mean_latency_ms, 4),
            "legit_p95_latency_ms": round(
                self.legit_latency_percentile_ms(95.0), 4),
            "p95_latency_ms": round(self.latency_percentile_ms(95.0), 4),
            "p99_latency_ms": round(self.latency_percentile_ms(99.0), 4),
            "max_latency_ms": round(self.max_latency_ms, 4),
            "uplink_utilisation": round(self.uplink_utilisation(), 5),
            "mean_uplink_queue": round(self.mean_uplink_queue(), 3),
            "peak_uplink_queue": self.uplink_queue_peak,
            "tcp_connections_opened": self.tcp_connections_opened,
            "tcp_connections_failed": self.tcp_connections_failed,
            "syn_backlog_peak": self.syn_backlog_peak,
            "syn_rejected": self.syn_rejected,
            "unroutable_packets": self.unroutable_packets,
            "active_attackers": self.active_attackers,
            "mitigated_sources": self.mitigated_sources,
            "drop_reasons": json.dumps(self.drop_reasons, sort_keys=True),
            "clean_p50_latency_ms": round(self.clean_latency_percentile_ms(50.0), 4),
            "clean_p95_latency_ms": round(self.clean_latency_percentile_ms(95.0), 4),
            "clean_p99_latency_ms": round(self.clean_latency_percentile_ms(99.0), 4),
            "clean_jitter_ms": round(self.clean_jitter_ms, 4),
            "clean_availability": round(self.clean_availability, 6),
            "clean_fairness": round(self.clean_fairness, 6),
            "collateral_byte_ratio": round(self.collateral_byte_ratio, 6),
            "attack_suppression_ratio": round(self.attack_suppression_ratio, 6),
            "clean_mitigation_dropped": self.clean_mitigation_dropped,
            **{f"delivery_ratio_{app}": round(self.app_delivery_ratio(app), 6)
               for app in LEGIT_APP_TAGS},
        }


METRIC_CSV_COLUMNS: tuple[str, ...] = (
    "window", "t_start", "t_end", "offered_packets", "offered_bytes",
    "delivered_packets", "delivered_bytes", "delivered_packets_up",
    "delivered_bytes_up", "dropped_packets", "dropped_bytes",
    "legit_offered", "legit_delivered", "legit_dropped", "attack_offered",
    "attack_delivered", "attack_dropped", "congestion_drops",
    "mitigation_drops", "random_loss_drops", "pps", "throughput_bps",
    "throughput_mbps", "downstream_mbps", "aggregate_mbps", "offered_mbps",
    "legit_throughput_pps", "loss_ratio", "legit_loss_ratio",
    "clean_offered", "clean_delivered", "clean_dropped",
    "clean_loss_ratio", "clean_throughput_pps", "clean_mean_latency_ms",
    "mean_latency_ms", "legit_mean_latency_ms", "legit_p95_latency_ms",
    "p95_latency_ms", "p99_latency_ms",
    "max_latency_ms", "uplink_utilisation", "mean_uplink_queue",
    "peak_uplink_queue", "tcp_connections_opened", "tcp_connections_failed",
    "syn_backlog_peak", "syn_rejected", "unroutable_packets",
    "active_attackers", "mitigated_sources", "drop_reasons",
    "clean_p50_latency_ms", "clean_p95_latency_ms", "clean_p99_latency_ms",
    "clean_jitter_ms", "clean_availability", "clean_fairness",
    "collateral_byte_ratio", "attack_suppression_ratio",
    "clean_mitigation_dropped",
    *(f"delivery_ratio_{app}" for app in LEGIT_APP_TAGS),
)


class TelemetryCollector:
    """Owns the flow table, the window metrics and the optional packet trace.

    Args:
        window_s: Feature/metric window length in seconds.
        trace_packets: Retain a bounded per-packet trace (debugging/tests).
        max_trace: Cap on retained trace rows.
    """

    def __init__(
        self,
        window_s: float,
        trace_packets: bool = False,
        max_trace: int = 20000,
        slo_latency_s: float = DEFAULT_SLO_LATENCY_S,
    ) -> None:
        if window_s <= 0:
            raise ValueError("window_s must be positive")
        self.window_s = float(window_s)
        self.trace_packets = bool(trace_packets)
        self.max_trace = int(max_trace)
        self.slo_latency_s = float(slo_latency_s)
        #: Per-flow RFC 3550 jitter state: flow key -> (last transit, J).
        self._jitter_state: dict[tuple, tuple[float, float]] = {}

        self.flows: dict[tuple, FlowRecord] = {}
        self.windows: dict[int, WindowMetrics] = {}
        self.trace: list[dict[str, Any]] = []
        self._trace_truncated = False
        #: Number of bottleneck channels the engine attributes busy time from.
        #: Set by :class:`~netshield.simulation.engine.SimulationEngine` once
        #: the topology is known, and stamped onto every window it creates.
        self.uplink_count: int = 1

    # -- window helpers ------------------------------------------------------ #
    def window_index(self, t: float) -> int:
        """Return the window index containing simulated time *t*."""
        return int(t // self.window_s)

    def window(self, index: int) -> WindowMetrics:
        """Return (creating if needed) the :class:`WindowMetrics` for *index*."""
        metrics = self.windows.get(index)
        if metrics is None:
            start = index * self.window_s
            metrics = WindowMetrics(
                window=index,
                t_start=start,
                t_end=start + self.window_s,
                uplink_count=max(1, self.uplink_count),
                slo_latency_s=self.slo_latency_s,
            )
            self.windows[index] = metrics
        return metrics

    def window_at(self, t: float) -> WindowMetrics:
        """Return the :class:`WindowMetrics` covering simulated time *t*."""
        return self.window(self.window_index(t))

    # -- recording ----------------------------------------------------------- #
    def on_generate(self, packet: Packet) -> None:
        """Record a packet at generation time (flow update + offered load)."""
        index = self.window_index(packet.t_gen)
        key = (
            index,
            packet.src,
            packet.dst,
            packet.src_ip,
            packet.dst_ip,
            packet.sport,
            packet.dport,
            packet.protocol,
        )
        record = self.flows.get(key)
        if record is None:
            record = FlowRecord(
                window=index,
                t_start=index * self.window_s,
                src_node=packet.src,
                dst_node=packet.dst,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                src_port=packet.sport,
                dst_port=packet.dport,
                protocol=packet.protocol,
                app=packet.app,
            )
            self.flows[key] = record
        record.update(packet)
        self.window(index).record_offered(packet)
        packet.enqueue_time = packet.t_gen

        if self.trace_packets:
            if len(self.trace) < self.max_trace:
                self.trace.append(
                    {
                        "pid": packet.pid,
                        "t": round(packet.t_gen, 6),
                        "src": packet.src,
                        "dst": packet.dst,
                        "src_ip": packet.src_ip,
                        "dst_ip": packet.dst_ip,
                        "sport": packet.sport,
                        "dport": packet.dport,
                        "protocol": Protocol.name(packet.protocol),
                        "flags": TCPFlag.describe(packet.flags),
                        "size": packet.size,
                        "app": packet.app,
                        "is_attack": int(packet.is_attack),
                        "outcome": "generated",
                    }
                )
            else:
                self._trace_truncated = True

    def on_deliver(
        self, packet: Packet, t_now: float, upstream: bool = True
    ) -> None:
        """Record successful delivery of *packet* at simulated time *t_now*.

        Args:
            packet: The delivered packet.
            t_now: Simulated delivery time.
            upstream: True when the destination is the cloud server.
        """
        latency = max(0.0, t_now - packet.t_gen)
        window = self.window_at(packet.t_gen)
        window.record_delivered(packet, latency, upstream)
        if not packet.is_attack and not packet.from_compromised:
            # RFC 3550 section 6.4.1: J += (|D(i-1,i)| - J) / 16, per flow.
            fkey = (packet.src, packet.dst, packet.sport, packet.dport, packet.protocol)
            state = self._jitter_state.get(fkey)
            if state is None:
                self._jitter_state[fkey] = (latency, 0.0)
            else:
                last, jit = state
                jit += (abs(latency - last) - jit) / 16.0
                self._jitter_state[fkey] = (latency, jit)
                window.clean_jitter_sum += jit
                window.clean_jitter_n += 1
        self._bump_flow(packet, delivered=True)
        if self.trace_packets and len(self.trace) < self.max_trace:
            self.trace.append(
                {
                    "pid": packet.pid,
                    "t": round(t_now, 6),
                    "src": packet.src,
                    "dst": packet.dst,
                    "src_ip": packet.src_ip,
                    "dst_ip": packet.dst_ip,
                    "sport": packet.sport,
                    "dport": packet.dport,
                    "protocol": Protocol.name(packet.protocol),
                    "flags": TCPFlag.describe(packet.flags),
                    "size": packet.size,
                    "app": packet.app,
                    "is_attack": int(packet.is_attack),
                    "outcome": f"delivered:{latency * 1000.0:.3f}ms",
                }
            )

    def on_drop(self, packet: Packet, reason: str, t_now: float) -> None:
        """Record a discarded packet, attributed to *reason*."""
        self.window_at(packet.t_gen).record_drop(packet, reason)
        self._bump_flow(packet, delivered=False)
        if self.trace_packets and len(self.trace) < self.max_trace:
            self.trace.append(
                {
                    "pid": packet.pid,
                    "t": round(t_now, 6),
                    "src": packet.src,
                    "dst": packet.dst,
                    "src_ip": packet.src_ip,
                    "dst_ip": packet.dst_ip,
                    "sport": packet.sport,
                    "dport": packet.dport,
                    "protocol": Protocol.name(packet.protocol),
                    "flags": TCPFlag.describe(packet.flags),
                    "size": packet.size,
                    "app": packet.app,
                    "is_attack": int(packet.is_attack),
                    "outcome": f"dropped:{reason}",
                }
            )

    def _bump_flow(self, packet: Packet, delivered: bool) -> None:
        """Increment the delivered/dropped counter on the packet's flow record."""
        key = (
            self.window_index(packet.t_gen),
            packet.src,
            packet.dst,
            packet.src_ip,
            packet.dst_ip,
            packet.sport,
            packet.dport,
            packet.protocol,
        )
        record = self.flows.get(key)
        if record is None:
            return
        if delivered:
            record.delivered += 1
        else:
            record.dropped += 1

    def sample_queue(self, t: float, occupancy: int) -> None:
        """Record a gateway-uplink queue-occupancy sample."""
        metrics = self.window_at(t)
        metrics.uplink_queue_sum += occupancy
        metrics.uplink_queue_n += 1
        metrics.uplink_queue_peak = max(metrics.uplink_queue_peak, occupancy)

    def add_uplink_busy(self, t: float, seconds: float) -> None:
        """Attribute *seconds* of uplink serialisation time to the window at *t*."""
        self.window_at(t).uplink_busy_time += seconds

    # -- export --------------------------------------------------------------- #
    def flow_rows(self) -> list[dict[str, Any]]:
        """Return all flow records as sorted CSV rows."""
        rows = [record.to_row(self.window_s) for record in self.flows.values()]
        rows.sort(key=lambda r: (r["window"], r["src_node"], r["dst_node"], r["src_port"]))
        return rows

    def metric_rows(self) -> list[dict[str, Any]]:
        """Return all window metrics as sorted CSV rows."""
        return [self.windows[i].to_row() for i in sorted(self.windows)]

    def iter_windows(self) -> Iterator[WindowMetrics]:
        """Iterate window metrics in chronological order."""
        for index in sorted(self.windows):
            yield self.windows[index]

    def truncate_to(self, duration_s: float) -> None:
        """Drop the trailing partial window so statistics are not rate-biased.

        Args:
            duration_s: Total simulated duration. Windows whose start time is at
                or beyond ``floor(duration_s / window_s) * window_s`` are removed
                when the final window is incomplete.
        """
        complete = int(duration_s // self.window_s)
        if abs(duration_s - complete * self.window_s) < 1e-9:
            last_valid = complete - 1
        else:
            last_valid = complete - 1 if complete >= 1 else -1
        if last_valid < 0:
            return
        self.windows = {i: w for i, w in self.windows.items() if i <= last_valid}
        self.flows = {k: v for k, v in self.flows.items() if k[0] <= last_valid}

    def summary(self) -> dict[str, Any]:
        """Return a compact run-level summary of the collected telemetry."""
        offered = sum(w.offered_packets for w in self.windows.values())
        delivered = sum(w.delivered_packets for w in self.windows.values())
        dropped = sum(w.dropped_packets for w in self.windows.values())
        attack = sum(w.attack_offered for w in self.windows.values())
        latency_n = sum(w.latency_count for w in self.windows.values())
        latency_sum = sum(w.latency_sum for w in self.windows.values())
        return {
            "n_flows": len(self.flows),
            "n_windows": len(self.windows),
            "offered_packets": offered,
            "delivered_packets": delivered,
            "dropped_packets": dropped,
            "attack_packets": attack,
            "attack_fraction": round(attack / offered, 5) if offered else 0.0,
            "overall_loss_ratio": round(dropped / max(1, delivered + dropped), 6),
            "mean_latency_ms": round(latency_sum / latency_n * 1000.0, 4) if latency_n else 0.0,
            "trace_truncated": self._trace_truncated,
        }


def write_csv(rows: Iterable[dict[str, Any]], path: str | Path, columns: Iterable[str]) -> Path:
    """Write *rows* to a CSV file, creating parent directories as needed.

    Args:
        rows: Iterable of row dicts.
        path: Destination path (repo-relative paths are resolved).
        columns: Explicit column order; extra keys in rows are ignored.

    Returns:
        The absolute path written.
    """
    target = ensure_parent(path)
    cols = list(columns)
    with target.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=cols, extrasaction="ignore")
        writer.writeheader()
        count = 0
        for row in rows:
            writer.writerow(row)
            count += 1
    _LOG.debug("Wrote %d rows -> %s", count, target)
    return target
