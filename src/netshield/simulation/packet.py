"""Packet and protocol primitives for the NetShield-GNN discrete-event engine.

The packet model is deliberately layered the way a real stack is:

* **L3** - source/destination IPv4 address, total datagram size in bytes.
* **L4** - protocol (TCP/UDP), source/destination port, TCP flag bitfield,
  sequence/acknowledgement numbers.
* **L7** - an application tag (``mqtt``, ``http``, ``coap``, ``attack``) so the
  feature extractor can compute a protocol/application distribution per node.

Sizes are *wire* sizes: the header overhead below is added to every payload so
that throughput and bandwidth-utilisation figures are physically meaningful.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntFlag
from typing import Final

# --------------------------------------------------------------------------- #
# Header overheads (bytes)
# --------------------------------------------------------------------------- #
ETHERNET_OVERHEAD: Final[int] = 18  # 14 B header + 4 B FCS
IPV4_HEADER: Final[int] = 20
TCP_HEADER: Final[int] = 20
UDP_HEADER: Final[int] = 8
MTU: Final[int] = 1500
MSS: Final[int] = MTU - IPV4_HEADER - TCP_HEADER  # 1460


class Protocol:
    """Transport protocol identifiers (IANA numbers)."""

    TCP: Final[int] = 6
    UDP: Final[int] = 17
    ICMP: Final[int] = 1

    _NAMES: Final[dict[int, str]] = {6: "TCP", 17: "UDP", 1: "ICMP"}

    @classmethod
    def name(cls, value: int) -> str:
        """Return the human-readable name of a protocol number."""
        return cls._NAMES.get(int(value), f"PROTO-{int(value)}")

    @classmethod
    def from_name(cls, name: str) -> int:
        """Return the protocol number for ``"TCP"``/``"UDP"``/``"ICMP"``.

        Raises:
            ValueError: If the protocol name is not recognised.
        """
        key = name.strip().upper()
        for number, label in cls._NAMES.items():
            if label == key:
                return number
        raise ValueError(f"Unknown protocol name: {name!r}")


class TCPFlag(IntFlag):
    """TCP control-flag bitfield."""

    NONE = 0
    FIN = 1
    SYN = 2
    RST = 4
    PSH = 8
    ACK = 16
    URG = 32

    @staticmethod
    def describe(flags: int) -> str:
        """Render a flag bitfield as e.g. ``"SYN|ACK"``."""
        if not flags:
            return "-"
        names = [f.name for f in TCPFlag if f.value and (flags & f.value)]
        return "|".join(n for n in names if n)


def wire_size(payload_bytes: int, protocol: int) -> int:
    """Return the on-the-wire frame size for an application payload.

    Args:
        payload_bytes: Application-layer payload size in bytes.
        protocol: :class:`Protocol` number.

    Returns:
        Total Ethernet frame size in bytes, floored at a 64-byte minimum frame.
    """
    l4 = TCP_HEADER if protocol == Protocol.TCP else UDP_HEADER
    total = int(payload_bytes) + l4 + IPV4_HEADER + ETHERNET_OVERHEAD
    return max(64, total)


@dataclass(slots=True)
class Packet:
    """A single packet traversing the simulated network.

    Attributes:
        pid: Monotonic packet identifier (unique per simulation run).
        t_gen: Simulated time at which the packet was generated, seconds.
        src: Source node id.
        dst: Destination node id.
        src_ip: Source IPv4 address (may be spoofed for SYN floods).
        dst_ip: Destination IPv4 address.
        sport: Source port.
        dport: Destination port.
        protocol: :class:`Protocol` number.
        size: Total wire size in bytes.
        payload: Application payload size in bytes.
        flags: TCP flag bitfield (0 for UDP).
        app: Application tag used for the protocol-distribution feature.
        is_attack: Ground-truth label written by the generator, never by a model.
        attack_type: Attack family when ``is_attack`` is set.
        origin: Node id of the *real* originator, even when ``src_ip`` is spoofed.
        conn_id: TCP connection identifier, or -1.
        seq: TCP sequence number in bytes.
        ack: TCP acknowledgement number in bytes.
        hops: Number of forwarding hops traversed so far.
        enqueue_time: Time the packet entered the current transmit queue.
        retransmit: True when this is a TCP retransmission.
        from_compromised: True when the originating device is a
            ground-truth compromised node. Used only to separate the
            service level of uninfected devices from that of bots whose
            legitimate traffic mitigation also cuts off.
        app_len: Total application-message length in bytes (the model's
            equivalent of an HTTP ``Content-Length`` header). Set on the
            first segment of a message so the receiver knows when the
            message is complete; 0 when not applicable.
    """

    pid: int
    t_gen: float
    src: str
    dst: str
    src_ip: str
    dst_ip: str
    sport: int
    dport: int
    protocol: int
    size: int
    payload: int = 0
    flags: int = 0
    app: str = "generic"
    is_attack: bool = False
    attack_type: str = ""
    origin: str = ""
    conn_id: int = -1
    seq: int = 0
    ack: int = 0
    hops: int = 0
    enqueue_time: float = 0.0
    retransmit: bool = False
    app_len: int = 0
    #: True when the *originating device* is a ground-truth compromised
    #: node, regardless of whether this particular packet is attack
    #: traffic. Evaluation-only: never exposed as a model feature.
    from_compromised: bool = False

    def flow_key(self) -> tuple[str, str, int, int, int]:
        """Return the classic 5-tuple flow key.

        Returns:
            ``(src_ip, dst_ip, sport, dport, protocol)``.
        """
        return (self.src_ip, self.dst_ip, self.sport, self.dport, self.protocol)

    def is_syn_only(self) -> bool:
        """True when the packet is a bare SYN (connection request)."""
        return bool(self.flags & TCPFlag.SYN) and not (self.flags & TCPFlag.ACK)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        proto = Protocol.name(self.protocol)
        flags = TCPFlag.describe(self.flags) if self.protocol == Protocol.TCP else "-"
        tag = "ATK" if self.is_attack else "ok"
        return (
            f"<Pkt#{self.pid} t={self.t_gen:.4f} {self.src_ip}:{self.sport}"
            f"->{self.dst_ip}:{self.dport} {proto} {self.size}B {flags} {tag}>"
        )


@dataclass(slots=True)
class DropRecord:
    """Bookkeeping entry describing why and where a packet was discarded.

    Attributes:
        t: Simulated time of the drop.
        node: Node id at which the drop occurred.
        reason: One of ``queue_overflow``, ``random_loss``, ``cpu_overload``,
            ``syn_backlog_full``, ``mitigation_block``, ``mitigation_ratelimit``,
            ``mitigation_filter``, ``mitigation_isolate``, ``ttl_expired``.
        packet_size: Wire size of the dropped packet.
        is_attack: Ground-truth attack flag of the dropped packet.
        src: Originating node id.
    """

    t: float
    node: str
    reason: str
    packet_size: int
    is_attack: bool
    src: str


MITIGATION_DROP_REASONS: Final[frozenset[str]] = frozenset(
    {
        "mitigation_block",
        "mitigation_ratelimit",
        "mitigation_filter",
        "mitigation_isolate",
    }
)

CONGESTION_DROP_REASONS: Final[frozenset[str]] = frozenset(
    {"queue_overflow", "cpu_overload", "syn_backlog_full"}
)


@dataclass(slots=True)
class PacketCounters:
    """Aggregate packet counters maintained by nodes and channels."""

    tx_packets: int = 0
    tx_bytes: int = 0
    rx_packets: int = 0
    rx_bytes: int = 0
    dropped_packets: int = 0
    dropped_bytes: int = 0
    drop_reasons: dict[str, int] = field(default_factory=dict)

    def record_drop(self, reason: str, size: int) -> None:
        """Increment drop counters for *reason*."""
        self.dropped_packets += 1
        self.dropped_bytes += int(size)
        self.drop_reasons[reason] = self.drop_reasons.get(reason, 0) + 1
