"""A compact but genuine TCP implementation for the simulation engine.

What is modelled
----------------
* **Three-way handshake** - ``SYN`` / ``SYN+ACK`` / ``ACK``, with SYN
  retransmission and a bounded retry count. A connection whose SYNs are never
  answered *fails*, which is precisely the collateral damage a SYN flood
  inflicts on legitimate IoT devices.
* **Byte-stream sequencing** - cumulative acknowledgements, ``rcv_next``
  tracking and duplicate ACKs on a sequence gap.
* **Congestion control** - Reno-style slow start (``cwnd += MSS`` per ACK) up to
  ``ssthresh``, then congestion avoidance (``cwnd += MSS^2/cwnd``), with a
  timeout collapsing ``cwnd`` to one segment and halving ``ssthresh``.
* **Retransmission timeout** - Jacobson/Karels RTT estimation
  (``SRTT``/``RTTVAR``) with exponential backoff, capped.

What is deliberately *not* modelled
-----------------------------------
Fast retransmit/fast recovery, SACK, window scaling, Nagle, delayed ACKs and
receiver-window flow control. These are documented in ``docs/methodology.md``
as simplifications; none of them changes the qualitative congestion behaviour
that the DDoS experiments depend on.
"""

from __future__ import annotations

from enum import IntEnum
from typing import Any, Callable

from ..utils.logging_utils import get_logger
from .engine import SimulationEngine, make_packet
from .packet import MSS, Packet, Protocol, TCPFlag, wire_size
from .topology import NetNode

_LOG = get_logger(__name__)

#: Initial retransmission timeout before any RTT sample (RFC 6298 recommends 1 s).
INITIAL_RTO_S: float = 1.0
MIN_RTO_S: float = 0.20
MAX_RTO_S: float = 8.0
#: Number of SYN attempts before the connection is declared failed.
SYN_RETRIES: int = 4
#: Number of data retransmissions before the connection is abandoned.
DATA_RETRIES: int = 6
#: Initial congestion window, in segments (RFC 3390 style).
INIT_CWND_SEGMENTS: float = 2.0
INIT_SSTHRESH_BYTES: float = 32.0 * MSS


class TcpState(IntEnum):
    """Connection states used by this implementation."""

    CLOSED = 0
    SYN_SENT = 1
    SYN_RCVD = 2
    ESTABLISHED = 3
    FIN_SENT = 4
    FAILED = 5


class TcpConnection:
    """One end of a TCP connection.

    The same class implements both roles; ``role`` selects the handshake branch.
    Both ends run the identical sender (congestion control + RTO) and receiver
    (cumulative ACK) machinery, so a server streaming an HTTP response is
    congestion-controlled exactly like a client uploading a firmware blob.

    Args:
        engine: The simulation engine.
        conn_id: Globally unique connection identifier (allocated by the client
            and echoed by the server so both ends share one key).
        local: Local node.
        remote: Remote node.
        sport: Local port.
        dport: Remote port.
        role: ``"client"`` or ``"server"``.
        app: Application tag propagated onto every packet.
        is_attack: Ground-truth attack label for every packet of this connection.
        attack_type: Attack family label.
    """

    __slots__ = (
        "engine", "conn_id", "local", "remote", "sport", "dport", "role", "app",
        "is_attack", "attack_type", "state", "cwnd", "ssthresh", "snd_una",
        "snd_nxt", "send_queue", "in_flight", "rcv_next", "srtt", "rttvar",
        "rto", "_rto_gen", "_rto_armed", "syn_attempts", "data_retries",
        "on_established", "on_failed", "on_data", "on_closed", "bytes_sent",
        "bytes_acked", "bytes_received", "opened_at", "peer_ip", "closed",
        "_pending_app_len", "context", "on_drained",
    )

    def __init__(
        self,
        engine: SimulationEngine,
        conn_id: int,
        local: NetNode,
        remote: NetNode,
        sport: int,
        dport: int,
        role: str = "client",
        app: str = "tcp",
        is_attack: bool = False,
        attack_type: str = "",
    ) -> None:
        self.engine = engine
        self.conn_id = conn_id
        self.local = local
        self.remote = remote
        self.sport = sport
        self.dport = dport
        self.role = role
        self.app = app
        self.is_attack = is_attack
        self.attack_type = attack_type

        self.state = TcpState.CLOSED
        self.cwnd: float = INIT_CWND_SEGMENTS * MSS
        self.ssthresh: float = INIT_SSTHRESH_BYTES
        self.snd_una: int = 0
        self.snd_nxt: int = 0
        self.send_queue: int = 0
        self.in_flight: dict[int, tuple[int, float, bool]] = {}
        self.rcv_next: int = 0

        self.srtt: float = 0.0
        self.rttvar: float = 0.0
        self.rto: float = INITIAL_RTO_S
        self._rto_gen: int = 0
        self._rto_armed: bool = False

        self.syn_attempts: int = 0
        self.data_retries: int = 0

        self.on_established: Callable[[TcpConnection, float], None] | None = None
        self.on_failed: Callable[[TcpConnection, float, str], None] | None = None
        self.on_data: Callable[[TcpConnection, Packet, float], None] | None = None
        self.on_closed: Callable[[TcpConnection, float], None] | None = None
        #: Fired once each time every queued byte has been acknowledged.
        self.on_drained: Callable[[TcpConnection, float], None] | None = None

        self.bytes_sent: int = 0
        self.bytes_acked: int = 0
        self.bytes_received: int = 0
        self.opened_at: float = engine.now
        self.peer_ip: str = remote.ip
        self.closed: bool = False
        self._pending_app_len: int = 0
        #: Free-form slot for the owning application's per-connection state.
        self.context: Any = None

    # ------------------------------------------------------------------ #
    # helpers
    # ------------------------------------------------------------------ #
    @property
    def unacked_bytes(self) -> int:
        """Bytes transmitted but not yet acknowledged."""
        return self.snd_nxt - self.snd_una

    def _emit(
        self,
        flags: int,
        payload: int,
        seq: int = 0,
        ack: int = 0,
        retransmit: bool = False,
        src_ip: str | None = None,
        app_len: int = 0,
    ) -> bool:
        """Build and inject a TCP segment. Returns False if the packet cap hit."""
        packet = make_packet(
            self.engine,
            src=self.local,
            dst=self.remote,
            sport=self.sport,
            dport=self.dport,
            protocol=Protocol.TCP,
            payload=payload,
            size=wire_size(payload, Protocol.TCP),
            flags=flags,
            app=self.app,
            is_attack=self.is_attack,
            attack_type=self.attack_type,
            src_ip=src_ip,
            conn_id=self.conn_id,
            seq=seq,
            ack=ack,
            retransmit=retransmit,
            app_len=app_len,
        )
        return self.engine.send(packet)

    # ------------------------------------------------------------------ #
    # RTO management (generation-counter based cancellation)
    # ------------------------------------------------------------------ #
    def _arm_rto(self) -> None:
        """(Re)arm the retransmission timer for the oldest unacked segment."""
        self._rto_gen += 1
        self._rto_armed = True
        self.engine.schedule(self.rto, self._on_rto, self._rto_gen)

    def _disarm_rto(self) -> None:
        """Cancel any pending retransmission timer."""
        self._rto_gen += 1
        self._rto_armed = False

    def _update_rtt(self, sample: float) -> None:
        """Fold an RTT sample into the Jacobson/Karels estimator."""
        if self.srtt <= 0.0:
            self.srtt = sample
            self.rttvar = sample / 2.0
        else:
            self.rttvar = 0.75 * self.rttvar + 0.25 * abs(self.srtt - sample)
            self.srtt = 0.875 * self.srtt + 0.125 * sample
        self.rto = min(MAX_RTO_S, max(MIN_RTO_S, self.srtt + 4.0 * self.rttvar))

    # ------------------------------------------------------------------ #
    # active open
    # ------------------------------------------------------------------ #
    def connect(self) -> None:
        """Perform an active open: transmit the initial SYN."""
        self.state = TcpState.SYN_SENT
        self.syn_attempts = 1
        self._emit(TCPFlag.SYN, payload=0, seq=0)
        self._arm_rto()

    def listen_accept(self, t: float) -> None:
        """Mark a passively opened connection as established (server side)."""
        self.state = TcpState.ESTABLISHED
        if self.on_established is not None:
            self.on_established(self, t)

    # ------------------------------------------------------------------ #
    # data path
    # ------------------------------------------------------------------ #
    def send_bytes(self, nbytes: int, app_len: int | None = None) -> None:
        """Queue an application message of *nbytes* for transmission.

        Args:
            nbytes: Message size in bytes.
            app_len: Total application-message length advertised on the first
                segment (defaults to *nbytes*). This is the model's equivalent
                of an HTTP ``Content-Length`` header and lets the receiving
                application detect message completion without a parser.
        """
        if self.closed:
            return
        nbytes = max(0, int(nbytes))
        if nbytes == 0:
            return
        self.send_queue += nbytes
        self._pending_app_len = int(nbytes if app_len is None else app_len)
        if self.state is TcpState.ESTABLISHED:
            self._pump(self.engine.now)

    def _pump(self, t: float) -> None:
        """Transmit as much queued data as the congestion window allows."""
        while self.send_queue > 0 and self.unacked_bytes + MSS <= max(MSS, int(self.cwnd)):
            segment = min(MSS, self.send_queue)
            seq = self.snd_nxt
            advertised, self._pending_app_len = self._pending_app_len, 0
            if not self._emit(TCPFlag.PSH | TCPFlag.ACK, payload=segment, seq=seq,
                              ack=self.rcv_next, app_len=advertised):
                return
            self.in_flight[seq] = (segment, t, False)
            self.snd_nxt += segment
            self.send_queue -= segment
            self.bytes_sent += segment
            if not self._rto_armed:
                self._arm_rto()

    def _on_rto(self, t: float, generation: Any) -> None:
        """Retransmission timeout: collapse cwnd and resend the oldest segment."""
        if generation != self._rto_gen or self.closed:
            return
        self._rto_armed = False

        if self.state is TcpState.SYN_SENT:
            if self.syn_attempts >= SYN_RETRIES:
                self.state = TcpState.FAILED
                self.closed = True
                if self.on_failed is not None:
                    self.on_failed(self, t, "syn_timeout")
                return
            self.syn_attempts += 1
            self.rto = min(MAX_RTO_S, self.rto * 2.0)
            self._emit(TCPFlag.SYN, payload=0, seq=0, retransmit=True)
            self._arm_rto()
            return

        if not self.in_flight:
            return

        self.data_retries += 1
        if self.data_retries > DATA_RETRIES:
            self.state = TcpState.FAILED
            self.closed = True
            if self.on_failed is not None:
                self.on_failed(self, t, "data_timeout")
            return

        # Reno timeout response.
        self.ssthresh = max(2.0 * MSS, self.unacked_bytes / 2.0)
        self.cwnd = float(MSS)
        self.rto = min(MAX_RTO_S, self.rto * 2.0)

        oldest = min(self.in_flight)
        size, _sent_at, _ = self.in_flight[oldest]
        self.in_flight[oldest] = (size, t, True)  # mark: Karn's algorithm
        self._emit(TCPFlag.PSH | TCPFlag.ACK, payload=size, seq=oldest,
                   ack=self.rcv_next, retransmit=True)
        self._arm_rto()

    # ------------------------------------------------------------------ #
    # inbound segment handling
    # ------------------------------------------------------------------ #
    def handle(self, packet: Packet, t: float) -> None:
        """Process an inbound segment belonging to this connection."""
        if self.closed:
            return
        flags = packet.flags
        syn = bool(flags & TCPFlag.SYN)
        ack = bool(flags & TCPFlag.ACK)
        fin = bool(flags & TCPFlag.FIN)

        if syn and ack and self.state is TcpState.SYN_SENT:
            self._disarm_rto()
            self._update_rtt(max(1e-6, t - self.opened_at))
            self.state = TcpState.ESTABLISHED
            self._emit(TCPFlag.ACK, payload=0, seq=self.snd_nxt, ack=self.rcv_next)
            if self.on_established is not None:
                self.on_established(self, t)
            self._pump(t)
            return

        if ack and self.in_flight:
            self._process_ack(packet.ack, t)

        if packet.payload > 0:
            self._receive_data(packet, t)

        if fin:
            self._handle_fin(t)

    def _process_ack(self, ack_number: int, t: float) -> None:
        """Apply a cumulative acknowledgement and grow the congestion window."""
        newly_acked = 0
        for seq in sorted(k for k in self.in_flight if k < ack_number):
            size, sent_at, was_retransmitted = self.in_flight.pop(seq)
            newly_acked += size
            if not was_retransmitted:  # Karn's algorithm
                self._update_rtt(max(1e-6, t - sent_at))

        if newly_acked <= 0:
            return

        self.snd_una = max(self.snd_una, ack_number)
        self.bytes_acked += newly_acked
        self.data_retries = 0

        if self.cwnd < self.ssthresh:
            self.cwnd += newly_acked                      # slow start
        else:
            self.cwnd += (float(MSS) * MSS) / max(1.0, self.cwnd)  # congestion avoidance

        if self.in_flight:
            self._arm_rto()
        else:
            self._disarm_rto()
        self._pump(t)
        if not self.in_flight and self.send_queue == 0 and self.on_drained is not None:
            self.on_drained(self, t)

    def _receive_data(self, packet: Packet, t: float) -> None:
        """Deliver in-order bytes to the application and acknowledge."""
        if packet.seq == self.rcv_next:
            self.rcv_next += packet.payload
            self.bytes_received += packet.payload
            if self.on_data is not None:
                self.on_data(self, packet, t)
        # Always acknowledge: in-order -> cumulative ACK, gap -> duplicate ACK.
        self._emit(TCPFlag.ACK, payload=0, seq=self.snd_nxt, ack=self.rcv_next)

    def _handle_fin(self, t: float) -> None:
        """Passive close."""
        if self.closed:
            return
        self._emit(TCPFlag.FIN | TCPFlag.ACK, payload=0, seq=self.snd_nxt, ack=self.rcv_next)
        self.close(t, notify=True)

    def close(self, t: float, send_fin: bool = False, notify: bool = True) -> None:
        """Close the connection, optionally emitting a FIN first."""
        if self.closed:
            return
        if send_fin and self.state is TcpState.ESTABLISHED:
            self._emit(TCPFlag.FIN | TCPFlag.ACK, payload=0, seq=self.snd_nxt,
                       ack=self.rcv_next)
        self.closed = True
        self.state = TcpState.CLOSED
        self._disarm_rto()
        if notify and self.on_closed is not None:
            self.on_closed(self, t)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<TCP#{self.conn_id} {self.role} {self.local.node_id}:{self.sport}"
            f"->{self.remote.node_id}:{self.dport} {self.state.name} "
            f"cwnd={self.cwnd / MSS:.1f}MSS>"
        )


class TcpRegistry:
    """Global registry mapping connection ids to their two endpoints.

    A connection id is allocated by the active opener and echoed by the server,
    so both endpoints share a single key. Demultiplexing a segment is therefore
    an O(1) dictionary lookup on ``(conn_id, receiving_node)``.
    """

    def __init__(self) -> None:
        self._by_endpoint: dict[tuple[int, str], TcpConnection] = {}
        self._next_id: int = 1
        self.opened: int = 0
        self.failed: int = 0
        self.closed: int = 0

    def allocate_id(self) -> int:
        """Return a fresh globally unique connection id."""
        conn_id = self._next_id
        self._next_id += 1
        return conn_id

    def register(self, conn: TcpConnection) -> TcpConnection:
        """Index a connection under ``(conn_id, local_node)``."""
        self._by_endpoint[(conn.conn_id, conn.local.node_id)] = conn
        return conn

    def lookup(self, conn_id: int, node_id: str) -> TcpConnection | None:
        """Return the connection endpoint living at *node_id*, if any."""
        return self._by_endpoint.get((conn_id, node_id))

    def unregister(self, conn: TcpConnection) -> None:
        """Remove a connection endpoint from the registry."""
        self._by_endpoint.pop((conn.conn_id, conn.local.node_id), None)

    def active_count(self) -> int:
        """Number of currently registered endpoints."""
        return len(self._by_endpoint)


class TcpDispatcher:
    """Per-node demultiplexer that hands inbound segments to their connection.

    Every endpoint (IoT device or compromised node) needs one of these: without
    it a SYN+ACK arriving from the server would be delivered to a node with no
    protocol handler and the handshake could never complete.

    Args:
        engine: The simulation engine (the dispatcher registers itself).
        registry: Shared connection registry.
        node: The node whose inbound segments are dispatched.
    """

    __slots__ = ("engine", "registry", "node", "orphan_segments", "udp_received")

    def __init__(self, engine: SimulationEngine, registry: TcpRegistry, node: NetNode) -> None:
        self.engine = engine
        self.registry = registry
        self.node = node
        self.orphan_segments = 0
        self.udp_received = 0
        engine.register_receiver(node.node_id, self.receive)

    def receive(self, packet: Packet, t: float) -> None:
        """Route a delivered packet to its owning TCP connection."""
        if packet.protocol != Protocol.TCP:
            self.udp_received += 1
            return
        conn = self.registry.lookup(packet.conn_id, self.node.node_id)
        if conn is None:
            # Late segment for a connection this endpoint already tore down.
            self.orphan_segments += 1
            return
        conn.handle(packet, t)
