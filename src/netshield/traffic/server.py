"""Cloud application server: TCP listener, SYN backlog and HTTP responder.

The server is the DDoS *target*. It models three resources that a real server
exhausts under attack, in increasing order of subtlety:

1. **Link and forwarding capacity** - handled by the engine's channels and
   processing servers (volumetric floods).
2. **The SYN backlog** - a finite half-open connection table with a timeout.
   When it fills, new connection requests are silently ignored, which is exactly
   how a SYN flood denies service to legitimate IoT devices while consuming
   almost no bandwidth.
3. **Application worker slots** - a bounded pool of concurrent request handlers
   with a service time, which is what an HTTP flood exhausts.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..simulation.engine import SimulationEngine, make_packet
from ..simulation.packet import Packet, Protocol, TCPFlag, wire_size
from ..simulation.tcp import TcpConnection, TcpRegistry, TcpState
from ..simulation.topology import NetNode, Topology
from ..utils.logging_utils import get_logger
from ..utils.seeding import rng_for

_LOG = get_logger(__name__)


@dataclass(slots=True)
class ServerStats:
    """Application-level counters for the cloud server."""

    syn_received: int = 0
    syn_accepted: int = 0
    syn_rejected: int = 0
    handshakes_completed: int = 0
    half_open_peak: int = 0
    half_open_expired: int = 0
    requests_served: int = 0
    requests_rejected: int = 0
    #: Handshakes refused because the established-connection table was full.
    #: This is the counter a slowloris attack drives.
    connections_refused: int = 0
    established_peak: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    udp_datagrams: int = 0
    orphan_segments: int = 0
    unroutable_synacks: int = 0


class CloudServer:
    """Passive endpoint terminating MQTT/HTTP/CoAP traffic from the fleet.

    Args:
        engine: The simulation engine.
        topology: The topology (used to resolve spoofed addresses).
        registry: Shared TCP connection registry.
        node: The cloud :class:`~netshield.simulation.topology.NetNode`.
        backlog: Half-open connection table size.
        syn_timeout_s: Lifetime of a half-open entry before it is reclaimed.
        worker_slots: Concurrent application request handlers.
        max_connections: Ceiling on simultaneously established connections.
            A real server cannot hold unbounded sockets open; this is the
            resource a slowloris attack exhausts, and it is deliberately
            separate from ``backlog`` (half-open) so the two attacks are
            distinguishable in the results.
        service_time_s: Mean service time of one application request.
        seed: Master seed for the server's response-size RNG.
    """

    def __init__(
        self,
        engine: SimulationEngine,
        topology: Topology,
        registry: TcpRegistry,
        node: NetNode,
        backlog: int = 256,
        syn_timeout_s: float = 8.0,
        worker_slots: int = 64,
        max_connections: int = 512,
        service_time_s: float = 0.004,
        seed: int = 42,
    ) -> None:
        self.engine = engine
        self.topology = topology
        self.registry = registry
        self.node = node
        self.backlog = int(backlog)
        self.syn_timeout_s = float(syn_timeout_s)
        self.worker_slots = int(worker_slots)
        self.max_connections = int(max_connections)
        self.service_time_s = float(service_time_s)
        self.rng = rng_for(seed, "cloud_server")

        self.stats = ServerStats()
        #: conn_id -> (expiry time, source ip) for half-open connections.
        self.half_open: dict[int, tuple[float, str]] = {}
        self.busy_workers: int = 0
        #: Connection ids currently established against this server.
        self.established: set[int] = set()
        #: Response byte range for HTTP-like services, set by the run builder.
        self.response_bytes: tuple[int, int] = (500, 6000)

        engine.register_receiver(node.node_id, self.receive)

    # ------------------------------------------------------------------ #
    # ingress
    # ------------------------------------------------------------------ #
    def receive(self, packet: Packet, t: float) -> None:
        """Handle a packet delivered to the cloud node."""
        if packet.protocol == Protocol.UDP:
            self.stats.udp_datagrams += 1
            self.stats.bytes_in += packet.size
            return

        self.stats.bytes_in += packet.size
        conn = self.registry.lookup(packet.conn_id, self.node.node_id)
        if conn is not None:
            conn.handle(packet, t)
            return

        if packet.is_syn_only():
            self._handle_syn(packet, t)
            return

        if packet.flags & TCPFlag.ACK and packet.conn_id in self.half_open:
            self._complete_handshake(packet, t)
            return

        # A segment for a connection we do not know about (e.g. after the
        # half-open entry expired). A real stack would answer with RST.
        self.stats.orphan_segments += 1

    # ------------------------------------------------------------------ #
    # handshake
    # ------------------------------------------------------------------ #
    def _handle_syn(self, packet: Packet, t: float) -> None:
        """Process a connection request against the finite SYN backlog."""
        self.stats.syn_received += 1

        if len(self.half_open) >= self.backlog:
            # Backlog exhausted: the SYN is discarded at the application layer.
            # No SYN+ACK is emitted, so the client will time out and fail.
            self.stats.syn_rejected += 1
            self.engine.telemetry.window_at(t).syn_rejected += 1
            return

        self.stats.syn_accepted += 1
        self.half_open[packet.conn_id] = (t + self.syn_timeout_s, packet.src_ip)
        peak = len(self.half_open)
        if peak > self.stats.half_open_peak:
            self.stats.half_open_peak = peak
        metrics = self.engine.telemetry.window_at(t)
        metrics.syn_backlog_peak = max(metrics.syn_backlog_peak, peak)

        self.engine.schedule(self.syn_timeout_s, self._expire_half_open, packet.conn_id)
        self._send_syn_ack(packet, t)

    def _send_syn_ack(self, syn: Packet, t: float) -> None:
        """Emit the SYN+ACK, honouring the (possibly spoofed) source address.

        A spoofed source address belongs to no node in the topology, so the
        SYN+ACK is routed towards the gateway - consuming real downstream
        bandwidth - and is then accounted as unroutable. This reproduces the
        *backscatter* cost that a SYN flood imposes on the defender's own link.
        """
        target_node_id = self.topology.ip_to_node.get(syn.src_ip)
        spoofed = target_node_id is None
        dst_node = self.topology.nodes[target_node_id or self.topology.gateway_id]

        packet = make_packet(
            self.engine,
            src=self.node,
            dst=dst_node,
            sport=syn.dport,
            dport=syn.sport,
            protocol=Protocol.TCP,
            payload=0,
            size=wire_size(0, Protocol.TCP),
            flags=int(TCPFlag.SYN | TCPFlag.ACK),
            app="syn_ack_backscatter" if spoofed else f"srv:{syn.app}",
            is_attack=syn.is_attack,
            attack_type=syn.attack_type,
            conn_id=syn.conn_id,
        )
        packet.dst_ip = syn.src_ip
        self.stats.bytes_out += packet.size
        if spoofed:
            self.stats.unroutable_synacks += 1
        self.engine.send(packet)

    def _complete_handshake(self, packet: Packet, t: float) -> None:
        """Promote a half-open entry to an established server connection."""
        expiry_entry = self.half_open.pop(packet.conn_id, None)
        if expiry_entry is None:
            return

        client_node_id = self.topology.ip_to_node.get(packet.src_ip)
        if client_node_id is None:  # spoofed ACK - impossible for a real client
            return

        # Connection-table ceiling. Refusing here rather than at SYN time is
        # deliberate: the slot is only consumed once the handshake actually
        # completes, which is why a slowloris (which completes handshakes and
        # then stalls) exhausts it while a SYN flood (which never does) does
        # not.
        if len(self.established) >= self.max_connections:
            self.stats.connections_refused += 1
            return

        conn = TcpConnection(
            engine=self.engine,
            conn_id=packet.conn_id,
            local=self.node,
            remote=self.topology.nodes[client_node_id],
            sport=packet.dport,
            dport=packet.sport,
            role="server",
            app=f"srv:{packet.app}",
            is_attack=packet.is_attack,
            attack_type=packet.attack_type,
        )
        conn.state = TcpState.ESTABLISHED
        conn.on_data = self._on_server_data
        conn.on_closed = self._on_server_closed
        conn.context = {"service_port": packet.dport, "received": 0, "expected": 0}
        self.registry.register(conn)
        self.registry.opened += 1
        self.established.add(int(packet.conn_id))
        self.stats.established_peak = max(
            self.stats.established_peak, len(self.established)
        )
        self.stats.handshakes_completed += 1
        self.engine.telemetry.window_at(t).tcp_connections_opened += 1

    def _expire_half_open(self, t: float, conn_id: Any) -> None:
        """Reclaim a half-open slot whose handshake never completed."""
        entry = self.half_open.pop(int(conn_id), None)
        if entry is not None:
            self.stats.half_open_expired += 1

    # ------------------------------------------------------------------ #
    # application layer
    # ------------------------------------------------------------------ #
    def _on_server_data(self, conn: TcpConnection, packet: Packet, t: float) -> None:
        """Accumulate an inbound application message and respond when complete."""
        state = conn.context
        if state is None:  # pragma: no cover - defensive
            return
        if packet.app_len:
            state["expected"] = packet.app_len
        state["received"] += packet.payload

        expected = state["expected"]
        if expected <= 0 or state["received"] < expected:
            return
        state["received"] = 0
        state["expected"] = 0

        port = int(state["service_port"])
        if port in (80, 443):
            self._serve_http(conn, t)
        else:
            # MQTT publish / bulk upload: acknowledged at the TCP layer only.
            self.stats.requests_served += 1

    def _serve_http(self, conn: TcpConnection, t: float) -> None:
        """Answer an HTTP-like request subject to the worker pool."""
        if self.busy_workers >= self.worker_slots:
            self.stats.requests_rejected += 1
            return
        self.busy_workers += 1
        self.engine.schedule(self.service_time_s, self._release_worker, conn)

    def _release_worker(self, t: float, conn: Any) -> None:
        """Worker finished: emit the response body."""
        self.busy_workers = max(0, self.busy_workers - 1)
        connection: TcpConnection = conn
        if connection.closed:
            return
        lo, hi = self.response_bytes
        size = int(self.rng.integers(int(lo), int(hi) + 1))
        self.stats.requests_served += 1
        self.stats.bytes_out += size
        connection.send_bytes(size, app_len=size)

    def _on_server_closed(self, conn: TcpConnection, t: float) -> None:
        """Release server-side connection state and free its table slot."""
        self.established.discard(int(conn.conn_id))
        self.registry.unregister(conn)
        self.registry.closed += 1

    # ------------------------------------------------------------------ #
    def report(self) -> dict[str, Any]:
        """Return a JSON-serialisable summary of server-side counters."""
        return {
            "connections_refused": self.stats.connections_refused,
            "established_peak": self.stats.established_peak,
            "max_connections": self.max_connections,
            "syn_received": self.stats.syn_received,
            "syn_accepted": self.stats.syn_accepted,
            "syn_rejected": self.stats.syn_rejected,
            "handshakes_completed": self.stats.handshakes_completed,
            "half_open_peak": self.stats.half_open_peak,
            "half_open_expired": self.stats.half_open_expired,
            "backlog_capacity": self.backlog,
            "requests_served": self.stats.requests_served,
            "requests_rejected": self.stats.requests_rejected,
            "udp_datagrams": self.stats.udp_datagrams,
            "orphan_segments": self.stats.orphan_segments,
            "unroutable_synacks": self.stats.unroutable_synacks,
            "bytes_in": self.stats.bytes_in,
            "bytes_out": self.stats.bytes_out,
        }


class GatewaySink:
    """Terminates packets that arrive at the gateway with no valid route.

    Backscatter SYN+ACKs addressed to spoofed sources land here. They are
    counted (never re-forwarded) so the bandwidth they consumed on the
    cloud-to-gateway link is accounted for without inventing a fake destination.
    """

    def __init__(self, engine: SimulationEngine, node: NetNode) -> None:
        self.engine = engine
        self.node = node
        self.unroutable: int = 0
        self.unroutable_bytes: int = 0
        engine.register_receiver(node.node_id, self.receive)

    def receive(self, packet: Packet, t: float) -> None:
        """Absorb an unroutable packet delivered to the gateway."""
        if packet.dst_ip != self.node.ip:
            self.unroutable += 1
            self.unroutable_bytes += packet.size
            self.engine.telemetry.window_at(t).unroutable_packets += 1
