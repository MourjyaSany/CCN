"""Legitimate IoT application traffic models.

Four device classes are modelled, chosen because together they span the traffic
shapes a real IoT deployment produces:

======================  ========  ==========================================
Class                   Protocol  Shape
======================  ========  ==========================================
``mqtt_sensor``         TCP       Persistent session, small periodic publishes
``http_client``         TCP       Short-lived request/response transactions
``tcp_uploader``        TCP       Infrequent bulk transfers (firmware/logs)
``udp_streamer``        UDP       Constant-bitrate connectionless telemetry
======================  ========  ==========================================

Every application reconnects with exponential backoff when a connection fails.
That is what turns a SYN flood from an abstract packet count into an observable
**service outage**: legitimate devices stop being able to publish.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from ..simulation.engine import SimulationEngine, make_packet
from ..simulation.packet import Packet, Protocol, wire_size
from ..simulation.tcp import TcpConnection, TcpRegistry
from ..simulation.topology import NetNode
from ..utils.logging_utils import get_logger
from ..utils.seeding import fast_rng_for

_LOG = get_logger(__name__)

#: First ephemeral port assigned to application sockets (IANA dynamic range).
EPHEMERAL_PORT_BASE: int = 49152
#: Backoff schedule (seconds) applied after consecutive connection failures.
RECONNECT_BACKOFF_S: tuple[float, ...] = (1.0, 2.0, 4.0, 8.0, 15.0)


@dataclass(slots=True)
class AppStats:
    """Per-device application-level counters (the user-visible service KPIs)."""

    messages_attempted: int = 0
    messages_sent: int = 0
    responses_received: int = 0
    connections_opened: int = 0
    connections_failed: int = 0
    reconnects: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    latencies: list[float] = field(default_factory=list)
    #: Application-level completion times: HTTP request to full response, or
    #: bulk upload start to fully acknowledged transfer.
    completion_times: list[float] = field(default_factory=list)

    def success_ratio(self) -> float:
        """Fraction of attempted application messages that were transmitted."""
        return self.messages_sent / self.messages_attempted if self.messages_attempted else 0.0


def completion_summary(times: list[float]) -> dict[str, Any]:
    """Summarise application completion times (flow completion time, FCT)."""
    if not times:
        return {"completed": 0, "fct_mean_ms": "", "fct_p50_ms": "", "fct_p95_ms": ""}
    ordered = sorted(times)
    def pct(q: float) -> float:
        return ordered[min(len(ordered) - 1, int(round(q * (len(ordered) - 1))))] * 1000.0
    return {
        "completed": len(ordered),
        "fct_mean_ms": round(sum(ordered) / len(ordered) * 1000.0, 3),
        "fct_p50_ms": round(pct(0.50), 3),
        "fct_p95_ms": round(pct(0.95), 3),
    }


class Application:
    """Base class for a traffic-generating application on an endpoint node.

    Args:
        engine: The simulation engine.
        registry: Shared TCP connection registry.
        node: The endpoint node this application runs on.
        server: The cloud server node.
        params: Class-specific parameters from ``config/default.yaml``.
        seed: Master seed; each application derives an independent stream.
        stop_time_s: Simulated time after which no new activity is scheduled.
    """

    kind: str = "generic"

    def __init__(
        self,
        engine: SimulationEngine,
        registry: TcpRegistry,
        node: NetNode,
        server: NetNode,
        params: Mapping[str, Any],
        seed: int = 42,
        stop_time_s: float = 1e9,
    ) -> None:
        self.engine = engine
        self.registry = registry
        self.node = node
        self.server = server
        self.params = dict(params)
        self.rng = fast_rng_for(seed, "app", node.node_id, self.kind)
        self.stop_time_s = float(stop_time_s)
        self.stats = AppStats()
        self._port_cursor = EPHEMERAL_PORT_BASE + int(self.rng.integers(0, 4096))
        self._failures = 0
        #: Rate multiplier applied by a benign surge (flash crowd); 1 = normal.
        self.rate_boost = 1.0

    # -- helpers ------------------------------------------------------------ #
    def next_port(self) -> int:
        """Allocate the next ephemeral source port for this device."""
        self._port_cursor += 1
        if self._port_cursor > 65535:
            self._port_cursor = EPHEMERAL_PORT_BASE
        return self._port_cursor

    def jittered(self, base: float, jitter: float) -> float:
        """Return *base* perturbed by +/- ``jitter`` fraction, floored at 1 ms."""
        base = base / max(1e-6, self.rate_boost)
        if jitter <= 0:
            return max(0.001, base)
        factor = 1.0 + float(self.rng.uniform(-jitter, jitter))
        return max(0.001, base * factor)

    def size_from(self, key: str, default: tuple[int, int] = (64, 256)) -> int:
        """Draw a payload size from a ``[lo, hi]`` configuration range."""
        bounds = self.params.get(key, list(default))
        lo, hi = int(bounds[0]), int(bounds[1])
        return int(self.rng.integers(lo, hi + 1)) if hi > lo else lo

    def backoff(self) -> float:
        """Return the reconnect delay for the current failure streak."""
        idx = min(self._failures, len(RECONNECT_BACKOFF_S) - 1)
        return RECONNECT_BACKOFF_S[idx] * float(self.rng.uniform(0.8, 1.2))

    def active(self, t: float) -> bool:
        """True while the application should keep scheduling work."""
        return t < self.stop_time_s

    def start(self, t0: float) -> None:  # pragma: no cover - overridden
        """Schedule the application's first activity."""
        raise NotImplementedError

    def report(self) -> dict[str, Any]:
        """Return the application's service-level counters."""
        return {
            "node_id": self.node.node_id,
            "device_class": self.kind,
            "messages_attempted": self.stats.messages_attempted,
            "messages_sent": self.stats.messages_sent,
            "responses_received": self.stats.responses_received,
            "connections_opened": self.stats.connections_opened,
            "connections_failed": self.stats.connections_failed,
            "reconnects": self.stats.reconnects,
            "bytes_sent": self.stats.bytes_sent,
            "bytes_received": self.stats.bytes_received,
            "success_ratio": round(self.stats.success_ratio(), 5),
            **completion_summary(self.stats.completion_times),
        }

    # -- TCP plumbing shared by the connection-oriented classes ------------- #
    def _open_connection(self, dport: int, app_tag: str) -> TcpConnection:
        """Actively open a TCP connection to the cloud server."""
        conn = TcpConnection(
            engine=self.engine,
            conn_id=self.registry.allocate_id(),
            local=self.node,
            remote=self.server,
            sport=self.next_port(),
            dport=int(dport),
            role="client",
            app=app_tag,
        )
        self.registry.register(conn)
        conn.on_failed = self._on_conn_failed
        conn.connect()
        return conn

    def _on_conn_failed(self, conn: TcpConnection, t: float, reason: str) -> None:
        """Record a failed connection and schedule a backed-off retry."""
        self.registry.unregister(conn)
        self.registry.failed += 1
        self.stats.connections_failed += 1
        self._failures += 1
        self.engine.telemetry.window_at(t).tcp_connections_failed += 1
        if self.active(t):
            self.stats.reconnects += 1
            self.engine.schedule(self.backoff(), self._retry, None)

    def _retry(self, t: float, _: Any) -> None:  # pragma: no cover - overridden
        """Re-attempt whatever the failed connection was for."""
        raise NotImplementedError


class MqttSensorApp(Application):
    """Periodic MQTT publisher over a single long-lived TCP session."""

    kind = "mqtt_sensor"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.conn: TcpConnection | None = None
        self.interval = float(self.params.get("publish_interval_s", 2.0))
        self.jitter = float(self.params.get("interval_jitter", 0.3))
        self.dport = int(self.params.get("dst_port", 8883))

    def start(self, t0: float) -> None:
        """Connect after a randomised start offset (avoids a thundering herd)."""
        self.engine.schedule_at(t0 + float(self.rng.uniform(0.0, self.interval)),
                                self._connect, None)

    def _connect(self, t: float, _: Any) -> None:
        if not self.active(t):
            return
        conn = self._open_connection(self.dport, "mqtt")
        conn.on_established = self._on_established
        conn.on_closed = self._on_closed
        self.conn = conn

    def _on_established(self, conn: TcpConnection, t: float) -> None:
        self.stats.connections_opened += 1
        self._failures = 0
        self._publish(t, None)

    def _on_closed(self, conn: TcpConnection, t: float) -> None:
        self.registry.unregister(conn)
        if self.conn is conn:
            self.conn = None
        if self.active(t):
            self.engine.schedule(self.backoff(), self._connect, None)

    def _publish(self, t: float, _: Any) -> None:
        if not self.active(t):
            return
        conn = self.conn
        self.stats.messages_attempted += 1
        if conn is not None and not conn.closed:
            payload = self.size_from("payload_bytes", (48, 220))
            conn.send_bytes(payload, app_len=payload)
            self.stats.messages_sent += 1
            self.stats.bytes_sent += payload
        self.engine.schedule(self.jittered(self.interval, self.jitter), self._publish, None)

    def _retry(self, t: float, _: Any) -> None:
        self._connect(t, None)

    def reboot(self, t: float, down_s: Any) -> None:
        """Drop the session without a FIN (power loss) and reconnect later."""
        conn = self.conn
        if conn is not None and not conn.closed:
            conn.close(t, send_fin=False, notify=False)
            self.registry.unregister(conn)
        self.conn = None
        if self.active(t):
            self.engine.schedule(float(down_s), self._connect, None)


class HttpClientApp(Application):
    """Short-lived HTTP request/response transactions against the cloud API."""

    kind = "http_client"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.interval = float(self.params.get("request_interval_s", 6.0))
        self.jitter = float(self.params.get("interval_jitter", 0.5))
        self.dport = int(self.params.get("dst_port", 80))
        self._pending: dict[int, float] = {}

    def start(self, t0: float) -> None:
        """Issue the first request at a randomised offset."""
        self.engine.schedule_at(t0 + float(self.rng.uniform(0.0, self.interval)),
                                self._request, None)

    def _request(self, t: float, _: Any) -> None:
        if not self.active(t):
            return
        self.stats.messages_attempted += 1
        conn = self._open_connection(self.dport, "http")
        conn.on_established = self._on_established
        conn.on_data = self._on_response
        conn.on_closed = self._on_closed
        conn.context = {"expected": 0, "received": 0}
        self._pending[conn.conn_id] = t
        self.engine.schedule(self.jittered(self.interval, self.jitter), self._request, None)

    def _on_established(self, conn: TcpConnection, t: float) -> None:
        self.stats.connections_opened += 1
        self._failures = 0
        size = self.size_from("request_bytes", (180, 640))
        conn.send_bytes(size, app_len=size)
        self.stats.messages_sent += 1
        self.stats.bytes_sent += size

    def _on_response(self, conn: TcpConnection, packet: Packet, t: float) -> None:
        state = conn.context or {"expected": 0, "received": 0}
        if packet.app_len:
            state["expected"] = packet.app_len
        state["received"] += packet.payload
        conn.context = state
        if state["expected"] and state["received"] >= state["expected"]:
            self.stats.responses_received += 1
            self.stats.bytes_received += state["received"]
            started = self._pending.pop(conn.conn_id, None)
            if started is not None:
                self.stats.latencies.append(t - started)
                self.stats.completion_times.append(t - started)
            conn.close(t, send_fin=True, notify=True)

    def _on_closed(self, conn: TcpConnection, t: float) -> None:
        self.registry.unregister(conn)
        self._pending.pop(conn.conn_id, None)

    def _retry(self, t: float, _: Any) -> None:
        # The periodic schedule already covers the next attempt; no extra retry.
        return


class TcpUploaderApp(Application):
    """Infrequent bulk upload (firmware image / log batch) over TCP."""

    kind = "tcp_uploader"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.interval = float(self.params.get("upload_interval_s", 20.0))
        self.jitter = float(self.params.get("interval_jitter", 0.4))
        self.dport = int(self.params.get("dst_port", 443))

    def start(self, t0: float) -> None:
        """Start the first upload at a randomised offset."""
        self.engine.schedule_at(t0 + float(self.rng.uniform(0.0, self.interval)),
                                self._upload, None)

    def _upload(self, t: float, _: Any) -> None:
        if not self.active(t):
            return
        self.stats.messages_attempted += 1
        conn = self._open_connection(self.dport, "bulk")
        conn.context = {"started": t}
        conn.on_drained = self._on_drained
        conn.on_established = self._on_established
        conn.on_closed = self._on_closed
        self.engine.schedule(self.jittered(self.interval, self.jitter), self._upload, None)

    def upload_now(self, t: float, size: Any) -> None:
        """Start one out-of-schedule transfer of *size* bytes (OTA / log flush)."""
        if not self.active(t):
            return
        self.stats.messages_attempted += 1
        conn = self._open_connection(self.dport, "bulk")
        conn.context = {"started": t, "size": int(size)}
        conn.on_drained = self._on_drained
        conn.on_established = self._on_established
        conn.on_closed = self._on_closed

    def _on_established(self, conn: TcpConnection, t: float) -> None:
        self.stats.connections_opened += 1
        self._failures = 0
        size = int((conn.context or {}).get("size") or
                   self.size_from("upload_bytes", (20000, 120000)))
        conn.send_bytes(size, app_len=size)
        self.stats.messages_sent += 1
        self.stats.bytes_sent += size
        # Close once the transfer drains; poll on the RTO timescale.
        self.engine.schedule(0.5, self._check_done, conn)

    def _on_drained(self, conn: TcpConnection, t: float) -> None:
        """Record the upload's completion time at its final acknowledgement."""
        state = conn.context or {}
        started = state.pop("started", None)
        if started is not None:
            self.stats.completion_times.append(t - started)

    def _check_done(self, t: float, conn: Any) -> None:
        connection: TcpConnection = conn
        if connection.closed:
            return
        if connection.send_queue == 0 and not connection.in_flight:
            connection.close(t, send_fin=True, notify=True)
            return
        if self.active(t):
            self.engine.schedule(0.5, self._check_done, connection)

    def _on_closed(self, conn: TcpConnection, t: float) -> None:
        self.registry.unregister(conn)

    def _retry(self, t: float, _: Any) -> None:
        return


class UdpStreamerApp(Application):
    """Constant-bitrate connectionless telemetry (CoAP/RTP-like)."""

    kind = "udp_streamer"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.interval = float(self.params.get("packet_interval_s", 0.08))
        self.jitter = float(self.params.get("interval_jitter", 0.2))
        self.dport = int(self.params.get("dst_port", 5683))
        self.sport = self.next_port()

    def start(self, t0: float) -> None:
        """Begin streaming at a randomised phase offset."""
        self.engine.schedule_at(t0 + float(self.rng.uniform(0.0, self.interval)),
                                self._emit, None)

    def _emit(self, t: float, _: Any) -> None:
        if not self.active(t):
            return
        payload = self.size_from("payload_bytes", (200, 400))
        packet = make_packet(
            self.engine,
            src=self.node,
            dst=self.server,
            sport=self.sport,
            dport=self.dport,
            protocol=Protocol.UDP,
            payload=payload,
            size=wire_size(payload, Protocol.UDP),
            app="coap",
        )
        self.stats.messages_attempted += 1
        if self.engine.send(packet):
            self.stats.messages_sent += 1
            self.stats.bytes_sent += payload
        self.engine.schedule(self.jittered(self.interval, self.jitter), self._emit, None)

    def _retry(self, t: float, _: Any) -> None:
        return


#: Registry mapping a device class name to its application implementation.
APPLICATION_CLASSES: dict[str, type[Application]] = {
    MqttSensorApp.kind: MqttSensorApp,
    HttpClientApp.kind: HttpClientApp,
    TcpUploaderApp.kind: TcpUploaderApp,
    UdpStreamerApp.kind: UdpStreamerApp,
}


def build_application(
    device_class: str,
    engine: SimulationEngine,
    registry: TcpRegistry,
    node: NetNode,
    server: NetNode,
    traffic_config: Mapping[str, Any],
    seed: int,
    stop_time_s: float,
) -> Application:
    """Instantiate the application matching *device_class*.

    Args:
        device_class: One of the keys of :data:`APPLICATION_CLASSES`.
        engine: The simulation engine.
        registry: Shared TCP connection registry.
        node: The endpoint the application runs on.
        server: The cloud server node.
        traffic_config: The ``traffic`` configuration section.
        seed: Master seed.
        stop_time_s: Time after which the application stops scheduling work.

    Returns:
        A constructed, not-yet-started :class:`Application`.

    Raises:
        KeyError: If *device_class* is unknown.
    """
    try:
        cls = APPLICATION_CLASSES[device_class]
    except KeyError as exc:
        known = ", ".join(sorted(APPLICATION_CLASSES))
        raise KeyError(f"Unknown device class {device_class!r}. Known: {known}") from exc

    return cls(
        engine,
        registry,
        node,
        server,
        traffic_config.get(device_class, {}) or {},
        seed=seed,
        stop_time_s=stop_time_s,
    )
