"""Discrete-event packet-level network simulation engine.

This is the Python simulation engine used when NS-3 is not available (see
:mod:`netshield.simulation.ns3_bridge` for detection and the NS-3 path). It is a
genuine discrete-event simulator, not a statistical traffic generator:

* A global event queue advances simulated time in strictly increasing order.
* Every packet is **store-and-forward** switched hop by hop.
* Each directed channel is a single-server queue with finite drop-tail buffer,
  a serialisation delay of ``size * 8 / bandwidth`` and a propagation delay.
* Each router/gateway/server additionally has a **processing server** limited to
  ``forwarding_pps``, giving a second, packet-rate-bound bottleneck. This is what
  makes a SYN flood (low bandwidth, very high packet rate) hurt.
* End-to-end latency, packet loss and throughput are therefore *emergent*: they
  are computed from timestamps and queue behaviour, never configured.

The engine also owns the in-band enforcement point used by the mitigation
engine, so that a mitigation decision taken at time *t* physically changes what
happens to packets after *t* inside the same run.
"""

from __future__ import annotations

import heapq
import itertools
from dataclasses import dataclass
from typing import Any, Callable, Protocol as TypingProtocol

from ..utils.logging_utils import get_logger
from ..utils.seeding import fast_rng_for
from .packet import Packet, Protocol
from .telemetry import TelemetryCollector
from .topology import Channel, NetNode, NodeKind, Topology

_LOG = get_logger(__name__)

#: Interval (simulated seconds) between gateway-uplink queue-occupancy samples.
QUEUE_SAMPLE_INTERVAL_S: float = 0.2

EventCallback = Callable[[float, Any], None]


class PacketFilter(TypingProtocol):
    """Interface implemented by the mitigation enforcer.

    The engine calls :meth:`inspect` for every packet arriving at the configured
    enforcement point. Returning ``None`` forwards the packet; returning a string
    drops it and uses that string as the drop reason.
    """

    def inspect(self, packet: Packet, t: float) -> str | None:  # pragma: no cover
        """Return a drop reason, or ``None`` to allow the packet through."""
        ...


class WindowController(TypingProtocol):
    """Interface implemented by in-loop detection/mitigation controllers."""

    def on_window(self, engine: "SimulationEngine", window_index: int, t: float) -> None:
        """Called once, in simulated time, after *window_index* completes."""
        ...


@dataclass(slots=True)
class EngineStats:
    """Counters describing the simulation run itself."""

    events_processed: int = 0
    packets_generated: int = 0
    packets_delivered: int = 0
    packets_dropped: int = 0
    packets_forwarded: int = 0
    max_queue_seen: int = 0
    wall_seconds: float = 0.0
    truncated_by_cap: bool = False
    truncated_by_time: bool = False
    completed_fraction: float = 1.0


class SimulationEngine:
    """Event-driven simulator for the IoT-edge-cloud topology.

    Args:
        topology: The wired :class:`~netshield.simulation.topology.Topology`.
        telemetry: Collector receiving flow records and window metrics.
        duration_s: Total simulated duration.
        seed: Master seed; all stochastic behaviour derives from it.
        max_packets: Hard safety cap on generated packets.
        log_every_s: Simulated-time interval between progress log lines.
        max_wall_seconds: Wall-clock budget. A fuzzer is free to pick an
            attack rate that would take hours to simulate; rather than
            hanging a batch job, the run stops at the next event, marks
            itself truncated, and the caller reports it honestly.
    """

    def __init__(
        self,
        topology: Topology,
        telemetry: TelemetryCollector,
        duration_s: float,
        seed: int = 42,
        max_packets: int = 4_000_000,
        log_every_s: float = 15.0,
        max_wall_seconds: float = 240.0,
    ) -> None:
        if duration_s <= 0:
            raise ValueError("duration_s must be positive")
        self.topology = topology
        self.telemetry = telemetry
        self.duration_s = float(duration_s)
        self.seed = int(seed)
        self.max_packets = int(max_packets)
        self.log_every_s = float(log_every_s)
        self.max_wall_seconds = float(max_wall_seconds)
        self._wall_deadline: float | None = None

        self.now: float = 0.0
        self.stats = EngineStats()

        self._queue: list[tuple[float, int, EventCallback, Any]] = []
        self._counter = itertools.count()
        self._pid = itertools.count(1)
        self._loss_rng = fast_rng_for(seed, "channel_loss")
        self._stopped = False

        #: Per-node receive handlers, keyed by node id.
        self._receivers: dict[str, Callable[[Packet, float], None]] = {}
        #: Cancelled timer ids (lazy cancellation).
        self._cancelled: set[int] = set()
        self._timer_ids = itertools.count(1)

        #: Optional in-band packet filter (the mitigation enforcement point).
        self.packet_filter: PacketFilter | None = None
        #: Every node at which the filter is consulted. A single-gateway
        #: topology has one; a multi-gateway fabric enforces at all of them,
        #: because a botnet spread across gateways is otherwise unstoppable.
        self.enforcement_nodes: set[str] = set(
            topology.enforcement_nodes or ([topology.gateway_id] if topology.gateway_id else [])
        )
        #: Controllers invoked at every feature-window boundary.
        self.controllers: list[WindowController] = []
        #: Free-form run annotations surfaced in the result bundle.
        self.annotations: dict[str, Any] = {}

        # Bottleneck channels, declared by the topology builder rather than
        # assumed to be "gateway -> cloud": a dumbbell's bottleneck is its
        # backbone span, and a multi-gateway fabric has one uplink per gateway.
        self._uplinks: list[Channel] = []
        if topology.uplink_keys:
            self._uplinks = [topology.channels[key] for key in topology.uplink_keys
                             if key in topology.channels]
        elif topology.gateway_id and topology.cloud_id:
            self._uplinks = [topology.channel(topology.gateway_id, topology.cloud_id)]
        self._uplink_set = {id(ch) for ch in self._uplinks}
        self.telemetry.uplink_count = max(1, len(self._uplinks))

    # ------------------------------------------------------------------ #
    # event scheduling
    # ------------------------------------------------------------------ #
    def schedule_at(self, t: float, callback: EventCallback, arg: Any = None) -> int:
        """Schedule *callback* at absolute simulated time *t*.

        Args:
            t: Absolute simulated time (must not precede :attr:`now`).
            callback: Callable invoked as ``callback(t, arg)``.
            arg: Opaque payload handed back to the callback.

        Returns:
            The event's sequence id (usable with :meth:`cancel`).
        """
        when = max(t, self.now)
        seq = next(self._counter)
        heapq.heappush(self._queue, (when, seq, callback, arg))
        return seq

    def schedule(self, delay: float, callback: EventCallback, arg: Any = None) -> int:
        """Schedule *callback* after *delay* simulated seconds."""
        return self.schedule_at(self.now + max(0.0, delay), callback, arg)

    def new_timer_id(self) -> int:
        """Allocate a cancellable timer identifier."""
        return next(self._timer_ids)

    def cancel_timer(self, timer_id: int) -> None:
        """Mark a timer id as cancelled (checked by the timer callback)."""
        self._cancelled.add(timer_id)

    def is_cancelled(self, timer_id: int) -> bool:
        """Return True when *timer_id* was cancelled."""
        return timer_id in self._cancelled

    def stop(self) -> None:
        """Request early termination of the event loop."""
        self._stopped = True

    # ------------------------------------------------------------------ #
    # registration
    # ------------------------------------------------------------------ #
    def register_receiver(
        self, node_id: str, handler: Callable[[Packet, float], None]
    ) -> None:
        """Register the application handler invoked when a packet is delivered.

        Args:
            node_id: Destination node whose deliveries should be handled.
            handler: Callable ``handler(packet, t)``.

        Raises:
            KeyError: If *node_id* is not part of the topology.
        """
        if node_id not in self.topology.nodes:
            raise KeyError(f"Cannot register receiver for unknown node {node_id!r}")
        self._receivers[node_id] = handler

    def add_controller(self, controller: WindowController) -> None:
        """Register a controller invoked at every feature-window boundary."""
        self.controllers.append(controller)

    def next_packet_id(self) -> int:
        """Return a fresh monotonic packet id."""
        return next(self._pid)

    # ------------------------------------------------------------------ #
    # packet ingress
    # ------------------------------------------------------------------ #
    def send(self, packet: Packet) -> bool:
        """Inject a freshly generated packet into the network at its source.

        Args:
            packet: The packet to transmit. ``packet.src`` must be a real node.

        Returns:
            True when the packet entered the network, False when the global
            packet cap has been reached (the run is then truncated).
        """
        if self.stats.packets_generated >= self.max_packets:
            if not self.stats.truncated_by_cap:
                self.stats.truncated_by_cap = True
                _LOG.warning(
                    "Packet cap of %d reached at t=%.3fs; halting packet generation.",
                    self.max_packets,
                    self.now,
                )
                self.stop()
            return False

        self.stats.packets_generated += 1
        packet.t_gen = self.now
        self.telemetry.on_generate(packet)
        node = self.topology.nodes[packet.src]
        node.counters.tx_packets += 1
        node.counters.tx_bytes += packet.size
        self._forward(self.now, packet, packet.src)
        return True

    # ------------------------------------------------------------------ #
    # forwarding / queueing
    # ------------------------------------------------------------------ #
    def _forward(self, t: float, packet: Packet, at_node: str) -> None:
        """Enqueue *packet* on the outgoing channel toward its destination."""
        if at_node == packet.dst:
            self._deliver(t, packet)
            return

        nxt = self.topology.next_hop.get((at_node, packet.dst))
        if nxt is None:
            self._drop(t, packet, "no_route")
            return

        channel = self.topology.channels.get((at_node, nxt))
        if channel is None:  # pragma: no cover - defensive
            self._drop(t, packet, "no_route")
            return

        if len(channel.queue) >= channel.queue_packets:
            channel.counters.record_drop("queue_overflow", packet.size)
            self._drop(t, packet, "queue_overflow")
            return

        packet.enqueue_time = t
        channel.queue.append(packet)
        occupancy = len(channel.queue)
        if occupancy > channel.peak_queue:
            channel.peak_queue = occupancy
        if occupancy > self.stats.max_queue_seen:
            self.stats.max_queue_seen = occupancy

        if not channel.busy:
            self._start_tx(t, channel)

    def _start_tx(self, t: float, channel: Channel) -> None:
        """Begin serialising the head-of-line packet of *channel*."""
        if not channel.queue:
            channel.busy = False
            return
        packet = channel.queue.popleft()
        channel.busy = True

        queue_delay = t - packet.enqueue_time
        if queue_delay > 0:
            channel.queue_delay_sum += queue_delay
            channel.queue_delay_n += 1

        service = channel.service_time(packet.size)
        channel.busy_time += service
        channel.counters.tx_packets += 1
        channel.counters.tx_bytes += packet.size
        if id(channel) in self._uplink_set:
            self.telemetry.add_uplink_busy(t, service)

        done = t + service
        self.schedule_at(done, self._on_tx_complete, channel)

        if channel.loss > 0.0 and float(self._loss_rng.random()) < channel.loss:
            channel.counters.record_drop("random_loss", packet.size)
            self.schedule_at(done, self._on_random_loss, packet)
        else:
            self.schedule_at(done + channel.delay_s, self._on_arrive, (packet, channel.dst))

    def _on_tx_complete(self, t: float, channel: Channel) -> None:
        """Serialiser became free: start the next queued packet."""
        channel.busy = False
        if channel.queue:
            self._start_tx(t, channel)

    def _on_random_loss(self, t: float, packet: Packet) -> None:
        """A packet was corrupted/lost on the medium."""
        self._drop(t, packet, "random_loss")

    def _on_arrive(self, t: float, payload: tuple[Packet, str]) -> None:
        """A packet completed propagation and arrived at *node_id*."""
        packet, node_id = payload
        node = self.topology.nodes[node_id]
        node.counters.rx_packets += 1
        node.counters.rx_bytes += packet.size
        packet.hops += 1

        # ---- in-band mitigation enforcement point --------------------------
        if (
            self.packet_filter is not None
            and node_id in self.enforcement_nodes
            and node.kind is not NodeKind.CLOUD
        ):
            reason = self.packet_filter.inspect(packet, t)
            if reason is not None:
                self._drop(t, packet, reason)
                return

        if node_id == packet.dst:
            self._deliver(t, packet)
            return

        self._process_and_forward(t, node, packet)

    def _process_and_forward(self, t: float, node: NetNode, packet: Packet) -> None:
        """Push *packet* through the node's finite-rate processing server."""
        pps = node.forwarding_pps
        if pps <= 0:
            self._forward(t, packet, node.node_id)
            return

        service = 1.0 / pps
        start = t if node.proc_busy_until <= t else node.proc_busy_until
        pending = max(0.0, node.proc_busy_until - t) * pps
        if node.proc_queue > 0 and pending >= node.proc_queue:
            node.counters.record_drop("cpu_overload", packet.size)
            self._drop(t, packet, "cpu_overload")
            return

        node.proc_busy_until = start + service
        self.stats.packets_forwarded += 1
        self.schedule_at(node.proc_busy_until, self._on_processed, (packet, node.node_id))

    def _on_processed(self, t: float, payload: tuple[Packet, str]) -> None:
        """Processing complete: forward toward the next hop."""
        packet, node_id = payload
        self._forward(t, packet, node_id)

    # ------------------------------------------------------------------ #
    # terminal outcomes
    # ------------------------------------------------------------------ #
    def _deliver(self, t: float, packet: Packet) -> None:
        """Hand a packet to the destination node's application handler."""
        self.stats.packets_delivered += 1
        self.telemetry.on_deliver(
            packet, t, upstream=packet.dst == self.topology.cloud_id
        )
        handler = self._receivers.get(packet.dst)
        if handler is not None:
            handler(packet, t)

    def _drop(self, t: float, packet: Packet, reason: str) -> None:
        """Record a discarded packet."""
        self.stats.packets_dropped += 1
        self.telemetry.on_drop(packet, reason, t)

    def drop_externally(self, packet: Packet, reason: str, t: float | None = None) -> None:
        """Allow an application (e.g. the cloud server) to record a drop."""
        self._drop(self.now if t is None else t, packet, reason)

    # ------------------------------------------------------------------ #
    # periodic housekeeping
    # ------------------------------------------------------------------ #
    def _sample_queues(self, t: float, _: Any) -> None:
        """Sample the gateway-uplink queue occupancy and reschedule."""
        if self._uplinks:
            self.telemetry.sample_queue(
                t, sum(len(ch.queue) for ch in self._uplinks)
            )
        nxt = t + QUEUE_SAMPLE_INTERVAL_S
        if nxt < self.duration_s:
            self.schedule_at(nxt, self._sample_queues, None)

    def _window_boundary(self, t: float, index: int) -> None:
        """Run every registered controller for the window that just closed."""
        for controller in self.controllers:
            try:
                controller.on_window(self, index, t)
            except Exception:  # pragma: no cover - controller bugs must be loud
                _LOG.exception(
                    "Controller %s failed on window %d; aborting run.",
                    type(controller).__name__,
                    index,
                )
                raise
        # Record how many sources are under an active rule as of this window's
        # close. The enforcer (installed as the packet filter) is the source of
        # truth; controllers have just run, so its state is current. Without
        # this the per-window ``mitigated_sources`` counter stays 0 and the
        # "Rules active" dashboard reads empty even while rules are enforcing.
        pf = self.packet_filter
        if pf is not None and hasattr(pf, "active_sources"):
            win = self.telemetry.windows.get(index)
            if win is not None:
                try:
                    win.mitigated_sources = len(pf.active_sources())
                except Exception:  # pragma: no cover - never fail a run over a counter
                    pass
        nxt = t + self.telemetry.window_s
        if nxt <= self.duration_s + 1e-9:
            self.schedule_at(nxt, self._window_boundary, index + 1)

    def _progress(self, t: float, _: Any) -> None:
        """Emit a progress line and reschedule."""
        _LOG.info(
            "  t=%6.1fs | generated=%8d delivered=%8d dropped=%7d | events=%9d",
            t,
            self.stats.packets_generated,
            self.stats.packets_delivered,
            self.stats.packets_dropped,
            self.stats.events_processed,
        )
        nxt = t + self.log_every_s
        if nxt < self.duration_s:
            self.schedule_at(nxt, self._progress, None)

    # ------------------------------------------------------------------ #
    # main loop
    # ------------------------------------------------------------------ #
    def run(self) -> EngineStats:
        """Run the event loop until the simulated duration elapses.

        Returns:
            The populated :class:`EngineStats` for this run.
        """
        import time as _time

        wall_start = _time.perf_counter()

        self.schedule_at(0.0, self._sample_queues, None)
        window_s = self.telemetry.window_s
        if window_s <= self.duration_s:
            self.schedule_at(window_s, self._window_boundary, 0)
        if self.log_every_s > 0:
            self.schedule_at(self.log_every_s, self._progress, None)

        if self.max_wall_seconds > 0:
            self._wall_deadline = wall_start + self.max_wall_seconds

        queue = self._queue
        checks = 0
        while queue and not self._stopped:
            when, _seq, callback, arg = heapq.heappop(queue)
            if when > self.duration_s:
                break
            self.now = when
            self.stats.events_processed += 1
            callback(when, arg)

            # Poll the wall clock sparsely: perf_counter() on every event
            # would itself be a measurable share of the run time.
            checks += 1
            if self._wall_deadline is not None and (checks & 0x3FFF) == 0:
                if _time.perf_counter() > self._wall_deadline:
                    self.stats.truncated_by_time = True
                    _LOG.warning(
                        'Wall-clock budget of %.0fs exhausted at simulated '
                        't=%.1fs of %.1fs; stopping early and marking the '
                        'run truncated.',
                        self.max_wall_seconds, when, self.duration_s,
                    )
                    break

        # Drain: let in-flight packets finish so latency samples are complete.
        drain_limit = self.duration_s + 2.0
        while queue:
            when, _seq, callback, arg = heapq.heappop(queue)
            if when > drain_limit:
                break
            self.now = when
            self.stats.events_processed += 1
            callback(when, arg)

        self.now = min(self.now, self.duration_s)
        self.stats.wall_seconds = _time.perf_counter() - wall_start
        self.stats.completed_fraction = (
            round(min(1.0, self.now / self.duration_s), 4)
            if self.duration_s else 1.0
        )
        _LOG.info(
            "Simulation finished: %d events, %d packets generated, %d delivered, "
            "%d dropped (%.2fs wall clock).",
            self.stats.events_processed,
            self.stats.packets_generated,
            self.stats.packets_delivered,
            self.stats.packets_dropped,
            self.stats.wall_seconds,
        )
        return self.stats

    # ------------------------------------------------------------------ #
    # link statistics
    # ------------------------------------------------------------------ #
    def link_report(self) -> list[dict[str, Any]]:
        """Return per-directed-channel utilisation and loss statistics."""
        elapsed = max(1e-9, self.duration_s)
        rows: list[dict[str, Any]] = []
        for (src, dst), channel in sorted(self.topology.channels.items()):
            if channel.counters.tx_packets == 0 and channel.counters.dropped_packets == 0:
                continue
            rows.append(
                {
                    "src": src,
                    "dst": dst,
                    "bandwidth_mbps": round(channel.bandwidth_bps / 1e6, 4),
                    "tx_packets": channel.counters.tx_packets,
                    "tx_bytes": channel.counters.tx_bytes,
                    "dropped_packets": channel.counters.dropped_packets,
                    "utilisation": round(channel.utilisation(elapsed), 5),
                    "mean_queue_delay_ms": round(channel.mean_queue_delay() * 1000.0, 4),
                    "peak_queue": channel.peak_queue,
                    "drop_reasons": dict(channel.counters.drop_reasons),
                }
            )
        return rows

    def node_report(self) -> list[dict[str, Any]]:
        """Return per-node transmit/receive/drop counters."""
        rows: list[dict[str, Any]] = []
        for node in self.topology.nodes.values():
            counters = node.counters
            rows.append(
                {
                    "node_id": node.node_id,
                    "kind": node.kind.value,
                    "ip": node.ip,
                    "device_class": node.device_class,
                    "is_attacker": node.is_attacker,
                    "tx_packets": counters.tx_packets,
                    "tx_bytes": counters.tx_bytes,
                    "rx_packets": counters.rx_packets,
                    "rx_bytes": counters.rx_bytes,
                    "dropped_packets": counters.dropped_packets,
                    "drop_reasons": dict(counters.drop_reasons),
                }
            )
        return rows


def make_packet(
    engine: SimulationEngine,
    src: NetNode,
    dst: NetNode,
    sport: int,
    dport: int,
    protocol: int,
    payload: int,
    size: int,
    flags: int = 0,
    app: str = "generic",
    is_attack: bool = False,
    attack_type: str = "",
    src_ip: str | None = None,
    conn_id: int = -1,
    seq: int = 0,
    ack: int = 0,
    retransmit: bool = False,
    app_len: int = 0,
) -> Packet:
    """Construct a :class:`~netshield.simulation.packet.Packet` for *engine*.

    Args:
        engine: Engine providing the packet-id sequence and current time.
        src: Source node.
        dst: Destination node.
        sport: Source port.
        dport: Destination port.
        protocol: :class:`~netshield.simulation.packet.Protocol` number.
        payload: Application payload size in bytes.
        size: Total wire size in bytes.
        flags: TCP flag bitfield.
        app: Application tag.
        is_attack: Ground-truth attack label.
        attack_type: Attack family label when ``is_attack`` is set.
        src_ip: Override the source address (used for spoofing).
        conn_id: TCP connection id, or -1.
        seq: TCP sequence number.
        ack: TCP acknowledgement number.
        retransmit: Mark the packet as a TCP retransmission.
        app_len: Total application-message length carried by this segment.

    Returns:
        A populated packet, not yet injected into the network.
    """
    return Packet(
        pid=engine.next_packet_id(),
        t_gen=engine.now,
        src=src.node_id,
        dst=dst.node_id,
        src_ip=src_ip if src_ip is not None else src.ip,
        dst_ip=dst.ip,
        sport=sport,
        dport=dport,
        protocol=protocol,
        size=size,
        payload=payload,
        flags=flags,
        app=app,
        is_attack=is_attack,
        attack_type=attack_type,
        origin=src.node_id,
        conn_id=conn_id,
        seq=seq,
        ack=ack,
        retransmit=retransmit,
        app_len=app_len,
        from_compromised=src.kind is NodeKind.ATTACKER,
    )


__all__ = [
    "SimulationEngine",
    "EngineStats",
    "PacketFilter",
    "WindowController",
    "make_packet",
    "Protocol",
    "QUEUE_SAMPLE_INTERVAL_S",
]
