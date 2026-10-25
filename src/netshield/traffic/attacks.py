"""Simulated DDoS attack generators.

.. warning::

   **Every generator in this module writes into the in-memory event queue of
   :class:`~netshield.simulation.engine.SimulationEngine` and nothing else.**
   No module in NetShield-GNN imports ``socket``, ``scapy``, ``raw`` sockets or
   any other host networking API. Destination addresses are validated to belong
   to the simulated topology before an attacker is constructed, so an attack can
   only ever target a node that this process itself created in memory. There is
   no code path by which a packet leaves the machine.

Four attack families are implemented, chosen to cover the standard taxonomy:

``udp_flood``
    Volumetric / bandwidth exhaustion. Large connectionless datagrams saturate
    the gateway uplink; the queue fills, latency climbs and drop-tail loss hits
    legitimate traffic sharing the same link.

``syn_flood``
    Protocol / state exhaustion. Minimum-size TCP SYNs with spoofed sources fill
    the server's half-open connection table. Bandwidth cost is negligible; the
    damage is that legitimate handshakes are refused.

``http_flood``
    Application layer. Complete, individually plausible HTTP transactions - full
    three-way handshake, request, response, teardown - issued at a rate that
    exhausts the server's worker pool. Every packet looks legitimate in
    isolation, which is why per-packet signatures fail and *relational*
    (graph-level) structure is needed.

``mixed``
    Heterogeneous botnet: each compromised node is deterministically assigned
    one of the three families above, producing the multi-vector attack that the
    distributed scenario (Experiment 5) requires.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Sequence

from ..simulation.engine import SimulationEngine, make_packet
from ..simulation.packet import Protocol, TCPFlag, wire_size
from ..simulation.tcp import TcpConnection, TcpRegistry
from ..simulation.topology import NetNode, Topology, spoofed_ip_pool
from ..utils.logging_utils import get_logger
from ..utils.seeding import fast_rng_for, rng_for

_LOG = get_logger(__name__)

#: Attack families that map to exactly one attacker implementation.
SINGLE_FAMILIES: tuple[str, ...] = (
    "udp_flood",
    "syn_flood",
    "http_flood",
    "icmp_flood",
    "ack_flood",
    "slowloris",
)

#: Attack families understood by :func:`build_attack_campaign`. ``"mixed"``
#: assigns one of the single families per compromised node.
ATTACK_TYPES: tuple[str, ...] = SINGLE_FAMILIES + ("mixed",)

#: Families used by ``"mixed"`` when no explicit ``family_mix`` is configured.
#: Deliberately the three classic layers (volumetric / protocol / application)
#: so the default multi-vector scenario stays comparable with the literature.
DEFAULT_MIX_FAMILIES: tuple[str, ...] = ("udp_flood", "syn_flood", "http_flood")

#: Rate-shaping waveforms understood by :meth:`AttackProfile.rate_multiplier`.
RATE_PROFILES: tuple[str, ...] = ("constant", "ramp", "sine", "step")

#: One-line description per family, surfaced by the API and the dashboard.
FAMILY_DESCRIPTIONS: dict[str, str] = {
    "udp_flood": "Volumetric: connectionless datagrams saturate the bottleneck link.",
    "syn_flood": "Protocol: bare SYNs exhaust the server's half-open backlog.",
    "http_flood": "Application: complete, plausible HTTP transactions at high rate.",
    "icmp_flood": "Volumetric: ICMP echo traffic; no ports, pure packet-rate load.",
    "ack_flood": "Protocol: stateless bare ACKs burn forwarding capacity, bypassing SYN defences.",
    "slowloris": "Application: many half-finished connections held open to exhaust the connection table.",
    "mixed": "Heterogeneous botnet: each bot is assigned one of the single families.",
}

#: Source-port pool size per attacker (bounds flow-table cardinality while still
#: producing the port entropy that real botnets exhibit).
ATTACKER_PORT_POOL: int = 64
#: Smallest simulated-time step used to guarantee event-loop progress.
_MIN_TIME_STEP: float = 1e-6
#: Relative tolerance applied when locating a burst-cycle boundary.
_CYCLE_EPSILON: float = 1e-9
LEGIT_LIKE_PORT_BASE: int = 32768


class AttackSafetyError(RuntimeError):
    """Raised when an attack is configured against a non-simulated target."""


@dataclass(slots=True)
class AttackProfile:
    """Fully resolved attack parameters for one run.

    Attributes:
        enabled: Whether any attack traffic is generated at all.
        attack_type: One of :data:`ATTACK_TYPES`.
        start_s: Simulated time the attack begins.
        duration_s: How long the attack lasts.
        packets_per_second: Per-attacker rate. For ``http_flood`` this is the
            *request* rate; each request expands into a full TCP transaction.
        packet_bytes: ``(lo, hi)`` payload size range.
        dst_ports: Destination ports cycled by the attackers.
        target: ``"cloud"`` or ``"gateway"``.
        burst_enabled: Enable on/off pulsing.
        burst_on_s: Length of the active phase.
        burst_off_s: Length of the idle phase.
        spoof_sources: Randomise the source IP from a non-existent pool.
        spoof_pool: Size of that pool.
    """

    enabled: bool
    attack_type: str
    start_s: float
    duration_s: float
    packets_per_second: float
    packet_bytes: tuple[int, int]
    dst_ports: tuple[int, ...]
    target: str = "cloud"
    burst_enabled: bool = False
    burst_on_s: float = 2.0
    burst_off_s: float = 3.0
    spoof_sources: bool = False
    spoof_pool: int = 64

    # ---- rate shaping ------------------------------------------------------
    #: Waveform applied to ``packets_per_second`` over the attack window. The
    #: on/off ``burst`` switch is orthogonal and multiplies on top, so a
    #: pulsing ramp is expressible.
    rate_profile: str = "constant"
    ramp_start_factor: float = 0.1
    ramp_end_factor: float = 1.0
    sine_period_s: float = 10.0
    sine_depth: float = 0.5
    step_levels: tuple[float, ...] = (0.25, 0.5, 0.75, 1.0)
    step_interval_s: float = 5.0

    # ---- per-attacker heterogeneity ---------------------------------------
    #: Each bot's rate is multiplied by a draw from this range. A real botnet
    #: is heterogeneous hardware on heterogeneous links; identical bots make
    #: the detection problem artificially easy.
    rate_jitter: tuple[float, float] = (1.0, 1.0)
    #: Bots join over this many seconds rather than all at t=start_s.
    stagger_s: float = 0.0
    #: Relative weights per family when ``attack_type == "mixed"``. Empty means
    #: uniform over the three classic families.
    family_mix: tuple[tuple[str, float], ...] = ()
    #: Size of each attacker's source-port pool.
    port_pool: int = ATTACKER_PORT_POOL

    # ---- family-specific ---------------------------------------------------
    #: slowloris: concurrent half-finished connections held open per bot.
    slowloris_sockets: int = 40
    #: slowloris: seconds between keep-alive dribbles on each held socket.
    slowloris_keepalive_s: float = 8.0

    @property
    def end_s(self) -> float:
        """Simulated time at which the attack stops."""
        return self.start_s + self.duration_s

    def rate_multiplier(self, t: float) -> float:
        """Return the rate-shaping factor in ``[0, inf)`` at simulated time *t*.

        This is the *waveform* only; the on/off burst duty cycle is applied
        separately by :meth:`Attacker.in_burst`, so the two compose.

        Args:
            t: Simulated time.

        Returns:
            A multiplier applied to :attr:`packets_per_second`. Always
            strictly positive so the emission interval stays finite.
        """
        profile = self.rate_profile
        if profile == "constant" or self.duration_s <= 0:
            return 1.0

        elapsed = max(0.0, t - self.start_s)
        fraction = min(1.0, elapsed / self.duration_s)

        if profile == "ramp":
            lo, hi = self.ramp_start_factor, self.ramp_end_factor
            value = lo + (hi - lo) * fraction
        elif profile == "sine":
            period = max(1e-6, self.sine_period_s)
            depth = min(1.0, max(0.0, self.sine_depth))
            value = 1.0 - depth + depth * (
                0.5 * (1.0 - math.cos(2.0 * math.pi * elapsed / period))
            ) * 2.0
        elif profile == "step":
            levels = self.step_levels or (1.0,)
            interval = max(1e-6, self.step_interval_s)
            value = levels[min(len(levels) - 1, int(elapsed // interval))]
        else:
            value = 1.0
        # A zero multiplier would make the emission interval infinite and stall
        # the attacker; clamp to a small floor instead.
        return max(1e-3, float(value))

    @classmethod
    def from_config(cls, config: Any) -> "AttackProfile":
        """Build a profile from the merged ``attack`` configuration section.

        Args:
            config: A :class:`~netshield.utils.config.Config`-like object.

        Returns:
            The resolved :class:`AttackProfile`.
        """
        sizes = config.get("attack.packet_bytes", [512, 512])
        ports = config.get("attack.dst_ports", [8883]) or [8883]
        jitter = config.get("attack.rate_jitter", [1.0, 1.0]) or [1.0, 1.0]
        levels = config.get("attack.shape.step_levels", [0.25, 0.5, 0.75, 1.0])
        mix = config.get("attack.family_mix", {}) or {}
        return cls(
            enabled=bool(config.get("attack.enabled", False)),
            attack_type=str(config.get("attack.type", "udp_flood")).lower(),
            start_s=float(config.get("attack.start_s", 0.0)),
            duration_s=float(config.get("attack.duration_s", 0.0)),
            packets_per_second=float(config.get("attack.packets_per_second", 0.0)),
            packet_bytes=(int(sizes[0]), int(sizes[1])),
            dst_ports=tuple(int(p) for p in ports),
            target=str(config.get("attack.target", "cloud")).lower(),
            burst_enabled=bool(config.get("attack.burst.enabled", False)),
            burst_on_s=float(config.get("attack.burst.on_s", 2.0)),
            burst_off_s=float(config.get("attack.burst.off_s", 3.0)),
            spoof_sources=bool(config.get("attack.spoof_sources", False)),
            spoof_pool=int(config.get("attack.spoof_pool", 64)),
            rate_profile=str(config.get("attack.shape.profile", "constant")).lower(),
            ramp_start_factor=float(config.get("attack.shape.ramp_start_factor", 0.1)),
            ramp_end_factor=float(config.get("attack.shape.ramp_end_factor", 1.0)),
            sine_period_s=float(config.get("attack.shape.sine_period_s", 10.0)),
            sine_depth=float(config.get("attack.shape.sine_depth", 0.5)),
            step_levels=tuple(float(v) for v in levels) or (1.0,),
            step_interval_s=float(config.get("attack.shape.step_interval_s", 5.0)),
            rate_jitter=(float(jitter[0]), float(jitter[-1])),
            stagger_s=float(config.get("attack.stagger_s", 0.0)),
            family_mix=tuple((str(k), float(v)) for k, v in sorted(mix.items())),
            port_pool=int(config.get("attack.port_pool", ATTACKER_PORT_POOL)),
            slowloris_sockets=int(config.get("attack.slowloris.sockets", 40)),
            slowloris_keepalive_s=float(config.get("attack.slowloris.keepalive_s", 8.0)),
        )

    def validate(self) -> "AttackProfile":
        """Check the profile is internally consistent.

        Returns:
            ``self``, unchanged.

        Raises:
            ValueError: If a parameter is outside its supported range.
        """
        if self.enabled and self.attack_type not in ATTACK_TYPES:
            raise ValueError(
                f"Unknown attack type {self.attack_type!r}; "
                f"expected one of {ATTACK_TYPES}."
            )
        if self.rate_profile not in RATE_PROFILES:
            raise ValueError(
                f"Unknown attack.shape.profile {self.rate_profile!r}; "
                f"expected one of {RATE_PROFILES}."
            )
        if self.enabled and self.packets_per_second <= 0:
            raise ValueError("attack.packets_per_second must be positive.")
        if self.packet_bytes[0] > self.packet_bytes[1]:
            raise ValueError("attack.packet_bytes must be [lo, hi] with lo <= hi.")
        if self.rate_jitter[0] <= 0 or self.rate_jitter[0] > self.rate_jitter[1]:
            raise ValueError("attack.rate_jitter must be [lo, hi] with 0 < lo <= hi.")
        if self.stagger_s < 0:
            raise ValueError("attack.stagger_s must be >= 0.")
        if not self.dst_ports:
            raise ValueError("attack.dst_ports must not be empty.")
        if self.port_pool < 1:
            raise ValueError("attack.port_pool must be >= 1.")
        for name, weight in self.family_mix:
            if name not in SINGLE_FAMILIES:
                raise ValueError(
                    f"attack.family_mix key {name!r} is not a single attack "
                    f"family; expected one of {SINGLE_FAMILIES}."
                )
            if weight < 0:
                raise ValueError("attack.family_mix weights must be >= 0.")
        return self

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view of the profile."""
        return {
            "enabled": self.enabled,
            "type": self.attack_type,
            "start_s": self.start_s,
            "duration_s": self.duration_s,
            "end_s": self.end_s,
            "packets_per_second": self.packets_per_second,
            "packet_bytes": list(self.packet_bytes),
            "dst_ports": list(self.dst_ports),
            "target": self.target,
            "burst": {
                "enabled": self.burst_enabled,
                "on_s": self.burst_on_s,
                "off_s": self.burst_off_s,
            },
            "spoof_sources": self.spoof_sources,
            "spoof_pool": self.spoof_pool,
            "shape": {
                "profile": self.rate_profile,
                "ramp_start_factor": self.ramp_start_factor,
                "ramp_end_factor": self.ramp_end_factor,
                "sine_period_s": self.sine_period_s,
                "sine_depth": self.sine_depth,
                "step_levels": list(self.step_levels),
                "step_interval_s": self.step_interval_s,
            },
            "rate_jitter": list(self.rate_jitter),
            "stagger_s": self.stagger_s,
            "family_mix": {k: v for k, v in self.family_mix},
            "port_pool": self.port_pool,
            "slowloris": {
                "sockets": self.slowloris_sockets,
                "keepalive_s": self.slowloris_keepalive_s,
            },
        }


class Attacker:
    """Base class for a compromised node emitting attack traffic.

    Args:
        engine: The simulation engine.
        node: The compromised endpoint.
        target: The node under attack (must belong to the same topology).
        profile: Resolved attack parameters.
        seed: Master seed; each attacker derives an independent RNG stream.
    """

    family: str = "generic"

    def __init__(
        self,
        engine: SimulationEngine,
        node: NetNode,
        target: NetNode,
        profile: AttackProfile,
        seed: int = 42,
    ) -> None:
        if target.node_id not in engine.topology.nodes:
            raise AttackSafetyError(
                f"Attack target {target.node_id!r} is not part of the simulated "
                "topology. Attacks may only target in-memory simulated nodes."
            )
        self.engine = engine
        self.node = node
        self.target = target
        self.profile = profile
        self.rng = fast_rng_for(seed, "attacker", node.node_id, self.family)
        self.packets_emitted: int = 0
        self.bytes_emitted: int = 0

        # Per-bot rate heterogeneity. A botnet of identical emitters is an
        # artificially easy detection problem: every bot lands on the same
        # point in feature space. Drawing a per-node multiplier spreads them.
        lo, hi = profile.rate_jitter
        self.rate_factor: float = (
            float(self.rng.uniform(lo, hi)) if hi > lo else float(lo)
        )
        self.base_rate: float = max(1e-6, profile.packets_per_second * self.rate_factor)
        self.interval = 1.0 / self.base_rate

        # Bots join over a window rather than simultaneously, so the attack
        # ramps in the way a real botnet activates.
        self.join_offset: float = (
            float(self.rng.uniform(0.0, profile.stagger_s))
            if profile.stagger_s > 0 else 0.0
        )

        self._ports = [
            LEGIT_LIKE_PORT_BASE + int(self.rng.integers(0, 30000))
            for _ in range(max(1, profile.port_pool))
        ]
        self._spoof_pool: Sequence[str] = ()
        if profile.spoof_sources:
            self._spoof_pool = spoofed_ip_pool(
                profile.spoof_pool, seed=int(self.rng.integers(0, 2**31))
            )

    def pick_src_ip(self) -> str | None:
        """Return a spoofed source address, or ``None`` to use the real one."""
        if not self._spoof_pool:
            return None
        return self._spoof_pool[int(self.rng.integers(0, len(self._spoof_pool)))]

    # -- timing -------------------------------------------------------------- #
    def in_attack_window(self, t: float) -> bool:
        """True while *t* lies inside the overall attack interval."""
        return self.profile.start_s <= t < self.profile.end_s

    def in_burst(self, t: float) -> bool:
        """True while the pulsing duty cycle is in its active phase."""
        if not self.profile.burst_enabled:
            return True
        cycle = self.profile.burst_on_s + self.profile.burst_off_s
        if cycle <= 0:
            return True
        phase = (t - self.profile.start_s) % cycle
        return phase < self.profile.burst_on_s

    def next_burst_start(self, t: float) -> float:
        """Return the time the next active phase begins.

        Args:
            t: Current simulated time.

        Returns:
            A time strictly greater than *t*. The epsilon inside the floor
            keeps the result from collapsing onto *t* when ``t`` lands on
            an exact cycle boundary, which would livelock the event loop.
        """
        cycle = self.profile.burst_on_s + self.profile.burst_off_s
        if cycle <= 0:
            return t + _MIN_TIME_STEP
        elapsed = t - self.profile.start_s
        cycles_done = int(math.floor(elapsed / cycle + _CYCLE_EPSILON))
        nxt = self.profile.start_s + (cycles_done + 1) * cycle
        return nxt if nxt > t else t + cycle

    def rate_at(self, t: float) -> float:
        """Return this bot's instantaneous emission rate at time *t*.

        Combines the per-bot rate multiplier with the campaign-level waveform
        (:meth:`AttackProfile.rate_multiplier`).
        """
        return max(1e-6, self.base_rate * self.profile.rate_multiplier(t))

    def next_interval(self, t: float | None = None) -> float:
        """Return the delay to the next emission.

        Args:
            t: Current simulated time. When given, the campaign rate waveform
                is evaluated at *t*; otherwise the nominal rate is used.
        """
        rate = self.rate_at(t) if t is not None else self.base_rate
        return (1.0 / rate) * float(self.rng.uniform(0.85, 1.15))

    # -- lifecycle ----------------------------------------------------------- #
    def start(self) -> None:
        """Schedule the first emission at this bot's join time."""
        offset = float(self.rng.uniform(0.0, min(0.5, self.interval * 5)))
        start_at = self.profile.start_s + self.join_offset + offset
        if start_at < self.profile.end_s:
            self.engine.schedule_at(start_at, self._tick, None)

    def _tick(self, t: float, _: Any) -> None:
        """Emission loop: fire if in an active burst phase, else skip forward."""
        if t >= self.profile.end_s:
            return
        if self.in_burst(t):
            self.emit(t)
            self.engine.schedule(self.next_interval(t), self._tick, None)
            return

        # Idle phase of a pulsing attack: skip straight to the next active
        # phase. The max() guarantees forward progress even if the burst
        # arithmetic degenerates, so the event loop can never stall.
        nxt = max(self.next_burst_start(t), t + _MIN_TIME_STEP)
        if nxt >= self.profile.end_s:
            return
        self.engine.schedule_at(nxt, self._tick, None)

    def emit(self, t: float) -> None:  # pragma: no cover - overridden
        """Emit one unit of attack traffic."""
        raise NotImplementedError

    # -- helpers ------------------------------------------------------------- #
    def pick_port(self) -> int:
        """Choose a destination port from the configured set."""
        ports = self.profile.dst_ports
        return int(ports[int(self.rng.integers(0, len(ports)))])

    def pick_sport(self) -> int:
        """Choose a source port from this attacker's pool."""
        return self._ports[int(self.rng.integers(0, len(self._ports)))]

    def pick_size(self) -> int:
        """Draw a payload size from the configured range."""
        lo, hi = self.profile.packet_bytes
        return int(self.rng.integers(lo, hi + 1)) if hi > lo else int(lo)

    def report(self) -> dict[str, Any]:
        """Return this attacker's emission counters."""
        return {
            "node_id": self.node.node_id,
            "family": self.family,
            "packets_emitted": self.packets_emitted,
            "bytes_emitted": self.bytes_emitted,
            "target": self.target.node_id,
        }


class UdpFloodAttacker(Attacker):
    """Volumetric UDP flood: connectionless datagrams at a fixed packet rate."""

    family = "udp_flood"

    def emit(self, t: float) -> None:
        """Transmit one UDP datagram at the target."""
        payload = self.pick_size()
        packet = make_packet(
            self.engine,
            src=self.node,
            dst=self.target,
            sport=self.pick_sport(),
            dport=self.pick_port(),
            protocol=Protocol.UDP,
            payload=payload,
            size=wire_size(payload, Protocol.UDP),
            app="attack_udp",
            is_attack=True,
            attack_type=self.family,
        )
        if self.engine.send(packet):
            self.packets_emitted += 1
            self.bytes_emitted += packet.size


class SynFloodAttacker(Attacker):
    """TCP SYN flood: bare SYNs, optionally with spoofed source addresses.

    The attacker is stateless by design - it never completes a handshake and
    never allocates a :class:`~netshield.simulation.tcp.TcpConnection`. That
    asymmetry (stateless attacker, stateful victim) *is* the attack.
    """

    family = "syn_flood"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._conn_seq = 0

    def emit(self, t: float) -> None:
        """Transmit one bare SYN segment."""
        payload = min(self.pick_size(), 64)
        src_ip = self.pick_src_ip()
        self._conn_seq += 1
        packet = make_packet(
            self.engine,
            src=self.node,
            dst=self.target,
            sport=self.pick_sport(),
            dport=self.pick_port(),
            protocol=Protocol.TCP,
            payload=0,
            size=wire_size(payload, Protocol.TCP),
            flags=int(TCPFlag.SYN),
            app="attack_syn",
            is_attack=True,
            attack_type=self.family,
            src_ip=src_ip,
            # Negative ids can never collide with registry-allocated connections.
            conn_id=-(self.packets_emitted + 1) * 1000 - self._conn_seq % 1000,
        )
        if self.engine.send(packet):
            self.packets_emitted += 1
            self.bytes_emitted += packet.size


class HttpFloodAttacker(Attacker):
    """Application-layer flood of complete, well-formed HTTP transactions.

    Args:
        registry: Shared TCP registry (the flood opens genuine connections).
    """

    family = "http_flood"

    def __init__(
        self,
        engine: SimulationEngine,
        node: NetNode,
        target: NetNode,
        profile: AttackProfile,
        registry: TcpRegistry,
        seed: int = 42,
    ) -> None:
        super().__init__(engine, node, target, profile, seed=seed)
        self.registry = registry
        self.connections_opened = 0
        self.connections_failed = 0

    def emit(self, t: float) -> None:
        """Open one attack connection and issue an HTTP-like request on it."""
        conn = TcpConnection(
            engine=self.engine,
            conn_id=self.registry.allocate_id(),
            local=self.node,
            remote=self.target,
            sport=self.pick_sport(),
            dport=self.pick_port(),
            role="client",
            app="attack_http",
            is_attack=True,
            attack_type=self.family,
        )
        self.registry.register(conn)
        conn.on_established = self._on_established
        conn.on_data = self._on_response
        conn.on_failed = self._on_failed
        conn.on_closed = self._on_closed
        conn.connect()
        self.packets_emitted += 1

    def _on_established(self, conn: TcpConnection, t: float) -> None:
        self.connections_opened += 1
        size = self.pick_size()
        conn.send_bytes(size, app_len=size)
        self.bytes_emitted += size

    def _on_response(self, conn: TcpConnection, packet: Any, t: float) -> None:
        # The flood does not care about the body; close as soon as it starts.
        conn.close(t, send_fin=True, notify=True)

    def _on_failed(self, conn: TcpConnection, t: float, reason: str) -> None:
        self.connections_failed += 1
        self.registry.unregister(conn)

    def _on_closed(self, conn: TcpConnection, t: float) -> None:
        self.registry.unregister(conn)

    def report(self) -> dict[str, Any]:
        """Return emission counters including connection-level statistics."""
        data = super().report()
        data.update(
            {
                "connections_opened": self.connections_opened,
                "connections_failed": self.connections_failed,
            }
        )
        return data


class IcmpFloodAttacker(Attacker):
    """Volumetric ICMP echo flood.

    Distinct from the UDP flood in the feature space the detector sees: there
    are no ports at all, so port-entropy and service-mix features go to zero
    while packet-rate features spike. A detector that leans on port structure
    (as the threshold baseline does) is blind to it.
    """

    family = "icmp_flood"

    def emit(self, t: float) -> None:
        """Transmit one ICMP echo-request-sized datagram."""
        payload = self.pick_size()
        packet = make_packet(
            self.engine,
            src=self.node,
            dst=self.target,
            # ICMP has no ports; 0/0 is what a flow exporter records.
            sport=0,
            dport=0,
            protocol=Protocol.ICMP,
            payload=payload,
            size=wire_size(payload, Protocol.ICMP),
            app="attack_icmp",
            is_attack=True,
            attack_type=self.family,
            src_ip=self.pick_src_ip(),
        )
        if self.engine.send(packet):
            self.packets_emitted += 1
            self.bytes_emitted += packet.size


class AckFloodAttacker(Attacker):
    """Stateless bare-ACK flood.

    An ACK flood carries no connection request, so a SYN-cookie or backlog
    defence never sees it. What it consumes is *forwarding* capacity and the
    server's orphan-segment handling: every packet must be routed, classified
    and discarded. It is the case that motivates modelling a per-node
    ``forwarding_pps`` server separately from link bandwidth.
    """

    family = "ack_flood"

    def emit(self, t: float) -> None:
        """Transmit one bare ACK segment belonging to no connection."""
        payload = min(self.pick_size(), 64)
        packet = make_packet(
            self.engine,
            src=self.node,
            dst=self.target,
            sport=self.pick_sport(),
            dport=self.pick_port(),
            protocol=Protocol.TCP,
            payload=0,
            size=wire_size(payload, Protocol.TCP),
            flags=int(TCPFlag.ACK),
            app="attack_ack",
            is_attack=True,
            attack_type=self.family,
            src_ip=self.pick_src_ip(),
            # No registry entry exists for this id, so the server treats the
            # segment as an orphan - exactly what a real ACK flood produces.
            conn_id=-(self.packets_emitted + 1) * 977 - 7,
        )
        if self.engine.send(packet):
            self.packets_emitted += 1
            self.bytes_emitted += packet.size


class SlowlorisAttacker(Attacker):
    """Low-bandwidth application attack: many connections, held open.

    Each bot opens up to :attr:`AttackProfile.slowloris_sockets` connections and
    keeps every one of them alive with a periodic few-byte dribble, never
    completing a request. The bandwidth cost is negligible - which is the point.
    What it exhausts is the server's *connection table*
    (:attr:`~netshield.traffic.server.CloudServer.max_connections`), so the
    damage appears as refused handshakes for legitimate devices while the link
    stays almost idle.

    This is the family that most clearly separates the detectors: per-node rate
    thresholds see nothing at all, because no individual bot is loud.
    """

    family = "slowloris"

    def __init__(
        self,
        engine: SimulationEngine,
        node: NetNode,
        target: NetNode,
        profile: AttackProfile,
        registry: TcpRegistry,
        seed: int = 42,
    ) -> None:
        super().__init__(engine, node, target, profile, seed=seed)
        self.registry = registry
        self.sockets_open = 0
        self.sockets_failed = 0
        self._held: list[TcpConnection] = []

    def emit(self, t: float) -> None:
        """Open one more held connection, up to the configured ceiling."""
        if len(self._held) >= max(1, self.profile.slowloris_sockets):
            return
        conn = TcpConnection(
            engine=self.engine,
            conn_id=self.registry.allocate_id(),
            local=self.node,
            remote=self.target,
            sport=self.pick_sport(),
            dport=self.pick_port(),
            role="client",
            app="attack_slowloris",
            is_attack=True,
            attack_type=self.family,
        )
        self.registry.register(conn)
        conn.on_established = self._on_established
        conn.on_failed = self._on_failed
        conn.on_closed = self._on_closed
        conn.connect()
        self._held.append(conn)
        self.packets_emitted += 1

    def _on_established(self, conn: TcpConnection, t: float) -> None:
        """Send a deliberately incomplete request, then start dribbling."""
        self.sockets_open += 1
        # A partial header: enough to make the server hold the connection,
        # never enough to constitute a complete request it could answer.
        conn.send_bytes(24, app_len=4096)
        self.bytes_emitted += 24
        self._schedule_keepalive(conn, t)

    def _schedule_keepalive(self, conn: TcpConnection, t: float) -> None:
        """Schedule the next keep-alive dribble for *conn*."""
        nxt = t + max(0.5, self.profile.slowloris_keepalive_s)
        if nxt < self.profile.end_s:
            self.engine.schedule_at(nxt, self._keepalive, conn)

    def _keepalive(self, t: float, conn: Any) -> None:
        """Send a few bytes so the server does not time the connection out."""
        if conn not in self._held or not getattr(conn, "established", False):
            return
        conn.send_bytes(8, app_len=4096)
        self.bytes_emitted += 8
        self.packets_emitted += 1
        self._schedule_keepalive(conn, t)

    def _on_failed(self, conn: TcpConnection, t: float, reason: str) -> None:
        self.sockets_failed += 1
        if conn in self._held:
            self._held.remove(conn)
        self.registry.unregister(conn)

    def _on_closed(self, conn: TcpConnection, t: float) -> None:
        if conn in self._held:
            self._held.remove(conn)
        self.registry.unregister(conn)

    def report(self) -> dict[str, Any]:
        """Return emission counters including held-socket statistics."""
        data = super().report()
        data.update(
            {
                "sockets_open": self.sockets_open,
                "sockets_failed": self.sockets_failed,
                "sockets_held": len(self._held),
            }
        )
        return data


def resolve_attack_target(topology: Topology, target: str) -> NetNode:
    """Resolve an ``attack.target`` value to a node of *topology*.

    Accepts the role aliases ``"cloud"`` and ``"gateway"``, or an explicit node
    id, which is what makes it possible to aim an attack at one gateway of a
    multi-gateway fabric.

    Args:
        topology: The simulated topology.
        target: Role alias or node id.

    Returns:
        The target node.

    Raises:
        AttackSafetyError: If *target* does not name a simulated node. This is
            the guard that makes it impossible to point the attack at anything
            outside this process's own in-memory topology.
    """
    alias = {"cloud": topology.cloud_id, "gateway": topology.gateway_id}
    node_id = alias.get(target, target)
    if node_id not in topology.nodes:
        raise AttackSafetyError(
            f"Attack target {target!r} does not resolve to a simulated node. "
            f"Valid roles: 'cloud', 'gateway'; or a node id from this topology."
        )
    return topology.nodes[node_id]


def _mix_families(profile: AttackProfile) -> tuple[tuple[str, ...], tuple[float, ...]]:
    """Return ``(families, cumulative_weights)`` for a ``mixed`` campaign."""
    if profile.family_mix:
        names = tuple(name for name, weight in profile.family_mix if weight > 0)
        weights = tuple(weight for _, weight in profile.family_mix if weight > 0)
        if names:
            total = sum(weights)
            return names, tuple(w / total for w in weights)
    n = len(DEFAULT_MIX_FAMILIES)
    return DEFAULT_MIX_FAMILIES, tuple(1.0 / n for _ in range(n))


def make_attacker(
    family: str,
    engine: SimulationEngine,
    node: NetNode,
    target: NetNode,
    profile: AttackProfile,
    registry: TcpRegistry,
    seed: int,
) -> Attacker:
    """Construct the attacker implementing *family*.

    Args:
        family: One of :data:`SINGLE_FAMILIES`.
        engine: The simulation engine.
        node: The compromised endpoint.
        target: The node under attack.
        profile: Resolved attack parameters.
        registry: Shared TCP registry (used by the connection-based families).
        seed: Master seed.

    Returns:
        The constructed attacker.

    Raises:
        ValueError: If *family* is not a known single family.
    """
    if family == "udp_flood":
        return UdpFloodAttacker(engine, node, target, profile, seed=seed)
    if family == "syn_flood":
        return SynFloodAttacker(engine, node, target, profile, seed=seed)
    if family == "http_flood":
        return HttpFloodAttacker(engine, node, target, profile, registry, seed=seed)
    if family == "icmp_flood":
        return IcmpFloodAttacker(engine, node, target, profile, seed=seed)
    if family == "ack_flood":
        return AckFloodAttacker(engine, node, target, profile, seed=seed)
    if family == "slowloris":
        return SlowlorisAttacker(engine, node, target, profile, registry, seed=seed)
    raise ValueError(f"Unhandled attack family {family!r}")


def build_attack_campaign(
    engine: SimulationEngine,
    topology: Topology,
    registry: TcpRegistry,
    profile: AttackProfile,
    seed: int = 42,
) -> list[Attacker]:
    """Instantiate one attacker per compromised node.

    Args:
        engine: The simulation engine.
        topology: The topology providing the attacker nodes and the target.
        registry: Shared TCP registry (needed by the HTTP flood).
        profile: Resolved attack parameters.
        seed: Master seed.

    Returns:
        The list of constructed attackers (empty when the attack is disabled).

    Raises:
        AttackSafetyError: If the configured target is not a simulated node.
        ValueError: If ``profile.attack_type`` is not a known family.
    """
    if not profile.enabled:
        return []

    profile.validate()
    target = resolve_attack_target(topology, profile.target)

    nodes = topology.attackers()
    if not nodes:
        _LOG.warning("attack.enabled is true but the topology has no attacker nodes.")
        return []

    assignment_rng = rng_for(seed, "attack_assignment")
    families, weights = _mix_families(profile)

    attackers: list[Attacker] = []
    for node in nodes:
        family = profile.attack_type
        if family == "mixed":
            # Weighted draw so a campaign can be, say, 70% volumetric.
            roll = float(assignment_rng.random())
            cumulative = 0.0
            family = families[-1]
            for name, weight in zip(families, weights):
                cumulative += weight
                if roll <= cumulative:
                    family = name
                    break
        attackers.append(
            make_attacker(family, engine, node, target, profile, registry, seed)
        )

    rates = [a.base_rate for a in attackers]
    _LOG.info(
        "Attack campaign '%s' [%s]: %d attacker(s) -> %s, %.0f-%.0f pps each, "
        "t=[%.1f, %.1f]s%s%s",
        profile.attack_type,
        profile.rate_profile,
        len(attackers),
        target.node_id,
        min(rates), max(rates),
        profile.start_s,
        profile.end_s,
        " (pulsing)" if profile.burst_enabled else "",
        f" (staggered over {profile.stagger_s:.0f}s)" if profile.stagger_s > 0 else "",
    )
    return attackers


def attack_family_counts(attackers: Sequence[Attacker]) -> dict[str, int]:
    """Return the number of attackers per family (useful for run metadata)."""
    counts: dict[str, int] = {}
    for attacker in attackers:
        counts[attacker.family] = counts.get(attacker.family, 0) + 1
    return counts


def attack_duty(profile: AttackProfile, t_start: float, t_end: float) -> float:
    """Return the fraction of ``[t_start, t_end)`` during which the attack is on.

    This is computed analytically from the attack schedule rather than measured,
    so it is exact even for pulsing attacks whose on/off cycle is not aligned
    with the feature-window grid. It is the temporal half of the ground-truth
    severity score used to label nodes (see
    :func:`netshield.features.node_features.label_from_severity`).

    Args:
        profile: The resolved attack profile.
        t_start: Window start time in seconds.
        t_end: Window end time in seconds.

    Returns:
        Duty cycle in ``[0, 1]``: 0 when the attack is entirely outside the
        window, 1 when the attack is continuously active across the whole window.
    """
    if not profile.enabled or t_end <= t_start:
        return 0.0

    lo = max(t_start, profile.start_s)
    hi = min(t_end, profile.end_s)
    if hi <= lo:
        return 0.0

    window = t_end - t_start
    if not profile.burst_enabled:
        return (hi - lo) / window

    cycle = profile.burst_on_s + profile.burst_off_s
    if cycle <= 0:
        return (hi - lo) / window

    # Integrate the on-phase indicator over [lo, hi) analytically.
    active = 0.0
    rel_lo = lo - profile.start_s
    rel_hi = hi - profile.start_s
    first = int(rel_lo // cycle)
    last = int(rel_hi // cycle)
    for index in range(first, last + 1):
        on_start = index * cycle
        on_end = on_start + profile.burst_on_s
        overlap = min(rel_hi, on_end) - max(rel_lo, on_start)
        if overlap > 0:
            active += overlap
    return max(0.0, min(1.0, active / window))
