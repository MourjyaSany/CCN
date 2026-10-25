"""IoT -> Router -> Edge Gateway -> Cloud topology construction.

The topology is a four-tier tree::

    [IoT devices] --access--> [access routers] --agg--> [edge gateway] --uplink--> [cloud]

Every physical link is instantiated as **two directed channels** so that upstream
and downstream traffic contend for their own serialisation capacity and queue,
exactly as in a full-duplex Ethernet/WLAN link. Store-and-forward, drop-tail
queueing, propagation delay and residual random loss are all modelled per
channel, which is what makes latency and packet loss *emergent* measurements
rather than configured constants.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Mapping

from ..utils.logging_utils import get_logger
from ..utils.seeding import rng_for
from .packet import PacketCounters

_LOG = get_logger(__name__)


class NodeKind(str, Enum):
    """Role of a node inside the tiered topology."""

    IOT = "iot"
    ATTACKER = "attacker"
    ROUTER = "router"
    GATEWAY = "gateway"
    CLOUD = "cloud"

    @property
    def is_endpoint(self) -> bool:
        """True for traffic-originating leaf nodes."""
        return self in (NodeKind.IOT, NodeKind.ATTACKER)

    @property
    def is_infrastructure(self) -> bool:
        """True for forwarding/serving infrastructure nodes."""
        return self in (NodeKind.ROUTER, NodeKind.GATEWAY, NodeKind.CLOUD)


#: Legitimate IoT device classes recognised by the traffic model.
DEVICE_CLASSES: tuple[str, ...] = (
    "mqtt_sensor",
    "http_client",
    "tcp_uploader",
    "udp_streamer",
)


@dataclass(slots=True)
class NetNode:
    """A node in the simulated network.

    Attributes:
        node_id: Stable string identifier, e.g. ``"iot-07"``.
        kind: :class:`NodeKind` role.
        ip: IPv4 address inside the simulated 10.0.0.0/8 private range.
        device_class: Traffic-model class for endpoints, ``""`` otherwise.
        parent: Upstream neighbour id (``None`` for the cloud root).
        forwarding_pps: Packet-processing capacity for infrastructure nodes.
        proc_queue: Depth of the processing backlog before CPU-overload drops.
        counters: Live packet counters.
        tier: Integer tier (0 = cloud, 1 = gateway, 2 = router, 3 = endpoint).
    """

    node_id: str
    kind: NodeKind
    ip: str
    device_class: str = ""
    parent: str | None = None
    forwarding_pps: float = 0.0
    proc_queue: int = 0
    counters: PacketCounters = field(default_factory=PacketCounters)
    tier: int = 3

    # runtime processing-server state (single server, FIFO)
    proc_busy_until: float = 0.0
    proc_backlog: int = 0

    @property
    def is_attacker(self) -> bool:
        """Ground-truth flag: this node is a compromised/botnet member."""
        return self.kind is NodeKind.ATTACKER

    def to_dict(self) -> dict[str, Any]:
        """Serialise the static description of the node."""
        return {
            "node_id": self.node_id,
            "kind": self.kind.value,
            "ip": self.ip,
            "device_class": self.device_class,
            "parent": self.parent,
            "tier": self.tier,
            "is_attacker": self.is_attacker,
        }


@dataclass(slots=True)
class Channel:
    """A directed, full-duplex half of a physical link.

    A channel is a single-server queue: packets are serialised at
    ``bandwidth_bps``, buffered in a drop-tail FIFO of ``queue_packets`` slots,
    and then propagate for ``delay_s`` seconds.

    Attributes:
        src: Transmitting node id.
        dst: Receiving node id.
        bandwidth_bps: Serialisation capacity in bits per second.
        delay_s: One-way propagation delay in seconds.
        queue_packets: Drop-tail buffer depth, in packets.
        loss: Independent per-packet loss probability.
        queue: Pending packets awaiting transmission.
        busy: True while the serialiser is transmitting.
        counters: Live packet counters for this direction.
        busy_time: Cumulative seconds spent transmitting (for utilisation).
        queue_delay_sum: Cumulative queueing delay of transmitted packets.
        queue_delay_n: Number of samples in ``queue_delay_sum``.
        peak_queue: Maximum observed queue occupancy.
    """

    src: str
    dst: str
    bandwidth_bps: float
    delay_s: float
    queue_packets: int
    loss: float = 0.0

    queue: deque = field(default_factory=deque)
    busy: bool = False
    counters: PacketCounters = field(default_factory=PacketCounters)
    busy_time: float = 0.0
    queue_delay_sum: float = 0.0
    queue_delay_n: int = 0
    peak_queue: int = 0

    @property
    def key(self) -> tuple[str, str]:
        """Directed channel key ``(src, dst)``."""
        return (self.src, self.dst)

    def service_time(self, size_bytes: int) -> float:
        """Return the serialisation time for a frame of *size_bytes*."""
        return (size_bytes * 8.0) / self.bandwidth_bps

    def occupancy(self) -> int:
        """Current number of packets waiting in the transmit buffer."""
        return len(self.queue)

    def utilisation(self, elapsed_s: float) -> float:
        """Fraction of wall-clock (simulated) time the serialiser was busy."""
        return (self.busy_time / elapsed_s) if elapsed_s > 0 else 0.0

    def mean_queue_delay(self) -> float:
        """Mean queueing delay experienced by transmitted packets, seconds."""
        return (self.queue_delay_sum / self.queue_delay_n) if self.queue_delay_n else 0.0


@dataclass(slots=True)
class LinkSpec:
    """Static parameters of a physical (bidirectional) link."""

    bandwidth_bps: float
    delay_ms: float
    queue_packets: int
    loss: float = 0.0

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "LinkSpec":
        """Build a :class:`LinkSpec` from a YAML mapping."""
        return cls(
            bandwidth_bps=float(data["bandwidth_bps"]),
            delay_ms=float(data["delay_ms"]),
            queue_packets=int(data["queue_packets"]),
            loss=float(data.get("loss", 0.0)),
        )

    @property
    def delay_s(self) -> float:
        """Propagation delay in seconds."""
        return self.delay_ms / 1000.0


class Topology:
    """The instantiated network: nodes, directed channels and routing table.

    Routing is computed once by breadth-first search over the tree, producing a
    ``next_hop[(current, destination)]`` table. Because the physical layout is a
    tree, this is both the shortest path and the only path - which is exactly
    why the gateway uplink is a hard choke point for the DDoS scenarios.
    """

    def __init__(self, name: str = "topology") -> None:
        self.name = name
        self.nodes: dict[str, NetNode] = {}
        self.channels: dict[tuple[str, str], Channel] = {}
        self.neighbours: dict[str, list[str]] = {}
        self.next_hop: dict[tuple[str, str], str] = {}
        self.ip_to_node: dict[str, str] = {}
        self.cloud_id: str = ""
        self.gateway_id: str = ""
        #: Topology family that produced this instance (see
        #: :mod:`netshield.simulation.topologies`).
        self.family: str = "tree"
        #: Every node at which the mitigation enforcer may install rules. A
        #: single-gateway topology lists exactly one; a multi-gateway fabric
        #: lists all of them, because a botnet spread across two gateways can
        #: only be stopped if both enforce.
        self.enforcement_nodes: list[str] = []
        #: Directed channel keys that constitute the capacity bottleneck the
        #: attack is trying to exhaust. Which link this *is* depends on the
        #: family (a tree's gateway uplink, a dumbbell's backbone span), so the
        #: builder declares it rather than the engine assuming it.
        self.uplink_keys: list[tuple[str, str]] = []

    # -- construction ------------------------------------------------------- #
    def add_node(self, node: NetNode) -> NetNode:
        """Register a node and index its IP address.

        Raises:
            ValueError: If the node id or IP address is already in use.
        """
        if node.node_id in self.nodes:
            raise ValueError(f"Duplicate node id: {node.node_id}")
        if node.ip in self.ip_to_node:
            raise ValueError(f"Duplicate IP address {node.ip} for node {node.node_id}")
        self.nodes[node.node_id] = node
        self.ip_to_node[node.ip] = node.node_id
        self.neighbours.setdefault(node.node_id, [])
        return node

    def add_link(self, a: str, b: str, spec: LinkSpec) -> tuple[Channel, Channel]:
        """Create the two directed channels of a full-duplex link.

        Args:
            a: One endpoint node id.
            b: The other endpoint node id.
            spec: Physical link parameters, applied symmetrically.

        Returns:
            The ``(a->b, b->a)`` channel pair.

        Raises:
            KeyError: If either endpoint has not been added yet.
        """
        for node_id in (a, b):
            if node_id not in self.nodes:
                raise KeyError(f"Cannot link unknown node {node_id!r}")

        forward = Channel(a, b, spec.bandwidth_bps, spec.delay_s, spec.queue_packets, spec.loss)
        reverse = Channel(b, a, spec.bandwidth_bps, spec.delay_s, spec.queue_packets, spec.loss)
        self.channels[forward.key] = forward
        self.channels[reverse.key] = reverse
        self.neighbours[a].append(b)
        self.neighbours[b].append(a)
        return forward, reverse

    def compute_routes(self) -> None:
        """Populate the ``next_hop`` table using BFS from every destination."""
        self.next_hop.clear()
        for destination in self.nodes:
            visited = {destination}
            frontier: deque[str] = deque([destination])
            while frontier:
                current = frontier.popleft()
                for neighbour in self.neighbours.get(current, ()):
                    if neighbour in visited:
                        continue
                    visited.add(neighbour)
                    # From `neighbour`, the way to `destination` starts at `current`.
                    self.next_hop[(neighbour, destination)] = current
                    frontier.append(neighbour)

    # -- queries ------------------------------------------------------------ #
    def node(self, node_id: str) -> NetNode:
        """Return a node by id.

        Raises:
            KeyError: If the node does not exist.
        """
        try:
            return self.nodes[node_id]
        except KeyError as exc:  # pragma: no cover - defensive
            raise KeyError(f"Unknown node {node_id!r}") from exc

    def channel(self, src: str, dst: str) -> Channel:
        """Return the directed channel from *src* to *dst*.

        Raises:
            KeyError: If no such channel exists.
        """
        try:
            return self.channels[(src, dst)]
        except KeyError as exc:  # pragma: no cover - defensive
            raise KeyError(f"No channel {src} -> {dst}") from exc

    def endpoints(self) -> list[NetNode]:
        """Return all traffic-originating leaf nodes."""
        return [n for n in self.nodes.values() if n.kind.is_endpoint]

    def attackers(self) -> list[NetNode]:
        """Return the ground-truth set of attacker nodes."""
        return [n for n in self.nodes.values() if n.kind is NodeKind.ATTACKER]

    def legitimate(self) -> list[NetNode]:
        """Return the legitimate IoT devices."""
        return [n for n in self.nodes.values() if n.kind is NodeKind.IOT]

    def path(self, src: str, dst: str) -> list[str]:
        """Return the full hop list from *src* to *dst* inclusive.

        Raises:
            KeyError: If no route exists (should be impossible on a tree).
        """
        if src == dst:
            return [src]
        hops = [src]
        current = src
        guard = 0
        while current != dst:
            guard += 1
            if guard > len(self.nodes) + 2:  # pragma: no cover - defensive
                raise KeyError(f"Routing loop detected between {src} and {dst}")
            nxt = self.next_hop.get((current, dst))
            if nxt is None:
                raise KeyError(f"No route from {src} to {dst}")
            hops.append(nxt)
            current = nxt
        return hops

    def uplink_channel(self) -> Channel:
        """Return the primary bottleneck channel carrying traffic to the cloud.

        For a single-gateway tree this is ``gateway -> cloud``. Other families
        declare their own bottleneck in :attr:`uplink_keys` (a dumbbell's
        constrained backbone span, for instance), and this returns the first.
        """
        if self.uplink_keys:
            return self.channels[self.uplink_keys[0]]
        return self.channel(self.gateway_id, self.cloud_id)

    def uplink_channels(self) -> list[Channel]:
        """Return every bottleneck channel (one per uplink in this family)."""
        if self.uplink_keys:
            return [self.channels[key] for key in self.uplink_keys]
        return [self.channel(self.gateway_id, self.cloud_id)]

    def downlink_channel(self) -> Channel:
        """Return the reverse direction of the primary bottleneck channel."""
        up = self.uplink_channel()
        return self.channel(up.dst, up.src)

    def gateways(self) -> list[NetNode]:
        """Return every gateway node, ordered by id."""
        return sorted(
            (n for n in self.nodes.values() if n.kind is NodeKind.GATEWAY),
            key=lambda n: n.node_id,
        )

    # -- export ------------------------------------------------------------- #
    def describe(self) -> dict[str, Any]:
        """Return a JSON-serialisable description of the topology."""
        return {
            "name": self.name,
            "family": self.family,
            "n_nodes": len(self.nodes),
            "n_links": len(self.channels) // 2,
            "cloud": self.cloud_id,
            "gateway": self.gateway_id,
            "gateways": [n.node_id for n in self.gateways()],
            "enforcement_nodes": list(self.enforcement_nodes),
            "uplinks": [{"source": a, "target": b} for a, b in self.uplink_keys],
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "links": [
                {
                    "source": ch.src,
                    "target": ch.dst,
                    "bandwidth_bps": ch.bandwidth_bps,
                    "delay_ms": ch.delay_s * 1000.0,
                    "queue_packets": ch.queue_packets,
                }
                for key, ch in sorted(self.channels.items())
                if key[0] < key[1]  # emit each physical link once
            ],
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<Topology {self.name} nodes={len(self.nodes)} "
            f"links={len(self.channels) // 2}>"
        )


# --------------------------------------------------------------------------- #
# builder
# --------------------------------------------------------------------------- #
def _weighted_device_classes(
    mix: Mapping[str, float], count: int, seed: int
) -> list[str]:
    """Deterministically assign device classes according to a weight mix.

    Uses largest-remainder apportionment so the realised mix matches the
    requested proportions exactly, then shuffles with a derived RNG so the
    class order is not correlated with node index.

    Args:
        mix: Mapping of device class to relative weight.
        count: Number of devices to assign.
        seed: Master seed used to derive the shuffling RNG.

    Returns:
        A list of ``count`` device-class names.
    """
    classes = [c for c in DEVICE_CLASSES if float(mix.get(c, 0.0)) > 0.0]
    if not classes:
        classes = list(DEVICE_CLASSES)
    weights = [float(mix.get(c, 0.0)) for c in classes]
    total = sum(weights) or 1.0
    exact = [w / total * count for w in weights]
    counts = [int(v) for v in exact]
    remainder = count - sum(counts)
    order = sorted(range(len(classes)), key=lambda i: exact[i] - counts[i], reverse=True)
    for i in range(remainder):
        counts[order[i % len(order)]] += 1

    assigned: list[str] = []
    for cls, n in zip(classes, counts):
        assigned.extend([cls] * n)
    rng = rng_for(seed, "device_mix")
    rng.shuffle(assigned)
    return assigned[:count]


def build_topology(config: Mapping[str, Any] | Any) -> Topology:
    """Instantiate the topology described by the configuration.

    Dispatches on ``network.topology.family``. The default, ``"tree"``, is the
    original four-tier IoT-edge-cloud layout; the other families live in
    :mod:`netshield.simulation.topologies`.

    Args:
        config: A :class:`~netshield.utils.config.Config` (or any object with a
            ``get(dotted, default)`` method) holding ``network.topology.*`` and
            ``simulation.*`` keys.

    Returns:
        A fully wired :class:`Topology` with routes computed.

    Raises:
        ValueError: If the family is unknown or the fleet cannot be laid out.
    """
    # Imported here rather than at module scope: topologies.py builds on the
    # primitives defined above, so a top-level import would be circular.
    from .topologies import build_family_topology

    family = str((config.get("network.topology", {}) or {}).get("family", "tree"))
    if family == "tree":
        return build_tree_topology(config)
    return build_family_topology(family, config)


def build_tree_topology(config: Mapping[str, Any] | Any) -> Topology:
    """Instantiate the four-tier IoT -> router -> gateway -> cloud tree.

    Args:
        config: A :class:`~netshield.utils.config.Config` (or any object with a
            ``get(dotted, default)`` method) holding ``network.topology.*`` and
            ``simulation.*`` keys.

    Returns:
        A fully wired :class:`Topology` with routes computed.

    Raises:
        ValueError: If the requested fleet cannot be laid out (e.g. zero routers).
    """
    get = config.get  # duck-typed Config accessor
    seed = int(get("seed", 42))
    spec = get("network.topology", {}) or {}

    n_iot = int(get("simulation.n_iot_devices", 8))
    n_attackers = int(get("simulation.n_attackers", 0))
    n_routers = int(spec.get("routers", {}).get("count", 1))
    if n_routers < 1:
        raise ValueError("network.topology.routers.count must be >= 1")
    if n_iot + n_attackers < 1:
        raise ValueError("The fleet must contain at least one endpoint node.")

    topo = Topology(name=str(spec.get("name", "iot-edge-cloud")))

    # ---- Tier 0: cloud ----------------------------------------------------- #
    cloud_spec = spec.get("cloud", {}) or {}
    cloud_id = str(cloud_spec.get("id", "cloud-0"))
    cloud = topo.add_node(
        NetNode(
            node_id=cloud_id,
            kind=NodeKind.CLOUD,
            ip=str(cloud_spec.get("ip", "10.0.0.1")),
            forwarding_pps=float(cloud_spec.get("forwarding_pps", 60000.0)),
            proc_queue=int(cloud_spec.get("proc_queue", 2000)),
            tier=0,
        )
    )
    topo.cloud_id = cloud.node_id

    # ---- Tier 1: edge gateway --------------------------------------------- #
    gw_spec = spec.get("gateway", {}) or {}
    gateway_id = str(gw_spec.get("id", "gw-0"))
    gateway = topo.add_node(
        NetNode(
            node_id=gateway_id,
            kind=NodeKind.GATEWAY,
            ip=str(gw_spec.get("ip", "10.0.1.1")),
            parent=cloud.node_id,
            forwarding_pps=float(gw_spec.get("forwarding_pps", 20000.0)),
            proc_queue=int(gw_spec.get("proc_queue", 800)),
            tier=1,
        )
    )
    topo.gateway_id = gateway.node_id
    topo.add_link(gateway.node_id, cloud.node_id, LinkSpec.from_mapping(gw_spec["uplink"]))

    # ---- Tier 2: access routers ------------------------------------------- #
    router_spec = spec.get("routers", {}) or {}
    router_prefix = str(router_spec.get("ip_prefix", "10.0.2"))
    router_link = LinkSpec.from_mapping(router_spec["uplink"])
    router_ids: list[str] = []
    for idx in range(n_routers):
        router = topo.add_node(
            NetNode(
                node_id=f"rtr-{idx}",
                kind=NodeKind.ROUTER,
                ip=f"{router_prefix}.{idx + 1}",
                parent=gateway.node_id,
                forwarding_pps=float(router_spec.get("forwarding_pps", 40000.0)),
                proc_queue=int(router_spec.get("proc_queue", 1200)),
                tier=2,
            )
        )
        topo.add_link(router.node_id, gateway.node_id, router_link)
        router_ids.append(router.node_id)

    # ---- Tier 3: endpoints -------------------------------------------------- #
    access_link = LinkSpec.from_mapping(spec["access_link"])
    attacker_link = LinkSpec.from_mapping(spec.get("attacker_link", spec["access_link"]))
    device_mix = get("traffic.device_mix", {}) or {}
    classes = _weighted_device_classes(device_mix, n_iot, seed)
    # Compromised nodes are ordinary IoT devices that have been taken over:
    # they keep performing their legitimate function while also emitting
    # attack traffic. Giving them a real device class is what makes the
    # detection problem three-class rather than a trivial on/off split.
    attacker_classes = _weighted_device_classes(device_mix, n_attackers, seed + 1)

    host_octet = 10  # endpoints get 10.<10+router>.<subnet>.<host>
    for idx in range(n_iot):
        router_id = router_ids[idx % n_routers]
        subnet = int(router_id.split("-")[1])
        node = topo.add_node(
            NetNode(
                node_id=f"iot-{idx:02d}",
                kind=NodeKind.IOT,
                ip=f"10.{host_octet + subnet}.0.{(idx // n_routers) + 2}",
                device_class=classes[idx],
                parent=router_id,
                tier=3,
            )
        )
        topo.add_link(node.node_id, router_id, access_link)

    for idx in range(n_attackers):
        router_id = router_ids[idx % n_routers]
        subnet = int(router_id.split("-")[1])
        node = topo.add_node(
            NetNode(
                node_id=f"atk-{idx:02d}",
                kind=NodeKind.ATTACKER,
                ip=f"10.{host_octet + subnet}.9.{(idx // n_routers) + 2}",
                device_class=attacker_classes[idx],
                parent=router_id,
                tier=3,
            )
        )
        topo.add_link(node.node_id, router_id, attacker_link)

    topo.family = "tree"
    topo.enforcement_nodes = [gateway.node_id]
    topo.uplink_keys = [(gateway.node_id, cloud.node_id)]
    topo.compute_routes()
    _LOG.info(
        "Topology '%s': %d nodes (%d IoT, %d attackers, %d routers), %d links",
        topo.name,
        len(topo.nodes),
        n_iot,
        n_attackers,
        n_routers,
        len(topo.channels) // 2,
    )
    return topo


def spoofed_ip_pool(size: int, seed: int) -> list[str]:
    """Generate a deterministic pool of spoofed source addresses.

    The pool is drawn from ``10.66.0.0/16`` - an address block that is *not*
    assigned to any node in the simulated topology, so spoofed packets can never
    be confused with a real device and can never leave the simulator.

    Args:
        size: Number of distinct spoofed addresses.
        seed: Master seed for deterministic generation.

    Returns:
        A list of ``size`` unique IPv4 address strings.
    """
    rng = rng_for(seed, "spoof_pool")
    seen: set[str] = set()
    pool: list[str] = []
    while len(pool) < max(1, size):
        addr = f"10.66.{int(rng.integers(0, 256))}.{int(rng.integers(1, 255))}"
        if addr not in seen:
            seen.add(addr)
            pool.append(addr)
    return pool


def layout_positions(topo: Topology) -> dict[str, tuple[float, float]]:
    """Compute deterministic 2-D positions for topology visualisation.

    Nodes are laid out in horizontal tiers (cloud at the top, endpoints at the
    bottom) and evenly spaced within each tier.

    Args:
        topo: The topology to lay out.

    Returns:
        Mapping of node id to ``(x, y)`` in a 0..1 coordinate space.
    """
    tiers: dict[int, list[str]] = {}
    for node in topo.nodes.values():
        tiers.setdefault(node.tier, []).append(node.node_id)

    positions: dict[str, tuple[float, float]] = {}
    max_tier = max(tiers) if tiers else 1
    for tier, ids in tiers.items():
        ids = sorted(ids)
        y = 1.0 - (tier / max(1, max_tier))
        span = len(ids)
        for i, node_id in enumerate(ids):
            x = (i + 1) / (span + 1)
            positions[node_id] = (x, y)
    return positions


def iter_physical_links(topo: Topology) -> Iterable[tuple[str, str, Channel]]:
    """Yield each physical link once as ``(a, b, channel_a_to_b)``."""
    for (src, dst), channel in topo.channels.items():
        if src < dst:
            yield src, dst, channel
