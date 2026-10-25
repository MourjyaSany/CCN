"""Topology families beyond the baseline four-tier tree.

Why more than one topology
--------------------------
The original experiments all ran on a single tree with one gateway, which makes
the DDoS problem structurally easy in a way that flatters the detector: there is
exactly one choke point, exactly one aggregation path, and exactly one place to
enforce. Every bot's traffic provably crosses the same link, so "the graph" is
almost a straight line.

Real IoT deployments are not that. A campus has several gateways; a WAN has a
constrained backbone span rather than a constrained last mile; a resilient
fabric has *more than one path* between a device and the cloud, which means the
aggregation evidence a GNN relies on is split across routes. Each family below
changes one structural assumption, so the experiments can show which of the
detector's advantages are real and which were artefacts of the tree:

``tree``
    The baseline (implemented in :mod:`netshield.simulation.topology`). One
    gateway, one uplink, single path per device.

``star``
    Flat: every endpoint hangs off a single router beneath the gateway. No
    intermediate aggregation at all, so the two-hop receptive field of
    GraphSAGE sees strictly less structure. The control condition for "does the
    hierarchy actually matter".

``multi_gateway``
    Several independent gateways, each with its own routers and fleet, all
    homing to the cloud. A botnet is spread across gateways, so no single
    enforcement point can stop it and no single uplink shows the whole attack.

``dumbbell``
    The classic congestion topology: two router clusters joined by one
    constrained backbone span. The bottleneck is *in the middle of the network*
    rather than at the edge, so the gateway that enforces is not the device that
    saturates.

``fat_tree``
    Core / aggregation / edge, with every edge router dual-homed to two
    aggregation routers. The first family with genuinely redundant paths.

``mesh``
    Access routers interconnected in a ring plus chords. Multiple shortest
    paths exist and BFS routing spreads traffic over them.

``ring``
    Routers in a ring with a single gateway attachment: a degenerate mesh whose
    failure mode is a long path rather than a redundant one.

Structural invariants every family must honour
----------------------------------------------
The rest of the codebase depends on these, so each builder asserts them:

* exactly one cloud node, ``tier == 0``;
* at least one gateway, ``tier == 1``; ``topo.gateway_id`` names the primary;
* routers at ``tier == 2`` (aggregation and edge routers alike - tier encodes
  *role*, not hop count, so the ``tier`` node feature keeps the same meaning
  across every family);
* endpoints at ``tier == 3``;
* ``enforcement_nodes`` non-empty and every entry a gateway;
* ``uplink_keys`` non-empty and every entry an existing directed channel.

:func:`validate_topology` checks all of them and is exercised by the test suite
for every registered family.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping

from ..utils.logging_utils import get_logger
from ..utils.seeding import rng_for
from .topology import (
    LinkSpec,
    NetNode,
    NodeKind,
    Topology,
    _weighted_device_classes,
)

_LOG = get_logger(__name__)

#: Families this module can build, in addition to the baseline ``"tree"``.
TOPOLOGY_FAMILIES: tuple[str, ...] = (
    "tree",
    "star",
    "multi_gateway",
    "dumbbell",
    "fat_tree",
    "mesh",
    "ring",
)

#: Human-readable one-line description per family, surfaced by the API.
FAMILY_DESCRIPTIONS: dict[str, str] = {
    "tree": "Baseline four-tier IoT -> router -> gateway -> cloud tree.",
    "star": "Flat: all endpoints on one router; no intermediate aggregation.",
    "multi_gateway": "Several gateways homing to the cloud; enforcement is distributed.",
    "dumbbell": "Two router clusters joined by one constrained backbone span.",
    "fat_tree": "Core/aggregation/edge with dual-homed edge routers (redundant paths).",
    "mesh": "Access routers interconnected as a ring plus chords; multipath routing.",
    "ring": "Routers in a ring with a single gateway attachment.",
}


class TopologyError(ValueError):
    """Raised when a topology cannot be built or fails its structural checks."""


# --------------------------------------------------------------------------- #
# shared helpers
# --------------------------------------------------------------------------- #
def _link(spec: Mapping[str, Any], key: str, fallback: Mapping[str, Any]) -> LinkSpec:
    """Return the :class:`LinkSpec` at *key*, falling back to *fallback*."""
    return LinkSpec.from_mapping(spec.get(key) or fallback)


def _scaled(base: LinkSpec, bandwidth_factor: float = 1.0,
            delay_factor: float = 1.0) -> LinkSpec:
    """Return a copy of *base* with bandwidth and delay scaled."""
    return LinkSpec(
        bandwidth_bps=base.bandwidth_bps * bandwidth_factor,
        delay_ms=base.delay_ms * delay_factor,
        queue_packets=base.queue_packets,
        loss=base.loss,
    )


class _IpAllocator:
    """Hands out unique addresses inside the simulated ``10/8`` space.

    Every family allocates from the same allocator so that no two builders can
    accidentally mint the same address, and so that no address ever falls inside
    ``10.66.0.0/16`` - the block reserved for spoofed sources, which
    :func:`netshield.simulation.topology.spoofed_ip_pool` draws from and which a
    test asserts stays disjoint from real devices.
    """

    #: Second octet reserved for spoofed traffic; never allocated to a node.
    SPOOF_OCTET = 66

    def __init__(self) -> None:
        self._used: set[str] = set()

    def take(self, a: int, b: int, c: int) -> str:
        """Return ``10.a.b.c``, bumping *c* then *b* until it is unused."""
        if a == self.SPOOF_OCTET:
            raise TopologyError(
                f"10.{self.SPOOF_OCTET}/16 is reserved for spoofed sources "
                "and must never be assigned to a node."
            )
        for bb in range(b, 256):
            for cc in range(c, 255):
                addr = f"10.{a}.{bb}.{cc}"
                if addr not in self._used:
                    self._used.add(addr)
                    return addr
            c = 1
        raise TopologyError(f"Address space 10.{a}.x.x exhausted.")


def _add_endpoints(
    topo: Topology,
    ips: _IpAllocator,
    attach: list[str],
    n_iot: int,
    n_attackers: int,
    access: LinkSpec,
    attacker_link: LinkSpec,
    device_mix: Mapping[str, float],
    seed: int,
) -> None:
    """Attach the IoT fleet and the compromised nodes round-robin over *attach*.

    Args:
        topo: Topology under construction.
        ips: Shared address allocator.
        attach: Router ids to spread the fleet across (round-robin).
        n_iot: Number of legitimate devices.
        n_attackers: Number of compromised devices.
        access: Link specification for legitimate access links.
        attacker_link: Link specification for compromised nodes.
        device_mix: Device-class weight mapping.
        seed: Master seed.

    Raises:
        TopologyError: If there is nothing to attach the fleet to.
    """
    if not attach:
        raise TopologyError("No access routers available to attach endpoints to.")

    classes = _weighted_device_classes(device_mix, n_iot, seed)
    attacker_classes = _weighted_device_classes(device_mix, n_attackers, seed + 1)

    for idx in range(n_iot):
        parent = attach[idx % len(attach)]
        subnet = 10 + (attach.index(parent) % 40)
        node = topo.add_node(
            NetNode(
                node_id=f"iot-{idx:02d}",
                kind=NodeKind.IOT,
                ip=ips.take(subnet, 0, (idx // len(attach)) + 2),
                device_class=classes[idx],
                parent=parent,
                tier=3,
            )
        )
        topo.add_link(node.node_id, parent, access)

    for idx in range(n_attackers):
        parent = attach[idx % len(attach)]
        subnet = 10 + (attach.index(parent) % 40)
        node = topo.add_node(
            NetNode(
                node_id=f"atk-{idx:02d}",
                kind=NodeKind.ATTACKER,
                ip=ips.take(subnet, 9, (idx // len(attach)) + 2),
                device_class=attacker_classes[idx],
                parent=parent,
                tier=3,
            )
        )
        topo.add_link(node.node_id, parent, attacker_link)


def _add_cloud(topo: Topology, spec: Mapping[str, Any], ips: _IpAllocator) -> NetNode:
    """Create the single cloud node (tier 0) and register it on *topo*."""
    cloud_spec = spec.get("cloud", {}) or {}
    cloud = topo.add_node(
        NetNode(
            node_id=str(cloud_spec.get("id", "cloud-0")),
            kind=NodeKind.CLOUD,
            ip=str(cloud_spec.get("ip", ips.take(0, 0, 1))),
            forwarding_pps=float(cloud_spec.get("forwarding_pps", 60000.0)),
            proc_queue=int(cloud_spec.get("proc_queue", 2000)),
            tier=0,
        )
    )
    ips._used.add(cloud.ip)
    topo.cloud_id = cloud.node_id
    return cloud


def _add_gateway(
    topo: Topology, spec: Mapping[str, Any], ips: _IpAllocator, index: int = 0
) -> NetNode:
    """Create gateway *index* (tier 1) and register it on *topo*."""
    gw_spec = spec.get("gateway", {}) or {}
    node_id = str(gw_spec.get("id", "gw-0")) if index == 0 else f"gw-{index}"
    gateway = topo.add_node(
        NetNode(
            node_id=node_id,
            kind=NodeKind.GATEWAY,
            ip=ips.take(1, 1, index + 1),
            forwarding_pps=float(gw_spec.get("forwarding_pps", 20000.0)),
            proc_queue=int(gw_spec.get("proc_queue", 800)),
            tier=1,
        )
    )
    return gateway


def _add_router(
    topo: Topology,
    spec: Mapping[str, Any],
    ips: _IpAllocator,
    node_id: str,
    parent: str | None,
    *,
    octet_b: int = 0,
    octet_c: int = 1,
) -> NetNode:
    """Create a router (tier 2) and register it on *topo*."""
    router_spec = spec.get("routers", {}) or {}
    return topo.add_node(
        NetNode(
            node_id=node_id,
            kind=NodeKind.ROUTER,
            ip=ips.take(2, octet_b, octet_c),
            parent=parent,
            forwarding_pps=float(router_spec.get("forwarding_pps", 40000.0)),
            proc_queue=int(router_spec.get("proc_queue", 1200)),
            tier=2,
        )
    )


def _fleet_sizes(get: Callable[..., Any]) -> tuple[int, int]:
    """Return ``(n_iot, n_attackers)``, validated."""
    n_iot = int(get("simulation.n_iot_devices", 8))
    n_attackers = int(get("simulation.n_attackers", 0))
    if n_iot + n_attackers < 1:
        raise TopologyError("The fleet must contain at least one endpoint node.")
    return n_iot, n_attackers


# --------------------------------------------------------------------------- #
# families
# --------------------------------------------------------------------------- #
def build_star(config: Any) -> Topology:
    """Flat topology: one router carrying the whole fleet under one gateway."""
    get = config.get
    spec = get("network.topology", {}) or {}
    seed = int(get("seed", 42))
    n_iot, n_attackers = _fleet_sizes(get)

    topo = Topology(name="star")
    ips = _IpAllocator()
    cloud = _add_cloud(topo, spec, ips)
    gateway = _add_gateway(topo, spec, ips)
    topo.gateway_id = gateway.node_id
    topo.add_link(gateway.node_id, cloud.node_id, LinkSpec.from_mapping(spec["gateway"]["uplink"]))

    router = _add_router(topo, spec, ips, "rtr-0", gateway.node_id, octet_c=1)
    topo.add_link(router.node_id, gateway.node_id,
                  LinkSpec.from_mapping(spec["routers"]["uplink"]))

    _add_endpoints(
        topo, ips, [router.node_id], n_iot, n_attackers,
        LinkSpec.from_mapping(spec["access_link"]),
        _link(spec, "attacker_link", spec["access_link"]),
        get("traffic.device_mix", {}) or {}, seed,
    )

    topo.family = "star"
    topo.enforcement_nodes = [gateway.node_id]
    topo.uplink_keys = [(gateway.node_id, cloud.node_id)]
    topo.compute_routes()
    return topo


def build_multi_gateway(config: Any) -> Topology:
    """Several gateways, each with its own routers and share of the fleet.

    The fleet - legitimate and compromised alike - is spread round-robin across
    every access router of every gateway, so a botnet genuinely straddles
    enforcement domains. Each gateway gets its own uplink to the cloud, and all
    of them are enforcement points.
    """
    get = config.get
    spec = get("network.topology", {}) or {}
    seed = int(get("seed", 42))
    n_iot, n_attackers = _fleet_sizes(get)

    family_spec = spec.get("multi_gateway", {}) or {}
    n_gateways = int(family_spec.get("gateways", 3))
    per_gw = int(family_spec.get("routers_per_gateway", 2))
    if n_gateways < 2:
        raise TopologyError("multi_gateway needs at least 2 gateways.")
    if per_gw < 1:
        raise TopologyError("multi_gateway needs at least 1 router per gateway.")

    topo = Topology(name="multi-gateway")
    ips = _IpAllocator()
    cloud = _add_cloud(topo, spec, ips)

    uplink = LinkSpec.from_mapping(spec["gateway"]["uplink"])
    router_link = LinkSpec.from_mapping(spec["routers"]["uplink"])

    access_routers: list[str] = []
    gateway_ids: list[str] = []
    for g in range(n_gateways):
        gateway = _add_gateway(topo, spec, ips, index=g)
        gateway_ids.append(gateway.node_id)
        topo.add_link(gateway.node_id, cloud.node_id, uplink)
        for r in range(per_gw):
            router = _add_router(
                topo, spec, ips, f"rtr-{g}-{r}", gateway.node_id,
                octet_b=g, octet_c=r + 1,
            )
            topo.add_link(router.node_id, gateway.node_id, router_link)
            access_routers.append(router.node_id)

    topo.gateway_id = gateway_ids[0]
    _add_endpoints(
        topo, ips, access_routers, n_iot, n_attackers,
        LinkSpec.from_mapping(spec["access_link"]),
        _link(spec, "attacker_link", spec["access_link"]),
        get("traffic.device_mix", {}) or {}, seed,
    )

    topo.family = "multi_gateway"
    topo.enforcement_nodes = list(gateway_ids)
    topo.uplink_keys = [(g, cloud.node_id) for g in gateway_ids]
    topo.compute_routes()
    return topo


def build_dumbbell(config: Any) -> Topology:
    """Two router clusters joined by one constrained backbone span.

    Layout::

        endpoints -- edge routers -- gw-0 ==[backbone]== gw-1 -- cloud

    The backbone is deliberately narrower than either gateway uplink, so the
    bottleneck sits *between* two infrastructure nodes rather than at the edge.
    Enforcement stays at ``gw-0`` (the ingress gateway), which means the node
    that enforces is not the node that saturates - the case a tree cannot show.
    """
    get = config.get
    spec = get("network.topology", {}) or {}
    seed = int(get("seed", 42))
    n_iot, n_attackers = _fleet_sizes(get)

    family_spec = spec.get("dumbbell", {}) or {}
    n_edge = int(family_spec.get("edge_routers", 3))
    backbone_factor = float(family_spec.get("backbone_bandwidth_factor", 0.5))
    backbone_delay_factor = float(family_spec.get("backbone_delay_factor", 2.5))
    if n_edge < 1:
        raise TopologyError("dumbbell needs at least 1 edge router.")

    topo = Topology(name="dumbbell")
    ips = _IpAllocator()
    cloud = _add_cloud(topo, spec, ips)

    uplink = LinkSpec.from_mapping(spec["gateway"]["uplink"])
    ingress = _add_gateway(topo, spec, ips, index=0)
    egress = _add_gateway(topo, spec, ips, index=1)
    topo.gateway_id = ingress.node_id

    # The constrained span. Narrower and longer than the access side, so the
    # queue that fills under a volumetric attack is this one.
    topo.add_link(
        ingress.node_id, egress.node_id,
        _scaled(uplink, backbone_factor, backbone_delay_factor),
    )
    topo.add_link(egress.node_id, cloud.node_id, uplink)

    router_link = LinkSpec.from_mapping(spec["routers"]["uplink"])
    access_routers: list[str] = []
    for r in range(n_edge):
        router = _add_router(
            topo, spec, ips, f"rtr-{r}", ingress.node_id, octet_c=r + 1
        )
        topo.add_link(router.node_id, ingress.node_id, router_link)
        access_routers.append(router.node_id)

    _add_endpoints(
        topo, ips, access_routers, n_iot, n_attackers,
        LinkSpec.from_mapping(spec["access_link"]),
        _link(spec, "attacker_link", spec["access_link"]),
        get("traffic.device_mix", {}) or {}, seed,
    )

    topo.family = "dumbbell"
    topo.enforcement_nodes = [ingress.node_id]
    topo.uplink_keys = [(ingress.node_id, egress.node_id)]
    topo.compute_routes()
    return topo


def build_fat_tree(config: Any) -> Topology:
    """Core / aggregation / edge fabric with dual-homed edge routers.

    Every edge router connects to two aggregation routers, and every
    aggregation router to the gateway, so there are genuinely multiple equal-cost
    paths from a device to the cloud. Aggregation and edge routers are both
    ``tier == 2``: tier encodes role, not hop count.
    """
    get = config.get
    spec = get("network.topology", {}) or {}
    seed = int(get("seed", 42))
    n_iot, n_attackers = _fleet_sizes(get)

    family_spec = spec.get("fat_tree", {}) or {}
    n_agg = int(family_spec.get("aggregation", 2))
    n_edge = int(family_spec.get("edge", 4))
    if n_agg < 2:
        raise TopologyError("fat_tree needs at least 2 aggregation routers.")
    if n_edge < 1:
        raise TopologyError("fat_tree needs at least 1 edge router.")

    topo = Topology(name="fat-tree")
    ips = _IpAllocator()
    cloud = _add_cloud(topo, spec, ips)
    gateway = _add_gateway(topo, spec, ips)
    topo.gateway_id = gateway.node_id
    topo.add_link(gateway.node_id, cloud.node_id,
                  LinkSpec.from_mapping(spec["gateway"]["uplink"]))

    router_link = LinkSpec.from_mapping(spec["routers"]["uplink"])
    # Aggregation tier sits above the edge tier, so give it more capacity.
    agg_link = _scaled(router_link, float(family_spec.get("aggregation_bandwidth_factor", 2.0)))

    agg_ids: list[str] = []
    for a in range(n_agg):
        agg = _add_router(topo, spec, ips, f"agg-{a}", gateway.node_id,
                          octet_b=200, octet_c=a + 1)
        topo.add_link(agg.node_id, gateway.node_id, agg_link)
        agg_ids.append(agg.node_id)

    access_routers: list[str] = []
    for e in range(n_edge):
        edge = _add_router(topo, spec, ips, f"rtr-{e}", agg_ids[e % n_agg],
                           octet_b=0, octet_c=e + 1)
        # Dual-home: primary plus the next aggregation router round-robin.
        topo.add_link(edge.node_id, agg_ids[e % n_agg], router_link)
        topo.add_link(edge.node_id, agg_ids[(e + 1) % n_agg], router_link)
        access_routers.append(edge.node_id)

    _add_endpoints(
        topo, ips, access_routers, n_iot, n_attackers,
        LinkSpec.from_mapping(spec["access_link"]),
        _link(spec, "attacker_link", spec["access_link"]),
        get("traffic.device_mix", {}) or {}, seed,
    )

    topo.family = "fat_tree"
    topo.enforcement_nodes = [gateway.node_id]
    topo.uplink_keys = [(gateway.node_id, cloud.node_id)]
    topo.compute_routes()
    return topo


def _build_ringlike(config: Any, family: str) -> Topology:
    """Shared construction for the ``ring`` and ``mesh`` families.

    Both wire the access routers into a ring; ``mesh`` additionally adds a
    deterministic set of chords, which is what creates alternative shortest
    paths for the BFS routing table to choose between.
    """
    get = config.get
    spec = get("network.topology", {}) or {}
    seed = int(get("seed", 42))
    n_iot, n_attackers = _fleet_sizes(get)

    family_spec = spec.get(family, {}) or {}
    n_routers = int(family_spec.get("routers", 5))
    if n_routers < 3:
        raise TopologyError(f"{family} needs at least 3 routers to form a ring.")

    topo = Topology(name=family.replace("_", "-"))
    ips = _IpAllocator()
    cloud = _add_cloud(topo, spec, ips)
    gateway = _add_gateway(topo, spec, ips)
    topo.gateway_id = gateway.node_id
    topo.add_link(gateway.node_id, cloud.node_id,
                  LinkSpec.from_mapping(spec["gateway"]["uplink"]))

    router_link = LinkSpec.from_mapping(spec["routers"]["uplink"])
    # Inter-router spans are the ring itself; keep them at the router rate but
    # slightly longer, so a two-hop ring path is measurably worse than one hop.
    span = _scaled(router_link, 1.0, float(family_spec.get("span_delay_factor", 1.5)))

    router_ids: list[str] = []
    for r in range(n_routers):
        router = _add_router(topo, spec, ips, f"rtr-{r}", gateway.node_id, octet_c=r + 1)
        router_ids.append(router.node_id)

    # Close the ring.
    for r in range(n_routers):
        topo.add_link(router_ids[r], router_ids[(r + 1) % n_routers], span)

    # Attach the ring to the gateway. A ring hangs off the gateway at a single
    # point (that is its weakness); a mesh is multi-homed.
    attach_points = 1 if family == "ring" else max(2, n_routers // 2)
    step = max(1, n_routers // attach_points)
    for i in range(attach_points):
        topo.add_link(router_ids[(i * step) % n_routers], gateway.node_id, router_link)

    if family == "mesh":
        # Deterministic chords across the ring create the alternative paths.
        extra = int(family_spec.get("extra_links", max(1, n_routers // 2)))
        rng = rng_for(seed, "mesh_chords")
        added: set[tuple[str, str]] = set()
        attempts = 0
        while len(added) < extra and attempts < extra * 20:
            attempts += 1
            a = int(rng.integers(0, n_routers))
            b = int(rng.integers(0, n_routers))
            if a == b:
                continue
            lo, hi = sorted((router_ids[a], router_ids[b]))
            if (lo, hi) in added or (lo, hi) in topo.channels:
                continue
            added.add((lo, hi))
            topo.add_link(lo, hi, span)

    _add_endpoints(
        topo, ips, router_ids, n_iot, n_attackers,
        LinkSpec.from_mapping(spec["access_link"]),
        _link(spec, "attacker_link", spec["access_link"]),
        get("traffic.device_mix", {}) or {}, seed,
    )

    topo.family = family
    topo.enforcement_nodes = [gateway.node_id]
    topo.uplink_keys = [(gateway.node_id, cloud.node_id)]
    topo.compute_routes()
    return topo


def build_mesh(config: Any) -> Topology:
    """Access routers in a ring plus chords, multi-homed to the gateway."""
    return _build_ringlike(config, "mesh")


def build_ring(config: Any) -> Topology:
    """Access routers in a ring, attached to the gateway at a single point."""
    return _build_ringlike(config, "ring")


#: Dispatch table consumed by :func:`build_family_topology`.
BUILDERS: dict[str, Callable[[Any], Topology]] = {
    "star": build_star,
    "multi_gateway": build_multi_gateway,
    "dumbbell": build_dumbbell,
    "fat_tree": build_fat_tree,
    "mesh": build_mesh,
    "ring": build_ring,
}


# --------------------------------------------------------------------------- #
# validation
# --------------------------------------------------------------------------- #
def validate_topology(topo: Topology) -> Topology:
    """Assert the structural invariants every family must honour.

    Args:
        topo: A freshly built topology.

    Returns:
        The same topology, unchanged.

    Raises:
        TopologyError: If any invariant is violated.
    """
    clouds = [n for n in topo.nodes.values() if n.kind is NodeKind.CLOUD]
    if len(clouds) != 1:
        raise TopologyError(f"Expected exactly one cloud node, found {len(clouds)}.")
    if clouds[0].tier != 0:
        raise TopologyError("The cloud node must be tier 0.")
    if not topo.cloud_id or topo.cloud_id not in topo.nodes:
        raise TopologyError("topo.cloud_id must name an existing node.")

    gateways = topo.gateways()
    if not gateways:
        raise TopologyError("A topology must have at least one gateway.")
    if any(g.tier != 1 for g in gateways):
        raise TopologyError("Every gateway must be tier 1.")
    if topo.gateway_id not in {g.node_id for g in gateways}:
        raise TopologyError("topo.gateway_id must name a gateway node.")

    for node in topo.nodes.values():
        if node.kind is NodeKind.ROUTER and node.tier != 2:
            raise TopologyError(f"Router {node.node_id} must be tier 2.")
        if node.kind.is_endpoint and node.tier != 3:
            raise TopologyError(f"Endpoint {node.node_id} must be tier 3.")

    if not topo.enforcement_nodes:
        raise TopologyError("enforcement_nodes must not be empty.")
    gateway_ids = {g.node_id for g in gateways}
    for node_id in topo.enforcement_nodes:
        if node_id not in gateway_ids:
            raise TopologyError(
                f"Enforcement node {node_id!r} is not a gateway."
            )

    if not topo.uplink_keys:
        raise TopologyError("uplink_keys must not be empty.")
    for key in topo.uplink_keys:
        if key not in topo.channels:
            raise TopologyError(f"Uplink {key} is not an existing channel.")

    # Routing must actually reach the cloud from every endpoint, otherwise the
    # traffic model silently drops everything with "no_route".
    for node in topo.nodes.values():
        if node.kind.is_endpoint:
            if (node.node_id, topo.cloud_id) not in topo.next_hop:
                raise TopologyError(
                    f"No route from {node.node_id} to the cloud; "
                    "did the builder forget compute_routes()?"
                )
    return topo


def build_family_topology(family: str, config: Any) -> Topology:
    """Build and validate the topology for *family*.

    Args:
        family: One of :data:`TOPOLOGY_FAMILIES` (other than ``"tree"``, which
            is built by :func:`netshield.simulation.topology.build_tree_topology`).
        config: The project configuration.

    Returns:
        A validated, fully routed topology.

    Raises:
        TopologyError: If the family is unknown or the result is malformed.
    """
    builder = BUILDERS.get(family)
    if builder is None:
        raise TopologyError(
            f"Unknown topology family {family!r}. "
            f"Available: {', '.join(sorted(TOPOLOGY_FAMILIES))}"
        )
    topo = validate_topology(builder(config))
    _LOG.info(
        "Topology '%s' (family=%s): %d nodes, %d links, %d gateway(s), "
        "%d enforcement point(s), %d uplink(s)",
        topo.name, topo.family, len(topo.nodes), len(topo.channels) // 2,
        len(topo.gateways()), len(topo.enforcement_nodes), len(topo.uplink_keys),
    )
    return topo


__all__ = [
    "TOPOLOGY_FAMILIES",
    "FAMILY_DESCRIPTIONS",
    "TopologyError",
    "build_family_topology",
    "validate_topology",
    "build_star",
    "build_multi_gateway",
    "build_dumbbell",
    "build_fat_tree",
    "build_mesh",
    "build_ring",
    "BUILDERS",
]
