"""Export mitigation decisions as deployable data-plane rules.

The simulator enforces rules inside its own packet path. A real deployment
needs the same decisions expressed for real equipment. This module renders a
:class:`~netshield.mitigation.policy.MitigationAction` (or its dict form) for
three targets:

``openflow``
    ``ovs-ofctl`` commands for Open vSwitch (OpenFlow 1.3): a meter for
    rate-limits and a high-priority drop flow for blocks/isolation, matched
    on the **ingress port** of the gateway switch - the same identity the
    simulator keys on, so spoofed source addresses cannot dodge the rule.
``nftables``
    ``nft`` commands for a Linux gateway: an ingress-interface ``limit``
    or ``drop`` rule in a dedicated ``netshield`` table.
``p4runtime``
    Table-entry dictionaries for a P4 ``ingress_acl`` table with
    ``meter``/``drop`` actions, as a P4Runtime client would write them.

Releases render as the matching delete commands. Rendering is pure string
construction: nothing here talks to a switch, which keeps it safe to unit
test and lets an operator review rules before applying them.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

#: OpenFlow priority of NetShield rules (above learning-switch defaults).
OF_PRIORITY = 40000
_ACTING = {"rate_limit", "block", "isolate"}


@dataclass(slots=True)
class PortMap:
    """Maps NetShield node ids to switch ingress ports / interfaces.

    Attributes:
        bridge: OVS bridge name of the gateway switch.
        ports: ``{node_id: openflow_port_number}``.
        interfaces: ``{node_id: linux_interface}`` for nftables.
        cookie_base: Base cookie so NetShield flows can be listed/flushed.
    """

    bridge: str = "gw0"
    ports: Mapping[str, int] | None = None
    interfaces: Mapping[str, str] | None = None
    cookie_base: int = 0x4E530000  # "NS"
    #: Optional per-node bridge override: per-device enforcement happens at
    #: the access switch the device is plugged into, not at the gateway.
    bridges: Mapping[str, str] | None = None

    def bridge_of(self, node: str) -> str:
        return str((self.bridges or {}).get(node, self.bridge))

    def port(self, node: str) -> int:
        if not self.ports or node not in self.ports:
            raise KeyError(f"No switch port mapped for node {node!r}")
        return int(self.ports[node])

    def iface(self, node: str) -> str:
        if not self.interfaces or node not in self.interfaces:
            raise KeyError(f"No interface mapped for node {node!r}")
        return str(self.interfaces[node])

    def meter_id(self, node: str) -> int:
        return 1000 + self.port(node)

    def cookie(self, node: str) -> str:
        return hex(self.cookie_base + self.port(node))


def _as_dict(action: Any) -> dict[str, Any]:
    if isinstance(action, Mapping):
        out = dict(action)
    else:
        out = action.to_dict()
    out["action"] = str(getattr(out["action"], "value", out["action"]))
    return out


def to_openflow(action: Any, ports: PortMap, rate_pps: float = 60.0,
                burst: int = 30) -> list[str]:
    """Render one action as ``ovs-ofctl -O OpenFlow13`` commands."""
    a = _as_dict(action)
    node, kind = a["node"], a["action"]
    port, br, cookie = ports.port(node), ports.bridge_of(node), ports.cookie(node)
    match = f"in_port={port}"
    if kind == "rate_limit":
        mid = ports.meter_id(node)
        return [
            f"ovs-ofctl -O OpenFlow13 add-meter {br} "
            f"meter={mid},pktps,burst,bands=type=drop,rate={int(rate_pps)},burst_size={burst}",
            f"ovs-ofctl -O OpenFlow13 add-flow {br} "
            f"cookie={cookie},priority={OF_PRIORITY},{match},"
            f"actions=meter:{mid},NORMAL",
        ]
    if kind in ("block", "isolate"):
        return [f"ovs-ofctl -O OpenFlow13 add-flow {br} "
                f"cookie={cookie},priority={OF_PRIORITY + 10},{match},actions=drop"]
    if kind == "release":
        return [f"ovs-ofctl -O OpenFlow13 del-flows {br} cookie={cookie}/-1,{match}",
                f"ovs-ofctl -O OpenFlow13 del-meter {br} meter={ports.meter_id(node)}"]
    return []


def to_nftables(action: Any, ports: PortMap, rate_pps: float = 60.0,
                burst: int = 30) -> list[str]:
    """Render one action as ``nft`` commands (table ``inet netshield``)."""
    a = _as_dict(action)
    node, kind = a["node"], a["action"]
    iface = ports.iface(node)
    handle = f"ns_{node.replace('-', '_')}"
    setup = ["nft add table inet netshield",
             "nft 'add chain inet netshield ingress "
             "{ type filter hook forward priority -10 ; policy accept ; }'"]
    if kind == "rate_limit":
        return setup + [f"nft add rule inet netshield ingress iifname \"{iface}\" "
                        f"limit rate over {int(rate_pps)}/second burst {burst} packets "
                        f"drop comment \"{handle}\""]
    if kind in ("block", "isolate"):
        return setup + [f"nft add rule inet netshield ingress iifname \"{iface}\" "
                        f"drop comment \"{handle}\""]
    if kind == "release":
        return [f"nft -a list chain inet netshield ingress | awk '/\"{handle}\"/ "
                f"{{print $NF}}' | xargs -r -I{{}} nft delete rule inet netshield ingress "
                f"handle {{}}"]
    return []


def to_p4runtime(action: Any, ports: PortMap, rate_pps: float = 60.0) -> list[dict]:
    """Render one action as P4Runtime-style ``ingress_acl`` table entries."""
    a = _as_dict(action)
    node, kind = a["node"], a["action"]
    entry = {"table": "MyIngress.ingress_acl",
             "match": {"standard_metadata.ingress_port": ports.port(node)},
             "priority": OF_PRIORITY}
    if kind == "rate_limit":
        return [{**entry, "type": "INSERT", "action": "MyIngress.meter_and_forward",
                 "params": {"meter_index": ports.meter_id(node)},
                 "meter_config": {"cir_pps": int(rate_pps), "pir_pps": int(rate_pps * 1.5)}}]
    if kind in ("block", "isolate"):
        return [{**entry, "type": "INSERT", "action": "MyIngress.drop", "params": {}}]
    if kind == "release":
        return [{**entry, "type": "DELETE"}]
    return []


def render(actions: Iterable[Any], target: str, ports: PortMap, rate_pps: float = 60.0,
           burst: int = 30) -> list[Any]:
    """Render a mitigation log for *target* (``openflow``/``nftables``/``p4runtime``).

    Escalations replace the earlier rule for the same node (a delete is
    emitted first), so applying the output in order leaves exactly one
    NetShield rule per node.
    """
    out: list[Any] = []
    active: dict[str, str] = {}
    for raw in actions:
        a = _as_dict(raw)
        node, kind = a["node"], a["action"]
        if kind in _ACTING and node in active:
            release = {**a, "action": "release"}
            out += _render_one(release, target, ports, rate_pps, burst)
        if kind in _ACTING:
            active[node] = kind
        elif kind == "release":
            active.pop(node, None)
        out += _render_one(a, target, ports, rate_pps, burst)
    return out


def _render_one(a: Mapping[str, Any], target: str, ports: PortMap, rate_pps: float,
                burst: int) -> list[Any]:
    if target == "openflow":
        return to_openflow(a, ports, rate_pps, burst)
    if target == "nftables":
        return to_nftables(a, ports, rate_pps, burst)
    if target == "p4runtime":
        return to_p4runtime(a, ports, rate_pps)
    raise ValueError(f"Unknown export target {target!r}")


def write_script(actions: Iterable[Any], target: str, ports: PortMap, path: str) -> str:
    """Write rendered rules to *path* (shell script or JSON lines for P4)."""
    rules = render(actions, target, ports)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        if target == "p4runtime":
            for rule in rules:
                fh.write(json.dumps(rule) + "\n")
        else:
            fh.write("#!/bin/sh\nset -e\n# NetShield-GNN mitigation export\n")
            fh.write("\n".join(rules) + "\n")
    return path
