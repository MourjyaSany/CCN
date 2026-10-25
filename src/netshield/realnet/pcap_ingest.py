"""Offline ingestion of real packet captures into the NetShield feature pipeline.

This is how the detectors trained in simulation are tested on *real* traffic
(for example the CICIoT2023 captures). It never opens a socket: captures are
read from disk with ``dpkt``, a pure parser.

Method
------
Every IPv4 packet in the capture is converted into a
:class:`~netshield.simulation.packet.Packet` and fed to the simulator's own
:class:`~netshield.simulation.telemetry.TelemetryCollector`. The resulting
flow records therefore have exactly the schema the models were trained on,
and :func:`~netshield.features.node_features.build_node_window_features`
turns them into node-window rows through the same code path as the live
controller. Nothing is re-implemented for real data, so any gap in
performance is a property of the traffic, not of a second feature pipeline.

Topology inference
------------------
A capture has no topology, so a minimal edge topology is inferred:

* every private (RFC 1918) address becomes an endpoint ``h-<ip>`` attached to
  one access router ``rtr-0``, under gateway ``gw-0``;
* every other address is folded into the upstream node ``cloud-0``.

Labels
------
Public captures label whole files ("this capture is a SYN flood"), not
hosts. All rows are therefore emitted as BENIGN with ``is_attacker=False``;
evaluation is done at capture and window level (see
``scripts/real_data_eval.py``) and the benign capture gives a clean
false-positive measurement on real IoT traffic.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from ..simulation.packet import Packet, Protocol, TCPFlag
from ..simulation.telemetry import TelemetryCollector


def _inet_ntoa(raw: bytes) -> str:
    """Format a 4-byte IPv4 address without touching any socket API."""
    return str(ipaddress.IPv4Address(raw))

_PRIVATE = (ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"))


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _PRIVATE)


@dataclass(slots=True)
class CaptureView:
    """A :class:`SimulationResult`-shaped view of one real capture."""

    run_id: str
    meta: dict[str, Any]
    engine: str
    topology: dict[str, Any]
    summary: dict[str, Any]
    flows: list[dict[str, Any]]


def _reader(handle: Any) -> Iterator[tuple[float, bytes]]:
    import dpkt  # noqa: PLC0415 - optional dependency for real-data evaluation

    magic = handle.read(4)
    handle.seek(0)
    reader = dpkt.pcapng.Reader(handle) if magic == b"\x0a\x0d\x0d\x0a" else \
        dpkt.pcap.Reader(handle)
    iterator = iter(reader)
    while True:
        try:
            yield next(iterator)
        except StopIteration:
            return
        except (dpkt.NeedData, dpkt.UnpackError, ValueError):
            # A range-downloaded capture ends mid-record; stop cleanly there.
            return


def ingest_pcap(
    path: str | Path,
    window_s: float = 5.0,
    max_packets: int | None = 3_000_000,
    max_seconds: float | None = None,
    run_id: str | None = None,
) -> CaptureView:
    """Convert a capture into a feature-pipeline view.

    Args:
        path: ``.pcap`` or ``.pcapng`` file.
        window_s: Feature window length, matching the trained models.
        max_packets: Stop after this many IPv4 packets (bounds run time).
        max_seconds: Stop after this much capture time.
        run_id: Identifier for the produced rows (default: file stem).

    Returns:
        A :class:`CaptureView` ready for
        :func:`~netshield.features.node_features.build_node_window_features`.
    """
    import dpkt  # noqa: PLC0415

    path = Path(path)
    collector = TelemetryCollector(window_s=window_s)
    hosts: dict[str, str] = {}
    t0: float | None = None
    count = 0
    skipped = 0

    def node_of(ip: str) -> str:
        if ip in hosts:
            return hosts[ip]
        node = f"h-{ip}" if _is_private(ip) else "cloud-0"
        hosts[ip] = node
        return node

    with path.open("rb") as handle:
        for ts, buf in _reader(handle):
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except (dpkt.UnpackError, ValueError):
                skipped += 1
                continue
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                skipped += 1
                continue
            if t0 is None:
                t0 = float(ts)
            t = float(ts) - t0
            if max_seconds is not None and t > max_seconds:
                break
            src_ip, dst_ip = _inet_ntoa(ip.src), _inet_ntoa(ip.dst)
            l4 = ip.data
            sport = dport = flags = 0
            payload = 0
            if ip.p == dpkt.ip.IP_PROTO_TCP and isinstance(l4, dpkt.tcp.TCP):
                proto, sport, dport = Protocol.TCP, l4.sport, l4.dport
                payload = len(l4.data)
                f = l4.flags
                flags = int((TCPFlag.SYN if f & dpkt.tcp.TH_SYN else 0)
                            | (TCPFlag.ACK if f & dpkt.tcp.TH_ACK else 0)
                            | (TCPFlag.FIN if f & dpkt.tcp.TH_FIN else 0)
                            | (TCPFlag.RST if f & dpkt.tcp.TH_RST else 0)
                            | (TCPFlag.PSH if f & dpkt.tcp.TH_PUSH else 0))
            elif ip.p == dpkt.ip.IP_PROTO_UDP and isinstance(l4, dpkt.udp.UDP):
                proto, sport, dport = Protocol.UDP, l4.sport, l4.dport
                payload = len(l4.data)
            elif ip.p == dpkt.ip.IP_PROTO_ICMP:
                proto = Protocol.ICMP
                payload = max(0, len(ip) - ip.hl * 4 - 8)
            else:
                skipped += 1
                continue
            src, dst = node_of(src_ip), node_of(dst_ip)
            if src == dst:          # e.g. two external hosts folded into cloud-0
                continue
            packet = Packet(pid=count, t_gen=t, src=src, dst=dst, src_ip=src_ip,
                            dst_ip=dst_ip, sport=int(sport), dport=int(dport),
                            protocol=int(proto), size=len(ip) + 14, payload=int(payload),
                            flags=flags, app="real")
            collector.on_generate(packet)
            count += 1
            if max_packets is not None and count >= max_packets:
                break

    duration = 0.0 if not collector.windows else (max(collector.windows) + 1) * window_s
    collector.truncate_to(duration - 1e-9 if duration else 0.0)

    endpoints = sorted({n for n in hosts.values() if n != "cloud-0"})
    nodes = [
        {"node_id": "cloud-0", "kind": "cloud", "ip": "0.0.0.0", "device_class": "",
         "parent": None, "tier": 0, "is_attacker": False},
        {"node_id": "gw-0", "kind": "gateway", "ip": "", "device_class": "",
         "parent": "cloud-0", "tier": 1, "is_attacker": False},
        {"node_id": "rtr-0", "kind": "router", "ip": "", "device_class": "",
         "parent": "gw-0", "tier": 2, "is_attacker": False},
    ] + [{"node_id": n, "kind": "iot", "ip": n[2:], "device_class": "real",
          "parent": "rtr-0", "tier": 3, "is_attacker": False} for n in endpoints]
    links = [{"source": "cloud-0", "target": "gw-0"}, {"source": "gw-0", "target": "rtr-0"}]
    links += [{"source": "rtr-0", "target": n} for n in endpoints]
    topology = {"name": f"inferred:{path.stem}", "family": "inferred", "cloud": "cloud-0",
                "gateway": "gw-0", "gateways": ["gw-0"], "enforcement_nodes": ["gw-0"],
                "uplinks": [{"source": "gw-0", "target": "cloud-0"}],
                "n_nodes": len(nodes), "n_links": len(links), "nodes": nodes, "links": links}
    summary = {"window_s": window_s, "attack": {"enabled": False}, "packets": count,
               "skipped_frames": skipped, "hosts": len(endpoints),
               "duration_s": duration}
    rid = run_id or f"real_{path.stem}"
    return CaptureView(run_id=rid, meta={"experiment": rid}, engine="real-capture",
                       topology=topology, summary=summary, flows=collector.flow_rows())
