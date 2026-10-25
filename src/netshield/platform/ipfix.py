"""IPFIX (RFC 7011) encoding and decoding of NetShield flow records.

A deployed collector receives flow records from switches and probes over
IPFIX rather than reading the simulator's CSV files. This module defines one
template that carries everything the node-window features need and converts
in both directions, so the streaming pipeline can be fed by a real exporter
(Open vSwitch, nProbe, YAF) or by the simulator replaying a run.

Template 256 (field, IE id, length)::

    sourceIPv4Address          8   4     destinationIPv4Address    12   4
    sourceTransportPort        7   2     destinationTransportPort  11   2
    protocolIdentifier         4   1     packetDeltaCount           2   8
    octetDeltaCount            1   8     flowStartMilliseconds    152   8
    flowEndMilliseconds      153   8     minimumIpTotalLength      25   8
    maximumIpTotalLength      26   8
    -- enterprise 32473 (RFC 5612 documentation PEN) --
    synCount 1 / synAckCount 2 / ackCount 3 / finCount 4 / rstCount 5 /
    pshCount 6 (4 bytes each); packetSizeVariance 7, meanInterArrival 8,
    interArrivalStd 9, payloadOctets 10 (8 bytes each, float64 / uint64)

Standard exporters do not send the enterprise fields; the decoder then
leaves them at zero and the feature builder still runs (with less signal).
"""

from __future__ import annotations

import ipaddress
import struct
import time
from typing import Any, Iterable, Mapping

VERSION = 10
TEMPLATE_ID = 256
PEN = 32473
TEMPLATE_SET_ID = 2

# (name, ie, length, enterprise, kind)  kind: ip|u|f
FIELDS: tuple[tuple[str, int, int, bool, str], ...] = (
    ("src_ip", 8, 4, False, "ip"), ("dst_ip", 12, 4, False, "ip"),
    ("src_port", 7, 2, False, "u"), ("dst_port", 11, 2, False, "u"),
    ("protocol", 4, 1, False, "u"), ("packets", 2, 8, False, "u"),
    ("bytes", 1, 8, False, "u"), ("start_ms", 152, 8, False, "u"),
    ("end_ms", 153, 8, False, "u"), ("min_packet_size", 25, 8, False, "u"),
    ("max_packet_size", 26, 8, False, "u"), ("ingress_port", 10, 4, False, "u"),
    ("syn_count", 1, 4, True, "u"), ("syn_ack_count", 2, 4, True, "u"),
    ("ack_count", 3, 4, True, "u"), ("fin_count", 4, 4, True, "u"),
    ("rst_count", 5, 4, True, "u"), ("psh_count", 6, 4, True, "u"),
    ("packet_size_var", 7, 8, True, "f"), ("mean_iat", 8, 8, True, "f"),
    ("iat_std", 9, 8, True, "f"), ("payload_bytes", 10, 8, True, "u"),
)
_UFMT = {1: "B", 2: "H", 4: "I", 8: "Q"}


class IPFIXError(ValueError):
    """Malformed or unsupported IPFIX message."""


def _template_set(fields: Iterable[tuple[str, int, int, bool, str]] = FIELDS) -> bytes:
    fields = list(fields)
    body = struct.pack("!HH", TEMPLATE_ID, len(fields))
    for _, ie, length, ent, _k in fields:
        if ent:
            body += struct.pack("!HHI", ie | 0x8000, length, PEN)
        else:
            body += struct.pack("!HH", ie, length)
    return struct.pack("!HH", TEMPLATE_SET_ID, 4 + len(body)) + body


def _record(row: Mapping[str, Any], base_ms: int, window_s: float,
            port_of: Mapping[str, int] | None = None) -> bytes:
    start = base_ms + int(round(float(row.get("t_start", 0.0)) * 1000))
    duration = float(row.get("duration", 0.0) or 0.0)
    values = {**row, "start_ms": start,
              "end_ms": start + int(round(min(duration, window_s) * 1000)),
              "ingress_port": (port_of or {}).get(str(row.get("src_node", "")), 0)}
    out = b""
    for name, _ie, length, _ent, kind in FIELDS:
        v = values.get(name, 0) or 0
        if kind == "ip":
            out += ipaddress.IPv4Address(str(v) if v else "0.0.0.0").packed
        elif kind == "f":
            out += struct.pack("!d", float(v))
        else:
            out += struct.pack("!" + _UFMT[length], max(0, int(round(float(v)))))
    return out


def encode(rows: Iterable[Mapping[str, Any]], window_s: float = 5.0, sequence: int = 0,
           domain: int = 1, base_ms: int | None = None, include_template: bool = True,
           max_records: int = 40, port_of: Mapping[str, int] | None = None) -> list[bytes]:
    """Encode flow rows into one or more IPFIX messages (<= 1400 bytes each)."""
    base_ms = int(time.time() * 1000) if base_ms is None else int(base_ms)
    rows = list(rows)
    messages = []
    for i in range(0, max(1, len(rows)), max_records):
        chunk = rows[i:i + max_records]
        sets = _template_set() if include_template and i == 0 else b""
        if chunk:
            records = b"".join(_record(r, base_ms, window_s, port_of) for r in chunk)
            sets += struct.pack("!HH", TEMPLATE_ID, 4 + len(records)) + records
        header = struct.pack("!HHIII", VERSION, 16 + len(sets), int(base_ms // 1000),
                             sequence + i, domain)
        messages.append(header + sets)
    return messages


class Decoder:
    """Stateful decoder: remembers templates per observation domain."""

    def __init__(self) -> None:
        self.templates: dict[tuple[int, int], list[tuple[int, int, int | None]]] = {}

    def decode(self, message: bytes) -> list[dict[str, Any]]:
        if len(message) < 16:
            raise IPFIXError("short message")
        version, length, _export, _seq, domain = struct.unpack("!HHIII", message[:16])
        if version != VERSION:
            raise IPFIXError(f"not IPFIX (version {version})")
        if length != len(message):
            raise IPFIXError("length mismatch")
        out: list[dict[str, Any]] = []
        offset = 16
        while offset + 4 <= length:
            set_id, set_len = struct.unpack("!HH", message[offset:offset + 4])
            if set_len < 4 or offset + set_len > length:
                raise IPFIXError("bad set length")
            body = message[offset + 4:offset + set_len]
            if set_id == TEMPLATE_SET_ID:
                self._templates(domain, body)
            elif set_id >= 256:
                out += self._data(domain, set_id, body)
            offset += set_len
        return out

    def _templates(self, domain: int, body: bytes) -> None:
        pos = 0
        while pos + 4 <= len(body):
            tid, count = struct.unpack("!HH", body[pos:pos + 4])
            pos += 4
            fields = []
            for _ in range(count):
                ie, length = struct.unpack("!HH", body[pos:pos + 4])
                pos += 4
                pen = None
                if ie & 0x8000:
                    pen = struct.unpack("!I", body[pos:pos + 4])[0]
                    pos += 4
                    ie &= 0x7FFF
                fields.append((ie, length, pen))
            self.templates[(domain, tid)] = fields

    def _data(self, domain: int, set_id: int, body: bytes) -> list[dict[str, Any]]:
        template = self.templates.get((domain, set_id))
        if template is None:
            return []              # data before template: dropped, per RFC 7011 s8
        lookup = {(ie, PEN if ent else None): (name, kind) for name, ie, _l, ent, kind in FIELDS}
        size = sum(length for _, length, _ in template)
        rows = []
        for start in range(0, len(body) - size + 1, size):
            pos = start
            row: dict[str, Any] = {}
            for ie, length, pen in template:
                raw = body[pos:pos + length]
                pos += length
                key = lookup.get((ie, pen))
                if key is None:
                    continue
                name, kind = key
                if kind == "ip":
                    row[name] = str(ipaddress.IPv4Address(raw))
                elif kind == "f":
                    row[name] = struct.unpack("!d", raw)[0]
                else:
                    row[name] = int.from_bytes(raw, "big")
            rows.append(row)
        return rows


def to_flow_rows(records: Iterable[Mapping[str, Any]], node_of: Mapping[str, str],
                 window_s: float = 5.0, base_ms: int = 0,
                 node_of_port: Mapping[int, str] | None = None) -> list[dict[str, Any]]:
    """Turn decoded IPFIX records into NetShield flow rows.

    Args:
        records: Output of :meth:`Decoder.decode`.
        node_of: Address-to-node inventory (from the asset database / DHCP).
            Unknown addresses map to ``cloud-0``.
        window_s: Feature window length.
        base_ms: Epoch milliseconds that maps to window 0.
        node_of_port: Ingress-interface-to-node inventory. When the exporter
            reports ``ingressInterface``, the source node is taken from the
            physical port, so spoofed source addresses are still attributed
            to the device that sent them.
    """
    rows = []
    for r in records:
        t = (int(r.get("start_ms", 0)) - base_ms) / 1000.0
        window = int(t // window_s)
        packets = int(r.get("packets", 0))
        nbytes = int(r.get("bytes", 0))
        duration = max(0.0, (int(r.get("end_ms", 0)) - int(r.get("start_ms", 0))) / 1000.0)
        rows.append({
            "window": window, "t_start": window * window_s, "t_end": (window + 1) * window_s,
            "src_node": (node_of_port or {}).get(int(r.get("ingress_port", 0) or 0))
            or node_of.get(r.get("src_ip", ""), "cloud-0"),
            "dst_node": node_of.get(r.get("dst_ip", ""), "cloud-0"),
            "src_ip": r.get("src_ip", ""), "dst_ip": r.get("dst_ip", ""),
            "src_port": int(r.get("src_port", 0)), "dst_port": int(r.get("dst_port", 0)),
            "protocol": int(r.get("protocol", 0)), "app": "ipfix",
            "packets": packets, "bytes": nbytes,
            "payload_bytes": int(r.get("payload_bytes", 0)), "duration": duration,
            "packet_rate": packets / window_s, "byte_rate": nbytes / window_s,
            "mean_packet_size": nbytes / packets if packets else 0.0,
            "packet_size_var": float(r.get("packet_size_var", 0.0)),
            "min_packet_size": int(r.get("min_packet_size", 0)),
            "max_packet_size": int(r.get("max_packet_size", 0)),
            "mean_iat": float(r.get("mean_iat", 0.0)), "iat_std": float(r.get("iat_std", 0.0)),
            **{k: int(r.get(k, 0)) for k in ("syn_count", "syn_ack_count", "ack_count",
                                              "fin_count", "rst_count", "psh_count")},
            "delivered": 0, "dropped": 0, "retransmits": 0, "attack_packets": 0,
            "attack_ratio": 0.0, "attack_type": "",
        })
    return rows
