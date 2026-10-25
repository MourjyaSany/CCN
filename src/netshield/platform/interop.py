"""Alert interoperability: STIX 2.1 bundles and CEF syslog lines.

Mapping to MITRE ATT&CK (Enterprise, v15):

=============== ============================================================
NetShield       ATT&CK technique
=============== ============================================================
udp_flood       T1498.001  Network Denial of Service: Direct Network Flood
icmp_flood      T1498.001  Network Denial of Service: Direct Network Flood
ack_flood       T1498.001  Network Denial of Service: Direct Network Flood
syn_flood       T1499.001  Endpoint Denial of Service: OS Exhaustion Flood
http_flood      T1499.002  Endpoint Denial of Service: Service Exhaustion Flood
slowloris       T1499.002  Endpoint Denial of Service: Service Exhaustion Flood
reflection      T1498.002  Network Denial of Service: Reflection Amplification
unknown         T1498      Network Denial of Service
=============== ============================================================

STIX output is a ``bundle`` with one ``indicator``-free ``sighting`` per
alert, pointing at an ``attack-pattern`` (the ATT&CK technique) and an
``ipv4-addr`` observed-data object for the device. CEF output follows
ArcSight CEF rev 25 with severity on the 0-10 scale.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

ATTACK_MAP: dict[str, tuple[str, str]] = {
    "udp_flood": ("T1498.001", "Network Denial of Service: Direct Network Flood"),
    "icmp_flood": ("T1498.001", "Network Denial of Service: Direct Network Flood"),
    "ack_flood": ("T1498.001", "Network Denial of Service: Direct Network Flood"),
    "syn_flood": ("T1499.001", "Endpoint Denial of Service: OS Exhaustion Flood"),
    "http_flood": ("T1499.002", "Endpoint Denial of Service: Service Exhaustion Flood"),
    "slowloris": ("T1499.002", "Endpoint Denial of Service: Service Exhaustion Flood"),
    "reflection": ("T1498.002", "Network Denial of Service: Reflection Amplification"),
}
DEFAULT_TECHNIQUE = ("T1498", "Network Denial of Service")
_NS = uuid.UUID("6f2c3a2e-8d0b-4c63-9a3e-4e5354474e4e")  # stable namespace for ids


def technique_for(family: str | None) -> tuple[str, str]:
    return ATTACK_MAP.get(str(family or "").lower(), DEFAULT_TECHNIQUE)


def _ts(value: Any) -> str:
    if isinstance(value, (int, float)):
        dt = datetime.fromtimestamp(float(value), tz=timezone.utc)
    else:
        dt = datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _sid(kind: str, *parts: Any) -> str:
    return f"{kind}--{uuid.uuid5(_NS, '|'.join(str(p) for p in parts))}"


def to_stix_bundle(alerts: Iterable[Mapping[str, Any]], run_id: str = "",
                   wall_clock_base: float | None = None) -> dict[str, Any]:
    """Convert alerts (``node``, ``ip``, ``probability``, ``timestamp``,
    ``attack_family``/``predicted``) into a STIX 2.1 bundle."""
    identity = {"type": "identity", "spec_version": "2.1",
                "id": _sid("identity", "netshield-gnn"), "name": "NetShield-GNN",
                "identity_class": "system", "created": _ts(0), "modified": _ts(0)}
    objects: list[dict[str, Any]] = [identity]
    patterns: dict[str, dict] = {}
    base = wall_clock_base if wall_clock_base is not None else 0.0
    for a in alerts:
        tid, tname = technique_for(a.get("attack_family"))
        if tid not in patterns:
            patterns[tid] = {
                "type": "attack-pattern", "spec_version": "2.1",
                "id": _sid("attack-pattern", tid), "name": tname,
                "created": _ts(0), "modified": _ts(0),
                "external_references": [{"source_name": "mitre-attack", "external_id": tid,
                                         "url": "https://attack.mitre.org/techniques/"
                                                + tid.replace(".", "/") + "/"}]}
            objects.append(patterns[tid])
        when = _ts(base + float(a.get("timestamp", 0.0)))
        addr = {"type": "ipv4-addr", "spec_version": "2.1",
                "id": _sid("ipv4-addr", a.get("ip", "")), "value": str(a.get("ip", ""))}
        observed = {"type": "observed-data", "spec_version": "2.1",
                    "id": _sid("observed-data", run_id, a.get("node"), a.get("timestamp")),
                    "created": when, "modified": when, "first_observed": when,
                    "last_observed": when, "number_observed": 1,
                    "object_refs": [addr["id"]], "created_by_ref": identity["id"]}
        confidence = int(round(100 * float(a.get("probability", 0.0))))
        sighting = {"type": "sighting", "spec_version": "2.1",
                    "id": _sid("sighting", run_id, a.get("node"), a.get("timestamp")),
                    "created": when, "modified": when, "first_seen": when, "last_seen": when,
                    "count": 1, "confidence": max(0, min(100, confidence)),
                    "sighting_of_ref": patterns[tid]["id"],
                    "observed_data_refs": [observed["id"]],
                    "where_sighted_refs": [identity["id"]],
                    "created_by_ref": identity["id"],
                    "description": f"{a.get('node')} scored P(hostile)="
                                   f"{float(a.get('probability', 0.0)):.3f}"
                                   + (f" in run {run_id}" if run_id else "")}
        objects += [addr, observed, sighting]
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


def _cef_escape(value: Any, header: bool = False) -> str:
    text = str(value)
    if header:
        return text.replace("\\", "\\\\").replace("|", "\\|")
    return text.replace("\\", "\\\\").replace("=", "\\=").replace("\n", " ")


def to_cef(alert: Mapping[str, Any], version: str = "1.0") -> str:
    """One ArcSight CEF line for an alert."""
    tid, tname = technique_for(alert.get("attack_family"))
    p = float(alert.get("probability", 0.0))
    severity = max(0, min(10, int(round(p * 10))))
    ext = {"src": alert.get("ip", ""), "shost": alert.get("node", ""),
           "cs1Label": "mitreTechnique", "cs1": tid,
           "cs2Label": "detector", "cs2": alert.get("detector", ""),
           "cfp1Label": "pHostile", "cfp1": f"{p:.4f}",
           "act": alert.get("action", "alert"),
           "rt": int(1000 * float(alert.get("wall_time", 0.0) or 0.0))}
    extension = " ".join(f"{k}={_cef_escape(v)}" for k, v in ext.items())
    header = "|".join(_cef_escape(x, True) for x in (
        "CEF:0", "NetShield", "NetShield-GNN", version,
        f"DDOS-{tid}", f"DDoS source detected: {tname}", severity))
    return f"{header}|{extension}"


def export_alerts(alerts: list[Mapping[str, Any]], fmt: str, run_id: str = "") -> str:
    """Serialise alerts as ``stix`` (JSON) or ``cef`` (newline-separated)."""
    if fmt == "stix":
        return json.dumps(to_stix_bundle(alerts, run_id), indent=2)
    if fmt == "cef":
        return "\n".join(to_cef(a) for a in alerts)
    raise ValueError(f"Unknown export format {fmt!r}")
