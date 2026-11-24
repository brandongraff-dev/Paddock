"""Sentry passive flows -> reach edges and observed coverage (docs/ASSURANCE_P1.md section 4.3).

Input: ``reach_flow_obs`` rows (aggregated by otdiscovery), the machine-identity assets (so an IP
that is a known device / cloud resource becomes the *same* node the other builders use), and the
sensors table. ``build`` is pure (no DB, clock or network), deterministic and sorted.

Soundness stance (a false HOLDS is the worst failure, so every unknown widens, D6):

* An observed flow is an edge ``src -> dst`` at basis ``observed``. When the sensor could only
  guess which end opened the connection (``oriented='heuristic'``) the edge is kept but its
  confidence drops to 50 and the evidence says so; the count is surfaced in ``notes``.
* An address claimed by more than one asset is not guessed: the edge is emitted for **every**
  candidate (and ``ip:<addr>``), and the address earns no coverage.
* A protocol we cannot name (``any``) or a TCP/UDP flow with no port is widened to all ports.
* Coverage (directions ``in`` and ``out``, tier ``observed``) is asserted only for a node **all**
  of whose known addresses were seen, inside the window, by a sensor that is active, online and has
  uploaded. ``observed_at`` is the OLDEST such sensor's ``last_upload_at`` among the sensors that
  saw the node, so one stale vantage point ages the claim. A silent or offline sensor leaves its
  nodes blind. Nothing is inferred for an address that was never seen. Observed coverage proves
  "no such traffic was seen", not "impossible" (section 10); the tier says exactly that.
"""
from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Optional

from .. import refs
from ..types import BuildOutput, CoverageOut, EdgeOut, NodeOut
from . import _ipmap

SOURCE = "sentry_flow"
TIER = "observed"

#: Same slack as the store/library: a timestamp further ahead than this is not believed.
CLOCK_SLACK = dt.timedelta(minutes=5)
#: Rows read per build. Hitting the cap loses edges (older ones first) and, conservatively, coverage.
MAX_FLOWS = 200_000
#: Candidates per endpoint when an address is ambiguous; beyond this we stop multiplying.
_MAX_CANDIDATES = 8
_MAX_EVIDENCE_SENSORS = 8
_PROTOS = ("icmp", "tcp", "udp", "any")

_FLOWS_SQL = """
SELECT src_ip, dst_ip, proto, dst_port, sensor_id::text AS sensor_id,
       first_seen, last_seen, packets, bytes, oriented
  FROM reach_flow_obs
 WHERE last_seen >= $1
 ORDER BY last_seen DESC, src_ip, dst_ip, proto, dst_port
 LIMIT $2
"""
_SENSORS_SQL = """
SELECT id::text AS id, name, status, online, last_upload_at
  FROM sensors
 ORDER BY id
"""


# --------------------------------------------------------------------------- #
# Loading (read-only SQL; the connection is already tenant-bound)
# --------------------------------------------------------------------------- #

def default_window() -> dt.timedelta:
    from ...config import settings
    return dt.timedelta(hours=settings.assurance_edge_window_h)


async def load(conn: Any, now: dt.datetime, **opts: Any) -> dict[str, Any]:
    """Recent flows + identity assets + sensors. Tenancy comes from the connection, never SQL."""
    window: dt.timedelta = opts.get("window") or default_window()
    flows = [dict(r) for r in await conn.fetch(_FLOWS_SQL, now - window, MAX_FLOWS + 1)]
    truncated = len(flows) > MAX_FLOWS
    return {
        "flows": flows[:MAX_FLOWS],
        "truncated": truncated,
        "assets": await _ipmap.load_ip_rows(conn),
        "sensors": [dict(r) for r in await conn.fetch(_SENSORS_SQL)],
    }


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #

def _aware(ts: Any) -> Optional[dt.datetime]:
    if not isinstance(ts, dt.datetime):
        return None
    return ts.replace(tzinfo=dt.timezone.utc) if ts.tzinfo is None else ts


def _uuid_text(v: Any) -> Optional[str]:
    try:
        return str(uuid.UUID(str(v)))
    except (ValueError, TypeError):
        return None


def eligible_sensors(sensors: Iterable[Mapping[str, Any]], now: dt.datetime) -> dict[str, dt.datetime]:
    """sensor id -> ``observed_at`` for sensors whose silence we can rule out.

    Active (not revoked), flagged online, and with a real upload time. A ``last_upload_at`` in
    the future is clamped to ``now``: it must never make coverage look fresher than it is.
    """
    out: dict[str, dt.datetime] = {}
    for s in sensors:
        sid = _uuid_text(s.get("id"))
        up = _aware(s.get("last_upload_at"))
        if sid is None or up is None or s.get("status") != "active" or s.get("online") is not True:
            continue
        out[sid] = min(up, now)
    return out


@dataclass
class _Edge:
    first: dt.datetime
    last: dt.datetime
    syn: bool = False
    packets: int = 0
    bytes: int = 0
    sensors: set[str] = field(default_factory=set)
    src_ips: set[str] = field(default_factory=set)
    dst_ips: set[str] = field(default_factory=set)
    widened: Optional[str] = None
    ambiguous: bool = False
    reverse: bool = False        # the possible reverse of a flow whose orientation was only guessed


def _ports(proto: str, port: int) -> tuple[int, int, Optional[str]]:
    """``(lo, hi, reason)``. ICMP has no ports; an unknown protocol or a port-less TCP/UDP flow is
    widened rather than pinned to port 0 (D6)."""
    if proto == "icmp":
        return 0, 0, None
    # Port 0 is not a real TCP/UDP port (the store refuses it): "all ports" is 1-65535.
    if proto == "any":
        return 1, 65535, "unknown_protocol"
    if port == 0:
        return 1, 65535, "no_port"
    return port, port, None


def _usable(row: Mapping[str, Any], now: dt.datetime, floor: dt.datetime) -> Optional[dict[str, Any]]:
    src, dst = _ipmap.norm_ip(row.get("src_ip")), _ipmap.norm_ip(row.get("dst_ip"))
    last, first = _aware(row.get("last_seen")), _aware(row.get("first_seen"))
    proto, port = row.get("proto"), row.get("dst_port")
    if (src is None or dst is None or last is None or proto not in _PROTOS
            or not isinstance(port, int) or isinstance(port, bool) or not 0 <= port <= 65535):
        return None
    last = min(last, now + CLOCK_SLACK)
    if last < floor:
        return None
    first = min(first or last, last)
    return {"src": src, "dst": dst, "proto": proto, "port": port, "first": first, "last": last,
            "syn": row.get("oriented") == "syn", "sensor": _uuid_text(row.get("sensor_id")),
            "packets": max(0, int(row.get("packets") or 0)), "bytes": max(0, int(row.get("bytes") or 0))}


def _candidates(ip_map: _ipmap.IpMap, ip: str) -> tuple[str, ...]:
    cands = ip_map.resolve_all(ip)
    return cands[:_MAX_CANDIDATES]


# --------------------------------------------------------------------------- #
# Build
# --------------------------------------------------------------------------- #

def build(rows: Mapping[str, Any], now: dt.datetime, **opts: Any) -> BuildOutput:
    """Edges, nodes and observed coverage from one tenant's recent flows. Pure."""
    window: dt.timedelta = opts.get("window") or default_window()
    floor = now - window
    ip_map = _ipmap.build_ip_map(rows.get("assets") or [])
    sensors = eligible_sensors(rows.get("sensors") or [], now)

    flows: list[dict[str, Any]] = []
    bad = 0
    for raw in rows.get("flows") or []:
        u = _usable(raw, now, floor)
        if u is None:
            bad += 1
        else:
            flows.append(u)
    flows.sort(key=lambda f: (f["src"], f["dst"], f["proto"], f["port"], f["sensor"] or ""))

    edges: dict[tuple, _Edge] = {}
    seen: dict[str, set[str]] = {}          # ip -> eligible sensors that saw it in the window
    self_loops = 0
    for f in flows:
        if f["sensor"] in sensors:
            for ip in (f["src"], f["dst"]):
                seen.setdefault(ip, set()).add(f["sensor"])
        lo, hi, widened = _ports(f["proto"], f["port"])
        srcs, dsts = _candidates(ip_map, f["src"]), _candidates(ip_map, f["dst"])
        ambiguous = ip_map.is_ambiguous(f["src"]) or ip_map.is_ambiguous(f["dst"])
        for s in srcs:
            for d in dsts:
                if s == d:
                    self_loops += 1
                    continue
                e = edges.setdefault((s, d, f["proto"], lo, hi), _Edge(f["first"], f["last"]))
                e.first, e.last = min(e.first, f["first"]), max(e.last, f["last"])
                e.syn = e.syn or f["syn"]
                e.packets, e.bytes = e.packets + f["packets"], e.bytes + f["bytes"]
                if f["sensor"]:
                    e.sensors.add(f["sensor"])
                e.src_ips.add(f["src"])
                e.dst_ips.add(f["dst"])
                e.widened = e.widened or widened
                e.ambiguous = e.ambiguous or ambiguous

    _add_possible_reverses(edges)
    edge_outs = [_edge_out(k, e) for k, e in sorted(edges.items())]
    coverage, cov_notes = _coverage(ip_map, seen, sensors)

    node_refs = {e.src_ref for e in edge_outs} | {e.dst_ref for e in edge_outs} | {c.node_ref for c in coverage}
    nodes = [_node(ref, ip_map) for ref in sorted(node_refs)]

    notes = _notes(len(flows), bad, edge_outs, edges, self_loops, sensors, rows, ip_map, cov_notes)
    return BuildOutput(source=SOURCE, mode="window", nodes=nodes, edges=edge_outs,
                       coverage=coverage, window=window, notes=notes)


def _add_possible_reverses(edges: dict[tuple, _Edge]) -> None:
    """A guessed orientation may be backwards, and then the real edge ``dst -> src`` is missing
    from the graph: a false HOLDS for an invariant about that direction (D6). So every edge that
    no SYN confirmed also gets its reverse, on every port because we do not know the real service
    port, at the same confidence and with the assumption recorded."""
    for (s, d, proto, _lo, _hi), e in list(edges.items()):
        if e.syn or e.reverse:
            continue
        lo, hi = (0, 0) if proto == "icmp" else (1, 65535)
        key = (d, s, proto, lo, hi)
        r = edges.get(key)
        if r is None:
            r = edges[key] = _Edge(e.first, e.last, reverse=True)
        elif not r.reverse:
            continue                     # a real flow already covers that direction on all ports
        r.first, r.last = min(r.first, e.first), max(r.last, e.last)
        r.packets, r.bytes = r.packets + e.packets, r.bytes + e.bytes
        r.sensors |= e.sensors
        r.src_ips |= e.dst_ips
        r.dst_ips |= e.src_ips
        r.ambiguous = r.ambiguous or e.ambiguous
        r.widened = "reverse_of_guessed_orientation"


def _edge_out(key: tuple, e: _Edge) -> EdgeOut:
    src, dst, proto, lo, hi = key
    evidence: dict[str, Any] = {
        "oriented": "syn" if e.syn else "heuristic",
        "packets": e.packets, "bytes": e.bytes,
        "sensors": sorted(e.sensors)[:_MAX_EVIDENCE_SENSORS],
        "src_ips": sorted(e.src_ips)[:_MAX_EVIDENCE_SENSORS],
        "dst_ips": sorted(e.dst_ips)[:_MAX_EVIDENCE_SENSORS],
    }
    if not e.syn:
        evidence["assumption"] = "orientation guessed from ports; the reverse direction may be the real one"
    if e.widened:
        evidence["assumed_all_ports"] = e.widened
    if e.ambiguous:
        evidence["ambiguous_identity"] = True
    return EdgeOut(src_ref=src, dst_ref=dst, proto=proto, port_lo=lo, port_hi=hi, basis="observed",
                   source=SOURCE, last_seen=e.last, first_seen=e.first,
                   confidence=100 if e.syn else 50, evidence=evidence)


def _node(ref: str, ip_map: _ipmap.IpMap) -> NodeOut:
    prefix, value = refs.parse_ref(ref)
    if prefix == "asset":
        return NodeOut(ref=ref, kind=ip_map.node_kind(ref), asset_id=value,
                       attrs={"ips": list(ip_map.ips_of(ref))})
    return NodeOut(ref=ref, kind="ip", label=value or "", attrs={"ip": value})


def _coverage(ip_map: _ipmap.IpMap, seen: Mapping[str, set[str]],
              sensors: Mapping[str, dt.datetime]) -> tuple[list[CoverageOut], dict[str, int]]:
    """Both-direction observed coverage for fully seen, unambiguous nodes only."""
    stats = {"partial": 0, "ambiguous": 0}
    # node ref -> the addresses that must ALL have been seen for the node to count as covered
    owned: dict[str, tuple[str, ...]] = {}
    for ip in sorted(seen):
        if ip_map.is_ambiguous(ip):
            stats["ambiguous"] += 1
            continue
        ref = ip_map.resolve(ip)
        owned[ref] = (ip_map.ips_of(ref) or (ip,)) if ref.startswith("asset:") else (ip,)
    out: list[CoverageOut] = []
    for ref, ips in sorted(owned.items()):
        if any(ip not in seen or ip_map.is_ambiguous(ip) for ip in ips):
            stats["partial"] += 1
            continue
        vantage = sorted({s for ip in ips for s in seen[ip]})
        observed_at = min(sensors[s] for s in vantage)
        detail = {"sensors": vantage[:_MAX_EVIDENCE_SENSORS], "ips": list(ips)[:_MAX_EVIDENCE_SENSORS]}
        for direction in ("in", "out"):
            out.append(CoverageOut(node_ref=ref, direction=direction, tier=TIER,
                                   observed_at=observed_at, source=SOURCE, detail=detail))
    return out, stats


def _notes(n_flows: int, bad: int, edge_outs: list[EdgeOut], edges: Mapping[tuple, _Edge],
           self_loops: int, sensors: Mapping[str, dt.datetime], rows: Mapping[str, Any],
           ip_map: _ipmap.IpMap, cov: Mapping[str, int]) -> list[str]:
    notes = [f"{n_flows} flow record(s) in the window -> {len(edge_outs)} edge(s); "
             f"{len(sensors)} active online sensor(s)"]
    if rows.get("truncated"):
        notes.append(f"flow read hit the {MAX_FLOWS} row cap: older flows and their coverage are missing")
    if bad:
        notes.append(f"{bad} flow record(s) skipped (unreadable or outside the window)")
    guessed = sum(1 for e in edges.values() if not e.syn)
    if guessed:
        notes.append(f"{guessed} edge(s) have a guessed direction (confidence 50)")
    if self_loops:
        notes.append(f"{self_loops} flow(s) stay inside one asset (same node at both ends) and were dropped")
    if cov["partial"]:
        notes.append(f"{cov['partial']} node(s) seen on only some of their addresses: left blind")
    if cov["ambiguous"]:
        notes.append(f"{cov['ambiguous']} address(es) claimed by several assets: no coverage asserted")
    notes += ip_map.report()
    if not sensors:
        notes.append("no active online sensor: Sentry asserts no coverage")
    return notes


__all__ = ["SOURCE", "load", "build", "eligible_sensors", "default_window"]
