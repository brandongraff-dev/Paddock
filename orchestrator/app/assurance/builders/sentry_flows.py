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
* Coverage (directions ``in`` and ``out``, tier ``observed``) is asserted for a node only when
  **every** known address of the node is (1) inside a CIDR that an active, online sensor's operator
  declared as that sensor's scope (``sensor_scopes``, schema 040) **and** (2) seen in the window in
  a flow reported by that same sensor. A sensor that saw ONE flow to a host does not see the host's
  other traffic (a cloud instance reached over a VPN, an on-prem machine that reuses a VPC's
  private address), so "was an endpoint of a flow" is not visibility; the declared scope is the
  only statement of what the sensor can see (review finding builders-3). A sensor with no declared
  scope (or only unusable entries) covers nothing, and says so in ``notes``. The pinned contract
  asks for one address in scope; requiring them all is stricter on purpose, because traffic on a
  second address outside the scope is invisible to the sensor and a node-wide claim would be false.
  ``observed_at`` is the OLDEST such sensor's ``last_upload_at`` (clamped to ``now``), so one stale
  vantage point ages the claim; the newest sighting of the node is disclosed in ``detail`` so a
  reader can see how old the node's own last flow is (builders-4). A silent or offline sensor leaves
  its nodes blind. Observed coverage proves "no such traffic was seen", not "impossible"
  (section 10); the tier says exactly that.
* A read that hit the row cap is a soundness failure, not a note: edges that were loaded are kept
  but **no coverage at all** is emitted, so a flood of cheap distinct flows degrades the verdict to
  UNKNOWN instead of hiding an older violating edge behind "fully observed" nodes (builders-5,
  security-1). The SQL aggregates per ``(src, dst, proto, port)`` first so row multiplicity (one row
  per sensor) cannot cause that on its own.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import json
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
#: Aggregated flows read per build. Hitting the cap loses edges (older ones first), so the builder
#: then withdraws ALL its coverage (a truncated edge set must never come with "fully observed").
MAX_FLOWS = 200_000
#: CIDRs honoured per sensor scope; a longer list is dropped whole (fail closed, bounded work).
MAX_SCOPE_CIDRS = 256
#: Candidates per endpoint when an address is ambiguous; beyond this we stop multiplying.
_MAX_CANDIDATES = 8
_MAX_EVIDENCE_SENSORS = 8
_PROTOS = ("icmp", "tcp", "udp", "any")

# One row per distinct flow (src, dst, proto, port), not per sensor: the table already keeps a row per
# sensor, and the cap must count flows, not copies of them. Orientation is 'syn' if any sensor saw a
# SYN, timestamps are the envelope, counters add. The cap then orders by newest sighting.
_FLOWS_SQL = """
SELECT src_ip, dst_ip, proto, dst_port,
       array_agg(DISTINCT sensor_id::text ORDER BY sensor_id::text) AS sensor_ids,
       MIN(first_seen) AS first_seen, MAX(last_seen) AS last_seen,
       COALESCE(SUM(packets), 0) AS packets, COALESCE(SUM(bytes), 0) AS bytes,
       CASE WHEN bool_or(oriented = 'syn') THEN 'syn' ELSE 'heuristic' END AS oriented
  FROM reach_flow_obs
 WHERE last_seen >= $1
 GROUP BY src_ip, dst_ip, proto, dst_port
 ORDER BY MAX(last_seen) DESC, src_ip, dst_ip, proto, dst_port
 LIMIT $2
"""
_SENSORS_SQL = """
SELECT id::text AS id, name, status, online, last_upload_at
  FROM sensors
 ORDER BY id
"""
_SCOPES_SQL = """
SELECT sensor_id::text AS sensor_id, cidrs
  FROM sensor_scopes
 ORDER BY sensor_id, id
"""


# --------------------------------------------------------------------------- #
# Loading (read-only SQL; the connection is already tenant-bound)
# --------------------------------------------------------------------------- #

def default_window() -> dt.timedelta:
    from ...config import settings
    return dt.timedelta(hours=settings.assurance_edge_window_h)


async def load(conn: Any, now: dt.datetime, **opts: Any) -> dict[str, Any]:
    """Recent aggregated flows + identity assets + sensors + sensor scopes. Tenancy comes from the connection, never SQL."""
    window: dt.timedelta = opts.get("window") or default_window()
    flows = [dict(r) for r in await conn.fetch(_FLOWS_SQL, now - window, MAX_FLOWS + 1)]
    truncated = len(flows) > MAX_FLOWS
    return {
        "flows": flows[:MAX_FLOWS],
        "truncated": truncated,
        "assets": await _ipmap.load_ip_rows(conn),
        "sensors": [dict(r) for r in await conn.fetch(_SENSORS_SQL)],
        "scopes": [dict(r) for r in await conn.fetch(_SCOPES_SQL)],
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


def parse_scopes(rows: Iterable[Mapping[str, Any]]) -> tuple[dict[str, tuple[Any, ...]], dict[str, int]]:
    """sensor id -> declared networks, plus counters for the notes. Pure, order independent.

    Only what parses as a canonical CIDR (or a bare address, a /32 or /128) is honoured. A network
    with host bits set (``10.20.0.5/24``) is rejected rather than "fixed": we will not guess the
    operator's intent, and guessing wide is a false HOLDS. ``/0`` is no scope at all (a sensor does
    not see the whole address space), a ``%scope`` is not an address, and a v4-mapped v6 network is
    read as the v4 network (the same unwrapping :func:`_ipmap.norm_ip` applies to addresses). More
    than ``MAX_SCOPE_CIDRS`` entries, or two rows for one sensor, drop that sensor's scope entirely.
    """
    stats = {"bad_entries": 0, "too_many": 0, "duplicate": 0}
    nets: dict[str, set[Any]] = {}
    dup: set[str] = set()
    for row in sorted(rows, key=lambda r: (str(r.get("sensor_id")), json.dumps(r.get("cidrs"), default=str))):
        sid = _uuid_text(row.get("sensor_id"))
        if sid is None:
            continue
        if sid in nets or sid in dup:
            dup.add(sid)
            continue
        cidrs = row.get("cidrs")
        cidrs = list(cidrs) if isinstance(cidrs, (list, tuple)) else []
        if len(cidrs) > MAX_SCOPE_CIDRS:
            stats["too_many"] += 1
            dup.add(sid)             # reuse the "no scope for this sensor" path
            continue
        good: set[Any] = set()
        for c in cidrs:
            net = _parse_cidr(c)
            if net is None:
                stats["bad_entries"] += 1
            else:
                good.add(net)
        nets[sid] = good
    for sid in dup:
        nets.pop(sid, None)
    stats["duplicate"] = len(dup) - stats["too_many"]
    out = {sid: tuple(sorted(ns, key=lambda n: (n.version, int(n.network_address), n.prefixlen)))
           for sid, ns in nets.items() if ns}
    return out, stats


def _parse_cidr(text: Any) -> Any:
    if not isinstance(text, str) or "%" in text or len(text) > 64:
        return None
    try:
        net = ipaddress.ip_network(text.strip(), strict=True)
    except ValueError:
        return None
    if net.prefixlen == 0:
        return None
    if net.version == 6 and net.subnet_of(_V4_MAPPED):
        net = ipaddress.ip_network((net.network_address.ipv4_mapped, net.prefixlen - 96), strict=True)
        if net.prefixlen == 0:
            return None
    return net


_V4_MAPPED = ipaddress.ip_network("::ffff:0:0/96")


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


def _row_sensors(row: Mapping[str, Any]) -> tuple[str, ...]:
    """Sensors that reported this flow: one (``sensor_id``) or, for an aggregated row, several
    (``sensor_ids``). Unparseable ids are dropped; they can earn neither coverage nor evidence."""
    raw = row.get("sensor_ids")
    cand = list(raw) if isinstance(raw, (list, tuple)) else []
    cand.append(row.get("sensor_id"))
    return tuple(sorted({u for u in (_uuid_text(c) for c in cand if c is not None) if u}))


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
            "syn": row.get("oriented") == "syn", "sensors": _row_sensors(row),
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
    scopes, scope_stats = parse_scopes(rows.get("scopes") or [])
    truncated = bool(rows.get("truncated"))

    flows: list[dict[str, Any]] = []
    bad = 0
    for raw in rows.get("flows") or []:
        u = _usable(raw, now, floor)
        if u is None:
            bad += 1
        else:
            flows.append(u)
    flows.sort(key=lambda f: (f["src"], f["dst"], f["proto"], f["port"], f["sensors"]))

    edges: dict[tuple, _Edge] = {}
    seen: dict[str, dict[str, dt.datetime]] = {}   # ip -> eligible sensor -> its newest sighting
    self_loops = 0
    for f in flows:
        for sid in f["sensors"]:
            if sid in sensors:
                for ip in (f["src"], f["dst"]):
                    cur = seen.setdefault(ip, {})
                    cur[sid] = max(cur.get(sid, f["last"]), f["last"])
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
                e.sensors.update(f["sensors"])
                e.src_ips.add(f["src"])
                e.dst_ips.add(f["dst"])
                e.widened = e.widened or widened
                e.ambiguous = e.ambiguous or ambiguous

    _add_possible_reverses(edges)
    edge_outs = [_edge_out(k, e) for k, e in sorted(edges.items())]
    if truncated:
        # Edges were lost with the rows past the cap, so no node can be called "fully observed":
        # fail closed. (Loaded edges stay: more edges only make verdicts more cautious.)
        coverage, cov_notes = [], {"partial": 0, "ambiguous": 0, "out_of_scope": 0}
    else:
        coverage, cov_notes = _coverage(ip_map, seen, sensors, scopes)

    node_refs = {e.src_ref for e in edge_outs} | {e.dst_ref for e in edge_outs} | {c.node_ref for c in coverage}
    nodes = [_node(ref, ip_map) for ref in sorted(node_refs)]

    notes = _notes(len(flows), bad, edge_outs, edges, self_loops, sensors, scopes, scope_stats, truncated,
                   ip_map, cov_notes)
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


def _vantage(ip: str, sightings: Mapping[str, dt.datetime], scopes: Mapping[str, tuple[Any, ...]]) -> list[str]:
    """Sensors that saw ``ip`` AND declared a scope containing it, sorted."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:                      # pragma: no cover - norm_ip output always parses
        return []
    return sorted(s for s in sightings if any(addr in net for net in scopes.get(s, ())))


def _coverage(ip_map: _ipmap.IpMap, seen: Mapping[str, Mapping[str, dt.datetime]],
              sensors: Mapping[str, dt.datetime],
              scopes: Mapping[str, tuple[Any, ...]]) -> tuple[list[CoverageOut], dict[str, int]]:
    """Both-direction observed coverage for unambiguous nodes all of whose addresses are in scope."""
    stats = {"partial": 0, "ambiguous": 0, "out_of_scope": 0}
    # node ref -> the addresses that must ALL be seen inside a declared scope for the node to count
    owned: dict[str, tuple[str, ...]] = {}
    for ip in sorted(seen):
        if ip_map.is_ambiguous(ip):
            stats["ambiguous"] += 1
            continue
        ref = ip_map.resolve(ip)
        owned[ref] = (ip_map.ips_of(ref) or (ip,)) if ref.startswith("asset:") else (ip,)
    out: list[CoverageOut] = []
    for ref, ips in sorted(owned.items()):
        van = {ip: (_vantage(ip, seen[ip], scopes) if ip in seen and not ip_map.is_ambiguous(ip) else [])
               for ip in ips}
        if any(not v for v in van.values()):
            # seen by a sensor whose declared scope does not include it is the loud case (a remote
            # endpoint); an address never seen at all is the older "partial" case
            if any(ip in seen and not van[ip] and not ip_map.is_ambiguous(ip) for ip in ips):
                stats["out_of_scope"] += 1
            else:
                stats["partial"] += 1
            continue
        vantage = sorted({s for v in van.values() for s in v})
        observed_at = min(sensors[s] for s in vantage)
        last = max(seen[ip][s] for ip in ips for s in van[ip])
        detail = {"sensors": vantage[:_MAX_EVIDENCE_SENSORS], "ips": list(ips)[:_MAX_EVIDENCE_SENSORS],
                  "last_sighting": last.isoformat()}
        for direction in ("in", "out"):
            out.append(CoverageOut(node_ref=ref, direction=direction, tier=TIER,
                                   observed_at=observed_at, source=SOURCE, detail=detail))
    return out, stats


def _notes(n_flows: int, bad: int, edge_outs: list[EdgeOut], edges: Mapping[tuple, _Edge],
           self_loops: int, sensors: Mapping[str, dt.datetime], scopes: Mapping[str, tuple[Any, ...]],
           scope_stats: Mapping[str, int], truncated: bool, ip_map: _ipmap.IpMap,
           cov: Mapping[str, int]) -> list[str]:
    notes = [f"{n_flows} flow record(s) in the window -> {len(edge_outs)} edge(s); "
             f"{len(sensors)} active online sensor(s)"]
    if truncated:
        notes.append(f"TRUNCATED: flow read hit the {MAX_FLOWS} row cap, older flows are missing, so this build "
                     "asserts no coverage at all and verdicts that depend on Sentry stay UNKNOWN")
    if bad:
        notes.append(f"{bad} flow record(s) skipped (unreadable or outside the window)")
    guessed = sum(1 for e in edges.values() if not e.syn)
    if guessed:
        notes.append(f"{guessed} edge(s) have a guessed direction (confidence 50)")
    if self_loops:
        notes.append(f"{self_loops} flow(s) stay inside one asset (same node at both ends) and were dropped")
    if cov["out_of_scope"]:
        notes.append(f"{cov['out_of_scope']} node(s) seen outside every declared sensor scope: left blind")
    if cov["partial"]:
        notes.append(f"{cov['partial']} node(s) seen on only some of their addresses: left blind")
    if cov["ambiguous"]:
        notes.append(f"{cov['ambiguous']} address(es) claimed by several assets: no coverage asserted")
    notes += ip_map.report()
    if not sensors:
        notes.append("no active online sensor: Sentry asserts no coverage")
    noscope = sum(1 for sid in sensors if sid not in scopes)
    if noscope:
        notes.append(f"{noscope} active online sensor(s) have no declared scope (sensor_scopes): they cover nothing")
    if scope_stats["bad_entries"]:
        notes.append(f"{scope_stats['bad_entries']} sensor scope entr(y/ies) ignored: not a canonical CIDR, or /0")
    if scope_stats["too_many"]:
        notes.append(f"{scope_stats['too_many']} sensor scope(s) ignored: too many CIDRs (cap {MAX_SCOPE_CIDRS})")
    if scope_stats["duplicate"]:
        notes.append(f"{scope_stats['duplicate']} sensor(s) with several scope rows: scope ignored")
    return notes


__all__ = ["SOURCE", "load", "build", "eligible_sensors", "parse_scopes", "default_window"]
