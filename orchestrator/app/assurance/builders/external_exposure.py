"""``external_exposure`` builder: what the internet can reach, from port observations.

Edges ``internet -> host:port`` come from ``assets`` rows of kind ``port`` (written by the active
``port_scan`` worker and by the passive Shodan lookup). Coverage (``in``, tier ``observed``) is
asserted ONLY for hosts whose latest completed ``port_scan`` covered every port 1-65535 with no
recorded tool failure (docs/ASSURANCE_P1.md D4 and section 4.2): a top-100 scan proves nothing about
the other 65,435 ports, and a Shodan row is somebody else's old crawl, so it never gives coverage.

Soundness notes (a false HOLDS is the worst bug):
* Unknown facts are over-approximated and recorded (D6): an ambiguous address maps to every candidate
  asset; a port whose canonical and metadata disagree yields both ports; an unknown protocol is ``any``.
* Coverage names ``detail.proto = "tcp"`` because the scanner is TCP-only, and ``detail.origin =
  "internet"`` because only outside-in observations back it (see the package report's gaps).
* An asset with several public addresses is covered only if EVERY one of them is, and an address
  claimed by two assets covers neither.

``load`` is read-only SQL on a tenant-bound connection (tenancy comes from the pool, never from the
SQL). ``build`` is pure: no DB, clock or network; ``now`` is a parameter; output is sorted.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Optional

from .. import refs
from ..types import BuildOutput, CoverageOut, EdgeOut, NodeOut
from . import _ipmap

SOURCE = "external_scan"
SHODAN_ORIGIN = "shodan_internetdb"
SHODAN_CONFIDENCE = 60
SCAN_CONFIDENCE = 100
#: rule ids the active worker records when naabu is missing or failed (workers/active port_scan).
TOOL_FAILURE_RULES = ("tool-unavailable-naabu", "tool-error-naabu")
_FUTURE_SKEW = dt.timedelta(minutes=5)
_FULL = ((1, 65535),)
_SHODAN_SOURCES = frozenset({"shodan", "internetdb", "shodan_internetdb"})

# --------------------------------------------------------------------------- #
# SQL (read-only; no tenant_id anywhere: RLS on the pooled connection scopes it)
# --------------------------------------------------------------------------- #

# A port asset's canonical is "<host>:<port>" with the port RIGHT-anchored, so an IPv6 host such as
# "2001:db8::1:443" splits correctly. The host asset is optional (LEFT JOIN): a missing ipv4/ipv6 row
# must not hide an observed port.
PORTS_SQL = """
SELECT p.id, p.canonical, p.value, p.source, p.confidence, p.last_seen, p.metadata,
       h.id AS host_asset_id
  FROM assets p
  LEFT JOIN assets h
    ON h.kind IN ('ipv4', 'ipv6')
   AND h.canonical = btrim(substring(p.canonical from '^(.*):[0-9]{1,5}$'), '[]')
 WHERE p.kind = 'port'
   AND p.canonical ~ ':[0-9]{1,5}$'
   AND p.last_seen >= $1
 ORDER BY p.canonical, p.id
"""

SCOPE_SQL = """
SELECT id, kind, value, expires_at
  FROM scope_entries
 WHERE active = TRUE
   AND kind IN ('ipv4_cidr', 'ipv6_cidr')
   AND (expires_at IS NULL OR expires_at > $1)
 ORDER BY id
"""

# Latest COMPLETED port_scan per target. tool_failed: the worker records a policy finding on the
# target's host asset when naabu is missing or errored, yet still completes the scan with zero ports;
# without this check such a scan would look like "scanned everything, nothing open".
SCANS_SQL = """
SELECT DISTINCT ON (s.target)
       s.id, s.target, s.started_at, s.finished_at, s.config, s.result_summary, s.error,
       EXISTS (
         SELECT 1 FROM findings f JOIN assets a ON a.id = f.asset_id
          WHERE a.kind IN ('ipv4', 'ipv6') AND a.canonical = s.target
            AND f.rule_id = ANY($2::text[])
            AND f.last_seen >= COALESCE(s.started_at, s.queued_at)
       ) AS tool_failed
  FROM scans s
 WHERE s.kind = 'port_scan' AND s.status = 'completed'
   AND s.finished_at IS NOT NULL AND s.finished_at >= $1
 ORDER BY s.target, s.finished_at DESC, s.id DESC
"""


@dataclass
class ExternalRows:
    """Everything ``build`` needs, as plain data (JSON columns already decoded)."""
    ports: list[dict[str, Any]] = field(default_factory=list)
    scope: list[dict[str, Any]] = field(default_factory=list)
    scans: list[dict[str, Any]] = field(default_factory=list)
    assets: list[dict[str, Any]] = field(default_factory=list)   # identity rows for _ipmap


def _aware(t: dt.datetime) -> dt.datetime:
    return t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)


def _max_age(max_age: Optional[dt.timedelta]) -> dt.timedelta:
    if max_age is not None:
        return max_age
    from ...config import settings   # lazy: keeps ``build`` importable without a configured env
    return dt.timedelta(hours=settings.assurance_external_max_age_h)


def _json(v: Any) -> Any:
    if isinstance(v, (str, bytes)):
        try:
            return json.loads(v)
        except ValueError:
            return {}
    return v


def _rec(row: Any) -> dict[str, Any]:
    d = dict(row)
    for k in ("metadata", "config", "result_summary"):
        if k in d:
            d[k] = _json(d[k]) or {}
    return d


async def load(conn, now: dt.datetime, *, max_age: Optional[dt.timedelta] = None,
               **_opts: Any) -> ExternalRows:
    """Read the rows ``build`` needs. ``conn`` is tenant-bound; nothing here names a tenant."""
    now = _aware(now)
    cutoff = now - _max_age(max_age)
    ports = [_rec(r) for r in await conn.fetch(PORTS_SQL, cutoff)]
    scope = [dict(r) for r in await conn.fetch(SCOPE_SQL, now)]
    scans = [_rec(r) for r in await conn.fetch(SCANS_SQL, cutoff, list(TOOL_FAILURE_RULES))]
    assets = [_rec(r) for r in await _ipmap.load_ip_rows(conn)]
    return ExternalRows(ports=ports, scope=scope, scans=scans, assets=assets)


# --------------------------------------------------------------------------- #
# Parsing helpers (pure)
# --------------------------------------------------------------------------- #

_HOST_PORT = re.compile(r"^(?P<host>.+):(?P<port>[0-9]{1,5})$")


def split_host_port(canonical: str) -> Optional[tuple[str, int]]:
    """``(canonical_ip, port)`` from ``"<host>:<port>"``, port right-anchored; ``None`` if invalid.

    Handles ``1.2.3.4:80``, ``2001:db8::1:443`` and ``[2001:db8::1]:443``. The asset *kind* of the host
    is never trusted (the worker labels IPv6 hosts ``ipv4``): the text is parsed.
    """
    m = _HOST_PORT.match((canonical or "").strip())
    if not m:
        return None
    ip = _ipmap.norm_ip(m.group("host"))
    port = int(m.group("port"))
    if ip is None or not 1 <= port <= 65535:
        return None
    return ip, port


def parse_port_spec(spec: Any) -> Optional[tuple[tuple[int, int], ...]]:
    """Merged inclusive intervals for ``80``, ``"80,443,8000-8100"``, a list of those, or ``"full"``.

    ``None`` for anything else (``top-100``, ``u:53``, garbage, empty): an unparseable spec asserts
    nothing. Same grammar as the library's port parser, kept local so this module imports no library
    code at module level.
    """
    if isinstance(spec, bool):
        return None
    if isinstance(spec, str):
        if len(spec) > 512:
            return None
        if spec.strip().lower() == "full":     # naabu's keyword for 1-65535
            return _FULL
        parts: list[Any] = [p.strip() for p in spec.split(",") if p.strip()]
    elif isinstance(spec, int):
        parts = [spec]
    elif isinstance(spec, (list, tuple)):
        parts = list(spec)
    else:
        return None
    if not parts:
        return None
    items: list[tuple[int, int]] = []
    for p in parts:
        if isinstance(p, bool):
            return None
        if isinstance(p, int):
            lo = hi = p
        elif isinstance(p, str):
            a, sep, b = p.partition("-")
            try:
                lo = int(a)
                hi = int(b) if sep else lo
            except ValueError:
                return None
        else:
            return None
        if not 1 <= lo <= hi <= 65535:
            return None
        items.append((lo, hi))
    merged: list[list[int]] = []
    for lo, hi in sorted(items):
        if merged and lo <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], hi)
        else:
            merged.append([lo, hi])
    return tuple((a, b) for a, b in merged)


def scan_covers_all_ports(config: Any) -> bool:
    """True iff the scan config's ``ports`` is exactly 1-65535 and nothing is excluded.

    A missing ``ports`` key means the worker default (top-100): partial. Any ``exclude*`` key with a
    truthy value also disqualifies (we cannot see which ports it removed).
    """
    if not isinstance(config, dict) or "ports" not in config:
        return False
    if any("exclude" in str(k).lower() and v for k, v in config.items()):
        return False
    return parse_port_spec(config.get("ports")) == _FULL


def _summary_failed(scan: Mapping[str, Any]) -> bool:
    """A recorded failure on the scan row or in its summary (defence in depth next to the SQL flag)."""
    if scan.get("tool_failed") or scan.get("error"):
        return True
    summary = scan.get("result_summary")
    if not isinstance(summary, dict):
        return False
    return any(summary.get(k) for k in ("error", "errors", "failed", "tool_failed", "tool_error"))


def _proto(md: Mapping[str, Any]) -> str:
    p = str(md.get("protocol") or "tcp").strip().lower()
    return p if p in ("tcp", "udp") else "any"      # unknown transport: over-approximate


def _origin(source: Any) -> str:
    s = str(source or "").strip().lower()
    if s in _SHODAN_SOURCES:
        return SHODAN_ORIGIN
    return SOURCE if s == "port_scan" else (s or "unknown")


def _scope_nets(rows: Iterable[Mapping[str, Any]],
                now: dt.datetime) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    nets: list[Any] = []
    for r in rows:
        exp = r.get("expires_at")
        if exp is not None and _aware(exp) <= now:
            continue                                   # expired entries scope nothing
        try:
            nets.append(ipaddress.ip_network(str(r.get("value", "")).strip(), strict=False))
        except ValueError:
            continue
    return nets


def _in_scope(ip: str, nets: list[Any]) -> bool:
    a = ipaddress.ip_address(ip)
    return any(a.version == n.version and a in n for n in nets)


# --------------------------------------------------------------------------- #
# build
# --------------------------------------------------------------------------- #

@dataclass
class _Obs:
    """One merged (host, proto, port) observation."""
    last_seen: dt.datetime
    confidence: int
    origins: set[str] = field(default_factory=set)
    assets: set[str] = field(default_factory=set)
    host_assets: set[str] = field(default_factory=set)
    port_mismatch: bool = False


def _observations(rows: ExternalRows, now: dt.datetime, max_age: dt.timedelta,
                  nets: list[Any], counters: dict[str, int]) -> dict[tuple[str, str, int], _Obs]:
    obs: dict[tuple[str, str, int], _Obs] = {}
    for row in rows.ports:
        parsed = split_host_port(str(row.get("canonical") or ""))
        last = row.get("last_seen")
        if parsed is None or last is None:
            counters["unparsable"] += 1
            continue
        ip, port = parsed
        last = min(_aware(last), now)                  # never trust a timestamp from the future
        if now - last > max_age:
            counters["stale"] += 1
            continue
        if not _ipmap.is_public_ip(ip) or not _in_scope(ip, nets):
            counters["out_of_scope"] += 1
            continue
        md = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
        ports = {port}
        mp = md.get("port")
        if isinstance(mp, int) and not isinstance(mp, bool) and 1 <= mp <= 65535 and mp != port:
            ports.add(mp)                              # canonical and metadata disagree: keep both
        origin = _origin(row.get("source"))
        conf = SHODAN_CONFIDENCE if origin != SOURCE else SCAN_CONFIDENCE
        for p in sorted(ports):
            o = obs.setdefault((ip, _proto(md), p), _Obs(last_seen=last, confidence=conf))
            o.last_seen = max(o.last_seen, last)
            o.confidence = max(o.confidence, conf)
            o.origins.add(origin)
            if row.get("id") is not None:
                o.assets.add(str(row["id"]))
            if row.get("host_asset_id") is not None:
                o.host_assets.add(str(row["host_asset_id"]))
            o.port_mismatch = o.port_mismatch or len(ports) > 1
    return obs


def _edge(src: str, dst: str, ip: str, proto: str, port: int, o: _Obs,
          ambiguous: bool) -> EdgeOut:
    origin = SOURCE if SOURCE in o.origins else sorted(o.origins)[0]
    evidence: dict[str, Any] = {
        "origin": origin,
        "origins": sorted(o.origins),
        "host": ip,
        "port": port,
        "port_assets": sorted(o.assets),
        "host_assets": sorted(o.host_assets),
        "observed_at": o.last_seen.isoformat(),
        "assumptions": sorted(
            (["ambiguous_identity"] if ambiguous else []) + (["port_mismatch"] if o.port_mismatch else [])
            + (["protocol_assumed_any"] if proto == "any" else [])),
    }
    return EdgeOut(src_ref=src, dst_ref=dst, proto=proto, port_lo=port, port_hi=port,  # type: ignore[arg-type]
                   basis="observed", source=SOURCE, last_seen=o.last_seen,
                   confidence=o.confidence, evidence=evidence)


def _covered_scans(rows: ExternalRows, now: dt.datetime, max_age: dt.timedelta, nets: list[Any],
                   counters: dict[str, int]) -> dict[str, dict[str, Any]]:
    """ip -> scan facts, for public in-scope hosts whose latest completed scan was a full, clean one."""
    out: dict[str, dict[str, Any]] = {}
    for scan in rows.scans:
        ip = _ipmap.norm_ip(str(scan.get("target") or ""))
        fin = scan.get("finished_at")
        if ip is None or fin is None or not _ipmap.is_public_ip(ip) or not _in_scope(ip, nets):
            continue
        fin = min(_aware(fin), now)
        if now - fin > max_age:
            continue
        if _summary_failed(scan):
            counters["tool_failed"] += 1
            continue
        if not scan_covers_all_ports(scan.get("config")):
            counters["partial"] += 1
            continue
        prev = out.get(ip)
        if prev is None or fin > prev["finished_at"]:  # defensive: SQL already picks the latest
            out[ip] = {"finished_at": fin, "scan_id": str(scan.get("id"))}
    return out


def _coverage(full: dict[str, dict[str, Any]], ipm: _ipmap.IpMap, counters: dict[str, int]
              ) -> list[CoverageOut]:
    """One fact per node; an asset needs every public address of its own covered and unambiguous."""
    by_node: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for ip, facts in full.items():
        if ipm.is_ambiguous(ip):
            counters["ambiguous_uncovered"] += 1       # two assets claim it: cover neither
            continue
        by_node.setdefault(ipm.resolve(ip), []).append((ip, facts))
    out: list[CoverageOut] = []
    for ref, items in sorted(by_node.items()):
        if ref.startswith("asset:"):
            need = sorted(a for a in ipm.ips_of(ref) if _ipmap.is_public_ip(a))
            if not need or any(a not in full or ipm.resolve(a) != ref for a in need):
                counters["multi_ip_uncovered"] += 1
                continue
            items = [(a, full[a]) for a in need]
        oldest = min(f["finished_at"] for _, f in items)
        out.append(CoverageOut(
            node_ref=ref, direction="in", tier="observed", observed_at=oldest, source=SOURCE,
            detail={"ports": "1-65535", "proto": "tcp", "origin": "internet",
                    "ips": sorted(ip for ip, _ in items),
                    "scans": sorted(f["scan_id"] for _, f in items)}))
    return out


def build(rows: ExternalRows, now: dt.datetime, *, max_age: Optional[dt.timedelta] = None,
          **_opts: Any) -> BuildOutput:
    """Pure: ``internet -> host:port`` observed edges plus full-scan inbound coverage."""
    now = _aware(now)
    age = _max_age(max_age)
    nets = _scope_nets(rows.scope, now)
    ipm = _ipmap.build_ip_map(rows.assets)
    counters = {k: 0 for k in ("unparsable", "stale", "out_of_scope", "partial", "tool_failed",
                               "ambiguous_uncovered", "multi_ip_uncovered")}

    edges: list[EdgeOut] = []
    nodes: dict[str, NodeOut] = {refs.INTERNET: NodeOut(ref=refs.INTERNET, kind="internet",
                                                        label="internet")}
    seen: set[tuple[str, str, int, int]] = set()
    for (ip, proto, port), o in sorted(_observations(rows, now, age, nets, counters).items()):
        targets = ipm.resolve_all(ip)
        for dst in targets:
            key = (dst, proto, port, port)
            if key in seen:
                continue
            seen.add(key)
            edges.append(_edge(refs.INTERNET, dst, ip, proto, port, o, ambiguous=ipm.is_ambiguous(ip)))
            if dst.startswith("ip:") and dst not in nodes:
                nodes[dst] = NodeOut(ref=dst, kind="host", label=ip, attrs={"ips": [ip]})

    full = _covered_scans(rows, now, age, nets, counters)
    coverage = _coverage(full, ipm, counters)
    for cov in coverage:                                # a covered host is a known node even with 0 ports
        if cov.node_ref.startswith("ip:") and cov.node_ref not in nodes:
            ip = cov.node_ref[3:]
            nodes[cov.node_ref] = NodeOut(ref=cov.node_ref, kind="host", label=ip, attrs={"ips": [ip]})

    edges.sort(key=lambda e: (e.dst_ref, e.proto, e.port_lo, e.port_hi))
    return BuildOutput(
        source=SOURCE, mode="window", window=age,
        nodes=sorted(nodes.values(), key=lambda n: n.ref), edges=edges, coverage=coverage,
        notes=_notes(counters, ipm, len(edges), len(coverage)))


def _notes(c: Mapping[str, int], ipm: _ipmap.IpMap, n_edges: int, n_cov: int) -> list[str]:
    notes = [f"external_scan: {n_edges} exposure edge(s), {n_cov} host(s) with full-port coverage"]
    labels = (
        ("partial", "host(s) latest scan covered fewer than all 65535 ports: no coverage asserted"),
        ("tool_failed", "host(s) latest scan recorded a tool failure: no coverage asserted"),
        ("multi_ip_uncovered", "asset(s) with several public addresses not all fully scanned: "
                               "no coverage asserted"),
        ("ambiguous_uncovered", "scanned address(es) claimed by more than one asset: no coverage asserted"),
        ("stale", "port observation(s) older than the freshness window ignored"),
        ("out_of_scope", "port observation(s) on non-public or out-of-scope hosts ignored"),
        ("unparsable", "port asset(s) with an unparsable canonical ignored"),
    )
    notes += [f"external_scan: {c[k]} {text}" for k, text in labels if c[k]]
    notes += [f"external_scan: {line}" for line in ipm.report()]
    return notes
