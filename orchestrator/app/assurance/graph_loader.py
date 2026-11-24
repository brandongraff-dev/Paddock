"""Tables -> paddock_assurance graph document. Owned by the store work package (section 5).

``load_graph_doc`` is READ-ONLY and deterministic: the same rows always give the same document
(sorted nodes, edges and coverage facts), so a verdict digest is stable. The document is the
format of docs/ASSURANCE_P1.md section 3 and loads with ``paddock_assurance.ReachGraph.from_dict``.

Where the stored facts are coarser than the document can say, the loader widens rather than
narrows (a false HOLDS is the worst bug): an edge port range that touches port 0 becomes
``1-hi`` (or the full range when it is only port 0), and no edge is ever dropped. Coverage is
never given to the internet node.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import json
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from .refs import INTERNET, KINDS
from .store import Zone, _zone, resolve_zone

#: label values that explicitly turn a tag off (e.g. un-mark a metadata-derived crown jewel).
_FALSE_VALUES = frozenset({"false", "no", "0", "off"})
_SPECIAL_TAGS = frozenset({"zone", "class", "kind"})
_SOURCE_RANK = {"declared": 3, "connector": 2, "metadata": 1}
_IP_KEYS = ("ips", "public_ips", "private_ips", "ip")

_ASSET_SQL = (
    "SELECT id, kind, value, jsonb_build_object("
    "'crown_jewel', metadata->'crown_jewel', 'ips', metadata->'ips', "
    "'public_ips', metadata->'public_ips', 'private_ips', metadata->'private_ips', "
    "'ip', metadata->'ip') AS md FROM assets WHERE id = ANY($1::uuid[])"
)


#: Most edges the CIDR expansion may add to one document. Past it a destination keeps its CIDR
#: edge but loses its inbound coverage (so the evaluator assumes unknown edges into it) instead of
#: silently under-approximating who is inside the CIDR.
MAX_EXPANDED_EDGES = 400_000


@dataclass
class LoadDiagnostics:
    """Facts about the load that are not part of the document."""
    graph_version: int = 0
    #: destinations whose CIDR sources could not be expanded (cap hit): inbound coverage withdrawn.
    cidr_unexpanded: list[str] = field(default_factory=list)
    #: node id -> zone names its addresses resolved into (a multi-homed node in two zones).
    zone_conflicts: dict[str, list[str]] = field(default_factory=dict)


def _iso(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).isoformat()


def _truthy(v: Any) -> bool:
    if isinstance(v, str):
        return v.strip().lower() not in _FALSE_VALUES and v.strip() != ""
    return bool(v)


def _ports(proto: str, lo: int, hi: int) -> Optional[str]:
    """``'lo-hi'`` (library-parsable: 1..65535). ``None`` for icmp (no ports)."""
    if proto == "icmp":
        return None
    lo, hi = max(1, int(lo)), min(65535, int(hi))
    if hi < lo:                       # only port 0 / nonsense: widen, never narrow
        lo, hi = 1, 65535
    return f"{lo}-{hi}"


_ORIGINS = frozenset({"internet"})
_FACT_PROTOS = frozenset({"icmp", "tcp", "udp"})


def _add_qualifiers(fact: dict[str, str], detail: Any) -> bool:
    """Copy a builder's ``detail.origin`` / ``detail.proto`` onto the coverage fact.

    A scan that looked from the internet over TCP is not coverage against internal sources or UDP
    (the library only applies a qualified fact where it speaks). A qualifier the library does not
    know would make it reject the whole graph, so such a fact is dropped instead (False): a node
    left blind is the safe outcome.
    """
    if not isinstance(detail, dict):
        return True
    origin, proto = detail.get("origin"), detail.get("proto")
    if origin is not None:
        if origin not in _ORIGINS or fact["direction"] != "in":
            return False
        fact["origin"] = origin
    if proto is not None:
        if proto not in _FACT_PROTOS:
            return False
        fact["proto"] = proto
    return True


def _default_kind(ref: str) -> str:
    return {"internet": "internet", "ip": "ip", "cidr": "cidr"}.get(ref.partition(":")[0], "host")


def _ips_of(*sources: Any) -> list[str]:
    """Flatten ip-ish values (str or list) from several dict/obj sources, order-stable."""
    out: list[str] = []
    for src in sources:
        if not isinstance(src, dict):
            continue
        for k in _IP_KEYS:
            v = src.get(k)
            for item in ([v] if isinstance(v, str) else v if isinstance(v, list) else []):
                if isinstance(item, str) and item not in out:
                    out.append(item)
    return out


def _loads(v: Any) -> Any:
    if isinstance(v, str):
        try:
            return json.loads(v)
        except ValueError:
            return None
    return v


async def _fetch(conn) -> dict[str, Any]:
    return {
        "state": await conn.fetchrow("SELECT graph_version FROM assurance_state"),
        "nodes": await conn.fetch("SELECT node_ref, kind, asset_id, attrs FROM reach_nodes ORDER BY node_ref"),
        "edges": await conn.fetch(
            "SELECT src_ref, dst_ref, proto, port_lo, port_hi, basis, source FROM reach_edges "
            "ORDER BY src_ref, dst_ref, proto, port_lo, port_hi, source, basis"),
        "cov": await conn.fetch(
            "SELECT node_ref, direction, tier, observed_at, source, detail FROM reach_coverage "
            "ORDER BY node_ref, direction, source"),
        "labels": await conn.fetch("SELECT node_ref, tag, value, source FROM asset_labels ORDER BY node_ref, tag"),
        "zones": await conn.fetch("SELECT * FROM zones ORDER BY name"),
    }


async def _fetch_snapshot(conn) -> dict[str, Any]:
    """One consistent snapshot when we own the transaction; inside a caller's, just read."""
    if conn.is_in_transaction():
        return await _fetch(conn)
    async with conn.transaction(isolation="repeatable_read", readonly=True):
        return await _fetch(conn)


def _labels_by_node(rows: list[Any]) -> dict[str, dict[str, tuple[int, str]]]:
    by: dict[str, dict[str, tuple[int, str]]] = {}
    for r in rows:
        by.setdefault(r["node_ref"], {})[r["tag"]] = (_SOURCE_RANK.get(r["source"], 1), r["value"] or "")
    return by


def _node_doc(ref: str, kind: str, labels: dict[str, tuple[int, str]], md: dict[str, Any],
              zone: Optional[str], cov: list[dict[str, str]]) -> dict[str, Any]:
    """Labels: ``declared`` rows override metadata-derived defaults (crown jewel, data store)."""
    tags: set[str] = set()
    cls: Optional[str] = None
    if _truthy(md.get("crown_jewel")):
        tags.add("crown-jewel")
    if kind == "cloud_db":
        cls = "data_store"
    for tag, (_rank, value) in labels.items():
        if tag == "class":
            if value:
                cls = value
        elif tag == "kind":
            if value in KINDS:
                kind = value
        elif tag != "zone":
            if value.strip().lower() in _FALSE_VALUES:
                tags.discard(tag)
            else:
                tags.add(tag)
    doc: dict[str, Any] = {"id": ref, "kind": kind}
    if zone:
        doc["zone"] = zone
    if cls:
        doc["class"] = cls
    doc["tags"] = sorted(tags)
    if cov:
        doc["coverage"] = cov
    return doc


def _declared_zone_label(labels: dict[str, tuple[int, str]]) -> tuple[Optional[str], Optional[str]]:
    """``(declared zone, weaker non-declared zone)`` from the node's labels."""
    rank, value = labels.get("zone", (0, ""))
    if not value:
        return None, None
    return (value, None) if rank >= _SOURCE_RANK["declared"] else (None, value)


def _node_addrs(ref: str, attrs: Any, md: Any) -> list[Any]:
    """The addresses a node is known by (``[]`` = unknown, which may be anywhere)."""
    raw = [ref.partition(":")[2]] if ref.startswith("ip:") else _ips_of(attrs, md)
    out: list[Any] = []
    for v in raw:
        try:
            out.append(ipaddress.ip_address(str(v).strip()))
        except ValueError:
            continue
    return out


def _expand_cidr_sources(nodes: list[dict[str, Any]], edges: list[dict[str, Any]],
                         addrs: dict[str, list[Any]]) -> list[str]:
    """Make ``cidr:<net> -> dst`` mean what it says: every node inside ``net`` may connect to ``dst``.

    A security group rule "allow 10.0.0.0/8" is stored as an edge from the node ``cidr:10.0.0.0/8``,
    which is connected to nothing else in the graph. Without this step a guest laptop at 10.20.0.5
    (known only from Sentry) has no edge to that server, the server is covered inbound by its
    configuration, and "guest cannot reach the server" would HOLD although the rule admits it.
    A node whose addresses are unknown may be inside any CIDR, so it is included (D6). The
    ``internet`` node is never inside a CIDR (world-open rules on addressable nodes are already
    ``internet`` edges). Returns the destinations that could not be expanded within the cap; their
    inbound coverage is withdrawn from the document.
    """
    by_dst: dict[str, list[dict[str, Any]]] = {}
    for e in edges:
        if e["src"].startswith("cidr:"):
            by_dst.setdefault(e["dst"], []).append(e)
    if not by_dst:
        return []
    have = {(e["src"], e["dst"], e["proto"], e.get("ports"), e["basis"], e["source"]) for e in edges}
    members: dict[str, list[str]] = {}
    candidates = sorted(r for r in addrs if r != INTERNET and not r.startswith("cidr:"))
    added: list[dict[str, Any]] = []
    unexpanded: list[str] = []
    for dst in sorted(by_dst):
        new: list[dict[str, Any]] = []
        for e in by_dst[dst]:
            net = e["src"][len("cidr:"):]
            if net not in members:
                try:
                    n = ipaddress.ip_network(net, strict=False)
                except ValueError:
                    n = None
                members[net] = candidates if n is None else [
                    r for r in candidates if not addrs[r] or any(a.version == n.version and a in n for a in addrs[r])]
            for r in members[net]:
                if r == dst:
                    continue
                key = (r, dst, e["proto"], e.get("ports"), e["basis"], e["source"])
                if key not in have:
                    have.add(key)
                    new.append({**e, "src": r})
        if len(added) + len(new) > MAX_EXPANDED_EDGES:
            unexpanded.append(dst)
            continue
        added.extend(new)
    edges.extend(added)
    edges.sort(key=lambda d: (d["src"], d["dst"], d["proto"], d.get("ports", ""), d["source"], d["basis"]))
    if unexpanded:
        bad = set(unexpanded)
        for n in nodes:
            if n["id"] in bad and n.get("coverage"):
                n["coverage"] = [c for c in n["coverage"] if c["direction"] != "in"]
                if not n["coverage"]:
                    del n["coverage"]
    return unexpanded


async def load_graph_doc_with_diagnostics(conn, now: dt.datetime) -> tuple[dict[str, Any], LoadDiagnostics]:
    """Build the graph document and the side facts a runner may want to record."""
    snap = await _fetch_snapshot(conn)
    zones: list[Zone] = [_zone(r) for r in snap["zones"]]
    labels = _labels_by_node(snap["labels"])
    diag = LoadDiagnostics(graph_version=int(snap["state"]["graph_version"]) if snap["state"] else 0)

    kinds: dict[str, str] = {}
    attrs: dict[str, dict[str, Any]] = {}
    asset_ids: dict[str, str] = {}
    for r in snap["nodes"]:
        kinds[r["node_ref"]] = r["kind"] if r["kind"] in KINDS else _default_kind(r["node_ref"])
        a = _loads(r["attrs"])
        attrs[r["node_ref"]] = a if isinstance(a, dict) else {}
        if r["asset_id"]:
            asset_ids[r["node_ref"]] = str(r["asset_id"])
    for e in snap["edges"]:
        for ref in (e["src_ref"], e["dst_ref"]):
            kinds.setdefault(ref, _default_kind(ref))
    kinds[INTERNET] = "internet"
    for ref in list(kinds):                       # asset:<uuid> refs carry their own id
        if ref.startswith("asset:"):
            try:
                asset_ids.setdefault(ref, str(uuid.UUID(ref[len("asset:"):])))
            except ValueError:
                pass

    assets: dict[str, dict[str, Any]] = {}
    if asset_ids:
        for r in await conn.fetch(_ASSET_SQL, sorted(set(asset_ids.values()))):
            md = _loads(r["md"]) or {}
            if r["kind"] in ("ipv4", "ipv6"):
                md = dict(md, ip=r["value"])
            assets[str(r["id"])] = md

    cov_by: dict[str, list[dict[str, str]]] = {}
    for r in snap["cov"]:
        if r["node_ref"] == INTERNET:
            continue                              # the internet is never covered
        fact = {"direction": r["direction"], "tier": r["tier"],
                "observed_at": _iso(r["observed_at"]), "source": r["source"]}
        if not _add_qualifiers(fact, _loads(r["detail"])):
            continue                              # a qualifier we do not understand: no coverage
        cov_by.setdefault(r["node_ref"], []).append(fact)

    nodes: list[dict[str, Any]] = []
    for ref in sorted(kinds):
        lab = labels.get(ref, {})
        md = assets.get(asset_ids.get(ref, ""), {})
        if ref == INTERNET:
            zone: Optional[str] = INTERNET
        else:
            declared, weak = _declared_zone_label(lab)
            zone = declared
            if zone is None:
                if ref.startswith("ip:") or ref.startswith("cidr:"):
                    addrs = [ref.partition(":")[2]]
                else:
                    addrs = _ips_of(attrs.get(ref), md)
                zone, conflict = resolve_zone(zones, addrs)
                if conflict:
                    diag.zone_conflicts[ref] = conflict
                if zone is None:
                    zone = weak
        nodes.append(_node_doc(ref, kinds[ref], lab, md, zone,
                               sorted(cov_by.get(ref, []), key=lambda c: (c["direction"], c["source"], c["tier"]))
                               if ref != INTERNET else []))

    edges: list[dict[str, Any]] = []
    for e in sorted(snap["edges"], key=lambda r: (r["src_ref"], r["dst_ref"], r["proto"], r["port_lo"],
                                                   r["port_hi"], r["source"], r["basis"])):
        d: dict[str, Any] = {"src": e["src_ref"], "dst": e["dst_ref"], "proto": e["proto"]}
        ports = _ports(e["proto"], e["port_lo"], e["port_hi"])
        if ports is not None:
            d["ports"] = ports
        d["basis"] = e["basis"]
        d["source"] = e["source"]
        edges.append(d)

    addrs = {ref: _node_addrs(ref, attrs.get(ref), assets.get(asset_ids.get(ref, ""), {})) for ref in kinds}
    diag.cidr_unexpanded = _expand_cidr_sources(nodes, edges, addrs)
    doc = {"version": 1, "now": _iso(now), "nodes": nodes, "edges": edges}
    return doc, diag


async def load_graph_doc(conn, now: dt.datetime) -> dict[str, Any]:
    """The tenant's reach graph as a section-3 document (see module docstring)."""
    doc, _ = await load_graph_doc_with_diagnostics(conn, now)
    return doc
