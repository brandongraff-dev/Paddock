"""AWS security groups -> reach edges and inbound coverage (docs/ASSURANCE_P1.md section 4.1).

Reads what the AWS connector already stored in ``assets`` (EC2 instances, RDS, load balancers and
security groups, whose metadata now carries ``ingress_rules``) and emits "may open a connection to"
edges with basis ``configured``. Nothing here talks to AWS or the network; ``build`` is pure.

Soundness rules (a false HOLDS is the worst failure, so every unknown widens, D6):

* Edges are over-approximate. Whatever the rules do not let us resolve (a prefix list, a security
  group we never synced, one with no modeled members, an unreadable CIDR) becomes "the whole
  world" and says so in ``evidence``. Security-group and CIDR sources also expand to every modeled
  node that could sit inside them, because a ``cidr:`` node by itself is connected to nothing.
* Coverage (direction ``in``, tier ``configured``) is asserted for a node only when **every**
  one of its groups has synced, untruncated rules and every rule was read. Anything less leaves
  the node blind so the evaluator adds unknown edges into it.
* Never direction ``out``: ingress rules say nothing about what a node connects to.
* Not modeled, so not claimed (D7): NACLs, route tables, egress, peering routes, ENIs of services
  we do not read (Lambda, Fargate, endpoints). They are over-approximated where a rule points at
  them and listed as blind spots, never treated as closed.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import json
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from ..refs import INTERNET, asset_ref, cidr_ref
from ..types import BuildOutput, CoverageOut, EdgeOut, NodeOut

SOURCE = "aws_sg"
TIER = "configured"

# Cap on edges created only by expanding a CIDR/SG source over modeled nodes (each is a possible
# n*m blow-up). A destination that would exceed it keeps its direct edges but loses coverage.
MAX_EXPANDED_EDGES = 50_000

_NODE_KIND = {"instance": "cloud_instance", "db_instance": "cloud_db"}
_PROTOS = ("tcp", "udp", "icmp", "any")
_WORLD4 = ipaddress.ip_network("0.0.0.0/0")
_SELECT = """
SELECT id::text AS id, canonical, last_seen, metadata
  FROM assets
 WHERE kind = 'cloud_resource'
   AND metadata->>'provider' = 'aws'
   AND (metadata->>'resource_type' = ANY($1::text[])
        OR metadata->>'resource_type' LIKE '%\\_load\\_balancer')
 ORDER BY canonical
"""
_RESOURCE_TYPES = ["instance", "db_instance", "security_group"]


# --------------------------------------------------------------------------- #
# Loading (read-only SQL; the connection is already tenant-bound)
# --------------------------------------------------------------------------- #

async def load(conn: Any, now: dt.datetime, **opts: Any) -> list[dict[str, Any]]:
    """AWS cloud_resource rows we model. Tenancy comes from the connection, never from SQL.

    Filters on ``metadata`` (provider/resource_type) rather than ``assets.source``: the bulk
    upsert never updates ``source`` on conflict, so a row first seen through another path would
    keep a different one.
    """
    out: list[dict[str, Any]] = []
    for r in await conn.fetch(_SELECT, _RESOURCE_TYPES):
        md = r["metadata"]
        if isinstance(md, (str, bytes)):
            try:
                md = json.loads(md)
            except ValueError:
                continue
        if not isinstance(md, dict):
            continue
        out.append({"id": str(r["id"]), "canonical": r["canonical"],
                    "last_seen": r["last_seen"], "metadata": md})
    return out


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #

def _utc(ts: Any) -> Optional[dt.datetime]:
    if not isinstance(ts, dt.datetime):
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=dt.timezone.utc)


def is_world_like(net: Any) -> bool:
    """True for ``/0`` and for public ranges so broad they stand in for "the internet".

    ``0.0.0.0/1`` plus ``128.0.0.0/1`` is the world spelled differently; a ``cidr:`` node would
    hide that from every internet invariant. Broad *private* ranges (10.0.0.0/8) stay CIDRs.
    """
    if net.prefixlen == 0:
        return True
    limit = 8 if net.version == 4 else 16
    return net.prefixlen < limit and not net.is_private


def _parse_net(value: Any) -> Optional[Any]:
    try:
        return ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError:
        return None


@dataclass(frozen=True)
class _Rule:
    proto: str
    lo: int
    hi: int
    sources: tuple[dict[str, Any], ...]
    ok: bool = True


def _parse_rule(rule: Any) -> _Rule:
    """A stored rule as the builder trusts it. Malformed means widen and flag, never skip."""
    bad = _Rule("any", 1, 65535, ({"type": "cidr", "value": "0.0.0.0/0", "unparsed": True},), False)
    if not isinstance(rule, dict):
        return bad
    proto = rule.get("proto")
    if proto not in _PROTOS:
        return bad
    try:
        lo, hi = int(rule["from"]), int(rule["to"])
    except (KeyError, TypeError, ValueError):
        lo, hi = 0, 65535
    if not (0 <= lo <= hi <= 65535):
        lo, hi = 0, 65535
    if proto == "icmp":
        lo, hi = 0, 0
    elif proto == "any":
        lo, hi = 1, 65535
    else:   # the store rejects port 0 for tcp/udp/any; a 0-only range widens instead of vanishing
        lo, hi = (1, 65535) if hi < 1 else (max(1, lo), hi)
    srcs = rule.get("sources")
    if not isinstance(srcs, list) or not all(isinstance(s, dict) for s in srcs):
        return bad
    return _Rule(proto, lo, hi, tuple(srcs))


@dataclass
class _Res:
    """One modeled AWS resource (a graph node)."""
    ref: str
    asset_id: str
    kind: str
    label: str
    canonical: str
    account: str
    region: str
    sg_ids: Optional[tuple[str, ...]]
    addressable: Optional[bool]
    last_seen: dt.datetime
    ips: tuple[Any, ...]
    attrs: dict[str, Any]


@dataclass
class _Sg:
    arn: str
    rules: Optional[list[Any]]
    truncated: bool
    last_seen: dt.datetime


@dataclass
class _Edge:
    sgs: set[str] = field(default_factory=set)
    rules: set[tuple[str, int]] = field(default_factory=set)
    lists: dict[str, set[str]] = field(default_factory=dict)
    flags: set[str] = field(default_factory=set)
    last: Optional[dt.datetime] = None
    src_asset: Optional[str] = None
    dst_asset: str = ""


def _node_kind(rtype: Any) -> Optional[str]:
    if rtype in _NODE_KIND:
        return _NODE_KIND[rtype]
    if isinstance(rtype, str) and rtype.endswith("_load_balancer"):
        return "cloud_lb"
    return None


def _addressable(kind: str, md: dict[str, Any]) -> Optional[bool]:
    """Can the internet address this node at all? ``None`` means the data does not say."""
    if kind == "cloud_instance":
        ips = md.get("public_ips")
        return bool(ips) if isinstance(ips, list) else None
    if kind == "cloud_db":
        v = md.get("publicly_accessible")
        return v if isinstance(v, bool) else None
    scheme = md.get("scheme")
    if scheme == "internet-facing":
        return True
    return False if scheme == "internal" else None


def _ips(md: dict[str, Any]) -> tuple[Any, ...]:
    out: list[Any] = []
    for key in ("private_ips", "public_ips"):
        for v in md.get(key) if isinstance(md.get(key), list) else []:
            try:
                out.append(ipaddress.ip_address(str(v)))
            except ValueError:
                continue
    return tuple(out)


def _str(v: Any) -> str:
    return v if isinstance(v, str) else ""


def _resource(row: dict[str, Any], now: dt.datetime) -> Optional[_Res]:
    md = row.get("metadata") or {}
    kind = _node_kind(md.get("resource_type"))
    seen = _utc(row.get("last_seen"))
    if kind is None or seen is None:
        return None
    try:
        ref = asset_ref(row["id"])
    except (KeyError, ValueError):
        return None
    sgs = md.get("security_groups")
    sg_ids = tuple(sorted({g for g in sgs if isinstance(g, str) and g})) if isinstance(sgs, list) else None
    addr = _addressable(kind, md)
    acct, region = _str(md.get("account_id")), _str(md.get("region"))
    attrs: dict[str, Any] = {
        "arn": row.get("canonical"), "account_id": acct, "region": region,
        "resource_type": md.get("resource_type"), "security_groups": list(sg_ids or ()),
        "addressable": addr,
        "public_ips": sorted(str(v) for v in md.get("public_ips") or [] if isinstance(v, str)),
        "private_ips": sorted(str(v) for v in md.get("private_ips") or [] if isinstance(v, str)),
    }
    if md.get("vpc_id"):
        attrs["vpc_id"] = str(md["vpc_id"])
    label = str(md.get("name") or md.get("instance_id") or row.get("canonical") or ref)[:200]
    return _Res(ref, str(row["id"]), kind, label, str(row.get("canonical") or ""), acct, region,
                sg_ids, addr, min(seen, now), _ips(md), attrs)


def _security_group(row: dict[str, Any], now: dt.datetime) -> Optional[tuple[tuple[str, str, str], _Sg]]:
    md = row.get("metadata") or {}
    if md.get("resource_type") != "security_group":
        return None
    acct, region, gid = _str(md.get("account_id")), _str(md.get("region")), _str(md.get("group_id"))
    seen = _utc(row.get("last_seen"))
    if not (acct and region and gid) or seen is None:
        return None
    rules = md.get("ingress_rules")
    return (acct, region, gid), _Sg(
        str(row.get("canonical") or ""), rules if isinstance(rules, list) else None,
        md.get("ingress_truncated") is True, min(seen, now))


class _Builder:
    def __init__(self, rows: Iterable[dict[str, Any]], now: dt.datetime, max_expanded: int):
        self.now = _utc(now) or dt.datetime.now(dt.timezone.utc)
        self.max_expanded = max_expanded
        self.res: dict[str, _Res] = {}
        self.sgs: dict[tuple[str, str, str], _Sg] = {}
        for row in sorted((r for r in rows if isinstance(r, dict)),
                          key=lambda r: (str(r.get("canonical")), str(r.get("id")))):
            parsed = _security_group(row, self.now)
            if parsed:
                self.sgs[parsed[0]] = parsed[1]
                continue
            res = _resource(row, self.now)
            if res:
                self.res[res.ref] = res
        self.members: dict[tuple[str, str, str], list[str]] = {}
        for ref in sorted(self.res):
            r = self.res[ref]
            for gid in r.sg_ids or ():
                self.members.setdefault((r.account, r.region, gid), []).append(ref)
        self.edges: dict[tuple[str, str, str, int, int], _Edge] = {}
        self.cidr_nodes: dict[str, str] = {}
        self.coverage: list[CoverageOut] = []
        self.notes: dict[str, set[str]] = {}
        self.expanded = 0

    def note(self, key: str, item: str) -> None:
        self.notes.setdefault(key, set()).add(item)

    # -- edges ------------------------------------------------------------- #
    def add_edge(self, src: str, dst: _Res, rule: _Rule, sg_id: str, idx: int, last: dt.datetime,
                 *, src_asset: Optional[str] = None, flags: Iterable[str] = (),
                 lists: Optional[dict[str, str]] = None) -> None:
        if src == dst.ref:
            return
        e = self.edges.setdefault((src, dst.ref, rule.proto, rule.lo, rule.hi),
                                  _Edge(dst_asset=dst.asset_id))
        e.sgs.add(sg_id)
        e.rules.add((sg_id, idx))
        e.flags.update(flags)
        for k, v in (lists or {}).items():
            e.lists.setdefault(k, set()).add(v)
        e.last = last if e.last is None else min(e.last, last)
        if src_asset:
            e.src_asset = src_asset

    def top_ref(self, net: Any, dst: _Res, flags: set[str]) -> str:
        """The node a world-like source stands for: the internet only if dst is addressable."""
        if dst.addressable is not False:
            if dst.addressable is None:
                flags.add("assumed_public")
            return INTERNET
        ref = cidr_ref(str(net))
        self.cidr_nodes[ref] = str(net)
        return ref

    def expand(self, net: Any, dst: _Res) -> Optional[list[_Res]]:
        """Modeled nodes that could be inside ``net``; ``None`` when the cap is hit."""
        world = is_world_like(net)
        out = [r for ref, r in sorted(self.res.items()) if r.ref != dst.ref and (
            world or not r.ips or any(i.version == net.version and i in net for i in r.ips))]
        if self.expanded + len(out) > self.max_expanded:
            return None
        self.expanded += len(out)
        return out

    def add_source(self, dst: _Res, rule: _Rule, sg_id: str, idx: int, last: dt.datetime,
                   src: dict[str, Any]) -> bool:
        """Emit the edges one rule source implies. False when the expansion cap was hit."""
        flags: set[str] = set()
        lists: dict[str, str] = {}
        stype, value = src.get("type"), _str(src.get("value"))
        if src.get("unparsed"):
            flags.add("unparsed_source")
        net: Any = None
        members: list[str] = []
        if stype in ("cidr", "cidr6"):
            net = _parse_net(value)
            if net is None:
                net = _WORLD4
                flags.add("unparsed_source")
        elif stype == "prefix_list":
            net = _WORLD4
            lists["prefix_list"] = value
            self.note("prefix", value)
        elif stype == "sg":
            key = (_str(src.get("account")) or dst.account, dst.region, value)
            if key not in self.sgs:
                net = _WORLD4
                lists["unresolved_sg"] = value
                self.note("unresolved", value)
            else:
                members = [m for m in self.members.get(key, []) if m != dst.ref]
                if not self.members.get(key):
                    net = _WORLD4
                    lists["unmodeled_sg_members"] = value
                    self.note("unmodeled", value)
                else:
                    lists["via_sg"] = value
        else:
            net = _WORLD4
            flags.add("unparsed_source")
        for m in members:
            self.add_edge(m, dst, rule, sg_id, idx, last, src_asset=self.res[m].asset_id,
                          lists=lists)
        if net is None:
            return True
        if is_world_like(net) and net.prefixlen != 0:
            flags.add("broad_public_cidr")
        lists = {**lists, "via_cidr": str(net)} if "via_sg" not in lists else lists
        ref = self.top_ref(net, dst, flags) if is_world_like(net) else cidr_ref(str(net))
        if ref.startswith("cidr:"):
            self.cidr_nodes[ref] = str(net)
        self.add_edge(ref, dst, rule, sg_id, idx, last, flags=flags, lists=lists)
        scope = self.expand(net, dst)
        if scope is None:
            return False
        for r in scope:
            self.add_edge(r.ref, dst, rule, sg_id, idx, last, src_asset=r.asset_id,
                          flags={"ip_unknown"} if not r.ips and not is_world_like(net) else (),
                          lists=lists)
        return True

    # -- per destination ----------------------------------------------------- #
    def process(self, dst: _Res) -> None:
        if not dst.sg_ids or not dst.account or not dst.region:
            self.note("nosg", dst.label)
            return
        complete, oldest = True, dst.last_seen
        for gid in dst.sg_ids:
            sg = self.sgs.get((dst.account, dst.region, gid))
            if sg is None:
                self.note("missing", gid)
                complete = False
                continue
            oldest = min(oldest, sg.last_seen)
            if sg.rules is None:
                self.note("norules", gid)
                complete = False
                continue
            if sg.truncated:
                self.note("truncated", gid)
                complete = False
            for idx, raw in enumerate(sg.rules):
                rule = _parse_rule(raw)
                if not rule.ok:
                    self.note("malformed", gid)
                    complete = False
                for src in rule.sources:
                    if not self.add_source(dst, rule, gid, idx, sg.last_seen, src):
                        self.note("capped", dst.label)
                        complete = False
        if complete:
            self.coverage.append(CoverageOut(
                dst.ref, "in", TIER, oldest, SOURCE,
                {"security_groups": list(dst.sg_ids), "synced_rules": True}))

    # -- output -------------------------------------------------------------- #
    def output(self) -> BuildOutput:
        nodes = [NodeOut(r.ref, r.kind, r.label, r.asset_id, r.attrs)
                 for _, r in sorted(self.res.items())]
        for ref, net in sorted(self.cidr_nodes.items()):
            nodes.append(NodeOut(ref, "cidr", net, None, {"cidr": net}))
        if any(k[0] == INTERNET for k in self.edges):
            nodes.append(NodeOut(INTERNET, "internet", "internet"))
        nodes.sort(key=lambda n: n.ref)
        edges = [self._edge_out(k, e) for k, e in sorted(self.edges.items())]
        return BuildOutput(SOURCE, "replace", nodes, edges,
                           sorted(self.coverage, key=lambda c: c.node_ref), None, self._notes())

    def _edge_out(self, key: tuple[str, str, str, int, int], e: _Edge) -> EdgeOut:
        src, dst, proto, lo, hi = key
        ev: dict[str, Any] = {
            "dst_asset": e.dst_asset, "sg": sorted(e.sgs),
            "rules": [{"sg": g, "index": i} for g, i in sorted(e.rules)]}
        if e.src_asset:
            ev["src_asset"] = e.src_asset
        for k, v in sorted(e.lists.items()):
            ev[k] = sorted(v)
        for f in sorted(e.flags):
            ev[f] = True
        return EdgeOut(src, dst, proto, lo, hi, TIER, SOURCE, e.last or self.now, None, 100, ev)  # type: ignore[arg-type]

    def _notes(self) -> list[str]:
        text = {
            "nosg": "node(s) with no security-group data (no inbound coverage): ",
            "missing": "security group(s) referenced by a node but not synced (node left blind): ",
            "norules": "security group(s) without synced ingress rules (node left blind): ",
            "truncated": "security group(s) whose rules were capped (node left blind): ",
            "malformed": "security group(s) with an unreadable rule, widened to world-open: ",
            "capped": "node(s) whose CIDR/SG expansion hit the edge cap (node left blind): ",
            "prefix": "prefix list(s) treated as world-open, membership is not synced: ",
            "unresolved": "referenced security group(s) not synced, treated as world-open: ",
            "unmodeled": "referenced security group(s) with no modeled member (ENIs of unread "
                         "services?), treated as world-open: ",
        }
        out = []
        for key in sorted(self.notes):
            items = sorted(self.notes[key])
            shown = ", ".join(items[:5]) + (f" (+{len(items) - 5} more)" if len(items) > 5 else "")
            out.append(f"aws_sg: {len(items)} {text[key]}{shown}")
        return out


def build(rows: list[dict[str, Any]], now: dt.datetime, **opts: Any) -> BuildOutput:
    """Pure: rows as returned by :func:`load` -> nodes, edges, inbound coverage and notes."""
    b = _Builder(rows, now, int(opts.get("max_expanded_edges", MAX_EXPANDED_EDGES)))
    for ref in sorted(b.res):
        b.process(b.res[ref])
    return b.output()
