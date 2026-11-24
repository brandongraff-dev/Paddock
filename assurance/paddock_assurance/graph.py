"""The directed reach graph (in-memory, loaded from JSON).

Edge ``A -> B`` means "A may open connections to B" on the given protocol and ports.

**Coverage is a property of nodes and it is directional and multi-source.** A node carries a
list of coverage *facts*, each saying "for direction ``in`` / ``out`` / ``both`` we know every
connection completely, as of ``observed_at``, at ``tier``". A security group's ingress rules cover
a node *inbound* and say nothing about what the node connects out to, so a fact must never be read
wider than its direction.

A connection ``u -> v`` needs ``u`` to be allowed to open it (outbound) and ``v`` to accept it
(inbound). So an *unknown* edge ``u -> v`` can exist only if ``u`` is **not covered outbound** and
``v`` is **not covered inbound**. The evaluator uses exactly that rule to stay sound.
"""
from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

from . import ports as P
from .model import Selector, Tier

PROTOS = ("icmp", "tcp", "udp", "any")
MAX_NODES = 200_000
MAX_EDGES = 2_000_000


class GraphError(ValueError):
    pass


DIRECTIONS = ("in", "out", "both")
#: The id of the one node that stands for everything outside the estate.
INTERNET = "internet"
#: Optional qualifiers of a coverage fact (see ``Coverage``). Anything else is a GraphError.
ORIGINS = ("", INTERNET)
FACT_PROTOS = ("", "icmp", "tcp", "udp")
MAX_COVERAGE_FACTS = 32
FUTURE_SLACK = dt.timedelta(minutes=5)
# When no fact qualifies, report the reason closest to qualifying (a quiet sensor beats a missing
# one). Independent of fact order, so the output is deterministic.
_REASON_ORDER = ("stale", "future_timestamp", "tier_below_min", "no_sensor")


@dataclass(frozen=True)
class Coverage:
    """One coverage fact. ``direction`` says which side of a node's connections it speaks for.

    ``origin`` and ``proto`` narrow what the fact is complete *for*. An outside-in TCP port scan
    knows every TCP port the internet can reach, and nothing about connections from inside the
    estate or about UDP, so it carries ``origin="internet"`` and ``proto="tcp"``. A qualified fact
    only rules out an unknown edge whose source and protocols it speaks for (``applies``); an
    unqualified fact (the default) speaks for every source and protocol.
    """

    tier: Tier
    observed_at: dt.datetime
    source: str = ""
    direction: str = "both"
    origin: str = ""
    proto: str = ""

    def covers(self, direction: str) -> bool:
        return self.direction == "both" or self.direction == direction

    def applies(self, internet_src: bool, protocols: frozenset[str]) -> bool:
        """Does this fact rule out unknown edges from the given kind of source over ``protocols``?"""
        if self.origin == INTERNET and not internet_src:
            return False
        return self.proto == "" or protocols <= {self.proto}


@dataclass(frozen=True)
class Node:
    id: str
    kind: str = "host"
    zone: Optional[str] = None
    tags: frozenset[str] = frozenset()
    cls: Optional[str] = None
    coverage: tuple[Coverage, ...] = ()


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    proto: str
    ports: P.Intervals
    basis: Tier
    source: str = ""
    last_seen: Optional[dt.datetime] = None

    def sort_key(self) -> tuple:
        return (self.dst, -self.basis.rank, self.proto, self.ports, self.source)


@dataclass
class ReachGraph:
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    now: Optional[dt.datetime] = None  # optional "as of" carried by the file
    _out: dict[str, list[Edge]] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        self._index()

    def _index(self) -> None:
        self.edges = sorted(self.edges, key=lambda e: (e.src,) + e.sort_key())
        out: dict[str, list[Edge]] = {n: [] for n in self.nodes}
        for e in self.edges:
            out[e.src].append(e)
        self._out = out

    def out(self, node_id: str) -> list[Edge]:
        return self._out.get(node_id, [])

    def select(self, sel: Optional[Selector]) -> list[Node]:
        """Nodes matching ``sel`` (``None`` = every node), sorted by id."""
        res = [n for n in self.nodes.values() if sel is None or matches(sel, n)]
        return sorted(res, key=lambda n: n.id)

    # ----- loading --------------------------------------------------------------------------

    @classmethod
    def from_dict(cls, doc: Any) -> "ReachGraph":
        if not isinstance(doc, dict):
            raise GraphError("graph document must be an object")
        ver = doc.get("version", 1)
        if type(ver) is not int or ver != 1:      # True == 1 and 1.0 == 1 must not pass
            raise GraphError("unsupported graph version")
        raw_nodes, raw_edges = doc.get("nodes", []), doc.get("edges", [])
        if not isinstance(raw_nodes, list) or not isinstance(raw_edges, list):
            raise GraphError("'nodes' and 'edges' must be lists")
        if len(raw_nodes) > MAX_NODES or len(raw_edges) > MAX_EDGES:
            raise GraphError("graph too large")
        nodes: dict[str, Node] = {}
        for i, rn in enumerate(raw_nodes):
            n = _node(rn, i)
            if n.id in nodes:
                raise GraphError(f"duplicate node id {n.id!r}")
            nodes[n.id] = n
        edges = [_edge(re_, i, nodes) for i, re_ in enumerate(raw_edges)]
        now = _ts(doc["now"], "now") if doc.get("now") is not None else None
        return cls(nodes=nodes, edges=edges, now=now)

    @classmethod
    def from_json(cls, text: str) -> "ReachGraph":
        try:
            return cls.from_dict(json.loads(text))
        except json.JSONDecodeError as exc:
            raise GraphError(f"invalid JSON: {exc.msg}") from exc

    @classmethod
    def from_file(cls, path: str | Path) -> "ReachGraph":
        return cls.from_json(Path(path).read_text(encoding="utf-8"))


def matches(sel: Selector, node: Node) -> bool:
    if sel.id and node.id not in sel.id:
        return False
    if sel.zone and node.zone not in sel.zone:
        return False
    if sel.kind and node.kind not in sel.kind:
        return False
    if sel.cls and node.cls not in sel.cls:
        return False
    if sel.tag and not (node.tags & set(sel.tag)):
        return False
    return True


def _ts(value: Any, what: str) -> dt.datetime:
    if not isinstance(value, str):
        raise GraphError(f"{what}: timestamp must be an ISO-8601 string")
    try:
        t = dt.datetime.fromisoformat(value)
    except ValueError as exc:
        raise GraphError(f"{what}: bad timestamp {value!r}") from exc
    if t.tzinfo is None:
        raise GraphError(f"{what}: timestamp needs a timezone (use Z or +00:00)")
    try:
        return t.astimezone(dt.timezone.utc)
    except (ValueError, OverflowError) as exc:      # year 0001 / 9999 at a non-UTC offset
        raise GraphError(f"{what}: timestamp out of range {value!r}") from exc


def _node(raw: Any, i: int) -> Node:
    if not isinstance(raw, dict) or not isinstance(raw.get("id"), str) or not raw["id"]:
        raise GraphError(f"nodes[{i}]: needs a string 'id'")
    nid = raw["id"]
    tags = raw.get("tags", [])
    if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
        raise GraphError(f"node {nid!r}: 'tags' must be a list of strings")
    cov = _coverage(raw.get("coverage"), nid)
    zone, cls = raw.get("zone"), raw.get("class")
    for what, v in (("zone", zone), ("class", cls)):
        if v is not None and not isinstance(v, str):
            raise GraphError(f"node {nid!r}: {what!r} must be a string")
    return Node(id=nid, kind=str(raw.get("kind", "host")), zone=zone,
                tags=frozenset(tags), cls=cls, coverage=cov)


def _qualifier(c: dict, key: str, nid: str) -> str:
    """A fact's ``origin`` / ``proto``: absent (unqualified) or a non-empty string.

    A qualifier that is *present* but not a usable string (0, false, [], "", null) must not be read
    as "no qualifier": an unqualified fact speaks for every source and protocol, so dropping a
    qualifier a builder meant to apply would widen the claim. Fail loudly instead."""
    if key not in c:
        return ""
    v = c[key]
    if not isinstance(v, str) or not v:
        raise GraphError(f"node {nid!r}: coverage {key} must be a non-empty string when given")
    return v


def _tier(value: Any, message: str) -> Tier:
    if not isinstance(value, str):
        raise GraphError(message)
    try:
        return Tier(value)
    except ValueError as exc:
        raise GraphError(message) from exc


def _fact(c: Any, nid: str, *, legacy: bool) -> Coverage:
    if not isinstance(c, dict):
        raise GraphError(f"node {nid!r}: a coverage fact must be an object")
    if "direction" in c:
        direction = c["direction"]
    elif legacy:
        direction = "both"      # the P0 single-object form
    else:
        # A fact in a list must say which way it looks. Defaulting to "both" would let a builder
        # that forgot the field claim more than it knows.
        raise GraphError(f"node {nid!r}: coverage fact needs a 'direction' (in, out or both)")
    if not isinstance(direction, str) or direction not in DIRECTIONS:
        raise GraphError(f"node {nid!r}: bad coverage direction {direction!r}")
    origin, proto = _qualifier(c, "origin", nid), _qualifier(c, "proto", nid)
    if origin not in ORIGINS or proto not in FACT_PROTOS:
        raise GraphError(f"node {nid!r}: bad coverage origin/proto {origin!r}/{proto!r}")
    if origin and direction != "in":
        raise GraphError(f"node {nid!r}: a coverage fact with an origin must have direction 'in'")
    tier = _tier(c.get("tier"), f"node {nid!r}: bad coverage tier {c.get('tier')!r}")
    return Coverage(tier, _ts(c.get("observed_at"), f"node {nid!r} observed_at"),
                    str(c.get("source", "")), direction, origin, proto)


def _coverage(raw: Any, nid: str) -> tuple[Coverage, ...]:
    """A list of facts, the P0 single object (= both directions), or nothing."""
    if raw is None:
        return ()
    if isinstance(raw, dict):
        return (_fact(raw, nid, legacy=True),)
    if not isinstance(raw, list):
        raise GraphError(f"node {nid!r}: 'coverage' must be an object or a list of objects")
    if len(raw) > MAX_COVERAGE_FACTS:
        raise GraphError(f"node {nid!r}: too many coverage facts (max {MAX_COVERAGE_FACTS})")
    return tuple(sorted((_fact(c, nid, legacy=False) for c in raw),
                        key=lambda f: (f.direction, f.tier.rank, f.observed_at, f.source, f.origin,
                                       f.proto)))


def _edge(raw: Any, i: int, nodes: dict[str, Node]) -> Edge:
    if not isinstance(raw, dict):
        raise GraphError(f"edges[{i}]: must be an object")
    src, dst = raw.get("src"), raw.get("dst")
    if not isinstance(src, str) or not isinstance(dst, str) or src not in nodes or dst not in nodes:
        raise GraphError(f"edges[{i}]: src/dst must name existing nodes ({src!r} -> {dst!r})")
    proto = raw.get("proto", "tcp")
    if not isinstance(proto, str) or proto not in PROTOS:
        raise GraphError(f"edges[{i}]: proto must be one of {PROTOS}")
    basis = _tier(raw.get("basis", "configured"), f"edges[{i}]: bad basis {raw.get('basis')!r}")
    if proto == "icmp":
        ports: P.Intervals = ()
    elif "ports" in raw:
        try:
            ports = P.parse_ports(raw["ports"])
        except ValueError as exc:
            raise GraphError(f"edges[{i}]: {exc}") from exc
    else:
        ports = P.FULL
    last = _ts(raw["last_seen"], f"edges[{i}] last_seen") if raw.get("last_seen") is not None else None
    return Edge(src, dst, proto, ports, basis, str(raw.get("source", "")), last)


def _fact_reason(c: Coverage, now: dt.datetime, min_tier: Tier, max_age: dt.timedelta) \
        -> Optional[str]:
    """Why this single fact does not qualify, else ``None``."""
    if c.tier.rank < min_tier.rank:
        return "tier_below_min"
    if c.observed_at > now + FUTURE_SLACK:
        return "future_timestamp"
    if now - c.observed_at > max_age:
        return "stale"
    return None


@dataclass(frozen=True)
class DirState:
    """Coverage of one node in one direction: the best qualifying fact, or why there is none."""

    fact: Optional[Coverage]
    reason: Optional[str]       # None iff covered

    @property
    def covered(self) -> bool:
        return self.reason is None


_ALL_PROTOS = frozenset({"icmp", "tcp", "udp"})


def direction_state(node: Node, direction: str, now: dt.datetime, min_tier: Tier,
                    max_age: dt.timedelta, *, internet_src: bool = False,
                    protocols: frozenset[str] = _ALL_PROTOS) -> DirState:
    """Is ``node`` covered in ``direction`` (``in`` or ``out``)?

    Any fresh fact of at least ``min_tier`` whose direction is that one (or ``both``) qualifies.
    The *best* qualifying fact (highest tier, then freshest) is returned so a verdict's evidence
    tier and expiry come from a single fact that really holds, never a mix of two.

    By default only unqualified facts count (every source, every protocol): the safe answer for
    "could *anything* connect to this node". Pass ``internet_src`` and ``protocols`` to ask the
    narrower question "could the *internet* connect over these protocols", which origin- and
    proto-qualified facts (an outside-in TCP scan) can answer.
    """
    facts = [c for c in node.coverage if c.covers(direction) and c.applies(internet_src, protocols)]
    if not facts:
        return DirState(None, "no_sensor")
    ok = [c for c in facts if _fact_reason(c, now, min_tier, max_age) is None]
    if ok:
        best = max(ok, key=lambda c: (c.tier.rank, c.observed_at, c.source, c.direction))
        return DirState(best, None)
    reasons = {_fact_reason(c, now, min_tier, max_age) for c in facts}
    return DirState(None, next(r for r in _REASON_ORDER if r in reasons))


def blind_reason(node: Node, now: dt.datetime, min_tier: Tier, max_age: dt.timedelta,
                 direction: str = "both") -> Optional[str]:
    """``None`` when the node is covered in ``direction``, else a machine-readable reason.

    ``both`` means covered only if covered in *both* directions (the in-direction reason is
    reported first when both are lacking).
    """
    dirs = ("in", "out") if direction == "both" else (direction,)
    for d in dirs:
        r = direction_state(node, d, now, min_tier, max_age).reason
        if r is not None:
            return r
    return None


def iter_nodes(g: ReachGraph, ids: Iterable[str]) -> list[Node]:
    return [g.nodes[i] for i in sorted(ids)]
