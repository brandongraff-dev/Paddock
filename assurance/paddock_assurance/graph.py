"""The directed reach graph (P0: in-memory, loaded from JSON).

Edge ``A -> B`` means "A may open connections to B" on the given protocol and ports.
**Coverage is a property of nodes**: a *covered* node is one whose incident connections we know
completely (fresh evidence of at least the required tier). A connection needs both ends to allow
it, so a covered endpoint is enough to rule an edge *out*. Unknown edges can therefore only exist
between two *blind* (uncovered) nodes. The evaluator uses exactly that to stay sound.
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


@dataclass(frozen=True)
class Coverage:
    tier: Tier
    observed_at: dt.datetime
    source: str = ""


@dataclass(frozen=True)
class Node:
    id: str
    kind: str = "host"
    zone: Optional[str] = None
    tags: frozenset[str] = frozenset()
    cls: Optional[str] = None
    coverage: Optional[Coverage] = None


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
        if doc.get("version", 1) != 1:
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
        now = _ts(doc["now"], "now") if doc.get("now") else None
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
    return t.astimezone(dt.timezone.utc)


def _node(raw: Any, i: int) -> Node:
    if not isinstance(raw, dict) or not isinstance(raw.get("id"), str) or not raw["id"]:
        raise GraphError(f"nodes[{i}]: needs a string 'id'")
    nid = raw["id"]
    tags = raw.get("tags", [])
    if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
        raise GraphError(f"node {nid!r}: 'tags' must be a list of strings")
    cov = None
    if raw.get("coverage") is not None:
        c = raw["coverage"]
        if not isinstance(c, dict):
            raise GraphError(f"node {nid!r}: 'coverage' must be an object")
        try:
            tier = Tier(c.get("tier"))
        except ValueError as exc:
            raise GraphError(f"node {nid!r}: bad coverage tier {c.get('tier')!r}") from exc
        cov = Coverage(tier, _ts(c.get("observed_at"), f"node {nid!r} observed_at"),
                       str(c.get("source", "")))
    return Node(id=nid, kind=str(raw.get("kind", "host")), zone=raw.get("zone"),
                tags=frozenset(tags), cls=raw.get("class"), coverage=cov)


def _edge(raw: Any, i: int, nodes: dict[str, Node]) -> Edge:
    if not isinstance(raw, dict):
        raise GraphError(f"edges[{i}]: must be an object")
    src, dst = raw.get("src"), raw.get("dst")
    if src not in nodes or dst not in nodes:
        raise GraphError(f"edges[{i}]: src/dst must name existing nodes ({src!r} -> {dst!r})")
    proto = raw.get("proto", "tcp")
    if proto not in PROTOS:
        raise GraphError(f"edges[{i}]: proto must be one of {PROTOS}")
    try:
        basis = Tier(raw.get("basis", "configured"))
    except ValueError as exc:
        raise GraphError(f"edges[{i}]: bad basis {raw.get('basis')!r}") from exc
    if proto == "icmp":
        ports: P.Intervals = ()
    elif "ports" in raw:
        try:
            ports = P.parse_ports(raw["ports"])
        except ValueError as exc:
            raise GraphError(f"edges[{i}]: {exc}") from exc
    else:
        ports = P.FULL
    last = _ts(raw["last_seen"], f"edges[{i}] last_seen") if raw.get("last_seen") else None
    return Edge(src, dst, proto, ports, basis, str(raw.get("source", "")), last)


def blind_reason(node: Node, now: dt.datetime, min_tier: Tier, max_age: dt.timedelta) \
        -> Optional[str]:
    """``None`` when the node is covered, else a machine-readable reason."""
    c = node.coverage
    if c is None:
        return "no_sensor"
    if c.tier.rank < min_tier.rank:
        return "tier_below_min"
    if c.observed_at > now + dt.timedelta(minutes=5):
        return "future_timestamp"
    if now - c.observed_at > max_age:
        return "stale"
    return None


def iter_nodes(g: ReachGraph, ids: Iterable[str]) -> list[Node]:
    return [g.nodes[i] for i in sorted(ids)]
