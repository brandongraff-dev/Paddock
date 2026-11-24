"""The counterexample search.

Soundness rules (these are what make a HOLDS worth anything):

1. **Unknown is not safe.** A *blind* node (no sensor, stale, or evidence below the required
   tier) has unknown connections. Because a connection needs both ends to allow it, an unknown
   edge can only exist between two blind nodes. We therefore search a second time with a clique
   added among the blind nodes; if a target becomes reachable only that way, the verdict is
   ``UNKNOWN``, never ``HOLDS``.
2. **A selector that matches nothing is not a pass.** A typo in a zone name would otherwise make
   every invariant vacuously true.
3. **Violations win.** A known witness is ``VIOLATED`` whatever the coverage.
4. **Freshness is part of the verdict.** ``valid_until`` is the stalest evidence used plus
   ``max_age``; after it the verdict is ``EXPIRED``.

Output is deterministic: sorted adjacency, sorted tie-breaks, no hidden clock.
"""
from __future__ import annotations

import datetime as dt
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

from . import ports as P
from .compile import Plan, PlanKind
from .graph import Edge, Node, ReachGraph, blind_reason, matches
from .model import Allow, Tier

MAX_WITNESSES = 5


class Verdict(str, Enum):
    HOLDS = "HOLDS"
    VIOLATED = "VIOLATED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class Hop:
    src: str
    dst: str
    proto: str          # "unknown" for a possible edge between two blind nodes
    ports: str
    basis: str          # declared | configured | observed | tested | unknown
    source: str = ""


@dataclass(frozen=True)
class Witness:
    hops: tuple[Hop, ...]
    weakest_basis: str
    confirmed: bool     # every hop is at least `observed`; active confirmation arrives in P5
    detail: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class BlindSpot:
    node: str
    reason: str
    relevant: bool      # could an unknown edge at this node change the verdict?


@dataclass
class Result:
    invariant_id: str
    digest: str
    severity: str
    verdict: Verdict
    evaluated_at: dt.datetime
    reasons: list[str] = field(default_factory=list)
    witnesses: list[Witness] = field(default_factory=list)
    violation_count: int = 0
    evidence_tier: Optional[Tier] = None
    valid_until: Optional[dt.datetime] = None
    coverage_universe: int = 0
    coverage_covered: int = 0
    coverage_required: float = 0.0
    blind_spots: list[BlindSpot] = field(default_factory=list)
    exceptions_used: list[dict[str, str]] = field(default_factory=list)
    expired_exceptions: list[dict[str, str]] = field(default_factory=list)
    confirmation: str = "not_run"
    boundaries_reached: list[str] = field(default_factory=list)  # nodes where the search stopped

    @property
    def coverage_ratio(self) -> float:
        return 1.0 if self.coverage_universe == 0 else self.coverage_covered / self.coverage_universe

    def status_at(self, now: dt.datetime) -> str:
        """``EXPIRED`` once a HOLDS has outlived its evidence; otherwise the verdict."""
        if self.verdict is Verdict.HOLDS and self.valid_until is not None and now > self.valid_until:
            return "EXPIRED"
        return self.verdict.value

    def to_dict(self) -> dict[str, Any]:
        def iso(t: Optional[dt.datetime]) -> Optional[str]:
            return None if t is None else t.astimezone(dt.timezone.utc).isoformat() \
                .replace("+00:00", "Z")

        return {
            "invariant": self.invariant_id,
            "digest": self.digest,
            "severity": self.severity,
            "verdict": self.verdict.value,
            "reasons": list(self.reasons),
            "evaluated_at": iso(self.evaluated_at),
            "valid_until": iso(self.valid_until),
            "evidence_tier": self.evidence_tier.value if self.evidence_tier else None,
            "coverage": {"universe": self.coverage_universe, "covered": self.coverage_covered,
                         "ratio": round(self.coverage_ratio, 4), "required": self.coverage_required},
            "violation_count": self.violation_count,
            "witnesses": [{
                "hops": [h.__dict__ for h in w.hops],
                "weakest_basis": w.weakest_basis, "confirmed": w.confirmed, "detail": w.detail,
            } for w in self.witnesses],
            "blind_spots": [b.__dict__ for b in self.blind_spots],
            "exceptions_used": self.exceptions_used,
            "expired_exceptions": self.expired_exceptions,
            "confirmation": self.confirmation,
            "boundaries_reached": self.boundaries_reached,
        }


# --------------------------------------------------------------------------------------------
# search

_Parent = dict[str, Optional[tuple[str, Optional[Edge]]]]


def _search(g: ReachGraph, sources: set[str], edge_ok: Callable[[Edge], bool], max_hops: int,
            blind: frozenset[str] = frozenset(),
            stop: frozenset[str] = frozenset()) -> tuple[_Parent, dict[str, int]]:
    """Multi-source BFS. ``blind`` nodes are joined by possible (unknown) edges. Nodes in
    ``stop`` are reached but not expanded (unless they are themselves sources)."""
    blind_sorted = sorted(blind)
    parent: _Parent = {s: None for s in sorted(sources)}
    dist = {s: 0 for s in parent}
    q: deque[str] = deque(sorted(sources))
    while q:
        u = q.popleft()
        if dist[u] >= max_hops or (u in stop and u not in sources):
            continue
        cands: list[tuple[str, Optional[Edge]]] = [(e.dst, e) for e in g.out(u) if edge_ok(e)]
        if u in blind:
            cands += [(v, None) for v in blind_sorted if v != u]
        # known edges sort before unknown ones for the same neighbour (stable sort on dst only)
        for v, e in sorted(cands, key=lambda c: (c[0], c[1] is None)):
            if v not in dist:
                dist[v] = dist[u] + 1
                parent[v] = (u, e)
                q.append(v)
    return parent, dist


def _path(parent: _Parent, target: str) -> tuple[Hop, ...]:
    hops: list[Hop] = []
    cur = target
    while parent[cur] is not None:
        prev, e = parent[cur]  # type: ignore[misc]
        if e is None:
            hops.append(Hop(prev, cur, "unknown", "", "unknown"))
        else:
            hops.append(Hop(prev, cur, e.proto, P.format_ports(e.ports), e.basis.value, e.source))
        cur = prev
    return tuple(reversed(hops))


def _witness(hops: tuple[Hop, ...], detail: Optional[dict[str, str]] = None) -> Witness:
    ranks = {"declared": 0, "configured": 1, "observed": 2, "tested": 3, "unknown": -1}
    weakest = min(hops, key=lambda h: ranks[h.basis]).basis if hops else "declared"
    return Witness(hops, weakest, all(ranks[h.basis] >= 2 for h in hops), detail or {})


def _edge_filter(plan: Plan) -> Callable[[Edge], bool]:
    def ok(e: Edge) -> bool:
        if e.proto != "any" and e.proto not in plan.protocols:
            return False
        if e.proto == "any" and not (plan.protocols & {"tcp", "udp"}):
            return False
        if plan.via_ports is not None and e.proto != "icmp":
            return bool(P.intersect(e.ports, plan.via_ports))
        return True
    return ok


def _active_allows(plan: Plan, now: dt.datetime) -> tuple[list[Allow], list[Allow]]:
    today = now.astimezone(dt.timezone.utc).date()
    active = [a for a in plan.invariant.allow if a.expires >= today]
    expired = [a for a in plan.invariant.allow if a.expires < today]
    return active, expired


def _finish(res: Result, plan: Plan, g: ReachGraph, now: dt.datetime, blind: dict[str, str],
            relevant: set[str]) -> Result:
    res.coverage_universe = len(g.nodes)
    res.coverage_covered = len(g.nodes) - len(blind)
    res.blind_spots = [BlindSpot(n, blind[n], n in relevant) for n in sorted(blind)]
    if res.verdict is Verdict.HOLDS:
        covered_rel = [g.nodes[n] for n in sorted(relevant) if n not in blind]
        times = [n.coverage.observed_at for n in covered_rel if n.coverage]
        tiers = [n.coverage.tier for n in covered_rel if n.coverage]
        if tiers:
            res.evidence_tier = min(tiers, key=lambda t: t.rank)
        if times:
            res.valid_until = min(times) + plan.max_age
        if res.coverage_ratio + 1e-12 < plan.coverage_required:
            res.verdict = Verdict.UNKNOWN
            res.reasons.append("coverage_below_required")
            res.evidence_tier, res.valid_until = None, None
    return res


def _new(plan: Plan, now: dt.datetime, verdict: Verdict, reason: str) -> Result:
    return Result(plan.id, plan.digest, plan.invariant.severity, verdict, now, [reason],
                  coverage_required=plan.coverage_required)


def _exc(a: Allow, target: str) -> dict[str, str]:
    return {"target": target, "reason": a.reason, "expires": a.expires.isoformat()}


# --------------------------------------------------------------------------------------------
# REACH: assert unreachable

def _eval_reach(plan: Plan, g: ReachGraph, now: dt.datetime) -> Result:
    inv = plan.invariant
    S = {n.id for n in g.select(inv.subjects.from_)}
    T = {n.id for n in g.select(inv.subjects.to)} - S
    blind = {n.id: r for n in g.nodes.values()
             if (r := blind_reason(n, now, plan.min_tier, plan.max_age))}
    allows, expired = _active_allows(plan, now)

    def done(res: Result, relevant: set[str]) -> Result:
        res.expired_exceptions = [_exc(a, "*") for a in expired]
        return _finish(res, plan, g, now, blind, relevant)

    if not S or not T:
        which = "from" if not S else "to"
        return done(_new(plan, now, Verdict.UNKNOWN, f"empty_selector:{which}"), set(S) | set(T))

    exempt: dict[str, Allow] = {}
    for t in sorted(T):
        for a in allows:
            if matches(a.to, g.nodes[t]):
                exempt[t] = a
                break
    edge_ok = _edge_filter(plan)
    stop = frozenset(n.id for n in g.select(inv.via.stop_at)) if inv.via.stop_at else frozenset()
    parent, _ = _search(g, S, edge_ok, plan.max_hops, stop=stop)
    hit = sorted(t for t in T if t in parent)
    bad = [t for t in hit if t not in exempt]
    boundaries = sorted(n for n in stop if n in parent and n not in S)

    if bad:
        res = _new(plan, now, Verdict.VIOLATED, "witness_found")
        # Report root causes: drop a target whose path already runs through another violator.
        paths = {t: _path(parent, t) for t in bad}
        roots = [t for t in bad
                 if not ({h.src for h in paths[t]} & set(bad))]
        ws = sorted((_witness(paths[t]) for t in roots),
                    key=lambda w: (len(w.hops), w.hops[-1].dst, w.hops[0].src))
        res.witnesses, res.violation_count = ws[:MAX_WITNESSES], len(bad)
        res.exceptions_used = [_exc(exempt[t], t) for t in hit if t in exempt]
        res.boundaries_reached = boundaries
        return done(res, set(S) | set(T) | set(parent))

    aparent, _ = _search(g, S, edge_ok, plan.max_hops, blind=frozenset(blind), stop=stop)
    maybe = sorted(t for t in T if t in aparent and t not in exempt)
    relevant = set(S) | set(T) | set(aparent)
    if maybe:
        res = _new(plan, now, Verdict.UNKNOWN, "possible_via_unknown_edges")
        res.witnesses = [_witness(_path(aparent, t)) for t in maybe[:MAX_WITNESSES]]
        res.exceptions_used = [_exc(exempt[t], t) for t in hit if t in exempt]
        res.boundaries_reached = boundaries
        return done(res, relevant)

    res = _new(plan, now, Verdict.HOLDS, "no_counterexample")
    res.exceptions_used = [_exc(exempt[t], t) for t in hit if t in exempt]
    res.boundaries_reached = boundaries
    return done(res, relevant)


# --------------------------------------------------------------------------------------------
# EXPOSURE_SET: assert exposes-only

def _eval_exposure(plan: Plan, g: ReachGraph, now: dt.datetime) -> Result:
    inv = plan.invariant
    S = {n.id for n in g.select(inv.subjects.from_)}
    T = {n.id for n in g.select(inv.subjects.to)} - S
    blind = {n.id: r for n in g.nodes.values()
             if (r := blind_reason(n, now, plan.min_tier, plan.max_age))}
    allows, expired = _active_allows(plan, now)

    def done(res: Result, relevant: set[str]) -> Result:
        res.expired_exceptions = [_exc(a, "*") for a in expired]
        return _finish(res, plan, g, now, blind, relevant)

    if not S or not T:
        which = "from" if not S else "to"
        return done(_new(plan, now, Verdict.UNKNOWN, f"empty_selector:{which}"), set(S) | set(T))

    edge_ok = _edge_filter(plan)
    witnesses: list[Witness] = []
    used: dict[tuple[str, str], dict[str, str]] = {}
    violations = 0
    for e in g.edges:
        if e.src not in S or e.dst not in T or e.proto == "icmp" or not edge_ok(e):
            continue
        exposed = e.ports if plan.via_ports is None else P.intersect(e.ports, plan.via_ports)
        permitted = plan.allowed_ports
        for a in allows:
            if matches(a.to, g.nodes[e.dst]):
                extra = P.parse_ports(a.ports) if a.ports else P.FULL
                over = P.intersect(P.subtract(exposed, plan.allowed_ports), extra)
                if over:
                    used[(e.dst, a.reason)] = _exc(a, e.dst) | {"ports": P.format_ports(over)}
                permitted = P.merge(list(permitted) + list(extra))
        disallowed = P.subtract(exposed, permitted)
        if disallowed:
            violations += 1
            hop = Hop(e.src, e.dst, e.proto, P.format_ports(exposed), e.basis.value, e.source)
            witnesses.append(Witness((hop,), e.basis.value, e.basis.rank >= 2, {
                "disallowed_ports": P.format_ports(disallowed),
                "allowed_ports": P.format_ports(permitted),
                "disallowed_count": str(P.count(disallowed)),
            }))
    exc_list = [used[k] for k in sorted(used)]
    relevant = set(S) | set(T)
    if witnesses:
        res = _new(plan, now, Verdict.VIOLATED, "witness_found")
        witnesses.sort(key=lambda w: (w.hops[0].dst, w.hops[0].src, w.hops[0].proto))
        res.witnesses, res.violation_count, res.exceptions_used = \
            witnesses[:MAX_WITNESSES], violations, exc_list
        return done(res, relevant)

    possible = sorted((s, t) for s in S & blind.keys() for t in T & blind.keys() if s != t)
    if possible:
        res = _new(plan, now, Verdict.UNKNOWN, "possible_via_unknown_edges")
        res.witnesses = [_witness((Hop(s, t, "unknown", "", "unknown"),))
                         for s, t in possible[:MAX_WITNESSES]]
        res.exceptions_used = exc_list
        return done(res, relevant)

    res = _new(plan, now, Verdict.HOLDS, "no_counterexample")
    res.exceptions_used = exc_list
    return done(res, relevant)


def evaluate(plan: Plan, graph: ReachGraph, now: dt.datetime) -> Result:
    """Evaluate one compiled invariant against a graph "as of" ``now`` (timezone-aware)."""
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    now = now.astimezone(dt.timezone.utc)
    if plan.kind is PlanKind.REACH:
        return _eval_reach(plan, graph, now)
    return _eval_exposure(plan, graph, now)


__all__ = ["BlindSpot", "Hop", "Result", "Verdict", "Witness", "evaluate", "Node"]
