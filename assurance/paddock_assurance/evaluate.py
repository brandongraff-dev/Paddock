"""The counterexample search.

Soundness rules (these are what make a HOLDS worth anything):

1. **Unknown is not safe.** Coverage is directional: a node can be blind *outbound* (we do not
   know what it connects to), blind *inbound* (we do not know what connects to it), or both. A
   connection ``u -> v`` needs ``u`` to open it and ``v`` to accept it, so an unknown edge
   ``u -> v`` can exist only if ``u`` is blind outbound **and** ``v`` is blind inbound. We search
   a second time with exactly those possible edges added; if a target becomes reachable only that
   way, the verdict is ``UNKNOWN``, never ``HOLDS``. (A security-group-style source covers
   ``in`` only, so it can never rule out what its node connects *out* to.)
2. **A selector that matches nothing is not a pass.** A typo in a zone name would otherwise make
   every invariant vacuously true.
3. **Violations win.** A known witness is ``VIOLATED`` whatever the coverage.
4. **Freshness is part of the verdict.** For every node-direction the verdict relied on, the best
   qualifying coverage fact is taken; ``evidence_tier`` is the weakest of those and
   ``valid_until`` the stalest plus ``max_age``; after it the verdict is ``EXPIRED``.
5. **Coverage itself can be asserted** (``assert: covered``): every selected node must be covered
   in both directions; each one that is not becomes a hop-less witness.

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
from .graph import INTERNET, DirState, Edge, Node, ReachGraph, direction_state, matches
from .model import Allow, Tier

MAX_WITNESSES = 5
PSEUDO_KINDS = frozenset({"internet", "cidr"})   # not coverable: outside the coverage universe
MAX_COVERED_WITNESSES = 50   # one per uncovered node: the list is the work queue


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
    direction: str = "both"   # which side is blind: in | out | both


@dataclass
class Result:
    invariant_id: str
    digest: str
    severity: str
    verdict: Verdict
    evaluated_at: dt.datetime
    assertion: str = ""      # unreachable | exposes-only | covered
    reasons: list[str] = field(default_factory=list)
    witnesses: list[Witness] = field(default_factory=list)
    violation_count: int = 0
    evidence_tier: Optional[Tier] = None
    valid_until: Optional[dt.datetime] = None
    coverage_universe: int = 0
    coverage_covered: int = 0
    coverage_required: float = 0.0
    # The floor is measured over the nodes this verdict is about (see _finish), not the whole tenant.
    relevant_universe: int = 0
    relevant_covered: int = 0
    blind_spots: list[BlindSpot] = field(default_factory=list)
    exceptions_used: list[dict[str, str]] = field(default_factory=list)
    expired_exceptions: list[dict[str, str]] = field(default_factory=list)
    confirmation: str = "not_run"
    boundaries_reached: list[str] = field(default_factory=list)  # nodes where the search stopped

    @property
    def coverage_ratio(self) -> float:
        return 1.0 if self.coverage_universe == 0 else self.coverage_covered / self.coverage_universe

    @property
    def relevant_ratio(self) -> float:
        return 1.0 if self.relevant_universe == 0 else self.relevant_covered / self.relevant_universe

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
            "assertion": self.assertion,
            "verdict": self.verdict.value,
            "reasons": list(self.reasons),
            "evaluated_at": iso(self.evaluated_at),
            "valid_until": iso(self.valid_until),
            "evidence_tier": self.evidence_tier.value if self.evidence_tier else None,
            "coverage": {"universe": self.coverage_universe, "covered": self.coverage_covered,
                         "ratio": round(self.coverage_ratio, 4), "required": self.coverage_required,
                         "relevant_universe": self.relevant_universe,
                         "relevant_covered": self.relevant_covered,
                         "relevant_ratio": round(self.relevant_ratio, 4)},
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
            blind_out: frozenset[str] = frozenset(), blind_in: frozenset[str] = frozenset(),
            stop: frozenset[str] = frozenset(),
            blind_in_net: Optional[frozenset[str]] = None) -> tuple[_Parent, dict[str, int]]:
    """Multi-source BFS. A possible (unknown) edge ``u -> v`` exists iff ``u`` is in ``blind_out``
    and ``v`` is in ``blind_in``. Nodes in ``stop`` are reached but not expanded (unless they
    are themselves sources).

    ``blind_in_net`` is the (smaller) set of nodes an *internet* source could still reach through
    an unknown edge: a node covered inbound only by an outside-in scan is in ``blind_in`` (anything
    inside the estate may reach it) but not in ``blind_in_net``. Default: the same as ``blind_in``."""
    pending = sorted(blind_in)           # blind-inbound nodes not reached yet
    pending_net = sorted(blind_in if blind_in_net is None else blind_in_net)
    parent: _Parent = {s: None for s in sorted(sources)}
    dist = {s: 0 for s in parent}
    q: deque[str] = deque(sorted(sources))
    while q:
        u = q.popleft()
        if dist[u] >= max_hops or (u in stop and u not in sources):
            continue
        cands: list[tuple[str, Optional[Edge]]] = [(e.dst, e) for e in g.out(u) if edge_ok(e)]
        if u in blind_out:
            # Everything still pending is first reached from here (BFS order), so the list is
            # consumed rather than rescanned: linear overall instead of blind_out x blind_in.
            cands += [(v, None) for v in (pending_net if u == INTERNET else pending) if v != u]
        # known edges sort before unknown ones for the same neighbour (stable sort on dst only)
        for v, e in sorted(cands, key=lambda c: (c[0], c[1] is None)):
            if v not in dist:
                dist[v] = dist[u] + 1
                parent[v] = (u, e)
                q.append(v)
        if u in blind_out:
            pending = [v for v in pending if v not in dist]
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
        # proto "any" is "all traffic" (an AWS -1 rule): it includes ICMP, so an icmp-only invariant
        # must not skip it.
        if plan.via_ports is not None and e.proto != "icmp":
            return bool(P.intersect(e.ports, plan.via_ports))
        return True
    return ok


def _active_allows(plan: Plan, now: dt.datetime) -> tuple[list[Allow], list[Allow]]:
    today = now.astimezone(dt.timezone.utc).date()
    active = [a for a in plan.invariant.allow if a.expires >= today]
    expired = [a for a in plan.invariant.allow if a.expires < today]
    return active, expired


@dataclass(frozen=True)
class _NodeCov:
    """A node's coverage in each direction at the evaluation time and policy."""

    inn: DirState                 # covered for every source and protocol
    out: DirState
    inn_net: DirState             # covered against the *internet* as the source (>= inn)

    def of(self, direction: str) -> DirState:
        return self.inn if direction == "in" else self.out

    def relied(self, direction: str) -> Optional[Any]:
        """The fact a verdict that relies on this node-direction rests on: the unqualified one if
        there is one, else (inbound only) the origin-qualified one."""
        st = self.of(direction)
        if st.fact is None and direction == "in":
            st = self.inn_net
        return st.fact

    @property
    def both(self) -> bool:
        return self.inn.covered and self.out.covered


def _coverage_map(plan: Plan, g: ReachGraph, now: dt.datetime) -> dict[str, _NodeCov]:
    return {n.id: _NodeCov(
        direction_state(n, "in", now, plan.min_tier, plan.max_age, protocols=plan.protocols),
        direction_state(n, "out", now, plan.min_tier, plan.max_age, protocols=plan.protocols),
        direction_state(n, "in", now, plan.min_tier, plan.max_age,
                        internet_src=True, protocols=plan.protocols))
        for n in g.nodes.values()}


def _blind_spots(cov: dict[str, _NodeCov], relevant: set[str]) -> list[BlindSpot]:
    """One row per blind node-direction; ``both`` only when both directions are blind for the same
    reason, so each row names a single thing to fix."""
    rows: list[BlindSpot] = []
    for n in sorted(cov):
        c = cov[n]
        if c.both:
            continue
        rel = n in relevant
        if not c.inn.covered and not c.out.covered and c.inn.reason == c.out.reason:
            rows.append(BlindSpot(n, str(c.inn.reason), rel, "both"))
            continue
        for d in ("in", "out"):
            st = c.of(d)
            if not st.covered:
                rows.append(BlindSpot(n, str(st.reason), rel, d))
    return rows


def _finish(res: Result, plan: Plan, g: ReachGraph, cov: dict[str, _NodeCov],
            relevant: set[str], relied: set[tuple[str, str]]) -> Result:
    """Fill coverage counts, blind spots and (for HOLDS) the evidence the verdict rests on.

    ``relied`` lists the (node, direction) pairs whose coverage the verdict depends on. For each
    the best qualifying fact is used; the weakest tier and the earliest expiry among them bound
    the whole verdict.
    """
    # The internet and CIDR blocks are not things a sensor can be installed on: counting them as
    # blind would cap a small estate below any coverage floor (5 covered hosts + the internet is
    # 0.83 of 6, under the 0.95 the std invariants ask for) however well it was covered.
    real = [n for n in g.nodes if g.nodes[n].kind not in PSEUDO_KINDS]
    res.coverage_universe = len(real)
    res.coverage_covered = sum(1 for n in real if cov[n].both)
    # The FLOOR is scoped to the nodes this verdict is about. A tenant-wide, both-direction ratio
    # made every std invariant UNKNOWN for any estate with AWS nodes: security groups can only
    # ever cover INBOUND, so the ratio sat near zero however well the relevant nodes were covered.
    # Soundness does not depend on the floor (unknown edges are searched regardless); the floor
    # is a disclosed policy overlay, so "some evidence in at least one direction" is the right bar.
    rel = [n for n in sorted(relevant) if n in g.nodes and g.nodes[n].kind not in PSEUDO_KINDS]
    res.relevant_universe = len(rel)
    res.relevant_covered = sum(1 for n in rel if cov[n].inn.covered or cov[n].out.covered)
    res.blind_spots = _blind_spots(cov, relevant)
    if res.verdict is Verdict.HOLDS:
        facts = [f for n, d in sorted(relied) if (f := cov[n].relied(d)) is not None]
        if facts:
            res.evidence_tier = min((f.tier for f in facts), key=lambda t: t.rank)
            res.valid_until = min(f.observed_at for f in facts) + plan.max_age
        floor = plan.kind is not PlanKind.COVERED
        if floor and res.relevant_ratio + 1e-12 < plan.coverage_required:
            res.verdict = Verdict.UNKNOWN
            res.reasons.append("coverage_below_required")
            res.evidence_tier, res.valid_until = None, None
    return res


def _new(plan: Plan, now: dt.datetime, verdict: Verdict, reason: str) -> Result:
    return Result(plan.id, plan.digest, plan.invariant.severity, verdict, now,
                  assertion=plan.invariant.assert_, reasons=[reason],
                  coverage_required=plan.coverage_required)


def _exc(a: Allow, target: str) -> dict[str, str]:
    return {"target": target, "reason": a.reason, "expires": a.expires.isoformat()}


# --------------------------------------------------------------------------------------------
# REACH: assert unreachable

def _reach_reliance(cov: dict[str, _NodeCov], expandable: list[str],
                    frontier: set[str]) -> set[tuple[str, str]]:
    """Which node-directions a REACH ``HOLDS`` stands on.

    ``expandable`` are the reached nodes the search could still have left from. Every possible
    edge ``u -> v`` from one of them was ruled out by ``u`` being covered outbound or ``v`` being
    covered inbound. We rely on all covered outbound ``u`` and on every covered inbound ``v`` that
    has some other expandable node to be reached from. That includes covered nodes far off the
    found paths, because if their coverage lapsed an unknown edge into them would appear.
    Either end alone would suffice, so this is deliberately the conservative union for nodes on
    the frontier, and an expiry only ever comes sooner, never later.
    """
    exp = set(expandable)
    blind_out = {u for u in exp if not cov[u].out.covered}
    relied: set[tuple[str, str]] = {(u, "out") for u in exp if cov[u].out.covered}
    for v, c in cov.items():
        if not c.inn_net.covered:      # (covered for every source implies covered for the internet)
            continue
        others = len(exp) - (v in exp)
        if others and (v in frontier or len(blind_out) - (v in blind_out) > 0):
            relied.add((v, "in"))
    return relied


def _eval_reach(plan: Plan, g: ReachGraph, now: dt.datetime) -> Result:
    inv = plan.invariant
    S = {n.id for n in g.select(inv.subjects.from_)}
    T = {n.id for n in g.select(inv.subjects.to)} - S
    cov = _coverage_map(plan, g, now)
    blind_out = frozenset(n for n, c in cov.items() if not c.out.covered)
    blind_in = frozenset(n for n, c in cov.items() if not c.inn.covered)
    blind_in_net = frozenset(n for n, c in cov.items() if not c.inn_net.covered)
    allows, expired = _active_allows(plan, now)

    def done(res: Result, relevant: set[str],
             relied: Optional[set[tuple[str, str]]] = None) -> Result:
        res.expired_exceptions = [_exc(a, "*") for a in expired]
        return _finish(res, plan, g, cov, relevant, relied or set())

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

    aparent, adist = _search(g, S, edge_ok, plan.max_hops, blind_out=blind_out,
                             blind_in=blind_in, stop=stop, blind_in_net=blind_in_net)
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
    expandable = sorted(u for u in aparent
                        if adist[u] < plan.max_hops and not (u in stop and u not in S))
    return done(res, relevant, _reach_reliance(cov, expandable, relevant))


# --------------------------------------------------------------------------------------------
# EXPOSURE_SET: assert exposes-only

def _eval_exposure(plan: Plan, g: ReachGraph, now: dt.datetime) -> Result:
    inv = plan.invariant
    S = {n.id for n in g.select(inv.subjects.from_)}
    T = {n.id for n in g.select(inv.subjects.to)} - S
    cov = _coverage_map(plan, g, now)
    allows, expired = _active_allows(plan, now)

    def done(res: Result, relevant: set[str],
             relied: Optional[set[tuple[str, str]]] = None) -> Result:
        res.expired_exceptions = [_exc(a, "*") for a in expired]
        return _finish(res, plan, g, cov, relevant, relied or set())

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

    # An unknown s -> t needs s blind outbound and t blind inbound (s != t: T excludes S).
    s_blind = sorted(s for s in S if not cov[s].out.covered)
    # (an internet source is only ruled out by an origin-qualified fact, anything else needs an
    # unqualified one)
    possible = [(s, t) for s in s_blind for t in sorted(T)
                if not (cov[t].inn_net if s == INTERNET else cov[t].inn).covered]
    if possible:
        res = _new(plan, now, Verdict.UNKNOWN, "possible_via_unknown_edges")
        res.witnesses = [_witness((Hop(s, t, "unknown", "", "unknown"),))
                         for s, t in possible[:MAX_WITNESSES]]
        res.exceptions_used = exc_list
        return done(res, relevant)

    res = _new(plan, now, Verdict.HOLDS, "no_counterexample")
    res.exceptions_used = exc_list
    # Either end rules s -> t out; both are counted (conservative: the weakest evidence wins).
    relied = {(s, "out") for s in S if cov[s].out.covered} \
        | {(t, "in") for t in T if cov[t].inn_net.covered}
    return done(res, relevant, relied)


# --------------------------------------------------------------------------------------------
# COVERED: assert covered

_REASON_RANK = {"no_sensor": 0, "tier_below_min": 1, "future_timestamp": 2, "stale": 3}


def _uncovered_witness(node: str, c: _NodeCov) -> Witness:
    """A hop-less witness: the node, which direction is blind, and why."""
    blind = [(d, c.of(d)) for d in ("in", "out") if not c.of(d).covered]
    direction = "both" if len(blind) == 2 else blind[0][0]
    reasons = {d: str(st.reason) for d, st in blind}
    detail = {"node": node, "direction": direction,
              # one machine-readable reason: the most fundamental one if the directions differ
              "reason": min(reasons.values(), key=lambda r: _REASON_RANK[r])}
    for d, r in sorted(reasons.items()):
        detail[f"reason_{d}"] = r
    return Witness((), "unknown", False, detail)


def _eval_covered(plan: Plan, g: ReachGraph, now: dt.datetime) -> Result:
    """HOLDS iff every selected node is covered in both directions, fresh, at ``min_tier``."""
    sel = [n.id for n in g.select(plan.invariant.subjects.to)]
    cov = _coverage_map(plan, g, now)
    if not sel:
        return _finish(_new(plan, now, Verdict.UNKNOWN, "empty_selector:to"), plan, g, cov,
                       set(), set())
    gaps = [(n, cov[n]) for n in sel if not cov[n].both]
    if gaps:
        res = _new(plan, now, Verdict.VIOLATED, "witness_found")
        ws = [_uncovered_witness(n, c) for n, c in gaps]
        # Root causes first: nodes nobody watches at all, then weak evidence, then quiet sensors.
        ws.sort(key=lambda w: (_REASON_RANK[w.detail["reason"]],
                               ("both", "in", "out").index(w.detail["direction"]),
                               w.detail["node"]))
        res.witnesses, res.violation_count = ws[:MAX_COVERED_WITNESSES], len(gaps)
        return _finish(res, plan, g, cov, set(sel), set())
    res = _new(plan, now, Verdict.HOLDS, "all_covered")
    relied = {(n, d) for n in sel for d in ("in", "out")}
    return _finish(res, plan, g, cov, set(sel), relied)


def evaluate(plan: Plan, graph: ReachGraph, now: dt.datetime) -> Result:
    """Evaluate one compiled invariant against a graph "as of" ``now`` (timezone-aware)."""
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    now = now.astimezone(dt.timezone.utc)
    if plan.kind is PlanKind.REACH:
        return _eval_reach(plan, graph, now)
    if plan.kind is PlanKind.COVERED:
        return _eval_covered(plan, graph, now)
    return _eval_exposure(plan, graph, now)


__all__ = ["BlindSpot", "Hop", "Result", "Verdict", "Witness", "evaluate", "Node"]
