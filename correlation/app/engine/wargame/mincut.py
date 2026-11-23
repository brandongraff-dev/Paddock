"""Minimum-cost fix set over open routes — a weighted hitting-set solver.

The job (``docs/WARGAME.md`` §2.1): given the open routes the backward search
found, pick the cheapest set of changes that breaks *every* one of them. Each
open route is the set of cuttable elements (candidate ids) that lie on it
(:attr:`Route.fix_elements`). A fix set ``S`` **breaks** a route iff ``S``
intersects that route's element set, and we must break every open route.

This is the **minimum-cost hitting set** (equivalently weighted set cover): we
hit every route-set with the lowest total candidate cost. It is NOT a simple
min-cut, and it must NOT be solved by enumerating paths and counting them —
that over-counts and explodes combinatorially. We work directly over the
(entry, jewel) route element-sets.

**Minimum-cost hitting set is NP-hard.** So:

* For small instances (``≤ _EXACT_MAX_ELEMENTS`` distinct candidate ids across
  the *reduced* routes) we run an exact branch-and-bound. It is labelled
  ``optimality="exact"`` only when the search **completed** (it carries a
  node limit, :data:`_BNB_NODE_LIMIT`; if that is hit the better of its
  incumbent and the greedy answer is returned, labelled ``"greedy"``).
* For larger instances we fall back to the classic cost-effective greedy
  (repeatedly take the candidate maximising newly-covered-routes per unit
  cost) and label it ``optimality="greedy"``. We never call a greedy result
  "minimal".

``"greedy"`` therefore means "not proven minimal" (the persisted schema only
admits ``exact``/``greedy``). :class:`VerifiedFixSet.solver` records which
algorithm actually ran.

Listed routes vs the model. The backward search lists *example* routes,
bounded by a hop limit, a per-pair cap and a budget; a hitting set over that
listing is only a hitting set over the listing. :func:`fix_set_for` therefore
refuses to claim ``cuts_all``/``exact`` when the listing is incomplete for any
open pair (:attr:`ReachabilityResult.incomplete_pairs`).
:func:`verified_fix_set` closes the gap: it solves, removes every edge the fix
set cuts, re-runs exact reachability and, while any pair is still open, adds
the surviving routes as new constraints and re-solves (lazy constraint
generation), reporting ``cuts_all=True`` only when the post-fix model has no
open pair left. Because every added constraint is a real route, each solve is
over a relaxation of the true problem, so an exact solve that verifies is
the true optimum.

Because cost drives selection, a cheaper **compensating control** (e.g.
``cost_class="compensating"``) is chosen over an expensive ``device_patch``
whenever it also cuts the route — the optimiser prefers the low-cost change
that happens to hit the same routes rather than the "impossible"/very-high
``device_patch`` class, with no special-casing. A route with no cuttable
element (an inferred hop with no modelled control) cannot be cut at all; it is
reported in ``uncut_routes`` and forces ``cuts_all=False``, but the rest of the
routes are still covered optimally.

Pure Python, stdlib only, deterministic.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Iterable, Optional

from . import reachability
from .model import (
    DEFAULT_COST_CLASSES,
    Edge,
    FixCandidate,
    FixSet,
    Node,
    ReachabilityResult,
    Route,
    RuleSet,
)

#: Cost used for a candidate id we cannot price (unknown cost class, or a
#: candidate id that appears on a route but has no :class:`FixCandidate`).
#: Documented default so pricing never silently reads as free.
DEFAULT_UNKNOWN_COST: float = 5.0

#: Exact branch-and-bound is used when the number of distinct candidate ids
#: appearing across the (reduced) routes is at most this; otherwise we fall
#: back to greedy. Hitting set is NP-hard, so the exact solver is only safe to
#: run on small instances.
_EXACT_MAX_ELEMENTS: int = 24

#: Hard cap on branch-and-bound search nodes. Hitting the cap means the
#: search did not complete, so the result is NOT labelled exact.
_BNB_NODE_LIMIT: int = 250_000


def cost_for(cost_class: str, overrides: "dict[str, float] | None" = None) -> float:
    """Cost weight for a cost class.

    Looks the class up in :data:`DEFAULT_COST_CLASSES` merged with ``overrides``
    (overrides win). An unknown class falls back to
    :data:`DEFAULT_UNKNOWN_COST` (``5.0``) rather than ``0`` so an unpriced
    change never reads as free.
    """
    table: dict[str, float] = dict(DEFAULT_COST_CLASSES)
    if overrides:
        table.update(overrides)
    return float(table.get(cost_class, DEFAULT_UNKNOWN_COST))


def _cost_of(candidate_id: str, candidates: "dict[str, FixCandidate]") -> float:
    """Cost of one candidate id. Uses the candidate's own ``cost``; an id with
    no modelled candidate falls back to :data:`DEFAULT_UNKNOWN_COST`."""
    cand = candidates.get(candidate_id)
    if cand is None:
        return DEFAULT_UNKNOWN_COST
    return float(cand.cost)


def _checked_costs(
    ids: "Iterable[str]", candidates: "dict[str, FixCandidate]"
) -> "dict[str, float]":
    """Price every id, rejecting negative / non-finite costs: they would make
    the branch-and-bound pruning and lower bound unsound."""
    out: dict[str, float] = {}
    for cid in ids:
        c = _cost_of(cid, candidates)
        if not math.isfinite(c) or c < 0:
            raise ValueError(f"fix candidate {cid!r} has invalid cost {c!r}")
        out[cid] = c
    return out


def _reduce_routes(
    route_sets: "list[frozenset[str]]",
) -> "list[frozenset[str]]":
    """Drop duplicate and superset routes.

    If one route's element-set is a subset of another's, any fix hitting the
    smaller set also hits the larger (the hitting element is in both), so the
    larger (superset) route is redundant for covering purposes. Deduplicating
    and keeping only subset-minimal routes shrinks the search without changing
    the optimum. Deterministic: input order is irrelevant to the output set.
    Empty sets must be filtered out by the caller.
    """
    uniq = sorted({r for r in route_sets}, key=lambda r: (len(r), tuple(sorted(r))))
    minimal: list[frozenset[str]] = []
    for r in uniq:
        if any(m <= r for m in minimal):
            # some already-kept route is a subset of r → r is a superset,
            # hitting the kept one hits r too.
            continue
        minimal.append(r)
    return minimal


def _bits(mask: int) -> "list[int]":
    out = []
    while mask:
        low = mask & -mask
        out.append(low.bit_length() - 1)
        mask ^= low
    return out


def _lower_bound(eff: "list[int]", cost: "list[float]") -> float:
    """Admissible lower bound on the cost to hit every route mask in ``eff``.

    Greedily collects pairwise-disjoint routes; disjoint routes need distinct
    hitting elements, so the cost is at least the sum over them of each
    route's cheapest (still allowed) element. Never over-estimates.
    """
    keyed = []
    for r in eff:
        bs = _bits(r)
        cheapest = min(cost[b] for b in bs)
        keyed.append(((len(bs), -cheapest, tuple(bs)), r, cheapest))
    keyed.sort(key=lambda k: k[0])
    used = 0
    lb = 0.0
    for _, r, cheapest in keyed:
        if r & used:
            continue
        lb += cheapest
        used |= r
    return lb


def _branch_and_bound(
    routes: "list[frozenset[str]]",
    costs: "dict[str, float]",
    *,
    node_limit: Optional[int] = None,
) -> "tuple[Optional[list[str]], bool]":
    """Exact minimum-cost hitting set via branch-and-bound over bitmasks.

    ``routes`` must be non-empty element-sets (already reduced). Returns
    ``(selected, proven)``; ``proven`` is False when the node limit stopped
    the search (``selected`` is then the best incumbent, possibly ``None``).
    Deterministic throughout:

    * ids map to bits in sorted-id order;
    * the most-constrained uncovered route (fewest still-allowed options,
      then lexically smallest) is chosen to branch on;
    * its candidates are tried in ascending (cost, id) order, and branch
      ``i`` *forbids* the options tried before it (a standard exclusion
      that removes duplicate subtrees without losing any solution);
    * a disjoint-route lower bound prunes branches that cannot beat the
      incumbent (ties are pruned, so the first optimum found is kept).
    """
    if not routes:
        return [], True
    if node_limit is None:
        node_limit = _BNB_NODE_LIMIT
    ids = sorted({c for r in routes for c in r})
    bit = {c: i for i, c in enumerate(ids)}
    cost = [costs[c] for c in ids]
    masks = [sum(1 << bit[c] for c in r) for r in routes]

    best_cost = [math.inf]
    best_sel: list[Optional[int]] = [None]
    nodes = [0]
    aborted = [False]

    def recurse(sel: int, cur: float, remaining: "list[int]", forbidden: int) -> None:
        if aborted[0]:
            return
        nodes[0] += 1
        if nodes[0] > node_limit:
            aborted[0] = True
            return
        if not remaining:
            if cur < best_cost[0]:
                best_cost[0] = cur
                best_sel[0] = sel
            return
        allowed = ~forbidden
        eff = [r & allowed for r in remaining]
        if any(e == 0 for e in eff):
            return  # some route can no longer be hit in this subtree
        if cur + _lower_bound(eff, cost) >= best_cost[0]:
            return
        route = min(eff, key=lambda r: (bin(r).count("1"), tuple(_bits(r))))
        options = sorted(_bits(route), key=lambda b: (cost[b], b))
        excluded = 0
        for b in options:
            new_cost = cur + cost[b]
            if new_cost >= best_cost[0]:
                break  # options are cost-ascending: the rest cannot win
            m = 1 << b
            recurse(sel | m, new_cost, [r for r in remaining if not r & m], forbidden | excluded)
            if aborted[0]:
                return
            excluded |= m

    recurse(0, 0.0, masks, 0)
    sel = best_sel[0]
    chosen = None if sel is None else [ids[b] for b in _bits(sel)]
    return chosen, not aborted[0]


def _greedy(
    routes: "list[frozenset[str]]",
    costs: "dict[str, float]",
) -> "list[str]":
    """Classic cost-effective greedy weighted set cover.

    Repeatedly selects the candidate maximising (newly-covered routes / cost).
    Deterministic tie-break: higher ratio, then lower cost, then lower id
    (candidates are scanned in sorted-id order and only a strictly better key
    replaces the incumbent, so the lowest id wins an exact tie).
    """
    uncovered = [set(r) for r in routes if r]
    selected: list[str] = []
    while uncovered:
        universe = sorted({c for r in uncovered for c in r})
        best_id: Optional[str] = None
        best_key: Optional[tuple[float, float]] = None
        for cand in universe:
            newly = sum(1 for r in uncovered if cand in r)
            c = costs[cand]
            ratio = newly / c if c > 0 else math.inf
            key = (ratio, -c)
            if best_key is None or key > best_key:
                best_key = key
                best_id = cand
        if best_id is None:  # nothing left can cover anything
            break
        selected.append(best_id)
        uncovered = [r for r in uncovered if best_id not in r]
    return selected


def _solve(
    routes: "list[frozenset[str]]",
    candidates: "dict[str, FixCandidate]",
) -> "tuple[list[str], bool, str]":
    """Solve over non-empty routes. Returns ``(selected, proven, solver)``."""
    reduced = _reduce_routes([r for r in routes if r])
    if not reduced:
        return [], True, "none"
    ids = {c for r in reduced for c in r}
    costs = _checked_costs(ids, candidates)
    if len(ids) <= _EXACT_MAX_ELEMENTS:
        sel, proven = _branch_and_bound(reduced, costs)
        if proven and sel is not None:
            return sel, True, "branch_and_bound"
        greedy = _greedy(reduced, costs)
        if sel is None or sum(costs[c] for c in greedy) < sum(costs[c] for c in sel):
            sel = greedy
        return sel, False, "branch_and_bound_incomplete"
    return _greedy(reduced, costs), False, "greedy"


def min_cost_fix_set(
    routes: "list[frozenset[str]]",
    candidates: "dict[str, FixCandidate]",
) -> FixSet:
    """Cheapest set of candidates that breaks every given route.

    ``routes[i]`` is the set of cuttable candidate ids on open route ``i``
    (:attr:`Route.fix_elements`). The returned :class:`FixSet`:

    * ``selected`` — chosen candidate ids, sorted;
    * ``total_cost`` — sum of their costs;
    * ``cuts_all`` — ``True`` iff every input route is intersected by
      ``selected`` (checked, not assumed);
    * ``uncut_routes`` — sorted input indices of routes ``selected`` does not
      intersect: those with no cuttable element (an inferred hop with no
      modelled control) cannot be cut;
    * ``optimality`` — ``"exact"`` only when the branch-and-bound completed;
      ``"greedy"`` otherwise (not proven minimal).

    This only speaks for the routes it is given; see :func:`verified_fix_set`
    for a fix set checked against the model. Raises ``ValueError`` for a
    negative or non-finite candidate cost.
    """
    selected, proven, _solver = _solve(routes, candidates)
    selected_sorted = sorted(set(selected))
    chosen = set(selected_sorted)
    uncut = [i for i, r in enumerate(routes) if not (r & chosen)]
    total = round(sum(_cost_of(c, candidates) for c in selected_sorted), 10)
    return FixSet(
        selected=selected_sorted,
        total_cost=total,
        cuts_all=not uncut,
        uncut_routes=uncut,
        optimality="exact" if proven else "greedy",
    )


def fix_set_for(
    result: ReachabilityResult,
    candidates: "dict[str, FixCandidate]",
) -> FixSet:
    """Minimum-cost fix set over the *listed* open routes in ``result``.

    Pulls :attr:`Route.fix_elements` for every route whose (entry, jewel) pair
    is in ``result.open_pairs`` (conditional pairs are open, so they are
    included) and solves. Routes of closed pairs are ignored.

    Honesty: the listing is bounded. If any open pair's listing is incomplete
    (``result.incomplete_pairs``, which includes pairs with no listed route at
    all, or ``result.budget_exhausted``), the answer is not proven to cut it:
    ``cuts_all`` is ``False`` and ``optimality`` is ``"greedy"`` (not proven
    minimal). Use :func:`verified_fix_set` for a fix set checked against the
    model.
    """
    route_sets = [
        r.fix_elements for r in result.routes if r.pair in result.open_pairs
    ]
    fs = min_cost_fix_set(route_sets, candidates)
    incomplete = (
        bool(set(result.incomplete_pairs) & set(result.open_pairs))
        or bool(result.budget_exhausted)
    )
    if incomplete:
        fs.cuts_all = False
        fs.optimality = "greedy"
    return fs


# ---------------------------------------------------------------------------
# Verified fix set (solve → apply → re-check → add routes → re-solve)
# ---------------------------------------------------------------------------


@dataclass
class VerifiedFixSet(FixSet):
    """A :class:`FixSet` checked against the model by re-running reachability
    with the selected fixes applied.

    Inherited fields keep their meaning; ``uncut_routes`` indexes
    :attr:`routes`. ``cuts_all`` is ``True`` only when the post-fix model has
    no open pair among :attr:`target_pairs`.
    """

    #: The post-fix model was re-checked and every *cuttable* target pair is
    #: closed in it (uncuttable pairs are reported in ``uncut_pairs``).
    verified: bool = False
    #: The open pairs the fix set was asked to cut.
    target_pairs: set[tuple[str, str]] = field(default_factory=set)
    #: Target pairs still open in the post-fix model (uncuttable ones plus
    #: any not closed within ``max_iters``).
    uncut_pairs: set[tuple[str, str]] = field(default_factory=set)
    #: Target pairs no combination of candidates can cut (still open with
    #: every candidate applied — e.g. an uncontrolled inferred hop).
    uncuttable_pairs: set[tuple[str, str]] = field(default_factory=set)
    #: Solve/verify rounds run.
    iterations: int = 0
    #: The routes the final solve was constrained by (the listing plus the
    #: routes added by verification), then example routes of uncuttable pairs.
    routes: list[Route] = field(default_factory=list)
    #: ``"branch_and_bound"`` | ``"branch_and_bound_incomplete"`` |
    #: ``"greedy"`` | ``"none"`` — which solver produced the final selection.
    solver: str = "none"


def apply_fix_set(edges: "list[Edge]", selected: "Iterable[str]") -> "list[Edge]":
    """The edges left once every edge whose ``fix_candidate_id`` is in
    ``selected`` is cut. Pure; the input list is not modified."""
    cut = set(selected)
    return [e for e in edges if not (e.fix_candidate_id and e.fix_candidate_id in cut)]


def _route_key(r: Route) -> tuple:
    return (
        r.entry,
        r.jewel,
        tuple((h.src, h.dst, tuple(sorted(h.fix_candidate_ids))) for h in r.hops),
    )


def verified_fix_set(
    nodes: "dict[str, Node]",
    edges: "list[Edge]",
    rulesets: "dict[str, RuleSet]",
    candidates: "dict[str, FixCandidate]",
    *,
    pairs: "Optional[Iterable[tuple[str, str]]]" = None,
    max_iters: int = 25,
    max_hops: int = 8,
    max_routes_per_pair: int = 16,
    result: "Optional[ReachabilityResult]" = None,
) -> VerifiedFixSet:
    """Cheapest fix set that **provably** closes every open target pair.

    1. Run :func:`reachability.backward_reachability` on the model (or use
       ``result`` when the caller already has it for this exact model and
       these limits). Targets are its open pairs (restricted to ``pairs``
       when given).
    2. Pairs still open with *every* fix candidate on the edges applied are
       uncuttable; they are reported, not targeted.
    3. Solve the hitting set over the listed routes of the cuttable targets
       (truncated pairs contribute their witness route).
    4. Cut every edge whose ``fix_candidate_id`` was selected
       (:func:`apply_fix_set`) and re-run exact reachability. If a target is
       still open, add its surviving routes (or a shortest witness) as new
       constraints — each avoids every selected fix, so it is genuinely new —
       and re-solve. Repeat until verified or ``max_iters`` rounds.

    Every fix id carried by an edge is selectable; ids missing from
    ``candidates`` are priced at :data:`DEFAULT_UNKNOWN_COST`.

    Returns a :class:`VerifiedFixSet`: ``cuts_all`` is ``True`` iff the
    post-fix model has no open target pair; ``uncut_pairs`` lists those that
    stay open; ``optimality`` is ``"exact"`` only when verified and every
    final solve was a completed branch-and-bound (a relaxation optimum that
    is feasible for the full problem is its optimum), else ``"greedy"``.
    """
    base = result if result is not None else reachability.backward_reachability(
        nodes, edges, rulesets,
        max_hops=max_hops, max_routes_per_pair=max_routes_per_pair,
    )
    target = set(base.open_pairs)
    if pairs is not None:
        target &= set(pairs)

    all_ids = sorted({e.fix_candidate_id for e in edges if e.fix_candidate_id})
    if target:
        everything_cut = reachability.backward_reachability(
            nodes, apply_fix_set(edges, all_ids), rulesets,
            max_hops=max_hops, max_routes_per_pair=max_routes_per_pair,
        )
        uncuttable = target & everything_cut.open_pairs
    else:
        everything_cut = None
        uncuttable = set()
    cuttable = target - uncuttable

    constraints: list[Route] = []
    seen: set[tuple] = set()

    def _add(rs: "Iterable[Route]") -> int:
        n = 0
        for r in rs:
            if r.pair not in cuttable:
                continue
            k = _route_key(r)
            if k in seen:
                continue
            seen.add(k)
            constraints.append(r)
            n += 1
        return n

    _add(base.routes)
    _add(base.witness_routes)

    def _still_open(sel: "list[str]") -> "tuple[ReachabilityResult, set[tuple[str, str]]]":
        post = reachability.backward_reachability(
            nodes, apply_fix_set(edges, sel), rulesets,
            max_hops=max_hops, max_routes_per_pair=max_routes_per_pair,
        )
        return post, cuttable & post.open_pairs

    selected: list[str] = []
    proven = True
    solver = "none"
    # Once the exact solver is out of reach, re-solving the growing pool from
    # scratch with greedy can oscillate; instead grow the selection
    # monotonically (each round adds a fix on every newly found route, so it
    # terminates within the number of fix ids) and prune at the end.
    augment = False
    pending: list[Route] = []
    still_open: set[tuple[str, str]] = set(cuttable)
    iterations = 0
    verified = False
    while iterations < max_iters:
        iterations += 1
        if not augment:
            # Only the final solve's optimality matters: it is exact over a
            # relaxation (a subset of the real routes), so if it also
            # verifies it is the true optimum.
            sel, proven, solver = _solve([r.fix_elements for r in constraints], candidates)
            selected = sorted(set(sel))
            augment = not proven
        else:
            new_sets = _reduce_routes([r.fix_elements for r in pending if r.fix_elements])
            costs = _checked_costs({c for r in new_sets for c in r}, candidates)
            selected = sorted(set(selected) | set(_greedy(new_sets, costs)))
            solver = "greedy"
        post, still_open = _still_open(selected)
        if not still_open:
            verified = True
            break
        before = len(constraints)
        _add(r for r in post.routes if r.pair in still_open)
        _add(r for r in post.witness_routes if r.pair in still_open)
        pending = constraints[before:]
        if not pending:
            # Defensive: an open pair whose routes are all known yet uncut
            # cannot happen (each listed route avoids the selection). Stop
            # rather than loop.
            break

    if verified and augment:
        # Reverse-delete: drop any selected fix the constraint pool does not
        # need (most expensive first), then keep the result only if it still
        # verifies against the model.
        pool = [r.fix_elements for r in constraints]
        costs = _checked_costs(selected, candidates)
        keep = set(selected)
        for c in sorted(selected, key=lambda c: (-costs[c], c)):
            trial = keep - {c}
            if all(r & trial for r in pool):
                keep = trial
        if keep != set(selected):
            _, left = _still_open(sorted(keep))
            if not left:
                selected = sorted(keep)

    # Example routes of uncuttable pairs, so ``uncut_routes`` shows why.
    report_routes = list(constraints)
    if uncuttable and everything_cut is not None:
        extra = [r for r in everything_cut.routes if r.pair in uncuttable]
        extra += [r for r in everything_cut.witness_routes if r.pair in uncuttable]
        report_routes += extra

    chosen = set(selected)
    uncut_routes = [i for i, r in enumerate(report_routes) if not (r.fix_elements & chosen)]
    uncut_pairs = set(uncuttable) | set(still_open if not verified else ())
    total = round(sum(_cost_of(c, candidates) for c in selected), 10)
    cuts_all = verified and not uncut_pairs
    return VerifiedFixSet(
        selected=selected,
        total_cost=total,
        cuts_all=cuts_all,
        uncut_routes=uncut_routes,
        optimality="exact" if (verified and proven) else "greedy",
        verified=verified,
        target_pairs=target,
        uncut_pairs=uncut_pairs,
        uncuttable_pairs=uncuttable,
        iterations=iterations,
        routes=report_routes,
        solver=solver,
    )
