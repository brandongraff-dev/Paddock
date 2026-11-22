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
  the routes) we run an exact branch-and-bound and label the result
  ``optimality="exact"``. Only then is the fix set truly minimal.
* For larger instances we fall back to the classic cost-effective greedy
  (repeatedly take the candidate maximising newly-covered-routes per unit
  cost) and label it ``optimality="greedy"``. We never call a greedy result
  "minimal".

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

from .model import (
    DEFAULT_COST_CLASSES,
    FixCandidate,
    FixSet,
    ReachabilityResult,
)

#: Cost used for a candidate id we cannot price (unknown cost class, or a
#: candidate id that appears on a route but has no :class:`FixCandidate`).
#: Documented default so pricing never silently reads as free.
DEFAULT_UNKNOWN_COST: float = 5.0

#: Exact branch-and-bound is used when the number of distinct candidate ids
#: appearing across the routes is at most this; otherwise we fall back to
#: greedy. Hitting set is NP-hard, so the exact solver is only safe to run on
#: small instances.
_EXACT_MAX_ELEMENTS: int = 24


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


def _reduce_routes(
    route_sets: "list[frozenset[str]]",
) -> "list[frozenset[str]]":
    """Drop duplicate and superset routes.

    If one route's element-set is a subset of another's, any fix hitting the
    smaller set also hits the larger (the hitting element is in both), so the
    larger (superset) route is redundant for covering purposes. Deduplicating
    and keeping only subset-minimal routes shrinks the search without changing
    the optimum. Deterministic: input order is irrelevant to the output set.
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


def _lower_bound(
    remaining: "list[frozenset[str]]",
    candidates: "dict[str, FixCandidate]",
) -> float:
    """Admissible lower bound on the cost to hit all ``remaining`` routes.

    Greedily collects pairwise-disjoint routes; disjoint routes need distinct
    hitting elements, so the cost is at least the sum over them of each route's
    cheapest element. This never over-estimates, so it is safe for pruning.
    """
    used: set[str] = set()
    lb = 0.0
    # Favour routes whose cheapest element is expensive and that are small,
    # for a tighter (but still admissible) bound. Deterministic ordering.
    def _route_key(r: frozenset[str]) -> tuple:
        cheapest = min(_cost_of(c, candidates) for c in r)
        return (len(r), -cheapest, tuple(sorted(r)))

    for r in sorted(remaining, key=_route_key):
        if r & used:
            continue
        lb += min(_cost_of(c, candidates) for c in r)
        used |= set(r)
    return lb


def _branch_and_bound(
    routes: "list[frozenset[str]]",
    candidates: "dict[str, FixCandidate]",
) -> "list[str]":
    """Exact minimum-cost hitting set via branch-and-bound.

    ``routes`` must be non-empty element-sets (already reduced). Returns the
    selected candidate ids. Deterministic throughout:

    * the most-constrained uncovered route (fewest options, then lexically
      smallest) is chosen to branch on;
    * its candidates are tried in ascending (cost, id) order;
    * a cost lower bound prunes branches that cannot beat the incumbent;
    * the first optimal solution found under this fixed order is kept.
    """
    if not routes:
        return []

    best: dict[str, object] = {"cost": float("inf"), "sel": None}

    def recurse(selected: "list[str]", current_cost: float, remaining: "list[frozenset[str]]") -> None:
        if current_cost >= best["cost"]:  # type: ignore[operator]
            return
        if not remaining:
            best["cost"] = current_cost
            best["sel"] = list(selected)
            return
        if current_cost + _lower_bound(remaining, candidates) >= best["cost"]:  # type: ignore[operator]
            return
        # Branch on the most-constrained uncovered route.
        route = min(remaining, key=lambda r: (len(r), tuple(sorted(r))))
        for cand in sorted(route, key=lambda c: (_cost_of(c, candidates), c)):
            new_cost = current_cost + _cost_of(cand, candidates)
            if new_cost >= best["cost"]:  # type: ignore[operator]
                continue
            new_remaining = [r for r in remaining if cand not in r]
            selected.append(cand)
            recurse(selected, new_cost, new_remaining)
            selected.pop()

    recurse([], 0.0, routes)
    sel = best["sel"] or []
    return list(sel)  # type: ignore[arg-type]


def _greedy(
    routes: "list[frozenset[str]]",
    candidates: "dict[str, FixCandidate]",
) -> "list[str]":
    """Classic cost-effective greedy weighted set cover.

    Repeatedly selects the candidate maximising (newly-covered routes / cost).
    Deterministic tie-break: higher ratio, then lower cost, then lower id.
    """
    uncovered = [set(r) for r in routes if r]
    selected: list[str] = []
    while uncovered:
        universe = sorted({c for r in uncovered for c in r})
        best_id: str | None = None
        best_key: tuple | None = None
        for cand in universe:
            newly = sum(1 for r in uncovered if cand in r)
            if newly == 0:
                continue
            c = _cost_of(cand, candidates)
            ratio = newly / c if c > 0 else float("inf")
            # Maximise ratio; tie-break prefers lower cost then lower id.
            key = (ratio, -c, _neg_id(cand))
            if best_key is None or key > best_key:
                best_key = key
                best_id = cand
        if best_id is None:  # nothing left can cover anything
            break
        selected.append(best_id)
        uncovered = [r for r in uncovered if best_id not in r]
    return selected


def _neg_id(cand: str) -> tuple:
    """Sort helper so that, as part of a max-key, a *lower* id wins a tie.

    Returns a value that is larger for lexically smaller ids.
    """
    return tuple(-ord(ch) for ch in cand)


def min_cost_fix_set(
    routes: "list[frozenset[str]]",
    candidates: "dict[str, FixCandidate]",
) -> FixSet:
    """Cheapest set of candidates that breaks every open route.

    ``routes[i]`` is the set of cuttable candidate ids on open route ``i``
    (:attr:`Route.fix_elements`). The returned :class:`FixSet`:

    * ``selected`` — chosen candidate ids, sorted;
    * ``total_cost`` — sum of their costs;
    * ``cuts_all`` — ``True`` iff every input route is intersected (i.e. no
      route was empty / uncuttable);
    * ``uncut_routes`` — sorted input indices of routes with no cuttable
      element (an inferred hop with no modelled control); these cannot be cut;
    * ``optimality`` — ``"exact"`` for the branch-and-bound solver on small
      instances, ``"greedy"`` otherwise. Only ``"exact"`` results are minimal.
    """
    # Empty routes cannot be cut — record their input index.
    uncut: list[int] = [i for i, r in enumerate(routes) if not r]
    non_empty = [r for r in routes if r]

    distinct_ids = {c for r in non_empty for c in r}

    if not non_empty:
        return FixSet(
            selected=[],
            total_cost=0.0,
            cuts_all=(len(uncut) == 0),
            uncut_routes=sorted(uncut),
            optimality="exact",
        )

    reduced = _reduce_routes(non_empty)

    if len(distinct_ids) <= _EXACT_MAX_ELEMENTS:
        selected = _branch_and_bound(reduced, candidates)
        optimality = "exact"
    else:
        selected = _greedy(reduced, candidates)
        optimality = "greedy"

    selected_sorted = sorted(set(selected))
    total = round(sum(_cost_of(c, candidates) for c in selected_sorted), 10)

    return FixSet(
        selected=selected_sorted,
        total_cost=total,
        cuts_all=(len(uncut) == 0),
        uncut_routes=sorted(uncut),
        optimality=optimality,
    )


def fix_set_for(
    result: ReachabilityResult,
    candidates: "dict[str, FixCandidate]",
) -> FixSet:
    """Convenience: minimum-cost fix set over the open routes in ``result``.

    Pulls :attr:`Route.fix_elements` for every route whose (entry, jewel) pair
    is in ``result.open_pairs`` and solves. Routes for closed/conditional pairs
    are not included.
    """
    route_sets = [
        r.fix_elements for r in result.routes if r.pair in result.open_pairs
    ]
    return min_cost_fix_set(route_sets, candidates)
