"""Wargame scorecard: Crown-Jewel Closure, Model Coverage, boundary verdicts.

Implements ``docs/WARGAME.md`` section 3 ("The numbers"). Pure reporting
over the solver's :class:`~.model.ReachabilityResult`; deterministic, no I/O.

Honesty rules enforced here:

* A closure figure is **never** presented without its coverage caveat. If
  coverage was not measured the board line says so; it never implies full
  coverage.
* Absence of a protected-side sensor is absence of evidence, not proof.
* Free text (the board line) passes through :func:`.safety.safe_text`.

DECOUPLING. Per-boundary verdicts come from ``agreement.py``'s
``AgreementReport``. This module does **not** import it: it consumes any
iterable of objects *duck-typed* on these attributes::

    boundary_src: str
    boundary_dst: str
    verdict: str            # "pass" | "fail_open" | "conditional" | "insufficient"
    note: str
    disagreements: list[str]

(``port``, ``agree`` exist on the real type but are not needed here.)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from .model import LABEL_STRENGTH, ReachabilityResult, Route
from .safety import safe_text


# ---------------------------------------------------------------------------
# Closure
# ---------------------------------------------------------------------------

@dataclass
class ClosureScore:
    """Crown-Jewel Closure over (entry, jewel) pairs.

    ``total_pairs`` = ``|open ∪ closed|``. ``open_pairs`` is ``|open|``;
    ``closed_pairs`` is ``|closed - open|`` (a pair with any open route is
    never closed). ``conditional_pairs`` is a separate overlay count
    (``|conditional|``) and is not part of the total.
    """

    total_pairs: int
    open_pairs: int
    closed_pairs: int
    conditional_pairs: int
    closure_pct: float
    #: Histogram over OPEN pairs of the weakest label of that pair's
    #: strongest route (see :func:`closure_score`). Keys are label values.
    by_weakest_label: dict[str, int] = field(default_factory=dict)


def _route_sort_key(r: Route) -> tuple[Any, ...]:
    # strongest first (negated), then shorter, then lexical for determinism
    return (
        -LABEL_STRENGTH[r.weakest_label],
        r.length,
        tuple((h.src, h.dst) for h in r.hops),
    )


def closure_score(result: ReachabilityResult) -> ClosureScore:
    """Score closure.

    Histogram choice: for each open pair we take its *best* route (the one
    whose weakest hop is strongest; ties go to the shorter, then
    lexicographically first route) and count that route's weakest label.
    This answers "how well-evidenced is the best way in?". An open pair with
    no route objects is counted as ``unknown``.
    """
    open_set = set(result.open_pairs)
    closed_set = set(result.closed_pairs) - open_set
    total = len(open_set | closed_set)
    closed = len(closed_set)
    pct = (closed / total * 100.0) if total else 0.0

    hist: dict[str, int] = {}
    for pair in sorted(open_set):
        routes = result.routes_for(pair)
        if routes:
            label = min(routes, key=_route_sort_key).weakest_label.value
        else:
            label = "unknown"
        hist[label] = hist.get(label, 0) + 1

    return ClosureScore(
        total_pairs=total,
        open_pairs=len(open_set),
        closed_pairs=closed,
        conditional_pairs=len(set(result.conditional_pairs)),
        closure_pct=pct,
        by_weakest_label=dict(sorted(hist.items())),
    )


# ---------------------------------------------------------------------------
# Verdicts, coverage, scorecard
# ---------------------------------------------------------------------------

@dataclass
class BoundaryVerdict:
    boundary_src: str
    boundary_dst: str
    verdict: str
    detail: str


@dataclass
class CoverageSummary:
    """Model coverage. ``coverage_pct`` None means *unknown*, never full."""

    coverage_pct: Optional[float]
    blind_spots: list[str]
    sensors_on_protected_side: Optional[int]
    note: str


@dataclass
class Scorecard:
    closure: ClosureScore
    coverage: CoverageSummary
    boundary_verdicts: list[BoundaryVerdict]
    board_line: str


def _fmt_pct(x: float) -> str:
    s = f"{x:.1f}"
    return s[:-2] if s.endswith(".0") else s


def _coverage_summary(
    coverage_pct: Optional[float],
    blind_spots: Iterable[str],
    sensors: Optional[int],
) -> CoverageSummary:
    spots = sorted({str(b) for b in blind_spots})
    if coverage_pct is None:
        note = (
            "Coverage is unknown: it has not been measured. Closure is "
            "limited to what the model contains; do not read it as full "
            "coverage."
        )
    else:
        note = (
            f"Model explains {_fmt_pct(coverage_pct)}% of observed traffic."
        )
    if sensors is None:
        note += " Protected-side sensor count is unknown."
    elif sensors == 0:
        note += (
            " No sensor on the protected side: silence there is absence of "
            "evidence, not proof of closure."
        )
    if spots:
        note += f" Known blind spots: {len(spots)}."
    return CoverageSummary(coverage_pct, spots, sensors, note)


def build_scorecard(
    result: ReachabilityResult,
    *,
    agreement_reports: Iterable[Any] = (),
    coverage_pct: Optional[float] = None,
    blind_spots: Iterable[str] = (),
    sensors_on_protected_side: Optional[int] = None,
) -> Scorecard:
    """Assemble the scorecard. ``agreement_reports`` are duck-typed (see the
    module docstring); nothing from ``agreement.py`` is imported."""
    closure = closure_score(result)

    verdicts = [
        BoundaryVerdict(
            boundary_src=r.boundary_src,
            boundary_dst=r.boundary_dst,
            verdict=r.verdict,
            detail=(getattr(r, "note", "") or "; ".join(getattr(r, "disagreements", []) or [])),
        )
        for r in agreement_reports
    ]
    verdicts.sort(key=lambda v: (v.boundary_src, v.boundary_dst))

    coverage = _coverage_summary(coverage_pct, blind_spots, sensors_on_protected_side)

    if coverage_pct is None:
        cov_clause = "over a model whose coverage is not yet measured"
    else:
        cov_clause = (
            f"over a model explaining {_fmt_pct(coverage_pct)}% of observed traffic"
        )
    raw = (
        f"{_fmt_pct(closure.closure_pct)}% of routes to crown jewels are "
        f"proved closed, {cov_clause}; "
        f"{closure.open_pairs} routes remain open."
    )
    fallback = (
        "Closure figure withheld: wording failed the safety filter; "
        "coverage not yet measured."
    )
    board_line = safe_text(raw, fallback)

    return Scorecard(closure, coverage, verdicts, board_line)


def render_lines(scorecard: Scorecard) -> list[str]:
    """Printable board/auditor summary (impact only, no steps)."""
    c = scorecard.closure
    cov = scorecard.coverage
    lines = [
        scorecard.board_line,
        "",
        "Crown-Jewel Closure",
        f"  pairs in model: {c.total_pairs}  closed: {c.closed_pairs}  "
        f"open: {c.open_pairs}  conditional: {c.conditional_pairs}",
        f"  closure: {_fmt_pct(c.closure_pct)}%",
    ]
    for label, n in c.by_weakest_label.items():
        lines.append(f"  open, weakest label {label}: {n}")
    lines += ["", "Model coverage"]
    lines.append(
        "  coverage: "
        + ("not yet measured" if cov.coverage_pct is None else f"{_fmt_pct(cov.coverage_pct)}%")
    )
    lines.append(
        "  protected-side sensors: "
        + ("unknown" if cov.sensors_on_protected_side is None else str(cov.sensors_on_protected_side))
    )
    lines.append(f"  {cov.note}")
    for b in cov.blind_spots:
        lines.append(f"  blind spot: {b}")
    lines += ["", "Boundary verdicts"]
    if not scorecard.boundary_verdicts:
        lines.append("  none reported")
    for v in scorecard.boundary_verdicts:
        tail = f" - {v.detail}" if v.detail else ""
        lines.append(f"  {v.boundary_src} -> {v.boundary_dst}: {v.verdict}{tail}")
    return lines
