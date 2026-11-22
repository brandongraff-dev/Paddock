from __future__ import annotations

from dataclasses import dataclass, field

from app.engine.wargame.model import EvidenceLabel as L
from app.engine.wargame.model import Hop, ReachabilityResult, Route
from app.engine.wargame.report import build_scorecard, closure_score, render_lines
from app.engine.wargame.safety import contains_unsafe_token


def _route(entry, jewel, *label_sets):
    hops = []
    prev = entry
    for i, labels in enumerate(label_sets):
        dst = jewel if i == len(label_sets) - 1 else f"{entry}-{jewel}-{i}"
        hops.append(Hop(prev, dst, frozenset(labels)))
        prev = dst
    return Route(entry, jewel, hops)


def _result():
    r1 = _route("inet", "ehr", {L.PROVED_CONFIG})
    r2 = _route("guest", "pci", {L.PROVED_CONFIG}, {L.INFERRED})
    return ReachabilityResult(
        routes=[r1, r2],
        open_pairs={("inet", "ehr"), ("guest", "pci")},
        closed_pairs={("vpn", "ehr"), ("vpn", "pci"), ("iot", "ehr")},
        conditional_pairs={("vpn", "pci")},
    )


def test_closure_pct_three_of_four():
    res = ReachabilityResult(
        routes=[],
        open_pairs={("a", "j")},
        closed_pairs={("b", "j"), ("c", "j"), ("d", "j")},
    )
    c = closure_score(res)
    assert (c.total_pairs, c.open_pairs, c.closed_pairs) == (4, 1, 3)
    assert c.closure_pct == 75.0


def test_pair_in_both_sets_counts_open_only():
    res = ReachabilityResult(
        routes=[], open_pairs={("a", "j")}, closed_pairs={("a", "j"), ("b", "j")}
    )
    c = closure_score(res)
    assert (c.total_pairs, c.open_pairs, c.closed_pairs) == (2, 1, 1)


def test_histogram_reflects_route_evidence():
    c = closure_score(_result())
    assert c.by_weakest_label == {"inferred": 1, "proved_config": 1}


def test_histogram_uses_best_route_per_pair():
    weak = _route("a", "j", {L.INFERRED})
    strong = _route("a", "j", {L.OBSERVED})
    res = ReachabilityResult(
        routes=[weak, strong], open_pairs={("a", "j")}, closed_pairs=set()
    )
    assert closure_score(res).by_weakest_label == {"observed": 1}


def test_open_pair_without_routes_is_unknown():
    res = ReachabilityResult(routes=[], open_pairs={("a", "j")}, closed_pairs=set())
    assert closure_score(res).by_weakest_label == {"unknown": 1}


def test_conditional_counted_separately():
    c = closure_score(_result())
    assert c.conditional_pairs == 1
    assert c.total_pairs == 5
    assert c.closed_pairs == 3


def test_board_line_with_coverage():
    sc = build_scorecard(_result(), coverage_pct=82.5)
    assert "60% of routes to crown jewels are proved closed" in sc.board_line
    assert "explaining 82.5% of observed traffic" in sc.board_line
    assert "2 routes remain open" in sc.board_line
    assert not contains_unsafe_token(sc.board_line)


def test_board_line_without_coverage_says_not_measured():
    sc = build_scorecard(_result())
    assert "not yet measured" in sc.board_line
    assert "unknown" in sc.coverage.note
    assert sc.coverage.coverage_pct is None
    assert not contains_unsafe_token(sc.board_line)


@dataclass
class FakeReport:
    boundary_src: str
    boundary_dst: str
    verdict: str
    port: int = 443
    agree: bool = True
    disagreements: list[str] = field(default_factory=list)
    note: str = ""


def test_boundary_verdicts_duck_typed_and_sorted():
    reps = [
        FakeReport("z", "y", "fail_open", agree=False, disagreements=["probe crossed", "flow seen"]),
        FakeReport("a", "b", "pass", note="all agree"),
    ]
    sc = build_scorecard(_result(), agreement_reports=reps)
    assert [(v.boundary_src, v.boundary_dst) for v in sc.boundary_verdicts] == [
        ("a", "b"),
        ("z", "y"),
    ]
    assert sc.boundary_verdicts[0].detail == "all agree"
    assert sc.boundary_verdicts[1].detail == "probe crossed; flow seen"
    assert sc.boundary_verdicts[1].verdict == "fail_open"


def test_coverage_blind_spots_and_zero_sensors():
    sc = build_scorecard(
        _result(), coverage_pct=50, blind_spots=["serial links", "cellular modems"],
        sensors_on_protected_side=0,
    )
    assert sc.coverage.blind_spots == ["cellular modems", "serial links"]
    assert "absence of evidence" in sc.coverage.note


def test_empty_result():
    res = ReachabilityResult(routes=[], open_pairs=set(), closed_pairs=set())
    c = closure_score(res)
    assert c.closure_pct == 0.0 and c.total_pairs == 0
    sc = build_scorecard(res)
    assert "not yet measured" in sc.board_line
    assert render_lines(sc)


def test_deterministic_and_render():
    a = build_scorecard(_result(), coverage_pct=70.0, blind_spots=["b", "a"])
    b = build_scorecard(_result(), coverage_pct=70.0, blind_spots=["a", "b"])
    assert a == b
    lines = render_lines(a)
    assert lines == render_lines(b)
    assert lines[0] == a.board_line
    assert any("coverage: 70%" in ln for ln in lines)
