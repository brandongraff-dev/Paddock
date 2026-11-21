"""The exploit-cost / weight model (pure; mirrors attackpath.py)."""
from __future__ import annotations

from app import queries


def test_severity_bonus_precedence() -> None:
    # KEV dominates everything.
    assert queries.severity_bonus(["high", "critical"], kev=True) == queries.BONUS_KEV
    # critical beats high.
    assert queries.severity_bonus(["high", "critical"], kev=False) == queries.BONUS_CRITICAL
    assert queries.severity_bonus(["high", "low"], kev=False) == queries.BONUS_HIGH
    assert queries.severity_bonus(["low", "medium"], kev=False) == 0
    assert queries.severity_bonus([], kev=False) == 0


def test_severity_bonus_capped() -> None:
    assert queries.severity_bonus(["critical"], kev=True) <= queries.BONUS_CAP


def test_node_entry_cost_matches_attackpath_model() -> None:
    # base 10 - bonus, floored at 1.
    assert queries.node_entry_cost([], False) == 10
    assert queries.node_entry_cost(["high"], False) == 10 - queries.BONUS_HIGH   # 6
    assert queries.node_entry_cost(["critical"], False) == 10 - queries.BONUS_CRITICAL  # 4
    assert queries.node_entry_cost([], True) == 10 - queries.BONUS_KEV           # 2
    # floor at 1 is respected even with the cap.
    assert queries.node_entry_cost(["critical"], True) >= queries.FLOOR_COST


def test_source_is_free() -> None:
    assert queries.node_entry_cost(["critical"], True, is_source=True) == 0
    assert queries.node_entry_cost([], False, is_source=True) == 0


def test_max_severity() -> None:
    assert queries.max_severity(["low", "high", "medium"]) == "high"
    assert queries.max_severity(["critical", "info"]) == "critical"
    assert queries.max_severity([]) is None
    assert queries.max_severity(["unknown"]) is None
