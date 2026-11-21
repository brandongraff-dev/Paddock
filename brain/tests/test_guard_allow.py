"""Guard accept + LIMIT-enforcement tests."""
from __future__ import annotations

import pytest

from app.guard import ALLOWED_VIEWS, apply_limit, validate


@pytest.mark.parametrize("view", sorted(ALLOWED_VIEWS))
def test_allows_simple_select_over_each_view(view):
    ok, reason = validate(f"SELECT * FROM {view}")
    assert ok is True, reason


def test_allows_where_order_group_limit():
    ok, reason = validate(
        "SELECT severity, COUNT(*) AS c FROM ask_findings "
        "WHERE status = 'open' GROUP BY severity ORDER BY c DESC LIMIT 50"
    )
    assert ok is True, reason


def test_allows_join_among_ask_views():
    ok, reason = validate(
        "SELECT a.value, f.severity FROM ask_findings f "
        "JOIN ask_assets a ON a.id = f.asset_id "
        "WHERE f.severity = 'critical'"
    )
    assert ok is True, reason


def test_allows_subquery_on_ask_view():
    ok, reason = validate(
        "SELECT value FROM ask_assets WHERE id IN "
        "(SELECT asset_id FROM ask_findings WHERE severity = 'high')"
    )
    assert ok is True, reason


def test_allows_readonly_cte():
    ok, reason = validate(
        "WITH sev AS (SELECT severity FROM ask_findings WHERE status = 'open') "
        "SELECT severity, COUNT(*) AS c FROM sev GROUP BY severity"
    )
    assert ok is True, reason


def test_allows_trailing_semicolon():
    ok, reason = validate("SELECT * FROM ask_assets;")
    assert ok is True, reason


def test_limit_appended_when_absent():
    out = apply_limit("SELECT * FROM ask_findings", 500)
    assert "LIMIT 500" in out.upper()


def test_limit_capped_when_too_large():
    out = apply_limit("SELECT * FROM ask_findings LIMIT 100000", 500)
    assert "LIMIT 500" in out.upper()
    assert "100000" not in out


def test_limit_preserved_when_within_cap():
    out = apply_limit("SELECT * FROM ask_findings LIMIT 10", 500)
    assert "LIMIT 10" in out.upper()
