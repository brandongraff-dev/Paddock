"""Pure python tests for predicate matching helpers — no DB required."""
from __future__ import annotations

from app.engine.policy import (
    FindingPredicate,
    asset_matches,
    finding_matches,
)


def test_finding_matches_rule_id_regex():
    pred = FindingPredicate(rule_id_match=r"^cve-2024-.*")
    assert finding_matches(pred, {"rule_id": "cve-2024-9876"})
    assert not finding_matches(pred, {"rule_id": "cve-2020-1"})


def test_finding_matches_severity_min():
    pred = FindingPredicate(severity_min="high")
    assert finding_matches(pred, {"severity": "critical"})
    assert finding_matches(pred, {"severity": "high"})
    assert not finding_matches(pred, {"severity": "medium"})


def test_finding_matches_cvss_min():
    pred = FindingPredicate(cvss_min=7.0)
    assert finding_matches(pred, {"cvss": 7.0})
    assert finding_matches(pred, {"cvss": 9.3})
    assert not finding_matches(pred, {"cvss": 6.9})
    assert not finding_matches(pred, {"cvss": None})


def test_finding_matches_kev_flag():
    pred = FindingPredicate(known_exploited=True)
    assert finding_matches(pred, {"metadata": {"kev": True}})
    assert finding_matches(pred, {"metadata": {"known_exploited": True}})
    assert not finding_matches(pred, {"metadata": {"kev": False}})


def test_asset_matches_kind_and_metadata():
    assert asset_matches(
        {"kind": "endpoint", "metadata": {"env": "prod"}},
        {"kind": "endpoint", "value": "a", "metadata": {"env": "prod"}},
    )
    assert not asset_matches(
        {"kind": "endpoint", "metadata": {"env": "prod"}},
        {"kind": "endpoint", "metadata": {"env": "dev"}},
    )


def test_asset_matches_value_regex():
    assert asset_matches(
        {"value_match": r"\.example\.com$"},
        {"value": "api.example.com", "kind": "subdomain"},
    )
    assert not asset_matches(
        {"value_match": r"\.example\.com$"},
        {"value": "api.other.net"},
    )
