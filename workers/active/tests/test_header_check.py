from __future__ import annotations

import pytest

from app.modules.header_check import analyze_headers


def _by_rule(findings, rule_id):
    return [f for f in findings if f["rule_id"] == rule_id]


def test_flags_missing_hsts_on_https():
    findings = analyze_headers(
        final_url="https://example.com/",
        headers={},
        status_code=200,
    )
    assert _by_rule(findings, "missing-strict-transport-security")


def test_no_hsts_finding_on_http():
    findings = analyze_headers(
        final_url="http://example.com/",
        headers={},
        status_code=200,
    )
    assert not _by_rule(findings, "missing-strict-transport-security")


def test_weak_csp_flagged():
    findings = analyze_headers(
        final_url="https://example.com/",
        headers={"Content-Security-Policy": "default-src 'self' 'unsafe-inline'"},
        status_code=200,
    )
    assert _by_rule(findings, "weak-content-security-policy")


def test_cookie_missing_flags():
    findings = analyze_headers(
        final_url="https://example.com/",
        headers={"Set-Cookie": "sid=abc"},
        status_code=200,
    )
    rules = {f["rule_id"] for f in findings}
    assert "cookie-missing-secure" in rules
    assert "cookie-missing-httponly" in rules
    assert "cookie-missing-samesite" in rules


def test_frame_ancestors_substitutes_for_xfo():
    findings = analyze_headers(
        final_url="https://example.com/",
        headers={"Content-Security-Policy": "frame-ancestors 'none'; default-src 'self'"},
        status_code=200,
    )
    assert not _by_rule(findings, "missing-frame-protection")
