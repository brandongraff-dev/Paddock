from __future__ import annotations

import json

import pytest

from app.normalize.nuclei_output import normalize_hits


def test_normalize_single_hit():
    line = json.dumps({
        "template-id": "http-missing-security-headers",
        "info": {
            "name": "Missing security headers",
            "severity": "info",
            "description": "No HSTS/CSP",
            "reference": ["https://owasp.org/..."],
            "classification": {"cve-id": [], "cvss-score": 0.0},
            "tags": ["misconfig", "generic"],
        },
        "host": "https://example.com/",
        "matched-at": "https://example.com/",
        "type": "http",
    })
    hits = normalize_hits([line])
    assert len(hits) == 1
    h = hits[0]
    assert h["rule_id"] == "http-missing-security-headers"
    assert h["severity"] == "info"
    assert h["target_host"] == "example.com"
    assert h["references"] == ["https://owasp.org/..."]


def test_drops_out_of_scope_hosts():
    line_in = json.dumps({"template-id": "a", "info": {"severity": "low", "name": "a"},
                           "matched-at": "https://in.example.com/"})
    line_out = json.dumps({"template-id": "b", "info": {"severity": "low", "name": "b"},
                            "matched-at": "https://offscope.example.net/"})
    hits = normalize_hits([line_in, line_out], in_scope_hosts={"in.example.com"})
    assert [h["rule_id"] for h in hits] == ["a"]


def test_malformed_lines_tolerated():
    hits = normalize_hits(["not json", "", "  "])
    assert hits == []


def test_severity_defaults_to_info():
    line = json.dumps({"template-id": "x", "info": {"severity": "weird", "name": "x"},
                       "matched-at": "https://example.com/"})
    assert normalize_hits([line])[0]["severity"] == "info"
