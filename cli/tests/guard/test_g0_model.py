# SPDX-License-Identifier: AGPL-3.0-or-later
"""Data model (contract 3.4, D8, D10)."""
from __future__ import annotations

import json
import re

import pytest

from paddock_cli.guard import GUARD_VERSION, model

FINDING_KEYS = [
    "fingerprint", "check_id", "title", "severity", "confidence", "blocking", "file", "line",
    "end_line", "evidence", "message", "fix_hint", "agent_prompt", "fixer", "cwe",
    "tier_evidence", "status", "data",
]
REPORT_KEYS = [
    "schema", "tool", "root", "mode", "summary", "findings", "notes", "skipped", "errors",
    "checks_run", "checks_off_at_tier", "suppressions_added", "baseline_growth",
    "config_changes", "origin",
]


def _finding(**kw):
    base = dict(
        fingerprint="a" * 16, check_id="PG-TST-001", title="Title", severity="high",
        confidence="high", blocking=True, file="a.py", line=3, end_line=3, evidence="ev",
        message="Title", fix_hint="fix", agent_prompt="p", fixer=None, cwe=None,
        tier_evidence="unmeasured", status="open", data={},
    )
    base.update(kw)
    return model.GuardFinding(**base)


def test_version_constant_and_require_tiers_agree():
    assert GUARD_VERSION == "0.1.0"
    assert model.REQUIRE_TIERS == (".dev" not in GUARD_VERSION)


def test_fingerprint_is_16_hex_and_depends_only_on_check_file_anchor():
    fp = model.fingerprint("PG-SEC-001", "src/a.js", "aws:1")
    assert re.fullmatch(r"[0-9a-f]{16}", fp)
    assert fp == model.fingerprint("PG-SEC-001", "src/a.js", "aws:1")
    assert fp != model.fingerprint("PG-SEC-001", "src/b.js", "aws:1")
    assert fp != model.fingerprint("PG-SEC-001", "src/a.js", "aws:2")
    assert fp != model.fingerprint("PG-SEC-002", "src/a.js", "aws:1")


def test_fingerprint_matches_documented_formula():
    import hashlib

    want = hashlib.sha256(b"PG-X-001|f.txt|anchor").hexdigest()[:16]
    assert model.fingerprint("PG-X-001", "f.txt", "anchor") == want


def test_severity_and_tier_order():
    assert model.SEVERITIES == ("info", "low", "medium", "high", "critical")
    assert model.severity_rank("critical") > model.severity_rank("high") > model.severity_rank("low")
    assert model.tier_rank("high") > model.tier_rank("medium") > model.tier_rank("low")
    with pytest.raises(ValueError):
        model.severity_rank("urgent")
    with pytest.raises(ValueError):
        model.tier_rank("huge")


@pytest.mark.parametrize("bad", ["", "/abs", "../x", "a/../b", "a\\b", "a\x00b", "a//b/.."])
def test_norm_relpath_rejects_traversal(bad):
    assert model.norm_relpath(bad) is None


def test_norm_relpath_normalises():
    assert model.norm_relpath("./a/b.py") == "a/b.py"
    assert model.norm_relpath("a/./b") == "a/b"
    assert model.norm_relpath("a//b") == "a/b"


def test_hit_defaults_and_frozen():
    h = model.Hit(file="a.py", anchor="x")
    assert h.line is None and h.end_line is None and h.evidence == "" and h.data == {}
    assert h.related == ()
    with pytest.raises(Exception):
        h.file = "b"  # type: ignore[misc]


def test_finding_to_dict_has_exactly_the_public_keys_in_order():
    d = _finding().to_dict()
    assert list(d) == FINDING_KEYS
    json.dumps(d)


def test_report_to_dict_has_exactly_the_documented_keys():
    r = model.Report(mode={"tier": "high", "scope": "full", "base": None, "offline": False, "fail_on": "high"})
    r.findings.append(_finding())
    d = r.to_dict()
    assert list(d) == REPORT_KEYS
    assert d["schema"] == "paddock-guard/report/v1"
    assert d["tool"] == {"name": "paddock-guard", "version": GUARD_VERSION}
    assert d["root"] == "."
    assert set(d["summary"]) == {"blocking", "open", "suppressed", "baselined", "complete", "by_severity", "by_check"}
    assert set(d["config_changes"]) == {"disabled_checks", "excluded", "severity_overrides", "packages", "ignored_loosening"}
    assert d["summary"]["blocking"] == 1 and d["summary"]["open"] == 1
    json.dumps(d)


def test_report_summary_counts_by_status():
    r = model.Report()
    r.findings += [
        _finding(fingerprint="1" * 16),
        _finding(fingerprint="2" * 16, status="suppressed", blocking=False),
        _finding(fingerprint="3" * 16, status="baselined", blocking=False, severity="low"),
        _finding(fingerprint="4" * 16, severity="medium", confidence="medium", blocking=False, check_id="PG-TST-002"),
    ]
    s = r.summary()
    assert (s["blocking"], s["open"], s["suppressed"], s["baselined"]) == (1, 2, 1, 1)
    assert s["by_severity"] == {"high": 1, "medium": 1}
    assert s["by_check"] == {"PG-TST-001": 1, "PG-TST-002": 1}


def test_report_complete_false_when_incomplete_flag_set():
    r = model.Report()
    assert r.to_dict()["summary"]["complete"] is True
    r.complete = False
    assert r.to_dict()["summary"]["complete"] is False
