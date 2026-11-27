# SPDX-License-Identifier: AGPL-3.0-or-later
"""Output writers: text, json, sarif, markdown (contract 3.4, 9.9, H5, H6)."""
from __future__ import annotations

import gzip
import json
import re
import unicodedata

import pytest

from paddock_cli.guard import GUARD_VERSION, model, output, registry

FORBIDDEN = {"Cc", "Cf", "Cs", "Co", "Cn"}


def _f(i=0, **kw):
    base = dict(
        fingerprint="%016x" % (i + 1), check_id="PG-TST-001", title="Forbidden word", severity="high",
        confidence="high", blocking=True, file="src/a.py", line=3, end_line=3, evidence="AKIA****[20]",
        message="Forbidden word", fix_hint="Remove it.", agent_prompt="Paddock Guard PG-TST-001: x",
        fixer=None, cwe="CWE-1", tier_evidence="unmeasured", status="open", data={"name": "x"})
    base.update(kw)
    return model.GuardFinding(**base)


def _report(findings=(), **kw):
    r = model.Report(mode={"tier": "high", "scope": "full", "base": None, "offline": False, "fail_on": "high"})
    r.findings = list(findings)
    r.checks_run = ["PG-TST-001"]
    r.checks_off_at_tier = ["PG-TST-002"]
    r.notes = ["PG-META-002: 1 checks ran at tier high; 1 checks are off at this tier (PG-TST-002); no findings is not a safety result"]
    for k, v in kw.items():
        setattr(r, k, v)
    return r


def _hostile():
    bad = "\u202eEVIL\x1b[31m\u200b\x07 <script>alert(1)</script> | `x` --> [a](http://evil.example/x) \n![i](http://evil.example/i.png) " + "Z" * 10000
    return _f(
        title=bad, message=bad, file="we\u202eird|na`me\n.py", evidence=bad, fix_hint=bad, agent_prompt=bad,
        cwe=bad, check_id="PG-TST-001", data={"name": "x"})


def _no_forbidden(text: str, allow_newline=True) -> list[str]:
    return [hex(ord(c)) for c in text if unicodedata.category(c) in FORBIDDEN and not (allow_newline and c == "\n")]


# ---- text -------------------------------------------------------------------------------------------
def test_text_headline_and_meta_line_and_no_all_clear_wording():
    out = output.render_text(_report())
    first = out.splitlines()[0]
    assert "0 blocking" in first and "0 open" in first
    assert "checks ran at tier high" in out and "no findings is not a safety result" in out
    low = out.lower()
    for word in ("all clear", "passed", "no issues", "all good"):
        assert word not in low
    assert not re.search(r"\bclean\b", low)


def test_text_lists_findings_with_location_confidence_and_label():
    out = output.render_text(_report([_f()]))
    assert "src/a.py:3" in out and "PG-TST-001" in out and "Forbidden word" in out
    assert "high" in out and "unmeasured" in out and "AKIA****[20]" in out
    assert "1 blocking" in out.splitlines()[0]


def test_text_first_line_carries_config_notices():
    r = _report(first_line_notices=["config: ignored 1 setting(s) that would loosen checks: guard.offline (project file)"])
    out = output.render_text(r)
    assert out.splitlines()[0].startswith("config: ignored 1 setting(s)")


def test_text_caps_the_list_unless_all():
    fs = [_f(i, file="f%d.py" % i) for i in range(80)]
    out = output.render_text(_report(fs))
    assert "30 more" in out and "--all" in out
    out_all = output.render_text(_report(fs), show_all=True)
    assert "more" not in out_all.split("notes")[0] or "--all" not in out_all
    assert out_all.count("PG-TST-001") >= 80


def test_text_shows_suppressed_and_baselined_counts_not_lines():
    fs = [_f(0), _f(1, status="suppressed", blocking=False), _f(2, status="baselined", blocking=False)]
    out = output.render_text(_report(fs))
    assert "1 suppressed" in out and "1 baselined" in out
    assert out.count("src/a.py:3") == 1


def test_text_incomplete_is_prominent_and_notes_are_listed():
    r = _report(complete=False, notes=["PG-META-002: x", "file limit reached"], errors=[{"check": "PG-TST-006", "file": "slow.txt", "error": "check_timed_out"}],
                skipped=[{"file": "l.txt", "reason": "symlink"}])
    out = output.render_text(r)
    assert "INCOMPLETE" in out and "check_timed_out" in out and "file limit reached" in out and "l.txt" in out


def test_text_labels_every_unmeasured_finding_line():
    out = output.render_text(_report([_f(), _f(1, file="b.py", tier_evidence="measured")]))
    lines = [ln for ln in out.splitlines() if "PG-TST-001" in ln and ".py:" in ln]
    by_file = {("b.py" if "b.py:" in ln else "a.py"): ln for ln in lines}
    assert len(lines) == 2 and "unmeasured" in by_file["a.py"] and "unmeasured" not in by_file["b.py"] and "measured" in by_file["b.py"]


# ---- json -------------------------------------------------------------------------------------------
def test_json_matches_the_documented_schema_keys():
    doc = json.loads(output.render_json(_report([_f()])))
    assert list(doc) == ["schema", "tool", "root", "mode", "summary", "findings", "notes", "skipped", "errors",
                         "checks_run", "checks_off_at_tier", "suppressions_added", "baseline_growth", "config_changes", "origin"]
    assert doc["schema"] == "paddock-guard/report/v1" and doc["tool"]["version"] == GUARD_VERSION
    assert list(doc["findings"][0])[:3] == ["fingerprint", "check_id", "title"]
    assert doc["checks_run"] == ["PG-TST-001"] and doc["checks_off_at_tier"] == ["PG-TST-002"]


# ---- sarif ------------------------------------------------------------------------------------------
def test_sarif_structure():
    r = _report([_f(), _f(1, severity="medium", confidence="medium", blocking=False, file="b.py", line=None, end_line=None),
                 _f(2, severity="low", file="c.py"), _f(3, severity="critical", file="d.py"), _f(4, severity="info", file="e.py"),
                 _f(5, status="suppressed", blocking=False, file="s.py")])
    doc = json.loads(output.render_sarif(r))
    assert doc["$schema"].endswith("sarif-2.1.0.json") and doc["version"] == "2.1.0"
    (run,) = doc["runs"]
    assert run["tool"]["driver"]["name"] == "paddock-guard" and run["tool"]["driver"]["version"] == GUARD_VERSION
    rule_ids = [x["id"] for x in run["tool"]["driver"]["rules"]]
    assert rule_ids == sorted(set(rule_ids)) and "PG-TST-001" in rule_ids
    res = {x["partialFingerprints"]["paddock-guard/v1"]: x for x in run["results"]}
    assert len(res) == 5  # suppressed findings are not uploaded
    levels = {x["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]: x["level"] for x in run["results"]}
    assert levels == {"src/a.py": "error", "b.py": "warning", "c.py": "note", "d.py": "error", "e.py": "note"}
    sev = {x["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]: x["properties"]["security-severity"] for x in run["results"]}
    assert sev == {"src/a.py": "8.0", "b.py": "5.5", "c.py": "3.0", "d.py": "9.5", "e.py": "0.0"}
    first = run["results"][0]
    assert first["ruleId"] == "PG-TST-001" and first["message"]["text"]
    loc = [x for x in run["results"] if x["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/a.py"][0]
    assert loc["locations"][0]["physicalLocation"]["region"]["startLine"] == 3
    nolines = [x for x in run["results"] if x["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "b.py"][0]
    assert "region" not in nolines["locations"][0]["physicalLocation"] or "startLine" not in nolines["locations"][0]["physicalLocation"]["region"]
    for x in run["results"]:
        uri = x["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert not uri.startswith("/") and ".." not in uri and "://" not in uri


def test_sarif_rule_metadata_comes_from_the_registry_when_registered(registry_sandbox):
    registry.register(registry.Check(id="PG-TST-001", title="Forbidden word", severity="high", proposed_tier="high",
                                     scope="file", why="Because it is bad.", fix_hint="Remove it.", cwe="CWE-798",
                                     agent_prompt="x", run=lambda c, f: []))
    doc = json.loads(output.render_sarif(_report([_f()])))
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["shortDescription"]["text"] == "Forbidden word" and "anecdotal, unmeasured" in rule["fullDescription"]["text"]
    assert rule["properties"]["security-severity"] == "8.0" and "CWE-798" in " ".join(rule["properties"].get("tags", []))


def test_sarif_caps_results_at_5000_highest_severity_first_and_notes_the_cut():
    fs = [_f(i, severity="low", file="f%05d.py" % i) for i in range(5200)] + [_f(9000 + i, severity="critical", file="c%d.py" % i) for i in range(10)]
    doc = json.loads(output.render_sarif(_report(fs)))
    res = doc["runs"][0]["results"]
    assert len(res) == 5000
    assert sum(1 for x in res if x["level"] == "error") == 10
    assert any("5000" in n or "5,000" in n for n in doc["runs"][0]["properties"]["notes"])
    assert doc["runs"][0]["properties"]["truncated"] == 210


def test_sarif_gzip_size_is_bounded_by_dropping_the_lowest_severity(monkeypatch):
    monkeypatch.setattr(output, "SARIF_MAX_GZIP_BYTES", 20_000)
    import random

    rng = random.Random(1)
    fs = [_f(i, severity="low", file="f%d.py" % i, title="".join(rng.choice("abcdefghij klmnop") for _ in range(120)))
          for i in range(3000)] + [_f(9999, severity="critical", file="keep.py")]
    text = output.render_sarif(_report(fs))
    assert len(gzip.compress(text.encode())) <= 20_000
    doc = json.loads(text)
    assert any(x["level"] == "error" for x in doc["runs"][0]["results"])
    assert doc["runs"][0]["properties"]["truncated"] > 0


# ---- markdown ---------------------------------------------------------------------------------------
def test_markdown_table_row_count_equals_open_finding_count():
    fs = [_f(i, file="f%d.py" % i) for i in range(7)] + [_f(20, status="suppressed", blocking=False)]
    md = output.render_markdown(_report(fs))
    rows = [ln for ln in md.splitlines() if ln.startswith("| ") and not ln.startswith("| Severity") and not ln.startswith("| ---")]
    assert len(rows) == 7
    assert "checks ran at tier high" in md and "no findings is not a safety result" in md


def test_markdown_lists_new_suppressions_baseline_growth_and_disabled_checks():
    r = _report([_f()], suppressions_added=[{"kind": "inline", "file": "a.py", "check_id": "PG-TST-001", "line": 2, "reason": "because", "fingerprint": "0123456789abcdef"}],
                baseline_growth=2)
    r.config_changes["disabled_checks"] = ["PG-WEB-005"]
    md = output.render_markdown(r)
    assert "Suppressions added" in md and "a.py" in md and "Baseline entries added" in md and "PG-WEB-005" in md


def test_markdown_neutralises_injection_golden():
    md = output.render_markdown(_report([_hostile()]))
    stripped = re.sub(r"`[^`\n]*`", "``", md)
    assert "://" not in stripped and "<" not in stripped and ">" not in stripped and "-->" not in md
    assert "](" not in stripped and "![" not in stripped
    rows = [ln for ln in md.splitlines() if ln.startswith("| ") and not ln.startswith("| Severity") and not ln.startswith("| ---")]
    assert len(rows) == 1 and "\n" not in rows[0]
    assert rows[0].count("|") - rows[0].count("\\|") == md.splitlines()[[i for i, l in enumerate(md.splitlines()) if l.startswith("| Severity")][0]].count("|")
    assert not _no_forbidden(md)


def test_markdown_has_no_url_and_no_promotion():
    md = output.render_markdown(_report([_f()]))
    assert "http" not in md.lower() and "star" not in re.findall(r"\b\w+\b", md.lower())


# ---- hostile finding is clean in all four ---------------------------------------------------------------
@pytest.mark.parametrize("fmt", ["text", "json", "sarif", "markdown"])
def test_hostile_finding_is_clean_in_every_format(fmt):
    r = _report([_hostile()], first_line_notices=["config: \u202e\x1b[31m hostile notice"],
                notes=["PG-META-002: x \u202e\x1b[31m"], skipped=[{"file": "a\u202eb", "reason": "x\x1b[0m"}],
                errors=[{"check": "PG-X-001", "file": "q\u200bz", "error": "E\x07"}])
    text = output.render(r, fmt)
    assert not _no_forbidden(text)
    assert "\x1b" not in text and "\u202e" not in text and "\u200b" not in text
    if fmt in ("json", "sarif"):
        doc = json.loads(text)
        blob = json.dumps(doc, ensure_ascii=False)
        assert not _no_forbidden(blob, allow_newline=False) and "\u202e" not in blob
    longest = max((len(ln) for ln in text.splitlines()), default=0)
    assert longest < 3000
    assert "Z" * 1201 not in text


def test_render_dispatch_and_unknown_format():
    assert output.render(_report(), "json").startswith("{")
    with pytest.raises(ValueError):
        output.render(_report(), "xml")


def test_exit_code_helper_follows_d12():
    assert output.exit_code(_report([_f()])) == 1
    assert output.exit_code(_report([_f(blocking=False, confidence="medium")])) == 0
    assert output.exit_code(_report([])) == 0
