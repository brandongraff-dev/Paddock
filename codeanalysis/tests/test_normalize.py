from __future__ import annotations

from app.sast import normalize

_HIT = {
    "engine": "taint_fallback",
    "language": "python",
    "rule": "sql-injection",
    "rule_class": "sql_injection",
    "message": "Untrusted input reaches execute()",
    "severity": "high",
    "file": "app/views.py",
    "start_line": 12,
    "end_line": 12,
    "source": "request.args",
    "sink": "execute",
    "dataflow": [{"step": "source", "label": "request.args", "line": 10},
                 {"step": "sink", "label": "execute", "line": 12}],
    "cwe": "CWE-89",
}


def test_code_finding_row_shape():
    project = {"id": "pid", "name": "demo", "asset_id": "aid"}
    row = normalize.code_finding_row(_HIT, project)
    assert row["project_id"] == "pid"
    assert row["asset_id"] == "aid"
    assert row["rule"] == "sql-injection"
    assert row["cwe"] == "CWE-89"
    assert row["dataflow"] == _HIT["dataflow"]
    assert row["metadata"]["rule_class"] == "sql_injection"


def test_build_sast_finding_rule_source_and_evidence():
    project = {"id": None, "name": "my-repo", "asset_id": None}
    item = normalize.build_sast_finding(_HIT, project)
    assert item["rule_source"] == "sast"
    assert item["severity"] == "high"
    assert item["rule_id"] == "sast:sql-injection"
    # evidence carries the dataflow
    assert item["evidence"]["dataflow"] == _HIT["dataflow"]
    assert item["evidence"]["cwe"] == "CWE-89"
    # no asset_id -> falls back to project name as a repository asset
    assert item["asset_value"] == "my-repo"
    assert item["asset_kind"] == "repository"
    assert "asset_id" not in item
    assert "cwe.mitre.org/data/definitions/89" in item["references"][0]


def test_build_sast_finding_uses_asset_id_when_present():
    item = normalize.build_sast_finding(
        _HIT, {"id": "p", "name": "demo", "asset_id": "11111111-1111-1111-1111-111111111111"})
    assert item["asset_id"] == "11111111-1111-1111-1111-111111111111"
    assert "asset_value" not in item


def test_normalize_severity_defaults_to_medium():
    assert normalize.normalize_severity("bogus") == "medium"
    assert normalize.normalize_severity("critical") == "critical"
    assert normalize.normalize_severity(None) == "medium"


def test_dedupe_collapses_same_location_keeps_worst():
    a = dict(_HIT, severity="low")
    b = dict(_HIT, severity="critical")
    c = dict(_HIT, start_line=99)
    out = normalize.dedupe([a, b, c])
    assert len(out) == 2
    same = [h for h in out if h["start_line"] == 12][0]
    assert same["severity"] == "critical"
