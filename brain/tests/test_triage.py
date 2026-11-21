"""Triage clustering + template summaries (pure, no DB/LLM)."""
from __future__ import annotations

from app.triage import build_clusters, template_summaries, _apply_llm


def _f(fid, asset, sev, src, rule="r", title="t"):
    return {"id": fid, "asset_value": asset, "severity": sev,
            "rule_source": src, "rule_id": rule, "title": title}


def test_clusters_group_by_asset_severityfamily_rulefamily():
    findings = [
        _f("1", "a.com", "critical", "nuclei"),
        _f("2", "a.com", "high", "nuclei"),      # same family 'severe' -> same cluster
        _f("3", "a.com", "low", "nuclei"),       # different family
        _f("4", "a.com", "critical", "cve_match"),  # different rule family
        _f("5", "b.com", "critical", "nuclei"),  # different asset
    ]
    clusters = build_clusters(findings)
    # (a.com,severe,nuclei)=[1,2], (a.com,low,nuclei)=[3],
    # (a.com,severe,cve_match)=[4], (b.com,severe,nuclei)=[5]
    assert len(clusters) == 4
    by_ids = {tuple(sorted(c["finding_ids"])): c for c in clusters}
    assert ("1", "2") in by_ids
    assert by_ids[("1", "2")]["severity"] == "critical"  # max of crit/high
    assert by_ids[("1", "2")]["asset_value"] == "a.com"
    assert by_ids[("1", "2")]["rule_source"] == "nuclei"


def test_template_summaries_have_required_fields():
    findings = [_f("1", "a.com", "high", "secret_scan"),
                _f("2", "a.com", "high", "secret_scan")]
    records = template_summaries(build_clusters(findings))
    assert len(records) == 1
    rec = records[0]
    for key in ("label", "summary", "remediation", "severity", "finding_ids"):
        assert key in rec
    assert rec["severity"] == "high"
    assert sorted(rec["finding_ids"]) == ["1", "2"]
    assert rec["label"]
    assert rec["summary"]
    assert rec["remediation"]
    # Deterministic: same input -> identical output.
    assert template_summaries(build_clusters(findings)) == records


def test_empty_findings_yield_no_clusters():
    assert build_clusters([]) == []
    assert template_summaries([]) == []


def test_apply_llm_keeps_severity_and_ids():
    findings = [_f("1", "a.com", "critical", "nuclei")]
    clusters = build_clusters(findings)
    merged = _apply_llm(clusters, [{"label": "L", "summary": "S", "remediation": "R"}])
    assert merged[0]["label"] == "L"
    assert merged[0]["summary"] == "S"
    assert merged[0]["remediation"] == "R"
    # severity + finding_ids come from our deterministic clustering, not the LLM.
    assert merged[0]["severity"] == "critical"
    assert merged[0]["finding_ids"] == ["1"]
