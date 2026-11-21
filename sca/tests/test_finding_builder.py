from __future__ import annotations

from app.orchestrator import build_sca_finding, worst_severity


def test_worst_severity():
    assert worst_severity(["low", "high", "medium"]) == "high"
    assert worst_severity(["info", "info"]) == "info" or worst_severity(["info"]) in ("info", "low")
    assert worst_severity(["low", "critical"]) == "critical"


def test_build_finding_with_asset_id():
    comp = {"ecosystem": "npm", "name": "demo-lib", "version": "1.0.0",
            "direct": True, "depth": 0, "paths": []}
    vulns = [{
        "osv_id": "GHSA-x", "cve_id": "CVE-2023-9999", "severity": "critical",
        "cvss": 9.8, "fixed_version": "1.2.3", "refs": ["https://e/x"],
    }]
    project = {"name": "demo", "asset_id": "11111111-1111-1111-1111-111111111111"}
    item = build_sca_finding(component=comp, vulns=vulns, project=project)
    assert item["rule_source"] == "sca"
    assert item["severity"] == "critical"
    assert item["asset_id"] == project["asset_id"]
    assert "asset_value" not in item
    assert item["evidence"]["osv_ids"] == ["GHSA-x"]
    assert item["cvss"] == 9.8
    assert "1.2.3" in item["remediation"]


def test_build_finding_falls_back_to_project_name_asset():
    comp = {"ecosystem": "PyPI", "name": "requests", "version": "2.0.0",
            "direct": False, "depth": 2, "paths": ["flask"]}
    vulns = [{"osv_id": "OSV-1", "cve_id": None, "severity": "high", "cvss": 7.5,
              "fixed_version": None, "refs": []}]
    project = {"name": "my-repo", "asset_id": None}
    item = build_sca_finding(component=comp, vulns=vulns, project=project)
    assert item["asset_value"] == "my-repo"
    assert item["asset_kind"] == "repository"
    assert "asset_id" not in item
    assert "transitive" in item["impact"]
