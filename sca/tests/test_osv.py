from __future__ import annotations

import pytest

from app import osv


def test_build_queries_includes_and_omits_version():
    body = osv.build_queries([("npm", "left-pad", "1.0.0"), ("PyPI", "django", "")])
    assert body["queries"][0]["package"]["ecosystem"] == "npm"
    assert body["queries"][0]["version"] == "1.0.0"
    assert "version" not in body["queries"][1]


def test_extract_ids():
    assert osv.extract_ids({}) == []
    assert osv.extract_ids({"results": [{}, {"vulns": []}]}) == [[], []]
    assert osv.extract_ids(
        {"results": [{"vulns": [{"id": "GHSA-1"}, {"id": "GHSA-2"}]}]}
    ) == [["GHSA-1", "GHSA-2"]]


def test_cvss3_base_score_critical():
    vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert osv.cvss3_base_score(vec) == pytest.approx(9.8, abs=0.05)
    assert osv.severity_bucket(9.8) == "critical"


def test_cvss3_base_score_medium_scope_changed():
    vec = "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N"
    score = osv.cvss3_base_score(vec)
    assert score is not None and 4.0 <= score < 7.0
    assert osv.severity_bucket(score) == "medium"


def test_cvss_invalid_vector_returns_none():
    assert osv.cvss3_base_score("not-a-vector") is None
    assert osv.severity_bucket(None) == "medium"


def test_cve_and_malicious_detection():
    ghsa = {"id": "GHSA-abc", "aliases": ["CVE-2024-1", "OTHER"]}
    assert osv.cve_from_aliases(ghsa) == "CVE-2024-1"
    assert osv.is_malicious({"id": "MAL-2023-1"}) is True
    assert osv.is_malicious(ghsa) is False


def test_fixed_version_from_ranges():
    vuln = {
        "affected": [{
            "package": {"ecosystem": "npm", "name": "demo-lib"},
            "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}],
        }]
    }
    assert osv.fixed_version_for(vuln, "npm", "demo-lib") == "1.2.3"


def test_map_vuln_full(fake_osv_session):
    import json
    import pathlib
    data = json.loads(
        (pathlib.Path(__file__).parent / "fixtures" / "osv_vuln_ghsa.json").read_text()
    )
    mapped = osv.map_vuln(data, "npm", "demo-lib")
    assert mapped["osv_id"] == "GHSA-xxxx-yyyy-zzzz"
    assert mapped["cve_id"] == "CVE-2023-9999"
    assert mapped["severity"] == "critical"
    assert mapped["fixed_version"] == "1.2.3"
    assert mapped["malicious"] is False


def test_severity_from_label_fallback():
    vuln = {"id": "MAL-1", "database_specific": {"severity": "HIGH"}}
    sev, score = osv.severity_and_score(vuln)
    assert sev == "high" and score is None


async def test_scan_components_end_to_end(fake_osv_session):
    components = [
        {"ecosystem": "npm", "name": "demo-lib", "version": "1.0.0"},
        {"ecosystem": "npm", "name": "safe-lib", "version": "2.0.0"},
        {"ecosystem": "npm", "name": "evil-lib", "version": "6.6.6"},
    ]
    results = await osv.scan_components(fake_osv_session, components)
    assert "npm|demo-lib|1.0.0" in results
    assert results["npm|demo-lib|1.0.0"][0]["cve_id"] == "CVE-2023-9999"
    # second query had no vulns
    assert "npm|safe-lib|2.0.0" not in results
    # third is a malicious advisory
    assert results["npm|evil-lib|6.6.6"][0]["malicious"] is True
    # batch posted once, details fetched per unique id
    assert len(fake_osv_session.posts) == 1
