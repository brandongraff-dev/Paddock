from __future__ import annotations

from app.enrich import finding_writer


def test_severity_from_cvss() -> None:
    assert finding_writer.severity_for(9.5, False) == "critical"
    assert finding_writer.severity_for(7.0, False) == "high"
    assert finding_writer.severity_for(4.0, False) == "medium"
    assert finding_writer.severity_for(3.9, False) == "low"


def test_severity_bumped_by_kev() -> None:
    assert finding_writer.severity_for(2.0, True) == "critical"
    assert finding_writer.severity_for(None, True) == "critical"


def test_severity_defaults_low_for_unknown() -> None:
    assert finding_writer.severity_for(None, False) == "low"
    assert finding_writer.severity_for("junk", False) == "low"  # type: ignore[arg-type]


def test_build_finding_shape() -> None:
    cve = {
        "id": "CVE-2024-1234",
        "description": "test overflow",
        "cvss_v3": 7.5,
        "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N",
        "epss": 0.4,
        "epss_percentile": 0.9,
        "refs": [
            {"url": "https://example.com/adv"},
            "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
        ],
        "cwe_ids": ["CWE-120"],
        "known_exploited": False,
    }
    asset = {
        "id": "aaaaaaaa-0000-0000-0000-000000000000",
        "value": "nginx@host1",
        "metadata": {"vendor": "nginx", "product": "nginx", "version": "1.18.0"},
    }
    out = finding_writer.build_finding(cve=cve, asset=asset, confidence=85)
    assert out["rule_source"] == "cve_match"
    assert out["rule_id"] == "CVE-2024-1234"
    assert out["severity"] == "high"
    assert out["asset_id"] == asset["id"]
    assert out["cvss"] == 7.5
    assert out["epss"] == 0.4
    assert "example.com/adv" in out["references"][0]
    assert out["metadata"]["confidence"] == 85
    assert "CVSS v3 base score" in out["impact"]


def test_build_finding_kev_marks_critical() -> None:
    cve = {
        "id": "CVE-X",
        "description": "d",
        "cvss_v3": 3.0,
        "cvss_v3_vector": None,
        "refs": [],
        "cwe_ids": [],
        "known_exploited": True,
    }
    out = finding_writer.build_finding(
        cve=cve,
        asset={"id": "aid", "metadata": {"product": "x"}},
        confidence=85,
    )
    assert out["severity"] == "critical"
    assert "CISA KEV" in out["impact"]
    assert "CISA KEV" in out["remediation"]


def test_remediation_never_includes_exploit_wording() -> None:
    cve = {"id": "CVE-A", "description": "d", "refs": [], "cwe_ids": []}
    out = finding_writer.build_finding(
        cve=cve,
        asset={"id": "x", "metadata": {"product": "p"}},
        confidence=70,
    )
    for banned in ("payload", "exploit", "POC", "poc ", "proof-of-concept"):
        assert banned.lower() not in out["remediation"].lower()
