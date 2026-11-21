"""OCSF 1.3 mapping of findings and integration events (pure, no DB)."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.integrations import Event, ocsf

T0 = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)
T1 = datetime(2026, 11, 20, 8, 30, tzinfo=timezone.utc)

REQUIRED_BASE = ("activity_id", "category_uid", "class_uid", "finding_info", "metadata",
                 "severity_id", "time", "type_uid")


def _finding(**kw):
    f = {
        "id": "8d6f5c1e-0000-4000-8000-000000000001",
        "asset_id": "a0000000-0000-4000-8000-0000000000aa",
        "asset_value": "api.acme-demo.example",
        "asset_kind": "subdomain",
        "rule_id": "exposed-git",
        "rule_source": "exposed_file",
        "severity": "high",
        "title": "Exposed .git directory",
        "description": "/.git/HEAD is publicly readable",
        "impact": "Source code disclosure",
        "remediation": "Block access to /.git in the web server config.",
        "evidence": {"url": "https://api.acme-demo.example/.git/HEAD", "body_snippet": "ref: refs/heads/main"},
        "cvss": None,
        "epss": None,
        "references": ["https://example.org/git-exposure"],
        "status": "open",
        "first_seen": T0,
        "last_seen": T1,
        "assigned_to": "web-team",
        "metadata": {"blast_score": 4.2},
        "classification": "internal",
        "blast_score": 4.2,
    }
    f.update(kw)
    return f


def _assert_shape(o):
    for k in REQUIRED_BASE:
        assert k in o, k
    assert o["category_uid"] == 2
    assert o["type_uid"] == o["class_uid"] * 100 + o["activity_id"]
    assert o["metadata"]["version"] == "1.3.0"
    assert o["metadata"]["product"]["vendor_name"] == "Paddock"
    assert o["finding_info"]["uid"] and o["finding_info"]["title"]
    assert isinstance(o["time"], int) and o["time"] > 1_600_000_000_000  # ms epoch


def test_detection_finding_basic_mapping():
    o = ocsf.finding_to_ocsf(_finding())
    _assert_shape(o)
    assert o["class_uid"] == 2004 and o["class_name"] == "Detection Finding"
    assert o["activity_id"] == 1 and o["type_uid"] == 200401
    assert (o["severity_id"], o["severity"]) == (4, "High")
    assert (o["status_id"], o["status"]) == (1, "New")
    assert o["finding_info"]["analytic"]["uid"] == "exposed-git"
    assert o["finding_info"]["types"] == ["exposed_file"]
    assert o["finding_info"]["first_seen_time"] == int(T0.timestamp() * 1000)
    assert o["finding_info"]["last_seen_time"] == int(T1.timestamp() * 1000)
    res = o["resources"][0]
    assert res == {"uid": "a0000000-0000-4000-8000-0000000000aa", "name": "api.acme-demo.example",
                   "type": "subdomain", "labels": ["classification:internal"]}
    assert o["observables"][0]["type_id"] == 1 and o["observables"][0]["value"] == "api.acme-demo.example"
    assert o["remediation"]["desc"].startswith("Block access")
    assert o["remediation"]["references"] == ["https://example.org/git-exposure"]
    pd = o["unmapped"]["paddock"]
    assert pd["severity"] == "high" and pd["blast_score"] == 4.2 and pd["rule_source"] == "exposed_file"
    assert pd["impact"] == "Source code disclosure"
    assert "vulnerabilities" not in o
    # evidence is never copied wholesale (response snippets stay in Paddock)
    assert "body_snippet" not in str(o)


def test_cve_finding_becomes_vulnerability_finding_with_cvss_epss_kev_cwe():
    f = _finding(rule_id="CVE-2024-3094", rule_source="cve_match", severity="critical",
                 title="xz backdoor", cvss=10.0, epss=0.951, metadata={"kev": True})
    cve = {"id": "CVE-2024-3094", "cvss_v3": 10.0,
           "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
           "epss": 0.951, "epss_percentile": 0.99, "cwe_ids": ["CWE-506"],
           "known_exploited": False, "published_at": T0}
    o = ocsf.finding_to_ocsf(f, cve=cve)
    _assert_shape(o)
    assert o["class_uid"] == 2002 and o["type_uid"] == 200201
    assert (o["severity_id"], o["severity"]) == (5, "Critical")
    [v] = o["vulnerabilities"]
    assert v["cve"]["uid"] == "CVE-2024-3094"
    assert v["cve"]["cvss"][0] == {"version": "3.1", "base_score": 10.0,
                                   "vector_string": cve["cvss_v3_vector"]}
    assert v["cve"]["epss"] == {"score": "0.951", "percentile": 0.99}
    assert v["cwe"]["uid"] == "CWE-506"
    assert v["is_exploit_available"] is True  # finding metadata kev wins
    assert o["unmapped"]["paddock"]["cvss"] == 10.0


def test_sca_finding_with_multiple_cves_and_package():
    f = _finding(rule_id="sca:npm:lodash", rule_source="sca", severity="high",
                 evidence={"ecosystem": "npm", "package": "lodash", "version": "4.17.15",
                           "cve_ids": ["CVE-2020-8203", "cve-2021-23337"], "fixed_version": "4.17.21"})
    o = ocsf.finding_to_ocsf(f)
    assert o["class_uid"] == 2002
    assert [v["cve"]["uid"] for v in o["vulnerabilities"]] == ["CVE-2020-8203", "CVE-2021-23337"]
    pkg = o["vulnerabilities"][0]["affected_packages"][0]
    assert pkg == {"name": "lodash", "version": "4.17.15", "package_manager": "npm",
                   "fixed_in_version": "4.17.21"}
    assert o["vulnerabilities"][0]["is_fix_available"] is True


def test_sast_finding_has_cwe_and_affected_code():
    f = _finding(rule_id="sast:python.sqli", rule_source="sast", severity="medium",
                 evidence={"file": "app/db.py", "start_line": 42, "end_line": 43, "cwe": "CWE-89",
                           "rule": "python.sqli"}, asset_kind="repository", asset_value="acme/api")
    o = ocsf.finding_to_ocsf(f)
    assert o["class_uid"] == 2004
    [v] = o["vulnerabilities"]
    assert v["cwe"] == {"uid": "CWE-89", "caption": "CWE-89",
                        "src_url": "https://cwe.mitre.org/data/definitions/89.html"}
    code = v["affected_code"][0]
    assert code["file"]["path"] == "app/db.py" and code["file"]["name"] == "db.py"
    assert (code["start_line"], code["end_line"]) == (42, 43)
    assert "observables" not in o  # a repository is not a hostname/IP


@pytest.mark.parametrize("status,sid,label", [
    ("open", 1, "New"), ("triaged", 2, "In Progress"), ("accepted_risk", 3, "Suppressed"),
    ("false_positive", 3, "Suppressed"), ("wontfix", 3, "Suppressed"), ("fixed", 4, "Resolved"),
])
def test_status_mapping(status, sid, label):
    o = ocsf.finding_to_ocsf(_finding(status=status))
    assert (o["status_id"], o["status"]) == (sid, label)
    if status == "fixed":
        assert o["activity_id"] == 3 and o["type_uid"] == 200403


@pytest.mark.parametrize("sev,sid", [("info", 1), ("low", 2), ("medium", 3), ("high", 4),
                                     ("critical", 5), (None, 0), ("bogus", 0)])
def test_severity_ids(sev, sid):
    assert ocsf.severity_id(sev) == sid


@pytest.mark.parametrize("etype,activity,status_id", [
    ("finding.opened", 1, 1), ("finding.updated", 2, 1), ("finding.reopened", 2, 1),
    ("finding.accepted", 2, 3), ("finding.resolved", 3, 4),
])
def test_finding_events(etype, activity, status_id):
    ev = Event(type=etype, title="t", severity="high", data={"finding": _finding()},
               url="https://paddock.example/findings/1", tenant_id="t1", occurred_at=T1)
    o = ocsf.event_to_ocsf(ev)
    _assert_shape(o)
    assert o["activity_id"] == activity and o["status_id"] == status_id
    assert o["metadata"]["uid"] == ev.id                       # idempotency key
    assert o["metadata"]["correlation_uid"] == _finding()["id"]
    assert o["metadata"]["tenant_uid"] == "t1"
    assert o["finding_info"]["src_url"] == "https://paddock.example/findings/1"
    assert o["time"] == int(T1.timestamp() * 1000)
    assert ocsf.event_uid(o) == ev.id


def test_finding_event_with_top_level_fields():
    data = {k: v for k, v in _finding().items()}
    o = ocsf.event_to_ocsf(Event(type="finding.opened", title="t", data=data))
    assert o["finding_info"]["uid"] == data["id"]


def test_non_finding_events_are_detection_findings():
    ev = Event(type="attack_path.opened", title="Path to payments DB", summary="3 hops",
               severity="critical", data={"attack_path_id": "p-1", "hops": 3,
                                          "asset": {"id": "x", "value": "10.0.0.5", "kind": "ipv4"},
                                          "nested": {"secretish": "not copied"}})
    o = ocsf.event_to_ocsf(ev)
    _assert_shape(o)
    assert o["class_uid"] == 2004 and o["activity_id"] == 1
    assert o["finding_info"]["uid"] == "p-1" and o["finding_info"]["types"] == ["attack_path.opened"]
    assert o["resources"][0]["name"] == "10.0.0.5" and o["observables"][0]["type"] == "IP Address"
    assert o["unmapped"]["paddock"]["data"] == {"attack_path_id": "p-1", "hops": 3}
    assert "secretish" not in str(o)

    t = ocsf.event_to_ocsf(Event(type="integration.test", title="hi"))
    assert t["activity_id"] == 99 and t["type_uid"] == 200499 and t["severity_id"] == 1


def test_event_dict_input_accepted():
    ev = Event(type="scan.completed", title="done", severity="info")
    assert ocsf.event_to_ocsf(ev.as_dict())["finding_info"]["title"] == "done"
