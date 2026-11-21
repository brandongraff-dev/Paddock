"""SARIF / CycloneDX / SPDX / VEX builders and the SBOM import parser (pure)."""
from __future__ import annotations

import pytest

from app import standards

from .standards_shapes import assert_cyclonedx, assert_openvex, assert_sarif, assert_spdx

PROJECT = {"id": "11111111-1111-4111-8111-111111111111", "name": "acme/web",
           "source_ref": "https://example.com/acme/web.git"}

COMPONENTS = [
    {"id": "c1", "ecosystem": "npm", "name": "express", "version": "4.18.2", "purl": "pkg:npm/express@4.18.2",
     "direct": True, "depth": 0, "paths": []},
    {"id": "c2", "ecosystem": "npm", "name": "qs", "version": "6.11.0", "purl": None,
     "direct": False, "depth": 1, "paths": ["express@4.18.2"]},
    {"id": "c3", "ecosystem": "npm", "name": "@babel/core", "version": "7.22.0", "purl": None,
     "direct": True, "depth": 0, "paths": []},
    {"id": "c4", "ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core", "version": "2.14.1",
     "purl": None, "direct": True, "depth": 0, "paths": []},
    {"id": "c5", "ecosystem": "PyPI", "name": "Django_Rest", "version": "1.0", "purl": None,
     "direct": False, "depth": 2, "paths": [["x", "qs"]]},
]


def test_purl_builder_and_parser_roundtrip():
    assert standards.purl_for("npm", "@babel/core", "7.22.0") == "pkg:npm/%40babel/core@7.22.0"
    assert standards.purl_for("Maven", "org.a:b", "1.0") == "pkg:maven/org.a/b@1.0"
    assert standards.purl_for("PyPI", "Django_Rest", "1.0") == "pkg:pypi/django-rest@1.0"
    assert standards.purl_for("Go", "github.com/x/y", "v1.2.3") == "pkg:golang/github.com/x/y@v1.2.3"
    assert standards.purl_for("unknown-eco", "x", "1") is None
    assert standards.purl_to_component("pkg:npm/%40babel/core@7.22.0") == {
        "ecosystem": "npm", "name": "@babel/core", "version": "7.22.0"}
    assert standards.purl_to_component("pkg:maven/org.a/b@1.0?type=jar") == {
        "ecosystem": "Maven", "name": "org.a:b", "version": "1.0"}
    assert standards.purl_to_component("pkg:deb/debian/openssl@3.0.11") == {
        "ecosystem": "Debian", "name": "debian/openssl", "version": "3.0.11"}
    assert standards.parse_purl("not-a-purl") is None


def test_cyclonedx_sbom_shape_and_dependency_graph():
    doc = standards.cyclonedx_sbom(PROJECT, COMPONENTS)
    assert_cyclonedx(doc)
    comps = {c["name"]: c for c in doc["components"]}
    assert comps["log4j-core"]["group"] == "org.apache.logging.log4j"
    assert comps["qs"]["purl"] == "pkg:npm/qs@6.11.0"
    root = doc["metadata"]["component"]["bom-ref"]
    deps = {d["ref"]: d["dependsOn"] for d in doc["dependencies"]}
    assert set(deps[root]) == {"pkg:npm/express@4.18.2", "pkg:npm/%40babel/core@7.22.0",
                               "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}
    assert deps["pkg:npm/express@4.18.2"] == ["pkg:npm/qs@6.11.0"]
    assert doc["metadata"]["tools"]["components"][0]["name"] == "Paddock"


def test_spdx_shape():
    doc = standards.spdx_sbom(PROJECT, COMPONENTS)
    assert_spdx(doc)
    assert len(doc["packages"]) == 1 + len(COMPONENTS)
    by_name = {p["name"]: p for p in doc["packages"]}
    rels = {(r["spdxElementId"], r["relationshipType"], r["relatedSpdxElement"]) for r in doc["relationships"]}
    assert (by_name["express"]["SPDXID"], "DEPENDS_ON", by_name["qs"]["SPDXID"]) in rels
    root = by_name["acme/web"]["SPDXID"]
    assert ("SPDXRef-DOCUMENT", "DESCRIBES", root) in rels
    assert (root, "DEPENDS_ON", by_name["express"]["SPDXID"]) in rels


VULNS = [
    {"id": "v1", "osv_id": "GHSA-hrpp-h998-j3pp", "cve_id": "CVE-2022-24999", "severity": "high", "cvss": 7.5,
     "summary": "qs prototype pollution", "fixed_version": "6.11.1", "reachability": "reachable",
     "reachable_symbol": "qs.parse", "component_id": "c2", "ecosystem": "npm", "name": "qs",
     "version": "6.11.0", "purl": None, "direct": False, "depth": 1},
    {"id": "v2", "osv_id": "GHSA-jfh8-c2jp-5v3q", "cve_id": "CVE-2021-44228", "severity": "critical",
     "cvss": 10.0, "summary": "Log4Shell", "fixed_version": "2.15.0", "reachability": "unreachable",
     "reachable_symbol": "JndiLookup", "component_id": "c4", "ecosystem": "Maven",
     "name": "org.apache.logging.log4j:log4j-core", "version": "2.14.1", "purl": None, "direct": True,
     "depth": 0},
    {"id": "v3", "osv_id": "PYSEC-2024-1", "cve_id": None, "severity": "medium", "cvss": None,
     "summary": None, "fixed_version": None, "reachability": "unknown", "reachable_symbol": None,
     "component_id": "c5", "ecosystem": "PyPI", "name": "Django_Rest", "version": "1.0", "purl": None,
     "direct": False, "depth": 2},
]


def test_cyclonedx_vex_reachability_states():
    doc = standards.cyclonedx_vex(PROJECT, VULNS)
    assert_cyclonedx(doc)
    by_id = {v["id"]: v for v in doc["vulnerabilities"]}
    assert by_id["CVE-2022-24999"]["analysis"]["state"] == "exploitable"
    assert by_id["CVE-2022-24999"]["analysis"]["response"] == ["update"]
    assert by_id["CVE-2022-24999"]["references"][0]["id"] == "GHSA-hrpp-h998-j3pp"
    l4 = by_id["CVE-2021-44228"]
    assert l4["analysis"] == {"state": "not_affected", "justification": "code_not_reachable",
                              "detail": l4["analysis"]["detail"]}
    assert "no call path" in l4["analysis"]["detail"]
    assert l4["affects"][0]["versions"][0]["status"] == "unaffected"
    assert l4["ratings"][0] == {"severity": "critical", "score": 10.0, "method": "CVSSv3"}
    assert by_id["PYSEC-2024-1"]["analysis"]["state"] == "in_triage"
    assert by_id["PYSEC-2024-1"]["source"]["name"] == "OSV"


def test_openvex_statuses():
    doc = standards.openvex(PROJECT, VULNS)
    assert_openvex(doc)
    st = {s["vulnerability"]["name"]: s for s in doc["statements"]}
    assert st["CVE-2022-24999"]["status"] == "affected"
    assert "6.11.1" in st["CVE-2022-24999"]["action_statement"]
    assert st["CVE-2021-44228"]["status"] == "not_affected"
    assert st["CVE-2021-44228"]["justification"] == "vulnerable_code_not_in_execute_path"
    assert st["CVE-2021-44228"]["vulnerability"]["aliases"] == ["GHSA-jfh8-c2jp-5v3q"]
    assert st["PYSEC-2024-1"]["status"] == "under_investigation"
    assert st["CVE-2022-24999"]["products"] == [{"@id": "pkg:npm/qs@6.11.0"}]


def test_sarif_log_shape():
    hits = [
        {"kind": "sast", "rule_id": "python.sqli", "title": "SQL injection", "message": "tainted query",
         "severity": "high", "file": "./app/db.py", "start_line": 10, "end_line": 12, "cwe": "CWE-89",
         "dataflow": [{"step": "source", "label": "request.args", "line": 8},
                      {"step": "sink", "label": "cursor.execute", "line": 10}], "finding_id": "f1"},
        {"kind": "sast", "rule_id": "python.sqli", "title": "SQL injection", "message": "again",
         "severity": "high", "file": "/src/repo/app/x.py", "start_line": 0, "cwe": "89"},
        {"kind": "sca", "rule_id": "GHSA-x", "title": "CVE-1 in qs", "message": "m", "severity": "critical",
         "cvss": 9.8, "file": "package-lock.json", "level": "note", "suppressed": "accepted_risk"},
    ]
    doc = standards.sarif_log(hits, automation_id="paddock/acme/", strip_prefix="/src/repo")
    assert_sarif(doc)
    run = doc["runs"][0]
    assert [r["id"] for r in run["tool"]["driver"]["rules"]] == ["python.sqli", "GHSA-x"]
    r0 = run["tool"]["driver"]["rules"][0]
    assert r0["properties"]["security-severity"] == "8.0"
    assert "external/cwe/cwe-89" in r0["properties"]["tags"]
    assert r0["relationships"][0]["target"]["id"] == "89"
    assert run["taxonomies"][0]["taxa"] == [{"id": "89", "name": "CWE-89",
                                             "helpUri": "https://cwe.mitre.org/data/definitions/89.html"}]
    res = run["results"]
    loc0 = res[0]["locations"][0]["physicalLocation"]
    assert loc0["artifactLocation"] == {"uri": "app/db.py", "uriBaseId": "%SRCROOT%"}
    assert loc0["region"] == {"startLine": 10, "endLine": 12}
    assert len(res[0]["codeFlows"][0]["threadFlows"][0]["locations"]) == 2
    assert res[0]["properties"]["paddockFindingId"] == "f1"
    assert res[1]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app/x.py"
    assert "region" not in res[1]["locations"][0]["physicalLocation"]   # line 0 -> file-level
    assert res[2]["level"] == "note" and res[2]["suppressions"][0]["status"] == "accepted"
    assert run["tool"]["driver"]["rules"][1]["properties"]["security-severity"] == "9.8"
    assert run["automationDetails"]["id"] == "paddock/acme/"


@pytest.mark.parametrize("sev,level", [("critical", "error"), ("high", "error"), ("medium", "warning"),
                                       ("low", "note"), ("info", "note")])
def test_sarif_levels(sev, level):
    assert standards.sarif_level(sev) == level


def test_manifest_choice():
    m = {"npm": ["web/package-lock.json", "package-lock.json"]}
    assert standards.sca_manifest_for("npm", m) == "package-lock.json"
    assert standards.sca_manifest_for("PyPI", m) == "requirements.txt"
    assert standards.sca_manifest_for("Hex", m) == "SBOM"


# --------------------------------------------------------------------------- #
# import parser
# --------------------------------------------------------------------------- #

CDX_IN = {
    "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
    "metadata": {"component": {"type": "application", "name": "shop", "bom-ref": "root"}},
    "components": [
        {"type": "library", "name": "express", "version": "4.18.2", "purl": "pkg:npm/express@4.18.2",
         "bom-ref": "e", "components": [
             {"type": "library", "name": "qs", "version": "6.11.0", "purl": "pkg:npm/qs@6.11.0", "bom-ref": "q"}]},
        {"type": "library", "group": "org.a", "name": "b", "version": "1.0", "bom-ref": "m"},
        {"type": "library", "name": "no-version"},
        {"type": "library", "name": "express", "version": "4.18.2", "purl": "pkg:npm/express@4.18.2"},
    ],
    "dependencies": [{"ref": "root", "dependsOn": ["e", "m"]}, {"ref": "e", "dependsOn": ["q"]}],
    "vulnerabilities": [
        {"id": "CVE-2022-24999", "ratings": [{"severity": "high", "score": 7.5}],
         "description": "qs pp", "affects": [{"ref": "q"}],
         "analysis": {"state": "not_affected", "justification": "code_not_reachable"}},
        {"id": "GHSA-zzz", "affects": [{"ref": "unknown-ref"}]},
    ],
}


def test_parse_cyclonedx():
    out = standards.parse_sbom(CDX_IN)
    assert out["format"] == "cyclonedx" and out["name"] == "shop"
    comps = {(c["ecosystem"], c["name"]): c for c in out["components"]}
    assert set(comps) == {("npm", "express"), ("npm", "qs"), ("generic", "org.a/b")}
    assert comps[("npm", "express")]["direct"] and comps[("npm", "express")]["depth"] == 0
    assert not comps[("npm", "qs")]["direct"] and comps[("npm", "qs")]["depth"] == 1
    assert comps[("npm", "qs")]["paths"] == ["express@4.18.2"]
    [v] = out["vulns"]
    assert v["key"] == ("npm", "qs", "6.11.0") and v["cve_id"] == "CVE-2022-24999"
    assert v["severity"] == "high" and v["cvss"] == 7.5 and v["reachability"] == "unreachable"


def test_parse_spdx():
    doc = standards.spdx_sbom(PROJECT, COMPONENTS)
    out = standards.parse_sbom(doc)
    assert out["format"] == "spdx" and out["name"] == "acme/web"
    got = {(c["ecosystem"], c["name"], c["version"]): c for c in out["components"]}
    assert ("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1") in got
    assert ("npm", "@babel/core", "7.22.0") in got
    assert got[("npm", "qs", "6.11.0")]["direct"] is False
    assert got[("npm", "express", "4.18.2")]["direct"] is True


@pytest.mark.parametrize("doc", [[], {"hello": 1}, {"bomFormat": "Other"}, {"spdxVersion": "SPDX-3.0"}])
def test_parse_rejects_non_sbom(doc):
    with pytest.raises(standards.ImportError_):
        standards.parse_sbom(doc)


def test_parse_limits_components(monkeypatch):
    monkeypatch.setattr(standards, "MAX_IMPORT_COMPONENTS", 3)
    doc = {"bomFormat": "CycloneDX", "components": [
        {"type": "library", "name": f"p{i}", "version": "1"} for i in range(5)]}
    with pytest.raises(standards.ImportError_):
        standards.parse_sbom(doc)


def test_parse_deep_nesting_is_bounded():
    inner: dict = {"type": "library", "name": "leaf", "version": "1"}
    for i in range(100):
        inner = {"type": "library", "name": f"n{i}", "version": "1", "components": [inner]}
    out = standards.parse_sbom({"bomFormat": "CycloneDX", "components": [inner]})
    assert len(out["components"]) <= standards._MAX_NEST + 2
