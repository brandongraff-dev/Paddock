"""DB-backed tests for /v1/export/* and /v1/import/* (exports.py)."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from app.auth import Principal, capabilities_for, current_principal, required_capability

from .standards_shapes import assert_cyclonedx, assert_openvex, assert_sarif, assert_spdx

NOW = datetime.now(timezone.utc)


async def _seed(pool) -> dict:
    ids: dict = {}
    async with pool.acquire() as con:
        ids["asset"] = await con.fetchval(
            "INSERT INTO assets (kind, value, canonical, source) VALUES "
            "('subdomain','api.acme-demo.example','api.acme-demo.example','test') RETURNING id")
        ids["repo"] = await con.fetchval(
            "INSERT INTO assets (kind, value, canonical, source) VALUES "
            "('repository','acme/web','acme/web','test') RETURNING id")
        await con.execute(
            "INSERT INTO cves (id, cvss_v3, cvss_v3_vector, epss, epss_percentile, cwe_ids, known_exploited) "
            "VALUES ('CVE-2021-44228', 10.0, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 0.975, 0.99, "
            "ARRAY['CWE-502'], TRUE)")

        async def finding(rule_id, source, sev, title, *, status="open", cls="internal", evidence=None,
                          metadata=None, last_seen=NOW, asset=None, cvss=None):
            return await con.fetchval(
                """INSERT INTO findings (asset_id, rule_id, rule_source, severity, title, description,
                       remediation, evidence, metadata, status, classification, last_seen, cvss,
                       status_reason)
                   VALUES ($1,$2,$3,$4,$5,$6,'fix it',$7::jsonb,$8::jsonb,$9,$10,$11,$12,$13) RETURNING id""",
                asset or ids["asset"], rule_id, source, sev, title, f"{title} description",
                json.dumps(evidence or {}), json.dumps(metadata or {}), status, cls, last_seen, cvss,
                # dismissals require a reason (schema 019)
                "reviewed: test fixture" if status in ("accepted", "false_positive") else None)

        ids["f_cve"] = await finding("CVE-2021-44228", "cve_match", "critical", "Log4Shell", cvss=10.0)
        ids["f_hdr"] = await finding("missing-hsts", "header_check", "low", "HSTS missing",
                                     last_seen=NOW - timedelta(days=30))
        ids["f_fixed"] = await finding("exposed-env", "exposed_file", "high", "Exposed .env", status="fixed")
        ids["f_secret"] = await finding("restricted-thing", "manual", "high", "Restricted finding",
                                        cls="restricted")
        ids["f_sast_orphan"] = await finding(
            "sast:python.cmdi", "sast", "high", "Command injection in app/run.py", asset=ids["repo"],
            evidence={"file": "app/run.py", "start_line": 7, "end_line": 7, "cwe": "CWE-78",
                      "rule": "python.cmdi", "dataflow": [{"step": "source", "label": "argv", "line": 5}]},
            metadata={"project": "acme/web", "cwe": "CWE-78"})
        ids["f_sast_mirror"] = await finding(
            "sast:python.sqli", "sast", "high", "SQL injection in app/db.py", asset=ids["repo"],
            evidence={"file": "app/db.py", "start_line": 42}, metadata={"project": "acme/web"})
        ids["f_sast_fp"] = await finding(
            "sast:python.xss", "sast", "medium", "XSS in app/views.py", asset=ids["repo"],
            status="false_positive", evidence={"file": "app/views.py", "start_line": 3},
            metadata={"project": "acme/web"})

        ids["project"] = await con.fetchval(
            "INSERT INTO sca_projects (name, source_ref, ecosystems, asset_id) "
            "VALUES ('acme/web', 'https://example.com/acme/web', ARRAY['npm','Maven'], $1) RETURNING id",
            ids["repo"])
        pid = ids["project"]

        async def comp(eco, name, ver, direct, depth, paths):
            return await con.fetchval(
                "INSERT INTO sbom_components (project_id, ecosystem, name, version, purl, direct, depth, paths) "
                "VALUES ($1,$2,$3,$4,NULL,$5,$6,$7::jsonb) RETURNING id",
                pid, eco, name, ver, direct, depth, json.dumps(paths))

        ids["c_express"] = await comp("npm", "express", "4.18.2", True, 0, [])
        ids["c_qs"] = await comp("npm", "qs", "6.11.0", False, 1, ["express@4.18.2"])
        ids["c_log4j"] = await comp("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1", True, 0, [])

        async def vuln(cid, osv, cve, sev, reach, fixed=None):
            await con.execute(
                "INSERT INTO sbom_component_vulns (component_id, osv_id, cve_id, severity, cvss, summary, "
                "fixed_version, reachability, reachable_symbol) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
                cid, osv, cve, sev, 7.5, f"{osv} summary", fixed, reach, "sym")

        await vuln(ids["c_qs"], "GHSA-hrpp-h998-j3pp", "CVE-2022-24999", "high", "reachable", "6.11.1")
        await vuln(ids["c_log4j"], "GHSA-jfh8-c2jp-5v3q", "CVE-2021-44228", "critical", "unreachable", "2.15.0")
        await vuln(ids["c_express"], "GHSA-xxxx", None, "medium", "unknown")

        await con.execute(
            "INSERT INTO code_findings (project_id, asset_id, finding_id, rule, message, severity, file, "
            "start_line, end_line, source, sink, dataflow, cwe) VALUES "
            "($1,$2,$3,'python.sqli','tainted SQL','high','app/db.py',42,44,'request.args','cursor.execute',"
            "$4::jsonb,'CWE-89')",
            pid, ids["repo"], ids["f_sast_mirror"],
            json.dumps([{"step": "source", "label": "request.args", "line": 40},
                        {"step": "sink", "label": "cursor.execute", "line": 42}]))
        await con.execute(
            "INSERT INTO code_findings (project_id, asset_id, finding_id, rule, message, severity, file, "
            "start_line, cwe) VALUES ($1,$2,$3,'python.xss','xss','medium','app/views.py',3,'CWE-79')",
            pid, ids["repo"], ids["f_sast_fp"])
        await con.execute(
            "INSERT INTO sca_project_manifests (project_id, path, ecosystem) VALUES "
            "($1,'web/package-lock.json','npm'), ($1,'pom.xml','Maven')", pid)
    return ids


def _lines(resp) -> list[dict]:
    return [json.loads(x) for x in resp.text.splitlines() if x.strip()]


# --------------------------------------------------------------------------- #
# RBAC wiring
# --------------------------------------------------------------------------- #

def test_rbac_rules():
    for p in ("/v1/export/findings.ocsf", "/v1/export/sarif", "/v1/export/sbom", "/v1/export/vex"):
        assert required_capability("GET", p) == "read"
    assert required_capability("POST", "/v1/import/sbom") == "scan"
    assert required_capability("POST", "/v1/import/lockfiles") == "scan"
    assert required_capability("POST", "/v1/export/sarif") == "admin"   # deny-closed


# --------------------------------------------------------------------------- #
# OCSF NDJSON
# --------------------------------------------------------------------------- #

async def test_findings_ocsf_ndjson(client, db_pool):
    ids = await _seed(db_pool)
    r = await client.get("/v1/export/findings.ocsf")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/x-ndjson")
    assert "attachment" in r.headers["content-disposition"]
    rows = _lines(r)
    by_uid = {o["finding_info"]["uid"]: o for o in rows}
    assert len(rows) == 7  # dev admin sees restricted too
    cve = by_uid[str(ids["f_cve"])]
    assert cve["class_uid"] == 2002 and cve["type_uid"] == 200201 and cve["severity_id"] == 5
    v = cve["vulnerabilities"][0]
    assert v["cve"]["uid"] == "CVE-2021-44228" and v["is_exploit_available"] is True
    assert v["cwe"]["uid"] == "CWE-502" and v["cve"]["cvss"][0]["vector_string"].startswith("CVSS:3.1")
    assert cve["resources"][0]["name"] == "api.acme-demo.example"
    fixed = by_uid[str(ids["f_fixed"])]
    assert fixed["status_id"] == 4 and fixed["activity_id"] == 3
    assert by_uid[str(ids["f_hdr"])]["class_uid"] == 2004


async def test_findings_ocsf_filters(client, db_pool):
    ids = await _seed(db_pool)
    r = await client.get("/v1/export/findings.ocsf", params=[("severity", "critical"), ("severity", "low")])
    assert {o["finding_info"]["uid"] for o in _lines(r)} == {str(ids["f_cve"]), str(ids["f_hdr"])}
    r = await client.get("/v1/export/findings.ocsf", params={"min_severity": "high", "status": "fixed"})
    assert [o["finding_info"]["uid"] for o in _lines(r)] == [str(ids["f_fixed"])]
    since = (NOW - timedelta(days=1)).isoformat()
    r = await client.get("/v1/export/findings.ocsf", params={"since": since})
    assert str(ids["f_hdr"]) not in {o["finding_info"]["uid"] for o in _lines(r)}
    r = await client.get("/v1/export/findings.ocsf", params={"rule_source": "sast", "limit": 1})
    assert len(_lines(r)) == 1
    r = await client.get("/v1/export/findings.ocsf", params={"severity": "urgent"})
    assert r.status_code == 422


async def test_findings_ocsf_abac(app, client, db_pool):
    ids = await _seed(db_pool)
    app.dependency_overrides[current_principal] = lambda: Principal(
        actor="viewer", role="viewer", clearance="internal",
        capabilities=capabilities_for("viewer"), kind="user")
    try:
        r = await client.get("/v1/export/findings.ocsf")
    finally:
        app.dependency_overrides.clear()
    uids = {o["finding_info"]["uid"] for o in _lines(r)}
    assert str(ids["f_secret"]) not in uids and len(uids) == 6


async def test_exports_are_audited(client, db_pool):
    await _seed(db_pool)
    await client.get("/v1/export/findings.ocsf")
    await client.get("/v1/export/sbom", params={"project": "acme/web"})
    async with db_pool.acquire() as con:
        rows = await con.fetch("SELECT path, classification FROM audit_log WHERE path LIKE '/v1/export/%'")
    paths = {r["path"]: r["classification"] for r in rows}
    assert paths["/v1/export/findings.ocsf"] == "restricted"
    assert "/v1/export/sbom" in paths


# --------------------------------------------------------------------------- #
# SARIF
# --------------------------------------------------------------------------- #

async def test_sarif_code_and_sca(client, db_pool):
    ids = await _seed(db_pool)
    r = await client.get("/v1/export/sarif", params={"project": "acme/web"})
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/sarif+json")
    doc = r.json()
    assert_sarif(doc)
    run = doc["runs"][0]
    assert run["automationDetails"]["id"] == "paddock/acme/web/"
    results = run["results"]
    by_rule = {}
    for res in results:
        by_rule.setdefault(res["ruleId"], []).append(res)
    # code finding from code_findings (+ mirror), and the orphan unified sast finding
    sqli = by_rule["python.sqli"][0]
    loc = sqli["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "app/db.py" and loc["region"] == {"startLine": 42, "endLine": 44}
    assert sqli["properties"]["paddockFindingId"] == str(ids["f_sast_mirror"])
    assert sqli["taxa"][0]["id"] == "89" and sqli["codeFlows"]
    cmdi = by_rule["python.cmdi"][0]
    assert cmdi["locations"][0]["physicalLocation"]["region"]["startLine"] == 7
    assert cmdi["taxa"][0]["id"] == "78"
    # false positive is excluded by default; mirrored finding not duplicated
    assert "python.xss" not in by_rule and len(by_rule["python.sqli"]) == 1
    # dependency vulns on recorded manifests; unreachable -> note
    qs = by_rule["GHSA-hrpp-h998-j3pp"][0]
    assert qs["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "web/package-lock.json"
    assert qs["level"] == "error" and qs["properties"]["reachability"] == "reachable"
    l4 = by_rule["GHSA-jfh8-c2jp-5v3q"][0]
    assert l4["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "pom.xml"
    assert l4["level"] == "note"
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    assert rules["GHSA-hrpp-h998-j3pp"]["properties"]["security-severity"] == "7.5"
    assert rules["GHSA-hrpp-h998-j3pp"]["helpUri"].startswith("https://osv.dev/")


async def test_sarif_options(client, db_pool):
    await _seed(db_pool)
    r = await client.get("/v1/export/sarif", params={"project": "acme/web", "include_sca": "false",
                                                     "include_suppressed": "true"})
    doc = r.json()
    assert_sarif(doc)
    rules = {res["ruleId"]: res for res in doc["runs"][0]["results"]}
    assert not any(k.startswith("GHSA") for k in rules)
    assert rules["python.xss"]["suppressions"][0]["status"] == "accepted"
    r = await client.get("/v1/export/sarif", params={"project": "acme/web", "min_severity": "critical"})
    assert {res["ruleId"] for res in r.json()["runs"][0]["results"]} == {"GHSA-jfh8-c2jp-5v3q"}
    r = await client.get("/v1/export/sarif", params={"project": "nope"})
    assert r.status_code == 404
    r = await client.get("/v1/export/sarif")      # all projects
    assert r.status_code == 200 and r.json()["runs"][0]["automationDetails"]["id"] == "paddock/all/"


# --------------------------------------------------------------------------- #
# SBOM + VEX
# --------------------------------------------------------------------------- #

async def test_sbom_cyclonedx_and_spdx(client, db_pool):
    ids = await _seed(db_pool)
    r = await client.get("/v1/export/sbom", params={"project": "acme/web"})
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/vnd.cyclonedx+json")
    cdx = r.json()
    assert_cyclonedx(cdx)
    assert {c["name"] for c in cdx["components"]} == {"express", "qs", "log4j-core"}
    deps = {d["ref"]: d["dependsOn"] for d in cdx["dependencies"]}
    assert deps["pkg:npm/express@4.18.2"] == ["pkg:npm/qs@6.11.0"]

    r = await client.get("/v1/export/sbom", params={"project": str(ids["project"]), "format": "spdx"})
    assert r.headers["content-type"].startswith("application/spdx+json")
    assert_spdx(r.json())
    assert len(r.json()["packages"]) == 4
    assert (await client.get("/v1/export/sbom", params={"project": "x"})).status_code == 404
    assert (await client.get("/v1/export/sbom", params={"project": "acme/web",
                                                        "format": "xml"})).status_code == 422


async def test_vex_cyclonedx_and_openvex(client, db_pool):
    await _seed(db_pool)
    r = await client.get("/v1/export/vex", params={"project": "acme/web"})
    doc = r.json()
    assert_cyclonedx(doc)
    st = {v["id"]: v["analysis"] for v in doc["vulnerabilities"]}
    assert st["CVE-2021-44228"]["state"] == "not_affected"
    assert st["CVE-2021-44228"]["justification"] == "code_not_reachable"
    assert st["CVE-2022-24999"]["state"] == "exploitable"
    assert st["GHSA-xxxx"]["state"] == "in_triage"

    r = await client.get("/v1/export/vex", params={"project": "acme/web", "format": "openvex"})
    ov = r.json()
    assert_openvex(ov)
    s = {x["vulnerability"]["name"]: x for x in ov["statements"]}
    assert s["CVE-2021-44228"]["status"] == "not_affected"
    assert s["CVE-2021-44228"]["justification"] == "vulnerable_code_not_in_execute_path"
    assert s["CVE-2022-24999"]["status"] == "affected"


# --------------------------------------------------------------------------- #
# Imports
# --------------------------------------------------------------------------- #

CDX_DOC = {
    "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
    "metadata": {"component": {"type": "application", "name": "shop", "bom-ref": "root"}},
    "components": [
        {"type": "library", "name": "express", "version": "4.18.2", "purl": "pkg:npm/express@4.18.2", "bom-ref": "e"},
        {"type": "library", "name": "qs", "version": "6.11.0", "purl": "pkg:npm/qs@6.11.0", "bom-ref": "q"},
    ],
    "dependencies": [{"ref": "root", "dependsOn": ["e"]}, {"ref": "e", "dependsOn": ["q"]}],
    "vulnerabilities": [{"id": "CVE-2022-24999", "ratings": [{"severity": "high", "score": 7.5}],
                         "affects": [{"ref": "q"}],
                         "analysis": {"state": "not_affected", "justification": "code_not_reachable"}}],
}


async def test_import_cyclonedx_roundtrip(client, db_pool):
    r = await client.post("/v1/import/sbom", content=json.dumps(CDX_DOC),
                          headers={"content-type": "application/vnd.cyclonedx+json"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["project"] == "shop" and body["format"] == "cyclonedx"
    assert body["components"] == 2 and body["vulnerabilities"] == 1 and body["ecosystems"] == ["npm"]
    out = (await client.get("/v1/export/sbom", params={"project": "shop"})).json()
    assert_cyclonedx(out)
    assert {(c["name"], c["version"]) for c in out["components"]} == {("express", "4.18.2"), ("qs", "6.11.0")}
    vex = (await client.get("/v1/export/vex", params={"project": "shop"})).json()
    assert vex["vulnerabilities"][0]["analysis"]["state"] == "not_affected"
    async with db_pool.acquire() as con:
        row = await con.fetchrow("SELECT direct, depth FROM sbom_components WHERE name = 'qs'")
        man = await con.fetchrow("SELECT kind, sha256, uploaded_by FROM sca_project_manifests")
    assert (row["direct"], row["depth"]) == (False, 1)
    assert man["kind"] == "cyclonedx" and len(man["sha256"]) == 64 and man["uploaded_by"] == "dev-admin"

    # re-import with a smaller SBOM and replace=true removes the stale component
    smaller = {**CDX_DOC, "components": CDX_DOC["components"][:1], "vulnerabilities": [],
               "dependencies": [{"ref": "root", "dependsOn": ["e"]}]}
    r = await client.post("/v1/import/sbom", params={"replace": "true"}, content=json.dumps(smaller))
    assert r.status_code == 201 and r.json()["removed"] == 1


async def test_import_spdx_with_explicit_project(client, db_pool):
    await _seed(db_pool)
    spdx = (await client.get("/v1/export/sbom", params={"project": "acme/web", "format": "spdx"})).json()
    r = await client.post("/v1/import/sbom", params={"project": "acme/web-copy"}, content=json.dumps(spdx))
    assert r.status_code == 201, r.text
    assert r.json()["components"] == 3 and r.json()["format"] == "spdx"
    async with db_pool.acquire() as con:
        n = await con.fetchval(
            "SELECT COUNT(*) FROM sbom_components c JOIN sca_projects p ON p.id = c.project_id "
            "WHERE p.name = 'acme/web-copy'")
    assert n == 3


async def test_import_rejections(client, monkeypatch):
    r = await client.post("/v1/import/sbom", content=b"{not json")
    assert r.status_code == 400
    r = await client.post("/v1/import/sbom", content=json.dumps({"hello": "world"}))
    assert r.status_code == 422
    r = await client.post("/v1/import/sbom", content=json.dumps({"bomFormat": "CycloneDX", "components": []}),
                          params={"project": "p"})
    assert r.status_code == 422
    nameless = {**CDX_DOC, "metadata": {}}
    r = await client.post("/v1/import/sbom", content=json.dumps(nameless))
    assert r.status_code == 422 and "project" in r.text
    r = await client.post("/v1/import/sbom", content=b"[" * 100_000 + b"]" * 100_000, params={"project": "p"})
    assert r.status_code in (400, 422)
    monkeypatch.setenv("PADDOCK_SBOM_IMPORT_MAX_BYTES", "2048")
    r = await client.post("/v1/import/sbom", content=json.dumps(CDX_DOC) + " " * 4096)
    assert r.status_code == 413


@pytest.fixture
def fake_sca(monkeypatch):
    calls = []
    real = httpx.AsyncClient
    state = {"status": 200, "project_id": None, "fail": False}

    def handler(request):
        calls.append(json.loads(request.content))
        if state["fail"]:
            raise httpx.ConnectError("refused", request=request)
        if state["status"] != 200:
            return httpx.Response(state["status"], json={"error": "boom"})
        return httpx.Response(200, json={"project": "acme/web", "project_id": state["project_id"],
                                         "components": 3, "vulnerable_components": 1})

    def factory(*a, **kw):
        kw["transport"] = httpx.MockTransport(handler)
        return real(*a, **kw)

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    return calls, state


async def test_import_lockfiles_proxies_to_sca_and_records_manifests(client, db_pool, fake_sca):
    calls, state = fake_sca
    ids = await _seed(db_pool)
    state["project_id"] = str(ids["project"])
    files = {"package-lock.json": "{}", "services/api/requirements.txt": "flask==2.0.0\n",
             "README.md": "# nope", "../etc/poetry.lock": "x"}
    r = await client.post("/v1/import/lockfiles", json={"project": "acme/web", "files": files,
                                                        "source_ref": "https://example.com/acme/web"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["files"] == ["package-lock.json", "services/api/requirements.txt"]
    assert set(body["ignored"]) == {"README.md", "../etc/poetry.lock"}
    assert calls[0]["project_name"] == "acme/web" and set(calls[0]["files"]) == set(body["files"])
    async with db_pool.acquire() as con:
        rows = await con.fetch("SELECT path, ecosystem FROM sca_project_manifests WHERE project_id = $1 "
                               "ORDER BY path", ids["project"])
    got = {r["path"]: r["ecosystem"] for r in rows}
    assert got["package-lock.json"] == "npm" and got["services/api/requirements.txt"] == "PyPI"
    # SARIF now places npm results on the shallowest npm lockfile
    doc = (await client.get("/v1/export/sarif", params={"project": "acme/web"})).json()
    qs = [x for x in doc["runs"][0]["results"] if x["ruleId"] == "GHSA-hrpp-h998-j3pp"][0]
    assert qs["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "package-lock.json"


async def test_import_lockfiles_errors(client, fake_sca):
    _calls, state = fake_sca
    r = await client.post("/v1/import/lockfiles", json={"project": "p", "files": {"README.md": "x"}})
    assert r.status_code == 422
    r = await client.post("/v1/import/lockfiles", json={"project": "", "files": {"yarn.lock": "x"}})
    assert r.status_code == 422
    r = await client.post("/v1/import/lockfiles", json={"project": "p", "files": {
        f"d{i}/yarn.lock": "x" for i in range(201)}})
    assert r.status_code == 422
    state["fail"] = True
    r = await client.post("/v1/import/lockfiles", json={"project": "p", "files": {"yarn.lock": "x"}})
    assert r.status_code == 503
    state["fail"], state["status"] = False, 500
    r = await client.post("/v1/import/lockfiles", json={"project": "p", "files": {"yarn.lock": "x"}})
    assert r.status_code == 502 and "boom" in r.text
