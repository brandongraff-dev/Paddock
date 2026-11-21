"""Tier 3 endpoints: SCA/SBOM, supply-chain risk, ATT&CK mapping, LLM triage
clusters, the NL-query ("Ask") proxy, and the Neo4j graph proxy.

The SCA / correlation / brain / graphsync services own the writes, so we seed
`sca_projects`, `sbom_components`, `sbom_component_vulns`, `supply_chain_risks`,
`attack_technique_map`, `finding_techniques`, and `finding_clusters` directly
and exercise the orchestrator's read surface.

The two proxy endpoints (`/v1/ask`, `/v1/graph/*`) are driven against a dead
upstream port and must DEGRADE to the documented body -- never raise, never 5xx.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from app.config import settings

# A port nothing listens on: the proxy calls get ECONNREFUSED immediately and
# must degrade gracefully instead of propagating an exception.
_DEAD_URL = "http://127.0.0.1:59999"


# --------------------------------------------------------------------------- #
# Seed helpers
# --------------------------------------------------------------------------- #

async def _mk_asset(con, kind: str, value: str) -> str:
    return str(
        await con.fetchval(
            "INSERT INTO assets (kind, value, canonical, source) "
            "VALUES ($1,$2,$3,'seed') RETURNING id",
            kind,
            value,
            value.lower(),
        )
    )


async def _mk_finding(con, asset_id: str, severity: str, title: str) -> str:
    return str(
        await con.fetchval(
            "INSERT INTO findings (asset_id, rule_id, rule_source, severity, "
            "title, description) VALUES ($1,$2,'sca',$3,$4,'desc') RETURNING id",
            asset_id,
            f"rule-{title}",
            severity,
            title,
        )
    )


async def _mk_project(
    con,
    *,
    name: str,
    source_ref: str = "https://example.com/repo",
    ecosystems: list[str] | None = None,
    asset_id: str | None = None,
) -> str:
    return str(
        await con.fetchval(
            """
            INSERT INTO sca_projects (name, source_ref, ecosystems, asset_id)
            VALUES ($1, $2, $3::text[], $4)
            RETURNING id
            """,
            name,
            source_ref,
            ecosystems or [],
            asset_id,
        )
    )


async def _mk_component(
    con,
    *,
    project_id: str,
    ecosystem: str,
    name: str,
    version: str,
    direct: bool = True,
    depth: int = 0,
    purl: str | None = None,
    paths: list | None = None,
) -> str:
    return str(
        await con.fetchval(
            """
            INSERT INTO sbom_components
                (project_id, ecosystem, name, version, purl, direct, depth, paths)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb)
            RETURNING id
            """,
            project_id,
            ecosystem,
            name,
            version,
            purl,
            direct,
            depth,
            json.dumps(paths or []),
        )
    )


async def _mk_vuln(
    con,
    *,
    component_id: str,
    osv_id: str,
    severity: str,
    cve_id: str | None = None,
    cvss: float | None = None,
    fixed_version: str | None = None,
    summary: str | None = "vuln",
) -> str:
    return str(
        await con.fetchval(
            """
            INSERT INTO sbom_component_vulns
                (component_id, osv_id, cve_id, severity, cvss, summary, fixed_version)
            VALUES ($1,$2,$3,$4,$5,$6,$7)
            RETURNING id
            """,
            component_id,
            osv_id,
            cve_id,
            severity,
            cvss,
            summary,
            fixed_version,
        )
    )


async def _mk_risk(
    con,
    *,
    project_id: str,
    component_id: str | None,
    risk_type: str,
    severity: str,
    summary: str,
    detail: dict | None = None,
) -> str:
    return str(
        await con.fetchval(
            """
            INSERT INTO supply_chain_risks
                (project_id, component_id, risk_type, severity, summary, detail)
            VALUES ($1,$2,$3,$4,$5,$6::jsonb)
            RETURNING id
            """,
            project_id,
            component_id,
            risk_type,
            severity,
            summary,
            json.dumps(detail or {}),
        )
    )


async def _mk_technique(
    con,
    *,
    finding_id: str,
    technique_id: str,
    technique: str,
    tactic: str,
    cwe: str | None = None,
    confidence: int = 80,
) -> None:
    await con.execute(
        """
        INSERT INTO finding_techniques
            (finding_id, technique_id, technique, tactic, cwe, confidence)
        VALUES ($1,$2,$3,$4,$5,$6)
        """,
        finding_id,
        technique_id,
        technique,
        tactic,
        cwe,
        confidence,
    )


async def _mk_catalog(
    con,
    *,
    technique_id: str,
    technique: str,
    tactic: str,
    cwe: str | None = None,
    priority: int = 100,
    match: dict | None = None,
) -> None:
    await con.execute(
        """
        INSERT INTO attack_technique_map
            (match, technique_id, technique, tactic, cwe, priority)
        VALUES ($1::jsonb,$2,$3,$4,$5,$6)
        """,
        json.dumps(match or {}),
        technique_id,
        technique,
        tactic,
        cwe,
        priority,
    )


async def _mk_cluster(
    con,
    *,
    label: str,
    summary: str,
    severity: str,
    finding_ids: list[str],
    engine: str = "template",
    created_at: datetime | None = None,
) -> str:
    return str(
        await con.fetchval(
            """
            INSERT INTO finding_clusters
                (label, summary, severity, finding_ids, engine, created_at)
            VALUES ($1,$2,$3,$4::uuid[],$5,$6)
            RETURNING id
            """,
            label,
            summary,
            severity,
            finding_ids,
            engine,
            created_at or datetime.now(timezone.utc),
        )
    )


# --------------------------------------------------------------------------- #
# SCA / SBOM
# --------------------------------------------------------------------------- #

async def test_sbom_projects_list_with_counts(client, db_pool):
    async with db_pool.acquire() as con:
        pid = await _mk_project(con, name="webapp", ecosystems=["npm", "PyPI"])
        c1 = await _mk_component(con, project_id=pid, ecosystem="npm", name="lodash", version="4.17.20")
        c2 = await _mk_component(con, project_id=pid, ecosystem="PyPI", name="flask", version="2.0.0")
        await _mk_vuln(con, component_id=c1, osv_id="GHSA-aaaa", severity="high")
        await _mk_vuln(con, component_id=c1, osv_id="GHSA-bbbb", severity="low")
        await _mk_vuln(con, component_id=c2, osv_id="GHSA-cccc", severity="medium")

    r = await client.get("/v1/sbom/projects")
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body) == 1
    proj = body[0]
    assert proj["name"] == "webapp"
    assert sorted(proj["ecosystems"]) == ["PyPI", "npm"]
    assert proj["component_count"] == 2
    assert proj["vuln_count"] == 3


async def test_sbom_components_paged_shape_and_rollup(client, db_pool):
    async with db_pool.acquire() as con:
        pid = await _mk_project(con, name="webapp")
        c1 = await _mk_component(con, project_id=pid, ecosystem="npm", name="lodash", version="4.17.20")
        await _mk_component(con, project_id=pid, ecosystem="npm", name="clean-pkg", version="1.0.0")
        await _mk_vuln(con, component_id=c1, osv_id="GHSA-aaaa", severity="low")
        await _mk_vuln(con, component_id=c1, osv_id="GHSA-bbbb", severity="high")

    r = await client.get("/v1/sbom/components", params={"limit": 50, "offset": 0})
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body.keys()) == {"items", "total", "limit", "offset"}
    assert body["total"] == 2
    assert body["limit"] == 50 and body["offset"] == 0
    by_name = {c["name"]: c for c in body["items"]}
    # Rolled-up vuln count + highest severity, no N+1.
    assert by_name["lodash"]["vuln_count"] == 2
    assert by_name["lodash"]["max_vuln_severity"] == "high"
    assert by_name["clean-pkg"]["vuln_count"] == 0
    assert by_name["clean-pkg"]["max_vuln_severity"] is None


async def test_sbom_components_filter_vulnerable(client, db_pool):
    async with db_pool.acquire() as con:
        pid = await _mk_project(con, name="webapp")
        c1 = await _mk_component(con, project_id=pid, ecosystem="npm", name="vuln-pkg", version="1.0.0")
        await _mk_component(con, project_id=pid, ecosystem="npm", name="clean-pkg", version="1.0.0")
        await _mk_vuln(con, component_id=c1, osv_id="GHSA-aaaa", severity="critical")

    r = await client.get("/v1/sbom/components", params={"vulnerable": "true"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 1
    assert [c["name"] for c in body["items"]] == ["vuln-pkg"]

    r2 = await client.get("/v1/sbom/components", params={"vulnerable": "false"})
    assert r2.status_code == 200, r2.text
    body2 = r2.json()
    assert body2["total"] == 1
    assert [c["name"] for c in body2["items"]] == ["clean-pkg"]


async def test_sbom_components_filter_ecosystem_and_project(client, db_pool):
    async with db_pool.acquire() as con:
        pid1 = await _mk_project(con, name="proj-one")
        pid2 = await _mk_project(con, name="proj-two")
        await _mk_component(con, project_id=pid1, ecosystem="npm", name="a", version="1")
        await _mk_component(con, project_id=pid1, ecosystem="PyPI", name="b", version="1")
        await _mk_component(con, project_id=pid2, ecosystem="npm", name="c", version="1")

    r = await client.get("/v1/sbom/components", params={"ecosystem": "npm"})
    assert r.status_code == 200, r.text
    assert r.json()["total"] == 2

    # project filter by uuid
    r2 = await client.get("/v1/sbom/components", params={"project": pid1})
    assert r2.status_code == 200, r2.text
    assert r2.json()["total"] == 2

    # project filter by name
    r3 = await client.get("/v1/sbom/components", params={"project": "proj-two"})
    assert r3.status_code == 200, r3.text
    assert r3.json()["total"] == 1
    assert r3.json()["items"][0]["name"] == "c"


async def test_sbom_component_detail_with_vulns(client, db_pool):
    async with db_pool.acquire() as con:
        pid = await _mk_project(con, name="webapp")
        cid = await _mk_component(
            con, project_id=pid, ecosystem="npm", name="lodash",
            version="4.17.20", purl="pkg:npm/lodash@4.17.20",
        )
        await _mk_vuln(
            con, component_id=cid, osv_id="GHSA-high", severity="high",
            cve_id="CVE-2021-23337", cvss=7.2, fixed_version="4.17.21",
        )
        await _mk_vuln(con, component_id=cid, osv_id="GHSA-low", severity="low")

    r = await client.get(f"/v1/sbom/components/{cid}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["component"]["name"] == "lodash"
    assert body["component"]["vuln_count"] == 2
    assert body["component"]["max_vuln_severity"] == "high"
    assert len(body["vulns"]) == 2
    # highest severity listed first
    assert body["vulns"][0]["severity"] == "high"
    assert body["vulns"][0]["cve_id"] == "CVE-2021-23337"
    assert body["vulns"][0]["fixed_version"] == "4.17.21"
    assert abs(body["vulns"][0]["cvss"] - 7.2) < 1e-6


async def test_sbom_component_detail_404(client, db_pool):
    import uuid

    r = await client.get(f"/v1/sbom/components/{uuid.uuid4()}")
    assert r.status_code == 404


async def test_sbom_summary_shape(client, db_pool):
    async with db_pool.acquire() as con:
        pid = await _mk_project(con, name="webapp")
        c1 = await _mk_component(con, project_id=pid, ecosystem="npm", name="a", version="1")
        c2 = await _mk_component(con, project_id=pid, ecosystem="npm", name="b", version="1")
        await _mk_component(con, project_id=pid, ecosystem="npm", name="clean", version="1")
        await _mk_vuln(con, component_id=c1, osv_id="GHSA-1", severity="high")
        await _mk_vuln(con, component_id=c1, osv_id="GHSA-2", severity="low")
        await _mk_vuln(con, component_id=c2, osv_id="GHSA-3", severity="high")
        await _mk_risk(con, project_id=pid, component_id=c1, risk_type="typosquat",
                       severity="high", summary="looks like 'a'")
        await _mk_risk(con, project_id=pid, component_id=c2, risk_type="unpinned",
                       severity="low", summary="range not pinned")
        await _mk_risk(con, project_id=pid, component_id=None, risk_type="typosquat",
                       severity="medium", summary="another typosquat")

    r = await client.get("/v1/sbom/summary")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["components"] == 3
    assert body["vulnerable_components"] == 2
    assert body["by_risk_type"] == {"typosquat": 2, "unpinned": 1}
    # vuln severities, zero-filled across buckets
    assert body["by_severity"]["high"] == 2
    assert body["by_severity"]["low"] == 1
    assert body["by_severity"]["critical"] == 0


# --------------------------------------------------------------------------- #
# Supply-chain risks
# --------------------------------------------------------------------------- #

async def test_supply_chain_risks_paged_and_enriched(client, db_pool):
    async with db_pool.acquire() as con:
        pid = await _mk_project(con, name="webapp")
        cid = await _mk_component(con, project_id=pid, ecosystem="npm", name="evil-pkg", version="1")
        await _mk_risk(con, project_id=pid, component_id=cid, risk_type="dependency_confusion",
                       severity="critical", summary="internal name claimable publicly")

    r = await client.get("/v1/supply-chain-risks")
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body.keys()) == {"items", "total", "limit", "offset"}
    assert body["total"] == 1
    item = body["items"][0]
    assert item["risk_type"] == "dependency_confusion"
    assert item["severity"] == "critical"
    assert item["component_name"] == "evil-pkg"
    assert item["component_ecosystem"] == "npm"
    assert item["project_name"] == "webapp"


async def test_supply_chain_risks_filter_type(client, db_pool):
    async with db_pool.acquire() as con:
        pid = await _mk_project(con, name="webapp")
        cid = await _mk_component(con, project_id=pid, ecosystem="npm", name="p", version="1")
        await _mk_risk(con, project_id=pid, component_id=cid, risk_type="typosquat",
                       severity="high", summary="typo")
        await _mk_risk(con, project_id=pid, component_id=cid, risk_type="abandoned",
                       severity="low", summary="old")

    r = await client.get("/v1/supply-chain-risks", params={"type": "typosquat"})
    assert r.status_code == 200, r.text
    assert r.json()["total"] == 1
    assert r.json()["items"][0]["risk_type"] == "typosquat"


async def test_supply_chain_risks_filter_severity(client, db_pool):
    async with db_pool.acquire() as con:
        pid = await _mk_project(con, name="webapp")
        cid = await _mk_component(con, project_id=pid, ecosystem="npm", name="p", version="1")
        await _mk_risk(con, project_id=pid, component_id=cid, risk_type="typosquat",
                       severity="high", summary="typo")
        await _mk_risk(con, project_id=pid, component_id=cid, risk_type="unpinned",
                       severity="low", summary="range")

    r = await client.get("/v1/supply-chain-risks", params={"severity": "low"})
    assert r.status_code == 200, r.text
    assert r.json()["total"] == 1
    assert r.json()["items"][0]["severity"] == "low"


# --------------------------------------------------------------------------- #
# ATT&CK
# --------------------------------------------------------------------------- #

async def test_attack_coverage_aggregation(client, db_pool):
    async with db_pool.acquire() as con:
        aid = await _mk_asset(con, "endpoint", "https://app.example.com/a")
        f_a = await _mk_finding(con, aid, "high", "exposed-a")
        f_b = await _mk_finding(con, aid, "medium", "exposed-b")
        # finding A: two techniques in Initial Access + one in Reconnaissance
        await _mk_technique(con, finding_id=f_a, technique_id="T1190",
                            technique="Exploit Public-Facing Application",
                            tactic="Initial Access", cwe="CWE-22")
        await _mk_technique(con, finding_id=f_a, technique_id="T1133",
                            technique="External Remote Services",
                            tactic="Initial Access")
        await _mk_technique(con, finding_id=f_a, technique_id="T1595",
                            technique="Active Scanning", tactic="Reconnaissance")
        # finding B: one technique in Initial Access (shared T1190)
        await _mk_technique(con, finding_id=f_b, technique_id="T1190",
                            technique="Exploit Public-Facing Application",
                            tactic="Initial Access", cwe="CWE-22")

    r = await client.get("/v1/attack/coverage")
    assert r.status_code == 200, r.text
    body = r.json()
    # distinct findings mapped overall
    assert body["total_findings_mapped"] == 2
    # per-technique DISTINCT finding counts
    by_tech = {t["technique_id"]: t for t in body["by_technique"]}
    assert by_tech["T1190"]["count"] == 2
    assert by_tech["T1133"]["count"] == 1
    assert by_tech["T1595"]["count"] == 1
    assert by_tech["T1190"]["tactic"] == "Initial Access"
    # per-tactic DISTINCT finding counts (A+B in Initial Access = 2, counted once each)
    assert body["by_tactic"]["Initial Access"] == 2
    assert body["by_tactic"]["Reconnaissance"] == 1


async def test_attack_catalog(client, db_pool):
    async with db_pool.acquire() as con:
        await _mk_catalog(con, technique_id="T1190", technique="Exploit Public-Facing Application",
                          tactic="Initial Access", cwe="CWE-22", priority=10,
                          match={"rule_source": "exposed_file"})
        await _mk_catalog(con, technique_id="T1552", technique="Unsecured Credentials",
                          tactic="Credential Access", cwe="CWE-798", priority=20)

    r = await client.get("/v1/attack/catalog")
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body) == 2
    # priority ascending
    assert body[0]["technique_id"] == "T1190"
    assert body[0]["match"] == {"rule_source": "exposed_file"}
    assert body[1]["cwe"] == "CWE-798"


async def test_finding_techniques(client, db_pool):
    async with db_pool.acquire() as con:
        aid = await _mk_asset(con, "endpoint", "https://app.example.com/x")
        fid = await _mk_finding(con, aid, "high", "exposed")
        await _mk_technique(con, finding_id=fid, technique_id="T1190",
                            technique="Exploit Public-Facing Application",
                            tactic="Initial Access", cwe="CWE-22", confidence=90)
        await _mk_technique(con, finding_id=fid, technique_id="T1595",
                            technique="Active Scanning", tactic="Reconnaissance",
                            confidence=60)

    r = await client.get(f"/v1/findings/{fid}/techniques")
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body) == 2
    # highest confidence first
    assert body[0]["technique_id"] == "T1190"
    assert body[0]["confidence"] == 90
    assert body[0]["cwe"] == "CWE-22"
    assert body[0]["finding_id"] == fid


# --------------------------------------------------------------------------- #
# Clusters
# --------------------------------------------------------------------------- #

async def test_clusters_newest_first(client, db_pool):
    now = datetime.now(timezone.utc)
    async with db_pool.acquire() as con:
        aid = await _mk_asset(con, "endpoint", "https://app.example.com/c")
        f1 = await _mk_finding(con, aid, "high", "f1")
        f2 = await _mk_finding(con, aid, "low", "f2")
        await _mk_cluster(con, label="older", summary="s", severity="low",
                          finding_ids=[f2], engine="template",
                          created_at=now - timedelta(hours=2))
        await _mk_cluster(con, label="newer", summary="s", severity="high",
                          finding_ids=[f1], engine="llm",
                          created_at=now - timedelta(minutes=5))

    r = await client.get("/v1/clusters")
    assert r.status_code == 200, r.text
    body = r.json()
    assert [c["label"] for c in body] == ["newer", "older"]
    assert body[0]["engine"] == "llm"
    assert body[0]["finding_ids"] == [f1]

    # engine filter
    r2 = await client.get("/v1/clusters", params={"engine": "llm"})
    assert r2.status_code == 200
    assert [c["label"] for c in r2.json()] == ["newer"]


# --------------------------------------------------------------------------- #
# Ask proxy -- degrade when brain is down
# --------------------------------------------------------------------------- #

async def test_ask_degrades_when_brain_down(client, monkeypatch):
    monkeypatch.setattr(settings, "brain_url", _DEAD_URL)
    r = await client.post("/v1/ask", json={"question": "how many critical findings?"})
    # Never a 5xx: degrade cleanly.
    assert r.status_code == 200, r.text
    assert r.json() == {
        "ok": False,
        "engine": "unavailable",
        "note": "brain service not reachable",
    }


async def test_ask_validates_empty_question(client):
    r = await client.post("/v1/ask", json={"question": ""})
    assert r.status_code == 422


# --------------------------------------------------------------------------- #
# Graph proxy -- degrade when graphsync is down
# --------------------------------------------------------------------------- #

async def test_graph_paths_degrades_when_graphsync_down(client, monkeypatch):
    monkeypatch.setattr(settings, "graphsync_url", _DEAD_URL)
    r = await client.get("/v1/graph/paths", params={"source": "a", "target": "b"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["available"] is False
    assert "reason" in body and body["reason"]


async def test_graph_neighborhood_degrades_when_graphsync_down(client, monkeypatch):
    import uuid

    monkeypatch.setattr(settings, "graphsync_url", _DEAD_URL)
    r = await client.get(f"/v1/graph/neighborhood/{uuid.uuid4()}", params={"depth": 2})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["available"] is False
    assert "reason" in body and body["reason"]
