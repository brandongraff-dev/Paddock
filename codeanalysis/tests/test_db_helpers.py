from __future__ import annotations

import uuid

import pytest


async def _seed_project_with_vuln(db) -> tuple[str, str]:
    """Create a sca_project + component + vuln; return (project_name, vuln_id)."""
    name = f"ca-test-{uuid.uuid4().hex[:8]}"
    pid = await db.fetchval(
        "INSERT INTO sca_projects (name, ecosystems) VALUES ($1, $2::text[]) "
        "RETURNING id::text",
        name, ["Go"],
    )
    cid = await db.fetchval(
        "INSERT INTO sbom_components (project_id, ecosystem, name, version) "
        "VALUES ($1::uuid, 'Go', 'gopkg.in/yaml.v2', '2.2.1') RETURNING id::text",
        pid,
    )
    vid = await db.fetchval(
        "INSERT INTO sbom_component_vulns (component_id, osv_id, cve_id, severity, summary) "
        "VALUES ($1::uuid, 'GO-2022-0956', 'CVE-2022-28948', 'high', "
        "'DoS in Unmarshal') RETURNING id::text",
        cid,
    )
    return name, vid


@pytest.mark.asyncio
async def test_fetch_project_vulns_and_update_reachability(db):
    name, vid = await _seed_project_with_vuln(db)
    try:
        vulns = await db.fetch_project_vulns(name)
        assert len(vulns) == 1
        assert vulns[0]["name"] == "gopkg.in/yaml.v2"
        assert vulns[0]["reachability"] == "unknown"  # schema default

        ok = await db.update_reachability(
            vid, "reachable", "Unmarshal",
            ["main.go::<module>", "gopkg.in/yaml.v2.Unmarshal"],
        )
        assert ok is True

        again = await db.fetch_project_vulns(name)
        assert again[0]["reachability"] == "reachable"
        row = await db.fetchrow(
            "SELECT reachable_symbol, call_path FROM sbom_component_vulns WHERE id=$1::uuid",
            vid,
        )
        assert row["reachable_symbol"] == "Unmarshal"
        assert "gopkg.in/yaml.v2.Unmarshal" in row["call_path"]
    finally:
        await db.execute("DELETE FROM sca_projects WHERE name=$1", name)


@pytest.mark.asyncio
async def test_upsert_code_finding_is_idempotent(db):
    name, _ = await _seed_project_with_vuln(db)
    pid = await db.fetchval("SELECT id::text FROM sca_projects WHERE name=$1", name)
    try:
        kwargs = dict(
            project_id=pid, asset_id=None, engine="taint_fallback",
            rule="sql-injection", message="first", severity="high",
            file="app/views.py", start_line=12, end_line=12,
            source="request.args", sink="execute",
            dataflow=[{"step": "sink", "label": "execute", "line": 12}],
            cwe="CWE-89", metadata={"rule_class": "sql_injection"},
        )
        r1 = await db.upsert_code_finding(**kwargs)
        assert r1["inserted"] is True
        kwargs["message"] = "second"
        r2 = await db.upsert_code_finding(**kwargs)
        assert r2["inserted"] is False  # same (project, rule, file, line)
        assert r1["id"] == r2["id"]
        n = await db.fetchval(
            "SELECT COUNT(*) FROM code_findings WHERE project_id=$1::uuid", pid)
        assert n == 1
        stats = await db.stats()
        assert stats["code_findings"] >= 1
    finally:
        await db.execute("DELETE FROM sca_projects WHERE name=$1", name)
