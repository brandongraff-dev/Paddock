"""DB round-trip tests. Skip cleanly without TEST_DATABASE_URL / DATABASE_URL
(mirrors intel / changewatch). These exercise the SCA table writers end-to-end.
"""
from __future__ import annotations

import uuid

import pytest

from app.db import Database

# Share the session loop with the session-scoped `db` pool fixture.
pytestmark = pytest.mark.asyncio(loop_scope="session")


async def _fresh_project(db: Database, name: str):
    return await db.upsert_project(name, "https://example/repo", ["npm"], asset_id=None)


async def test_upsert_project_idempotent(db: Database):
    name = f"proj-{uuid.uuid4().hex[:8]}"
    p1 = await _fresh_project(db, name)
    p2 = await _fresh_project(db, name)
    assert p1["id"] == p2["id"]  # UNIQUE(name) -> same row
    assert p1["name"] == name


async def test_component_vuln_risk_roundtrip(db: Database):
    name = f"proj-{uuid.uuid4().hex[:8]}"
    project = await _fresh_project(db, name)
    pid = project["id"]
    comp = await db.upsert_component(pid, {
        "ecosystem": "npm", "name": "demo-lib", "version": "1.0.0",
        "direct": True, "depth": 0, "paths": ["root"], "metadata": {},
    })
    assert comp["name"] == "demo-lib"
    # upserting again is idempotent on (project, eco, name, version)
    comp2 = await db.upsert_component(pid, {
        "ecosystem": "npm", "name": "demo-lib", "version": "1.0.0",
        "direct": False, "depth": 5, "paths": [], "metadata": {},
    })
    assert comp2["id"] == comp["id"]

    inserted = await db.upsert_vuln(comp["id"], {
        "osv_id": "GHSA-x", "cve_id": "CVE-2023-9999", "severity": "critical",
        "cvss": 9.8, "summary": "x", "fixed_version": "1.2.3", "refs": [],
    })
    assert inserted is True
    # second time -> update, not insert
    assert await db.upsert_vuln(comp["id"], {
        "osv_id": "GHSA-x", "severity": "high", "cvss": 7.0, "refs": [],
    }) is False

    r_ins = await db.upsert_risk(pid, comp["id"], {
        "risk_type": "typosquat", "severity": "medium",
        "summary": "looks like request", "detail": {"resembles": "request"},
    })
    assert r_ins is True
    # dedupe via UNIQUE(project, component, risk_type)
    assert await db.upsert_risk(pid, comp["id"], {
        "risk_type": "typosquat", "severity": "high", "summary": "x", "detail": {},
    }) is False

    stats = await db.stats()
    assert stats["components"] >= 1
    assert stats["vulnerable_components"] >= 1
    assert "typosquat" in stats["risks_by_type"]
