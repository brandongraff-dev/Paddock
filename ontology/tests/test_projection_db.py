"""DB-backed projection test (skipped without TEST_DATABASE_URL).

Seeds a small, representative slice of the raw tables, runs a full projection
pass, and asserts the resulting objects/links -- plus idempotency and pruning.
"""
from __future__ import annotations

import json

import pytest

pytestmark = pytest.mark.asyncio


async def _seed(con) -> dict[str, str]:
    """Seed assets/edges/findings/paths/tickets/sbom; return key ids."""
    sub = await con.fetchval(
        "INSERT INTO assets (kind,value,canonical,source,classification) "
        "VALUES ('subdomain','api.example.com','api.example.com','dns','confidential') RETURNING id"
    )
    ip = await con.fetchval(
        "INSERT INTO assets (kind,value,canonical,source) "
        "VALUES ('ipv4','10.0.0.5','10.0.0.5','dns') RETURNING id"
    )
    port = await con.fetchval(
        "INSERT INTO assets (kind,value,canonical,source,metadata) "
        "VALUES ('port','tcp/443','10.0.0.5:443','scan','{\"port\":\"443\"}') RETURNING id"
    )
    cert = await con.fetchval(
        "INSERT INTO assets (kind,value,canonical,source) "
        "VALUES ('certificate','CN=api.example.com','cn=api.example.com','ct') RETURNING id"
    )
    repo = await con.fetchval(
        "INSERT INTO assets (kind,value,canonical,source) "
        "VALUES ('repository','github.com/acme/app','github.com/acme/app','vcs') RETURNING id"
    )
    secret = await con.fetchval(
        "INSERT INTO assets (kind,value,canonical,source) "
        "VALUES ('secret_candidate','AKIA...','akia-leak','gitleaks') RETURNING id"
    )
    # edges
    await con.execute(
        "INSERT INTO asset_edges (src_id,dst_id,kind) VALUES "
        "($1,$2,'resolves_to'),($3,$2,'hosts'),($4,$1,'issued_for'),($5,$6,'contains')",
        sub, ip, port, cert, repo, secret,
    )
    # finding on the host
    fid = await con.fetchval(
        "INSERT INTO findings (asset_id,rule_id,rule_source,severity,title,description,cvss) "
        "VALUES ($1,'CVE-2021-1','cve_match','high','RCE','desc',9.8) RETURNING id",
        sub,
    )
    # ticket tracking the finding, owned by a team
    await con.execute(
        "INSERT INTO tickets (finding_id,title,severity,owner_team,status) "
        "VALUES ($1,'Fix RCE','high','platform','open')",
        fid,
    )
    # attack path through the host
    await con.execute(
        "INSERT INTO attack_paths (source_asset_id,target_asset_id,hops,length,"
        "total_cost,exploitability,severity,title,fingerprint) "
        "VALUES ($1,$2,$3::jsonb,2,1.0,80.0,'critical','edge->crown','fp-1')",
        sub, ip, json.dumps([{"asset_id": str(sub)}, {"asset_id": str(ip)}]),
    )
    # sbom project bound to the repository asset + a component
    proj = await con.fetchval(
        "INSERT INTO sca_projects (name,asset_id) VALUES ('acme/app',$1) RETURNING id",
        repo,
    )
    await con.execute(
        "INSERT INTO sbom_components (project_id,ecosystem,name,version,direct,depth) "
        "VALUES ($1,'npm','left-pad','1.0.0',true,0)",
        proj,
    )
    return {"sub": str(sub), "ip": str(ip), "fid": str(fid), "repo": str(repo)}


async def test_full_projection(db):
    async with db.acquire() as con:
        await _seed(con)

    res = await db.project()
    assert res["objects"] > 0
    assert res["links"] > 0

    stats = await db.stats()
    by_type = stats["objects_by_type"]
    # Representative objects of each key type exist.
    for t in ("Host", "Service", "Certificate", "Repository", "Secret",
              "Vulnerability", "Package", "Ticket", "Team", "AttackPath"):
        assert by_type.get(t, 0) >= 1, (t, by_type)

    links = stats["links_by_type"]
    for lt in ("RESOLVES_TO", "RUNS", "SECURES", "CONTAINS", "AFFECTS",
               "ON_PATH", "OWNED_BY", "TRACKS", "DECLARES"):
        assert links.get(lt, 0) >= 1, (lt, links)

    # Host carried its source classification through.
    async with db.acquire() as con:
        clazz = await con.fetchval(
            "SELECT classification FROM ontology_objects "
            "WHERE object_type='Host' AND title='api.example.com'"
        )
    assert clazz == "confidential"


async def test_projection_is_idempotent(db):
    async with db.acquire() as con:
        await _seed(con)
    first = await db.project()
    second = await db.project()
    assert first["objects"] == second["objects"]
    assert first["links"] == second["links"]
    assert second["pruned_objects"] == 0
    assert second["pruned_links"] == 0


async def test_projection_prunes_vanished_rows(db):
    async with db.acquire() as con:
        await _seed(con)
    await db.project()
    # Delete the finding -> its Vulnerability object (+ AFFECTS/TRACKS) go away.
    async with db.acquire() as con:
        await con.execute("DELETE FROM findings")
    res = await db.project()
    assert res["pruned_objects"] >= 1
    stats = await db.stats()
    assert stats["objects_by_type"].get("Vulnerability", 0) == 0
