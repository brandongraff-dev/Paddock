"""Tenant isolation for ontology projection against real Postgres RLS
(``paddock_svc_ontology``)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
import pytest_asyncio

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import tenant_testkit as kit  # noqa: E402

from app import config as config_module  # noqa: E402
from app import tenancy  # noqa: E402
from app.db import Database  # noqa: E402
from app.main import OntologyService  # noqa: E402

ROLE = "paddock_svc_ontology"
pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def env():
    tdb = await kit.make_db(roles=(ROLE,))
    svc = OntologyService(config_module.load())
    svc.db = Database(tdb.role_dsn(ROLE))
    await svc.db.connect()
    a = await kit.seed_asset(tdb, kit.TENANT_A, "a.example.com", kind="subdomain")
    b = await kit.seed_asset(tdb, kit.TENANT_B, "b.example.com", kind="subdomain")
    await kit.seed_finding(tdb, kit.TENANT_A, a)
    await kit.seed_finding(tdb, kit.TENANT_B, b)
    try:
        yield tdb, svc, a, b
    finally:
        await svc.db.close()
        await tdb.drop()


async def _objects(tdb) -> dict[str, set[str]]:
    rows = await tdb.raw("SELECT tenant_id::text, backing_id::text FROM ontology_objects")
    out: dict[str, set[str]] = {}
    for tid, bid in rows:
        out.setdefault(tid, set()).add(bid)
    return out


async def test_least_privilege_role(env):
    _, svc, *_ = env
    info = await tenancy.check_role(svc.db.pool, require=True)
    assert info["role"] == ROLE and not info["superuser"] and not info["bypassrls"]


async def test_projection_for_a_never_reads_or_writes_b_and_prune_is_scoped(env):
    tdb, svc, a, b = env
    with tenancy.tenant_context(kit.TENANT_A):
        await svc.project()
    with tenancy.tenant_context(kit.TENANT_B):
        await svc.project()
    objs = await _objects(tdb)
    assert a in objs[kit.TENANT_A] and b not in objs[kit.TENANT_A]
    assert b in objs[kit.TENANT_B] and a not in objs[kit.TENANT_B]
    # A's asset disappears -> A's next pass prunes A's object only
    await tdb.raw("DELETE FROM findings WHERE tenant_id = $1", kit.TENANT_A)
    await tdb.raw("DELETE FROM assets WHERE tenant_id = $1", kit.TENANT_A)
    with tenancy.tenant_context(kit.TENANT_A):
        await svc.project()
    objs = await _objects(tdb)
    assert not objs.get(kit.TENANT_A)
    assert b in objs[kit.TENANT_B]  # untouched by A's prune


async def test_scheduled_projection_covers_every_tenant(env):
    tdb, svc, a, b = env
    res = await svc.project_scoped()
    assert res["failed"] == 0 and res["tenants"] >= 2
    objs = await _objects(tdb)
    assert a in objs[kit.TENANT_A] and b in objs[kit.TENANT_B]


async def test_type_catalogue_is_global_and_platform_written(env):
    tdb, svc, *_ = env
    with tenancy.tenant_context(kit.TENANT_A):
        await svc.db.seed_types()  # writes via the platform context, whoever called
        async with svc.db.acquire() as con:
            assert await con.fetchval("SELECT count(*) FROM ontology_object_types") > 0
        async with svc.db.acquire() as con:
            await kit.expect_denied(con.execute(
                "INSERT INTO ontology_object_types (name, display) VALUES ('Evil','x')"),
                what="tenant write to the type catalogue")
    with tenancy.tenant_context(kit.TENANT_B):
        async with svc.db.acquire() as con:
            assert await con.fetchval("SELECT count(*) FROM ontology_object_types") > 0
