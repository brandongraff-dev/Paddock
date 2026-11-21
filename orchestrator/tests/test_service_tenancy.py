"""Tenancy for the compute services and workers, orchestrator side.

* every stream event and queued job carries ``tenant_id``;
* a worker callback must belong to the tenant of the job it answers
  (``X-Paddock-Tenant`` + ``X-Paddock-Scan`` are verified; a mismatch is a 409);
* the shared service key cannot act without naming a tenant under
  TENANCY_STRICT, and its tenant selection is audited;
* schema/029: service roles exist, are unprivileged, and hold every grant the
  service source code needs; the migration is order-independent;
* ``provision-roles`` gives the roles LOGIN + passwords.
"""
from __future__ import annotations

import json
import re
import sys
import uuid
from pathlib import Path

import asyncpg
import pytest

from app import job_binding, queue, tenancy
from app.config import settings

from .test_tenancy import TENANT_A, TENANT_B, _h, enforce, tenants  # noqa: F401  (fixtures)

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
SVC_KEY = "svc-test-key-123"


@pytest.fixture
def svc_key(monkeypatch):
    monkeypatch.setattr(settings, "service_api_key", SVC_KEY)
    job_binding.reset_cache()
    return {"X-API-Key": SVC_KEY}


async def _scan_as(client, key, target):
    r = await client.post("/v1/scans", headers=_h(key), json={"kind": "passive_subdomains", "target": target})
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def test_every_published_event_carries_its_tenant(tenants, fake_redis):  # noqa: F811
    entries = await fake_redis.xrange("stream:events")
    assert entries
    tids = set()
    for _id, fields in entries:
        ev = json.loads(fields["event"])
        assert ev.get("tenant_id"), ev
        tids.add(ev["tenant_id"])
    assert tids == {TENANT_A, TENANT_B}


async def test_enqueue_refuses_a_job_without_a_tenant(fake_redis, monkeypatch):
    monkeypatch.setattr(settings, "tenancy_strict", True)
    with pytest.raises(RuntimeError):
        await queue.enqueue_scan(fake_redis, {"kind": "passive_dns", "scan_id": "x"})
    with tenancy.tenant_context(TENANT_B):
        await queue.enqueue_scan(fake_redis, {"kind": "passive_dns", "scan_id": "x"})
    job = json.loads((await fake_redis.xrange("queue:passive"))[-1][1]["job"])
    assert job["tenant_id"] == TENANT_B


async def test_worker_result_for_the_right_tenant_is_accepted(tenants, client, svc_key):  # noqa: F811
    key_b, _ = tenants["b"]
    sid = await _scan_as(client, key_b, "bravo-only.example")
    hdr = {**svc_key, "X-Paddock-Tenant": TENANT_B, job_binding.SCAN_HEADER: sid}
    r = await client.patch(f"/v1/scans/{sid}", headers=hdr, json={"status": "running", "worker_id": "w1"})
    assert r.status_code == 200, r.text
    r = await client.post(f"/v1/scans/{sid}/complete", headers=hdr, json={"result_summary": {"n": 1}})
    assert r.status_code == 200, r.text


async def test_worker_result_with_a_mismatched_tenant_is_rejected(tenants, client, svc_key, db_pool):  # noqa: F811
    key_a, _ = tenants["a"]
    key_b, _ = tenants["b"]
    sid_b = await _scan_as(client, key_b, "bravo-only.example")
    # A worker holding B's job reports it as tenant A (or the reverse): 409, nothing changes.
    for claimed in (TENANT_A, str(uuid.UUID(int=0))):
        hdr = {**svc_key, "X-Paddock-Tenant": claimed, job_binding.SCAN_HEADER: sid_b}
        r = await client.patch(f"/v1/scans/{sid_b}", headers=hdr, json={"status": "completed"})
        assert r.status_code in (401, 409), r.text  # unknown tenant -> 401, wrong tenant -> 409
    hdr = {**svc_key, "X-Paddock-Tenant": TENANT_A, job_binding.SCAN_HEADER: sid_b}
    r = await client.patch(f"/v1/scans/{sid_b}", headers=hdr, json={"status": "completed"})
    assert r.status_code == 409 and "job_tenant_mismatch" in r.text
    # a callback whose echoed job differs from the scan in the URL is also refused
    sid_a = await _scan_as(client, key_a, "alpha-only.example")
    hdr = {**svc_key, "X-Paddock-Tenant": TENANT_A, job_binding.SCAN_HEADER: sid_a}
    r = await client.patch(f"/v1/scans/{sid_b}", headers=hdr, json={"status": "completed"})
    assert r.status_code == 409
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT status FROM scans WHERE id = $1::uuid", sid_b) == "queued"


async def test_service_key_must_name_a_tenant_in_strict_mode_and_its_use_is_audited(
        tenants, client, svc_key, monkeypatch, db_pool):  # noqa: F811
    monkeypatch.setattr(settings, "tenancy_strict", True)
    assert (await client.get("/v1/scope", headers=svc_key)).status_code == 401  # no header
    assert (await client.get("/v1/scope", headers={**svc_key, "X-Paddock-Tenant": str(uuid.uuid4())})).status_code == 401
    r = await client.post("/v1/assets/bulk", headers={**svc_key, "X-Paddock-Tenant": TENANT_B},
                          json={"items": [{"kind": "domain", "value": "svc-added.example", "source": "worker"}]})
    assert r.status_code in (200, 201), r.text
    async with db_pool.acquire() as con:
        rows = await con.fetch(
            "SELECT tenant_id::text AS t, details FROM audit_log WHERE details->>'via' = 'service_key'")
    assert rows and {r["t"] for r in rows} == {TENANT_B}
    assert all(json.loads(r["details"])["acting_tenant"] == TENANT_B for r in rows)


async def test_suspended_tenant_cannot_be_selected_by_the_service_key(tenants, client, svc_key, db_pool):  # noqa: F811
    async with db_pool.acquire() as con:
        await con.execute("UPDATE tenants SET status = 'suspended' WHERE id = $1::uuid", TENANT_B)
    r = await client.get("/v1/scope", headers={**svc_key, "X-Paddock-Tenant": TENANT_B})
    assert r.status_code == 401


# --------------------------------------------------------------------------- #
# Roles + grants (schema/029)
# --------------------------------------------------------------------------- #

async def test_service_roles_are_unprivileged_and_cannot_touch_secrets(db_pool):
    for name in tenancy.SERVICE_ROLE_NAMES:
        role = f"paddock_svc_{name}"
        r = await db_pool.fetchrow(
            "SELECT rolsuper, rolbypassrls, rolcreatedb, rolcreaterole, rolcanlogin FROM pg_roles WHERE rolname=$1",
            role)
        assert r is not None, role
        assert not (r["rolsuper"] or r["rolbypassrls"] or r["rolcreatedb"] or r["rolcreaterole"]), role
        for tbl in ("audit_log", "app_users", "api_keys", "integrations", "scim_tokens", "fleet_agents"):
            if await db_pool.fetchval("SELECT to_regclass($1) IS NOT NULL", tbl):
                for priv in ("SELECT", "INSERT", "UPDATE", "DELETE"):
                    assert not await db_pool.fetchval(
                        "SELECT has_table_privilege($1, $2, $3)", role, tbl, priv), (role, tbl, priv)


_TBL = r"([a-z_][a-z0-9_]*)"
_WRITE = re.compile(r"(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+" + _TBL, re.I)
_READ = re.compile(r"(?:FROM|JOIN)\s+" + _TBL, re.I)


async def test_service_roles_hold_the_grants_their_source_needs(db_pool):
    """Every real table a service's SQL names must be readable (and, for
    INSERT/UPDATE/DELETE targets, writable) by that service's role."""
    tables = {r[0] for r in await db_pool.fetch(
        "SELECT relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
        "WHERE n.nspname='public' AND c.relkind IN ('r','v','p')")}
    problems = []
    for name in tenancy.SERVICE_ROLE_NAMES:
        role = f"paddock_svc_{name}"
        for py in (ROOT / name / "app").rglob("*.py"):
            if py.name == "tenancy.py":
                continue
            src = py.read_text()
            for m in _WRITE.finditer(src):
                t = m.group(1).lower()
                if t in tables and not await db_pool.fetchval(
                        "SELECT has_table_privilege($1,$2,'INSERT') AND has_table_privilege($1,$2,'UPDATE')", role, t):
                    # global catalogues are append-only for roles that only seed them
                    if not await db_pool.fetchval("SELECT has_table_privilege($1,$2,'UPDATE')", role, t):
                        problems.append((role, "write", t, py.name))
            for m in _READ.finditer(src):
                t = m.group(1).lower()
                if t in tables and not await db_pool.fetchval("SELECT has_table_privilege($1,$2,'SELECT')", role, t):
                    problems.append((role, "read", t, py.name))
    assert not problems, problems


async def test_migration_029_is_idempotent_and_order_independent(db_pool):
    sql = (ROOT / "schema" / "029_service_tenancy.sql").read_text()
    await db_pool.execute(sql)  # re-run after 099 already ran: no error
    await db_pool.execute(sql)
    await db_pool.execute("SELECT paddock_apply_service_grants()")
    assert await db_pool.fetchval("SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE relname='service_cursors'")


async def test_029_applied_AFTER_099_still_secures_its_own_tables():
    import tenant_testkit as kit

    admin = await asyncpg.connect(f"{kit._base()}/postgres")
    name = f"t_{uuid.uuid4().hex[:12]}"
    await admin.execute(f'CREATE DATABASE "{name}"')
    try:
        con = await asyncpg.connect(f"{kit._base()}/{name}")
        try:
            files = sorted(kit.SCHEMA_DIR.glob("*.sql"))
            for f in [f for f in files if not f.name.startswith("029")]:
                await con.execute(kit._fix(f.read_text()))   # ... 098, 099 first
            await con.execute((kit.SCHEMA_DIR / "029_service_tenancy.sql").read_text())  # then 029
            assert await con.fetchval(
                "SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE relname='service_cursors'")
            assert await con.fetchval("SELECT count(*) FROM pg_policies WHERE tablename='service_cursors'") == 1
            keys = await con.fetch("SELECT conname FROM pg_constraint WHERE conrelid='sca_projects'::regclass AND contype='u'")
            assert [k[0] for k in keys] == ["sca_projects_tenant_name_key"]
        finally:
            await con.close()
    finally:
        await admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        await admin.close()


async def test_provision_roles_sets_login_and_passwords(db_pool):
    env = {"PADDOCK_APP_DB_PASSWORD": "app-pw", "PADDOCK_SVC_BRAIN_DB_PASSWORD": "brain-pw",
           "PADDOCK_SERVICES_DB_PASSWORD": "svc-pw"}
    async with db_pool.acquire() as con:
        out = await tenancy.provision_roles(con, env)
        assert out["paddock_app"] == "login" and out["paddock_svc_brain"] == "login"
        assert out["paddock_svc_intel"] == "login"
        assert await con.fetchval("SELECT rolcanlogin FROM pg_roles WHERE rolname='paddock_svc_brain'")
        none = await tenancy.provision_roles(con, {})
        assert set(none.values()) == {"nologin"}
    assert tenancy.role_password("paddock_svc_brain", env) == "brain-pw"
    assert tenancy.role_password("paddock_svc_sca", env) == "svc-pw"
    assert tenancy.role_password("paddock_app", env) == "app-pw"
