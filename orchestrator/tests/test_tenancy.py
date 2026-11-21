"""Multi-tenancy (schema/099_tenancy.sql + app/tenancy.py): RLS isolation.

Every test here serves the API through ``app_pool`` -- the NON-superuser
``paddock_app`` role with the production pool setup hook -- because RLS does
not apply to superusers. ``db_pool`` (superuser) is used only to seed and to
look behind the app's back.
"""
from __future__ import annotations

import json
import uuid

import asyncpg
import pytest
import pytest_asyncio

from app import audit as audit_svc
from app import auth as auth_svc
from app import tenancy
from app.config import settings
from app.db import warn_if_privileged

TENANT_A = tenancy.DEFAULT_TENANT_ID
TENANT_B = "00000000-0000-0000-0000-0000000000b2"

SHARED_DOMAIN = "shared.example"
A_ONLY = "alpha-only.example"
B_ONLY = "bravo-only.example"


@pytest.fixture
def enforce():
    prev = settings.auth_mode
    settings.auth_mode = "enforce"
    try:
        yield
    finally:
        settings.auth_mode = prev


async def _seed_admin(db_pool, tenant_id: str, username: str) -> str:
    """Superuser seed: a restricted-clearance admin + full-scope key in a tenant."""
    full, prefix, key_hash = auth_svc.generate_api_key()
    async with db_pool.acquire() as con:
        uid = await con.fetchval(
            "INSERT INTO app_users (username, role, clearance, pw_hash, tenant_id) "
            "VALUES ($1, 'admin', 'restricted', $2, $3) RETURNING id",
            username,
            auth_svc.hash_password("pw-" + username),
            tenant_id,
        )
        await con.execute(
            "INSERT INTO api_keys (user_id, name, prefix, key_hash, scopes, tenant_id) "
            "VALUES ($1, 'k', $2, $3, $4::text[], $5)",
            uid,
            prefix,
            key_hash,
            sorted(auth_svc.ROLE_CAPABILITIES["admin"]),
            tenant_id,
        )
    return full


def _h(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


async def _seed_via_api(client, key: str, *, only: str) -> dict:
    """Write scope + assets + findings through the API (i.e. through RLS)."""
    out: dict = {}
    for value in (SHARED_DOMAIN, only):
        r = await client.post(
            "/v1/scope", headers=_h(key), json={"kind": "domain", "value": value, "added_by": "t"}
        )
        assert r.status_code == 201, r.text
        out.setdefault("scope", []).append(r.json())
    r = await client.post(
        "/v1/assets/bulk",
        headers=_h(key),
        json={"items": [
            {"kind": "domain", "value": SHARED_DOMAIN, "source": "test"},
            {"kind": "domain", "value": only, "source": "test"},
        ]},
    )
    assert r.status_code in (200, 201), r.text
    out["assets"] = r.json()["items"]
    r = await client.post(
        "/v1/findings/bulk",
        headers=_h(key),
        json={"items": [{
            "asset_value": SHARED_DOMAIN, "asset_kind": "domain", "rule_id": "tenancy-rule",
            "rule_source": "policy", "severity": "high", "title": f"finding for {only}",
            "description": "d",
        }]},
    )
    assert r.status_code in (200, 201), r.text
    out["findings"] = r.json()["items"]
    return out


@pytest_asyncio.fixture
async def tenants(enforce, app, app_pool, db_pool, client):
    """Tenant A (= default) and tenant B, each with an admin and the SAME
    scope value / asset / finding rule, seeded through the API."""
    app.state.pool = app_pool
    await tenancy.create_tenant(db_pool, slug="bravo", name="Bravo Corp", tenant_id=TENANT_B)
    key_a = await _seed_admin(db_pool, TENANT_A, "alice-admin")
    key_b = await _seed_admin(db_pool, TENANT_B, "bob-admin")
    data_a = await _seed_via_api(client, key_a, only=A_ONLY)
    data_b = await _seed_via_api(client, key_b, only=B_ONLY)
    return {"a": (key_a, data_a), "b": (key_b, data_b)}


# --------------------------------------------------------------------------- #
# Schema-level guarantees
# --------------------------------------------------------------------------- #

async def test_every_public_table_has_rls(db_pool):
    async with db_pool.acquire() as con:
        rows = await con.fetch(
            """
            SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,
                   EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid
                            AND a.attname = 'tenant_id' AND NOT a.attisdropped) AS has_tenant,
                   ARRAY(SELECT polname::text FROM pg_policy p WHERE p.polrelid = c.oid) AS policies
              FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = 'public' AND c.relkind IN ('r','p') AND NOT c.relispartition
            """
        )
    assert rows
    for r in rows:
        assert r["relrowsecurity"], f"{r['relname']} has no RLS"
        if r["has_tenant"]:
            assert r["relforcerowsecurity"], f"{r['relname']} RLS not FORCEd"
            assert "tenant_isolation" in r["policies"], r["relname"]
        else:
            assert "global_read" in r["policies"] or r["relname"] == "tenants", r["relname"]
    tenant_tables = {r["relname"] for r in rows if r["has_tenant"]}
    for t in ("scope_entries", "assets", "findings", "audit_log", "app_users", "api_keys",
              "scans", "tickets", "integrations", "fleet_agents"):
        assert t in tenant_tables


async def test_app_role_is_not_privileged(db_pool, app_pool):
    su = await warn_if_privileged(db_pool)
    app_role = await warn_if_privileged(app_pool)
    assert su["rolsuper"] is True
    assert app_role["role"] == "paddock_app"
    assert app_role["rolsuper"] is False and app_role["rolbypassrls"] is False


async def test_app_role_cannot_rewrite_audit_or_tenants(app_pool):
    await audit_svc.record(app_pool, action="create", actor="x")
    async with app_pool.acquire() as con:
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await con.execute("UPDATE audit_log SET actor = 'mallory'")
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await con.execute("DELETE FROM audit_log")
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await con.execute("INSERT INTO tenants (slug, name) VALUES ('evil', 'Evil')")


async def test_new_table_gets_rls_when_099_reapplied(db_pool):
    """The DO-block is dynamic: a table another migration adds is covered."""
    from pathlib import Path

    sql = (Path(__file__).resolve().parents[2] / "schema" / "099_tenancy.sql").read_text()
    async with db_pool.acquire() as con:
        await con.execute("CREATE TABLE widgets (id SERIAL PRIMARY KEY, name TEXT UNIQUE)")
        await con.execute("CREATE TABLE feed_x (id SERIAL PRIMARY KEY)")
        await con.execute("COMMENT ON TABLE feed_x IS 'vendor feed @paddock:global'")
        await con.execute(sql)
        await con.execute(sql)  # idempotent
        w = await con.fetchrow(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = 'widgets'"
        )
        has_col = await con.fetchval(
            "SELECT count(*) FROM information_schema.columns "
            "WHERE table_name = 'feed_x' AND column_name = 'tenant_id'"
        )
    assert w["relrowsecurity"] and w["relforcerowsecurity"]
    assert has_col == 0


# --------------------------------------------------------------------------- #
# Read isolation through the API
# --------------------------------------------------------------------------- #

async def test_same_values_coexist_per_tenant(tenants, db_pool):
    _, a = tenants["a"]
    _, b = tenants["b"]
    a_scope = {e["value"]: e["id"] for e in a["scope"]}
    b_scope = {e["value"]: e["id"] for e in b["scope"]}
    assert a_scope[SHARED_DOMAIN] != b_scope[SHARED_DOMAIN]
    async with db_pool.acquire() as con:
        n = await con.fetchval(
            "SELECT count(DISTINCT tenant_id) FROM assets WHERE canonical = $1", SHARED_DOMAIN
        )
    assert n == 2


@pytest.mark.parametrize(
    "path",
    ["/v1/scope", "/v1/assets", "/v1/findings", "/v1/findings/list", "/v1/audit",
     "/v1/auth/apikeys", "/v1/scans", "/v1/assets/graph", "/v1/timeline", "/v1/tickets",
     "/v1/changes", "/v1/schedules", "/v1/owners", "/v1/alert-rules", "/v1/chains",
     "/v1/fleet/agents", "/v1/devices", "/v1/remediation", "/v1/code-findings",
     "/v1/anomalies", "/v1/tls-grades", "/v1/sbom/projects", "/v1/ontology/objects",
     "/v1/ti/matches", "/v1/attack-paths"],
)
async def test_read_endpoints_never_show_other_tenant(tenants, client, path):
    key_a, a = tenants["a"]
    key_b, b = tenants["b"]
    for key, mine, theirs, other_data in (
        (key_a, A_ONLY, B_ONLY, b),
        (key_b, B_ONLY, A_ONLY, a),
    ):
        r = await client.get(path, headers=_h(key))
        body = r.text
        assert theirs not in body, f"{path} leaked {theirs}"
        assert "bob-admin" not in body or key == key_b
        assert "alice-admin" not in body or key == key_a
        # (scope ids are small integers; the UUID ids are checked by substring)
        for item in other_data["assets"] + other_data["findings"]:
            assert item["id"] not in body, f"{path} leaked id {item['id']}"


async def test_lists_return_only_own_rows(tenants, client):
    for who, only in (("a", A_ONLY), ("b", B_ONLY)):
        key, data = tenants[who]
        scope = (await client.get("/v1/scope", headers=_h(key))).json()
        assert sorted(e["value"] for e in scope) == sorted([SHARED_DOMAIN, only])
        assets = (await client.get("/v1/assets", headers=_h(key))).json()
        items = assets["items"] if isinstance(assets, dict) else assets
        assert {i["value"] for i in items} == {SHARED_DOMAIN, only}
        findings = (await client.get("/v1/findings", headers=_h(key))).json()["items"]
        assert [f["title"] for f in findings] == [f"finding for {only}"]
        audit = (await client.get("/v1/audit", headers=_h(key))).json()["items"]
        assert audit and {e["actor"] for e in audit} == {f"{'alice' if who == 'a' else 'bob'}-admin"}
        me = (await client.get("/v1/auth/me", headers=_h(key))).json()
        assert me["tenant_id"] == (TENANT_A if who == "a" else TENANT_B)


async def test_scope_check_is_per_tenant(tenants, client):
    key_a, _ = tenants["a"]
    key_b, _ = tenants["b"]
    ra = await client.post("/v1/scope/check", headers=_h(key_a), json={"target": A_ONLY})
    rb = await client.post("/v1/scope/check", headers=_h(key_b), json={"target": A_ONLY})
    assert ra.status_code == 200 and rb.status_code == 200
    assert ra.json()["allow"] is True
    assert rb.json()["allow"] is False  # B's (cached) allowlist never sees A's scope
    # and B cannot queue a scan against A's scope
    r = await client.post(
        "/v1/scans", headers=_h(key_b), json={"kind": "passive_subdomains", "target": A_ONLY}
    )
    assert r.status_code == 403


async def test_audit_chains_are_per_tenant_and_verify(tenants, client, app_pool):
    for who, tid in (("a", TENANT_A), ("b", TENANT_B)):
        key, _ = tenants[who]
        v = (await client.get("/v1/audit/verify", headers=_h(key))).json()
        assert v["ok"] is True, v
        assert v["tenant_id"] == tid
        assert v["checked"] >= 4
    with tenancy.tenant_context(TENANT_B):
        assert (await audit_svc.verify(app_pool))["ok"] is True


# --------------------------------------------------------------------------- #
# Cross-tenant writes fail
# --------------------------------------------------------------------------- #

async def test_cross_tenant_api_writes_fail(tenants, client, db_pool):
    _, a = tenants["a"]
    key_b, _ = tenants["b"]
    a_finding = a["findings"][0]["id"]
    a_scope = next(e["id"] for e in a["scope"] if e["value"] == A_ONLY)
    a_asset = next(x["id"] for x in a["assets"] if x["value"] == A_ONLY)

    r = await client.patch(f"/v1/findings/{a_finding}", headers=_h(key_b), json={"status": "fixed"})
    assert r.status_code == 404
    r = await client.delete(f"/v1/scope/{a_scope}", headers=_h(key_b))
    assert r.status_code == 404
    r = await client.get(f"/v1/assets/{a_asset}", headers=_h(key_b))
    assert r.status_code == 404

    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT status FROM findings WHERE id = $1::uuid", a_finding) == "open"
        assert await con.fetchval("SELECT active FROM scope_entries WHERE id = $1", a_scope) is True


async def test_cross_tenant_sql_writes_fail(tenants, app_pool):
    _, a = tenants["a"]
    a_asset = next(x["id"] for x in a["assets"] if x["value"] == A_ONLY)
    with tenancy.tenant_context(TENANT_B):
        async with app_pool.acquire() as con:
            # invisible, so UPDATE/DELETE touch nothing ...
            assert await con.execute(
                "UPDATE assets SET value = 'pwned' WHERE id = $1::uuid", a_asset
            ) == "UPDATE 0"
            assert await con.execute("DELETE FROM assets WHERE id = $1::uuid", a_asset) == "DELETE 0"
            # ... and writing a row INTO another tenant is rejected by WITH CHECK
            with pytest.raises(asyncpg.InsufficientPrivilegeError):
                await con.execute(
                    "INSERT INTO scope_entries (kind, value, added_by, tenant_id) "
                    "VALUES ('domain', 'smuggled.example', 'b', $1::uuid)",
                    TENANT_A,
                )
            with pytest.raises(asyncpg.InsufficientPrivilegeError):
                await con.execute(
                    "UPDATE scope_entries SET tenant_id = $1::uuid", TENANT_A
                )
            # A forged tenant GUC inside a statement cannot widen visibility of
            # another tenant's rows beyond what that GUC names.
            n = await con.fetchval("SELECT count(*) FROM assets WHERE value = $1", A_ONLY)
            assert n == 0


async def test_every_tenant_table_isolated_at_sql_level(tenants, db_pool, app_pool):
    """For every tenant-scoped table that holds tenant A rows, tenant B's
    session sees none of them (sweeps tables other engineers add, too)."""
    async with db_pool.acquire() as con:
        tables = [
            r["table_name"] for r in await con.fetch(
                "SELECT table_name FROM information_schema.columns "
                "WHERE table_schema = 'public' AND column_name = 'tenant_id'"
            )
        ]
        populated = {
            t for t in tables
            if await con.fetchval(f'SELECT count(*) FROM "{t}" WHERE tenant_id = $1::uuid', TENANT_A)
        }
    assert {"scope_entries", "assets", "findings", "audit_log", "app_users", "api_keys"} <= populated
    with tenancy.tenant_context(TENANT_B):
        async with app_pool.acquire() as con:
            for t in tables:
                leaked = await con.fetchval(
                    f'SELECT count(*) FROM "{t}" WHERE tenant_id <> $1::uuid', TENANT_B
                )
                assert leaked == 0, f"{t}: {leaked} foreign rows visible"


async def test_strict_mode_without_tenant_sees_and_writes_nothing(tenants, app_pool, monkeypatch):
    monkeypatch.setattr(settings, "tenancy_strict", True)
    assert tenancy.current_tenant_id() is None
    async with app_pool.acquire() as con:
        assert await con.fetchval("SELECT count(*) FROM assets") == 0
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await con.execute(
                "INSERT INTO scope_entries (kind, value, added_by) VALUES ('domain', 'x.example', 'x')"
            )


async def test_pooled_connection_does_not_leak_tenant(tenants, app_pool):
    with tenancy.tenant_context(TENANT_B):
        async with app_pool.acquire() as con:
            assert await con.fetchval("SELECT current_setting('app.tenant_id')") == TENANT_B
    # same (single) pooled connection, no tenant in context -> default tenant
    async with app_pool.acquire() as con:
        assert await con.fetchval("SELECT current_setting('app.tenant_id')") == TENANT_A
        values = {r["value"] for r in await con.fetch("SELECT value FROM assets")}
    assert B_ONLY not in values and A_ONLY in values


# --------------------------------------------------------------------------- #
# Credentials resolve to their tenant
# --------------------------------------------------------------------------- #

async def test_password_login_lands_in_users_tenant(tenants, client):
    r = await client.post("/v1/auth/login", json={"username": "bob-admin", "password": "pw-bob-admin"})
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]
    me = (await client.get("/v1/auth/me", headers={"Authorization": f"Bearer {token}"})).json()
    assert me["tenant_id"] == TENANT_B
    scope = (await client.get("/v1/scope", headers={"Authorization": f"Bearer {token}"})).json()
    assert sorted(e["value"] for e in scope) == sorted([SHARED_DOMAIN, B_ONLY])


async def test_service_key_selects_tenant_by_header(tenants, client, monkeypatch):
    monkeypatch.setattr(settings, "service_api_key", "svc-test-key-123")
    hdr = {"X-API-Key": "svc-test-key-123"}
    r = await client.get("/v1/scope", headers={**hdr, "X-Paddock-Tenant": "bravo"})
    assert sorted(e["value"] for e in r.json()) == sorted([SHARED_DOMAIN, B_ONLY])
    r = await client.get("/v1/scope", headers={**hdr, "X-Paddock-Tenant": TENANT_B})
    assert B_ONLY in r.text and A_ONLY not in r.text
    r = await client.get("/v1/scope", headers=hdr)  # no header -> default tenant
    assert A_ONLY in r.text and B_ONLY not in r.text
    r = await client.get("/v1/scope", headers={**hdr, "X-Paddock-Tenant": str(uuid.uuid4())})
    assert r.status_code == 401


async def test_suspended_tenant_is_locked_out(tenants, client, db_pool):
    key_b, _ = tenants["b"]
    async with db_pool.acquire() as con:
        await con.execute("UPDATE tenants SET status = 'suspended' WHERE id = $1::uuid", TENANT_B)
    r = await client.get("/v1/scope", headers=_h(key_b))
    assert r.status_code == 401
    r = await client.post("/v1/auth/login", json={"username": "bob-admin", "password": "pw-bob-admin"})
    assert r.status_code == 401


async def test_startup_audit_hardening_is_quiet_noop_for_app_role(app_pool, caplog):
    import logging

    with caplog.at_level(logging.INFO, logger="app.auth"):
        await auth_svc.harden_audit_table(app_pool)
    assert "append-only" in caplog.text
    assert "could not revoke" not in caplog.text


async def test_jobs_carry_tenant(tenants, client, fake_redis):
    key_b, _ = tenants["b"]
    r = await client.post(
        "/v1/scans", headers=_h(key_b), json={"kind": "passive_subdomains", "target": B_ONLY}
    )
    assert r.status_code == 201, r.text
    entries = await fake_redis.xrange("queue:passive")
    assert json.loads(entries[-1][1]["job"])["tenant_id"] == TENANT_B
