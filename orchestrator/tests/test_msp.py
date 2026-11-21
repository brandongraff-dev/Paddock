"""MSP console (schema/033_msp.sql + app/msp + routers/msp.py).

Security-critical suite. Every test serves the API through ``app_pool`` (the
NON-superuser ``paddock_app`` role with the production pool hook), because RLS
does not apply to superusers; ``db_pool`` seeds and looks behind the app's back.
"""
from __future__ import annotations

import asyncio
import json
import time
import uuid

import asyncpg
import jwt
import pytest
import pytest_asyncio

from app import auth as auth_svc
from app import tenancy
from app.config import settings
from app.msp import core as msp_core
from app.msp import health as msp_health

from .integrations_helpers import fake_dns, secret_key  # noqa: F401 (fixtures)

MSP_ID = "00000000-0000-0000-0000-0000000000a1"
MSP2_ID = "00000000-0000-0000-0000-0000000000a2"


@pytest.fixture
def enforce():
    prev = settings.auth_mode
    settings.auth_mode = "enforce"
    try:
        yield
    finally:
        settings.auth_mode = prev


def _h(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _seed_user(db_pool, tenant_id: str, username: str, role: str = "viewer",
                     clearance: str = "restricted") -> str:
    async with db_pool.acquire() as con:
        return str(await con.fetchval(
            "INSERT INTO app_users (username, role, clearance, pw_hash, tenant_id) "
            "VALUES ($1, $2, $3, $4, $5) RETURNING id",
            username, role, clearance, auth_svc.hash_password("pw-" + username), tenant_id,
        ))


async def _login(client, username: str, password: str | None = None) -> str:
    r = await client.post("/v1/auth/login", json={"username": username, "password": password or "pw-" + username})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


async def _seed_msp(db_pool, tenant_id: str, slug: str, name: str, *, max_children: int | None = None) -> None:
    await tenancy.create_tenant(db_pool, slug=slug, name=name, tenant_id=tenant_id)
    async with db_pool.acquire() as con:
        await con.execute(
            "INSERT INTO msp_orgs (tenant_id, name, max_children, created_by) VALUES ($1, $2, $3, 'test')",
            tenant_id, name, max_children,
        )


async def _seed_findings(db_pool, tenant_id: str, *, criticals=0, highs=0, overdue_critical=0,
                         verified_fix=False, scan=False, assets=1) -> None:
    """Superuser seed INSIDE one tenant (the GUC makes the triggers' default
    tenant_id agree with the explicit one)."""
    async with db_pool.acquire() as con:
        async with con.transaction():
            await con.execute("SELECT set_config('app.tenant_id', $1, true)", tenant_id)
            asset_ids = []
            for i in range(max(assets, 1)):
                asset_ids.append(await con.fetchval(
                    "INSERT INTO assets (kind, value, canonical, source, tenant_id) "
                    "VALUES ('domain', $1, $1, 'test', $2) RETURNING id",
                    f"a{i}.{tenant_id[-4:]}.example", tenant_id,
                ))
            n = 0

            async def add(sev: str, *, first_seen_sql="NOW()") -> uuid.UUID:
                nonlocal n
                n += 1
                return await con.fetchval(
                    f"INSERT INTO findings (asset_id, rule_id, rule_source, severity, title, description, "
                    f"first_seen, tenant_id) VALUES ($1, $2, 'policy', $3, 't', 'd', {first_seen_sql}, $4) "
                    "RETURNING id",
                    asset_ids[0], f"r{n}", sev, tenant_id,
                )

            for _ in range(criticals):
                await add("critical")
            for _ in range(highs):
                await add("high")
            for _ in range(overdue_critical):
                await add("critical", first_seen_sql="NOW() - INTERVAL '3 days'")
            if verified_fix:
                fid = await add("medium")
                await con.execute("UPDATE findings SET status = 'fixed' WHERE id = $1", fid)
                # the asset was re-observed well after the fix and the finding was not
                await con.execute(
                    "UPDATE assets SET last_seen = NOW() + INTERVAL '10 minutes' WHERE id = $1", asset_ids[0]
                )
            if scan:
                await con.execute(
                    "INSERT INTO scans (kind, target, status, finished_at, tenant_id) "
                    "VALUES ('passive', 'x.example', 'completed', NOW(), $1)", tenant_id,
                )


async def _audit_rows(db_pool, tenant_id: str) -> list[asyncpg.Record]:
    async with db_pool.acquire() as con:
        return await con.fetch(
            "SELECT id, action, actor, actor_role, resource_id, path, status, details "
            "  FROM audit_log WHERE tenant_id = $1 ORDER BY id",
            tenant_id,
        )


def _details(row) -> dict:
    d = row["details"]
    return json.loads(d) if isinstance(d, str) else d


@pytest_asyncio.fixture
async def world(enforce, app, app_pool, db_pool, client):
    """An MSP with an admin (root), an analyst (bea) and an outsider (otto,
    no grants), two customers (A, B), and an unrelated second MSP with its own
    customer (X)."""
    app.state.pool = app_pool
    await _seed_msp(db_pool, MSP_ID, "msp-one", "MSP One")
    await _seed_msp(db_pool, MSP2_ID, "msp-two", "MSP Two")
    root_id = await _seed_user(db_pool, MSP_ID, "root", "admin")
    bea_id = await _seed_user(db_pool, MSP_ID, "bea", "analyst")
    otto_id = await _seed_user(db_pool, MSP_ID, "otto", "analyst")
    boss2_id = await _seed_user(db_pool, MSP2_ID, "boss2", "admin")
    t_root = await _login(client, "root")
    t_bea = await _login(client, "bea")
    t_otto = await _login(client, "otto")
    t_boss2 = await _login(client, "boss2")

    async def mk(token, slug, name):
        r = await client.post("/v1/msp/customers", headers=_h(token), json={"slug": slug, "name": name})
        assert r.status_code == 201, r.text
        return r.json()

    a = await mk(t_root, "cust-a", "Customer A")
    b = await mk(t_root, "cust-b", "Customer B")
    x = await mk(t_boss2, "cust-x", "Customer X")
    w = dict(
        root=t_root, bea=t_bea, otto=t_otto, boss2=t_boss2, a=a, b=b, x=x,
        root_id=root_id, bea_id=bea_id, otto_id=otto_id, boss2_id=boss2_id,
    )
    # bea: analyst on A only.
    r = await client.post("/v1/msp/grants", headers=_h(t_root),
                          json={"user_id": bea_id, "customer_id": a["id"], "role": "analyst"})
    assert r.status_code == 201, r.text
    w["bea_grant_a"] = r.json()["id"]
    return w


async def _switch(client, token, customer_id):
    return await client.post(f"/v1/msp/customers/{customer_id}/switch", headers=_h(token))


# --------------------------------------------------------------------------- #
# Switching: the grant decides
# --------------------------------------------------------------------------- #

async def test_user_without_grant_cannot_switch(client, world, db_pool):
    r = await _switch(client, world["otto"], world["a"]["id"])
    assert r.status_code == 403
    assert "no access grant" in r.json()["detail"]
    # the refusal is in the MSP's own trail
    rows = await _audit_rows(db_pool, MSP_ID)
    denied = [x for x in rows if x["action"] == "msp.switch_denied"]
    assert denied and denied[-1]["actor"] == "otto"
    # ... and nothing was written to the customer's trail
    assert not [x for x in await _audit_rows(db_pool, world["a"]["id"]) if x["actor"].endswith("/otto")]


async def test_grant_for_a_gives_nothing_in_b(client, world):
    assert (await _switch(client, world["bea"], world["a"]["id"])).status_code == 200
    r = await _switch(client, world["bea"], world["b"]["id"])
    assert r.status_code == 403
    # Same answer for a customer of another MSP and for a random id: no probing.
    assert (await _switch(client, world["bea"], world["x"]["id"])).status_code == 403
    assert (await _switch(client, world["bea"], str(uuid.uuid4()))).status_code == 403


async def test_a_token_is_not_authority(client, world, db_pool):
    """A validly SIGNED switch token for B, minted for a user with no grant on B,
    is useless: the grant is re-read on every request."""
    facts = {
        "user_id": world["bea_id"], "username": "bea", "msp_tenant_id": MSP_ID,
        "child_tenant_id": world["b"]["id"], "role": "admin",
    }
    forged, _ = msp_core.issue_switch_token(facts=facts)
    r = await client.get("/v1/findings", headers=_h(forged))
    assert r.status_code == 401
    # A token signed with the wrong key is rejected outright.
    bad = jwt.encode({"typ": "msp_switch", "sub": world["bea_id"], "mtid": MSP_ID, "tid": world["b"]["id"],
                      "iat": int(time.time()), "exp": int(time.time()) + 600}, "not-the-secret", algorithm="HS256")
    assert (await client.get("/v1/findings", headers=_h(bad))).status_code == 401
    # Expired token.
    old = jwt.encode({"typ": "msp_switch", "sub": world["bea_id"], "mtid": MSP_ID, "tid": world["a"]["id"],
                      "iat": int(time.time()) - 7200, "exp": int(time.time()) - 3600},
                     auth_svc._jwt_secret(), algorithm=settings.jwt_algorithm)
    assert (await client.get("/v1/findings", headers=_h(old))).status_code == 401


async def test_switch_token_is_not_an_access_token(client, world):
    sw = (await _switch(client, world["bea"], world["a"]["id"])).json()
    with pytest.raises(jwt.PyJWTError):
        auth_svc.verify_jwt(sw["access_token"])
    # and an ordinary access token is not a switch token
    assert not msp_core.is_switch_token(world["bea"])


async def test_switch_runs_in_the_customers_tenant_only(client, world, db_pool):
    await _seed_findings(db_pool, world["a"]["id"], criticals=2)
    await _seed_findings(db_pool, world["b"]["id"], highs=3)
    sw = (await _switch(client, world["root"], world["a"]["id"])).json()
    me = (await client.get("/v1/auth/me", headers=_h(sw["access_token"]))).json()
    assert me["tenant_id"] == world["a"]["id"]
    assert me["actor"] == "msp:msp-one/root"
    f = await client.get("/v1/findings", headers=_h(sw["access_token"]), params={"limit": 100})
    assert f.status_code == 200
    items = f.json()["items"] if isinstance(f.json(), dict) else f.json()
    assert len(items) == 2 and {i["severity"] for i in items} == {"critical"}
    # The MSP user's OWN session sees the MSP tenant, never a customer's data.
    own = await client.get("/v1/findings", headers=_h(world["root"]), params={"limit": 100})
    own_items = own.json()["items"] if isinstance(own.json(), dict) else own.json()
    assert own_items == []


async def test_grant_role_limits_what_the_msp_user_can_do(client, world):
    # bea is an ANALYST on A: may triage-level things, may not do admin things.
    sw = (await _switch(client, world["bea"], world["a"]["id"])).json()
    assert sw["role"] == "analyst"
    r = await client.post("/v1/scope", headers=_h(sw["access_token"]),
                          json={"kind": "domain", "value": "x.example", "added_by": "bea"})
    assert r.status_code == 403
    # root has an admin grant on A: admin actions work.
    sw2 = (await _switch(client, world["root"], world["a"]["id"])).json()
    r = await client.post("/v1/scope", headers=_h(sw2["access_token"]),
                          json={"kind": "domain", "value": "x.example", "added_by": "root"})
    assert r.status_code == 201, r.text


async def test_viewer_grant_is_read_only_and_clearance_is_capped(client, world, db_pool):
    r = await client.post("/v1/msp/grants", headers=_h(world["root"]),
                          json={"user_id": world["otto_id"], "customer_id": world["b"]["id"],
                                "role": "viewer", "clearance": "public"})
    assert r.status_code == 201
    sw = (await _switch(client, world["otto"], world["b"]["id"])).json()
    assert sw["role"] == "viewer" and sw["clearance"] == "public"
    r = await client.post("/v1/scans", headers=_h(sw["access_token"]), json={"kind": "passive", "target": "x.example"})
    assert r.status_code == 403
    me = (await client.get("/v1/auth/me", headers=_h(sw["access_token"]))).json()
    assert me["clearance"] == "public"


# --------------------------------------------------------------------------- #
# Revocation / suspension take effect immediately
# --------------------------------------------------------------------------- #

async def test_revoking_a_grant_takes_effect_immediately(client, world, db_pool):
    sw = (await _switch(client, world["bea"], world["a"]["id"])).json()
    ok = await client.get("/v1/findings", headers=_h(sw["access_token"]))
    assert ok.status_code == 200
    r = await client.delete(f"/v1/msp/grants/{world['bea_grant_a']}", headers=_h(world["root"]))
    assert r.status_code == 200
    again = await client.get("/v1/findings", headers=_h(sw["access_token"]))
    assert again.status_code == 401
    assert "no access grant" in again.json()["detail"]
    assert (await _switch(client, world["bea"], world["a"]["id"])).status_code == 403
    # the revocation is in the customer's trail too, and the refused token left a trace
    assert any(x["action"] == "msp.grant_revoked" for x in await _audit_rows(db_pool, world["a"]["id"]))
    assert any(x["action"] == "msp.switch_refused" for x in await _audit_rows(db_pool, MSP_ID))


async def test_wildcard_grant_and_per_customer_override(client, world):
    r = await client.post("/v1/msp/grants", headers=_h(world["root"]),
                          json={"user_id": world["otto_id"], "customer_id": None, "role": "admin"})
    assert r.status_code == 201
    assert (await _switch(client, world["otto"], world["a"]["id"])).json()["role"] == "admin"
    assert (await _switch(client, world["otto"], world["b"]["id"])).json()["role"] == "admin"
    # carve one customer down: the specific grant wins over the wildcard
    r = await client.post("/v1/msp/grants", headers=_h(world["root"]),
                          json={"user_id": world["otto_id"], "customer_id": world["b"]["id"], "role": "viewer"})
    assert r.status_code == 201
    assert (await _switch(client, world["otto"], world["b"]["id"])).json()["role"] == "viewer"
    assert (await _switch(client, world["otto"], world["a"]["id"])).json()["role"] == "admin"
    # a wildcard never reaches ANOTHER MSP's customers
    assert (await _switch(client, world["otto"], world["x"]["id"])).status_code == 403


async def test_suspended_customer_is_refused_and_reactivation_restores(client, world):
    sw = (await _switch(client, world["root"], world["a"]["id"])).json()
    assert (await client.get("/v1/findings", headers=_h(sw["access_token"]))).status_code == 200
    r = await client.post(f"/v1/msp/customers/{world['a']['id']}/suspend", headers=_h(world["root"]))
    assert r.status_code == 200 and r.json()["status"] == "suspended"
    assert (await client.get("/v1/findings", headers=_h(sw["access_token"]))).status_code == 401
    r = await _switch(client, world["root"], world["a"]["id"])
    assert r.status_code == 409 and "suspended" in r.json()["detail"]
    r = await client.post(f"/v1/msp/customers/{world['a']['id']}/reactivate", headers=_h(world["root"]))
    assert r.status_code == 200 and r.json()["status"] == "active"
    sw = (await _switch(client, world["root"], world["a"]["id"])).json()
    assert (await client.get("/v1/findings", headers=_h(sw["access_token"]))).status_code == 200


async def test_suspending_msp_or_deactivating_the_user_kills_tokens(client, world, db_pool):
    sw = (await _switch(client, world["root"], world["a"]["id"])).json()
    async with db_pool.acquire() as con:
        await con.execute("UPDATE app_users SET active = FALSE WHERE id = $1", world["root_id"])
    assert (await client.get("/v1/findings", headers=_h(sw["access_token"]))).status_code == 401
    async with db_pool.acquire() as con:
        await con.execute("UPDATE app_users SET active = TRUE WHERE id = $1", world["root_id"])
        await con.execute("UPDATE tenants SET status = 'suspended' WHERE id = $1", MSP_ID)
    assert (await client.get("/v1/findings", headers=_h(sw["access_token"]))).status_code == 401


async def test_session_revocation_watermark_applies(client, world, db_pool):
    sw = (await _switch(client, world["root"], world["a"]["id"])).json()
    async with db_pool.acquire() as con:
        await con.execute("UPDATE app_users SET sessions_revoked_at = NOW() + INTERVAL '1 minute' WHERE id = $1",
                          world["root_id"])
    assert (await client.get("/v1/findings", headers=_h(sw["access_token"]))).status_code == 401


# --------------------------------------------------------------------------- #
# Isolation: customers cannot see the parent or siblings
# --------------------------------------------------------------------------- #

async def test_customer_users_cannot_see_parent_or_siblings(client, world, db_pool, app_pool):
    a, b = world["a"], world["b"]
    # the customer's first admin comes from the onboarding invite
    r = await client.post("/v1/msp/invites/redeem", json={
        "token": a["invite"]["token"], "username": "alice-a", "password": "correct horse battery"})
    assert r.status_code == 201, r.text
    t_a = await _login(client, "alice-a", "correct horse battery")
    me = (await client.get("/v1/msp/me", headers=_h(t_a))).json()
    assert me == {"mode": "none", "is_msp": False}
    for path in ("/v1/msp/customers", "/v1/msp/summary", "/v1/msp/grants", "/v1/msp/templates", "/v1/msp/usage"):
        assert (await client.get(path, headers=_h(t_a))).status_code == 403, path
    for path in ("/v1/msp/customers", ):
        assert (await client.post(path, headers=_h(t_a), json={"slug": "sneaky", "name": "x"})).status_code == 403
    assert (await _switch(client, t_a, b["id"])).status_code == 403
    # Straight SQL as the app role inside A's tenant: none of the MSP's rows exist.
    with tenancy.tenant_context(a["id"]):
        async with app_pool.acquire() as con:
            for table in ("msp_orgs", "msp_children", "msp_grants", "msp_templates", "msp_child_health"):
                assert await con.fetchval(f"SELECT COUNT(*) FROM {table}") == 0, table
            assert await con.fetchval("SELECT COUNT(*) FROM audit_log WHERE tenant_id = $1", MSP_ID) == 0
            assert await con.fetchval("SELECT COUNT(*) FROM audit_log WHERE tenant_id = $1", b["id"]) == 0
            assert await con.fetchval("SELECT COUNT(*) FROM app_users WHERE tenant_id = $1", MSP_ID) == 0
    # ... and inside the MSP, the OTHER MSP's rows don't exist either
    with tenancy.tenant_context(MSP_ID):
        async with app_pool.acquire() as con:
            assert await con.fetchval("SELECT COUNT(*) FROM msp_children WHERE child_tenant_id = $1",
                                      world["x"]["id"]) == 0


async def test_app_role_cannot_forge_msp_rows_or_touch_tenants(app_pool, world):
    """Promoting a tenant / adopting a customer / writing `tenants` are not
    things the app role can do, even under its own tenant's context."""
    victim = world["x"]["id"]
    with tenancy.tenant_context(MSP_ID):
        async with app_pool.acquire() as con:
            with pytest.raises(asyncpg.InsufficientPrivilegeError):
                await con.execute(
                    "INSERT INTO msp_children (tenant_id, child_tenant_id, slug, name) VALUES ($1, $2, 'x', 'x')",
                    MSP_ID, victim)
            with pytest.raises(asyncpg.InsufficientPrivilegeError):
                await con.execute("UPDATE msp_orgs SET max_children = 999")
            with pytest.raises(asyncpg.InsufficientPrivilegeError):
                await con.execute("UPDATE tenants SET status = 'suspended' WHERE id = $1", victim)
            # the definer function refuses a customer that is not ours
            with pytest.raises(asyncpg.InsufficientPrivilegeError):
                await con.fetchval("SELECT msp_set_child_status($1, 'suspended')", victim)
    # a tenant that is not an MSP cannot create customers
    with tenancy.tenant_context(tenancy.DEFAULT_TENANT_ID):
        async with app_pool.acquire() as con:
            with pytest.raises(asyncpg.InsufficientPrivilegeError):
                await con.fetchval("SELECT msp_create_child_tenant('nope', 'Nope', 'x')")
            with pytest.raises(asyncpg.InsufficientPrivilegeError):
                await con.execute("INSERT INTO msp_orgs (tenant_id, name) VALUES ($1, 'self-promoted')",
                                  tenancy.DEFAULT_TENANT_ID)


async def test_delegated_session_surface_is_narrowed(client, world):
    sw = (await _switch(client, world["root"], world["a"]["id"])).json()["access_token"]
    # no nesting / pivoting through the MSP console
    assert (await client.get("/v1/msp/customers", headers=_h(sw))).status_code == 403
    assert (await _switch(client, sw, world["b"]["id"])).status_code == 403
    assert (await client.post("/v1/msp/customers", headers=_h(sw), json={"slug": "zz", "name": "z"})).status_code == 403
    # no persistent credentials in the customer
    assert (await client.post("/v1/auth/apikeys", headers=_h(sw), json={"name": "persist", "scopes": ["read"]})
            ).status_code == 403
    assert (await client.get("/v1/auth/sso/admin/providers", headers=_h(sw))).status_code == 403
    # nor the customer's own billing relationship or licence (reading the licence is fine)
    assert (await client.post("/v1/billing/checkout", headers=_h(sw), json={"plan": "team"})).status_code == 403
    assert (await client.post("/v1/billing/portal", headers=_h(sw), json={})).status_code == 403
    assert (await client.post("/v1/license", headers=_h(sw), json={"key": "x"})).status_code == 403
    assert (await client.delete("/v1/license", headers=_h(sw))).status_code == 403
    assert (await client.get("/v1/license", headers=_h(sw))).status_code == 200
    assert (await client.post("/v1/ingest/sources", headers=_h(sw), json={"name": "ci"})).status_code == 403
    # but /v1/msp/me tells the UI who is acting
    me = (await client.get("/v1/msp/me", headers=_h(sw))).json()
    assert me["mode"] == "delegated" and me["customer"]["slug"] == "cust-a" and me["msp"]["slug"] == "msp-one"


async def test_api_keys_cannot_switch(client, world, db_pool):
    full, prefix, key_hash = auth_svc.generate_api_key()
    async with db_pool.acquire() as con:
        await con.execute(
            "INSERT INTO api_keys (user_id, name, prefix, key_hash, scopes, tenant_id) "
            "VALUES ($1, 'k', $2, $3, $4::text[], $5)",
            world["root_id"], prefix, key_hash, sorted(auth_svc.ROLE_CAPABILITIES["admin"]), MSP_ID)
    assert (await _switch(client, full, world["a"]["id"])).status_code == 403


# --------------------------------------------------------------------------- #
# Audit: BOTH trails, with the acting MSP user
# --------------------------------------------------------------------------- #

async def test_every_switch_and_action_lands_in_both_trails(client, world, db_pool):
    a = world["a"]["id"]
    sw = (await _switch(client, world["root"], a)).json()["access_token"]
    assert (await client.get("/v1/findings", headers=_h(sw))).status_code == 200
    r = await client.post("/v1/scope", headers=_h(sw), json={"kind": "domain", "value": "audit.example", "added_by": "root"})
    assert r.status_code == 201

    child = await _audit_rows(db_pool, a)
    msp = await _audit_rows(db_pool, MSP_ID)

    # the switch itself
    assert any(x["action"] == "msp.switch" and x["actor"] == "msp:msp-one/root" for x in child)
    assert any(x["action"] == "msp.switch" and x["actor"] == "root" for x in msp)

    # the read and the write: customer-side rows name the MSP user ...
    cpaths = [(x["method"] if "method" in x.keys() else None, x["path"]) for x in child]
    assert any(p == "/v1/findings" for _, p in cpaths)
    scope_rows = [x for x in child if x["path"] == "/v1/scope"]
    assert scope_rows and all(x["actor"] == "msp:msp-one/root" for x in scope_rows)
    d = _details(scope_rows[-1])
    assert d["msp"]["msp_user"] == "root" and d["msp"]["msp"] == "msp-one" and d["msp"]["grant_role"] == "admin"
    # ... and the MSP trail has its own row for every one of them
    mrows = [x for x in msp if x["action"] == "msp.act" and x["resource_id"] == a]
    assert any(x["path"] == "/v1/findings" for x in mrows)
    assert any(x["path"] == "/v1/scope" for x in mrows)
    assert all(x["actor"] == "root" for x in mrows)
    # write-ahead + outcome for the mutation in both chains
    assert len([x for x in scope_rows]) >= 2
    assert len([x for x in mrows if x["path"] == "/v1/scope"]) >= 2
    # nothing leaked into the sibling's trail
    assert not any(x["actor"].startswith("msp:") for x in await _audit_rows(db_pool, world["b"]["id"])
                   if x["action"] not in ("msp.customer_created", "msp.invite_created"))


async def test_denied_delegated_request_is_audited_in_both_trails(client, world, db_pool):
    a = world["a"]["id"]
    sw = (await _switch(client, world["bea"], a)).json()["access_token"]
    assert (await client.post("/v1/scope", headers=_h(sw),
                              json={"kind": "domain", "value": "d.example", "added_by": "bea"})).status_code == 403
    assert any(x["action"] == "deny" and x["actor"] == "msp:msp-one/bea" for x in await _audit_rows(db_pool, a))
    assert any(x["action"] == "msp.act" and x["actor"] == "bea" and x["status"] == 403
               for x in await _audit_rows(db_pool, MSP_ID))


async def test_audit_chains_still_verify(client, world, db_pool, app_pool):
    from app import audit as audit_svc

    a = world["a"]["id"]
    sw = (await _switch(client, world["root"], a)).json()["access_token"]
    await client.get("/v1/findings", headers=_h(sw))
    for tid in (a, MSP_ID):
        with tenancy.tenant_context(tid):
            res = await audit_svc.verify(app_pool)
        assert res.get("ok", res.get("valid", True)) is not False, res


# --------------------------------------------------------------------------- #
# Rollup
# --------------------------------------------------------------------------- #

async def test_rollup_only_includes_granted_children(client, world, db_pool):
    await _seed_findings(db_pool, world["a"]["id"], criticals=2, highs=1, overdue_critical=1,
                         verified_fix=True, scan=True, assets=2)
    await _seed_findings(db_pool, world["b"]["id"], highs=4)
    await _seed_findings(db_pool, world["x"]["id"], criticals=9)

    # root: admin grant on A and B (creator grants) -- X belongs to ANOTHER MSP
    r = await client.get("/v1/msp/customers", headers=_h(world["root"]))
    assert r.status_code == 200
    body = r.json()
    ids = {i["id"] for i in body["items"]}
    assert ids == {world["a"]["id"], world["b"]["id"]} and body["total"] == 2
    by = {i["slug"]: i for i in body["items"]}
    ha = by["cust-a"]["health"]
    assert ha["open_criticals"] == 3                      # 2 + 1 overdue
    assert ha["exposure_index"] == 3 * 10 + 5             # 3 criticals + 1 high
    assert ha["sla_breaches"] >= 1                        # the 3-day-old critical (24h SLA)
    assert ha["verified_fixes"] == 1
    assert ha["last_scan_at"] is not None
    assert ha["grade"] == msp_health.grade_for(35, 3) == "C"
    assert ha["monitored_assets"] == 2
    hb = by["cust-b"]["health"]
    assert hb["open_criticals"] == 0 and hb["exposure_index"] == 20 and hb["grade"] == "B"
    assert hb["last_scan_at"] is None

    # bea: analyst on A only -> sees ONLY A
    body = (await client.get("/v1/msp/customers", headers=_h(world["bea"]))).json()
    assert [i["slug"] for i in body["items"]] == ["cust-a"] and body["total"] == 1
    # otto: no grants -> nothing at all
    body = (await client.get("/v1/msp/customers", headers=_h(world["otto"]))).json()
    assert body["items"] == [] and body["total"] == 0
    # the other MSP sees only its own
    body = (await client.get("/v1/msp/customers", headers=_h(world["boss2"]))).json()
    assert [i["slug"] for i in body["items"]] == ["cust-x"]
    assert body["items"][0]["health"]["open_criticals"] == 9
    # summary covers the same set
    s = (await client.get("/v1/msp/summary", headers=_h(world["root"]))).json()
    assert s["customers"] == 2 and s["open_criticals"] == 3


async def test_rollup_does_not_widen_when_a_grant_is_removed(client, world):
    await client.delete(f"/v1/msp/grants/{world['bea_grant_a']}", headers=_h(world["root"]))
    body = (await client.get("/v1/msp/customers", headers=_h(world["bea"]))).json()
    assert body["items"] == []


async def test_rollup_pagination_search_sort(client, world, db_pool):
    for i in range(3):
        r = await client.post("/v1/msp/customers", headers=_h(world["root"]),
                              json={"slug": f"extra-{i}", "name": f"Extra {i}"})
        assert r.status_code == 201
    await _seed_findings(db_pool, world["b"]["id"], criticals=5)
    r = await client.get("/v1/msp/customers", headers=_h(world["root"]), params={"limit": 2, "offset": 0})
    page1 = r.json()
    assert page1["total"] == 5 and len(page1["items"]) == 2
    page2 = (await client.get("/v1/msp/customers", headers=_h(world["root"]),
                              params={"limit": 2, "offset": 2})).json()
    page3 = (await client.get("/v1/msp/customers", headers=_h(world["root"]),
                              params={"limit": 2, "offset": 4})).json()
    seen = [i["slug"] for p in (page1, page2, page3) for i in p["items"]]
    assert len(seen) == 5 and len(set(seen)) == 5
    # search
    s = (await client.get("/v1/msp/customers", headers=_h(world["root"]), params={"q": "EXTRA"})).json()
    assert s["total"] == 3 and all(i["slug"].startswith("extra-") for i in s["items"])
    s = (await client.get("/v1/msp/customers", headers=_h(world["root"]), params={"q": "100%"})).json()
    assert s["total"] == 0                                  # LIKE wildcards are escaped
    # sort by a metric (worst first): B has 5 criticals
    s = (await client.get("/v1/msp/customers", headers=_h(world["root"]),
                          params={"sort": "criticals", "order": "desc"})).json()
    assert s["items"][0]["slug"] == "cust-b"
    assert (await client.get("/v1/msp/customers", headers=_h(world["root"]), params={"sort": "evil; drop"})
            ).status_code == 422


def test_grade_function():
    g = msp_health.grade_for
    assert g(0, 0) == "A" and g(10, 0) == "A" and g(11, 0) == "B" and g(40, 0) == "B"
    assert g(41, 0) == "C" and g(100, 0) == "C" and g(101, 0) == "D" and g(250, 0) == "D" and g(251, 0) == "F"
    assert g(0, 1) == "C" and g(0, 4) == "C" and g(0, 5) == "D" and g(300, 0) == "F"


async def test_compute_metrics_uses_one_tenant_even_without_rls(world, db_pool):
    """The rollup loop must be right even on a pool that bypasses RLS (the
    superuser test pool): every query names its tenant explicitly."""
    await _seed_findings(db_pool, world["a"]["id"], criticals=1)
    await _seed_findings(db_pool, world["b"]["id"], criticals=7)
    m = await msp_health.compute_child_metrics(db_pool, world["a"]["id"])
    assert m["open_criticals"] == 1


# --------------------------------------------------------------------------- #
# Lifecycle: provisioning + invites
# --------------------------------------------------------------------------- #

async def test_create_customer_grants_creator_and_issues_invite(client, world, db_pool):
    c = world["a"]
    assert c["status"] == "active" and c["invite"]["token"].startswith(c["id"] + ".")
    # only the hash is stored
    async with db_pool.acquire() as con:
        row = await con.fetchrow("SELECT token_hash, tenant_id FROM msp_invites WHERE tenant_id = $1", c["id"])
    assert row["token_hash"] != c["invite"]["token"] and str(row["tenant_id"]) == c["id"]
    child_rows = await _audit_rows(db_pool, c["id"])
    assert any(x["action"] == "msp.customer_created" and x["actor"] == "msp:msp-one/root" for x in child_rows)
    assert any(x["action"] == "msp.invite_created" for x in child_rows)
    assert any(x["action"] == "msp.customer_created" for x in await _audit_rows(db_pool, MSP_ID))


async def test_only_msp_admins_manage_lifecycle(client, world):
    for path, body in (
        ("/v1/msp/customers", {"slug": "nope", "name": "n"}),
        (f"/v1/msp/customers/{world['a']['id']}/suspend", None),
        ("/v1/msp/grants", {"user_id": world["otto_id"], "role": "admin"}),
    ):
        r = await client.post(path, headers=_h(world["bea"]), json=body) if body else \
            await client.post(path, headers=_h(world["bea"]))
        assert r.status_code == 403, path
    assert (await client.get("/v1/msp/grants", headers=_h(world["bea"]))).status_code == 403


async def test_admin_cannot_suspend_a_customer_without_a_grant_or_of_another_msp(client, world):
    # root's grants cover A and B; boss2 (other MSP) has none on A
    assert (await client.post(f"/v1/msp/customers/{world['a']['id']}/suspend",
                              headers=_h(world["boss2"]))).status_code == 403
    assert (await client.post(f"/v1/msp/customers/{world['x']['id']}/suspend",
                              headers=_h(world["root"]))).status_code == 403
    # an MSP admin with only a VIEWER grant cannot suspend either
    await client.post("/v1/msp/grants", headers=_h(world["root"]),
                      json={"user_id": world["otto_id"], "customer_id": world["b"]["id"], "role": "viewer"})
    # (otto is an analyst in the MSP, so also fails RBAC; the grant check is the second wall)
    assert (await client.post(f"/v1/msp/customers/{world['b']['id']}/suspend",
                              headers=_h(world["otto"]))).status_code == 403


async def test_slug_conflicts_and_customer_limit(client, world, db_pool):
    r = await client.post("/v1/msp/customers", headers=_h(world["root"]), json={"slug": "cust-a", "name": "dup"})
    assert r.status_code == 409
    r = await client.post("/v1/msp/customers", headers=_h(world["root"]), json={"slug": "default", "name": "d"})
    assert r.status_code == 409
    r = await client.post("/v1/msp/customers", headers=_h(world["root"]), json={"slug": "Bad Slug!", "name": "d"})
    assert r.status_code == 422
    async with db_pool.acquire() as con:
        await con.execute("UPDATE msp_orgs SET max_children = 2 WHERE tenant_id = $1", MSP_ID)
    r = await client.post("/v1/msp/customers", headers=_h(world["root"]), json={"slug": "third", "name": "t"})
    assert r.status_code == 409 and "limit" in r.json()["detail"]


async def test_invite_redeem_flow_and_abuse(client, world, db_pool):
    a = world["a"]
    tok = a["invite"]["token"]
    body = {"token": tok, "username": "carol-a", "password": "correct horse battery"}
    # wrong secret / wrong tenant prefix / garbage
    for bad in (tok[:-3] + "xxx", world["b"]["id"] + "." + tok.split(".", 1)[1], "garbage-token-garbage-token", tok.split(".")[0]):
        r = await client.post("/v1/msp/invites/redeem", json={**body, "token": bad})
        assert r.status_code in (400, 422), (bad, r.text)
    # short password
    assert (await client.post("/v1/msp/invites/redeem", json={**body, "password": "short"})).status_code == 422
    # good
    r = await client.post("/v1/msp/invites/redeem", json=body)
    assert r.status_code == 201, r.text
    # single use
    assert (await client.post("/v1/msp/invites/redeem", json={**body, "username": "dave-a"})).status_code == 400
    # the new user is an admin of A only
    t = await _login(client, "carol-a", "correct horse battery")
    me = (await client.get("/v1/auth/me", headers=_h(t))).json()
    assert me["tenant_id"] == a["id"] and me["role"] == "admin"
    assert any(x["action"] == "msp.invite_redeemed" for x in await _audit_rows(db_pool, a["id"]))
    assert any(x["action"] == "msp.invite_redeemed" for x in await _audit_rows(db_pool, MSP_ID))


async def test_invite_expired_or_customer_suspended(client, world, db_pool):
    b = world["b"]
    async with db_pool.acquire() as con:
        await con.execute("UPDATE msp_invites SET expires_at = NOW() - INTERVAL '1 minute' WHERE tenant_id = $1", b["id"])
    r = await client.post("/v1/msp/invites/redeem",
                          json={"token": b["invite"]["token"], "username": "late", "password": "correct horse battery"})
    assert r.status_code == 400
    # a fresh one, but the customer is suspended
    r = await client.post(f"/v1/msp/customers/{b['id']}/invites", headers=_h(world["root"]), json={})
    assert r.status_code == 201
    tok = r.json()["token"]
    await client.post(f"/v1/msp/customers/{b['id']}/suspend", headers=_h(world["root"]))
    r = await client.post("/v1/msp/invites/redeem",
                          json={"token": tok, "username": "late2", "password": "correct horse battery"})
    assert r.status_code == 400


async def test_grant_validation(client, world):
    # a user of ANOTHER MSP cannot be granted, a foreign customer cannot be granted on
    r = await client.post("/v1/msp/grants", headers=_h(world["root"]),
                          json={"user_id": world["boss2_id"], "customer_id": world["a"]["id"], "role": "admin"})
    assert r.status_code == 404
    r = await client.post("/v1/msp/grants", headers=_h(world["root"]),
                          json={"user_id": world["otto_id"], "customer_id": world["x"]["id"], "role": "admin"})
    assert r.status_code == 404
    r = await client.post("/v1/msp/grants", headers=_h(world["root"]),
                          json={"user_id": world["otto_id"], "customer_id": world["a"]["id"], "role": "owner"})
    assert r.status_code == 422
    items = (await client.get("/v1/msp/grants", headers=_h(world["root"]))).json()["items"]
    assert {i["username"] for i in items} >= {"root", "bea"}


# --------------------------------------------------------------------------- #
# Templates
# --------------------------------------------------------------------------- #

def _template_body(name="baseline"):
    return {
        "name": name, "description": "default alerting",
        "alert_rules": [{"name": "msp-high", "channel": "slack", "target": "https://hooks.example.com/x",
                         "match": {"min_severity": "high"}}],
        "integrations": [{"kind": "slack", "name": "msp-psa", "events": ["finding.opened"],
                          "min_severity": "high", "secrets": {"webhook_url": "https://hooks.example.com/T0/B0/SECRET123"}}],
        "scope_suggestions": [{"kind": "domain", "value": "Customer.Example"}],
    }


async def test_template_apply_to_many_customers(client, world, db_pool, fake_dns, secret_key):
    r = await client.post("/v1/msp/templates", headers=_h(world["root"]), json=_template_body())
    assert r.status_code == 201, r.text
    tpl = r.json()
    assert "SECRET123" not in json.dumps(tpl)
    assert tpl["spec"]["integrations"][0]["secrets"] == {"webhook_url": "********"}
    assert (await client.get("/v1/msp/templates", headers=_h(world["root"]))).status_code == 200
    assert "SECRET123" not in (await client.get("/v1/msp/templates", headers=_h(world["root"]))).text

    # A and B are root's; X is another MSP's customer -> refused, nothing written there.
    r = await client.post(f"/v1/msp/templates/{tpl['id']}/apply", headers=_h(world["root"]),
                          json={"customer_ids": [world["a"]["id"], world["b"]["id"], world["x"]["id"]]})
    assert r.status_code == 200, r.text
    res = {x["customer_id"]: x for x in r.json()["results"]}
    assert res[world["a"]["id"]]["status"] == "applied"
    assert res[world["a"]["id"]]["created"] == {"alert_rules": 1, "integrations": 1, "scope_suggestions": 1}
    assert res[world["b"]["id"]]["status"] == "applied"
    assert res[world["x"]["id"]]["status"] == "failed"

    async with db_pool.acquire() as con:
        for cid, expect in ((world["a"]["id"], 1), (world["b"]["id"], 1), (world["x"]["id"], 0),
                            (MSP_ID, 0), (tenancy.DEFAULT_TENANT_ID, 0)):
            assert await con.fetchval("SELECT COUNT(*) FROM alert_rules WHERE tenant_id = $1 AND name = 'msp-high'",
                                      cid) == expect, cid
            assert await con.fetchval("SELECT COUNT(*) FROM integrations WHERE tenant_id = $1 AND name = 'msp-psa'",
                                      cid) == expect, cid
        # scope suggestions are INACTIVE: a template never widens a customer's scope
        rows = await con.fetch("SELECT value, active, added_by FROM scope_entries WHERE tenant_id = $1",
                               world["a"]["id"])
        assert [(r["value"], r["active"]) for r in rows] == [("customer.example", False)]
        sec = await con.fetchval("SELECT secrets FROM integrations WHERE tenant_id = $1 AND name = 'msp-psa'",
                                 world["a"]["id"])
        assert sec and "SECRET123" not in sec        # encrypted at rest

    # idempotent re-apply
    r = await client.post(f"/v1/msp/templates/{tpl['id']}/apply", headers=_h(world["root"]),
                          json={"customer_ids": [world["a"]["id"]]})
    assert r.json()["results"][0]["status"] == "skipped"
    # audited in both trails with the acting MSP user
    arow = [x for x in await _audit_rows(db_pool, world["a"]["id"]) if x["action"] == "msp.template_applied"]
    assert arow and arow[0]["actor"] == "msp:msp-one/root"
    assert any(x["action"] == "msp.template_applied" and x["actor"] == "root" for x in await _audit_rows(db_pool, MSP_ID))


async def test_template_needs_an_admin_grant_per_customer(client, world, fake_dns, secret_key, db_pool):
    tpl = (await client.post("/v1/msp/templates", headers=_h(world["root"]), json=_template_body("t2"))).json()
    # make bea an MSP admin of the MSP but only an ANALYST on A
    async with db_pool.acquire() as con:
        await con.execute("UPDATE app_users SET role = 'admin' WHERE id = $1", world["bea_id"])
    r = await client.post(f"/v1/msp/templates/{tpl['id']}/apply", headers=_h(world["bea"]),
                          json={"customer_ids": [world["a"]["id"]]})
    assert r.status_code == 200
    assert r.json()["results"][0]["status"] == "failed"
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT COUNT(*) FROM alert_rules WHERE tenant_id = $1", world["a"]["id"]) == 0


async def test_template_validation_rejects_bad_input(client, world, fake_dns, secret_key):
    bad = _template_body("bad")
    bad["integrations"][0]["kind"] = "no-such-connector"
    assert (await client.post("/v1/msp/templates", headers=_h(world["root"]), json=bad)).status_code == 422
    bad = _template_body("bad2")
    bad["alert_rules"][0]["target"] = "ftp://nope"
    assert (await client.post("/v1/msp/templates", headers=_h(world["root"]), json=bad)).status_code == 422
    bad = _template_body("bad3")
    bad["scope_suggestions"] = [{"kind": "ipv4_cidr", "value": "0.0.0.0/0"}]
    assert (await client.post("/v1/msp/templates", headers=_h(world["root"]), json=bad)).status_code == 422
    bad = _template_body("bad4")
    bad["integrations"][0]["secrets"] = {"not_a_field": "x"}
    assert (await client.post("/v1/msp/templates", headers=_h(world["root"]), json=bad)).status_code == 422


async def test_templates_are_private_to_their_msp(client, world, fake_dns, secret_key):
    tpl = (await client.post("/v1/msp/templates", headers=_h(world["root"]), json=_template_body("mine"))).json()
    assert (await client.get("/v1/msp/templates", headers=_h(world["boss2"]))).json()["items"] == []
    r = await client.post(f"/v1/msp/templates/{tpl['id']}/apply", headers=_h(world["boss2"]),
                          json={"customer_ids": [world["x"]["id"]]})
    assert r.status_code == 404
    assert (await client.delete(f"/v1/msp/templates/{tpl['id']}", headers=_h(world["boss2"]))).status_code == 404
    assert (await client.delete(f"/v1/msp/templates/{tpl['id']}", headers=_h(world["root"]))).status_code == 200


# --------------------------------------------------------------------------- #
# Usage / billing
# --------------------------------------------------------------------------- #

async def test_usage_per_child_json_csv_and_snapshots(client, world, db_pool):
    await _seed_findings(db_pool, world["a"]["id"], criticals=1, assets=3, scan=True)
    await _seed_findings(db_pool, world["x"]["id"], assets=9)
    await client.post("/v1/msp/customers", headers=_h(world["root"]), json={"slug": "evil", "name": "=HYPERLINK(\"x\")"})
    r = await client.get("/v1/msp/usage", headers=_h(world["root"]))
    assert r.status_code == 200
    rep = r.json()
    by = {i["slug"]: i for i in rep["items"]}
    assert set(by) == {"cust-a", "cust-b", "evil"}          # never the other MSP's customer
    assert by["cust-a"]["monitored_assets"] == 3 and by["cust-a"]["scans_month"] == 1
    assert by["cust-b"]["monitored_assets"] == 0
    assert rep["totals"]["monitored_assets"] == 3

    snap = await client.post("/v1/msp/usage/snapshot", headers=_h(world["root"]))
    assert snap.status_code == 200 and snap.json()["snapshotted"] == 3
    rep2 = (await client.get("/v1/msp/usage", headers=_h(world["root"]))).json()
    assert {i["slug"]: i["snapshot_days"] for i in rep2["items"]}["cust-a"] == 1

    c = await client.get("/v1/msp/usage", headers=_h(world["root"]), params={"format": "csv"})
    assert c.status_code == 200 and c.headers["content-type"].startswith("text/csv")
    assert "attachment" in c.headers["content-disposition"]
    lines = c.text.strip().split("\n")
    assert lines[0].startswith("customer_id,slug,name,month,source")
    assert any(l.split(",")[1] == "cust-a" for l in lines[1:])
    assert not any(l.split(",")[1] == "cust-x" for l in lines[1:])
    # formula injection is neutralised
    assert "'=HYPERLINK" in c.text and ",=HYPERLINK" not in c.text.replace('"', "")
    # past month with no snapshots falls back to live, flagged
    past = (await client.get("/v1/msp/usage", headers=_h(world["root"]), params={"month": "2020-01"})).json()
    assert past["month"] == "2020-01" and past["items"][0]["source"].startswith("live")
    assert (await client.get("/v1/msp/usage", headers=_h(world["root"]), params={"month": "2020-13"})
            ).status_code == 422
    # viewer-level MSP users cannot read billing
    assert (await client.get("/v1/msp/usage", headers=_h(world["bea"]))).status_code == 403


async def test_usage_only_covers_the_callers_grants(client, world):
    await client.post("/v1/msp/grants", headers=_h(world["root"]),
                      json={"user_id": world["otto_id"], "customer_id": world["b"]["id"], "role": "viewer"})
    # make otto an MSP admin without touching the grants
    # (done via direct SQL in other tests; here prove root's view is the union of ITS grants)
    rep = (await client.get("/v1/msp/usage", headers=_h(world["root"]))).json()
    assert {i["slug"] for i in rep["items"]} == {"cust-a", "cust-b"}


# --------------------------------------------------------------------------- #
# Misc
# --------------------------------------------------------------------------- #

async def test_me_for_msp_user_and_unauthenticated_access(client, world):
    me = (await client.get("/v1/msp/me", headers=_h(world["root"]))).json()
    assert me["is_msp"] is True and me["mode"] == "msp" and me["org"]["name"] == "MSP One"
    assert (await client.get("/v1/msp/customers")).status_code == 401
    assert (await client.post("/v1/msp/customers/%s/switch" % world["a"]["id"])).status_code == 401


async def test_switch_token_lifetime_is_short(client, world):
    sw = (await _switch(client, world["root"], world["a"]["id"])).json()
    assert 60 <= sw["expires_in"] <= 3600
    claims = jwt.decode(sw["access_token"], options={"verify_signature": False})
    assert claims["exp"] - claims["iat"] == sw["expires_in"] and claims["typ"] == "msp_switch"
    assert claims["tid"] == world["a"]["id"] and claims["mtid"] == MSP_ID


async def test_concurrent_switches_do_not_cross_tenants(client, world, db_pool):
    """ContextVar isolation: simultaneous requests for A and B each see only
    their own data."""
    await _seed_findings(db_pool, world["a"]["id"], criticals=2)
    await _seed_findings(db_pool, world["b"]["id"], highs=1)
    ta = (await _switch(client, world["root"], world["a"]["id"])).json()["access_token"]
    tb = (await _switch(client, world["root"], world["b"]["id"])).json()["access_token"]

    async def sev(tok):
        r = await client.get("/v1/findings", headers=_h(tok), params={"limit": 100})
        j = r.json()
        return sorted(i["severity"] for i in (j["items"] if isinstance(j, dict) else j))

    outs = await asyncio.gather(*[sev(ta if i % 2 == 0 else tb) for i in range(12)])
    for i, o in enumerate(outs):
        assert o == (["critical", "critical"] if i % 2 == 0 else ["high"])
