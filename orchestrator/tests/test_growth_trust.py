"""Shareable trust pages: token, expiry, revocation, password, aggregate-only
output, per-view audit, and tenant isolation of the public lookup."""
from __future__ import annotations

import base64
import json
import re
from datetime import datetime, timezone

import pytest
import pytest_asyncio

from app import auth as auth_svc
from app import tenancy
from app.config import settings
from app.growth import trust
from app.growth.config import growth_settings
from tests.reports_seed import seed_demo

TENANT_A = tenancy.DEFAULT_TENANT_ID
TENANT_B = "00000000-0000-0000-0000-0000000000b2"
ALL = ["grade", "verified_fixes", "sla", "compliance", "coverage"]
NOW = datetime.now(timezone.utc)

# Things that must never appear on a public trust page.
SEEDED_LEAKS = ["acme-demo.example", "203.0.113.", "Citrix", "NetScaler", "Grafana", "subdomain-takeover",
                "exposed-dotenv", "CVE-2024-3400", "AWS access key", "grafana", "asset_value", "rule_id"]


@pytest.fixture
def enforce():
    prev = settings.auth_mode
    settings.auth_mode = "enforce"
    try:
        yield
    finally:
        settings.auth_mode = prev


async def _admin(db_pool, tenant_id, username, role="admin"):
    full, prefix, key_hash = auth_svc.generate_api_key()
    async with db_pool.acquire() as con:
        uid = await con.fetchval(
            "INSERT INTO app_users (username, role, clearance, pw_hash, tenant_id) "
            "VALUES ($1,$2,'restricted',$3,$4) RETURNING id",
            username, role, auth_svc.hash_password("pw-" + username), tenant_id,
        )
        await con.execute(
            "INSERT INTO api_keys (user_id, name, prefix, key_hash, scopes, tenant_id) VALUES ($1,'k',$2,$3,$4::text[],$5)",
            uid, prefix, key_hash, sorted(auth_svc.ROLE_CAPABILITIES[role]), tenant_id,
        )
    return {"Authorization": f"Bearer {full}"}


@pytest_asyncio.fixture
async def env(enforce, app, app_pool, db_pool, client):
    """Tenant A (default, empty) and tenant B (full demo data), served through RLS."""
    app.state.pool = app_pool
    await tenancy.create_tenant(db_pool, slug="bravo", name="Bravo", tenant_id=TENANT_B)
    with tenancy.tenant_context(TENANT_B):
        await seed_demo(app_pool, NOW)
    return {
        "a": await _admin(db_pool, TENANT_A, "alice"),
        "b": await _admin(db_pool, TENANT_B, "bob"),
        "viewer": await _admin(db_pool, TENANT_B, "vera", role="viewer"),
    }


async def mint(client, hdr, **kw):
    body = {"label": "for the insurer", "sections": ALL, "expires_in_days": 30, **kw}
    r = await client.post("/v1/trust-links", headers=hdr, json=body)
    assert r.status_code == 201, r.text
    return r.json()


async def view(client, token, **kw):
    return await client.get(f"/v1/public/trust/{token}", **kw)


# --------------------------------------------------------------------------- #
# tokens
# --------------------------------------------------------------------------- #

def test_token_entropy_format_and_signature():
    toks = {trust.new_token() for _ in range(2000)}
    assert len(toks) == 2000
    t = next(iter(toks))
    prefix, body, sig = t.split(".")
    assert prefix == "pt1"
    assert len(base64.urlsafe_b64decode(body + "=")) == 32  # 256 bits
    assert trust.token_well_formed(t)
    assert not trust.token_well_formed(t[:-2] + ("AA" if not t.endswith("AA") else "BB"))
    assert not trust.token_well_formed(f"pt1.{body}.{'A' * 22}")
    assert not trust.token_well_formed("pt1." + body)
    assert not trust.token_well_formed("x" * 500)
    assert not trust.token_well_formed(None)  # type: ignore[arg-type]
    # bits spread across the whole body: no constant positions
    assert len({x.split(".")[1][5] for x in toks}) > 20


def test_signing_key_rotation(monkeypatch):
    k1 = base64.urlsafe_b64encode(b"1" * 32).decode()
    k2 = base64.urlsafe_b64encode(b"2" * 32).decode()
    monkeypatch.setenv("PADDOCK_SECRET_KEY", k1)
    monkeypatch.delenv("PADDOCK_SECRET_KEY_OLD", raising=False)
    old = trust.new_token()
    assert trust.token_well_formed(old)
    monkeypatch.setenv("PADDOCK_SECRET_KEY", k2)
    assert not trust.token_well_formed(old)  # signed by a retired key
    monkeypatch.setenv("PADDOCK_SECRET_KEY_OLD", k1)
    assert trust.token_well_formed(old)  # still honoured during rotation
    assert trust.token_well_formed(trust.new_token())


async def test_only_the_hash_is_stored(env, client, db_pool):
    made = await mint(client, env["b"])
    token = made["token"]
    assert made["path"] == f"/trust/{token}" and made["status"] == "active"
    async with db_pool.acquire() as con:
        row = await con.fetchrow("SELECT * FROM trust_links")
    assert token not in json.dumps(dict(row), default=str)
    assert row["token_hash"] == trust.hash_token(token) and row["token_hint"] == row["token_hash"][-4:]
    listed = (await client.get("/v1/trust-links", headers=env["b"])).json()
    assert len(listed) == 1 and token not in json.dumps(listed) and "token" not in listed[0]


# --------------------------------------------------------------------------- #
# aggregates only
# --------------------------------------------------------------------------- #

async def test_view_returns_chosen_sections_as_aggregates_only(env, client):
    made = await mint(client, env["b"])
    r = await view(client, made["token"])  # anonymous: no Authorization header
    assert r.status_code == 200, r.text
    assert r.headers["cache-control"] == "no-store" and "noindex" in r.headers["x-robots-tag"]
    body = r.json()
    assert set(body["sections"]) == set(ALL) and set(body["data"]) == set(ALL)
    g = body["data"]["grade"]
    assert g["grade"] in "ABCDF" and set(g["open_by_severity"]) >= {"critical", "high"}
    assert body["data"]["verified_fixes"]["fixed"] > 0
    assert body["data"]["sla"]["by_severity"] and "breaches" not in body["data"]["sla"]
    assert body["data"]["compliance"] and "counts" in body["data"]["compliance"][0]
    assert body["data"]["coverage"]["assets_total"] > 0

    raw = r.text
    for leak in SEEDED_LEAKS:
        assert leak not in raw, leak
    assert not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", raw), "an IP address leaked"
    assert not re.search(r"\b[a-z0-9-]+\.(acme|example)\b", raw)
    # nothing tenant-ish or internal either
    for k in ("tenant", TENANT_B, "label", "for the insurer", "created_by", "bob"):
        assert k not in raw, k


async def test_only_selected_sections_are_returned(env, client):
    made = await mint(client, env["b"], sections=["sla", "grade"])
    body = (await view(client, made["token"])).json()
    assert body["sections"] == ["grade", "sla"] and set(body["data"]) == {"grade", "sla"}


async def test_empty_and_unknown_sections_rejected(env, client):
    for bad in ([], ["findings"], ["grade", "hosts"]):
        r = await client.post("/v1/trust-links", headers=env["b"], json={"label": "x", "sections": bad})
        assert r.status_code == 422


async def test_each_view_is_audited_with_a_running_count(env, client, db_pool):
    made = await mint(client, env["b"], sections=["grade"])
    for _ in range(3):
        assert (await view(client, made["token"])).status_code == 200
    async with db_pool.acquire() as con:
        rows = await con.fetch(
            "SELECT tenant_id, actor, action, details, ip FROM audit_log WHERE resource_type = 'trust_link' "
            "AND action = 'read' ORDER BY id"
        )
        count = await con.fetchval("SELECT view_count FROM trust_links")
    assert count == 3 and len(rows) == 3
    assert [json.loads(r["details"])["view_count"] for r in rows] == [1, 2, 3]
    assert all(str(r["tenant_id"]) == TENANT_B and r["actor"].startswith("trust-link:") for r in rows)
    assert json.loads(rows[0]["details"])["sections"] == ["grade"]
    listed = (await client.get("/v1/trust-links", headers=env["b"])).json()
    assert listed[0]["view_count"] == 3 and listed[0]["last_viewed_at"]
    # the audit chain of the other tenant is untouched
    async with db_pool.acquire() as con:
        assert await con.fetchval(
            "SELECT COUNT(*) FROM audit_log WHERE tenant_id = $1 AND resource_type = 'trust_link'", TENANT_A
        ) == 0


async def test_aggregates_are_cached_but_views_still_counted(env, client, monkeypatch):
    calls = []
    real = trust.build_sections

    async def spy(*a, **k):
        calls.append(1)
        return await real(*a, **k)

    monkeypatch.setattr(trust, "build_sections", spy)
    made = await mint(client, env["b"], sections=["grade"])
    for _ in range(3):
        assert (await view(client, made["token"])).status_code == 200
    assert len(calls) == 1


# --------------------------------------------------------------------------- #
# expiry / revocation / forgery
# --------------------------------------------------------------------------- #

async def test_expired_link_is_unavailable(env, client, db_pool):
    made = await mint(client, env["b"])
    assert (await view(client, made["token"])).status_code == 200
    async with db_pool.acquire() as con:
        await con.execute("UPDATE trust_links SET expires_at = NOW() - interval '1 second'")
    r = await view(client, made["token"])
    assert r.status_code == 404 and r.json()["detail"] == "this link is not available"
    assert (await client.get("/v1/trust-links", headers=env["b"])).json()[0]["status"] == "expired"


async def test_revocation_is_immediate_and_idempotent(env, client):
    made = await mint(client, env["b"])
    assert (await view(client, made["token"])).status_code == 200
    r = await client.delete(f"/v1/trust-links/{made['id']}", headers=env["b"])
    assert r.status_code == 200 and r.json()["status"] == "revoked"
    first = r.json()["revoked_at"]
    r = await view(client, made["token"])
    assert r.status_code == 404 and r.json()["detail"] == "this link is not available"
    again = await client.delete(f"/v1/trust-links/{made['id']}", headers=env["b"])
    assert again.json()["revoked_at"] == first
    # history is kept
    assert (await client.get("/v1/trust-links", headers=env["b"])).json()[0]["view_count"] == 1


async def test_expiry_cannot_exceed_the_cap(env, client):
    r = await client.post("/v1/trust-links", headers=env["b"], json={"label": "x", "expires_in_days": 4000})
    assert r.status_code == 422


async def test_forged_unknown_and_malformed_tokens_all_look_alike(env, client, db_pool):
    made = await mint(client, env["b"])
    t = made["token"]
    forged = t[:-3] + ("AAA" if not t.endswith("AAA") else "BBB")
    unknown = trust.new_token()  # well-formed, but never issued
    for bad in (forged, unknown, "pt1.short.sig", "x", "pt1." + "A" * 43 + "." + "B" * 22):
        r = await view(client, bad)
        assert r.status_code == 404 and r.json() == {"detail": "this link is not available"}, bad
    assert (await view(client, "a" * 300)).status_code == 404


# --------------------------------------------------------------------------- #
# password
# --------------------------------------------------------------------------- #

async def test_password_protected_link(env, client, db_pool):
    made = await mint(client, env["b"], password="correct horse battery")
    assert made["password_protected"] is True
    async with db_pool.acquire() as con:
        h = await con.fetchval("SELECT password_hash FROM trust_links")
    assert h.startswith("bcrypt$") and "correct horse" not in h

    t = made["token"]
    r = await view(client, t)
    assert r.status_code == 401 and r.json()["detail"] == {"code": "password_required"}
    r = await client.post(f"/v1/public/trust/{t}", json={"password": "wrong password"})
    assert r.status_code == 401 and r.json()["detail"]["code"] == "password_incorrect"
    r = await client.post(f"/v1/public/trust/{t}", json={"password": "correct horse battery"})
    assert r.status_code == 200 and "grade" in r.json()["data"]
    r = await view(client, t, headers={"X-Trust-Password": "correct horse battery"})
    assert r.status_code == 200
    # failed attempts are audited as denials; successes as reads
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT COUNT(*) FROM audit_log WHERE action='deny' AND resource_type='trust_link'") == 1
        assert await con.fetchval("SELECT COUNT(*) FROM audit_log WHERE action='read' AND resource_type='trust_link'") == 2


async def test_password_guessing_is_throttled(env, client, monkeypatch):
    monkeypatch.setattr(growth_settings, "trust_max_password_attempts", 3)
    t = (await mint(client, env["b"], password="correct horse battery"))["token"]
    codes = [(await client.post(f"/v1/public/trust/{t}", json={"password": f"guess-{i}"})).status_code for i in range(5)]
    assert codes == [401, 401, 401, 429, 429]
    # even the right password is refused while throttled
    assert (await client.post(f"/v1/public/trust/{t}", json={"password": "correct horse battery"})).status_code == 429


async def test_short_password_rejected(env, client):
    r = await client.post("/v1/trust-links", headers=env["b"], json={"label": "x", "password": "short"})
    assert r.status_code == 422


# --------------------------------------------------------------------------- #
# access control + tenant isolation
# --------------------------------------------------------------------------- #

async def test_management_is_admin_only(env, client):
    for method, path, kw in (("get", "/v1/trust-links", {}), ("post", "/v1/trust-links", {"json": {"label": "x"}})):
        assert (await getattr(client, method)(path, headers=env["viewer"], **kw)).status_code == 403
    made = await mint(client, env["b"])
    assert (await client.delete(f"/v1/trust-links/{made['id']}", headers=env["viewer"])).status_code == 403


async def test_a_tenant_cannot_see_or_revoke_anothers_links(env, client):
    made = await mint(client, env["b"])
    assert (await client.get("/v1/trust-links", headers=env["a"])).json() == []
    assert (await client.delete(f"/v1/trust-links/{made['id']}", headers=env["a"])).status_code == 404
    assert (await view(client, made["token"])).status_code == 200  # still live


async def test_public_view_is_scoped_to_the_links_own_tenant(env, client, db_pool):
    """Tenant A's link must show A's (empty) numbers, never B's."""
    a_link = await mint(client, env["a"], sections=["coverage"])
    b_link = await mint(client, env["b"], sections=["coverage"])
    a = (await view(client, a_link["token"])).json()["data"]["coverage"]
    b = (await view(client, b_link["token"])).json()["data"]["coverage"]
    assert a["assets_total"] == 0 and b["assets_total"] > 0


async def test_rls_lookup_policy_cannot_enumerate(env, client, app_pool):
    made = await mint(client, env["b"])
    h = trust.hash_token(made["token"])

    async def count(setup: str, *args) -> int:
        with tenancy.auth_lookup():
            async with app_pool.acquire() as con:
                async with con.transaction():
                    if setup:
                        await con.execute(setup, *args)
                    return await con.fetchval("SELECT COUNT(*) FROM trust_links")

    assert await count("") == 0  # no tenant, no lookup GUC
    assert await count("SELECT set_config('app.trust_lookup','on',true)") == 0  # lookup on, no hash
    assert await count("SELECT set_config('app.trust_lookup','on',true), set_config('app.trust_hash',$1,true)", "0" * 64) == 0
    assert await count("SELECT set_config('app.trust_hash',$1,true)", h) == 0  # hash alone is not enough
    assert await count("SELECT set_config('app.trust_lookup','on',true), set_config('app.trust_hash',$1,true)", h) == 1
    with tenancy.tenant_context(TENANT_A):  # another tenant's normal session
        async with app_pool.acquire() as con:
            assert await con.fetchval("SELECT COUNT(*) FROM trust_links") == 0
    with tenancy.tenant_context(TENANT_B):
        async with app_pool.acquire() as con:
            assert await con.fetchval("SELECT COUNT(*) FROM trust_links") == 1
            # the policy is read-only: a viewer-side transaction cannot use it to write
    with tenancy.auth_lookup():
        async with app_pool.acquire() as con:
            async with con.transaction():
                await con.execute(
                    "SELECT set_config('app.trust_lookup','on',true), set_config('app.trust_hash',$1,true)", h
                )
                n = await con.fetchval("WITH u AS (UPDATE trust_links SET view_count = 99 RETURNING 1) SELECT COUNT(*) FROM u")
    assert n == 0
