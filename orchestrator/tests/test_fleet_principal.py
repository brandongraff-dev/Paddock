"""The agent principal and the RBAC around it (docs/ASSURANCE_P2.md section 6; app/auth.py, routers/fleet.py).

``agent`` is a capability that is NOT a role: it is in no ``ROLE_CAPABILITIES`` entry and is no valid API-key scope,
so no user, key or service credential can ever post agent evidence, and an agent credential can never be anything
but an agent. The legacy hard cut (O3) answers 403 ``re_enroll_required`` on every route and keeps rows and history.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from app import auth as auth_svc
from app.config import settings

from .test_fleet_posture import (  # noqa: F401  (fixtures + helpers shared with the ingest tests)
    TENANT_A,
    TENANT_B,
    Host,
    agent_row,
    audits,
    build_envelope,
    canon,
    enroll_host,
    enforce,
    good_posture,
    hb,
    hdr,
    jd,
    key_row,
    ps,
    post,
    posture_rows,
    rls_app,
    seed_key,
    world,
    _reset_limiters,
)

UUID0 = "00000000-0000-0000-0000-000000000000"
UUID1 = "11111111-1111-4111-8111-111111111111"


# =========================================================================== #
# `agent` is a capability of its own
# =========================================================================== #

def test_agent_is_not_a_role_not_a_scope_and_held_by_no_other_principal():
    assert "agent" not in auth_svc.ROLE_CAPABILITIES
    assert all("agent" not in caps for caps in auth_svc.ROLE_CAPABILITIES.values())
    assert "agent" not in auth_svc._VALID_SCOPES
    for role in list(auth_svc.ROLE_CAPABILITIES) + ["agent", "scim", "nope"]:
        assert "agent" not in auth_svc.capabilities_for(role)
        assert "agent" not in auth_svc.capabilities_for(role, {"agent", "admin", "read"})   # a key scope cannot add it
    assert not auth_svc.dev_principal().has("agent") and not auth_svc.service_principal().has("agent")


@pytest.mark.parametrize("method,path,cap", [
    ("POST", "/v1/fleet/enroll", None),
    ("POST", "/v1/fleet/enroll/", None),
    ("POST", f"/v1/fleet/{UUID1}/heartbeat", "agent"),
    ("POST", f"/v1/fleet/{UUID1}/posture", "agent"),
    ("POST", f"/v1/fleet/{UUID1}/inventory", "agent"),
    ("POST", f"/v1/fleet/{UUID1}/keys/rotate", "agent"),
    ("POST", f"/v1/fleet/{UUID1.upper()}/heartbeat", "agent"),
    ("POST", f"/v1/fleet/actions/{UUID1}/result", "agent"),
    ("GET", "/v1/fleet/enroll-tokens", "admin"),
    ("POST", "/v1/fleet/enroll-tokens", "admin"),
    ("GET", f"/v1/fleet/enroll-tokens/{UUID1}", "admin"),
    ("DELETE", f"/v1/fleet/enroll-tokens/{UUID1}", "admin"),
    ("POST", f"/v1/fleet/agents/{UUID1}/revoke", "admin"),
    ("POST", f"/v1/fleet/agents/{UUID1}/keys/{'a' * 32}/revoke", "admin"),
    ("GET", f"/v1/fleet/agents/{UUID1}/posture", "triage"),
    ("GET", "/v1/fleet/agents/not-a-uuid/posture", "triage"),       # a malformed id must not fall to `read`
    ("GET", "/v1/fleet/agents", "read"),
    ("GET", f"/v1/fleet/agents/{UUID1}", "read"),
    ("GET", "/v1/fleet/actions", "read"),
    ("POST", "/v1/fleet/actions", "admin"),
    ("POST", f"/v1/fleet/actions/{UUID1}/approve", "admin"),
    ("POST", f"/v1/fleet/actions/{UUID1}/revert", "admin"),
    # anchored UUID patterns cannot be tricked into shadowing or being shadowed
    ("POST", "/v1/fleet/actions/heartbeat", "admin"),
    ("POST", "/v1/fleet/actions/posture", "admin"),
    ("POST", "/v1/fleet/network-actions/heartbeat", "admin"),
    ("POST", "/v1/fleet/not-a-uuid/heartbeat", "admin"),
    ("POST", f"/v1/fleet/{UUID1}/heartbeat/extra", "admin"),
    ("POST", f"/v1/fleet/{UUID1}x/heartbeat", "admin"),
    ("POST", f"/v1/fleet/actions/{UUID1}/result/x", "admin"),
    ("GET", f"/v1/fleet/{UUID1}/heartbeat", "read"),                # GET is not an agent route
    ("PUT", f"/v1/fleet/{UUID1}/heartbeat", "admin"),
    ("DELETE", f"/v1/fleet/{UUID1}/posture", "admin"),
])
def test_required_capability_table(method, path, cap):
    assert auth_svc.required_capability(method, path) == cap


def test_data_plane_exemption_covers_heartbeat_and_posture_only():
    dp = auth_svc._SENSOR_DATA_PLANE
    assert dp.match(f"/v1/fleet/{UUID1}/heartbeat") and dp.match(f"/v1/fleet/{UUID1}/posture/")
    assert dp.match("/v1/sensors/heartbeat") and dp.match("/v1/sensors/ingest/claim")
    for no in (f"/v1/fleet/{UUID1}/keys/rotate", f"/v1/fleet/{UUID1}/inventory", f"/v1/fleet/actions/{UUID1}/result",
               "/v1/fleet/enroll", "/v1/fleet/enroll-tokens", f"/v1/fleet/agents/{UUID1}/revoke",
               "/v1/fleet/actions/heartbeat", "/v1/fleet/x/heartbeat", f"/v1/fleet/{UUID1}/heartbeat/x"):
        assert not dp.match(no), no


# =========================================================================== #
# nothing but an agent principal reaches the agent routes; an agent reaches nothing else
# =========================================================================== #

def _routes(app):
    """Every documented (method, path template) of the app."""
    out = set()
    for path, ops in app.openapi()["paths"].items():
        for method in ops:
            if method.upper() in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                out.add((method.upper(), path))
    return sorted(out)


async def test_an_agent_credential_reaches_no_route_that_is_not_an_agent_or_public_route(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    app = c._transport.app
    seen = 0
    leaks = []
    for method, tpl in _routes(app):
        path = re.sub(r"\{[^}]+\}", UUID1, tpl)
        if auth_svc._is_exempt(path):
            continue
        cap = auth_svc.required_capability(method, path)
        if cap in (None, "agent"):
            continue
        r = await c.request(method, path, headers={"X-Agent-Token": host.token}, content=b"{}")
        seen += 1
        if r.status_code != 403:
            leaks.append((method, tpl, r.status_code))
    assert seen > 100, seen                 # the sweep is real: every other route of the app
    assert leaks == []


async def test_no_user_key_or_service_credential_can_post_agent_evidence(world, monkeypatch):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    monkeypatch.setattr(settings, "service_api_key", "svc-secret-key")
    creds = {
        "admin": hdr(world.admin_a), "analyst": hdr(world.analyst_a), "viewer": hdr(world.viewer_a),
        "service": {"X-API-Key": "svc-secret-key"},
    }
    routes = {
        "heartbeat": host.env("heartbeat"), "posture": host.env("posture"),
        "inventory": b"{}", "keys/rotate": host.env("rotate", b"{}"),
    }
    for who, h in creds.items():
        for route, body in routes.items():
            raw = body if isinstance(body, bytes) else json.dumps(body).encode()
            r = await c.post(f"/v1/fleet/{host.agent_id}/{route}", content=raw,
                             headers={**h, "Content-Type": "application/json"})
            assert r.status_code == 403, (who, route, r.status_code)
        r = await c.post(f"/v1/fleet/actions/{uuid.uuid4()}/result", json={"status": "failed", "output": {}}, headers=h)
        assert r.status_code == 403, (who, "result")
    assert await posture_rows(world.db, host.agent_id) == []
    assert (await key_row(world.db, host.agent_id, host.kid))["last_seq"] == 0


async def test_dev_mode_admin_cannot_post_agent_evidence_either(db_pool, rls_app):
    prev = settings.auth_mode
    settings.auth_mode = "dev"
    try:
        async with AsyncClient(transport=ASGITransport(app=rls_app), base_url="http://test") as c:
            r = await c.post(f"/v1/fleet/{UUID1}/heartbeat", json={})
            assert r.status_code == 403                  # the synthetic dev admin has no `agent` capability
            r = await c.post(f"/v1/fleet/actions/{UUID1}/result", json={"status": "failed", "output": {}})
            assert r.status_code == 403
    finally:
        settings.auth_mode = prev


async def test_an_agent_credential_never_combines_with_another_credential(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    r = await c.get("/v1/fleet/agents", headers={**hdr(world.admin_a), "X-Agent-Token": host.token})
    assert r.status_code == 403                          # the agent token wins: the admin key is not consulted
    r = await c.get("/v1/fleet/agents", headers={**hdr(world.admin_a), "X-Agent-Token": "fat_deadbeef0000_xxx"})
    assert r.status_code == 401                          # and a bad one is a 401 even with a good admin key
    # the agent token is not accepted as a bearer credential
    r = await c.get("/v1/fleet/agents", headers={"Authorization": f"Bearer {host.token}"})
    assert r.status_code == 401
    r = await c.get("/v1/fleet/agents", headers={"X-API-Key": host.token})
    assert r.status_code == 401


async def test_every_agent_route_asserts_the_path_id_is_the_principals(world):
    c = world.client
    a = await enroll_host(c, world.admin_a, "web-1")
    b = await enroll_host(c, world.admin_a, "web-2")          # the SAME tenant: only the id check separates them
    for route in ("heartbeat", "posture", "keys/rotate", "inventory"):
        r = await c.post(f"/v1/fleet/{a.agent_id}/{route}", headers=b.h, content=b"{}")
        assert r.status_code == 403, route
    assert (await key_row(world.db, a.agent_id, a.kid))["last_seq"] == 0
    # b's own signed envelope for a's id: still the principal's id that decides
    r = await post(c, b, "heartbeat", build_envelope(b.sk, agent_id=a.agent_id, tenant_id=a.tenant_id,
                                                     kind="heartbeat", seq=1, payload=b"{}"), agent_id=a.agent_id)
    assert r.status_code == 403


# =========================================================================== #
# credential resolution: no oracle, nothing cached
# =========================================================================== #

async def test_bad_agent_tokens_are_one_generic_401(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    secret = host.token.split("_", 2)[2]
    prefix = host.token.split("_")[1]
    bodies = set()
    for bad in (host.token[:-2] + ("aa" if not host.token.endswith("aa") else "bb"),      # wrong secret
                f"fat_{'0' * 12}_{secret}",                                                  # unknown prefix
                f"fat_{prefix}_short", "fat_", "garbage", f"fet_{prefix}_{secret}", f"fat_{prefix.upper()}_{secret}",
                f"fat_{prefix}_{secret}\u00e9".encode("latin-1"), "fat_" + "x" * 5000):
        r = await c.post(f"/v1/fleet/{host.agent_id}/heartbeat", headers={"X-Agent-Token": bad}, content=b"{}")
        assert r.status_code == 401, bad
        bodies.add(json.dumps(r.json(), sort_keys=True))
    assert len(bodies) == 1                                  # unknown, malformed and wrong-secret look the same
    r = await c.post(f"/v1/fleet/{host.agent_id}/heartbeat", headers={"X-Agent-Token": ""}, content=b"{}")
    assert r.status_code == 401
    assert (await hb(c, host)).status_code == 200            # the real one is untouched


async def test_a_suspended_tenant_stops_its_agents(world):
    c = world.client
    host = await enroll_host(c, world.admin_b, "web-b")
    assert (await hb(c, host)).status_code == 200
    await world.db.execute("UPDATE tenants SET status='suspended' WHERE id=$1", uuid.UUID(TENANT_B))
    r = await hb(c, host)
    assert r.status_code == 401 and "suspended" in r.json()["detail"]


async def test_revocation_is_immediate_on_every_agent_route_and_audited_in_the_agents_tenant(world):
    c = world.client
    host = await enroll_host(c, world.admin_b, "web-b")
    assert (await hb(c, host)).status_code == 200
    assert (await c.post(f"/v1/fleet/agents/{host.agent_id}/revoke", headers=hdr(world.admin_b),
                         json={})).status_code == 200
    for route in ("heartbeat", "posture", "keys/rotate", "inventory"):
        r = await c.post(f"/v1/fleet/{host.agent_id}/{route}", headers=host.h, content=b"{}")
        assert r.status_code == 403 and r.json()["error"] == "agent_revoked", route
    r = await c.get("/v1/fleet/agents", headers={"X-Agent-Token": host.token})
    assert r.status_code == 403 and r.json()["error"] == "agent_revoked"
    rows = await world.db.fetch("SELECT tenant_id, actor FROM audit_log WHERE action='deny' AND actor=$1",
                                f"agent:{host.hostname}")
    assert rows and all(str(x["tenant_id"]) == TENANT_B for x in rows)


# =========================================================================== #
# the legacy hard cut (O3)
# =========================================================================== #

async def _legacy_agent(db, tenant_id: str, hostname: str = "old-1", prefix_len: int = 8) -> tuple[str, str]:
    """A v1 agent exactly as 014 made it: an 8-hex prefix, no key, `legacy` as migration 041 marks it."""
    prefix = uuid.uuid4().hex[:prefix_len]
    token = f"fat_{prefix}_" + "s" * 43
    aid = uuid.uuid4()
    async with db.acquire() as con:
        await con.execute(
            "INSERT INTO fleet_agents (id, tenant_id, hostname, platform, status, token_prefix, token_hash, "
            "last_seen, legacy) VALUES ($1,$2,$3,'linux','online',$4,$5,NOW(),TRUE)",
            aid, tenant_id, hostname, prefix, hashlib.sha256(token.encode()).hexdigest())
        await con.execute("INSERT INTO agent_inventory (tenant_id, agent_id, os_info) VALUES ($1,$2,'{\"a\":1}')",
                          tenant_id, aid)
    return str(aid), token


async def test_legacy_agents_get_403_re_enroll_required_on_every_route_and_keep_their_history(world):
    c = world.client
    aid, token = await _legacy_agent(world.db, TENANT_A)
    h = {"X-Agent-Token": token, "Content-Type": "application/json"}
    calls = [("POST", f"/v1/fleet/{aid}/heartbeat"), ("POST", f"/v1/fleet/{aid}/posture"),
             ("POST", f"/v1/fleet/{aid}/keys/rotate"), ("POST", f"/v1/fleet/{aid}/inventory"),
             ("POST", f"/v1/fleet/actions/{uuid.uuid4()}/result"), ("GET", "/v1/fleet/agents"),
             ("GET", f"/v1/fleet/agents/{aid}"), ("POST", "/v1/fleet/enroll-tokens")]
    for method, path in calls:
        r = await c.request(method, path, headers=h, content=b"{}")
        assert r.status_code == 403, (path, r.status_code)
        assert r.json()["error"] == "re_enroll_required", path
    # it is a 403, not the 401 of an unknown credential: the 8-hex v1 prefix still resolves
    r = await c.post(f"/v1/fleet/{aid}/heartbeat", headers={**h, "X-Agent-Token": token[:-1] + "x"}, content=b"{}")
    assert r.status_code == 401
    # rows and history are kept and visible to the operators, marked legacy
    row = await agent_row(world.db, aid)
    assert row["legacy"] is True and row["status"] == "online"
    listed = {a["id"]: a for a in (await c.get("/v1/fleet/agents", headers=hdr(world.viewer_a))).json()}
    assert listed[aid]["legacy"] is True and listed[aid]["status"] == "stale" and listed[aid]["key_id"] is None
    detail = (await c.get(f"/v1/fleet/agents/{aid}", headers=hdr(world.viewer_a))).json()
    assert detail["inventory"]["os_info"] == {"a": 1} and detail["inventory"]["signed"] is False
    # nothing can be proposed for it, and an old action can no longer be reported on
    r = await c.post("/v1/fleet/actions", headers=hdr(world.admin_a),
                     json={"agent_id": aid, "action_type": "block_ip", "target": "203.0.113.5"})
    assert r.status_code == 409
    # the refusals are audited in the agent's own tenant
    assert await world.db.fetchval("SELECT count(*) FROM audit_log WHERE action='deny' AND actor=$1 AND tenant_id=$2",
                                   "agent:old-1", uuid.UUID(TENANT_A)) >= len(calls)


async def test_a_12_hex_legacy_credential_is_refused_the_same_way(world):
    aid, token = await _legacy_agent(world.db, TENANT_A, "old-2", prefix_len=12)
    r = await world.client.post(f"/v1/fleet/{aid}/heartbeat", headers={"X-Agent-Token": token}, content=b"{}")
    assert r.status_code == 403 and r.json()["error"] == "re_enroll_required"


async def test_a_legacy_agent_cannot_use_the_signed_routes_even_with_a_key(world):
    """Even if a key row somehow existed, `legacy` wins: the flag is checked by the principal AND the ingest."""
    c = world.client
    host = await enroll_host(c, world.admin_a)
    await world.db.execute("UPDATE fleet_agents SET legacy=TRUE WHERE id=$1", uuid.UUID(host.agent_id))
    r = await hb(c, host)
    assert r.status_code == 403 and r.json()["error"] == "re_enroll_required"
    assert (await key_row(world.db, host.agent_id, host.kid))["last_seq"] == 0


# =========================================================================== #
# enforce mode and tenants (the bug this fixes: fleet routes were admin-gated)
# =========================================================================== #

async def test_agents_work_in_enforce_mode_in_a_non_default_tenant_with_only_their_token(world):
    c = world.client
    host = await enroll_host(c, world.admin_b, "web-b")
    assert host.tenant_id == TENANT_B
    assert (await hb(c, host)).status_code == 200
    assert (await ps(c, host)).status_code == 200
    r = await c.post(f"/v1/fleet/{host.agent_id}/inventory", headers=host.h, content=json.dumps(
        {"os_info": {"system": "Linux"}, "packages": [], "listeners": [], "posture": {}}).encode())
    assert r.status_code == 201 and r.json()["signed"] is False
    # tenant B's own admin sees it; tenant A's does not
    assert [a["id"] for a in (await c.get("/v1/fleet/agents", headers=hdr(world.admin_b))).json()] == [host.agent_id]
    assert (await c.get("/v1/fleet/agents", headers=hdr(world.admin_a))).json() == []
    # the enrollment row landed in B's audit chain
    rows = await audits(world.db, "fleet.agent.enroll", host.agent_id)
    assert len(rows) == 1 and str(rows[0]["tenant_id"]) == TENANT_B


async def test_enroll_is_public_but_a_presented_bad_credential_is_still_a_401(world):
    c = world.client
    r = await c.post("/v1/fleet/enroll", json={"token": "x", "hostname": "h", "public_key_b64": "AA",
                                               "proof_b64": "AA"})
    assert r.status_code == 401 or r.status_code == 400                    # reaches the handler without a principal
    r = await c.post("/v1/fleet/enroll", headers={"X-Agent-Token": "fat_nope"}, json={
        "token": "x", "hostname": "h", "public_key_b64": "AA", "proof_b64": "AA"})
    assert r.status_code == 401 and "agent" in r.json()["detail"]
    # the removed v1 shared-secret enrollment is gone: its body shape is refused
    r = await c.post("/v1/fleet/enroll", json={"hostname": "h", "platform": "linux", "token": "dev-enroll"})
    assert r.status_code == 422


async def test_the_v1_shared_secret_and_hostname_upsert_are_gone(world, monkeypatch):
    c = world.client
    monkeypatch.setenv("FLEET_ENROLL_TOKEN", "s3cret")
    r = await c.post("/v1/fleet/enroll", json={"hostname": "h", "platform": "linux", "token": "s3cret"})
    assert r.status_code == 422                       # no public_key_b64 / proof_b64: not an enrollment
    host = await enroll_host(c, world.admin_a, "dup")
    # the hostname of a live agent cannot be taken over by anyone holding an ordinary token
    other = await enroll_host_expect(c, world.admin_a, "dup", 409)
    assert other["detail"].startswith("hostname already enrolled")
    assert (await hb(c, host)).status_code == 200      # the original credential is untouched


async def enroll_host_expect(client, admin_key, hostname, code):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from .test_fleet_posture import b64u, pubkey
    sk = Ed25519PrivateKey.generate()
    r = await client.post("/v1/fleet/enroll-tokens", headers=hdr(admin_key), json={})
    token = r.json()["token"]
    proof = sk.sign(b"paddock-enroll/v1\n" + token.split("_")[1].encode() + b"\n" + hostname.encode())
    r = await client.post("/v1/fleet/enroll", json={"token": token, "hostname": hostname,
                                                    "public_key_b64": b64u(pubkey(sk)), "proof_b64": b64u(proof)})
    assert r.status_code == code, r.text
    return r.json()


# =========================================================================== #
# enrollment tokens (admin surface)
# =========================================================================== #

async def test_enroll_token_api_policy_and_audit(world):
    c = world.client
    r = await c.post("/v1/fleet/enroll-tokens", headers=hdr(world.analyst_a), json={})
    assert r.status_code == 403
    assert (await c.get("/v1/fleet/enroll-tokens", headers=hdr(world.viewer_a))).status_code == 403
    r = await c.post("/v1/fleet/enroll-tokens", headers=hdr(world.admin_a),
                     json={"label": "web fleet", "labels": ["prod"], "max_uses": 5, "ttl_minutes": 120})
    assert r.status_code == 201, r.text
    t = r.json()
    assert t["token"].startswith("fet_") and t["max_uses"] == 5 and t["uses"] == 0 and t["state"] == "pending"
    assert t["created_by"] == "admin-a" and t["labels"] == ["prod"]
    bad = {"max_uses": 0}, {"max_uses": 51}, {"ttl_minutes": 0}, {"max_uses": 2, "ttl_minutes": 1441}, \
        {"ttl_minutes": 10081}, {"extra": 1}, {"for_agent": "nope"}, {"max_uses": 2, "for_agent": str(uuid.uuid4())}
    for body in bad:
        assert (await c.post("/v1/fleet/enroll-tokens", headers=hdr(world.admin_a), json=body)).status_code == 422, body
    # a re-key token for an agent of ANOTHER tenant (or a made-up one) is a 404
    host_b = await enroll_host(c, world.admin_b, "web-b")
    for aid in (host_b.agent_id, str(uuid.uuid4())):
        assert (await c.post("/v1/fleet/enroll-tokens", headers=hdr(world.admin_a),
                             json={"for_agent": aid})).status_code == 404
    listed = (await c.get("/v1/fleet/enroll-tokens", headers=hdr(world.admin_a))).json()
    assert [x["id"] for x in listed] == [t["id"]] and "token" not in listed[0] and "token_hash" not in listed[0]
    got = (await c.get(f"/v1/fleet/enroll-tokens/{t['id']}", headers=hdr(world.admin_a))).json()
    assert got["token_prefix"] == t["token_prefix"] and "token" not in got
    assert (await c.get(f"/v1/fleet/enroll-tokens/{t['id']}", headers=hdr(world.admin_b))).status_code == 404
    assert (await c.delete(f"/v1/fleet/enroll-tokens/{t['id']}", headers=hdr(world.admin_b))).status_code == 404
    assert (await c.delete(f"/v1/fleet/enroll-tokens/{t['id']}", headers=hdr(world.admin_a))).status_code == 204
    assert (await c.delete(f"/v1/fleet/enroll-tokens/{t['id']}", headers=hdr(world.admin_a))).status_code == 404
    for action in ("fleet.enroll_token.create", "fleet.enroll_token.list", "fleet.enroll_token.revoke"):
        assert await audits(world.db, action), action
    create_row = (await audits(world.db, "fleet.enroll_token.create"))[0]
    assert t["token"] not in json.dumps(create_row["details"]) and create_row["details"]["prefix"] == t["token_prefix"]
    # the revoked token enrolls nobody
    r = await c.post("/v1/fleet/enroll", json={"token": t["token"], "hostname": "x", "public_key_b64": "AA",
                                               "proof_b64": "AA"})
    assert r.status_code in (400, 401)


async def test_enroll_endpoint_maps_errors_and_rate_limits(world):
    c = world.client
    from app import fleet_enroll as fe
    for _ in range(5):                                # five failed redemptions lock the client out
        r = await c.post("/v1/fleet/enroll", json={"token": "fet_" + "0" * 12 + "_" + "x" * 30, "hostname": "h",
                                                   "public_key_b64": "AA", "proof_b64": "AA"})
        assert r.status_code in (400, 401)
    r = await c.post("/v1/fleet/enroll", json={"token": "fet_" + "0" * 12 + "_" + "x" * 30, "hostname": "h",
                                               "public_key_b64": "AA", "proof_b64": "AA"})
    assert r.status_code == 429 and r.headers["retry-after"] == "60"
    fe.reset_limiters()


# =========================================================================== #
# the action gate, now principal-bound
# =========================================================================== #

async def test_action_results_are_bound_to_the_agent_the_action_belongs_to(world):
    c = world.client
    a = await enroll_host(c, world.admin_a, "web-1")
    b = await enroll_host(c, world.admin_a, "web-2")
    admin2 = await seed_key(world.db, TENANT_A, "admin-a2", "admin")
    p = (await c.post("/v1/fleet/actions", headers=hdr(world.admin_a), json={
        "agent_id": a.agent_id, "action_type": "block_ip", "target": "203.0.113.10"})).json()
    r = await c.post(f"/v1/fleet/actions/{p['id']}/approve", headers=hdr(admin2), json={"apply_for_real": True})
    assert r.status_code == 200
    # only agent a is offered it
    assert [x["id"] for x in (await hb(c, a)).json()["pending_actions"]] == [p["id"]]
    assert (await hb(c, b)).json()["pending_actions"] == []
    body = {"status": "applied", "output": {"ok": True}, "revert": {"mechanism": "iptables", "commands": []}}
    r = await c.post(f"/v1/fleet/actions/{p['id']}/result", headers=b.h, json=body)
    assert r.status_code == 403                                           # agent b cannot report a's action
    r = await c.post(f"/v1/fleet/actions/{p['id']}/result", headers=hdr(world.admin_a), json=body)
    assert r.status_code == 403                                           # nor can an admin
    r = await c.post(f"/v1/fleet/actions/{uuid.uuid4()}/result", headers=a.h, json=body)
    assert r.status_code == 404
    r = await c.post(f"/v1/fleet/actions/{p['id']}/result", headers=a.h, json=body)
    assert r.status_code == 200 and r.json()["status"] == "applied"
    r = await c.post(f"/v1/fleet/actions/{p['id']}/result", headers=a.h, json=body)
    assert r.status_code == 409                                           # no double report
    row = (await audits(world.db, "apply", p["id"]))[0]
    assert row["actor"] == f"agent:{a.agent_id}" and row["actor_role"] == "agent"


# =========================================================================== #
# v1 inventory: unsigned, never evidence
# =========================================================================== #

async def test_v1_inventory_is_unsigned_and_never_proves_life(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    before = await agent_row(world.db, host.agent_id)
    r = await c.post(f"/v1/fleet/{host.agent_id}/inventory", headers=host.h, content=json.dumps({
        "os_info": {"system": "Linux"}, "packages": [{"name": "openssl"}],
        "listeners": [{"ip": "0.0.0.0", "port": 22}], "posture": {"firewall": "ufw", "_evidence": {"signed": True}},
    }).encode())
    assert r.status_code == 201 and r.json()["signed"] is False
    after = await agent_row(world.db, host.agent_id)
    assert after["last_seen"] == before["last_seen"] and after["online"] == before["online"]   # NOT a heartbeat
    assert await posture_rows(world.db, host.agent_id) == []                                    # not evidence
    stored = jd(await world.db.fetchval("SELECT posture FROM agent_inventory WHERE agent_id=$1",
                                        uuid.UUID(host.agent_id)))
    assert stored["_evidence"] == {"signed": False, "tier": "declared"}       # the agent cannot claim otherwise
    detail = (await c.get(f"/v1/fleet/agents/{host.agent_id}", headers=hdr(world.viewer_a))).json()
    assert detail["inventory"]["signed"] is False
    # extra fields are still refused, and oversize bodies are 413
    r = await c.post(f"/v1/fleet/{host.agent_id}/inventory", headers=host.h, content=b'{"nope": 1}')
    assert r.status_code == 422
    r = await c.post(f"/v1/fleet/{host.agent_id}/inventory", headers=host.h, content=b" " * (4 * 1024 * 1024 + 1))
    assert r.status_code == 413
    r = await c.post(f"/v1/fleet/{host.agent_id}/inventory", headers=host.h, content=b"not json")
    assert r.status_code == 422


# =========================================================================== #
# agent listing carries the new liveness facts
# =========================================================================== #

async def test_agent_listing_shows_liveness_and_key(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    assert (await hb(c, host)).status_code == 200
    row = [a for a in (await c.get("/v1/fleet/agents", headers=hdr(world.viewer_a))).json()
           if a["id"] == host.agent_id][0]
    assert row["online"] is True and row["legacy"] is False and row["key_id"] == host.kid
    assert row["status"] == "online" and row["silent_after_s"] == 300 and row["node_ref"] == f"agent:{host.agent_id}"
    await world.db.execute("UPDATE fleet_agents SET online=FALSE, status='offline' WHERE id=$1",
                           uuid.UUID(host.agent_id))
    row = [a for a in (await c.get("/v1/fleet/agents", headers=hdr(world.viewer_a))).json()
           if a["id"] == host.agent_id][0]
    assert row["status"] == "offline" and row["online"] is False


def test_unused_imports_are_fixtures():
    assert Host and canon and TENANT_A and TENANT_B and ps and enforce and rls_app and _reset_limiters
