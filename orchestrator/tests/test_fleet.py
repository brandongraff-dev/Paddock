"""Fleet + gated enforcement tests (schema 014, router app/routers/fleet.py).

The fleet router is wired by hand in production (see docs/FLEET_WIRING.md), so we
mount it onto the test app the same way test_threatintel.py mounts its router.

We prove the safety rails:
  * enroll mints a credential whose sha256 matches the stored token_hash;
  * agent-authenticated endpoints reject a wrong/missing agent token;
  * an action is proposed dry_run=TRUE and cannot be applied without approval;
  * approve is admin-only and four-eyes (approver != requester);
  * a dry-run action can never be reported 'applied' (rail #3);
  * an applied action must carry a revert plan, and revert is first-class;
  * every transition writes an audit row.
"""
from __future__ import annotations

import hashlib
import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app import auth as auth_svc
from app.config import settings


@pytest_asyncio.fixture
async def fleet_client(app):
    from app.routers import fleet
    app.include_router(fleet.router)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


# --------------------------------------------------------------------------- #
# Governance test helpers (mirror test_governance.py)
# --------------------------------------------------------------------------- #

@pytest.fixture
def enforce():
    prev = settings.auth_mode
    settings.auth_mode = "enforce"
    try:
        yield
    finally:
        settings.auth_mode = prev


async def _seed_user_with_key(pool, username, role, clearance, scopes=None):
    async with pool.acquire() as con:
        row = await con.fetchrow(
            "INSERT INTO app_users (username, role, clearance, pw_hash) "
            "VALUES ($1,$2,$3,NULL) RETURNING id",
            username, role, clearance,
        )
    uid = row["id"]
    if scopes is None:
        scopes = tuple(sorted(auth_svc.ROLE_CAPABILITIES.get(role, {"read"})))
    full, prefix, key_hash = auth_svc.generate_api_key()
    async with pool.acquire() as con:
        await con.execute(
            "INSERT INTO api_keys (user_id, name, prefix, key_hash, scopes) "
            "VALUES ($1,$2,$3,$4,$5::text[])",
            uid, f"key-{prefix}", prefix, key_hash, list(scopes),
        )
    return uid, full


def _hdr(key):
    return {"Authorization": f"Bearer {key}"}


async def _enroll(fleet_client, hostname="host-a.local", platform="linux",
                  token="dev-enroll", headers=None):
    r = await fleet_client.post("/v1/fleet/enroll", headers=headers, json={
        "hostname": hostname, "platform": platform, "token": token,
        "capabilities": ["inventory", "block", "quarantine"],
    })
    assert r.status_code == 201, r.text
    return r.json()


def _atok(enrolled):
    return {"X-Agent-Token": enrolled["agent_token"]}


async def _audit_actions(db_pool, resource_id=None):
    sql = "SELECT action, actor, resource_type, resource_id FROM audit_log"
    args = []
    if resource_id is not None:
        sql += " WHERE resource_id = $1"
        args.append(str(resource_id))
    async with db_pool.acquire() as con:
        rows = await con.fetch(sql, *args)
    return [dict(r) for r in rows]


# --------------------------------------------------------------------------- #
# Enrollment + token hashing
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_enroll_mints_token_whose_hash_is_stored(fleet_client, db_pool):
    out = await _enroll(fleet_client)
    assert out["agent_token"].startswith("fat_")
    assert out["token_prefix"] in out["agent_token"]
    assert out["status"] == "enrolled"

    async with db_pool.acquire() as con:
        row = await con.fetchrow(
            "SELECT token_hash, token_prefix FROM fleet_agents WHERE id = $1",
            uuid.UUID(out["id"]),
        )
    # The raw token is never stored; only its sha256.
    expected = hashlib.sha256(out["agent_token"].encode()).hexdigest()
    assert row["token_hash"] == expected
    assert row["token_hash"] != out["agent_token"]
    assert row["token_prefix"] == out["token_prefix"]

    audits = await _audit_actions(db_pool, out["id"])
    assert any(a["action"] == "enroll" for a in audits)


@pytest.mark.asyncio
async def test_enroll_rejects_bad_platform(fleet_client):
    r = await fleet_client.post("/v1/fleet/enroll", json={
        "hostname": "h", "platform": "plan9", "token": "x",
    })
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_enroll_enforces_shared_secret_when_set(fleet_client, monkeypatch):
    monkeypatch.setenv("FLEET_ENROLL_TOKEN", "s3cret")
    bad = await fleet_client.post("/v1/fleet/enroll", json={
        "hostname": "h2", "platform": "linux", "token": "wrong"})
    assert bad.status_code == 401
    good = await fleet_client.post("/v1/fleet/enroll", json={
        "hostname": "h2", "platform": "linux", "token": "s3cret"})
    assert good.status_code == 201


# --------------------------------------------------------------------------- #
# Heartbeat + inventory (agent-auth)
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_heartbeat_requires_valid_agent_token(fleet_client):
    out = await _enroll(fleet_client)
    aid = out["id"]
    # missing token
    r = await fleet_client.post(f"/v1/fleet/{aid}/heartbeat", json={})
    assert r.status_code == 401
    # wrong token
    r = await fleet_client.post(f"/v1/fleet/{aid}/heartbeat", json={},
                                headers={"X-Agent-Token": "fat_dead_beef"})
    assert r.status_code == 401
    # right token
    r = await fleet_client.post(f"/v1/fleet/{aid}/heartbeat", json={}, headers=_atok(out))
    assert r.status_code == 200
    assert r.json()["status"] == "online"
    assert r.json()["pending_actions"] == []


@pytest.mark.asyncio
async def test_inventory_roundtrip_and_agent_detail(fleet_client, db_pool):
    out = await _enroll(fleet_client)
    aid = out["id"]
    r = await fleet_client.post(f"/v1/fleet/{aid}/inventory", headers=_atok(out), json={
        "os_info": {"system": "Linux", "release": "6.1"},
        "packages": [{"name": "openssl", "version": "3.0.2"}],
        "listeners": [{"ip": "0.0.0.0", "port": 22, "proto": "tcp"}],
        "posture": {"firewall": "ufw", "ufw_active": True},
    })
    assert r.status_code == 201, r.text

    r = await fleet_client.get(f"/v1/fleet/agents/{aid}")
    assert r.status_code == 200
    body = r.json()
    assert body["inventory"]["os_info"]["system"] == "Linux"
    assert body["inventory"]["listeners"][0]["port"] == 22
    assert body["inventory"]["packages"][0]["name"] == "openssl"

    r = await fleet_client.get("/v1/fleet/agents")
    assert any(a["id"] == aid for a in r.json())


# --------------------------------------------------------------------------- #
# Propose / approve / deny — the gate
# --------------------------------------------------------------------------- #

async def _propose(fleet_client, agent_id, action_type="block_ip",
                   target="203.0.113.10", headers=None):
    r = await fleet_client.post("/v1/fleet/actions", headers=headers, json={
        "agent_id": agent_id, "action_type": action_type, "target": target,
        "reason": "known-bad indicator",
    })
    return r


@pytest.mark.asyncio
async def test_propose_is_dry_run_and_proposed(fleet_client, db_pool):
    out = await _enroll(fleet_client)
    r = await _propose(fleet_client, out["id"])
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["status"] == "proposed"
    assert body["dry_run"] is True             # rail #3: default dry-run
    assert body["requested_by"] is not None
    assert body["approved_by"] is None
    audits = await _audit_actions(db_pool, body["id"])
    assert any(a["action"] == "propose" for a in audits)


@pytest.mark.asyncio
async def test_propose_rejects_non_host_local_and_extra_fields(fleet_client):
    out = await _enroll(fleet_client)
    # URL target (remote-ish) -> 422
    r = await _propose(fleet_client, out["id"], action_type="block_domain",
                       target="http://evil.example/x")
    assert r.status_code == 422
    # a sneaky execution-host field -> 422 (extra=forbid; no remote targeting)
    r = await fleet_client.post("/v1/fleet/actions", json={
        "agent_id": out["id"], "action_type": "block_ip", "target": "203.0.113.10",
        "exec_host": "some-other-box",
    })
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_cannot_report_result_without_approval(fleet_client):
    """Rail #2: a proposed action can't be applied."""
    out = await _enroll(fleet_client)
    p = (await _propose(fleet_client, out["id"])).json()
    r = await fleet_client.post(
        f"/v1/fleet/actions/{p['id']}/result", headers=_atok(out),
        json={"status": "applied", "output": {}, "revert": {"m": "x"}},
    )
    assert r.status_code == 409
    assert "approved" in r.json()["detail"]


@pytest.mark.asyncio
async def test_four_eyes_self_approve_blocked_in_dev(fleet_client, db_pool):
    """Same actor proposes + approves (dev synthetic admin) -> rejected +
    recorded."""
    out = await _enroll(fleet_client)
    p = (await _propose(fleet_client, out["id"])).json()
    r = await fleet_client.post(f"/v1/fleet/actions/{p['id']}/approve", json={})
    assert r.status_code == 409
    assert "four-eyes" in r.json()["detail"]
    audits = await _audit_actions(db_pool, p["id"])
    assert any(a["action"] == "approve_denied_four_eyes" for a in audits)


@pytest.mark.asyncio
async def test_deny_transitions_and_audits(fleet_client, db_pool):
    out = await _enroll(fleet_client)
    p = (await _propose(fleet_client, out["id"])).json()
    r = await fleet_client.post(f"/v1/fleet/actions/{p['id']}/deny", json={"note": "no"})
    assert r.status_code == 200
    assert r.json()["status"] == "denied"
    # can't approve a denied action
    r = await fleet_client.post(f"/v1/fleet/actions/{p['id']}/approve", json={})
    assert r.status_code == 409
    audits = await _audit_actions(db_pool, p["id"])
    assert any(a["action"] == "deny" for a in audits)


# --------------------------------------------------------------------------- #
# Four-eyes success + admin-only (enforce mode, two distinct principals)
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_approve_requires_admin(enforce, app, fleet_client, db_pool):
    _, admin_key = await _seed_user_with_key(db_pool, "req-admin", "admin", "restricted")
    _, analyst_key = await _seed_user_with_key(db_pool, "an", "analyst", "internal")
    out = await _enroll(fleet_client, token="x", headers=_hdr(admin_key))
    # propose as admin (enforce: unclassified POST needs admin anyway)
    p = (await _propose(fleet_client, out["id"], headers=_hdr(admin_key))).json()
    # analyst cannot approve -> 403
    r = await fleet_client.post(f"/v1/fleet/actions/{p['id']}/approve",
                                headers=_hdr(analyst_key), json={})
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_four_eyes_success_with_two_admins(enforce, app, fleet_client, db_pool):
    _, admin_a = await _seed_user_with_key(db_pool, "admin-a", "admin", "restricted")
    _, admin_b = await _seed_user_with_key(db_pool, "admin-b", "admin", "restricted")
    out = await _enroll(fleet_client, token="x", headers=_hdr(admin_a))
    p = (await _propose(fleet_client, out["id"], headers=_hdr(admin_a))).json()
    # admin_a cannot self-approve
    r = await fleet_client.post(f"/v1/fleet/actions/{p['id']}/approve",
                                headers=_hdr(admin_a), json={})
    assert r.status_code == 409
    # admin_b CAN approve (four-eyes satisfied), promoting to a real apply
    r = await fleet_client.post(f"/v1/fleet/actions/{p['id']}/approve",
                                headers=_hdr(admin_b), json={"apply_for_real": True})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "approved"
    assert body["approved_by"] == "admin-b"
    assert body["dry_run"] is False            # promoted to a real apply


# --------------------------------------------------------------------------- #
# Dry-run guard + apply result + revert (the full lifecycle)
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_dry_run_action_cannot_be_applied(fleet_client, db_pool):
    """Rail #3: approve WITHOUT apply_for_real keeps dry_run=true, and a dry-run
    action can never be reported 'applied'."""
    out = await _enroll(fleet_client)
    # two distinct principals needed for approval; use enforce-free self + patch
    # the four-eyes toggle via a second proposer identity is overkill here, so
    # allow self-approve just for this dry-run guard check.
    import os
    os.environ["FLEET_ALLOW_SELF_APPROVE"] = "1"
    try:
        p = (await _propose(fleet_client, out["id"])).json()
        r = await fleet_client.post(f"/v1/fleet/actions/{p['id']}/approve", json={})
        assert r.status_code == 200
        assert r.json()["dry_run"] is True     # not promoted
        # heartbeat must NOT return a dry-run action as pending real work
        hb = await fleet_client.post(f"/v1/fleet/{out['id']}/heartbeat",
                                     headers=_atok(out), json={})
        assert hb.json()["pending_actions"] == []
        # reporting 'applied' on a dry-run action is refused
        r = await fleet_client.post(
            f"/v1/fleet/actions/{p['id']}/result", headers=_atok(out),
            json={"status": "applied", "output": {}, "revert": {"m": "x"}},
        )
        assert r.status_code == 409
        assert "dry-run" in r.json()["detail"]
    finally:
        os.environ.pop("FLEET_ALLOW_SELF_APPROVE", None)


@pytest.mark.asyncio
async def test_full_lifecycle_apply_then_revert(fleet_client, db_pool):
    out = await _enroll(fleet_client)
    import os
    os.environ["FLEET_ALLOW_SELF_APPROVE"] = "1"
    try:
        p = (await _propose(fleet_client, out["id"])).json()
        # approve for REAL
        r = await fleet_client.post(f"/v1/fleet/actions/{p['id']}/approve",
                                    json={"apply_for_real": True})
        assert r.status_code == 200 and r.json()["dry_run"] is False

        # heartbeat now returns it as pending real work
        hb = await fleet_client.post(f"/v1/fleet/{out['id']}/heartbeat",
                                     headers=_atok(out), json={})
        pend = hb.json()["pending_actions"]
        assert len(pend) == 1 and pend[0]["id"] == p["id"]

        # applied result MUST carry a revert plan (rail #5)
        r = await fleet_client.post(
            f"/v1/fleet/actions/{p['id']}/result", headers=_atok(out),
            json={"status": "applied", "output": {"blocked": "203.0.113.10"}},
        )
        assert r.status_code == 422  # missing revert plan

        revert_plan = {"mechanism": "iptables",
                       "commands": [["iptables", "-D", "INPUT", "-s", "203.0.113.10", "-j", "DROP"]]}
        r = await fleet_client.post(
            f"/v1/fleet/actions/{p['id']}/result", headers=_atok(out),
            json={"status": "applied", "output": {"blocked": "203.0.113.10"},
                  "revert": revert_plan},
        )
        assert r.status_code == 200
        assert r.json()["status"] == "applied"
        assert r.json()["result"]["revert"]["mechanism"] == "iptables"

        # revert is first-class: mint a revert action, agent applies it,
        # original becomes 'reverted'
        r = await fleet_client.post(f"/v1/fleet/actions/{p['id']}/revert", json={})
        assert r.status_code == 201, r.text
        child = r.json()
        assert child["action_type"] == "revert"
        assert child["status"] == "approved"
        assert child["revert_of"] == p["id"]
        assert child["dry_run"] is False

        r = await fleet_client.post(
            f"/v1/fleet/actions/{child['id']}/result", headers=_atok(out),
            json={"status": "applied", "output": {"removed": True}},
        )
        assert r.status_code == 200

        # the original is now reverted
        r = await fleet_client.get("/v1/fleet/actions",
                                   params={"agent": out["id"], "status": "reverted"})
        assert any(a["id"] == p["id"] for a in r.json()["items"])

        # every transition was audited
        audits = await _audit_actions(db_pool)
        actions_for_orig = {a["action"] for a in audits if a["resource_id"] == p["id"]}
        assert {"propose", "approve", "apply", "reverted"} <= actions_for_orig
    finally:
        os.environ.pop("FLEET_ALLOW_SELF_APPROVE", None)


@pytest.mark.asyncio
async def test_result_can_report_failure(fleet_client):
    out = await _enroll(fleet_client)
    import os
    os.environ["FLEET_ALLOW_SELF_APPROVE"] = "1"
    try:
        p = (await _propose(fleet_client, out["id"])).json()
        await fleet_client.post(f"/v1/fleet/actions/{p['id']}/approve",
                                json={"apply_for_real": True})
        r = await fleet_client.post(
            f"/v1/fleet/actions/{p['id']}/result", headers=_atok(out),
            json={"status": "failed", "output": {"error": "iptables not found"}},
        )
        assert r.status_code == 200
        assert r.json()["status"] == "failed"
    finally:
        os.environ.pop("FLEET_ALLOW_SELF_APPROVE", None)


@pytest.mark.asyncio
async def test_list_actions_filters(fleet_client):
    out = await _enroll(fleet_client)
    await _propose(fleet_client, out["id"], target="203.0.113.1")
    await _propose(fleet_client, out["id"], action_type="block_domain", target="bad.example")
    r = await fleet_client.get("/v1/fleet/actions", params={"agent": out["id"]})
    assert r.json()["total"] == 2
    r = await fleet_client.get("/v1/fleet/actions",
                               params={"agent": out["id"], "status": "proposed"})
    assert r.json()["total"] == 2
    r = await fleet_client.get("/v1/fleet/actions", params={"status": "bogus"})
    assert r.status_code == 422
