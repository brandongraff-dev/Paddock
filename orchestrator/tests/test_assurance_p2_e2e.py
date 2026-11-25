"""P2 definition of done, end to end (docs/ASSURANCE_P2.md section 10, last bullet).

The REAL pieces run, nothing mocked on either side of the wire:

* the agent is the real ``paddock_agent.agent.Agent``: it generates its Ed25519 key, proves possession, enrolls with a
  one-time token, runs the REAL collectors over a pretend host built from the REAL captured fixtures
  (``agent/tests/fixtures``), signs REAL envelopes and talks to the server through the REAL ``FleetClient``
  (carried in-process to the ASGI app by ``p2_support.AsgiBridge``);
* the server is the real orchestrator in ``AUTH_MODE=enforce``, served through the non-superuser role (RLS) in BOTH
  the normal and the ``ORCH_TEST_APP_ROLE=1`` run: routes, principal, envelope checks, store, ``host_fw`` builder,
  graph loader, the real ``paddock_assurance`` library, findings sync;
* tenant B is a second, real tenant.

The scenario is the contract's list, in order: a one-time token enrolls an agent with its key; a signed posture is
accepted; ``std:server-ssh-hardened`` and ``std:server-default-deny-inbound`` HOLD at tier ``configured``; flipping
``PasswordAuthentication yes`` makes the first VIOLATED with a finding; a tampered payload is rejected with 401 and an
audit row while the previous posture stays; a replayed envelope gets 409; silencing the agent makes it UNKNOWN (and
the open finding stays open); the external scan seeing a port the agent calls closed is a conflict, no coverage and
UNKNOWN; a legacy v1 credential gets 403 re_enroll_required; tenant B sees nothing of tenant A; 20 concurrent
redemptions of one token have exactly one winner.
"""
from __future__ import annotations

import asyncio
import base64
import datetime as dt
import hashlib
import json
import uuid

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from httpx import ASGITransport, AsyncClient

from app import auth as auth_svc
from app import fleet_enroll as fe
from app import fleet_monitor
from app import fleet_posture as fp
from app import tenancy
from app.config import settings

from . import p2_support as sup
from .p2_support import AgentRuntime, FixtureHost, hdr, seed_key

paddock_assurance = pytest.importorskip("paddock_assurance")

A = tenancy.DEFAULT_TENANT_ID
B = "00000000-0000-0000-0000-0000000000b7"
SSH = "std:server-ssh-hardened"
FWD = "std:server-default-deny-inbound"
UTC = dt.timezone.utc
MINUTE = dt.timedelta(minutes=1)


# --------------------------------------------------------------------------- #
# world
# --------------------------------------------------------------------------- #

@pytest.fixture(autouse=True)
def _fresh_limiters():
    fe.reset_limiters()
    fp.reset_limiters()
    yield
    fe.reset_limiters()
    fp.reset_limiters()


@pytest.fixture
def enforce():
    prev = settings.auth_mode
    settings.auth_mode = "enforce"
    try:
        yield
    finally:
        settings.auth_mode = prev


class World:
    pass


@pytest_asyncio.fixture
async def world(db_pool, app_pool, fake_redis, enforce, tmp_path):
    """Tenant A and tenant B, an admin key each, the app served through the RLS role."""
    from .conftest import _build_app

    app = _build_app(app_pool, fake_redis)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as http:
        w = World()
        await tenancy.create_tenant(db_pool, slug="bravo", name="Bravo", tenant_id=B)
        w.http, w.db, w.app_pool, w.tmp = http, db_pool, app_pool, tmp_path
        w.admin_a = await seed_key(db_pool, A, "admin-a", "admin")
        w.viewer_a = await seed_key(db_pool, A, "viewer-a", "viewer")
        w.admin_b = await seed_key(db_pool, B, "admin-b", "admin")
        w.loop = asyncio.get_running_loop()
        yield w


async def mint(w: World, key: str | None = None, **body) -> dict:
    r = await w.http.post("/v1/fleet/enroll-tokens", headers=hdr(key or w.admin_a), json=body)
    assert r.status_code == 201, r.text
    return r.json()


def runtime(w: World, hostname: str = "web-1", **kw) -> AgentRuntime:
    return AgentRuntime(w.tmp, w.http, w.loop, hostname=hostname, **kw)


async def audits(db, action: str, tenant: str | None = None) -> list[dict]:
    rows = await db.fetch("SELECT * FROM audit_log WHERE action = $1 ORDER BY id", action)
    out = [dict(r, details=json.loads(r["details"]) if isinstance(r["details"], str) else r["details"])
           for r in rows]
    return [r for r in out if tenant is None or str(r["tenant_id"]) == tenant]


async def invariant(w: World, std_id: str, key: str | None = None) -> dict:
    """The invariant's detail (verdict, last result) as the API shows it to this tenant's admin."""
    r = await w.http.get("/v1/invariants", headers=hdr(key or w.admin_a), params={"limit": 100})
    assert r.status_code == 200, r.text
    row = next(i for i in r.json()["items"] if i["invariant_id"] == std_id)
    r = await w.http.get(f"/v1/invariants/{row['id']}", headers=hdr(key or w.admin_a))
    assert r.status_code == 200, r.text
    return r.json()


async def evaluate(w: World, key: str | None = None) -> dict:
    r = await w.http.post("/v1/assurance/evaluate", headers=hdr(key or w.admin_a), json={"rebuild": True})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["ok"], out
    assert all(b.get("ok") for b in out["builders"].values()), out["builders"]
    return out


async def verdicts(w: World) -> dict:
    return {i: (await invariant(w, i))["last_verdict"] for i in (SSH, FWD)}


async def findings(w: World, std_id: str, tenant: str = A) -> list[dict]:
    rows = await w.db.fetch(
        "SELECT status, severity, rule_id, title, description, fix_verified_at FROM findings "
        "WHERE tenant_id = $1 AND rule_source = 'invariant' AND (rule_id = $2 OR starts_with(rule_id, $3)) "
        "ORDER BY rule_id", uuid.UUID(tenant), f"invariant:{std_id}", f"invariant:{std_id}@")
    return [dict(r) for r in rows]


async def count(db, table: str, tenant: str) -> int:
    return await db.fetchval(f"SELECT count(*) FROM {table} WHERE tenant_id = $1", uuid.UUID(tenant))


def canon(x) -> bytes:
    return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


async def enable_std(w: World) -> None:
    for sid in (SSH, FWD):
        r = await w.http.post(f"/v1/invariants/std/{sid}/enable", headers=hdr(w.admin_a))
        assert r.status_code in (200, 201), r.text


def tamper_posture(mutate_payload, *, fix_header: bool):
    """A bridge interceptor: the attacker on the wire rewrites the next posture's payload. ``fix_header`` also
    recomputes ``payload_sha256`` / ``payload_len`` (a careful attacker) but cannot re-sign."""
    done = {"n": 0}

    def hook(method, path, headers, body):
        if not path.endswith("/posture") or done["n"]:
            return None
        done["n"] += 1
        raw_body = body
        if headers.get("Content-Encoding") == "gzip":
            import gzip

            raw_body = gzip.decompress(body)
        env = json.loads(raw_body)
        payload = mutate_payload(b64u_dec(env["payload_b64"]))
        env["payload_b64"] = b64u(payload)
        if fix_header:
            env["payload_sha256"] = hashlib.sha256(payload).hexdigest()
            env["payload_len"] = len(payload)
        out = json.dumps(env).encode()
        if headers.get("Content-Encoding") == "gzip":
            import gzip

            out = gzip.compress(out)
        return out

    return hook


def flip_password_to_no(payload: bytes) -> bytes:
    assert b'"passwordauthentication":"yes"' in payload
    return payload.replace(b'"passwordauthentication":"yes"', b'"passwordauthentication":"no"', 1)


def same_length_edit(payload: bytes) -> bytes:
    """A one-word edit that keeps the length, so the length check passes and the digest check is what fails."""
    assert b'"passwordauthentication":"yes"' in payload
    return payload.replace(b'"passwordauthentication":"yes"', b'"passwordauthentication":"nos"', 1)


# --------------------------------------------------------------------------- #
# the definition of done
# --------------------------------------------------------------------------- #

async def test_p2_definition_of_done(world: World, tmp_path):
    w = world

    # ---- 1. a one-time token enrolls a real agent with its own key ------------------------------------------
    tok = await mint(w, label="e2e web-1")
    assert tok["token"].startswith("fet_") and tok["max_uses"] == 1 and tok["state"] == "pending"
    # a proof signed by a key other than the one being enrolled is refused, and does not spend the token
    prefix = tok["token"].split("_")[1]
    mine, thief = sup.agent_signing.generate_seed(), sup.agent_signing.generate_seed()
    r = await w.http.post("/v1/fleet/enroll", json={
        "token": tok["token"], "hostname": "web-1", "agent_version": sup.AGENT_VERSION,
        "public_key_b64": sup.agent_envelope.b64u(sup.agent_signing.public_key(mine)),
        "proof_b64": sup.agent_envelope.enroll_proof(thief, prefix, "web-1")})
    assert r.status_code == 400, r.text
    assert (await w.db.fetchrow("SELECT uses FROM fleet_enroll_tokens WHERE token_prefix = $1", prefix))["uses"] == 0
    assert await w.db.fetchval("SELECT count(*) FROM fleet_agents WHERE tenant_id = $1", uuid.UUID(A)) == 0
    rt = runtime(w)
    creds = await rt.enroll(tok["token"])
    assert creds.tenant_id == A and creds.agent_token.startswith("fat_")
    assert rt.key_id == creds.key_id and len(rt.public_key) == 32
    agent_id = uuid.UUID(creds.agent_id)

    row = await w.db.fetchrow("SELECT * FROM fleet_agents WHERE id = $1", agent_id)
    assert row["hostname"] == "web-1" and row["legacy"] is False and row["status"] == "enrolled"
    key = await w.db.fetchrow("SELECT * FROM fleet_agent_keys WHERE agent_id = $1", agent_id)
    assert key["status"] == "active" and bytes(key["public_key"]) == rt.public_key and key["key_id"] == rt.key_id
    # the credential is stored as a hash only, and the token secret appears nowhere (audit, rows)
    assert row["token_hash"] != creds.agent_token and creds.agent_token not in json.dumps(dict(row), default=str)
    dump = json.dumps([dict(r, details=str(r["details"])) for r in await w.db.fetch("SELECT * FROM audit_log")],
                      default=str)
    assert tok["token"].split("_", 2)[2] not in dump and creds.agent_token.split("_", 2)[2] not in dump
    assert len(await audits(w.db, "fleet.agent.enroll", A)) == 1
    spent = await w.db.fetchrow("SELECT uses, max_uses FROM fleet_enroll_tokens WHERE token_prefix = $1",
                                tok["token"].split("_")[1])
    assert spent["uses"] == 1
    # a second host presenting the SAME token gets the generic refusal and no agent
    stolen = runtime(w, "web-evil")
    with pytest.raises(sup.agent_client_error()) as exc:
        await stolen.enroll(tok["token"])
    assert exc.value.status == 401
    assert await w.db.fetchval("SELECT count(*) FROM fleet_agents WHERE tenant_id = $1", uuid.UUID(A)) == 1
    assert stolen.agent.state.load_key() is None and stolen.agent.state.load_pending_key() is None

    # ---- 2. a signed posture is accepted, with the REAL collectors' output ------------------------------------
    t_before = dt.datetime.now(UTC)
    ack = await rt.posture()
    assert ack["ok"] and ack["stored"] and ack["changed"] and not ack["idempotent"]
    prow = await w.db.fetchrow("SELECT * FROM agent_posture WHERE agent_id = $1", agent_id)
    assert prow["signed"] is True and prow["key_id"] == rt.key_id and prow["seq"] == ack["seq"]
    payload = bytes(prow["payload_raw"])
    assert hashlib.sha256(payload).hexdigest() == prow["payload_sha256"]
    sections = json.loads(payload)["sections"]
    assert {n: s["s"] for n, s in sections.items()} == {"sshd": "ok", "listeners": "ok", "firewall": "ok",
                                                         "patch": "ok", "self": "ok"}
    assert sections["sshd"]["v"]["config"]["passwordauthentication"] == "no"
    assert sections["firewall"]["conf"] == "exact"
    # verified independently of the server code: the signature over the stored header under the agent's public key
    header = json.loads(prow["header"]) if isinstance(prow["header"], str) else prow["header"]
    Ed25519PublicKey.from_public_bytes(rt.public_key).verify(
        bytes(prow["signature"]), b"paddock-agent-envelope/v1\n" + canon(header))
    assert header["agent_id"] == str(agent_id) and header["tenant_id"] == A and header["kid"] == rt.key_id
    assert dt.datetime.fromisoformat(header["issued_at"].replace("Z", "+00:00")) >= t_before.replace(microsecond=0)
    # the triage read returns the stored posture; a viewer may not
    r = await w.http.get(f"/v1/fleet/agents/{agent_id}/posture", headers=hdr(w.admin_a))
    assert r.status_code == 200 and r.json()["signed"] is True and r.json()["tier"] == "configured"
    assert (await w.http.get(f"/v1/fleet/agents/{agent_id}/posture", headers=hdr(w.viewer_a))).status_code == 403
    r = await w.http.get(f"/v1/fleet/agents/{agent_id}", headers=hdr(w.viewer_a))
    assert r.status_code == 200 and "machine_id_hash" not in json.dumps(r.json())

    # ---- 3. both std host invariants HOLD, at tier configured -------------------------------------------------
    await enable_std(w)
    out = await evaluate(w)
    assert out["builders"]["host_fw"]["ok"]
    assert await verdicts(w) == {SSH: "HOLDS", FWD: "HOLDS"}
    for sid in (SSH, FWD):
        res = (await invariant(w, sid))["last_result"]
        assert res["verdict"] == "HOLDS" and res["evidence_tier"] == "configured", res
        assert res["hosts"] == {"selected": 1, "holds": 1, "violated": 0, "unknown": 0}
        assert res["valid_until"] is not None
        assert await findings(w, sid) == []
    nodes = await w.db.fetch("SELECT node_ref FROM reach_nodes WHERE tenant_id = $1 AND node_ref LIKE 'agent:%'",
                             uuid.UUID(A))
    assert [n["node_ref"] for n in nodes] == [f"agent:{agent_id}"]
    cov = await w.db.fetch("SELECT node_ref, direction, tier, source FROM reach_coverage WHERE node_ref = $1",
                           f"agent:{agent_id}")
    assert [(c["direction"], c["tier"], c["source"]) for c in cov] == [("in", "configured", "host_fw")]
    facts = await w.db.fetchrow("SELECT tier, facts FROM reach_node_facts WHERE node_ref = $1 AND source = 'host_fw'",
                                f"agent:{agent_id}")
    facts_doc = json.loads(facts["facts"]) if isinstance(facts["facts"], str) else facts["facts"]
    assert facts["tier"] == "configured"
    assert {"sshd", "firewall", "listeners", "patch"} <= set(facts_doc)
    assert all(facts_doc[c]["signed"] is True and facts_doc[c]["key_id"] == rt.key_id
               for c in ("sshd", "firewall", "listeners"))

    # ---- 4. PasswordAuthentication yes => VIOLATED, with a finding --------------------------------------------
    rt.host.password_auth = "yes"
    ack = await rt.posture()
    assert ack["changed"]
    await evaluate(w)
    assert await verdicts(w) == {SSH: "VIOLATED", FWD: "HOLDS"}
    res = (await invariant(w, SSH))["last_result"]
    assert res["verdict"] == "VIOLATED" and res["violating_targets"] == [f"agent:{agent_id}"]
    detail = res["witnesses"][0]["detail"]
    assert detail["node"] == f"agent:{agent_id}" and detail["tier"] == "configured" and detail["signed"] == "true"
    assert detail["key_id"] == rt.key_id and "password" in detail["field"]
    f = await findings(w, SSH)
    assert len(f) == 1 and f[0]["status"] == "open" and f[0]["severity"] == "high"
    assert f[0]["rule_id"] == f"invariant:{SSH}@agent:{agent_id}" and "web-1" in f[0]["title"]
    assert await findings(w, FWD) == []
    assert (await invariant(w, FWD))["last_verdict"] == "HOLDS"

    # ---- 5. a tampered payload is rejected: 401, an audit row, and the previous posture stays -----------------
    posture_rows_before = await w.db.fetch("SELECT seq, payload_sha256 FROM agent_posture WHERE agent_id = $1 "
                                           "ORDER BY seq", agent_id)
    last_key_seq = await w.db.fetchval("SELECT last_seq FROM fleet_agent_keys WHERE agent_id = $1 AND status = 'active'",
                                       agent_id)
    # the attacker rewrites the violating posture into a clean one, recomputing the digest and length it can
    # see in the header; it cannot re-sign
    rt.bridge.interceptor = tamper_posture(flip_password_to_no, fix_header=True)
    rt.host.password_auth = "yes"
    with pytest.raises(sup.agent_client_error()) as exc:
        await rt.posture()
    assert exc.value.status == 401
    rej = [r for r in await audits(w.db, "fleet.evidence.rejected", A) if r["details"]["reason"] == "bad_signature"]
    assert len(rej) == 1 and rej[0]["resource_id"] == str(agent_id) and rej[0]["details"]["key_id"] == rt.key_id
    assert (await w.db.fetchrow("SELECT rejected_total FROM fleet_agents WHERE id = $1", agent_id))["rejected_total"] == 1
    # nothing moved: same stored postures, seq claim not advanced by the failed signature, verdicts unchanged
    assert await w.db.fetch("SELECT seq, payload_sha256 FROM agent_posture WHERE agent_id = $1 ORDER BY seq",
                            agent_id) == posture_rows_before
    assert await w.db.fetchval("SELECT last_seq FROM fleet_agent_keys WHERE agent_id = $1 AND status = 'active'",
                               agent_id) == last_key_seq
    await evaluate(w)
    assert await verdicts(w) == {SSH: "VIOLATED", FWD: "HOLDS"}
    # a cruder tamper (payload changed, header untouched) dies earlier, at the digest check, and is audited too
    rt.bridge.interceptor = tamper_posture(same_length_edit, fix_header=False)
    with pytest.raises(sup.agent_client_error()) as exc:
        await rt.posture()
    assert exc.value.status == 400
    reasons = sorted(r["details"]["reason"] for r in await audits(w.db, "fleet.evidence.rejected", A))
    assert reasons == ["bad_signature", "payload_sha256_mismatch"]
    rt.bridge.interceptor = None

    # ---- 6. a replayed envelope gets 409 ---------------------------------------------------------------------
    sent_bodies: list[tuple[str, bytes, dict]] = []
    orig = rt.bridge.interceptor

    def record(method, path, headers, body):
        sent_bodies.append((path, body, dict(headers)))
        return orig(method, path, headers, body) if orig else None

    rt.bridge.interceptor = record
    p1 = await rt.posture()                     # unchanged content: accepted, not stored again
    assert p1["ok"] and p1["stored"] is False
    p2 = await rt.posture()
    assert p2["ok"]
    rt.bridge.interceptor = None
    (old_path, old_body, old_h), (new_path, new_body, new_h) = [x for x in sent_bodies if x[0].endswith("/posture")][-2:]
    assert old_h.get("Content-Encoding") == "gzip" and new_h.get("Content-Encoding") == "gzip"
    replay_headers = {"X-Agent-Token": creds.agent_token, "Content-Type": "application/json",
                      "Content-Encoding": "gzip"}
    r = await w.http.post(old_path, content=old_body, headers=replay_headers)
    assert r.status_code == 409 and r.json()["reason"] == "replayed_seq", r.text
    assert r.json()["expected_min"] == p2["seq"] + 1
    # the very last envelope sent again (a lost answer) is the idempotent case: 200, nothing written
    before = await w.db.fetchrow("SELECT last_seen FROM fleet_agents WHERE id = $1", agent_id)
    r = await w.http.post(new_path, content=new_body, headers=replay_headers)
    assert r.status_code == 200 and r.json()["idempotent"] is True
    assert (await w.db.fetchrow("SELECT last_seen FROM fleet_agents WHERE id = $1", agent_id))["last_seen"] == before["last_seen"]
    replays = [x for x in await audits(w.db, "fleet.evidence.rejected", A) if x["details"]["reason"] == "replayed_seq"]
    assert len(replays) == 1

    # ---- 7. silencing the agent => UNKNOWN; the open finding stays open --------------------------------------------
    assert (await invariant(w, SSH))["last_verdict"] in ("VIOLATED",)
    await evaluate(w)
    assert (await verdicts(w))[SSH] == "VIOLATED"
    await w.db.execute("UPDATE fleet_agents SET last_seen = NOW() - interval '20 minutes' WHERE id = $1", agent_id)
    swept = await fleet_monitor.sweep_all_tenants(w.app_pool)
    assert swept >= 1
    assert (await w.db.fetchrow("SELECT online FROM fleet_agents WHERE id = $1", agent_id))["online"] is False
    assert len(await audits(w.db, "fleet.agent.offline", A)) == 1
    await evaluate(w)
    assert await verdicts(w) == {SSH: "UNKNOWN", FWD: "UNKNOWN"}
    res = (await invariant(w, SSH))["last_result"]
    assert res["verdict"] == "UNKNOWN" and res["reasons"] == ["hosts_unknown:1"] and res["evidence_tier"] is None
    assert res["unproven_targets"] == [f"agent:{agent_id}"]
    assert [(b["node"], b["reason"], b["collector"], b["direction"]) for b in res["blind_spots"]] == [
        (f"agent:{agent_id}", "no_sensor", "sshd", "host")]
    silent = await w.db.fetchrow("SELECT facts FROM reach_node_facts WHERE node_ref = $1 AND source = 'host_fw'",
                                 f"agent:{agent_id}")
    silent_doc = json.loads(silent["facts"]) if isinstance(silent["facts"], str) else silent["facts"]
    assert set(silent_doc) == {"host_agent"} and silent_doc["host_agent"]["reason"] == "silent"
    assert silent_doc["host_agent"]["status"] == "unavailable" and silent_doc["host_agent"]["signed"] is False
    cov = await w.db.fetch("SELECT 1 FROM reach_coverage WHERE node_ref = $1 AND source = 'host_fw'", f"agent:{agent_id}")
    assert cov == []                                                        # silence drops coverage
    assert [x["status"] for x in await findings(w, SSH)] == ["open"]         # UNKNOWN closes nothing

    # ---- 8. the agent comes back, is fixed, and the finding closes ----------------------------------------------
    await rt.heartbeat()
    assert (await w.db.fetchrow("SELECT online FROM fleet_agents WHERE id = $1", agent_id))["online"] is True
    assert len(await audits(w.db, "fleet.agent.online", A)) == 1
    rt.host.password_auth = "no"
    await rt.posture()
    await evaluate(w)
    assert await verdicts(w) == {SSH: "HOLDS", FWD: "HOLDS"}
    assert [x["status"] for x in await findings(w, SSH)] == ["fixed"]

    # ---- 9. the external scan sees a port the agent calls closed: conflict, no coverage, UNKNOWN -----------------
    now = dt.datetime.now(UTC)
    await w.db.execute("INSERT INTO scope_entries (kind, value, added_by, active) VALUES ('ipv4_cidr', "
                       "'93.184.216.0/24', 'test', TRUE) ON CONFLICT DO NOTHING")
    await w.db.execute(
        "INSERT INTO assets (kind, value, canonical, source, metadata, last_seen) VALUES "
        "('port', $1, $1, 'port_scan', $2::jsonb, $3)", f"{sup.PUBLIC_IP}:{sup.PUBLIC_PORT}",
        json.dumps({"port": sup.PUBLIC_PORT, "protocol": "tcp"}), now)
    await rt.heartbeat()
    await evaluate(w)
    assert await verdicts(w) == {SSH: "UNKNOWN", FWD: "UNKNOWN"}
    cov = await w.db.fetch("SELECT 1 FROM reach_coverage WHERE node_ref = $1 AND source = 'host_fw'", f"agent:{agent_id}")
    assert cov == []
    facts = await w.db.fetchrow("SELECT facts FROM reach_node_facts WHERE node_ref = $1 AND source = 'host_fw'",
                                f"agent:{agent_id}")
    facts_doc = json.loads(facts["facts"]) if isinstance(facts["facts"], str) else facts["facts"]
    conflicts = facts_doc["firewall"]["conflict"]
    assert conflicts[0]["kind"] == "agent_closed_scan_open" and conflicts[0]["port"] == sup.PUBLIC_PORT
    assert conflicts[0]["proto"] == "tcp"
    res = (await invariant(w, FWD))["last_result"]
    assert res["verdict"] == "UNKNOWN" and res["violating_targets"] == [] and res["unproven_targets"] == [f"agent:{agent_id}"]
    assert any(b["reason"] == "evidence_conflict" for b in res["blind_spots"]), res["blind_spots"]
    # the conflict is never turned into a pass, and a newer posture from the same host does not talk it away: the
    # observation stays inside its window (P1: observations age out, they are not disproved by one clean look)
    await rt.posture()
    await evaluate(w)
    assert await verdicts(w) == {SSH: "UNKNOWN", FWD: "UNKNOWN"}
    assert await w.db.fetchval("SELECT count(*) FROM reach_coverage WHERE node_ref = $1 AND source = 'host_fw'",
                               f"agent:{agent_id}") == 0

    # ---- 10. a legacy v1 credential gets 403 re_enroll_required ---------------------------------------------------
    legacy_id = uuid.uuid4()
    v1_secret = "v1" + uuid.uuid4().hex
    v1_token = f"fat_ab12cd34_{v1_secret}"
    await w.db.execute(
        "INSERT INTO fleet_agents (id, tenant_id, hostname, status, token_prefix, token_hash, legacy) "
        "VALUES ($1, $2, 'old-host', 'online', 'ab12cd34', $3, TRUE)",
        legacy_id, uuid.UUID(A), auth_svc.hash_api_key(v1_token))
    r = await w.http.post(f"/v1/fleet/{legacy_id}/heartbeat", headers={"X-Agent-Token": v1_token},
                          json={"agent_version": "0.1.0", "status": "ok"})
    assert r.status_code == 403 and "re_enroll_required" in r.text
    r = await w.http.post(f"/v1/fleet/{legacy_id}/inventory", headers={"X-Agent-Token": v1_token}, json={})
    assert r.status_code == 403 and "re_enroll_required" in r.text
    # the real agent, holding only a v1 credential, stops (exit status 7) instead of retrying forever
    old = runtime(w, "old-host")
    old.agent.state.ensure_dir()
    old.agent.state.save_credentials(sup.make_credentials(legacy_id, v1_token, A))
    old.agent.state.save_key(sup.agent_signing.generate_seed())
    assert await old.call(old.agent.step) == "fatal"
    # and a wrong secret on a current agent is a plain 401, not a hint
    r = await w.http.post(f"/v1/fleet/{agent_id}/heartbeat", headers={"X-Agent-Token": creds.agent_token[:-4] + "xxxx"},
                          json={})
    assert r.status_code == 401

    # ---- 11. tenant B sees nothing of tenant A ---------------------------------------------------------------------
    for path in ("/v1/fleet/agents", "/v1/fleet/enroll-tokens"):
        r = await w.http.get(path, headers=hdr(w.admin_b))
        assert r.status_code == 200 and r.json() == [], (path, r.text)
    for path in (f"/v1/fleet/agents/{agent_id}", f"/v1/fleet/agents/{agent_id}/posture"):
        assert (await w.http.get(path, headers=hdr(w.admin_b))).status_code == 404
    assert (await w.http.post(f"/v1/fleet/agents/{agent_id}/revoke", headers=hdr(w.admin_b), json={})).status_code == 404
    for table in ("fleet_agents", "fleet_agent_keys", "agent_posture", "reach_node_facts", "findings"):
        assert await count(w.db, table, B) == 0, table
    # B's own std invariants find no host at all (and certainly not A's): UNKNOWN empty_selector, never a pass
    for sid in (SSH, FWD):
        assert (await w.http.post(f"/v1/invariants/std/{sid}/enable", headers=hdr(w.admin_b))).status_code in (200, 201)
    r = await w.http.post("/v1/assurance/evaluate", headers=hdr(w.admin_b), json={"rebuild": True})
    assert r.status_code == 200 and r.json()["ok"], r.text
    for sid in (SSH, FWD):
        inv = await invariant(w, sid, w.admin_b)
        assert inv["last_verdict"] == "UNKNOWN" and inv["last_result"]["reasons"] == ["empty_selector:to"]
        assert str(agent_id) not in json.dumps(inv)
    r = await w.http.get("/v1/reach/nodes", headers=hdr(w.admin_b))
    assert r.status_code == 200 and str(agent_id) not in r.text
    assert await w.db.fetchval("SELECT count(*) FROM reach_nodes WHERE tenant_id = $1 AND node_ref LIKE 'agent:%'",
                               uuid.UUID(B)) == 0
    assert await count(w.db, "reach_node_facts", B) == 0
    # A's agent credential does nothing in B: B's agent routes do not know it, and it cannot post for another id
    r = await w.http.post(f"/v1/fleet/{uuid.uuid4()}/heartbeat", headers={"X-Agent-Token": creds.agent_token}, json={})
    assert r.status_code in (403, 404)
    # an enrollment token minted in B can never create an agent in A
    tok_b = await mint(w, w.admin_b)
    other = runtime(w, "web-b")
    cb = await other.enroll(tok_b["token"])
    assert cb.tenant_id == B
    assert await w.db.fetchval("SELECT tenant_id FROM fleet_agents WHERE id = $1", uuid.UUID(cb.agent_id)) == uuid.UUID(B)
    assert await count(w.db, "fleet_agents", A) == 2          # web-1 and the legacy row; nothing new in A


    # ---- 12. revoking the agent is immediate and nothing it signed is evidence any more -----------------------------
    r = await w.http.post(f"/v1/fleet/agents/{agent_id}/revoke", headers=hdr(w.admin_a), json={"reason": "e2e"})
    assert r.status_code == 200 and r.json()["status"] == "revoked"
    with pytest.raises(sup.agent_client_error()) as exc:
        await rt.heartbeat()
    assert exc.value.status == 403 and exc.value.body_mentions("agent_revoked")
    assert (await w.db.fetchrow("SELECT status FROM fleet_agent_keys WHERE agent_id = $1", agent_id))["status"] == "revoked"
    await evaluate(w)
    for sid in (SSH, FWD):
        res = (await invariant(w, sid))["last_result"]
        assert res["verdict"] == "UNKNOWN" and res["reasons"] == ["empty_selector:to"], res
    assert await w.db.fetchval("SELECT count(*) FROM reach_coverage WHERE node_ref = $1 AND source = 'host_fw'",
                               f"agent:{agent_id}") == 0
    assert (await w.http.post(f"/v1/fleet/agents/{agent_id}/revoke", headers=hdr(w.admin_a), json={})).status_code == 409
    assert len(await audits(w.db, "fleet.agent.revoke", A)) == 1


# --------------------------------------------------------------------------- #
# 20 concurrent redemptions of one token
# --------------------------------------------------------------------------- #

async def test_twenty_concurrent_redemptions_of_one_token_have_exactly_one_winner(world: World):
    w = world
    tok = await mint(w)
    prefix = tok["token"].split("_")[1]
    n = 20
    # the REAL agent code builds each request (its own key, a proof of possession over token prefix + hostname)
    reqs = []
    for i in range(n):
        seed = sup.agent_signing.generate_seed()
        host = f"race-{i:02d}"
        reqs.append((host, seed, {
            "token": tok["token"], "hostname": host,
            "public_key_b64": sup.agent_envelope.b64u(sup.agent_signing.public_key(seed)),
            "proof_b64": sup.agent_envelope.enroll_proof(seed, prefix, host),
            "agent_version": sup.AGENT_VERSION, "capabilities": ["posture"]}))

    # limiter off for this test: it is the atomic redemption, not the lockout, that must give one winner
    saved = (fe.enroll_limiter.limit, fe.enroll_fail_limiter.limit)
    fe.enroll_limiter.limit = fe.enroll_fail_limiter.limit = 10_000
    try:
        rs = await asyncio.gather(*[w.http.post("/v1/fleet/enroll", json=body) for _h, _s, body in reqs])
    finally:
        fe.enroll_limiter.limit, fe.enroll_fail_limiter.limit = saved
    codes = sorted(r.status_code for r in rs)
    assert codes == [201] + [401] * (n - 1), codes
    winner = next(r for r in rs if r.status_code == 201).json()
    for r in rs:
        if r.status_code == 401:
            assert r.json() == rs[[x.status_code for x in rs].index(401)].json()      # one generic, identical refusal
    assert await w.db.fetchval("SELECT count(*) FROM fleet_agents WHERE tenant_id = $1", uuid.UUID(A)) == 1
    assert await w.db.fetchval("SELECT count(*) FROM fleet_agent_keys WHERE tenant_id = $1", uuid.UUID(A)) == 1
    assert (await w.db.fetchrow("SELECT uses, max_uses FROM fleet_enroll_tokens WHERE token_prefix = $1", prefix))["uses"] == 1
    assert len(await audits(w.db, "fleet.agent.enroll", A)) == 1
    assert winner["agent_id"] == str(await w.db.fetchval("SELECT id FROM fleet_agents WHERE tenant_id = $1", uuid.UUID(A)))


async def test_a_multi_use_token_admits_exactly_max_uses_under_concurrency(world: World):
    w = world
    tok = await mint(w, max_uses=3, ttl_minutes=60)
    prefix = tok["token"].split("_")[1]
    reqs = []
    for i in range(12):
        seed = sup.agent_signing.generate_seed()
        host = f"fleet-{i:02d}"
        reqs.append({"token": tok["token"], "hostname": host,
                     "public_key_b64": sup.agent_envelope.b64u(sup.agent_signing.public_key(seed)),
                     "proof_b64": sup.agent_envelope.enroll_proof(seed, prefix, host)})
    saved = (fe.enroll_limiter.limit, fe.enroll_fail_limiter.limit)
    fe.enroll_limiter.limit = fe.enroll_fail_limiter.limit = 10_000
    try:
        rs = await asyncio.gather(*[w.http.post("/v1/fleet/enroll", json=b) for b in reqs])
    finally:
        fe.enroll_limiter.limit, fe.enroll_fail_limiter.limit = saved
    assert sorted(r.status_code for r in rs) == [201] * 3 + [401] * 9
    assert await w.db.fetchval("SELECT count(*) FROM fleet_agents WHERE tenant_id = $1", uuid.UUID(A)) == 3


async def test_with_the_default_rate_limits_the_race_still_has_exactly_one_winner(world: World):
    """Same race with the lockout ON: the failures it provokes are 401 or 429, never a second agent."""
    w = world
    tok = await mint(w)
    prefix = tok["token"].split("_")[1]
    bodies = []
    for i in range(20):
        seed = sup.agent_signing.generate_seed()
        host = f"limit-{i:02d}"
        bodies.append({"token": tok["token"], "hostname": host,
                       "public_key_b64": sup.agent_envelope.b64u(sup.agent_signing.public_key(seed)),
                       "proof_b64": sup.agent_envelope.enroll_proof(seed, prefix, host)})
    rs = await asyncio.gather(*[w.http.post("/v1/fleet/enroll", json=b) for b in bodies])
    codes = [r.status_code for r in rs]
    assert codes.count(201) == 1 and set(codes) <= {201, 401, 429}, codes
    assert all("retry-after" in r.headers for r in rs if r.status_code == 429)
    assert await w.db.fetchval("SELECT count(*) FROM fleet_agents WHERE tenant_id = $1", uuid.UUID(A)) == 1


async def test_key_rotation_end_to_end_with_the_real_agent(world: World):
    w = world
    rt = runtime(w)
    creds = await rt.enroll((await mint(w))["token"])
    old_kid, old_seed = rt.key_id, rt.seed
    await rt.posture()
    new_kid = await rt.call(rt.agent.rotate_key)
    assert new_kid != old_kid and rt.key_id == new_kid
    keys = {r["key_id"]: r["status"] for r in await w.db.fetch(
        "SELECT key_id, status FROM fleet_agent_keys WHERE agent_id = $1", uuid.UUID(creds.agent_id))}
    assert keys == {old_kid: "rotated", new_kid: "active"}
    rot = await audits(w.db, "fleet.agent.key_rotate", A)
    assert len(rot) == 1 and rot[0]["details"].get("new_key_id", new_kid) == new_kid
    ack = await rt.posture()                                  # signed by the NEW key, one seq counter across the rotation
    assert ack["ok"]
    stored = await w.db.fetch("SELECT key_id, seq FROM agent_posture WHERE agent_id = $1 ORDER BY seq",
                              uuid.UUID(creds.agent_id))
    assert [r["key_id"] for r in stored][0] == old_kid
    # the OLD key, which the host may still hold in a backup, can no longer sign anything the server accepts
    env_old = sup.agent_envelope.build_envelope(
        old_seed, agent_id=creds.agent_id, tenant_id=creds.tenant_id, kind="heartbeat",
        seq=99, issued_at=int(dt.datetime.now(UTC).timestamp()),
        payload=sup.agent_envelope.canon({"agent_version": "0.2.0", "status": "ok"}),
        payload_type=sup.agent_envelope.PAYLOAD_TYPE_HEARTBEAT, collectors={"agent": "0.2.0"})
    r = await w.http.post(f"/v1/fleet/{creds.agent_id}/heartbeat", json=env_old, headers={"X-Agent-Token": creds.agent_token})
    assert r.status_code == 401 and r.json()["reason"] == "key_not_active"   # check 4


async def test_a_host_that_lost_its_state_comes_back_only_with_a_rekey_token_and_keeps_its_history(world: World):
    w = world
    rt = runtime(w)
    creds = await rt.enroll((await mint(w))["token"])
    await rt.posture()
    old_kid = rt.key_id
    # the state directory is wiped (reinstall): a fresh agent object finds nothing and must re-enroll
    import shutil

    shutil.rmtree(rt.state_dir)
    again = runtime(w)
    assert again.agent.creds is None
    # a plain token cannot take over the hostname, and does not get spent trying
    plain = await mint(w)
    with pytest.raises(sup.agent_client_error()) as exc:
        await again.enroll(plain["token"])
    assert exc.value.status == 409
    assert (await w.db.fetchrow("SELECT uses FROM fleet_enroll_tokens WHERE token_prefix = $1",
                                plain["token"].split("_")[1]))["uses"] == 0
    # an admin mints a re-key token for exactly this agent
    rk = await mint(w, for_agent=creds.agent_id)
    new = await again.enroll(rk["token"])
    assert new.agent_id == creds.agent_id and new.key_id != old_kid
    keys = {r["key_id"]: (r["status"], r["revoke_reason"]) for r in await w.db.fetch(
        "SELECT key_id, status, revoke_reason FROM fleet_agent_keys WHERE agent_id = $1", uuid.UUID(creds.agent_id))}
    assert keys[old_kid][0] == "revoked" and "re-enrolled" in keys[old_kid][1] and keys[new.key_id][0] == "active"
    assert await w.db.fetchval("SELECT count(*) FROM fleet_agents WHERE tenant_id = $1", uuid.UUID(A)) == 1
    assert await w.db.fetchval("SELECT count(*) FROM agent_posture WHERE agent_id = $1", uuid.UUID(creds.agent_id)) == 1
    assert (await again.posture())["ok"]
    # the old credential is dead (the re-key replaced it)
    r = await w.http.post(f"/v1/fleet/{creds.agent_id}/heartbeat", headers={"X-Agent-Token": creds.agent_token}, json={})
    assert r.status_code == 401


async def test_a_healthy_host_keeps_holds_after_a_key_rotation(world: World):
    w = world
    rt = runtime(w)
    await rt.enroll((await mint(w))["token"])
    await enable_std(w)
    await rt.posture()
    await evaluate(w)
    assert await verdicts(w) == {SSH: "HOLDS", FWD: "HOLDS"}
    await rt.call(rt.agent.rotate_key)
    await rt.posture()
    await evaluate(w)
    assert await verdicts(w) == {SSH: "HOLDS", FWD: "HOLDS"}
