"""P2 adversarial review, package B: server wire, enrollment and report hardening.

One regression test per confirmed finding (the key is in the test name). Every test asserts the SAFE outcome, never
only that something raised: an unsafe input must not produce an acceptance, a false HOLDS, a silent closure, an
unaudited crash or an unbounded write. Shared fixtures and helpers come from ``test_fleet_posture`` (two tenants,
real HTTP surface, AUTH_MODE=enforce, the RLS-enforcing role).
"""
from __future__ import annotations

import asyncio
import datetime as dt
import json
import time
import uuid
from collections import Counter
from pathlib import Path

import asyncpg
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from httpx import ASGITransport, AsyncClient

from app import fleet_enroll as fe
from app import fleet_posture as fp
from app.config import settings

from .test_fleet_posture import (  # noqa: F401  (fixtures are shared on purpose)
    TENANT_A, _reset_limiters, agent_row, audits, b64u, build_envelope, canon, enforce, enroll_host, good_posture,
    hb, hdr, kid_of, key_row, pbytes, post, posture_rows, ps, pubkey, rejected, rls_app, rotate_payload, world)

def _peer(app, ip: str) -> AsyncClient:
    """A client whose socket peer is ``ip`` (what ``request.client`` reports)."""
    return AsyncClient(transport=ASGITransport(app=app, client=(ip, 5555)), base_url="http://test")


def _posture(tries: int = 3, **kw) -> dict:
    p = good_posture(**kw)
    p["sections"]["sshd"]["v"]["config"]["maxauthtries"] = tries
    return p


def _set(monkeypatch, mod, name, value):
    """Set a (possibly not yet existing) knob: the test must fail on the BEHAVIOUR, not on a missing attribute."""
    monkeypatch.setattr(mod, name, value, raising=False)


# =========================================================================== #
# wire-2: posture / inventory storage is bounded for a hostile (valid key / leaked bearer) sender
# =========================================================================== #

async def test_wire_2_changed_postures_coalesce_into_one_row_per_interval(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    for tries in (3, 4, 5, 6, 7):
        r = await ps(c, host, _posture(tries))
        assert r.status_code == 200 and r.json()["stored"] is True and r.json()["changed"] is True
    rows = await posture_rows(world.db, host.agent_id)
    assert len(rows) == 1, f"{len(rows)} posture rows for 5 changes inside one interval"
    # coalescing OVERWRITES the newest row: the newest evidence is never delayed or dropped
    latest = await fp.latest_posture(world.db, uuid.UUID(host.agent_id))
    assert latest["seq"] == 5
    assert latest["payload"]["sections"]["sshd"]["v"]["config"]["maxauthtries"] == 7
    assert latest["signed"] is True and latest["key_status"] == "active"


async def test_wire_2_a_new_interval_or_a_new_key_gets_a_new_row(world, monkeypatch):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    assert (await ps(c, host, _posture(3))).status_code == 200
    # age the row past the interval: the next change is a NEW row
    await world.db.execute("UPDATE agent_posture SET received_at = NOW() - interval '1 hour' WHERE agent_id=$1",
                           uuid.UUID(host.agent_id))
    a = await agent_row(world.db, host.agent_id)
    ident = json.loads(a["identity"]) if isinstance(a["identity"], str) else dict(a["identity"])
    ident["_ingest"]["row_at"] = "2020-01-01T00:00:00Z"
    ident["_ingest"]["stored_at"] = "2020-01-01T00:00:00Z"
    await world.db.execute("UPDATE fleet_agents SET identity=$2::jsonb WHERE id=$1", uuid.UUID(host.agent_id),
                           json.dumps(ident))
    assert (await ps(c, host, _posture(4))).status_code == 200
    assert len(await posture_rows(world.db, host.agent_id)) == 2
    # a rotation keeps the signed-by-the-active-key rule: the first posture under the new key is its own row
    new_sk = Ed25519PrivateKey.generate()
    r = await post(c, host, "keys/rotate", host.env("rotate", rotate_payload(new_sk, host.agent_id, host.kid)))
    assert r.status_code == 200, r.text
    host.sk, host.kid, host.seq = new_sk, kid_of(new_sk), 0
    assert (await ps(c, host, _posture(4))).status_code == 200
    rows = await posture_rows(world.db, host.agent_id)
    assert len(rows) == 3 and rows[-1]["key_id"] == host.kid


async def test_wire_2_per_agent_byte_cap_evicts_oldest_but_never_the_newest(world, monkeypatch):
    c = world.client
    size = len(pbytes(_posture(3)))
    _set(monkeypatch, fp, "MIN_STORE_INTERVAL_S", 0)                 # one row per change, so the cap is what bounds
    _set(monkeypatch, fp, "AGENT_POSTURE_MAX_BYTES", int(size * 2.5))
    host = await enroll_host(c, world.admin_a)
    for tries in (3, 4, 5, 6, 7):
        assert (await ps(c, host, _posture(tries))).status_code == 200
    rows = await posture_rows(world.db, host.agent_id)
    assert sum(r["size_bytes"] for r in rows) <= int(size * 2.5), [r["seq"] for r in rows]
    assert [r["seq"] for r in rows][-1] == 5 and 1 not in [r["seq"] for r in rows]
    # a single posture bigger than the cap is still kept (the newest evidence is never evicted)
    _set(monkeypatch, fp, "AGENT_POSTURE_MAX_BYTES", 10)
    assert (await ps(c, host, _posture(8))).status_code == 200
    rows = await posture_rows(world.db, host.agent_id)
    assert [r["seq"] for r in rows] == [6]


async def test_wire_2_per_tenant_byte_cap_evicts_oldest_but_keeps_every_agents_newest(world, monkeypatch):
    c = world.client
    size = len(pbytes(_posture(3)))
    _set(monkeypatch, fp, "MIN_STORE_INTERVAL_S", 0)
    _set(monkeypatch, fp, "TENANT_EVICT_EVERY_S", 0)           # the O(tenant rows) check is throttled in production
    _set(monkeypatch, fp, "TENANT_POSTURE_MAX_BYTES", int(size * 3.5))
    a = await enroll_host(c, world.admin_a, "web-1")
    b = await enroll_host(c, world.admin_a, "web-2")
    for host, tries in ((a, 3), (a, 4), (b, 3), (b, 4), (a, 5), (b, 5)):
        assert (await ps(c, host, _posture(tries))).status_code == 200
    rows_a, rows_b = await posture_rows(world.db, a.agent_id), await posture_rows(world.db, b.agent_id)
    assert len(rows_a) + len(rows_b) <= 3, (len(rows_a), len(rows_b))
    assert rows_a[-1]["seq"] == 3 and rows_b[-1]["seq"] == 3            # each agent keeps its newest


async def test_wire_2_enrolled_agents_per_tenant_are_capped_but_rekey_still_works(world, monkeypatch):
    c = world.client
    _set(monkeypatch, fe, "MAX_AGENTS_PER_TENANT", 2)
    h1 = await enroll_host(c, world.admin_a, "web-1")
    await enroll_host(c, world.admin_a, "web-2")
    tok = (await c.post("/v1/fleet/enroll-tokens", headers=hdr(world.admin_a), json={})).json()["token"]
    sk = Ed25519PrivateKey.generate()
    proof = sk.sign(b"paddock-enroll/v1\n" + tok.split("_")[1].encode() + b"\nweb-3")
    r = await c.post("/v1/fleet/enroll", json={"token": tok, "hostname": "web-3", "public_key_b64": b64u(pubkey(sk)),
                                               "proof_b64": b64u(proof)})
    assert r.status_code in (403, 409, 422), (r.status_code, r.text)
    async with world.db.acquire() as con:
        assert await con.fetchval("SELECT count(*) FROM fleet_agents") == 2
        assert await con.fetchval("SELECT uses FROM fleet_enroll_tokens WHERE token_prefix=$1",
                                  tok.split("_")[1]) == 0        # a refusal does not spend the token
    # re-keying an EXISTING agent is not a new agent
    rk = (await c.post("/v1/fleet/enroll-tokens", headers=hdr(world.admin_a), json={"for_agent": h1.agent_id})).json()
    sk2 = Ed25519PrivateKey.generate()
    proof = sk2.sign(b"paddock-enroll/v1\n" + rk["token_prefix"].encode() + b"\nweb-1")
    r = await c.post("/v1/fleet/enroll", json={"token": rk["token"], "hostname": "web-1",
                                               "public_key_b64": b64u(pubkey(sk2)), "proof_b64": b64u(proof)})
    assert r.status_code == 201, r.text


def _inv(i: int = 0, n: int = 1) -> bytes:
    return json.dumps({"os_info": {"system": "Linux", "i": i}, "packages": [{"name": f"p{k}"} for k in range(n)],
                       "listeners": [], "posture": {}}).encode()


async def test_wire_2_identical_v1_inventory_is_deduplicated_and_history_is_capped(world, monkeypatch):
    c = world.client
    fp.inventory_limiter.limit = 1000
    host = await enroll_host(c, world.admin_a)
    url = f"/v1/fleet/{host.agent_id}/inventory"
    r1 = await c.post(url, headers=host.h, content=_inv(1))
    r2 = await c.post(url, headers=host.h, content=_inv(1))
    assert r1.status_code == 201 and r2.status_code in (200, 201)
    n = await world.db.fetchval("SELECT count(*) FROM agent_inventory WHERE agent_id=$1", uuid.UUID(host.agent_id))
    assert n == 1, f"{n} inventory rows for two identical posts"
    assert r2.json()["inventory_id"] == r1.json()["inventory_id"]
    for i in range(2, 14):
        assert (await c.post(url, headers=host.h, content=_inv(i))).status_code in (200, 201)
    n = await world.db.fetchval("SELECT count(*) FROM agent_inventory WHERE agent_id=$1", uuid.UUID(host.agent_id))
    assert n <= 5, f"{n} inventory rows kept for one agent"
    newest = await world.db.fetchval(
        "SELECT os_info FROM agent_inventory WHERE agent_id=$1 ORDER BY collected_at DESC LIMIT 1",
        uuid.UUID(host.agent_id))
    assert (json.loads(newest) if isinstance(newest, str) else newest)["i"] == 13


async def test_wire_2_v1_inventory_body_cap_is_two_mib(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    big = json.dumps({"packages": [{"name": "x" * 150, "version": "1"} for _ in range(15000)]}).encode()
    assert 2 * 1024 * 1024 < len(big) < 4 * 1024 * 1024
    r = await c.post(f"/v1/fleet/{host.agent_id}/inventory", headers=host.h, content=big)
    assert r.status_code == 413, r.status_code


# =========================================================================== #
# wire-3 / enroll-1: the per-agent budget is charged only for VERIFIED envelopes; a bearer-only holder from
# another address cannot lock the real agent out; flooding cannot grow the audit chain one row per request
# =========================================================================== #

@pytest.mark.parametrize("route,kind,n", [("heartbeat", "heartbeat", 70), ("posture", "posture", 25),
                                          ("keys/rotate", "rotate", 12)])
async def test_wire_3_a_bearer_only_flood_cannot_lock_out_the_real_agent(world, rls_app, route, kind, n):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    codes = Counter()
    async with _peer(rls_app, "203.0.113.9") as bad:
        for _ in range(n):
            r = await bad.post(f"/v1/fleet/{host.agent_id}/{route}", content=b"{}", headers=host.h)
            codes[r.status_code] += 1
    assert codes[200] == 0
    payload = None
    if kind == "rotate":
        payload = rotate_payload(Ed25519PrivateKey.generate(), host.agent_id, host.kid)
    elif kind == "posture":
        payload = _posture(3)
    r = await post(c, host, route, host.env(kind, payload))        # the real agent, from its own address
    assert r.status_code == 200, (codes, r.status_code, r.text)


async def test_wire_3_garbage_never_charges_the_per_agent_budget(world, rls_app):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    sk = Ed25519PrivateKey.generate()                              # not the agent's key
    async with _peer(rls_app, "203.0.113.9") as bad:
        for i in range(25):
            env = host.env("posture", _posture(3), sk=sk, kid=host.kid, seq=i + 1)
            r = await bad.post(f"/v1/fleet/{host.agent_id}/posture", json=env, headers=host.h)
            assert r.status_code in (401, 429), r.status_code
    assert not fp.posture_limiter._hits.get(host.agent_id), "unverified envelopes were charged to the agent"
    assert (await ps(c, host)).status_code == 200


async def test_wire_3_rejection_audit_rows_are_aggregated_but_the_counter_is_exact(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    codes = Counter()
    for _ in range(80):
        r = await c.post(f"/v1/fleet/{host.agent_id}/heartbeat", content=b"{}", headers=host.h)
        codes[r.status_code] += 1
    processed = codes[400]
    assert processed >= 20, codes                                      # the bad ones were really processed
    a = await agent_row(world.db, host.agent_id)
    assert a["rejected_total"] == processed, (a["rejected_total"], codes)          # the counter stays exact
    rows = await rejected(world.db, host)
    assert 1 <= len(rows) <= 15, f"{len(rows)} audit rows for {processed} rejections"
    throttled = await audits(world.db, "fleet.evidence.throttled", host.agent_id)
    assert len(throttled) <= 3
    # the sampled rows say how many were folded into them
    folded = sum(int(r["details"].get("suppressed_before", 0)) for r in rows)
    assert folded + len(rows) <= processed


async def test_wire_3_throttled_requests_do_not_write_an_evidence_row_each(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    fp.heartbeat_limiter.limit = 2
    for _ in range(2):
        assert (await hb(c, host)).status_code == 200
    before = len(await audits(world.db, "fleet.evidence.rejected", host.agent_id))
    for _ in range(40):
        assert (await hb(c, host)).status_code == 429
    after = len(await audits(world.db, "fleet.evidence.rejected", host.agent_id))
    assert after - before <= 3, f"{after - before} evidence rows for 40 rate-limited requests"


# =========================================================================== #
# wire-4 / srv-env-1: lone surrogates and unexpected exceptions are clean, audited rejections
# =========================================================================== #

def _mut_collectors_value(env):
    env["collectors"]["agent"] = "x\ud800y"


def _mut_collectors_key(env):
    env["collectors"] = {"a\ud800": "x"}


def _mut_alg(env):
    env["alg"] = "ed25519\ud800"


def _mut_collectors_low(env):
    env["collectors"]["sshd"] = "\udc00"


@pytest.mark.parametrize("mut", [_mut_collectors_value, _mut_collectors_key, _mut_alg, _mut_collectors_low])
@pytest.mark.parametrize("kind", ["heartbeat", "posture"])
async def test_wire_4_a_lone_surrogate_in_the_envelope_is_an_audited_4xx(world, mut, kind):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    env = host.env(kind)
    mut(env)
    body = json.dumps(env).encode()                                # ensure_ascii: the surrogate travels as \ud800
    assert b"\\ud8" in body.lower() or b"\\udc" in body.lower()
    r = await post(c, host, kind, body)
    assert 400 <= r.status_code < 500, (r.status_code, r.text)
    assert r.json()["reason"] in ("bad_envelope", "alg_not_allowed")
    rows = await rejected(world.db, host)
    assert len(rows) == 1 and rows[0]["details"]["reason"] == r.json()["reason"]
    assert (await agent_row(world.db, host.agent_id))["rejected_total"] == 1
    assert (await key_row(world.db, host.agent_id, host.kid))["last_seq"] == 0


async def test_wire_4_a_lone_surrogate_in_a_signed_payload_is_a_422_that_keeps_the_previous_posture(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    assert (await ps(c, host)).status_code == 200
    raw = pbytes(good_posture())
    assert raw.count(b'"Ubuntu 24.04 LTS"') == 1
    bad = raw.replace(b'"Ubuntu 24.04 LTS"', b'"\\ud800"')
    r = await ps(c, host, bad)
    assert r.status_code in (400, 422), (r.status_code, r.text)
    assert (await key_row(world.db, host.agent_id, host.kid))["last_seq"] == 1       # the claim rolled back
    assert len(await posture_rows(world.db, host.agent_id)) == 1
    rows = await rejected(world.db, host)
    assert len(rows) == 1 and rows[0]["details"]["http_status"] == r.status_code
    assert (await ps(c, host)).status_code == 200                                     # the host is not wedged


async def test_wire_4_parse_envelope_never_raises_anything_but_a_rejection():
    base = {"v": 1, "alg": "ed25519", "kid": "k" * 32, "agent_id": str(uuid.uuid4()), "tenant_id": str(uuid.uuid4()),
            "kind": "heartbeat", "seq": 1, "issued_at": "2026-01-01T00:00:00Z", "nonce": b64u(b"0" * 16),
            "payload_type": "paddock.host.heartbeat/v1", "payload_sha256": "0" * 64, "payload_len": 0,
            "collectors": {"agent": "0.2.0"}, "payload_b64": "", "sig": b64u(b"0" * 64)}
    for field, value in (("alg", "\ud800"), ("collectors", {"\ud800": "x"}), ("collectors", {"a": "\udfff"}),
                         ("kid", "\ud800"), ("nonce", "\ud800"), ("payload_type", "\ud800"),
                         ("issued_at", "\ud800"), ("kind", "\ud800")):
        env = {**base, field: value}
        with pytest.raises(fp.Rejection) as ei:
            fp.parse_envelope(json.dumps(env).encode(), "heartbeat")
        assert ei.value.status in (400, 401), (field, ei.value.status)


async def test_wire_4_an_unexpected_exception_on_the_data_plane_is_audited(world, monkeypatch):
    c = world.client
    host = await enroll_host(c, world.admin_a)

    async def boom(*a, **kw):
        raise RuntimeError("boom")

    monkeypatch.setattr(fp, "_claim_and_persist", boom)
    r = await hb(c, host)
    assert r.status_code == 500 and r.json()["reason"] == "internal_error"
    rows = await rejected(world.db, host)
    assert len(rows) == 1 and rows[0]["details"]["reason"] == "internal_error"
    assert "boom" not in json.dumps(r.json())                      # no internals in the answer
    assert (await agent_row(world.db, host.agent_id))["rejected_total"] == 1


# =========================================================================== #
# wire-1-canon: seq and collectors keys stay inside what RFC 8785 and Python's canon agree on
# =========================================================================== #

def _hb_env(**over) -> bytes:
    env = {"v": 1, "alg": "ed25519", "kid": "k" * 32, "agent_id": str(uuid.uuid4()), "tenant_id": str(uuid.uuid4()),
           "kind": "heartbeat", "seq": 1, "issued_at": "2026-01-01T00:00:00Z", "nonce": b64u(b"0" * 16),
           "payload_type": "paddock.host.heartbeat/v1", "payload_sha256": "0" * 64, "payload_len": 0,
           "collectors": {"agent": "0.2.0"}, "payload_b64": "", "sig": b64u(b"0" * 64)}
    env.update(over)
    return json.dumps(env).encode()


def test_wire_1_canon_seq_is_capped_at_2_pow_53_minus_1():
    assert fp.parse_envelope(_hb_env(seq=2 ** 53 - 1), "heartbeat").seq == 2 ** 53 - 1
    for seq in (2 ** 53, 2 ** 62, 2 ** 62 + 1):
        with pytest.raises(fp.Rejection) as ei:
            fp.parse_envelope(_hb_env(seq=seq), "heartbeat")
        assert ei.value.status == 400 and ei.value.reason == "bad_envelope", seq


def test_wire_1_canon_collectors_keys_are_ascii_identifiers():
    for key in ("agent", "sshd", "a.b-c_1", "x" * 64):
        fp.parse_envelope(_hb_env(collectors={key: "1"}), "heartbeat")
    for key in ("Agent", "a b", "é", "\U00010000", "￿", "a/b", "", "x" * 65, "a:b"):
        with pytest.raises(fp.Rejection) as ei:
            fp.parse_envelope(_hb_env(collectors={key: "1"}), "heartbeat")
        assert ei.value.status == 400 and ei.value.reason == "bad_envelope", repr(key)


# =========================================================================== #
# wire-6: "reporting" means a verified signer inside the window, not merely enrolled
# =========================================================================== #

async def test_wire_6_reports_count_only_agents_that_can_and_do_report(world):
    from datetime import timedelta

    from app.reports import compliance, metrics

    c, db = world.client, world.db
    good = await enroll_host(c, world.admin_a, "good")
    assert (await hb(c, good)).status_code == 200
    await enroll_host(c, world.admin_a, "never-signed")
    legacy = await enroll_host(c, world.admin_a, "legacy")
    assert (await hb(c, legacy)).status_code == 200
    await db.execute("UPDATE fleet_agents SET legacy = TRUE WHERE id = $1", uuid.UUID(legacy.agent_id))
    revoked_key = await enroll_host(c, world.admin_a, "key-revoked")
    assert (await hb(c, revoked_key)).status_code == 200
    r = await c.post(f"/v1/fleet/agents/{revoked_key.agent_id}/keys/{revoked_key.kid}/revoke",
                     headers=hdr(world.admin_a), json={"reason": "x"})
    assert r.status_code == 200
    silent = await enroll_host(c, world.admin_a, "silent")
    assert (await hb(c, silent)).status_code == 200
    await db.execute("UPDATE fleet_agents SET last_seen = NOW() - interval '40 days' WHERE id = $1",
                     uuid.UUID(silent.agent_id))
    offline = await enroll_host(c, world.admin_a, "offline")
    assert (await hb(c, offline)).status_code == 200
    await db.execute("UPDATE fleet_agents SET online = FALSE WHERE id = $1", uuid.UUID(offline.agent_id))
    now = dt.datetime.now(dt.timezone.utc)

    ctx = compliance.Ctx(pool=db, now=now, cr=metrics.clearance_rank_of("restricted"), clearance="restricted",
                         fresh=timedelta(days=30))
    async with db.acquire() as con:
        ev = await compliance._internal_visibility(con, ctx)
    assert ev.metrics["agents"] == 1, ev.metrics
    rep = await metrics.build_report(db, days=7, end=now + timedelta(minutes=1), clearance="restricted")
    assert rep.coverage.fleet_agents_recent == 1, rep.coverage.fleet_agents_recent


# =========================================================================== #
# wire-7: revoking a rotated key must not silently leave its (attacker-chosen) successor active
# =========================================================================== #

async def _rotate(c, host, new_sk):
    r = await post(c, host, "keys/rotate", host.env("rotate", rotate_payload(new_sk, host.agent_id, host.kid)))
    assert r.status_code == 200, r.text
    host.sk, host.kid, host.seq = new_sk, kid_of(new_sk), 0


async def test_wire_7_revoking_a_rotated_key_with_an_active_successor_needs_a_decision(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    k1 = host.kid
    new_sk = Ed25519PrivateKey.generate()
    await _rotate(c, host, new_sk)
    k2 = kid_of(new_sk)
    url = f"/v1/fleet/agents/{host.agent_id}/keys/{k1}/revoke"
    r = await c.post(url, headers=hdr(world.admin_a), json={"reason": "stolen"})
    assert r.status_code == 409, (r.status_code, r.text)           # not a silent half revocation
    assert r.json()["active_successors"] == [k2]
    keys = {k["key_id"]: k["status"] for k in await key_row(world.db, host.agent_id)}
    assert keys == {k1: "rotated", k2: "active"}                  # nothing changed
    r = await c.post(url, headers=hdr(world.admin_a), json={"reason": "stolen", "successors": "revoke"})
    assert r.status_code == 200, r.text
    assert r.json()["revoked_successors"] == [k2]
    keys = {k["key_id"]: k["status"] for k in await key_row(world.db, host.agent_id)}
    assert keys == {k1: "revoked", k2: "revoked"}
    host.sk, host.kid = new_sk, k2
    assert (await hb(c, host)).status_code == 401                 # the successor is dead
    rk = (await key_row(world.db, host.agent_id, k2))
    assert rk["rotated_from"] == k1


async def test_wire_7_routine_cleanup_can_keep_the_live_successor(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    k1 = host.kid
    new_sk = Ed25519PrivateKey.generate()
    await _rotate(c, host, new_sk)
    r = await c.post(f"/v1/fleet/agents/{host.agent_id}/keys/{k1}/revoke", headers=hdr(world.admin_a),
                     json={"reason": "cleanup", "successors": "keep"})
    assert r.status_code == 200 and r.json()["revoked_successors"] == []
    host.sk, host.kid, host.seq = new_sk, kid_of(new_sk), 0
    assert (await hb(c, host)).status_code == 200


async def test_wire_7_a_key_without_a_successor_revokes_as_before(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    r = await c.post(f"/v1/fleet/agents/{host.agent_id}/keys/{host.kid}/revoke", headers=hdr(world.admin_a),
                     json={"reason": "x"})
    assert r.status_code == 200 and r.json()["status"] == "revoked"


# =========================================================================== #
# enroll-2: one global lock order (tokens, then the agent row, then keys), and a deadlock is retried
# =========================================================================== #

async def _wait_for_lock_waiter(db, timeout: float = 5.0) -> bool:
    """True once some backend of this database is blocked on a lock (no fixed sleep: it polls the condition)."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        n = await db.fetchval(
            "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'")
        if n:
            return True
        await asyncio.sleep(0.01)
    return False


async def test_enroll_2_rekey_enrollment_and_agent_revoke_do_not_deadlock(db_pool, monkeypatch):
    pool = db_pool
    agent_key = Ed25519PrivateKey.generate()

    def kwargs(token, host, sk):
        prefix = token.split("_")[1]
        return dict(token=token, hostname=host, public_key_b64=b64u(pubkey(sk)),
                    proof_b64=b64u(sk.sign(b"paddock-enroll/v1\n" + prefix.encode() + b"\n" + host.encode())),
                    agent_version="0.2.0", client_ip="198.51.100.7")

    first, _ = await fe.mint_token(pool, actor="admin@test")
    out = await fe.enroll_agent(pool, **kwargs(first, "web1", agent_key))
    agent_id = uuid.UUID(out["agent_id"])
    rekey, _ = await fe.mint_token(pool, actor="admin@test", for_agent=agent_id)

    entered = asyncio.Event()
    orig = fe._rekey

    async def held_rekey(*a, **kw):
        entered.set()                      # the token claim is held; now let the revoke run into it
        await _wait_for_lock_waiter(pool)
        return await orig(*a, **kw)

    monkeypatch.setattr(fe, "_rekey", held_rekey)
    new_sk = Ed25519PrivateKey.generate()
    t_enroll = asyncio.create_task(fe.enroll_agent(pool, **kwargs(rekey, "web1", new_sk)))
    await entered.wait()
    t_revoke = asyncio.create_task(fp.revoke_agent(pool, agent_id, actor="admin@test", actor_role="admin",
                                                   reason="incident"))
    res = await asyncio.gather(t_enroll, t_revoke, return_exceptions=True)
    assert not any(isinstance(r, BaseException) for r in res), res
    assert res[1] == "revoked"
    assert getattr(fp, "deadlock_retries", 0) + getattr(fe, "deadlock_retries", 0) == 0, "a deadlock was retried"
    async with pool.acquire() as con:
        a = await con.fetchrow("SELECT status, revoked_at FROM fleet_agents WHERE id=$1", agent_id)
        active = await con.fetchval("SELECT count(*) FROM fleet_agent_keys WHERE agent_id=$1 AND status='active'",
                                    agent_id)
    assert a["status"] == "revoked" and a["revoked_at"] is not None
    assert active == 0                                              # whoever won, nothing is left usable


async def test_enroll_2_a_deadlock_is_retried_not_surfaced():
    calls = []

    async def flaky():
        calls.append(1)
        if len(calls) < 3:
            raise asyncpg.DeadlockDetectedError("deadlock detected")
        return "ok"

    assert await fe.retry_on_deadlock(flaky) == "ok" and len(calls) == 3
    calls.clear()

    async def always():
        calls.append(1)
        raise asyncpg.DeadlockDetectedError("deadlock detected")

    with pytest.raises(asyncpg.DeadlockDetectedError):
        await fe.retry_on_deadlock(always)
    assert len(calls) == 3                                          # bounded


# =========================================================================== #
# enroll-3: names are matched whole
# =========================================================================== #

async def _enroll_raw(c, admin, hostname, caps=None, token=None):
    sk = Ed25519PrivateKey.generate()
    if token is None:
        token = (await c.post("/v1/fleet/enroll-tokens", headers=hdr(admin), json={"max_uses": 5})).json()["token"]
    prefix = token.split("_")[1]
    proof = sk.sign(b"paddock-enroll/v1\n" + prefix.encode() + b"\n" + hostname.encode())
    body = {"token": token, "hostname": hostname, "public_key_b64": b64u(pubkey(sk)), "proof_b64": b64u(proof)}
    if caps is not None:
        body["capabilities"] = caps
    return await c.post("/v1/fleet/enroll", json=body), token


@pytest.mark.parametrize("name", ["web1\n", "web1\r\n", "\nweb1", " web1", "web1 ", "web1\t", "web1..", ".", ".."])
async def test_enroll_3_hostnames_that_differ_from_their_stripped_form_are_refused(world, name):
    c = world.client
    r, token = await _enroll_raw(c, world.admin_a, name)
    assert r.status_code == 400, (repr(name), r.status_code, r.text)
    async with world.db.acquire() as con:
        assert await con.fetchval("SELECT count(*) FROM fleet_agents") == 0
        assert await con.fetchval("SELECT uses FROM fleet_enroll_tokens WHERE token_prefix=$1",
                                  token.split("_")[1]) == 0


async def test_enroll_3_a_trailing_dot_is_one_canonical_name(world):
    c = world.client
    r, token = await _enroll_raw(c, world.admin_a, "Web1.example.com.")
    assert r.status_code == 201, r.text
    assert r.json()["hostname"] == "web1.example.com"
    r, _ = await _enroll_raw(c, world.admin_a, "web1.example.com", token=token)
    assert r.status_code == 409                                    # the same host, not a lookalike
    r, _ = await _enroll_raw(c, world.admin_a, "WEB1.EXAMPLE.COM", token=token)
    assert r.status_code == 409


@pytest.mark.parametrize("cap", ["net\n", "net ", "\nnet", "NET", "n-t"])
async def test_enroll_3_capabilities_are_matched_whole(world, cap):
    c = world.client
    r, _ = await _enroll_raw(c, world.admin_a, "web1", caps=[cap])
    assert r.status_code == 400, (repr(cap), r.status_code, r.text)


# =========================================================================== #
# enroll-4: a key-revoked agent keeps no usable bearer on ANY agent route
# =========================================================================== #

async def test_enroll_4_revoking_the_active_key_cuts_inventory_and_action_results(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    from .test_fleet_posture import seed_key
    admin2 = await seed_key(world.db, TENANT_A, "admin-a2", "admin")
    p = (await c.post("/v1/fleet/actions", headers=hdr(world.admin_a), json={
        "agent_id": host.agent_id, "action_type": "block_ip", "target": "203.0.113.10"})).json()
    assert (await c.post(f"/v1/fleet/actions/{p['id']}/approve", headers=hdr(admin2),
                         json={"apply_for_real": True})).status_code == 200
    url = f"/v1/fleet/{host.agent_id}/inventory"
    assert (await c.post(url, headers=host.h, content=_inv(1))).status_code == 201       # works with a key
    r = await c.post(f"/v1/fleet/agents/{host.agent_id}/keys/{host.kid}/revoke", headers=hdr(world.admin_a),
                     json={"reason": "stolen"})
    assert r.status_code == 200
    assert (await hb(c, host)).status_code == 401                                         # signed routes: cut
    r = await c.post(url, headers=host.h, content=_inv(2))
    assert r.status_code == 401 and r.json().get("reason") == "key_not_active", (r.status_code, r.text)
    body = {"status": "applied", "output": {"ok": True}, "revert": {"mechanism": "iptables", "commands": []}}
    r = await c.post(f"/v1/fleet/actions/{p['id']}/result", headers=host.h, json=body)
    assert r.status_code == 401 and r.json().get("reason") == "key_not_active", (r.status_code, r.text)
    async with world.db.acquire() as con:
        assert await con.fetchval("SELECT status FROM agent_actions WHERE id=$1", uuid.UUID(p["id"])) == "approved"
        assert await con.fetchval("SELECT count(*) FROM agent_inventory WHERE agent_id=$1",
                                  uuid.UUID(host.agent_id)) == 1


async def test_enroll_4_a_rekeyed_agent_works_again(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    await c.post(f"/v1/fleet/agents/{host.agent_id}/keys/{host.kid}/revoke", headers=hdr(world.admin_a),
                 json={"reason": "stolen"})
    rk = (await c.post("/v1/fleet/enroll-tokens", headers=hdr(world.admin_a), json={"for_agent": host.agent_id})).json()
    sk = Ed25519PrivateKey.generate()
    proof = sk.sign(b"paddock-enroll/v1\n" + rk["token_prefix"].encode() + b"\nweb-1")
    r = await c.post("/v1/fleet/enroll", json={"token": rk["token"], "hostname": "web-1",
                                               "public_key_b64": b64u(pubkey(sk)), "proof_b64": b64u(proof)})
    assert r.status_code == 201, r.text
    h = {"X-Agent-Token": r.json()["agent_token"], "Content-Type": "application/json"}
    assert (await c.post(f"/v1/fleet/{host.agent_id}/inventory", headers=h, content=_inv(3))).status_code == 201


# =========================================================================== #
# enroll-5: the enrollment limiters key on the strict peer (and the token prefix when there is none)
# =========================================================================== #

async def test_enroll_5_a_forged_leftmost_xff_cannot_lock_a_victim_out(world, monkeypatch):
    monkeypatch.setattr(settings, "trusted_proxy_cidrs", "127.0.0.0/8")
    c = world.client                                              # peer 127.0.0.1 is the trusted, appending proxy
    junk = {"token": "fet_" + "0" * 12 + "_" + "x" * 30, "hostname": "h", "public_key_b64": "AA", "proof_b64": "AA"}
    codes = []
    for _ in range(7):                                            # the attacker really is 203.0.113.250
        r = await c.post("/v1/fleet/enroll", json=junk,
                         headers={"X-Forwarded-For": "198.51.100.77, 203.0.113.250"})
        codes.append(r.status_code)
    assert codes[-1] == 429 or codes[-2] == 429, codes            # the attacker locks THEMSELVES out
    # the victim (really 198.51.100.77: the proxy appends only that) is untouched
    host = await enroll_host(c, world.admin_a, "victim", headers={"X-Forwarded-For": "198.51.100.77"})
    assert host.agent_id


async def test_enroll_5_without_a_peer_address_junk_for_one_token_does_not_block_another(pool_db):
    pool = pool_db

    def kw(token, host):
        sk = Ed25519PrivateKey.generate()
        prefix = token.split("_")[1]
        return dict(token=token, hostname=host, public_key_b64=b64u(pubkey(sk)),
                    proof_b64=b64u(sk.sign(b"paddock-enroll/v1\n" + prefix.encode() + b"\n" + host.encode())),
                    client_ip=None)

    for i in range(8):
        with pytest.raises(fe.EnrollError) as ei:
            await fe.enroll_agent(pool, **kw("fet_" + "1" * 12 + "_" + "A" * 43, f"junk{i}"))
        assert ei.value.status in (401, 429)
    full, _ = await fe.mint_token(pool, actor="admin@test")
    out = await fe.enroll_agent(pool, **kw(full, "victim"))
    assert out["agent_id"]


@pytest.fixture
def pool_db(db_pool):
    return db_pool


# =========================================================================== #
# enroll-6: revoking an agent offers (and by default performs) revoking the fleet token it enrolled with
# =========================================================================== #

async def test_enroll_6_revoking_an_agent_revokes_the_fleet_token_it_came_from(world):
    c = world.client
    r, token = await _enroll_raw(c, world.admin_a, "web1")
    assert r.status_code == 201
    agent_id = r.json()["agent_id"]
    r, _ = await _enroll_raw(c, world.admin_a, "web2", token=token)
    assert r.status_code == 201                                    # the fleet token is multi-use
    r = await c.post(f"/v1/fleet/agents/{agent_id}/revoke", headers=hdr(world.admin_a), json={"reason": "stolen"})
    assert r.status_code == 200, r.text
    r, _ = await _enroll_raw(c, world.admin_a, "web1-new", token=token)
    assert r.status_code == 401, (r.status_code, r.text)           # the revoked host cannot come back as a new agent
    body = (await c.post(f"/v1/fleet/agents/{agent_id}/revoke", headers=hdr(world.admin_a), json={})).json()
    assert body["detail"]
    t = [x for x in (await c.get("/v1/fleet/enroll-tokens", headers=hdr(world.admin_a))).json()
         if x["token_prefix"] == token.split("_")[1]][0]
    assert t["state"] == "revoked"


async def test_enroll_6_the_response_says_what_happened_and_the_token_can_be_kept(world):
    c = world.client
    r, token = await _enroll_raw(c, world.admin_a, "web1")
    agent_id = r.json()["agent_id"]
    r = await c.post(f"/v1/fleet/agents/{agent_id}/revoke", headers=hdr(world.admin_a),
                     json={"reason": "x", "revoke_enroll_token": False})
    assert r.status_code == 200
    assert r.json()["enroll_token_prefix"] == token.split("_")[1] and r.json()["enroll_token_revoked"] is False
    r, _ = await _enroll_raw(c, world.admin_a, "web2", token=token)
    assert r.status_code == 201                                    # explicit choice: the fleet token lives on
    r, token2 = await _enroll_raw(c, world.admin_a, "web3")
    other = r.json()["agent_id"]
    r = await c.post(f"/v1/fleet/agents/{other}/revoke", headers=hdr(world.admin_a), json={"reason": "x"})
    assert r.json()["enroll_token_prefix"] == token2.split("_")[1] and r.json()["enroll_token_revoked"] is True


async def test_enroll_6_honest_reenrollment_through_a_rekey_token_still_works(world):
    c = world.client
    r, token = await _enroll_raw(c, world.admin_a, "web1")
    agent_id = r.json()["agent_id"]
    assert (await c.post(f"/v1/fleet/agents/{agent_id}/revoke", headers=hdr(world.admin_a),
                         json={"reason": "reinstall"})).status_code == 200
    rk = (await c.post("/v1/fleet/enroll-tokens", headers=hdr(world.admin_a), json={"for_agent": agent_id})).json()
    sk = Ed25519PrivateKey.generate()
    proof = sk.sign(b"paddock-enroll/v1\n" + rk["token_prefix"].encode() + b"\nweb1")
    r = await c.post("/v1/fleet/enroll", json={"token": rk["token"], "hostname": "web1",
                                               "public_key_b64": b64u(pubkey(sk)), "proof_b64": b64u(proof)})
    assert r.status_code == 201 and r.json()["rekey"] is True, r.text


# =========================================================================== #
# wire-3: the middleware is told when a rejection was folded into an aggregate
# =========================================================================== #

def test_wire_3_sampled_out_rejections_tell_the_audit_middleware():
    from types import SimpleNamespace

    from app.routers import fleet as router

    req = SimpleNamespace(state=SimpleNamespace())
    rej = fp.Rejection(400, "bad_envelope")
    router._note_sampled(req, rej)                      # a row was (or will be) written: the flag stays off
    assert not getattr(req.state, "audit_aggregated", False)
    rej.audit_row = False
    router._note_sampled(req, rej)
    assert req.state.audit_aggregated is True


async def test_wire_3_the_same_address_is_cut_off_cheaply_after_too_many_failures(world, monkeypatch):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    monkeypatch.setattr(fp.preauth_limiter, "limit", 5)
    codes = []
    for _ in range(8):
        r = await c.post(f"/v1/fleet/{host.agent_id}/heartbeat", content=b"{}", headers=host.h)
        codes.append(r.status_code)
    assert codes == [400] * 5 + [429] * 3
    # the throttled ones were not processed: no counter bump, no evidence rows beyond the sampled ones
    assert (await agent_row(world.db, host.agent_id))["rejected_total"] == 5
    assert len(await audits(world.db, "fleet.evidence.throttled", host.agent_id)) == 1


# =========================================================================== #
# wire-7 / enroll-6: migration 042 on an installation that already holds rotated keys
# =========================================================================== #

async def test_migration_042_backfills_the_rotation_chain_and_is_idempotent(empty_db, schema_before_041):
    import shutil

    import asyncpg

    from .conftest import SCHEMA_DIR
    from .test_fleet_enroll import _up

    shutil.copy(SCHEMA_DIR / "041_agent_v2.sql", schema_before_041 / "041_agent_v2.sql")
    await _up(empty_db, schema_before_041)                # up to 041, not 042
    con = await asyncpg.connect(empty_db)
    try:
        aid = uuid.uuid4()
        await con.execute(
            "INSERT INTO fleet_agents (id, hostname, platform, status, token_prefix, token_hash) "
            "VALUES ($1,'h','linux','online','p1234567','x')", aid)
        k1, k2, k3, k4 = ("1" * 32, "2" * 32, "3" * 32, "4" * 32)
        t0 = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
        t1 = t0 + dt.timedelta(days=1)
        for key, status, created, retired in ((k1, "rotated", t0 - dt.timedelta(days=1), t0),
                                              (k2, "rotated", t0, t1),
                                              (k3, "revoked", t1 + dt.timedelta(hours=1), None),   # a re-key: revoked, never rotated
                                              (k4, "active", t1 + dt.timedelta(days=1), None)):
            await con.execute(
                "INSERT INTO fleet_agent_keys (agent_id, key_id, public_key, status, created_at, retired_at) "
                "VALUES ($1,$2,'',$3,$4,$5)", aid, key, status, created, retired)
        shutil.copy(SCHEMA_DIR / "042_agent_v2_hardening.sql", schema_before_041 / "042_agent_v2_hardening.sql")
        assert (await _up(empty_db, schema_before_041)).applied == ["042_agent_v2_hardening.sql"]
        got = {r["key_id"]: r["rotated_from"] for r in await con.fetch("SELECT key_id, rotated_from FROM fleet_agent_keys")}
        assert got == {k1: None, k2: k1, k3: None, k4: None}, got      # only a retire+create in one instant links
        assert await con.fetchval("SELECT enroll_token_id FROM fleet_agents WHERE id=$1", aid) is None
        await con.execute((SCHEMA_DIR / "042_agent_v2_hardening.sql").read_text())      # idempotent
        got2 = {r["key_id"]: r["rotated_from"] for r in await con.fetch("SELECT key_id, rotated_from FROM fleet_agent_keys")}
        assert got2 == got
    finally:
        await con.close()


from .test_fleet_enroll import empty_db, schema_before_041  # noqa: E402,F401  (fixtures)


# =========================================================================== #
# ROUND 2 (verifier report): sampling must not mask verified evidence, tenant bookkeeping must stay cheap,
# the agent cap must not be a lifetime counter, v1 inventory is bounded per tenant and survives a NUL byte
# =========================================================================== #

async def _flood_four_reasons(bad: AsyncClient, host, rounds: int) -> None:
    """Bearer-only junk of four different rejection reasons (bad_envelope, bad_signature, unknown_key,
    alg_not_allowed): enough to exhaust the per-reason AND the per-agent audit sampler."""
    sk = Ed25519PrivateKey.generate()
    url = f"/v1/fleet/{host.agent_id}/heartbeat"
    for i in range(rounds):
        await bad.post(url, content=b"{}", headers=host.h)
        await bad.post(url, json=host.env("heartbeat", sk=sk, kid=host.kid, seq=100 + i), headers=host.h)
        await bad.post(url, json=host.env("heartbeat", seq=200 + i, kid="0" * 32), headers=host.h)
        env = host.env("heartbeat", seq=300 + i)
        env["alg"] = "none"
        await bad.post(url, json=env, headers=host.h)


async def test_wire_3_r2_a_bearer_only_flood_cannot_mask_a_verified_equivocation(world, rls_app):
    """The audit sampling is for UNVERIFIED rejections. A flood from another address that burns the per-agent and
    per-reason budgets of the sampler must not make the key holder's equivocation (key-clone evidence) vanish."""
    c = world.client
    host = await enroll_host(c, world.admin_a)
    assert (await post(c, host, "posture", host.env("posture", good_posture(pw="no"), seq=1))).status_code == 200
    async with _peer(rls_app, "203.0.113.9") as bad:
        await _flood_four_reasons(bad, host, 7)                       # 28 requests: inside the pre-auth limit of 30
    flood = await rejected(world.db, host)
    assert len(flood) >= 10, "the flood did not exhaust the sampler; the test proves nothing"
    b = build_envelope(host.sk, agent_id=host.agent_id, tenant_id=host.tenant_id, kind="posture", seq=1,
                       payload=pbytes(good_posture(pw="yes")))
    r = await post(c, host, "posture", b)
    assert r.status_code == 409 and r.json()["reason"] == "equivocation", r.text
    reasons = [x["details"]["reason"] for x in await rejected(world.db, host)]
    assert "equivocation" in reasons, f"the verified equivocation was sampled out of the audit: {reasons}"


async def test_wire_3_r2_every_verified_rejection_is_audited_even_when_the_sampler_is_exhausted(world, rls_app):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    async with _peer(rls_app, "203.0.113.9") as bad:
        await _flood_four_reasons(bad, host, 7)
    before = len(await rejected(world.db, host))
    assert before >= 10
    for i in range(3):                                       # verified, then clock_skew
        env = host.env("heartbeat", seq=10 + i, issued=dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=3))
        r = await post(c, host, "heartbeat", env)
        assert r.status_code == 422, (r.status_code, r.text)
    after = await rejected(world.db, host)
    assert len(after) - before == 3, f"{len(after) - before} audit rows for 3 verified rejections"


async def test_wire_2_r2_the_tenant_byte_sum_is_not_run_on_every_store(world, monkeypatch):
    c = world.client
    _set(monkeypatch, fp, "MIN_STORE_INTERVAL_S", 0)
    seen: list[str] = []
    real = asyncpg.Connection.fetchval

    async def spy(self, query, *a, **kw):
        if "SUM(size_bytes)" in query and "agent_posture" in query and "tenant_id" in query:
            seen.append(query)
        return await real(self, query, *a, **kw)

    monkeypatch.setattr(asyncpg.Connection, "fetchval", spy)
    host = await enroll_host(c, world.admin_a)
    for tries in (3, 4, 5, 6, 7, 8):
        assert (await ps(c, host, _posture(tries))).status_code == 200
    assert len(seen) <= 1, f"the O(tenant rows) SUM ran {len(seen)} times for 6 stores"


async def test_wire_2_r2_the_tenant_cap_still_bites_when_the_check_is_due(world, monkeypatch):
    c = world.client
    size = len(pbytes(_posture(3)))
    _set(monkeypatch, fp, "MIN_STORE_INTERVAL_S", 0)
    _set(monkeypatch, fp, "TENANT_EVICT_EVERY_S", 0)
    _set(monkeypatch, fp, "TENANT_POSTURE_MAX_BYTES", int(size * 2.5))
    a = await enroll_host(c, world.admin_a, "web-1")
    for tries in (3, 4, 5, 6):
        assert (await ps(c, a, _posture(tries))).status_code == 200
    rows = await posture_rows(world.db, a.agent_id)
    assert len(rows) <= 2 and rows[-1]["seq"] == 4


async def test_wire_2_r2_revoked_tombstones_do_not_exhaust_the_agent_cap_forever(world, monkeypatch):
    c = world.client
    _set(monkeypatch, fe, "MAX_AGENTS_PER_TENANT", 2)
    h1 = await enroll_host(c, world.admin_a, "web-1")
    await enroll_host(c, world.admin_a, "web-2")
    r = await c.post(f"/v1/fleet/agents/{h1.agent_id}/revoke", headers=hdr(world.admin_a), json={"reason": "gone"})
    assert r.status_code == 200
    h3 = await enroll_host(c, world.admin_a, "web-3")                       # one active slot is free again
    assert h3.agent_id
    async with world.db.acquire() as con:
        assert await con.fetchval("SELECT count(*) FROM fleet_agents") == 3     # the tombstone is still in the graph


async def test_wire_2_r2_tombstones_are_bounded_too_and_the_refusal_names_the_knob(world, monkeypatch):
    c = world.client
    _set(monkeypatch, fe, "MAX_AGENT_ROWS_PER_TENANT", 3)
    hosts = [await enroll_host(c, world.admin_a, f"web-{i}") for i in range(3)]
    for h in hosts[:2]:
        assert (await c.post(f"/v1/fleet/agents/{h.agent_id}/revoke", headers=hdr(world.admin_a),
                             json={"reason": "gone"})).status_code == 200
    tok = (await c.post("/v1/fleet/enroll-tokens", headers=hdr(world.admin_a), json={})).json()["token"]
    sk = Ed25519PrivateKey.generate()
    proof = sk.sign(b"paddock-enroll/v1\n" + tok.split("_")[1].encode() + b"\nweb-9")
    r = await c.post("/v1/fleet/enroll", json={"token": tok, "hostname": "web-9", "public_key_b64": b64u(pubkey(sk)),
                                               "proof_b64": b64u(proof)})
    assert r.status_code == 403, (r.status_code, r.text)
    assert "FLEET_MAX_AGENT_ROWS_PER_TENANT" in r.json()["detail"]


async def test_wire_2_r2_a_nul_byte_in_the_v1_inventory_is_a_clean_4xx(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    fp.inventory_limiter.limit = 1000
    url = f"/v1/fleet/{host.agent_id}/inventory"
    for body in ({"os_info": {"a": "x\u0000y"}}, {"packages": [{"name": "a\u0000"}]}, {"listeners": [{"p\u0000": 1}]},
                 {"posture": {"k": "\u0000"}}):
        r = await c.post(url, headers=host.h, content=json.dumps(body).encode())
        assert r.status_code == 422, (r.status_code, r.text)
    assert await world.db.fetchval("SELECT count(*) FROM agent_inventory WHERE agent_id=$1",
                                   uuid.UUID(host.agent_id)) == 0


async def test_wire_2_r2_v1_inventory_is_capped_per_tenant_and_keeps_each_agents_newest(world, monkeypatch):
    c = world.client
    fp.inventory_limiter.limit = 1000
    a = await enroll_host(c, world.admin_a, "web-1")
    b = await enroll_host(c, world.admin_a, "web-2")
    inv_bytes = ("SELECT COALESCE(SUM(pg_column_size(os_info) + pg_column_size(packages) + pg_column_size(listeners)"
                 " + pg_column_size(posture)), 0) FROM agent_inventory")
    _set(monkeypatch, fp, "TENANT_EVICT_EVERY_S", 0)
    assert (await c.post(f"/v1/fleet/{a.agent_id}/inventory", headers=a.h, content=_inv(1, 40))).status_code == 201
    one = await world.db.fetchval(inv_bytes)
    _set(monkeypatch, fp, "INVENTORY_TENANT_MAX_BYTES", int(one * 2.5))
    for who, i in ((b, 1), (a, 2), (b, 2), (a, 3), (b, 3)):
        r = await c.post(f"/v1/fleet/{who.agent_id}/inventory", headers=who.h, content=_inv(i, 40))
        assert r.status_code == 201, r.text
    total = await world.db.fetchval(inv_bytes)
    assert total <= one * 2.5, f"{total} bytes of v1 inventory for one tenant (cap {one * 2.5})"
    for who in (a, b):
        newest = await world.db.fetchval(
            "SELECT os_info FROM agent_inventory WHERE agent_id=$1 ORDER BY collected_at DESC LIMIT 1",
            uuid.UUID(who.agent_id))
        assert (json.loads(newest) if isinstance(newest, str) else newest)["i"] == 3     # never the newest


# the audit middleware (auth.py, not this package) writes one outcome row per rejected request unless the handler
# says the rejection was folded into an aggregate. The handler side is done; this test is the tripwire for the
# 2-line auth.py patch (docs: audit_aggregated). It is an expected failure until that patch is in, and a strict
# one, so the marker has to be removed the moment it is.
_AUTH_HONOURS_AGGREGATED = "audit_aggregated" in (Path(__file__).parent.parent / "app" / "auth.py").read_text()


@pytest.mark.xfail(condition=not _AUTH_HONOURS_AGGREGATED, strict=True,
                   reason="needs auth.py _audit to skip requests flagged request.state.audit_aggregated (lead patch)")
async def test_wire_3_r2_a_rejected_flood_grows_the_whole_audit_log_by_a_bounded_amount(world, rls_app):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    async with world.db.acquire() as con:
        before = await con.fetchval("SELECT count(*) FROM audit_log")
    async with _peer(rls_app, "203.0.113.9") as bad:
        for _ in range(60):
            await bad.post(f"/v1/fleet/{host.agent_id}/heartbeat", content=b"{}", headers=host.h)
    async with world.db.acquire() as con:
        after = await con.fetchval("SELECT count(*) FROM audit_log")
    assert after - before <= 15, f"{after - before} audit rows (all actions) for 60 rejected requests"


async def test_wire_2_r2_a_nul_byte_in_an_action_result_is_a_clean_4xx(world):
    c = world.client
    host = await enroll_host(c, world.admin_a)
    from .test_fleet_posture import seed_key
    admin2 = await seed_key(world.db, TENANT_A, "admin-a2", "admin")
    p = (await c.post("/v1/fleet/actions", headers=hdr(world.admin_a), json={
        "agent_id": host.agent_id, "action_type": "block_ip", "target": "203.0.113.10"})).json()
    assert (await c.post(f"/v1/fleet/actions/{p['id']}/approve", headers=hdr(admin2),
                         json={"apply_for_real": True})).status_code == 200
    body = {"status": "applied", "output": {"stderr": "bad\u0000byte"},
            "revert": {"mechanism": "iptables", "commands": []}}
    r = await c.post(f"/v1/fleet/actions/{p['id']}/result", headers=host.h, json=body)
    assert r.status_code == 422, (r.status_code, r.text)
    async with world.db.acquire() as con:
        assert await con.fetchval("SELECT status FROM agent_actions WHERE id=$1", uuid.UUID(p["id"])) == "approved"
