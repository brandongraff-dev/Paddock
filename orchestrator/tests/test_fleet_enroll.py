"""Fleet agent enrollment tokens, proof of possession and key binding (schema 041, app/fleet_enroll.py).

Covers: the token lifecycle (mint / list / revoke / expiry / max_uses), the atomic single-use redemption under
concurrency, the generic no-oracle failure, the per-client rate limit and lockout, the enrollment proof and key
validation (RFC 8032 vectors, small-order keys), hostname/key conflicts that must not spend a token, re-key
tokens, tenant isolation (through the NON-superuser app role), no hash leakage, the legacy marking migration
(including under FORCE ROW LEVEL SECURITY) and its idempotence.

``pool`` is the plain pool, or the RLS-enforcing app-role pool when ``ORCH_TEST_APP_ROLE=1``. The tenant
isolation tests always use the app-role pool.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shutil
import uuid
from datetime import datetime, timedelta, timezone

import asyncpg
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app import auth as auth_svc
from app import fleet_enroll as fe
from app import migrate, tenancy

from .conftest import SCHEMA_DIR, _schema_transform

TENANT_A = "00000000-0000-0000-0000-0000000000a1"
TENANT_B = "00000000-0000-0000-0000-0000000000b1"
GENERIC = (401, fe.GENERIC_ENROLL_DETAIL)


@pytest.fixture(autouse=True)
def _reset_limiters():
    fe.reset_limiters()
    yield
    fe.reset_limiters()


@pytest.fixture
def pool(db_pool, request):
    if os.environ.get("ORCH_TEST_APP_ROLE"):
        return request.getfixturevalue("app_pool")
    return db_pool


class Agent:
    """An agent's key material. The proof is built here INDEPENDENTLY of the module under test."""

    def __init__(self) -> None:
        self.sk = Ed25519PrivateKey.generate()
        self.pub = self.sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    @property
    def key_id(self) -> str:
        return hashlib.sha256(self.pub).hexdigest()[:32]

    def proof(self, token_prefix: str, hostname: str) -> bytes:
        return self.sk.sign(b"paddock-enroll/v1\n" + token_prefix.encode() + b"\n" + hostname.encode())

    def kwargs(self, token: str, hostname: str, **over) -> dict:
        import base64
        parts = token.split("_")
        prefix = parts[1] if len(parts) > 1 else "0" * 12
        kw = {
            "token": token, "hostname": hostname,
            "public_key_b64": base64.urlsafe_b64encode(self.pub).decode().rstrip("="),
            "proof_b64": base64.urlsafe_b64encode(self.proof(prefix, hostname)).decode().rstrip("="),
            "agent_version": "0.2.0", "client_ip": "198.51.100.7",
        }
        kw.update(over)
        return kw


async def _mint(pool, **kw):
    kw.setdefault("actor", "admin@test")
    return await fe.mint_token(pool, **kw)


async def _enroll(pool, token, hostname="web-1", agent=None, **over):
    agent = agent or Agent()
    return await fe.enroll_agent(pool, **agent.kwargs(token, hostname, **over))


async def _fail(pool, token, hostname="web-1", agent=None, **over) -> fe.EnrollError:
    with pytest.raises(fe.EnrollError) as ei:
        await _enroll(pool, token, hostname, agent, **over)
    return ei.value


async def _row(db_pool, sql, *args):
    async with db_pool.acquire() as con:
        return await con.fetchrow(sql, *args)


async def _uses(db_pool, token: str) -> int:
    prefix = token.split("_")[1]
    return await db_pool.fetchval("SELECT uses FROM fleet_enroll_tokens WHERE token_prefix = $1", prefix)


async def _no_agents(db_pool) -> bool:
    return await db_pool.fetchval("SELECT count(*) FROM fleet_agents") == 0


# --------------------------------------------------------------------------- #
# mint / list / policy
# --------------------------------------------------------------------------- #

async def test_token_format_is_shown_once_and_only_the_hash_is_stored(pool, db_pool):
    full, view = await _mint(pool, label="web fleet", labels=["prod", "web"])
    assert re.fullmatch(r"fet_[0-9a-f]{12}_[A-Za-z0-9_-]{43}", full)
    assert view["token_prefix"] == full.split("_")[1] and view["state"] == "pending"
    assert view["max_uses"] == 1 and view["uses"] == 0 and view["labels"] == ["prod", "web"]
    row = await _row(db_pool, "SELECT * FROM fleet_enroll_tokens WHERE id = $1", view["id"])
    assert row["token_hash"] == auth_svc.hash_api_key(full)
    secret = full.split("_", 2)[2]
    assert full not in json.dumps({k: str(v) for k, v in dict(row).items()})
    assert secret not in json.dumps({k: str(v) for k, v in dict(row).items()})
    assert timedelta(minutes=59) < row["expires_at"] - row["created_at"] <= timedelta(minutes=61)


async def test_list_and_views_never_expose_the_hash_or_the_token(pool):
    full, view = await _mint(pool)
    got = await fe.get_token(pool, view["id"])
    listed = await fe.list_tokens(pool)
    secret = full.split("_", 2)[2]
    for v in [view, got] + listed:
        assert "token_hash" not in v and "token" not in v
        text = json.dumps({k: str(x) for k, x in v.items()})
        assert auth_svc.hash_api_key(full) not in text and secret not in text
    assert listed[0]["token_prefix"] == view["token_prefix"] and listed[0]["state"] == "pending"


@pytest.mark.parametrize("kw", [
    {"max_uses": 0}, {"max_uses": 51}, {"max_uses": True}, {"max_uses": "3"},
    {"ttl_minutes": 0}, {"ttl_minutes": -5}, {"ttl_minutes": 7 * 24 * 60 + 1},
    {"max_uses": 2, "ttl_minutes": 24 * 60 + 1}, {"max_uses": 50, "ttl_minutes": 7 * 24 * 60},
    {"label": "x" * 129}, {"label": "bad\nlabel"}, {"labels": "prod"}, {"labels": ["has space"]},
    {"labels": [f"l{i}" for i in range(21)]}, {"for_agent": "not-a-uuid"},
    {"for_agent": str(uuid.uuid4()), "max_uses": 2},
])
async def test_mint_policy_rejects(pool, kw):
    with pytest.raises(fe.TokenPolicyError):
        await _mint(pool, **kw)


async def test_mint_policy_accepts_the_edges(pool):
    await _mint(pool, max_uses=1, ttl_minutes=7 * 24 * 60)
    await _mint(pool, max_uses=50, ttl_minutes=24 * 60)
    await _mint(pool, max_uses=2, ttl_minutes=1)


async def test_for_agent_must_exist_in_this_tenant(pool):
    with pytest.raises(fe.TokenPolicyError) as ei:
        await _mint(pool, for_agent=uuid.uuid4())
    assert ei.value.code == "not_found"


async def test_db_checks_back_the_policy(db_pool):
    row = ("INSERT INTO fleet_enroll_tokens (token_prefix, token_hash, expires_at, max_uses{x}) "
           "VALUES ($1, 'h', NOW() + interval '1 hour', $2{y})")
    async with db_pool.acquire() as con:
        for bad in (0, 51):
            with pytest.raises(asyncpg.CheckViolationError):
                await con.execute(row.format(x="", y=""), f"p{bad:02d}" + "0" * 9, bad)
        await con.execute(row.format(x="", y=""), "a" * 12, 1)
        with pytest.raises(asyncpg.CheckViolationError):      # uses can never exceed max_uses
            await con.execute("UPDATE fleet_enroll_tokens SET uses = 2 WHERE token_prefix = $1", "a" * 12)
        with pytest.raises(asyncpg.UniqueViolationError):     # the prefix is the global lookup handle
            await con.execute(row.format(x="", y=""), "a" * 12, 1)


# --------------------------------------------------------------------------- #
# enrollment: the happy path and what it writes
# --------------------------------------------------------------------------- #

async def test_enroll_creates_the_agent_key_and_credential(pool, db_pool):
    full, view = await _mint(pool, labels=["prod"])
    agent = Agent()
    out = await _enroll(pool, full, "Web-1", agent, capabilities=["inventory", "block"])
    assert set(out) == {"agent_id", "agent_token", "token_prefix", "key_id", "tenant_id", "hostname",
                        "rekey", "server_time"}
    assert out["key_id"] == agent.key_id and out["hostname"] == "web-1" and out["rekey"] is False
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", out["server_time"])
    assert re.fullmatch(r"fat_[0-9a-f]{12}_[A-Za-z0-9_-]{43}", out["agent_token"])
    assert fe.split_agent_token(out["agent_token"]) == out["token_prefix"]

    a = await _row(db_pool, "SELECT * FROM fleet_agents WHERE id = $1", uuid.UUID(out["agent_id"]))
    assert a["hostname"] == "web-1" and a["status"] == "enrolled" and a["legacy"] is False
    assert a["token_prefix"] == out["token_prefix"] and a["token_hash"] == auth_svc.hash_api_key(out["agent_token"])
    assert out["agent_token"] not in json.dumps({k: str(v) for k, v in dict(a).items()})
    assert a["node_ref"] == "agent:" + out["agent_id"]
    assert json.loads(a["identity"]) == {"hostname": "web-1", "basis": "claimed"}
    assert list(a["labels"]) == ["prod"] and list(a["capabilities"]) == ["block", "inventory"]
    assert a["platform"] == "linux" and a["agent_version"] == "0.2.0" and a["enrolled_by"] == "admin@test"
    assert a["online"] is True and a["silent_after_s"] == 300 and a["last_posture_seq"] == 0
    assert a["revoked_at"] is None and a["rejected_total"] == 0

    k = await db_pool.fetch("SELECT * FROM fleet_agent_keys WHERE agent_id = $1", a["id"])
    assert len(k) == 1 and k[0]["status"] == "active" and k[0]["key_id"] == agent.key_id
    assert bytes(k[0]["public_key"]) == agent.pub and k[0]["alg"] == "ed25519" and k[0]["last_seq"] == 0
    assert k[0]["tenant_id"] == a["tenant_id"]

    tok = await fe.get_token(pool, view["id"])
    assert tok["uses"] == 1 and tok["state"] == "used"

    audit_rows = await db_pool.fetch("SELECT * FROM audit_log WHERE action = 'fleet.agent.enroll'")
    assert len(audit_rows) == 1 and audit_rows[0]["resource_id"] == out["agent_id"]
    assert audit_rows[0]["tenant_id"] == a["tenant_id"]
    blob = json.dumps({k2: str(v) for k2, v in dict(audit_rows[0]).items()})
    assert full.split("_", 2)[2] not in blob and out["agent_token"] not in blob
    assert auth_svc.hash_api_key(full) not in blob and "enroll_token_prefix" in blob


async def test_issued_credential_authenticates_by_prefix_and_hash(pool, db_pool):
    full, _ = await _mint(pool)
    out = await _enroll(pool, full)
    row = await _row(db_pool, "SELECT token_prefix, token_hash FROM fleet_agents")
    prefix = fe.split_agent_token(out["agent_token"])
    assert prefix == row["token_prefix"]
    assert fe.hash_matches(row["token_hash"], out["agent_token"])
    assert not fe.hash_matches(row["token_hash"], out["agent_token"][:-1] + "x")
    assert not fe.hash_matches(None, out["agent_token"]) and not fe.hash_matches("", "")
    # v1 8-hex credentials still resolve (so they can be answered 403 re_enroll_required), garbage does not
    assert fe.split_agent_token("fat_deadbeef_" + "A" * 43) == "deadbeef"
    for bad in (None, "", "fat_zz_" + "A" * 43, "fet_" + "a" * 12 + "_" + "A" * 43, "fat_dead_" + "A" * 43,
                "fat_" + "a" * 12 + "_short"):
        assert fe.split_agent_token(bad) is None


async def test_labels_default_and_capability_validation(pool, db_pool):
    full, _ = await _mint(pool)
    err = await _fail(pool, full, capabilities=["Bad Cap"])
    assert err.status == 400 and await _uses(db_pool, full) == 0
    out = await _enroll(pool, full)
    a = await _row(db_pool, "SELECT labels, capabilities FROM fleet_agents WHERE id = $1", uuid.UUID(out["agent_id"]))
    assert list(a["labels"]) == [] and list(a["capabilities"]) == ["inventory"]


@pytest.mark.parametrize("over", [
    {"hostname": ""}, {"hostname": "has space"}, {"hostname": "a\nb"}, {"hostname": "x" * 254},
    {"hostname": "ho\u00e9st"}, {"platform": "plan9"}, {"agent_version": "1\n2"},
])
async def test_malformed_fields_are_400_and_spend_nothing(pool, db_pool, over):
    full, _ = await _mint(pool)
    over = dict(over)
    host = over.pop("hostname", "web-1")
    err = await _fail(pool, full, host, **over)
    assert err.status == 400
    assert await _uses(db_pool, full) == 0 and await _no_agents(db_pool)


# --------------------------------------------------------------------------- #
# single use, expiry, revoke, max_uses
# --------------------------------------------------------------------------- #

async def test_token_is_single_use(pool, db_pool):
    full, view = await _mint(pool)
    await _enroll(pool, full, "web-1")
    err = await _fail(pool, full, "web-2")
    assert (err.status, err.detail) == GENERIC
    assert await db_pool.fetchval("SELECT count(*) FROM fleet_agents") == 1
    assert (await fe.get_token(pool, view["id"]))["state"] == "used"


async def test_twenty_concurrent_redemptions_of_one_single_use_token_have_one_winner(pool, db_pool, monkeypatch):
    monkeypatch.setattr(fe.enroll_limiter, "limit", 1000)
    monkeypatch.setattr(fe.enroll_fail_limiter, "limit", 1000)
    full, _ = await _mint(pool)
    agents = [Agent() for _ in range(20)]
    results = await asyncio.gather(
        *[fe.enroll_agent(pool, **a.kwargs(full, f"host-{i}")) for i, a in enumerate(agents)],
        return_exceptions=True)
    ok = [r for r in results if isinstance(r, dict)]
    bad = [r for r in results if isinstance(r, fe.EnrollError)]
    assert len(ok) == 1 and len(bad) == 19 and len(results) == 20
    assert {(e.status, e.detail) for e in bad} == {GENERIC}
    assert await db_pool.fetchval("SELECT count(*) FROM fleet_agents") == 1
    assert await db_pool.fetchval("SELECT count(*) FROM fleet_agent_keys") == 1
    assert await _uses(db_pool, full) == 1


async def test_concurrent_redemptions_never_exceed_max_uses(pool, db_pool, monkeypatch):
    monkeypatch.setattr(fe.enroll_limiter, "limit", 1000)
    monkeypatch.setattr(fe.enroll_fail_limiter, "limit", 1000)
    full, _ = await _mint(pool, max_uses=5)
    agents = [Agent() for _ in range(20)]
    results = await asyncio.gather(
        *[fe.enroll_agent(pool, **a.kwargs(full, f"host-{i}")) for i, a in enumerate(agents)],
        return_exceptions=True)
    assert sum(isinstance(r, dict) for r in results) == 5
    assert all(isinstance(r, (dict, fe.EnrollError)) for r in results)
    assert await db_pool.fetchval("SELECT count(*) FROM fleet_agents") == 5
    assert await _uses(db_pool, full) == 5


async def test_expired_token_is_rejected(pool, db_pool):
    full, view = await _mint(pool)
    await db_pool.execute("UPDATE fleet_enroll_tokens SET expires_at = NOW() - interval '1 second'")
    err = await _fail(pool, full)
    assert (err.status, err.detail) == GENERIC
    assert (await fe.get_token(pool, view["id"]))["state"] == "expired"
    assert await _no_agents(db_pool) and await _uses(db_pool, full) == 0


async def test_token_expiring_between_uses_stops_a_fleet_token(pool, db_pool):
    full, _ = await _mint(pool, max_uses=3)
    await _enroll(pool, full, "a-1")
    await db_pool.execute("UPDATE fleet_enroll_tokens SET expires_at = NOW() - interval '1 second'")
    assert (await _fail(pool, full, "a-2")).status == 401
    assert await db_pool.fetchval("SELECT count(*) FROM fleet_agents") == 1


async def test_revoked_token_is_rejected_and_revoke_is_not_repeatable(pool, db_pool):
    full, view = await _mint(pool)
    assert await fe.revoke_token(pool, view["id"], "admin@test") is True
    assert await fe.revoke_token(pool, view["id"], "admin@test") is False
    assert await fe.revoke_token(pool, uuid.uuid4(), "admin@test") is False
    row = await _row(db_pool, "SELECT revoked_at, revoked_by FROM fleet_enroll_tokens WHERE id = $1", view["id"])
    assert row["revoked_at"] is not None and row["revoked_by"] == "admin@test"
    assert (await fe.get_token(pool, view["id"]))["state"] == "revoked"
    err = await _fail(pool, full)
    assert (err.status, err.detail) == GENERIC and await _no_agents(db_pool)


async def test_a_fully_used_token_cannot_be_revoked(pool):
    full, view = await _mint(pool)
    await _enroll(pool, full)
    assert await fe.revoke_token(pool, view["id"], "admin@test") is False


async def test_revoking_a_partly_used_fleet_token_stops_further_enrollment(pool, db_pool):
    full, view = await _mint(pool, max_uses=3)
    await _enroll(pool, full, "a-1")
    assert (await fe.get_token(pool, view["id"]))["state"] == "active"
    assert await fe.revoke_token(pool, view["id"], "admin@test") is True
    assert (await _fail(pool, full, "a-2")).status == 401
    assert await _uses(db_pool, full) == 1


async def test_max_uses_allows_exactly_that_many_agents(pool, db_pool):
    full, view = await _mint(pool, max_uses=3, ttl_minutes=60)
    ids = {(await _enroll(pool, full, f"fleet-{i}"))["agent_id"] for i in range(3)}
    assert len(ids) == 3
    assert (await fe.get_token(pool, view["id"]))["state"] == "used"
    assert (await _fail(pool, full, "fleet-3")).status == 401
    assert await db_pool.fetchval("SELECT count(*) FROM fleet_agents") == 3


# --------------------------------------------------------------------------- #
# no oracle, rate limit, lockout
# --------------------------------------------------------------------------- #

async def test_every_token_failure_is_the_same_generic_401(pool, db_pool):
    live, _ = await _mint(pool)
    used, _ = await _mint(pool)
    await _enroll(pool, used, "used-host")
    expired, _ = await _mint(pool)
    revoked, rview = await _mint(pool)
    await fe.revoke_token(pool, rview["id"], "admin@test")
    await db_pool.execute("UPDATE fleet_enroll_tokens SET expires_at = NOW() - interval '1 second' "
                          "WHERE token_prefix = $1", expired.split("_")[1])
    suspended, _ = await _mint(pool)
    wrong_secret = live[:-4] + ("AAAA" if not live.endswith("AAAA") else "BBBB")
    unknown_prefix = "fet_" + "0" * 12 + "_" + live.split("_", 2)[2]
    cases = {
        "used": used, "expired": expired, "revoked": revoked, "wrong_secret": wrong_secret,
        "unknown_prefix": unknown_prefix, "malformed": "garbage-token", "empty": "",
        "wrong_scheme": "pet_" + live[4:], "agent_scheme": "fat_" + live[4:],
        "short_secret": "fet_" + live.split("_")[1] + "_abc",
    }
    seen = set()
    for name, tok in cases.items():
        fe.reset_limiters()
        err = await _fail(pool, tok, f"h-{name}")
        seen.add((err.status, err.detail, err.retry_after))
        assert not tok or tok not in err.detail
    assert seen == {(401, fe.GENERIC_ENROLL_DETAIL, None)}
    # a suspended tenant looks the same too, and keeps the use
    await db_pool.execute("UPDATE tenants SET status = 'suspended' WHERE id = $1",
                          uuid.UUID(tenancy.DEFAULT_TENANT_ID))
    try:
        fe.reset_limiters()
        err = await _fail(pool, suspended, "h-suspended")
        assert (err.status, err.detail) == GENERIC
    finally:
        await db_pool.execute("UPDATE tenants SET status = 'active' WHERE id = $1",
                              uuid.UUID(tenancy.DEFAULT_TENANT_ID))
    assert await _uses(db_pool, suspended) == 0 and await _uses(db_pool, live) == 0


async def test_failures_lock_the_client_out_even_for_a_valid_token(pool, db_pool):
    full, _ = await _mint(pool)
    for _ in range(5):
        assert (await _fail(pool, "fet_" + "1" * 12 + "_" + "A" * 43, client_ip="203.0.113.9")).status == 401
    err = await _fail(pool, full, client_ip="203.0.113.9")
    assert err.status == 429 and err.retry_after == 60 and "too many" in err.detail
    assert await _no_agents(db_pool) and await _uses(db_pool, full) == 0
    # other clients are unaffected; a 429 does not itself extend the lockout
    out = await _enroll(pool, full, "web-1", client_ip="203.0.113.10")
    assert out["agent_id"]
    fe.enroll_fail_limiter.reset()
    full2, _ = await _mint(pool)
    assert (await _enroll(pool, full2, "web-2", client_ip="203.0.113.9"))["agent_id"]


async def test_bad_proof_counts_toward_the_lockout(pool):
    full, _ = await _mint(pool)
    agent = Agent()
    for _ in range(5):
        assert (await _fail(pool, full, agent=agent, proof_b64="A" * 86)).status == 400
    assert (await _fail(pool, full, agent=agent)).status == 429


async def test_conflicts_do_not_count_toward_the_lockout(pool):
    first, _ = await _mint(pool)
    await _enroll(pool, first, "taken")
    for _ in range(8):
        full, _ = await _mint(pool)
        assert (await _fail(pool, full, "taken")).status == 409
    full, _ = await _mint(pool)
    assert (await _enroll(pool, full, "free"))["agent_id"]


async def test_per_client_window_limit(pool):
    full, _ = await _mint(pool, max_uses=50)
    for i in range(20):
        await _enroll(pool, full, f"h-{i}", client_ip="192.0.2.1")
    assert (await _fail(pool, full, "h-20", client_ip="192.0.2.1")).status == 429
    assert (await _enroll(pool, full, "h-20", client_ip="192.0.2.2"))["agent_id"]


def test_limiter_keys_are_canonical():
    assert fe._limit_key("::ffff:203.0.113.9") == fe._limit_key("203.0.113.9") == "203.0.113.9"
    assert fe._limit_key("2001:db8:1:2::1") == fe._limit_key("2001:db8:1:2:ffff::7")
    assert fe._limit_key("2001:db8:1:2::1") != fe._limit_key("2001:db8:1:3::1")
    assert fe._limit_key(fe._limit_key("2001:db8:1:2::1")) == fe._limit_key("2001:db8:1:2::1")   # idempotent
    assert fe._limit_key(None) == "unknown" and fe._limit_key("") == "unknown"


# --------------------------------------------------------------------------- #
# proof of possession and key validation
# --------------------------------------------------------------------------- #

def _b64u(raw: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


async def test_proof_must_bind_this_key_token_and_hostname(pool, db_pool):
    full, _ = await _mint(pool)
    other_full, _ = await _mint(pool)
    agent, other = Agent(), Agent()
    prefix = full.split("_")[1]
    good = agent.proof(prefix, "web-1")
    bad_proofs = {
        "other_host": agent.proof(prefix, "web-2"),
        "other_token": agent.proof(other_full.split("_")[1], "web-1"),
        "other_key": other.proof(prefix, "web-1"),
        "no_domain": agent.sk.sign(prefix.encode() + b"\nweb-1"),
        "wrong_domain": agent.sk.sign(b"paddock-enroll/v2\n" + prefix.encode() + b"\nweb-1"),
        "envelope_domain": agent.sk.sign(b"paddock-agent-envelope/v1\n" + prefix.encode() + b"\nweb-1"),
        "truncated": good[:63], "extended": good + b"\x00", "zeros": b"\x00" * 64,
        "flipped_bit": bytes([good[0] ^ 1]) + good[1:],
    }
    for name, sig in bad_proofs.items():
        fe.reset_limiters()
        err = await _fail(pool, full, "web-1", agent, proof_b64=_b64u(sig))
        assert err.status == 400 and err.detail == "invalid proof of possession", name
    for junk in ("", "!!!", "A" * 3000, "not base64 at all"):
        fe.reset_limiters()
        assert (await _fail(pool, full, "web-1", agent, proof_b64=junk)).status == 400
    assert await _no_agents(db_pool) and await _uses(db_pool, full) == 0   # nothing was spent
    fe.reset_limiters()
    assert (await _enroll(pool, full, "web-1", agent, proof_b64=_b64u(good)))["key_id"] == agent.key_id


async def test_standard_base64_and_padding_are_accepted(pool):
    import base64
    full, _ = await _mint(pool)
    agent = Agent()
    kw = agent.kwargs(full, "web-1",
                      public_key_b64=base64.b64encode(agent.pub).decode(),
                      proof_b64=base64.b64encode(agent.proof(full.split("_")[1], "web-1")).decode())
    assert (await fe.enroll_agent(pool, **kw))["key_id"] == agent.key_id


# RFC 8032 section 7.1 test vectors (TEST 1, TEST 2)
_RFC = [
    ("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
]


@pytest.mark.parametrize("pub,msg,sig", _RFC)
def test_rfc8032_vectors_verify_and_tampering_does_not(pub, msg, sig):
    pub_b, msg_b, sig_b = bytes.fromhex(pub), bytes.fromhex(msg), bytes.fromhex(sig)
    assert fe.parse_public_key(pub_b) == pub_b
    assert fe.verify_ed25519(pub_b, msg_b, sig_b) is True
    assert fe.verify_ed25519(pub_b, msg_b + b"x", sig_b) is False
    assert fe.verify_ed25519(pub_b, msg_b, bytes([sig_b[0] ^ 1]) + sig_b[1:]) is False
    assert fe.verify_ed25519(pub_b, msg_b, sig_b[:-1]) is False
    assert fe.verify_ed25519(b"\x01" * 31, msg_b, sig_b) is False
    assert fe.verify_ed25519(pub_b, msg_b, b"") is False


def test_a_signature_with_a_non_canonical_s_is_rejected():
    """RFC 8032 requires S < L. S + L verifies under a lax verifier, which would make signatures malleable."""
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    sig = sk.sign(b"message")
    assert fe.verify_ed25519(pub, b"message", sig) is True
    order = 2**252 + 27742317777372353535851937790883648493
    s_int = int.from_bytes(sig[32:], "little")
    assert s_int < order
    malleated = sig[:32] + (s_int + order).to_bytes(32, "little")
    assert fe.verify_ed25519(pub, b"message", malleated) is False


def test_key_id_is_the_first_32_hex_of_the_sha256():
    pub = bytes.fromhex(_RFC[0][0])
    assert fe.key_id_for(pub) == hashlib.sha256(pub).hexdigest()[:32] and len(fe.key_id_for(pub)) == 32


def _torsion_encodings() -> set[bytes]:
    """All encodings of points of order dividing 8, computed independently of the module under test."""
    p = 2**255 - 19
    q = 2**252 + 27742317777372353535851937790883648493
    d = -121665 * pow(121666, p - 2, p) % p
    sqrt_m1 = pow(2, (p - 1) // 4, p)

    def inv(x):
        return pow(x, p - 2, p)

    def add(P, Q):
        A = (P[1] - P[0]) * (Q[1] - Q[0]) % p
        B = (P[1] + P[0]) * (Q[1] + Q[0]) % p
        C = 2 * P[3] * Q[3] * d % p
        D = 2 * P[2] * Q[2] % p
        E, F, G, H = B - A, D - C, D + C, B + A
        return (E * F % p, G * H % p, F * G % p, E * H % p)

    def mul(s, P):
        R = (0, 1, 1, 0)
        while s:
            if s & 1:
                R = add(R, P)
            P = add(P, P)
            s >>= 1
        return R

    def enc(P):
        zi = inv(P[2])
        x, y = P[0] * zi % p, P[1] * zi % p
        return (y | ((x & 1) << 255)).to_bytes(32, "little")

    found = {enc((0, 1, 1, 0))}
    for y in range(2, 80):
        xx = (y * y - 1) * inv(d * y * y + 1) % p
        x = pow(xx, (p + 3) // 8, p)
        if (x * x - xx) % p:
            x = x * sqrt_m1 % p
        if (x * x - xx) % p:
            continue
        P = (x, y, 1, x * y % p)
        T = mul(q, P)                       # the torsion component of P
        for k in range(1, 8):
            found.add(enc(mul(k, T)))
    return found


def test_every_small_order_public_key_is_rejected():
    torsion = _torsion_encodings()
    assert len(torsion) == 8                      # the full 8-torsion subgroup was found
    for raw in torsion:
        with pytest.raises(fe.KeyFormatError):
            fe.parse_public_key(raw)
        assert fe.verify_ed25519(raw, b"m", b"\x00" * 64) is False
    # the identity (y = 1) and (0, -1) in non-canonical form (y + p), and a point off the curve
    p = 2**255 - 19
    for y in (1 + p, p - 1 + p, 0 + p):
        with pytest.raises(fe.KeyFormatError):
            fe.parse_public_key((y).to_bytes(32, "little"))
    for raw in (b"\x02" + b"\x00" * 31, b"\xff" * 32, b"\x00" * 32, b"", b"\x01" * 33):
        with pytest.raises(fe.KeyFormatError):
            fe.parse_public_key(raw)


async def test_enroll_rejects_bad_public_keys_before_touching_the_token(pool, db_pool):
    full, _ = await _mint(pool)
    agent = Agent()
    for pk in (_b64u(b"\x01" + b"\x00" * 31), _b64u(b"\x00" * 32), _b64u(agent.pub[:31]), "", "!!", "A" * 400):
        fe.reset_limiters()
        err = await _fail(pool, full, "web-1", agent, public_key_b64=pk)
        assert err.status == 400 and err.detail.startswith("invalid public key")
    assert await _no_agents(db_pool) and await _uses(db_pool, full) == 0


# --------------------------------------------------------------------------- #
# conflicts must not spend the token, and must never replace a credential
# --------------------------------------------------------------------------- #

async def test_hostname_takeover_is_a_409_that_keeps_the_original_and_spends_nothing(pool, db_pool):
    first, _ = await _mint(pool)
    orig = await _enroll(pool, first, "web-1")
    before = await _row(db_pool, "SELECT token_prefix, token_hash, enrolled_at FROM fleet_agents")
    second, _ = await _mint(pool)
    for host in ("web-1", "WEB-1", "Web-1"):
        err = await _fail(pool, second, host)
        assert err.status == 409 and "re-key" in err.detail
    after = await _row(db_pool, "SELECT token_prefix, token_hash, enrolled_at FROM fleet_agents")
    assert dict(before) == dict(after) and fe.hash_matches(after["token_hash"], orig["agent_token"])
    assert await db_pool.fetchval("SELECT count(*) FROM fleet_agent_keys") == 1
    assert await _uses(db_pool, second) == 0                       # rolled back with the failed insert
    assert (await _enroll(pool, second, "web-2"))["hostname"] == "web-2"


async def test_a_public_key_cannot_be_registered_twice_in_a_tenant(pool, db_pool):
    first, _ = await _mint(pool)
    agent = Agent()
    await _enroll(pool, first, "web-1", agent)
    second, _ = await _mint(pool)
    err = await _fail(pool, second, "web-2", agent)
    assert err.status == 409 and "key already registered" in err.detail
    assert await db_pool.fetchval("SELECT count(*) FROM fleet_agents") == 1
    assert await _uses(db_pool, second) == 0


async def test_database_allows_only_one_active_key_per_agent(pool, db_pool):
    full, _ = await _mint(pool)
    out = await _enroll(pool, full)
    with pytest.raises(asyncpg.UniqueViolationError):
        await db_pool.execute(
            "INSERT INTO fleet_agent_keys (agent_id, key_id, public_key) VALUES ($1, $2, $3)",
            uuid.UUID(out["agent_id"]), "f" * 32, Agent().pub)
    await db_pool.execute("INSERT INTO fleet_agent_keys (agent_id, key_id, public_key, status) "
                          "VALUES ($1, $2, $3, 'rotated')", uuid.UUID(out["agent_id"]), "e" * 32, Agent().pub)


# --------------------------------------------------------------------------- #
# re-key tokens (for_agent): legacy agents and lost state
# --------------------------------------------------------------------------- #

async def _seed_legacy_agent(db_pool, hostname="old-1", status="enrolled") -> tuple[uuid.UUID, str]:
    cred = "fat_deadbeef_" + "S" * 43
    aid = uuid.uuid4()
    await db_pool.execute(
        "INSERT INTO fleet_agents (id, hostname, platform, status, token_prefix, token_hash, legacy) "
        "VALUES ($1,$2,'linux',$3,'deadbeef',$4,TRUE)", aid, hostname, status, auth_svc.hash_api_key(cred))
    await db_pool.execute("INSERT INTO agent_inventory (agent_id, os_info) VALUES ($1, '{\"pretty\":\"old\"}')", aid)
    return aid, cred


async def test_rekey_token_rebinds_a_legacy_agent_and_keeps_its_history(pool, db_pool):
    aid, old_cred = await _seed_legacy_agent(db_pool)
    full, view = await _mint(pool, for_agent=aid, labels=["rekeyed"])
    assert view["for_agent"] == aid
    agent = Agent()
    out = await _enroll(pool, full, "old-1", agent)
    assert out["agent_id"] == str(aid) and out["rekey"] is True
    a = await _row(db_pool, "SELECT * FROM fleet_agents WHERE id = $1", aid)
    assert a["legacy"] is False and a["status"] == "enrolled" and a["token_prefix"] == out["token_prefix"]
    assert fe.hash_matches(a["token_hash"], out["agent_token"]) and not fe.hash_matches(a["token_hash"], old_cred)
    assert list(a["labels"]) == ["rekeyed"] and a["node_ref"] == f"agent:{aid}"
    assert await db_pool.fetchval("SELECT count(*) FROM fleet_agents") == 1
    assert await db_pool.fetchval("SELECT count(*) FROM agent_inventory WHERE agent_id = $1", aid) == 1
    keys = await db_pool.fetch("SELECT key_id, status FROM fleet_agent_keys WHERE agent_id = $1", aid)
    assert [(k["key_id"], k["status"]) for k in keys] == [(agent.key_id, "active")]
    # the token is spent and cannot rebind the agent again
    assert (await _fail(pool, full, "old-1", Agent())).status == 401


async def test_rekey_revokes_the_previous_active_key_with_a_reason_and_resets_state(pool, db_pool):
    full, _ = await _mint(pool)
    first = Agent()
    out = await _enroll(pool, full, "web-1", first)
    aid = uuid.UUID(out["agent_id"])
    await db_pool.execute(
        "UPDATE fleet_agent_keys SET last_seq = 41 WHERE agent_id = $1", aid)
    await db_pool.execute(
        "UPDATE fleet_agents SET last_posture_seq = 41, last_posture_at = NOW(), online = FALSE, "
        "offline_since = NOW(), rejected_total = 3, node_ref = 'asset:' || gen_random_uuid(), "
        "identity = '{\"basis\": \"corroborated\"}'::jsonb WHERE id = $1", aid)
    rekey, _ = await _mint(pool, for_agent=aid)
    second = Agent()
    out2 = await _enroll(pool, rekey, "web-1", second)
    assert out2["agent_id"] == out["agent_id"]
    keys = {k["key_id"]: k for k in await db_pool.fetch("SELECT * FROM fleet_agent_keys WHERE agent_id = $1", aid)}
    assert keys[first.key_id]["status"] == "revoked" and keys[first.key_id]["revoked_at"] is not None
    assert keys[first.key_id]["revoke_reason"] == f"re-enrolled with token {rekey.split('_')[1]}"
    assert keys[second.key_id]["status"] == "active" and keys[second.key_id]["last_seq"] == 0
    a = await _row(db_pool, "SELECT * FROM fleet_agents WHERE id = $1", aid)
    assert a["last_posture_seq"] == 0 and a["last_posture_at"] is None and a["online"] is True
    assert a["offline_since"] is None and a["rejected_total"] == 3          # counters of history are kept
    assert a["node_ref"] == f"agent:{aid}" and json.loads(a["identity"])["basis"] == "claimed"
    assert not fe.hash_matches(a["token_hash"], out["agent_token"])


async def test_rekey_of_a_revoked_agent_is_an_explicit_admin_decision(pool, db_pool):
    aid, _ = await _seed_legacy_agent(db_pool, status="revoked")
    await db_pool.execute("UPDATE fleet_agents SET revoked_at = NOW(), revoked_by = 'admin' WHERE id = $1", aid)
    full, _ = await _mint(pool, for_agent=aid)
    await _enroll(pool, full, "old-1")
    a = await _row(db_pool, "SELECT status, revoked_at, revoked_by, legacy FROM fleet_agents WHERE id = $1", aid)
    assert a["status"] == "enrolled" and a["revoked_at"] is None and a["revoked_by"] is None and a["legacy"] is False


async def test_a_rekey_token_minted_before_the_revocation_cannot_undo_it(pool, db_pool):
    aid, _ = await _seed_legacy_agent(db_pool)
    full, _ = await _mint(pool, for_agent=aid)                       # minted while the agent was still trusted
    await db_pool.execute("UPDATE fleet_agents SET status = 'revoked', revoked_at = NOW(), revoked_by = 'admin' "
                          "WHERE id = $1", aid)
    err = await _fail(pool, full, "old-1")
    assert (err.status, err.detail) == GENERIC
    a = await _row(db_pool, "SELECT status, revoked_at, legacy FROM fleet_agents WHERE id = $1", aid)
    assert a["status"] == "revoked" and a["revoked_at"] is not None and a["legacy"] is True
    assert await db_pool.fetchval("SELECT count(*) FROM fleet_agent_keys") == 0
    assert await _uses(db_pool, full) == 0                           # the claim was rolled back with the refusal
    # a token minted AFTER the revocation is the admin's explicit decision to bring the agent back
    fresh, _ = await _mint(pool, for_agent=aid)
    assert (await _enroll(pool, fresh, "old-1"))["agent_id"] == str(aid)


async def test_an_undated_revocation_is_never_rekeyed(pool, db_pool):
    aid, _ = await _seed_legacy_agent(db_pool, status="revoked")      # revoked_at IS NULL (a v1 row)
    full, _ = await _mint(pool, for_agent=aid)
    err = await _fail(pool, full, "old-1")
    assert (err.status, err.detail) == GENERIC
    assert await db_pool.fetchval("SELECT status FROM fleet_agents WHERE id = $1", aid) == "revoked"


async def test_a_failed_rekey_rolls_everything_back(pool, db_pool):
    full, _ = await _mint(pool)
    keep = Agent()
    out = await _enroll(pool, full, "web-1", keep)
    await _enroll(pool, (await _mint(pool))[0], "web-2")
    aid = uuid.UUID(out["agent_id"])
    before = await _row(db_pool, "SELECT token_hash, hostname FROM fleet_agents WHERE id = $1", aid)
    rekey, _ = await _mint(pool, for_agent=aid)
    # rebinding to a hostname another agent owns: 409, the old key stays active, the token unspent
    err = await _fail(pool, rekey, "web-2")
    assert err.status == 409
    after = await _row(db_pool, "SELECT token_hash, hostname FROM fleet_agents WHERE id = $1", aid)
    assert dict(before) == dict(after)
    st = await db_pool.fetchval("SELECT status FROM fleet_agent_keys WHERE key_id = $1", keep.key_id)
    assert st == "active" and await _uses(db_pool, rekey) == 0
    # and registering an already-known key in a re-key: also all-or-nothing
    err = await _fail(pool, rekey, "web-1", keep)
    assert err.status == 409
    assert await db_pool.fetchval("SELECT status FROM fleet_agent_keys WHERE key_id = $1", keep.key_id) == "active"
    assert await _uses(db_pool, rekey) == 0
    assert (await _enroll(pool, rekey, "web-1"))["agent_id"] == out["agent_id"]      # the token still works


async def test_rekey_token_for_a_deleted_agent_is_the_generic_failure(pool, db_pool):
    aid, _ = await _seed_legacy_agent(db_pool)
    full, _ = await _mint(pool, for_agent=aid)
    await db_pool.execute("DELETE FROM fleet_agents WHERE id = $1", aid)
    err = await _fail(pool, full, "old-1")
    assert (err.status, err.detail) == GENERIC and await _uses(db_pool, full) == 0


# --------------------------------------------------------------------------- #
# tenant isolation (always through the NON-superuser app role)
# --------------------------------------------------------------------------- #

@pytest_asyncio.fixture
async def two_tenants(db_pool, app_pool):
    for slug, tid in (("tok-a", TENANT_A), ("tok-b", TENANT_B)):
        await tenancy.create_tenant(db_pool, slug=slug, name=slug, tenant_id=tid)
    return app_pool


async def test_enrollment_lands_in_the_tokens_tenant_and_is_invisible_to_others(two_tenants, db_pool):
    pool = two_tenants
    with tenancy.tenant_context(TENANT_A):
        full, view = await _mint(pool, label="a-fleet")
    # the redeemer has no tenant of its own (tenant-less request): the token decides
    out = await _enroll(pool, full, "web-1")
    assert out["tenant_id"] == TENANT_A
    assert str(await db_pool.fetchval("SELECT tenant_id FROM fleet_agents WHERE id = $1",
                                      uuid.UUID(out["agent_id"]))) == TENANT_A
    assert str(await db_pool.fetchval("SELECT tenant_id FROM fleet_agent_keys")) == TENANT_A
    assert str(await db_pool.fetchval("SELECT tenant_id FROM audit_log WHERE action = 'fleet.agent.enroll'")) == TENANT_A
    with tenancy.tenant_context(TENANT_B):
        assert await fe.list_tokens(pool) == []
        assert await fe.get_token(pool, view["id"]) is None
        assert await fe.revoke_token(pool, view["id"], "b-admin") is False
        async with pool.acquire() as con:
            assert await con.fetchval("SELECT count(*) FROM fleet_agents") == 0
            assert await con.fetchval("SELECT count(*) FROM fleet_agent_keys") == 0
            assert await con.fetchval("SELECT count(*) FROM fleet_enroll_tokens") == 0
    with tenancy.tenant_context(TENANT_A):
        assert [t["id"] for t in await fe.list_tokens(pool)] == [view["id"]]
        async with pool.acquire() as con:
            assert await con.fetchval("SELECT count(*) FROM fleet_agents") == 1
    # B's admin did not revoke A's token: it is spent (not revoked)
    assert (await db_pool.fetchval("SELECT revoked_at FROM fleet_enroll_tokens")) is None


async def test_two_tenants_can_enroll_the_same_hostname_and_the_same_key(two_tenants, db_pool):
    pool = two_tenants
    agent = Agent()
    outs = {}
    for tid in (TENANT_A, TENANT_B):
        with tenancy.tenant_context(tid):
            full, _ = await _mint(pool)
        outs[tid] = await _enroll(pool, full, "shared-host", agent)
    assert outs[TENANT_A]["tenant_id"] == TENANT_A and outs[TENANT_B]["tenant_id"] == TENANT_B
    assert outs[TENANT_A]["agent_id"] != outs[TENANT_B]["agent_id"]
    assert await db_pool.fetchval("SELECT count(*) FROM fleet_agent_keys WHERE key_id = $1", agent.key_id) == 2


async def test_a_rekey_token_cannot_name_another_tenants_agent(two_tenants, db_pool):
    pool = two_tenants
    with tenancy.tenant_context(TENANT_A):
        full, _ = await _mint(pool)
    out = await _enroll(pool, full, "web-1")
    with tenancy.tenant_context(TENANT_B):
        with pytest.raises(fe.TokenPolicyError) as ei:
            await _mint(pool, for_agent=out["agent_id"])
        assert ei.value.code == "not_found"
    with tenancy.tenant_context(TENANT_A):
        await _mint(pool, for_agent=out["agent_id"])


async def test_agent_credential_lookup_policy_is_select_only_and_needs_auth_lookup(two_tenants, db_pool):
    pool = two_tenants
    with tenancy.tenant_context(TENANT_A):
        full, _ = await _mint(pool)
    out = await _enroll(pool, full, "web-1")
    prefix = out["token_prefix"]
    # without auth_lookup a tenant-less (here: tenant B) session cannot see the row
    with tenancy.tenant_context(TENANT_B):
        async with pool.acquire() as con:
            assert await con.fetchval("SELECT count(*) FROM fleet_agents WHERE token_prefix = $1", prefix) == 0
    # inside auth_lookup the credential row is readable across tenants ...
    with tenancy.auth_lookup():
        async with pool.acquire() as con:
            row = await con.fetchrow("SELECT tenant_id, token_hash FROM fleet_agents WHERE token_prefix = $1", prefix)
            assert str(row["tenant_id"]) == TENANT_A and fe.hash_matches(row["token_hash"], out["agent_token"])
            # ... but never writable, and the key/posture tables are not opened up at all
            assert await con.execute("UPDATE fleet_agents SET hostname = 'x' WHERE token_prefix = $1", prefix) == "UPDATE 0"
            assert await con.execute("DELETE FROM fleet_agents") == "DELETE 0"
            assert await con.fetchval("SELECT count(*) FROM fleet_agent_keys") == 0
            assert await con.fetchval("SELECT count(*) FROM agent_posture") == 0


async def test_tenant_b_cannot_read_a_posture_or_node_facts(two_tenants, db_pool):
    pool = two_tenants
    with tenancy.tenant_context(TENANT_A):
        full, _ = await _mint(pool)
    out = await _enroll(pool, full, "web-1")
    await db_pool.execute(
        "INSERT INTO agent_posture (tenant_id, agent_id, key_id, seq) VALUES ($1, $2, 'k', 1)",
        uuid.UUID(TENANT_A), uuid.UUID(out["agent_id"]))
    await db_pool.execute(
        "INSERT INTO reach_node_facts (tenant_id, node_ref, source) VALUES ($1, 'agent:x', 'host_fw')",
        uuid.UUID(TENANT_A))
    with tenancy.tenant_context(TENANT_B):
        async with pool.acquire() as con:
            assert await con.fetchval("SELECT count(*) FROM agent_posture") == 0
            assert await con.fetchval("SELECT count(*) FROM reach_node_facts") == 0
            with pytest.raises(asyncpg.InsufficientPrivilegeError):
                await con.execute("INSERT INTO agent_posture (tenant_id, agent_id, key_id, seq) "
                                  "VALUES ($1, $2, 'k', 2)", uuid.UUID(TENANT_A), uuid.UUID(out["agent_id"]))
    with tenancy.tenant_context(TENANT_A):
        async with pool.acquire() as con:
            assert await con.fetchval("SELECT signed FROM agent_posture") is False   # nothing is signed by default


# --------------------------------------------------------------------------- #
# schema defaults that matter for soundness
# --------------------------------------------------------------------------- #

async def test_posture_rows_are_not_signed_unless_the_ingest_says_so(db_pool):
    aid = uuid.uuid4()
    await db_pool.execute("INSERT INTO fleet_agents (id, hostname) VALUES ($1, 'h')", aid)
    await db_pool.execute("INSERT INTO agent_posture (agent_id, key_id, seq) VALUES ($1, 'k', 1)", aid)
    assert await db_pool.fetchval("SELECT signed FROM agent_posture") is False
    with pytest.raises(asyncpg.UniqueViolationError):                       # replay-safe at the DB level
        await db_pool.execute("INSERT INTO agent_posture (agent_id, key_id, seq) VALUES ($1, 'k', 1)", aid)
    await db_pool.execute("INSERT INTO agent_posture (agent_id, key_id, seq) VALUES ($1, 'k', 2)", aid)


async def test_key_and_fact_checks(db_pool):
    aid = uuid.uuid4()
    await db_pool.execute("INSERT INTO fleet_agents (id, hostname) VALUES ($1, 'h')", aid)
    for sql in (
        "INSERT INTO fleet_agent_keys (agent_id, key_id, public_key) VALUES ($1, 'k1', '\\x0102'::bytea)",
        "INSERT INTO fleet_agent_keys (agent_id, key_id, alg) VALUES ($1, 'k2', 'rsa')",
        "INSERT INTO fleet_agent_keys (agent_id, key_id, status) VALUES ($1, 'k3', 'bogus')",
        "INSERT INTO fleet_agent_keys (agent_id, key_id, last_seq) VALUES ($1, 'k4', -1)",
    ):
        with pytest.raises(asyncpg.CheckViolationError):
            await db_pool.execute(sql, aid)
    with pytest.raises(asyncpg.CheckViolationError):
        await db_pool.execute("INSERT INTO reach_node_facts (node_ref, source, tier) VALUES ('n', 's', 'observed!')")
    with pytest.raises(asyncpg.CheckViolationError):
        await db_pool.execute("UPDATE fleet_agents SET silent_after_s = 29 WHERE id = $1", aid)
    with pytest.raises(asyncpg.CheckViolationError):
        await db_pool.execute("UPDATE fleet_agents SET silent_after_s = 86401 WHERE id = $1", aid)
    row = await _row(db_pool, "SELECT silent_after_s, online, legacy, identity, node_ref, rejected_total, "
                              "last_posture_seq FROM fleet_agents WHERE id = $1", aid)
    assert (row["silent_after_s"], row["online"], row["legacy"], row["rejected_total"], row["last_posture_seq"]) \
        == (300, True, False, 0, 0)


# --------------------------------------------------------------------------- #
# migration: legacy marking (O3) and idempotence
# --------------------------------------------------------------------------- #

@pytest_asyncio.fixture
async def empty_db(postgresql_my_proc):
    p = postgresql_my_proc
    auth = f"{p.user}:{p.password}" if p.password else p.user
    base = f"postgresql://{auth}@{p.host}:{p.port}"
    name = f"mig41_{uuid.uuid4().hex[:12]}"
    admin = await asyncpg.connect(f"{base}/postgres")
    await admin.execute(f'CREATE DATABASE "{name}"')
    await admin.close()
    try:
        yield f"{base}/{name}"
    finally:
        admin = await asyncpg.connect(f"{base}/postgres")
        await admin.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                            "WHERE datname = $1 AND pid <> pg_backend_pid()", name)
        await admin.execute(f'DROP DATABASE "{name}"')
        await admin.close()


@pytest.fixture
def schema_before_041(tmp_path):
    d = tmp_path / "schema"
    shutil.copytree(SCHEMA_DIR, d)
    (d / "041_agent_v2.sql").unlink()
    return d


async def _up(dsn, schema_dir):
    con = await asyncpg.connect(dsn)
    try:
        return await migrate.migrate_up(con, schema_dir=schema_dir, transform=_schema_transform)
    finally:
        await con.close()


def _final_do_block() -> str:
    sql = (SCHEMA_DIR / "041_agent_v2.sql").read_text()
    return sql[sql.index("DO $$\nDECLARE t record;"):]


async def test_preexisting_agents_are_marked_legacy_and_nothing_else_changes(empty_db, schema_before_041, tmp_path):
    await _up(empty_db, schema_before_041)           # an installation that already ran 001-040 and 099
    con = await asyncpg.connect(empty_db)
    ids = {}
    try:
        await con.execute("INSERT INTO tenants (id, slug, name) VALUES ($1, 'mig-a', 'mig-a')", uuid.UUID(TENANT_A))
        seeds = [("00000000-0000-0000-0000-000000000001", "v1-a", "enrolled"),
                 ("00000000-0000-0000-0000-000000000001", "v1-revoked", "revoked"),
                 (TENANT_A, "v1-tenant-a", "online")]
        for tid, host, status in seeds:
            ids[host] = uuid.uuid4()
            await con.execute(
                "INSERT INTO fleet_agents (id, tenant_id, hostname, platform, status, token_prefix, token_hash, last_seen) "
                "VALUES ($1,$2,$3,'linux',$4,$5,$6,NOW())",
                ids[host], uuid.UUID(tid), host, status, host[:8].ljust(8, "0"), auth_svc.hash_api_key(host))
            await con.execute("INSERT INTO agent_inventory (tenant_id, agent_id, os_info) VALUES ($1,$2,'{}')",
                              uuid.UUID(tid), ids[host])
        before = {r["hostname"]: dict(r) for r in await con.fetch(
            "SELECT hostname, status, token_prefix, token_hash, enrolled_at, last_seen FROM fleet_agents")}
    finally:
        await con.close()

    shutil.copy(SCHEMA_DIR / "041_agent_v2.sql", schema_before_041 / "041_agent_v2.sql")
    res = await _up(empty_db, schema_before_041)
    assert res.applied == ["041_agent_v2.sql"] and res.reasserted == [migrate.TENANCY_FILE]

    con = await asyncpg.connect(empty_db)
    try:
        rows = {r["hostname"]: r for r in await con.fetch("SELECT * FROM fleet_agents")}
        assert set(rows) == set(before)
        for host, r in rows.items():
            assert r["legacy"] is True, host                      # every pre-existing agent, every tenant
            assert r["silent_after_s"] == 300 and r["online"] is True and r["node_ref"] is None
            for col in ("status", "token_prefix", "token_hash", "enrolled_at", "last_seen"):
                assert r[col] == before[host][col], (host, col)    # rows and credentials untouched
            # only the v1 revoked agent gets (dated) a revoked_at: a re-key token must postdate a revocation
            assert (r["revoked_at"] is not None) == (host == "v1-revoked"), host
            if host == "v1-revoked":
                assert r["revoked_at"] == before[host]["last_seen"]
        assert await con.fetchval("SELECT count(*) FROM agent_inventory") == 3     # history kept
        assert await con.fetchval("SELECT count(*) FROM fleet_agent_keys") == 0
        for t in ("fleet_enroll_tokens", "fleet_agent_keys", "agent_posture", "reach_node_facts"):
            rls = await con.fetchrow("SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = $1", t)
            assert rls["relrowsecurity"] and rls["relforcerowsecurity"], t
            assert await con.fetchval(
                "SELECT count(*) FROM pg_policies WHERE tablename = $1 AND policyname = 'tenant_isolation'", t) == 1
        # a v2 agent enrolled afterwards is not legacy, and re-running the whole file marks nothing new
        pool = await asyncpg.create_pool(empty_db, min_size=1, max_size=2)
        try:
            full, _ = await fe.mint_token(pool, actor="admin")
            out = await _enroll(pool, full, "v2-host")
            legacy_id = ids["v1-a"]
            rekey, _ = await fe.mint_token(pool, actor="admin", for_agent=legacy_id)
            await _enroll(pool, rekey, "v1-a")
        finally:
            await pool.close()
        snap = await con.fetch("SELECT id, hostname, legacy FROM fleet_agents ORDER BY hostname")
        sql = (SCHEMA_DIR / "041_agent_v2.sql").read_text()
        await con.execute(sql)
        await con.execute(sql)
        again = await con.fetch("SELECT id, hostname, legacy FROM fleet_agents ORDER BY hostname")
        assert [dict(r) for r in snap] == [dict(r) for r in again]
        by = {r["hostname"]: r["legacy"] for r in again}
        assert by == {"v1-a": False, "v1-revoked": True, "v1-tenant-a": True, "v2-host": False}
        assert str(await con.fetchval("SELECT id FROM fleet_agents WHERE hostname = 'v2-host'")) == out["agent_id"]
    finally:
        await con.close()
    # and the runner agrees nothing is pending
    assert (await _up(empty_db, schema_before_041)).applied == []


async def test_legacy_marking_works_for_a_table_owner_that_row_level_security_applies_to(empty_db, schema_before_041):
    """FORCE ROW LEVEL SECURITY applies to a plain (non-superuser) owner: a naive UPDATE silently matches no
    row outside the session tenant. The per-tenant loop must reach every tenant. Proved as ``paddock_app``
    (NOSUPERUSER NOBYPASSRLS)."""
    await _up(empty_db, schema_before_041)
    shutil.copy(SCHEMA_DIR / "041_agent_v2.sql", schema_before_041 / "041_agent_v2.sql")
    await _up(empty_db, schema_before_041)
    con = await asyncpg.connect(empty_db)
    try:
        await con.execute("INSERT INTO tenants (id, slug, name) VALUES ($1, 'mig-b', 'mig-b')", uuid.UUID(TENANT_B))
        for tid, host in (("00000000-0000-0000-0000-000000000001", "d-1"), (TENANT_A, "a-1"), (TENANT_B, "b-1")):
            if tid == TENANT_A:
                await con.execute("INSERT INTO tenants (id, slug, name) VALUES ($1, 'mig-a', 'mig-a')", uuid.UUID(tid))
            await con.execute("INSERT INTO fleet_agents (tenant_id, hostname) VALUES ($1, $2)", uuid.UUID(tid), host)
        assert await con.fetchval("SELECT count(*) FROM fleet_agents WHERE legacy") == 0

        await con.execute("SET ROLE paddock_app")
        try:
            await con.execute("SELECT set_config('app.tenant_id', $1, false)", "00000000-0000-0000-0000-000000000001")
            naive = await con.execute(
                "UPDATE fleet_agents SET legacy = TRUE WHERE NOT EXISTS "
                "(SELECT 1 FROM fleet_agent_keys k WHERE k.agent_id = fleet_agents.id)")
            assert naive == "UPDATE 1"                                  # only the session tenant's agent
            await con.execute("UPDATE fleet_agents SET legacy = FALSE")
            await con.execute(_final_do_block())
        finally:
            await con.execute("RESET ROLE")
        assert await con.fetchval("SELECT count(*) FROM fleet_agents WHERE legacy") == 3
        assert await con.fetchval("SELECT current_setting('app.tenant_id', true)") == "00000000-0000-0000-0000-000000000001"
    finally:
        await con.close()


# --------------------------------------------------------------------------- #
# hygiene
# --------------------------------------------------------------------------- #

def test_module_never_selects_the_hash_into_a_view_and_stores_no_plaintext():
    import inspect
    src = inspect.getsource(fe)
    assert "token_hash" not in fe._TOKEN_COLS
    # the full token is only ever returned from mint_token / enroll_agent, never persisted or logged
    assert "logger" not in re.sub(r"logger\.exception\(\"ed25519_verify_unexpected\"\)|logger = [^\n]+|^import[^\n]*", "", src)


def test_token_state_precedence():
    now = datetime.now(timezone.utc)
    base = {"revoked_at": None, "uses": 0, "max_uses": 2, "expires_at": now + timedelta(hours=1)}
    assert fe.token_state(base, now) == "pending"
    assert fe.token_state({**base, "uses": 1}, now) == "active"
    assert fe.token_state({**base, "uses": 2}, now) == "used"
    assert fe.token_state({**base, "expires_at": now - timedelta(seconds=1)}, now) == "expired"
    assert fe.token_state({**base, "expires_at": now - timedelta(seconds=1), "uses": 2}, now) == "used"
    assert fe.token_state({**base, "revoked_at": now, "uses": 2}, now) == "revoked"
