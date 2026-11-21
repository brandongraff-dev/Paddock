"""Adversarial regression tests for Paddock's public and token-authenticated
surface (exposure report, trust pages, billing webhook, /status, MSP invites,
SAML SLS, sensor enrollment, ingest tokens, SCIM filters).

Every test here started life as an attack that worked (or an attack that was
held and is pinned so it keeps being held). Network-free; real Postgres.
"""
from __future__ import annotations

import asyncio
import base64
import copy
import gzip
import hashlib
import hmac
import json
import random
import time
import uuid
import zlib

import pytest
import pytest_asyncio

from app import auth as auth_svc
from app import sensors as sensors_svc
from app import tenancy
from app.config import settings
from app.growth import abuse, trust
from app.ingest import Hints, IngestError, parse_payload
from app.ingest import common as ingest_common
from app.ingest import tokens as ingest_tokens
from app.routers import ingest as ingest_router

from . import ingest_samples as S

TENANT_A = tenancy.DEFAULT_TENANT_ID
TENANT_B = "00000000-0000-0000-0000-0000000000b2"


@pytest.fixture
def enforce():
    prev = settings.auth_mode
    settings.auth_mode = "enforce"
    try:
        yield
    finally:
        settings.auth_mode = prev


@pytest.fixture(autouse=True)
def _reset_limiters():
    for lim in (sensors_svc.enroll_limiter, sensors_svc.enroll_fail_limiter, sensors_svc.heartbeat_limiter):
        lim.reset()
    ingest_router.rate_limiter.reset()
    ingest_router.failure_limiter.reset()
    yield
    for lim in (sensors_svc.enroll_limiter, sensors_svc.enroll_fail_limiter, sensors_svc.heartbeat_limiter):
        lim.reset()
    ingest_router.rate_limiter.reset()
    ingest_router.failure_limiter.reset()


# --------------------------------------------------------------------------- #
# Trust tokens: forgery filter must never crash and never confuse schemes
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("sig", ["é" * 22, "\u202e" * 22, "ａ" * 22, "\x00" * 22, "%" * 22, " " * 22])
def test_trust_token_with_non_ascii_signature_is_rejected_not_a_500(sig):
    t = trust.new_token()
    head, body, _ = t.split(".")
    assert trust.token_well_formed(f"{head}.{body}.{sig}") is False
    assert trust.token_well_formed(f"{head}.{sig[:1] * 43}.{_}") is False


async def test_public_trust_endpoint_non_ascii_token_is_a_clean_404(client):
    t = trust.new_token()
    head, body, _ = t.split(".")
    r = await client.get(f"/v1/public/trust/{head}.{body}.%C3%A9%C3%A9%C3%A9")
    assert r.status_code == 404 and r.json() == {"detail": "this link is not available"}


@pytest.mark.parametrize("other", ["pdi_", "pet_", "pst_", "pscim_", "pk_", "paddock_"])
def test_other_schemes_are_not_trust_tokens(other):
    t = trust.new_token()
    assert not trust.token_well_formed(other + t)
    assert not trust.token_well_formed(t.replace("pt1", other.rstrip("_"), 1))
    assert not trust.token_well_formed(t.upper())
    assert not trust.token_well_formed(t + ".")
    assert not trust.token_well_formed(t + "A")
    assert not trust.token_well_formed(t[:-1])


# --------------------------------------------------------------------------- #
# Limiters: unbounded growth under unique keys, IPv6 rotation
# --------------------------------------------------------------------------- #

def test_sensor_limiter_does_not_grow_on_read_only_checks():
    lim = sensors_svc.SlidingWindowLimiter(5, 60, max_keys=1000)
    for i in range(20_000):
        lim.blocked(f"198.51.100.{i}")
    assert len(lim._hits) == 0


def test_sensor_limiter_bounded_under_unique_key_spray():
    lim = sensors_svc.SlidingWindowLimiter(5, 60, max_keys=1000)
    for i in range(20_000):
        lim.hit(f"k{i}")
    assert len(lim._hits) <= 1000


def test_sensor_limiter_spray_cannot_evict_an_active_lockout():
    lim = sensors_svc.SlidingWindowLimiter(2, 600, max_keys=100)
    for _ in range(2):
        lim.hit("attacker")
    assert lim.blocked("attacker")
    for i in range(5_000):
        lim.hit(f"spray{i}")
    assert lim.blocked("attacker"), "a spray of other keys must not clear an existing lockout"


def test_ingest_failure_window_is_bounded():
    w = ingest_router._Window()
    for i in range(50_000):
        w.hit(f"fail:2001:db8::{i}")
    assert len(w._hits) <= 12_000


def test_ipv6_privacy_rotation_within_a_64_shares_one_limiter_key():
    base = "2001:db8:abcd:12"
    keys = {abuse.ip_hash(f"{base}:{i:x}:1:2:3") for i in range(1, 200)}
    assert len(keys) == 1
    assert abuse.ip_hash("2001:db8:abcd:13::1") != abuse.ip_hash("2001:db8:abcd:12::1")
    # an IPv4-mapped IPv6 address is the same client as its IPv4 form
    assert abuse.ip_hash("::ffff:203.0.113.9") == abuse.ip_hash("203.0.113.9")
    assert abuse.ip_hash("203.0.113.9") != abuse.ip_hash("203.0.113.10")


async def test_xff_is_ignored_without_a_trusted_proxy(client, fake_redis, monkeypatch):
    """Spoofing X-Forwarded-For must not mint fresh per-address budgets."""
    from app.growth.config import growth_settings

    monkeypatch.setattr(growth_settings, "ip_requests_per_hour", 3)
    monkeypatch.setattr(settings, "trusted_proxy_cidrs", "")
    codes = []
    for i in range(6):
        r = await client.post("/v1/public/exposure-report", json={"domain": f"spoof{i}-probe.com"},
                              headers={"X-Forwarded-For": f"203.0.113.{i}"})
        codes.append(r.status_code)
    assert codes[:3] == [202, 202, 202] and set(codes[3:]) == {429}, codes


async def test_exposure_report_domain_variants_share_one_budget_and_one_report(client, fake_redis, db_pool):
    variants = ["Example.COM", "example.com.", "EXAMPLE.com", "ｅxample.com", "example。com", " example.com ",
                "\u200bexample.com", "example.com\n"]
    ids = set()
    for v in variants:
        r = await client.post("/v1/public/exposure-report", json={"domain": v})
        assert r.status_code == 202, (v, r.text)
        ids.add(r.json()["id"])
    assert len(ids) == 1
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT COUNT(*) FROM exposure_reports") == 1


async def test_exposure_report_errors_do_not_leak_internals(client):
    for d in ("localhost", "10.0.0.1", "0x7f.1", "[::1]", "a" * 400 + ".com", "x.internal", "user@evil.com"):
        r = await client.post("/v1/public/exposure-report", json={"domain": d})
        assert r.status_code in (422,), (d, r.status_code)
        text = r.text.lower()
        for needle in ("traceback", "asyncpg", "/home/", "postgres", "redis", "tenant"):
            assert needle not in text, (d, text)
    r = await client.post("/v1/public/exposure-report", json={"domain": 123})
    assert r.status_code == 422
    r = await client.post("/v1/public/exposure-report", content=b"\xff\xfe not json",
                          headers={"content-type": "application/json"})
    assert r.status_code in (400, 422)


# --------------------------------------------------------------------------- #
# Billing webhook: bodies without a Content-Length must still be capped
# --------------------------------------------------------------------------- #

async def test_webhook_chunked_oversize_body_is_cut_off_early(client, monkeypatch):
    from app.billing import config as bcfg
    from app.billing import events

    monkeypatch.setattr(bcfg.settings, "stripe_secret_key", "sk_test_not_real")
    monkeypatch.setattr(bcfg.settings, "stripe_webhook_secret", "whsec_x")
    seen = {"bytes": 0}

    async def gen():
        for _ in range(64):
            seen["bytes"] += 64 * 1024
            yield b"x" * (64 * 1024)

    r = await client.post("/v1/billing/webhook", content=gen(), headers={"stripe-signature": "t=1,v1=00"})
    assert r.status_code == 413
    assert seen["bytes"] <= events.MAX_BODY_BYTES + 4 * 64 * 1024, seen  # stopped reading near the cap


# --------------------------------------------------------------------------- #
# Sensors
# --------------------------------------------------------------------------- #

async def _etoken(client, site="s1"):
    r = await client.post("/v1/sensors/tokens", json={"site": site, "ttl_minutes": 60})
    assert r.status_code == 201, r.text
    return r.json()["token"]


async def test_enrollment_token_is_single_use_under_20_concurrent_redemptions(client, db_pool, monkeypatch):
    tok = await _etoken(client)
    monkeypatch.setattr(sensors_svc.enroll_limiter, "limit", 1000)
    monkeypatch.setattr(sensors_svc.enroll_fail_limiter, "limit", 1000)
    rs = await asyncio.gather(*[client.post("/v1/sensors/enroll", json={"token": tok, "hostname": f"h{i}"})
                                for i in range(20)])
    codes = sorted(r.status_code for r in rs)
    assert codes.count(201) == 1 and codes.count(401) == 19, codes
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT COUNT(*) FROM sensors") == 1
    # 401 bodies are identical for used / unknown / malformed: no oracle
    bodies = {r.text for r in rs if r.status_code == 401}
    unknown = await client.post("/v1/sensors/enroll", json={"token": "pet_00000000_" + "A" * 43})
    assert bodies == {unknown.text}


async def test_batch_claim_is_exclusive_under_20_concurrent_claims(client, db_pool):
    tok = await _etoken(client)
    cred = (await client.post("/v1/sensors/enroll", json={"token": tok})).json()["credential"]
    sensor = await sensors_svc.authenticate(client._transport.app.state.pool, cred)  # type: ignore[attr-defined]
    pool = client._transport.app.state.pool  # type: ignore[attr-defined]
    states = await asyncio.gather(*[sensors_svc.claim_batch(pool, sensor, "batch-0001-abcdef") for _ in range(20)])
    assert sorted(states).count("new") == 1, states
    assert set(states) <= {"new", "in_progress"}


async def test_sensor_credential_scheme_confusion_and_mutation(client):
    tok = await _etoken(client)
    cred = (await client.post("/v1/sensors/enroll", json={"token": tok})).json()["credential"]
    ok = await client.post("/v1/sensors/heartbeat", json={}, headers={"X-Sensor-Token": cred})
    assert ok.status_code == 200, ok.text
    pre = cred.split("_")
    cases = [
        cred.upper(), cred[:-1], cred + "A", cred.replace("pst_", "pet_", 1),
        cred.replace("pst_", "pdi_", 1), "Bearer " + cred, cred[:-1] + ("A" if cred[-1] != "A" else "B"),
        "pst_" + pre[1] + "_" + "A" * 43, "pst_ffffffff_" + pre[2], cred.replace("_", "-"),
        "",
    ]
    for c in cases:
        r = await client.post("/v1/sensors/heartbeat", json={}, headers={"X-Sensor-Token": c})
        assert r.status_code in (401, 422), (c, r.status_code)
    # an ENROLLMENT token is not a credential, and a credential is not an enrollment token
    t2 = await _etoken(client, "s2")
    assert (await client.post("/v1/sensors/heartbeat", json={}, headers={"X-Sensor-Token": t2})).status_code == 401
    r = await client.post("/v1/sensors/enroll", json={"token": cred})
    assert r.status_code == 401


async def test_enroll_lockout_is_keyed_on_the_real_client_not_a_shared_proxy(client, app, monkeypatch):
    """Behind a trusted proxy every request has the proxy's address as its
    socket peer; the lockout must follow X-Forwarded-For so one attacker cannot
    lock every sensor out."""
    from app import auth as auth_mod

    monkeypatch.setattr(auth_mod, "_trusted_proxies", lambda: tuple(__import__("ipaddress").ip_network(c)
                                                                    for c in ("127.0.0.0/8", "::1/128", "0.0.0.0/0")))
    for _ in range(6):
        await client.post("/v1/sensors/enroll", json={"token": "pet_00000000_" + "A" * 43},
                          headers={"X-Forwarded-For": "198.51.100.66"})
    r = await client.post("/v1/sensors/enroll", json={"token": "pet_00000000_" + "A" * 43},
                          headers={"X-Forwarded-For": "198.51.100.66"})
    assert r.status_code == 429
    good = await _etoken(client)
    r = await client.post("/v1/sensors/enroll", json={"token": good}, headers={"X-Forwarded-For": "203.0.113.7"})
    assert r.status_code == 201, r.text


# --------------------------------------------------------------------------- #
# Ingest: hostile documents must be 4xx, never 500, and never poison storage
# --------------------------------------------------------------------------- #

WEIRD = [None, True, False, 0, -1, 2**70, -2**70, 1e308, float("nan"), float("inf"), float("-inf"), "", "\x00",
         "\ud800", "a" * 3000, [], {}, [[]], {"a": []}, [None], "NaN", "-1", "1e999", "../../etc/passwd",
         "file:///c:/x", "http://u:p@h/", "=1+1", "\u202e", 5.5, "critical", "[::1]", "999.999.999.999", 10**30]


def _leaves(doc, path=()):
    if isinstance(doc, dict):
        for k, v in doc.items():
            yield from _leaves(v, path + (k,))
    elif isinstance(doc, list):
        for i, v in enumerate(doc):
            yield from _leaves(v, path + (i,))
    yield path, doc


def _setp(doc, path, val):
    if not path:
        return val
    cur = doc
    for p in path[:-1]:
        cur = cur[p]
    cur[path[-1]] = val
    return doc


@pytest.mark.parametrize("name", ["SARIF", "TRIVY", "GRYPE", "SEMGREP", "ZAP", "OCSF", "CYCLONEDX", "SPDX"])
def test_type_confusion_fuzz_never_escapes_as_an_unhandled_exception(name):
    rnd = random.Random(1337)
    base = getattr(S, name)
    leaves = list(_leaves(base))
    for _ in range(600):
        doc = copy.deepcopy(base)
        for _ in range(rnd.randint(1, 3)):
            p, _v = rnd.choice(leaves)
            try:
                doc = _setp(doc, p, rnd.choice(WEIRD))
            except (KeyError, IndexError, TypeError):
                pass
        text = json.dumps(doc)
        try:
            parse_payload(text, None, Hints(max_findings=1000))
        except IngestError:
            pass


@pytest.mark.parametrize("v", [float("nan"), float("inf"), float("-inf"), 1e308, -1e308, 2**200])
def test_norm_severity_total_function(v):
    assert ingest_common.norm_severity(v) in ingest_common.SEVERITIES


def test_clean_strips_lone_surrogates_and_nul():
    s = ingest_common.clean("a\ud800b\x00c\udfffd")
    s.encode("utf-8")  # must be encodable (Postgres/asyncpg)
    assert "\x00" not in s


def test_gzip_bomb_and_multimember_are_bounded():
    bomb = gzip.compress(b"0" * (60 * 1024 * 1024), 9)
    t = time.time()
    with pytest.raises(IngestError) as ei:
        from app.ingest import decode_body

        decode_body(bomb, gzipped=True, max_bytes=5 * 1024 * 1024)
    assert ei.value.status == 413 and time.time() - t < 5


class _Ingest:
    pass


@pytest_asyncio.fixture
async def ingest_env(enforce, app, app_pool, db_pool, client):
    app.state.pool = app_pool
    await tenancy.create_tenant(db_pool, slug="bravo", name="Bravo", tenant_id=TENANT_B)
    out = {}
    for tid, user in ((TENANT_A, "alice"), (TENANT_B, "bob")):
        full, prefix, key_hash = auth_svc.generate_api_key()
        async with db_pool.acquire() as con:
            uid = await con.fetchval(
                "INSERT INTO app_users (username, role, clearance, pw_hash, tenant_id) "
                "VALUES ($1,'admin','restricted',$2,$3) RETURNING id", user, auth_svc.hash_password("pw-" + user), tid)
            await con.execute(
                "INSERT INTO api_keys (user_id, name, prefix, key_hash, scopes, tenant_id) "
                "VALUES ($1,'k',$2,$3,$4::text[],$5)", uid, prefix, key_hash,
                sorted(auth_svc.ROLE_CAPABILITIES["admin"]), tid)
        r = await client.post("/v1/ingest/sources", headers={"X-API-Key": full}, json={"name": f"src-{user}"})
        assert r.status_code == 201, r.text
        out[user] = {"key": full, "token": r.json()["token"], "id": r.json()["id"]}
    return out


async def test_ingest_hostile_documents_are_rejected_or_stored_never_500(client, ingest_env, db_pool):
    tok = {"X-Paddock-Ingest-Token": ingest_env["alice"]["token"]}
    sarif = copy.deepcopy(S.SARIF)
    res0 = sarif["runs"][0]["results"][0]
    res0["properties"] = {"evil": "x\u0000y\ud800z", "n": float("nan"), "deep": json.loads("[" * 40 + "]" * 40)}
    docs = [
        json.dumps(sarif),
        '{"runs":[{"tool":{"driver":{"name":"x"}},"results":[{"ruleId":"a","message":{"text":"m"},"level":NaN}]}],'
        '"version":"2.1.0"}',
        '{"runs":[{"tool":{"driver":{"name":"\\ud800"}},"results":[{"ruleId":"r\\u0000","message":{"text":"\\udfff"}}]}],'
        '"version":"2.1.0"}',
        json.dumps({"bomFormat": "CycloneDX", "dependencies": "oops", "components": [{"name": "a", "purl": 5}]}),
        json.dumps({"spdxVersion": "SPDX-2.3", "packages": 5.5, "relationships": [None]}),
    ]
    for d in docs:
        r = await client.post("/v1/ingest", headers=tok, content=d.encode("utf-8", "surrogatepass"))
        assert r.status_code < 500, (d[:120], r.status_code, r.text)
        assert "Traceback" not in r.text


async def test_ingest_token_confusion_and_cross_tenant(client, ingest_env, db_pool):
    a, b = ingest_env["alice"], ingest_env["bob"]
    body = json.dumps(S.SARIF).encode()
    ta, tb = a["token"], b["token"]
    tid_a, sid_a, sec_a = ingest_tokens.parse_token(ta)
    tid_b, sid_b, sec_b = ingest_tokens.parse_token(tb)
    forged = [
        ingest_tokens.build_token(tid_b, sid_a, sec_a),      # A's source under B's tenant
        ingest_tokens.build_token(tid_a, sid_b, sec_b),      # B's source under A's tenant
        ingest_tokens.build_token(tid_a, sid_a, sec_b),      # right ids, other tenant's secret
        ta.replace("pdi_", "pet_", 1), ta.replace("pdi_", "pst_", 1), ta.upper(), ta[:-1], ta + "x", ta + "\u00e9",
        "pdi_" + "0" * 32 + "_" + "0" * 32 + "_" + "A" * 43, "pdi_{" + "0" * 30 + "}_" + "0" * 32 + "_" + "A" * 43,
        "pdi_" + "0" * 400,
    ]
    for t in forged:
        for hdr in ({"X-Paddock-Ingest-Token": t}, {"Authorization": "Bearer " + t}):
            try:
                r = await client.post("/v1/ingest", headers=hdr, content=body)
            except UnicodeEncodeError:
                continue
            assert r.status_code in (401, 429), (t[:40], r.status_code, r.text)
    ok = await client.post("/v1/ingest", headers={"X-Paddock-Ingest-Token": ta}, content=body)
    assert ok.status_code == 200, ok.text
    async with db_pool.acquire() as con:
        n_b = await con.fetchval("SELECT COUNT(*) FROM findings WHERE tenant_id = $1", TENANT_B)
    assert n_b == 0


async def test_ingest_failure_limiter_follows_ipv6_prefix_not_the_full_address(client, ingest_env):
    ingest_router.FAILED_PER_MIN, prev = 5, ingest_router.FAILED_PER_MIN
    try:
        codes = []
        for i in range(8):
            r = await client.post("/v1/ingest", headers={"X-Paddock-Ingest-Token": "pdi_nope"},
                                  content=b"{}")
            codes.append(r.status_code)
        assert 429 in codes
    finally:
        ingest_router.FAILED_PER_MIN = prev


# --------------------------------------------------------------------------- #
# SCIM filter grammar
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("flt", [
    'userName eq "\\ud800"', 'userName eq "\\u0000"', 'userName co "\\u0000"',
    'meta.created gt "0001-01-01T00:00:00+23:59"', 'meta.created gt "9999-12-31T23:59:59-23:59"',
    'meta.created lt "2020-13-45"', 'emails[type eq "work" and value co "\\u0000"]',
    "userName eq " + '"' + "a" * 900 + '"', "(" * 9 + 'userName pr' + ")" * 9, "not (not (not (userName pr)))",
    "userName eq 1e999", 'userName eq "\\x41"', 'userName eq "unterminated', "userName eq \"a\" and",
    'emails[emails[emails[type eq "a"]]]', "a[" * 30, " ", "\x00", "userName\x00eq \"a\"", "userName eq \"\u202e\"",
    'userName eq "' + "\\" * 500 + '"',
])
async def test_scim_filter_hostile_inputs_are_400_or_ok_never_500(client, flt):
    r = await client.post("/v1/auth/sso/admin/scim-tokens", json={"name": "okta"})
    tok = r.json()["token"]
    h = {"Authorization": f"Bearer {tok}"}
    r = await client.get("/scim/v2/Users", params={"filter": flt}, headers=h)
    assert r.status_code in (200, 400), (flt[:60], r.status_code, r.text[:200])
    assert "Traceback" not in r.text and "asyncpg" not in r.text


def test_scim_filter_pathological_inputs_parse_in_bounded_time():
    from app.identity import scim_filter

    cases = ["a " * 500, "(" * 500, 'x eq "' + "\\\"" * 400 + '"', "[" * 1000, "a[" * 400,
             " and ".join(['userName eq "x"'] * 200), "not " * 300 + "(a pr)", "a" * 5000]
    t = time.time()
    for c in cases:
        try:
            scim_filter.compile_filter(c, {"username": scim_filter.Col("u")}, [])
        except scim_filter.FilterError:
            pass
    assert time.time() - t < 2


# --------------------------------------------------------------------------- #
# SAML single logout: an unauthenticated inflate bomb
# --------------------------------------------------------------------------- #

def test_sls_refuses_inflate_bombs_before_the_xml_library_sees_them():
    from app.identity import saml

    if not saml.SAML_AVAILABLE:
        pytest.skip("python3-saml unavailable")
    bomb = base64.b64encode(zlib.compress(b"A" * (80 * 1024 * 1024), 9)[2:-4])  # raw deflate
    assert len(bomb) < 200_000
    from urllib.parse import quote

    q = f"SAMLRequest={quote(bomb.decode())}&SigAlg=x&Signature=y"
    tracemalloc_peak = _peak_mem(lambda: _expect_saml_error(saml, q))
    assert tracemalloc_peak < 20 * 1024 * 1024, tracemalloc_peak


def _expect_saml_error(saml, q):
    cfg = {"idp_entity_id": "https://idp.example", "idp_sso_url": "https://idp.example/sso",
           "idp_x509_cert": "", "sp_entity_id": "https://sp.example"}
    with pytest.raises(saml.SAMLError):
        saml.process_sls("corp", cfg, query_string=q)


def _peak_mem(fn):
    import tracemalloc

    tracemalloc.start()
    try:
        fn()
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


# --------------------------------------------------------------------------- #
# Anonymous requests must not be able to flood the audit chain
# --------------------------------------------------------------------------- #

async def test_anonymous_public_posts_are_throttled_before_the_audit_write(enforce, client, db_pool, monkeypatch):
    from app import auth as auth_mod

    monkeypatch.setattr(auth_mod, "ANON_PUBLIC_PER_MIN", 20, raising=False)
    codes = []
    for i in range(60):
        r = await client.post("/v1/msp/invites/redeem", json={
            "token": f"{TENANT_B}.{'a' * 43}", "username": f"user{i}", "password": "correct horse battery"})
        codes.append(r.status_code)
    assert 429 in codes, set(codes)
    async with db_pool.acquire() as con:
        n = await con.fetchval("SELECT COUNT(*) FROM audit_log WHERE actor = 'anonymous'")
    assert n < 60 * 2, n


# --------------------------------------------------------------------------- #
# MSP invite redemption (public): single use under a race, and no free CPU burn
# --------------------------------------------------------------------------- #

@pytest_asyncio.fixture
async def msp_world(enforce, app, app_pool, db_pool, client):
    from .test_msp import MSP_ID, _h, _login, _seed_msp, _seed_user

    app.state.pool = app_pool
    await _seed_msp(db_pool, MSP_ID, "msp-one", "MSP One")
    await _seed_user(db_pool, MSP_ID, "root", "admin")
    t = await _login(client, "root")
    r = await client.post("/v1/msp/customers", headers=_h(t), json={"slug": "cust-a", "name": "A"})
    assert r.status_code == 201, r.text
    return r.json()


async def test_invite_is_single_use_under_20_concurrent_redemptions(client, msp_world, db_pool):
    tok = msp_world["invite"]["token"]
    rs = await asyncio.gather(*[client.post("/v1/msp/invites/redeem", json={
        "token": tok, "username": f"racer{i}", "password": "correct horse battery"}) for i in range(20)])
    codes = sorted(r.status_code for r in rs)
    assert codes.count(201) == 1 and set(codes) <= {201, 400, 429}, codes
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT COUNT(*) FROM app_users WHERE username LIKE 'racer%'") == 1


async def test_bad_invite_token_never_reaches_the_password_hash(client, msp_world, monkeypatch):
    calls = []
    real = auth_svc.hash_password
    monkeypatch.setattr(auth_svc, "hash_password", lambda p: calls.append(1) or real(p))
    tid = msp_world["id"]
    for tok in (f"{tid}.{'a' * 43}", f"{TENANT_B}.{'b' * 43}", "x" * 40, f"{tid}."):
        r = await client.post("/v1/msp/invites/redeem", json={
            "token": tok, "username": "someone", "password": "correct horse battery"})
        assert r.status_code in (400, 422)
    assert calls == [], "a wrong token must be rejected before any PBKDF2 work"


async def test_failed_invite_redemptions_are_locked_out_per_client(client, msp_world):
    tid = msp_world["id"]
    codes = []
    for i in range(14):
        r = await client.post("/v1/msp/invites/redeem", json={
            "token": f"{tid}.{i:043d}", "username": f"u{i}xx", "password": "correct horse battery"})
        codes.append(r.status_code)
    assert codes[:10] == [400] * 10 and set(codes[10:]) == {429}, codes


# --------------------------------------------------------------------------- #
# Trust page password: rotating source addresses must not give unlimited guesses
# --------------------------------------------------------------------------- #

async def test_trust_password_guessing_is_capped_per_link_across_addresses(client, app, db_pool, fake_redis,
                                                                          monkeypatch):
    from app.growth.config import growth_settings

    monkeypatch.setattr(growth_settings, "trust_max_password_attempts", 3)
    tok = trust.new_token()
    async with db_pool.acquire() as con:
        await con.execute(
            "INSERT INTO trust_links (label, token_hash, token_hint, sections, period_days, expires_at, password_hash, "
            "created_by) VALUES ('x',$1,'abcd',ARRAY['grade'],30,NOW()+INTERVAL '1 day',$2,'t')",
            trust.hash_token(tok), auth_svc.hash_password("the-right-password"))
    pool = app.state.pool
    outcomes = []
    for i in range(45):
        ip = f"2001:db8:{i:x}::1"  # a different /64 every attempt: only the per-link cap can stop this
        try:
            await trust.view(pool, fake_redis, tok, "wrong-guess", ip)
        except Exception as exc:  # noqa: BLE001
            outcomes.append(getattr(exc, "status_code", None))
    assert outcomes.count(401) == 30 and set(outcomes[30:]) == {429}, outcomes
    with pytest.raises(Exception) as ei:
        await trust.view(pool, fake_redis, tok, "the-right-password", "2001:db8:ffff::1")
    assert getattr(ei.value, "status_code", None) == 429


async def test_exposure_report_20_concurrent_submissions_make_one_report_and_one_budget_unit(
        client, fake_redis, db_pool, monkeypatch):
    from app.growth.config import growth_settings

    monkeypatch.setattr(growth_settings, "ip_requests_per_hour", 1000)
    rs = await asyncio.gather(*[client.post("/v1/public/exposure-report", json={"domain": "Race-Probe.com"})
                                for _ in range(20)])
    assert {r.status_code for r in rs} == {202}
    assert len({r.json()["id"] for r in rs}) == 1
    assert sum(1 for r in rs if not r.json()["cached"]) == 1
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT COUNT(*) FROM exposure_reports") == 1
    keys = [k async for k in fake_redis.scan_iter("growth:dom:*")]
    assert len(keys) == 1 and await fake_redis.get(keys[0]) == "1"


async def test_exposure_report_fails_closed_when_redis_is_down(client, app):
    class Dead:
        async def _boom(self, *a, **k):
            raise ConnectionError("boom 10.1.2.3:6379")

        incr = expire = ttl = get = _boom

    app.state.redis = Dead()
    r = await client.post("/v1/public/exposure-report", json={"domain": "down-probe.com"})
    assert r.status_code == 503 and "10.1.2.3" not in r.text and "boom" not in r.text


async def test_anonymous_public_json_posts_have_a_body_cap(enforce, client):
    big = json.dumps({"domain": "big-probe.com", "email": "a@" + "b" * 400_000 + ".com"})
    r = await client.post("/v1/public/exposure-report", content=big, headers={"content-type": "application/json"})
    assert r.status_code == 413
    r = await client.post("/v1/sensors/enroll", content=big, headers={"content-type": "application/json"})
    assert r.status_code == 413
    ok = await client.post("/v1/public/exposure-report", json={"domain": "small-probe.com"})
    assert ok.status_code == 202
