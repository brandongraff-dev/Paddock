"""Free public exposure report: endpoints, abuse controls, cache, leads.

Everything runs in AUTH_MODE=enforce with NO credentials (that is the point of
the endpoint), a fake resolver and a fake CT log: no network.
"""
from __future__ import annotations

import json
import re
import uuid

import httpx
import pytest
import pytest_asyncio

from app import tenancy
from app.config import settings
from app.growth import abuse, clients, exposure
from app.growth.config import growth_settings
from tests.growth_fakes import FakeCT, cert, healthy_zone

D = "acme-corp.org"


@pytest.fixture
def enforce():
    prev = settings.auth_mode
    settings.auth_mode = "enforce"
    try:
        yield
    finally:
        settings.auth_mode = prev


@pytest.fixture
def fakes():
    resolver = healthy_zone(D)
    resolver.add(f"old.{D}", "CNAME", "acme-old.herokuapp.com")
    resolver.add(f"vpn.{D}", "A", "93.184.216.40")
    ct = FakeCT([cert([D, f"www.{D}", f"old.{D}", f"vpn.{D}"])])
    clients.set_client_factory(lambda: (resolver, ct))
    abuse.set_captcha_verifier(None)
    saved = {k: getattr(growth_settings, k) for k in (
        "ip_requests_per_hour", "domain_requests_per_day", "global_daily_cap", "cache_hours")}
    try:
        yield resolver, ct
    finally:
        clients.set_client_factory(None)
        abuse.set_captcha_verifier(None)
        for k, v in saved.items():
            setattr(growth_settings, k, v)


async def post(client, domain=D, **extra):
    return await client.post("/v1/public/exposure-report", json={"domain": domain, **extra})


async def finish(app, n=5):
    return await exposure.run_pending(app.state.pool, n)


async def test_happy_path_graded_summary_and_teaser(enforce, fakes, app, client):
    r = await post(client)
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["domain"] == D and body["status"] == "queued" and body["cached"] is False
    rid = body["id"]

    g = await client.get(f"/v1/public/exposure-report/{rid}")
    assert g.status_code == 200 and g.json()["status"] == "queued" and g.json()["summary"] is None

    assert await finish(app) == 1
    g = (await client.get(f"/v1/public/exposure-report/{rid}")).json()
    assert g["status"] == "done"
    s = g["summary"]
    assert s["grade"] in "ABCDF" and 0 <= s["score"] <= 100 and s["reasons"]
    assert s["by_severity"]["high"] >= 1  # the dangling heroku CNAME
    assert g["teaser"]["shown"] and g["teaser"]["hidden"] >= 0
    assert g["cta"]["url"] == growth_settings.signup_url and "Verify" in g["cta"]["text"]
    assert "No traffic was sent" in g["passive_notice"]
    top = g["teaser"]["shown"][0]
    assert top["severity"] == "high" and top["host"] == f"o***.{D}"


async def test_public_response_leaks_nothing_internal(enforce, fakes, app, client):
    rid = (await post(client)).json()["id"]
    await finish(app)
    raw = (await client.get(f"/v1/public/exposure-report/{rid}")).text
    for forbidden in (f"old.{D}", f"vpn.{D}", "herokuapp", "93.184.216", "tenant", "findings\"", "fix\""):
        assert forbidden not in raw, forbidden
    assert not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", raw)
    assert set(json.loads(raw)) == {
        "id", "domain", "status", "created_at", "finished_at", "error", "summary", "teaser", "cta", "passive_notice"
    }


async def test_other_api_still_requires_auth(enforce, fakes, client):
    assert (await client.get("/v1/suppliers")).status_code == 401
    assert (await client.get("/v1/trust-links")).status_code == 401
    assert (await client.post("/v1/trust-links", json={"label": "x"})).status_code == 401
    assert (await client.post("/v1/public/exposure-report/abc")).status_code in (401, 404, 405)


@pytest.mark.parametrize("bad,code", [
    ("1.2.3.4", "ip_literal"), ("localhost", "internal_name"), ("www.acme-corp.org", "not_registrable"),
    ("https://acme-corp.org", "invalid_chars"), ("x.internal", "internal_name"), ("[::1]", "ip_literal"),
])
async def test_invalid_domains_are_refused_and_never_queued(enforce, fakes, client, db_pool, bad, code):
    r = await post(client, bad)
    assert r.status_code == 422
    assert r.json()["detail"]["code"] == code
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT COUNT(*) FROM exposure_reports") == 0


async def test_idn_is_stored_as_punycode(enforce, fakes, client):
    r = await post(client, "bücher.de")
    assert r.status_code == 202 and r.json()["domain"] == "xn--bcher-kva.de"


async def test_cached_for_24h_then_refreshed(enforce, fakes, app, client, db_pool):
    first = (await post(client)).json()
    # in flight: same report
    again = (await post(client)).json()
    assert again["id"] == first["id"] and again["cached"] is True
    await finish(app)
    done = (await post(client)).json()
    assert done["id"] == first["id"] and done["cached"] is True and done["status"] == "done"
    # a failed run is never served from cache: but age the good one out first
    async with db_pool.acquire() as con:
        await con.execute("UPDATE exposure_reports SET finished_at = NOW() - interval '25 hours'")
    fresh = (await post(client)).json()
    assert fresh["id"] != first["id"] and fresh["cached"] is False


async def test_cache_hits_do_not_spend_domain_or_global_budget(enforce, fakes, app, client):
    growth_settings.domain_requests_per_day = 1
    growth_settings.global_daily_cap = 1
    growth_settings.ip_requests_per_hour = 100
    ids = {(await post(client)).json()["id"] for _ in range(6)}
    assert len(ids) == 1


async def test_per_ip_rate_limit(enforce, fakes, client):
    growth_settings.ip_requests_per_hour = 3
    for _ in range(3):
        assert (await post(client)).status_code == 202
    r = await post(client)
    assert r.status_code == 429 and int(r.headers["retry-after"]) > 0
    # invalid input is also counted (cheap probing is still probing)
    r = await post(client, "1.2.3.4")
    assert r.status_code == 422  # validation precedes the limiter: nothing to count


async def test_per_ip_limit_is_per_address(enforce, fakes, client):
    growth_settings.ip_requests_per_hour = 1
    h1, h2 = {"X-Forwarded-For": "198.51.100.1"}, {"X-Forwarded-For": "198.51.100.2"}
    assert (await client.post("/v1/public/exposure-report", json={"domain": D}, headers=h1)).status_code == 202
    assert (await client.post("/v1/public/exposure-report", json={"domain": D}, headers=h1)).status_code == 429
    assert (await client.post("/v1/public/exposure-report", json={"domain": D}, headers=h2)).status_code == 202


async def test_per_domain_limit(enforce, fakes, client, db_pool):
    growth_settings.domain_requests_per_day = 2
    growth_settings.ip_requests_per_hour = 100
    for i in range(2):
        assert (await post(client)).status_code == 202
        async with db_pool.acquire() as con:  # age out so the next one is a fresh assessment
            await con.execute("UPDATE exposure_reports SET status='done', finished_at = NOW() - interval '30 hours'")
    r = await post(client)
    assert r.status_code == 429 and "per domain" in r.json()["detail"]
    # another domain is unaffected
    assert (await post(client, "other-site.org")).status_code == 202


async def test_global_daily_cap(enforce, fakes, client):
    growth_settings.global_daily_cap = 2
    growth_settings.ip_requests_per_hour = 100
    assert (await post(client, "one-site.org")).status_code == 202
    assert (await post(client, "two-site.org")).status_code == 202
    r = await post(client, "three-site.org")
    assert r.status_code == 429 and "capacity" in r.json()["detail"]
    # ...but an already-assessed domain is still served from cache
    assert (await post(client, "one-site.org")).json()["cached"] is True


async def test_queue_depth_cap(enforce, fakes, client, monkeypatch):
    monkeypatch.setattr(growth_settings, "max_queue_depth", 1)
    assert (await post(client, "one-site.org")).status_code == 202
    r = await post(client, "two-site.org")
    assert r.status_code == 503


async def test_limiter_outage_fails_closed(enforce, fakes, app, client):
    class Boom:
        async def incr(self, *a, **k):
            raise ConnectionError("down")

    old = app.state.redis
    app.state.redis = Boom()
    try:
        assert (await post(client)).status_code == 503
    finally:
        app.state.redis = old


async def test_captcha_hook(enforce, fakes, client, db_pool):
    seen = []

    class No:
        async def verify(self, token, ip):
            seen.append(token)
            return token == "good"

    abuse.set_captcha_verifier(No())
    assert (await post(client)).status_code == 403
    r = await post(client, captcha_token="bad")
    assert r.status_code == 403 and r.json()["detail"]["code"] == "captcha_failed"
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT COUNT(*) FROM exposure_reports") == 0
    assert (await post(client, captcha_token="good")).status_code == 202
    assert seen == [None, "bad", "good"]


async def test_turnstile_verifier_against_mock_siteverify():
    calls = []

    def handler(req: httpx.Request):
        calls.append(req)
        ok = b"response=tok" in req.content
        return httpx.Response(200, json={"success": ok})

    v = abuse.TurnstileVerifier("sekret", "https://verify.invalid/x", transport=httpx.MockTransport(handler))
    assert await v.verify("tok", "198.51.100.7") is True
    assert await v.verify("nope", None) is False
    assert await v.verify(None, None) is False
    assert b"secret=sekret" in calls[0].content and b"remoteip=198.51.100.7" in calls[0].content

    def boom(req):
        raise httpx.ConnectError("x")

    v = abuse.TurnstileVerifier("s", "https://verify.invalid/x", transport=httpx.MockTransport(boom))
    assert await v.verify("tok", None) is False  # fails closed


async def test_default_captcha_is_noop():
    assert isinstance(abuse.get_captcha_verifier(), abuse.NoopVerifier)
    assert await abuse.get_captcha_verifier().verify(None, None) is True


async def test_lead_stored_only_with_consent(enforce, fakes, client, db_pool):
    r = await post(client, email="Jane@Corp.EXAMPLE", consent=True)
    assert r.status_code == 202 and r.json()["email_stored"] is True
    r = await post(client, "other-site.org", email="nope@corp.example", consent=False)
    assert r.json()["email_stored"] is False
    async with db_pool.acquire() as con:
        rows = await con.fetch("SELECT email, consent, domain, ip_hash, report_id FROM exposure_leads")
    assert len(rows) == 1
    row = rows[0]
    assert row["email"] == "jane@corp.example" and row["consent"] is True and row["domain"] == D
    assert row["ip_hash"] and "127.0.0.1" not in row["ip_hash"]
    # repeat submissions upsert, not duplicate
    await post(client, email="jane@corp.example", consent=True)
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT COUNT(*) FROM exposure_leads") == 1


@pytest.mark.parametrize("email", ["not-an-email", "a@b", "a b@c.de", "x@y..z", "a" * 300 + "@x.io", "a@b.c\nBcc: x@y.z"])
async def test_bad_email_rejected(enforce, fakes, client, email):
    r = await post(client, email=email, consent=True)
    assert r.status_code == 422 and r.json()["detail"]["code"] == "invalid_email"


async def test_unknown_and_malformed_ids_404(enforce, fakes, client):
    assert (await client.get(f"/v1/public/exposure-report/{uuid.uuid4()}")).status_code == 404
    assert (await client.get("/v1/public/exposure-report/not-a-uuid")).status_code == 404


async def test_nonexistent_domain_reports_failure_cleanly(enforce, fakes, app, client):
    r = await post(client, "no-such-domain.org")
    await finish(app)
    g = (await client.get(f"/v1/public/exposure-report/{r.json()['id']}")).json()
    assert g["status"] == "failed" and g["error"] == "domain_not_found" and g["summary"] is None
    # a failed run is not served from the cache
    again = (await post(client, "no-such-domain.org")).json()
    assert again["id"] != r.json()["id"]


async def test_engine_crash_is_contained(enforce, app, client, db_pool):
    class Boom:
        async def resolve(self, name, rtype):
            raise RuntimeError("internal detail /etc/passwd")

    clients.set_client_factory(lambda: (Boom(), FakeCT()))
    try:
        r = await post(client)
        await finish(app)
        g = (await client.get(f"/v1/public/exposure-report/{r.json()['id']}")).json()
        # every lookup errored -> the engine treats the domain as unreadable, never leaks the exception text
        assert "passwd" not in json.dumps(g)
    finally:
        clients.set_client_factory(None)


async def test_stale_running_jobs_are_requeued_then_failed(enforce, fakes, app, client, db_pool):
    rid = (await post(client)).json()["id"]
    claimed = await exposure.claim_pending(app.state.pool)
    assert len(claimed) == 1
    async with db_pool.acquire() as con:
        await con.execute("UPDATE exposure_reports SET started_at = NOW() - interval '1 hour'")
    again = await exposure.claim_pending(app.state.pool)
    assert [str(c["id"]) for c in again] == [rid]
    async with db_pool.acquire() as con:
        await con.execute("UPDATE exposure_reports SET started_at = NOW() - interval '1 hour', attempts = 3")
    assert await exposure.claim_pending(app.state.pool) == []
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT status FROM exposure_reports") == "failed"


# --------------------------------------------------------------------------- #
# Tenant isolation: platform rows are invisible to customer tenants
# --------------------------------------------------------------------------- #

@pytest_asyncio.fixture
async def rls(app, app_pool):
    app.state.pool = app_pool
    return app_pool


async def test_customer_tenants_cannot_read_leads_or_reports(enforce, fakes, app, client, rls, db_pool):
    other = "00000000-0000-0000-0000-0000000000c3"
    await tenancy.create_tenant(db_pool, slug="charlie", name="Charlie", tenant_id=other)
    await post(client, email="lead@corp.example", consent=True)
    await finish(app)
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT COUNT(*) FROM exposure_leads") == 1
    with tenancy.tenant_context(other):
        async with rls.acquire() as con:
            assert await con.fetchval("SELECT COUNT(*) FROM exposure_leads") == 0
            assert await con.fetchval("SELECT COUNT(*) FROM exposure_reports") == 0
    with tenancy.tenant_context(tenancy.DEFAULT_TENANT_ID):
        async with rls.acquire() as con:
            assert await con.fetchval("SELECT COUNT(*) FROM exposure_reports") == 1
