"""Proof-of-control for scope (schema 021).

DNS and HTTP are always mocked: no test here sends a packet anywhere.
"""
from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from app import auth as auth_svc
from app import scope as scope_svc
from app import scope_proof
from app.config import settings

PUBLIC_IP = "93.184.215.14"


@pytest.fixture
def require_proof():
    prev = settings.require_scope_proof
    settings.require_scope_proof = True
    scope_svc.scope_cache.invalidate()
    try:
        yield
    finally:
        settings.require_scope_proof = prev
        scope_svc.scope_cache.invalidate()


@pytest.fixture
def no_rate_limit():
    prev = settings.scope_proof_min_interval_sec
    settings.scope_proof_min_interval_sec = 0
    try:
        yield
    finally:
        settings.scope_proof_min_interval_sec = prev


@pytest.fixture
def dns(monkeypatch):
    """Fake TXT zone + pinned A records (so scope.check never resolves)."""
    zone: dict[str, list[str]] = {}
    calls: list[str] = []

    async def fake_lookup(name: str) -> list[str]:
        calls.append(name)
        return list(zone.get(name, []))

    monkeypatch.setattr(scope_proof, "lookup_txt", fake_lookup)

    def pin(*hosts: str) -> None:
        for h in hosts:
            scope_svc.dns_cache._by_host[h] = (time.monotonic() + 10_000, [PUBLIC_IP])

    zone_obj = type("Zone", (), {"txt": zone, "calls": calls, "pin": staticmethod(pin)})
    return zone_obj


@pytest.fixture
def web(monkeypatch):
    """Fake HTTPS file server for fetch_http."""
    files: dict[str, tuple[int, str]] = {}
    calls: list[str] = []

    async def fake_fetch(url: str):
        calls.append(url)
        return files.get(url, (404, "not found"))

    monkeypatch.setattr(scope_proof, "fetch_http", fake_fetch)
    return type("Web", (), {"files": files, "calls": calls})


async def _add(client, kind, value):
    r = await client.post("/v1/scope", json={"kind": kind, "value": value, "added_by": "t"})
    assert r.status_code == 201, r.text
    return r.json()


async def _check(client, target):
    r = await client.post("/v1/scope/check", json={"target": target})
    assert r.status_code == 200, r.text
    return r.json()


# --------------------------------------------------------------------------- #
# Challenge
# --------------------------------------------------------------------------- #

async def test_challenge_for_domain_gives_exact_values_and_is_stable(client):
    e = await _add(client, "domain", "Example.com")
    r = await client.post(f"/v1/scope/{e['id']}/challenge")
    assert r.status_code == 200, r.text
    c = r.json()
    tok = c["token"]
    assert len(tok) >= 32
    assert c["dns_txt"] == {"name": "_paddock-challenge.example.com", "type": "TXT", "value": tok}
    assert c["http_file"] == {
        "url": f"https://example.com/.well-known/paddock-verification/{tok}",
        "body": tok,
    }
    assert c["methods"] == ["dns_txt", "http_file"]
    assert c["proof"]["status"] == "pending"
    # Re-issuing returns the same token (re-verification checks this value).
    again = (await client.post(f"/v1/scope/{e['id']}/challenge")).json()
    assert again["token"] == tok


async def test_wildcard_challenge_is_dns_only(client):
    e = await _add(client, "subdomain_wildcard", "*.example.org")
    c = (await client.post(f"/v1/scope/{e['id']}/challenge")).json()
    assert c["domain"] == "example.org"
    assert c["methods"] == ["dns_txt"]
    assert c["http_file"] is None


async def test_tokens_are_per_entry(client):
    a = await _add(client, "domain", "a.example.com")
    b = await _add(client, "domain", "b.example.com")
    ta = (await client.post(f"/v1/scope/{a['id']}/challenge")).json()["token"]
    tb = (await client.post(f"/v1/scope/{b['id']}/challenge")).json()["token"]
    assert ta != tb


async def test_challenge_refused_for_ip_ranges(client):
    e = await _add(client, "ipv4_cidr", "198.51.100.0/24")
    r = await client.post(f"/v1/scope/{e['id']}/challenge")
    assert r.status_code == 422
    assert "attestation" in r.json()["detail"]


async def test_challenge_unknown_entry_404(client):
    assert (await client.post("/v1/scope/99999/challenge")).status_code == 404


# --------------------------------------------------------------------------- #
# Verify: DNS / HTTP
# --------------------------------------------------------------------------- #

async def test_unverified_entry_never_matches_when_required(client, require_proof, dns):
    dns.pin("example.com")
    e = await _add(client, "domain", "example.com")
    d = await _check(client, "example.com")
    assert d["allow"] is False
    assert f"scope entry {e['id']}" in d["reason"] and "pending" in d["reason"]


async def test_unverified_entry_still_matches_when_not_required(client, dns):
    dns.pin("example.com")
    await _add(client, "domain", "example.com")
    assert (await _check(client, "example.com"))["allow"] is True


async def test_dns_txt_verifies_and_unlocks_scope(client, require_proof, dns):
    dns.pin("example.com", "api.example.com")
    e = await _add(client, "subdomain_wildcard", "example.com")
    tok = (await client.post(f"/v1/scope/{e['id']}/challenge")).json()["token"]

    r = await client.post(f"/v1/scope/{e['id']}/verify", json={})
    assert r.status_code == 200
    body = r.json()
    assert body["check"]["ok"] is False
    assert "no TXT record" in body["check"]["detail"]
    assert body["proof"]["status"] == "pending"
    assert (await _check(client, "api.example.com"))["allow"] is False

    dns.txt["_paddock-challenge.example.com"] = ["unrelated", f'"{tok}"']
    settings.scope_proof_min_interval_sec, prev = 0, settings.scope_proof_min_interval_sec
    try:
        body = (await client.post(f"/v1/scope/{e['id']}/verify", json={"method": "dns_txt"})).json()
    finally:
        settings.scope_proof_min_interval_sec = prev
    assert body["check"] == {"ok": True, "method": "dns_txt",
                             "detail": "TXT _paddock-challenge.example.com matches"}
    assert body["proof"]["status"] == "verified"
    assert body["proof"]["effective"] is True
    d = await _check(client, "api.example.com")
    assert d["allow"] is True and d["matched_entry"] == e["id"]
    assert dns.calls == ["_paddock-challenge.example.com"] * 2


async def test_http_file_verifies_exact_domain(client, require_proof, dns, web):
    dns.pin("www.example.net")
    e = await _add(client, "domain", "www.example.net")
    c = (await client.post(f"/v1/scope/{e['id']}/challenge")).json()
    web.files[c["http_file"]["url"]] = (200, c["token"] + "\n")
    body = (await client.post(f"/v1/scope/{e['id']}/verify",
                              json={"method": "http_file"})).json()
    assert body["check"]["ok"] is True
    assert body["proof"]["status"] == "verified"
    assert body["proof"]["method"] == "http_file"
    assert web.calls == [c["http_file"]["url"]]
    assert (await _check(client, "www.example.net"))["allow"] is True


async def test_http_file_wrong_body_or_status_fails(client, dns, web, no_rate_limit):
    e = await _add(client, "domain", "example.net")
    c = (await client.post(f"/v1/scope/{e['id']}/challenge")).json()
    web.files[c["http_file"]["url"]] = (200, "something else")
    body = (await client.post(f"/v1/scope/{e['id']}/verify", json={"method": "http_file"})).json()
    assert body["check"]["ok"] is False and "does not equal" in body["check"]["detail"]
    web.files[c["http_file"]["url"]] = (302, c["token"])
    body = (await client.post(f"/v1/scope/{e['id']}/verify", json={"method": "http_file"})).json()
    assert body["check"]["ok"] is False and "HTTP 302" in body["check"]["detail"]


async def test_default_method_tries_dns_then_http(client, dns, web):
    e = await _add(client, "domain", "example.io")
    c = (await client.post(f"/v1/scope/{e['id']}/challenge")).json()
    web.files[c["http_file"]["url"]] = (200, c["token"])
    body = (await client.post(f"/v1/scope/{e['id']}/verify")).json()
    assert body["check"]["ok"] is True and body["check"]["method"] == "http_file"
    assert dns.calls == ["_paddock-challenge.example.io"]


async def test_wildcard_cannot_be_proven_by_http_file(client, dns, web):
    e = await _add(client, "subdomain_wildcard", "example.io")
    c = (await client.post(f"/v1/scope/{e['id']}/challenge")).json()
    web.files[f"https://example.io/.well-known/paddock-verification/{c['token']}"] = (200, c["token"])
    body = (await client.post(f"/v1/scope/{e['id']}/verify", json={"method": "http_file"})).json()
    assert body["check"]["ok"] is False
    assert body["proof"]["status"] == "pending"
    assert web.calls == []


async def test_verify_requires_challenge_and_is_rate_limited(client, dns):
    e = await _add(client, "domain", "example.com")
    r = await client.post(f"/v1/scope/{e['id']}/verify")
    assert r.status_code == 409
    await client.post(f"/v1/scope/{e['id']}/challenge")
    assert (await client.post(f"/v1/scope/{e['id']}/verify")).status_code == 200
    r = await client.post(f"/v1/scope/{e['id']}/verify")
    assert r.status_code == 429
    assert int(r.headers["retry-after"]) >= 1


async def test_verify_history_is_recorded(client, dns, db_pool, no_rate_limit):
    e = await _add(client, "domain", "example.com")
    await client.post(f"/v1/scope/{e['id']}/challenge")
    for _ in range(3):
        await client.post(f"/v1/scope/{e['id']}/verify", json={"method": "dns_txt"})
    async with db_pool.acquire() as con:
        h = await con.fetchval(
            "SELECT jsonb_array_length(history) FROM scope_proofs WHERE scope_entry_id=$1",
            e["id"],
        )
    assert h == 3


# --------------------------------------------------------------------------- #
# Attestation (IP ranges)
# --------------------------------------------------------------------------- #

async def test_attestation_for_ip_range(client, require_proof):
    e = await _add(client, "ipv4_cidr", "198.51.100.0/24")
    assert (await _check(client, "198.51.100.7"))["allow"] is False
    r = await client.post(f"/v1/scope/{e['id']}/verify",
                          json={"method": "attestation", "loa_ref": "LOA-2026-17"})
    assert r.status_code == 422  # approver missing
    r = await client.post(f"/v1/scope/{e['id']}/verify", json={
        "method": "attestation", "loa_ref": "LOA-2026-17 (signed PDF in GRC)",
        "approver": "Jane Doe, CISO",
    })
    assert r.status_code == 200, r.text
    p = r.json()["proof"]
    assert p["status"] == "attested"
    assert p["attested_by"] == "dev-admin"
    assert p["approver"] == "Jane Doe, CISO"
    assert p["attested_at"] is not None
    assert (await _check(client, "198.51.100.7"))["allow"] is True


async def test_attestation_refused_for_domains(client):
    e = await _add(client, "domain", "example.com")
    r = await client.post(f"/v1/scope/{e['id']}/verify", json={
        "method": "attestation", "loa_ref": "x", "approver": "y"})
    assert r.status_code == 422


async def test_scope_list_carries_proof_status(client, dns):
    e = await _add(client, "ipv4_cidr", "198.51.100.0/24")
    d = await _add(client, "domain", "example.com")
    await client.post(f"/v1/scope/{e['id']}/verify",
                      json={"loa_ref": "LOA-1", "approver": "CISO"})
    rows = {x["id"]: x for x in (await client.get("/v1/scope")).json()}
    assert rows[e["id"]]["proof"]["status"] == "attested"
    assert rows[d["id"]]["proof"]["status"] == "pending"
    assert rows[d["id"]]["proof"]["methods"] == ["dns_txt", "http_file"]
    assert rows[d["id"]]["proof"]["required"] is False
    one = (await client.get(f"/v1/scope/{d['id']}/proof")).json()
    assert one["proof"]["status"] == "pending"
    assert "token" not in one["proof"]  # the token is only handed out by /challenge


# --------------------------------------------------------------------------- #
# Periodic re-verification + grace
# --------------------------------------------------------------------------- #

async def test_reverify_grace_then_expiry_then_recovery(client, db_pool, require_proof, dns):
    dns.pin("example.com")
    e = await _add(client, "domain", "example.com")
    tok = (await client.post(f"/v1/scope/{e['id']}/challenge")).json()["token"]
    dns.txt["_paddock-challenge.example.com"] = [tok]
    assert (await client.post(f"/v1/scope/{e['id']}/verify")).json()["proof"]["status"] == "verified"

    t0 = datetime.now(UTC)
    # Not due yet: nothing is checked.
    s = await scope_proof.reverify_due(db_pool, now=t0 + timedelta(hours=1))
    assert s["checked"] == 0

    # The record disappears; the next due check starts the grace period.
    dns.txt.clear()
    t1 = t0 + timedelta(hours=settings.scope_proof_reverify_hours + 1)
    s = await scope_proof.reverify_due(db_pool, now=t1)
    assert s == {"checked": 1, "ok": 0, "failed": 1, "expired": 0}
    p = (await client.get(f"/v1/scope/{e['id']}/proof")).json()["proof"]
    assert p["status"] == "verified" and p["failing_since"] is not None
    assert p["grace_until"] is not None
    assert (await _check(client, "example.com"))["allow"] is True  # still in grace

    # Past the grace period: expired, and scope stops matching.
    t2 = t1 + timedelta(hours=settings.scope_proof_grace_hours + 1)
    s = await scope_proof.reverify_due(db_pool, now=t2)
    assert s["expired"] == 1
    p = (await client.get(f"/v1/scope/{e['id']}/proof")).json()["proof"]
    assert p["status"] == "expired" and p["effective"] is False
    d = await _check(client, "example.com")
    assert d["allow"] is False and "expired" in d["reason"]

    # Re-publishing the record and verifying restores it.
    dns.txt["_paddock-challenge.example.com"] = [tok]
    settings.scope_proof_min_interval_sec, prev = 0, settings.scope_proof_min_interval_sec
    try:
        body = (await client.post(f"/v1/scope/{e['id']}/verify")).json()
    finally:
        settings.scope_proof_min_interval_sec = prev
    assert body["proof"]["status"] == "verified" and body["proof"]["failing_since"] is None
    assert (await _check(client, "example.com"))["allow"] is True


async def test_reverify_success_refreshes_and_clears_failure(client, db_pool, dns):
    e = await _add(client, "domain", "example.com")
    tok = (await client.post(f"/v1/scope/{e['id']}/challenge")).json()["token"]
    dns.txt["_paddock-challenge.example.com"] = [tok]
    await client.post(f"/v1/scope/{e['id']}/verify")
    later = datetime.now(UTC) + timedelta(hours=settings.scope_proof_reverify_hours + 1)
    s = await scope_proof.reverify_due(db_pool, now=later)
    assert s == {"checked": 1, "ok": 1, "failed": 0, "expired": 0}


async def test_attestation_expires_on_valid_until(client, db_pool, require_proof):
    e = await _add(client, "ipv4_cidr", "198.51.100.0/24")
    until = datetime.now(UTC) + timedelta(days=1)
    await client.post(f"/v1/scope/{e['id']}/verify", json={
        "loa_ref": "LOA-9", "approver": "CISO", "valid_until": until.isoformat()})
    assert (await _check(client, "198.51.100.9"))["allow"] is True
    s = await scope_proof.reverify_due(db_pool, now=until + timedelta(minutes=1))
    assert s["expired"] == 1
    assert (await _check(client, "198.51.100.9"))["allow"] is False


async def test_reverify_never_touches_inactive_or_pending(client, db_pool, dns):
    e = await _add(client, "domain", "example.com")
    await client.post(f"/v1/scope/{e['id']}/challenge")
    later = datetime.now(UTC) + timedelta(days=30)
    s = await scope_proof.reverify_due(db_pool, now=later)
    assert s["checked"] == 0
    assert dns.calls == []


# --------------------------------------------------------------------------- #
# The outbound fetch itself: minimal, identified, never off-host
# --------------------------------------------------------------------------- #

@pytest.fixture
def mock_transport(monkeypatch):
    seen: list[httpx.Request] = []
    routes: dict[str, httpx.Response] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return routes.get(str(request.url), httpx.Response(404))

    real = httpx.AsyncClient

    class Client(real):  # type: ignore[misc, valid-type]
        def __init__(self, *a, **kw):
            kw["transport"] = httpx.MockTransport(handler)
            super().__init__(*a, **kw)

    monkeypatch.setattr(httpx, "AsyncClient", Client)

    async def ok(url, **_kw):
        return url

    from app.integrations import netsafety

    monkeypatch.setattr(netsafety, "validate_outbound_url", ok)
    return type("T", (), {"seen": seen, "routes": routes})


async def test_fetch_identifies_itself_and_caps_body(mock_transport):
    url = "https://example.com/.well-known/paddock-verification/tok"
    mock_transport.routes[url] = httpx.Response(200, content=b"x" * 50_000)
    status, body = await scope_proof.fetch_http(url)
    assert status == 200 and len(body) == 1024
    req = mock_transport.seen[0]
    assert req.headers["user-agent"].startswith("Paddock-Verifier/")
    assert req.method == "GET"


async def test_fetch_follows_same_host_redirect_only(mock_transport):
    base = "https://example.com/.well-known/paddock-verification/tok"
    mock_transport.routes[base] = httpx.Response(301, headers={"location": "/v2/tok"})
    mock_transport.routes["https://example.com/v2/tok"] = httpx.Response(200, text="tok")
    assert await scope_proof.fetch_http(base) == (200, "tok")

    mock_transport.routes[base] = httpx.Response(302, headers={"location": "https://evil.example/tok"})
    with pytest.raises(scope_proof.FetchRefused, match="different host"):
        await scope_proof.fetch_http(base)

    mock_transport.routes[base] = httpx.Response(302, headers={"location": "http://example.com/tok"})
    with pytest.raises(scope_proof.FetchRefused, match="https"):
        await scope_proof.fetch_http(base)
    assert all(r.url.host == "example.com" for r in mock_transport.seen)


async def test_fetch_refuses_private_targets():
    # Real guardrail (no mock): a literal loopback/metadata address is refused
    # before any connection is attempted.
    with pytest.raises(scope_proof.FetchRefused):
        await scope_proof.fetch_http("https://127.0.0.1/.well-known/paddock-verification/t")
    with pytest.raises(scope_proof.FetchRefused):
        await scope_proof.fetch_http("https://169.254.169.254/.well-known/paddock-verification/t")


async def test_txt_lookup_parses_chunked_records(monkeypatch):
    import dns.asyncresolver

    class R:
        def __init__(self, *chunks):
            self.strings = chunks

    async def fake_resolve(name, rtype, **kw):
        assert name == "_paddock-challenge.example.com." and rtype == "TXT"
        assert kw.get("search") is False
        return [R(b"abc", b"def"), R(b"other")]

    monkeypatch.setattr(dns.asyncresolver, "resolve", fake_resolve)
    assert await scope_proof.lookup_txt("_paddock-challenge.example.com") == ["abcdef", "other"]


# --------------------------------------------------------------------------- #
# RBAC
# --------------------------------------------------------------------------- #

def test_rbac_proof_routes_are_admin_only():
    assert auth_svc.required_capability("POST", "/v1/scope/3/challenge") == "admin"
    assert auth_svc.required_capability("POST", "/v1/scope/3/verify") == "admin"
    assert auth_svc.required_capability("GET", "/v1/scope/3/proof") == "read"
    assert auth_svc.required_capability("PUT", "/v1/onboarding") == "admin"
    assert auth_svc.required_capability("GET", "/v1/onboarding") == "read"
