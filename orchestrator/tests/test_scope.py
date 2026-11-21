"""Scope service tests: normalization, kind-specific matching, audit
writes, cache invalidation, and the HTTP routes.
"""
from __future__ import annotations

import pytest

from app import scope as scope_svc


# --------------------------------------------------------------------------- #
# Pure normalize tests
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "inp,want",
    [
        ("Example.COM", "example.com"),
        ("example.com.", "example.com"),
        ("https://Example.COM:8443/foo?q=1", "example.com"),
        ("http://user:pass@sub.example.com/x", "sub.example.com"),
        ("example.com:80", "example.com"),
        ("10.0.0.5", "10.0.0.5"),
        ("10.0.0.5:8080", "10.0.0.5"),
        ("http://10.0.0.5:8080/admin", "10.0.0.5"),
        ("2001:db8::1", "2001:db8::1"),
        ("[2001:db8::1]:443", "2001:db8::1"),
        ("https://[2001:db8::1]:443/", "2001:db8::1"),
        ("  Example.com  ", "example.com"),
    ],
)
def test_normalize(inp, want):
    assert scope_svc.normalize(inp) == want


# --------------------------------------------------------------------------- #
# Matching
# --------------------------------------------------------------------------- #

def test_subdomain_wildcard_matches_base_and_any_depth():
    entries = [{"id": 1, "kind": "subdomain_wildcard", "value": "example.com"}]
    for host in ("example.com", "a.example.com", "x.y.z.example.com"):
        ok, mid = scope_svc._match_host_rules(host, entries)
        assert ok is True
        assert mid == 1


def test_subdomain_wildcard_rejects_sibling_and_lookalike():
    entries = [{"id": 1, "kind": "subdomain_wildcard", "value": "example.com"}]
    for host in ("notexample.com", "example.com.evil.com", "example.co"):
        ok, mid = scope_svc._match_host_rules(host, entries)
        assert ok is False, host


def test_domain_exact_only():
    entries = [{"id": 2, "kind": "domain", "value": "example.com"}]
    ok, _ = scope_svc._match_host_rules("example.com", entries)
    assert ok is True
    ok, _ = scope_svc._match_host_rules("api.example.com", entries)
    assert ok is False


def test_ipv4_cidr_match():
    import ipaddress

    entries = [{"id": 3, "kind": "ipv4_cidr", "value": "10.0.0.0/24"}]
    ok, mid = scope_svc._match_ip_rules(ipaddress.ip_address("10.0.0.5"), entries)
    assert ok and mid == 3
    ok, _ = scope_svc._match_ip_rules(ipaddress.ip_address("10.0.1.5"), entries)
    assert ok is False


def test_ipv6_cidr_match():
    import ipaddress

    entries = [{"id": 4, "kind": "ipv6_cidr", "value": "2001:db8::/32"}]
    ok, mid = scope_svc._match_ip_rules(ipaddress.ip_address("2001:db8::1"), entries)
    assert ok and mid == 4
    ok, _ = scope_svc._match_ip_rules(ipaddress.ip_address("2001:db9::1"), entries)
    assert ok is False


def test_asn_is_skipped():
    # asn entries never participate in matching; they are simply ignored.
    import ipaddress

    entries = [{"id": 5, "kind": "asn", "value": "AS12345"}]
    ok, _ = scope_svc._match_ip_rules(ipaddress.ip_address("10.0.0.1"), entries)
    assert ok is False


# --------------------------------------------------------------------------- #
# HTTP route behaviour (audit write + cache invalidation)
# --------------------------------------------------------------------------- #

async def _add_scope(client, kind, value, added_by="test"):
    r = await client.post(
        "/v1/scope",
        json={"kind": kind, "value": value, "added_by": added_by},
    )
    assert r.status_code == 201, r.text
    return r.json()


async def test_scope_check_deny_writes_audit(client, db_pool):
    """A deny decision still writes a scope_decisions row."""
    r = await client.post(
        "/v1/scope/check",
        json={"target": "example.com", "worker": "unit"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["allow"] is False
    async with db_pool.acquire() as con:
        rows = await con.fetch(
            "SELECT decision, worker FROM scope_decisions WHERE target = $1",
            "example.com",
        )
    assert len(rows) == 1
    assert rows[0]["decision"] == "deny"
    assert rows[0]["worker"] == "unit"


async def test_scope_check_allow_wildcard_subdomain(client, db_pool):
    await _add_scope(client, "subdomain_wildcard", "example.com")
    r = await client.post(
        "/v1/scope/check", json={"target": "https://api.example.com/x"}
    )
    assert r.status_code == 200
    body = r.json()
    assert body["allow"] is True
    assert body["normalized"] == "api.example.com"
    assert body["matched_entry"] is not None


async def test_scope_check_allow_case_insensitive_and_trailing_dot(client):
    await _add_scope(client, "subdomain_wildcard", "example.com")
    r = await client.post("/v1/scope/check", json={"target": "API.Example.COM."})
    assert r.status_code == 200
    assert r.json()["allow"] is True


async def test_scope_check_allow_ipv4_cidr_direct(client):
    await _add_scope(client, "ipv4_cidr", "10.0.0.0/24")
    r = await client.post("/v1/scope/check", json={"target": "10.0.0.5:8080"})
    body = r.json()
    assert body["allow"] is True
    assert body["normalized"] == "10.0.0.5"


async def test_scope_add_invalidates_cache(client):
    # First check: nothing in scope -> deny.
    r1 = await client.post("/v1/scope/check", json={"target": "example.com"})
    assert r1.json()["allow"] is False
    # Add an entry.
    await _add_scope(client, "domain", "example.com")
    # Check again: cache must be invalidated so the new entry is visible.
    r2 = await client.post("/v1/scope/check", json={"target": "example.com"})
    assert r2.json()["allow"] is True


async def test_scope_delete_deactivates(client):
    entry = await _add_scope(client, "domain", "example.com")
    r1 = await client.post("/v1/scope/check", json={"target": "example.com"})
    assert r1.json()["allow"] is True
    r = await client.delete(f"/v1/scope/{entry['id']}")
    assert r.status_code == 200
    assert r.json()["active"] is False
    r2 = await client.post("/v1/scope/check", json={"target": "example.com"})
    assert r2.json()["allow"] is False


async def test_scope_add_rejects_invalid_cidr(client):
    r = await client.post(
        "/v1/scope",
        json={"kind": "ipv4_cidr", "value": "not-a-cidr", "added_by": "t"},
    )
    assert r.status_code == 422


async def test_empty_target_fails_closed_and_audits(client, db_pool):
    # Pydantic blocks an empty string at the layer above, so test the
    # internal function directly with a whitespace-only target.
    decision = await scope_svc.check(db_pool, target="   ", worker="unit")
    assert decision.allow is False
    assert decision.reason == "empty_target"
    async with db_pool.acquire() as con:
        n = await con.fetchval("SELECT COUNT(*) FROM scope_decisions")
    assert n == 1
