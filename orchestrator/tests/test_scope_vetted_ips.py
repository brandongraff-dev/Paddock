"""/v1/scope/check returns the addresses it vetted.

A worker must connect to exactly these (never re-resolve the name), which is
what closes the DNS-rebinding window between the check and the connect.
"""
from __future__ import annotations

import pytest

from app import scope as scope_svc

from .test_scope_adversarial import _dns, _FakePool, _reset_caches  # noqa: F401

pytestmark = pytest.mark.asyncio


async def test_allowed_hostname_returns_the_vetted_addresses(monkeypatch):
    _dns(monkeypatch, {"www.target.com": ["93.184.215.14", "2606:2800:220:1::1"]})
    pool = _FakePool([("subdomain_wildcard", "target.com")])
    d = await scope_svc.check(pool, "https://www.target.com:8443/x", worker="t")
    assert d.allow is True
    assert d.resolved_ips == ["2606:2800:220:1::1", "93.184.215.14"]
    assert d.as_dict()["resolved_ips"] == d.resolved_ips


async def test_ipv4_mapped_answers_are_returned_unmapped(monkeypatch):
    _dns(monkeypatch, {"m.target.com": ["::ffff:93.184.215.14"]})
    pool = _FakePool([("subdomain_wildcard", "target.com")])
    assert (await scope_svc.check(pool, "m.target.com", worker="t")).resolved_ips == ["93.184.215.14"]


async def test_denied_decisions_carry_no_addresses(monkeypatch):
    _dns(monkeypatch, {"rebind.target.com": ["169.254.169.254"], "x.other.com": ["93.184.215.14"]})
    pool = _FakePool([("subdomain_wildcard", "target.com")])
    for t in ("rebind.target.com", "x.other.com"):
        d = await scope_svc.check(pool, t, worker="t")
        assert d.allow is False and d.resolved_ips == []
        assert "resolved_ips" not in d.as_dict()


async def test_ip_literal_and_cidr_fallback_return_their_addresses(monkeypatch):
    _dns(monkeypatch, {"h.other.net": ["203.0.113.5"]})
    pool = _FakePool([("ipv4_cidr", "203.0.113.0/24")])
    assert (await scope_svc.check(pool, "203.0.113.9:8080", worker="t")).resolved_ips == ["203.0.113.9"]
    assert (await scope_svc.check(pool, "h.other.net", worker="t")).resolved_ips == ["203.0.113.5"]


async def test_unresolvable_allowed_name_has_empty_list(monkeypatch):
    _dns(monkeypatch, {})
    pool = _FakePool([("subdomain_wildcard", "target.com")])
    d = await scope_svc.check(pool, "nx.target.com", worker="t")
    assert d.allow is True and d.resolved_ips == []


async def test_scope_check_endpoint_exposes_resolved_ips(client, monkeypatch):
    async def fake_resolve(host):
        return {"api.example.com": ["93.184.215.14"]}.get(host, [])

    monkeypatch.setattr(scope_svc.dns_cache, "resolve", fake_resolve)
    r = await client.post("/v1/scope", json={"kind": "subdomain_wildcard", "value": "example.com",
                                             "added_by": "t"})
    assert r.status_code == 201, r.text
    body = (await client.post("/v1/scope/check", json={"target": "api.example.com"})).json()
    assert body["allow"] is True and body["resolved_ips"] == ["93.184.215.14"]
    denied = (await client.post("/v1/scope/check", json={"target": "evil.test"})).json()
    assert denied["allow"] is False and denied["resolved_ips"] == []
