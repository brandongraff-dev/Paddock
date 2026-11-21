"""Tests for the DNS enum module.

We can't rely on real DNS in CI. We mock `_resolve_one` + `_run_subfinder`
to feed canned results into `run()` and verify asset + edge shapes.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from app.modules import dns_enum
from app.modules.dns_enum import DEFAULT_WORDLIST


def test_wordlist_is_reasonable_size() -> None:
    # Spec: "a small hardcoded wordlist (100 common subdomains)"
    assert 50 <= len(DEFAULT_WORDLIST) <= 100
    assert "www" in DEFAULT_WORDLIST
    assert "api" in DEFAULT_WORDLIST
    assert all(isinstance(w, str) and "." not in w for w in DEFAULT_WORDLIST)


async def test_dns_enum_with_subfinder_results(ctx) -> None:
    hosts = ["api.example.com", "www.example.com"]

    async def fake_subfinder(domain, timeout_s=90.0):
        return hosts

    async def fake_resolve_one(name, limiter):
        return (name, ["203.0.113.1"], [])

    with patch.object(dns_enum, "_run_subfinder", side_effect=fake_subfinder), \
         patch.object(dns_enum, "_resolve_one", side_effect=fake_resolve_one):
        r = await dns_enum.run("example.com", ctx)

    kinds = [a["kind"] for a in r.assets]
    assert kinds.count("subdomain") == 2
    assert kinds.count("ipv4") == 1  # deduped
    assert "domain" in kinds

    edges_kinds = {e["kind"] for e in r.edges}
    assert "contains" in edges_kinds
    assert "resolves_to" in edges_kinds


async def test_dns_enum_falls_back_to_wordlist(ctx) -> None:
    async def fake_subfinder(domain, timeout_s=90.0):
        return []   # subfinder missing

    async def fake_resolve_one(name, limiter):
        # Only 'www.example.com' answers
        if name == "www.example.com":
            return (name, ["203.0.113.1"], [])
        return (name, [], [])

    with patch.object(dns_enum, "_run_subfinder", side_effect=fake_subfinder), \
         patch.object(dns_enum, "_resolve_one", side_effect=fake_resolve_one):
        r = await dns_enum.run("example.com", ctx)

    sub_values = {a["value"] for a in r.assets if a["kind"] == "subdomain"}
    assert sub_values == {"www.example.com"}
    assert any(a["kind"] == "ipv4" and a["value"] == "203.0.113.1" for a in r.assets)


async def test_dns_enum_handles_ipv6(ctx) -> None:
    async def fake_subfinder(d, timeout_s=90.0):
        return ["v6.example.com"]

    async def fake_resolve_one(name, limiter):
        return (name, [], ["2001:db8::1"])

    with patch.object(dns_enum, "_run_subfinder", side_effect=fake_subfinder), \
         patch.object(dns_enum, "_resolve_one", side_effect=fake_resolve_one):
        r = await dns_enum.run("example.com", ctx)

    assert any(a["kind"] == "ipv6" and a["value"] == "2001:db8::1" for a in r.assets)
    assert any(e["kind"] == "resolves_to" and e["dst_kind"] == "ipv6" for e in r.edges)
