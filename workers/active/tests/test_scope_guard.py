"""Scope guard: the rule nobody breaks."""
from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from app.scope_guard import ScopeDenied, ScopeGuard, normalize_target


pytestmark = pytest.mark.asyncio


async def test_allow_in_scope_target(fake_orch, scope):
    dec = await scope.allow("https://example.com/foo")
    assert dec.allow is True
    assert fake_orch.scope_calls == ["https://example.com/foo"]


async def test_deny_out_of_scope_target(fake_orch, scope):
    fake_orch.set_decision("https://evil.example.net/", {
        "allow": False, "normalized": "evil.example.net",
        "matched_entry": None, "reason": "no matching scope",
    })
    with pytest.raises(ScopeDenied) as ei:
        await scope.allow("https://evil.example.net/")
    assert "no matching scope" in str(ei.value)


async def test_cache_hit_avoids_second_call(fake_orch, scope):
    await scope.allow("https://example.com/a")
    await scope.allow("https://example.com/b")  # same host → same cache key
    # normalize_target drops path, so one call to orch is enough.
    assert len(fake_orch.scope_calls) == 1


async def test_subprocess_launch_blocked_out_of_scope(fake_orch, scope):
    fake_orch.set_decision("1.2.3.4", {"allow": False, "normalized": "1.2.3.4",
                                        "matched_entry": None, "reason": "not in scope"})
    with pytest.raises(ScopeDenied):
        await scope.allow("1.2.3.4")


async def test_redirect_to_out_of_scope_is_blocked(fake_orch, scope):
    """The httpx event hook must re-check on every request including redirects."""
    fake_orch.set_decision("https://offscope.example.org/", {
        "allow": False, "normalized": "offscope.example.org",
        "matched_entry": None, "reason": "not in scope",
    })
    client = scope.build_client(transport=httpx.MockTransport(_make_redirect_transport()))

    with pytest.raises(ScopeDenied):
        await client.get("https://example.com/follow")
    await client.aclose()


def _make_redirect_transport():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "example.com":
            return httpx.Response(302, headers={"Location": "https://offscope.example.org/"})
        return httpx.Response(200, text="should not be reached")
    return handler


async def test_normalize_target_strips_scheme_and_default_port():
    assert normalize_target("https://Example.com:443/foo") == "example.com"
    assert normalize_target("http://example.com:8080/x") == "example.com:8080"
    assert normalize_target("example.com") == "example.com"
    assert normalize_target("1.2.3.4:443") == "1.2.3.4:443"


async def test_fail_closed_on_orch_error(fake_orch, scope, monkeypatch):
    async def boom(_target):
        raise RuntimeError("orchestrator unreachable")
    monkeypatch.setattr(fake_orch, "scope_check", boom)
    with pytest.raises(ScopeDenied):
        await scope.allow("https://example.com/")
