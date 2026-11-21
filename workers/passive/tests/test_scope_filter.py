"""Tests for the scope-filter gate.

The hard rule is: no asset leaves this worker without a positive scope_check
response from the orchestrator. If the orchestrator is unreachable, scope
fails closed and the asset is dropped.
"""
from __future__ import annotations

import pytest
from aioresponses import aioresponses

from app.orchestrator import OrchestratorClient, ScopeDecision


SCOPE_URL = "http://orchestrator.test/v1/scope/check"
ASSETS_URL = "http://orchestrator.test/v1/assets/bulk"
FINDINGS_URL = "http://orchestrator.test/v1/findings/bulk"


async def test_allowed_value_is_cached_and_returned(settings) -> None:
    async with OrchestratorClient(settings) as c:
        with aioresponses() as m:
            m.post(SCOPE_URL, payload={
                "allow": True, "normalized": "example.com",
                "matched_entry": 1, "reason": "domain match",
            })
            d1 = await c.scope_check("example.com")
            # Second call should hit the cache; aioresponses would raise if a
            # second HTTP call were made (no mock registered for a second hit).
            d2 = await c.scope_check("example.com")
        assert d1.allow is True
        assert d1.normalized == "example.com"
        assert d2.allow is True


async def test_denied_value_is_dropped(settings) -> None:
    async with OrchestratorClient(settings) as c:
        with aioresponses() as m:
            m.post(SCOPE_URL, payload={
                "allow": False, "normalized": "evil.net", "reason": "no match",
            })
            d = await c.scope_check("evil.net")
        assert d.allow is False


async def test_filter_in_scope_returns_only_allowed(settings) -> None:
    async with OrchestratorClient(settings) as c:
        with aioresponses() as m:
            # register two distinct responses by matching the request bodies
            # via the aioresponses callback.
            def router(url, **kwargs):
                body = kwargs.get("json") or {}
                v = body.get("target", "")
                if v == "example.com" or v.endswith(".example.com"):
                    return _mk_resp({"allow": True, "normalized": v, "reason": "ok"})
                return _mk_resp({"allow": False, "normalized": v, "reason": "nope"})
            from aioresponses import CallbackResult
            m.post(SCOPE_URL, callback=lambda url, **kw: CallbackResult(
                payload={
                    "allow": (kw.get("json", {}).get("target", "") == "example.com"
                              or kw.get("json", {}).get("target", "").endswith(".example.com")),
                    "normalized": kw.get("json", {}).get("target", ""),
                    "reason": "",
                }
            ), repeat=True)

            kept = await c.filter_in_scope(
                ["example.com", "api.example.com", "evil.net", "other.com"]
            )
        kept_set = set(kept)
        assert kept_set == {"example.com", "api.example.com"}
        assert c.dropped_out_of_scope == 2


def _mk_resp(payload):
    from aioresponses import CallbackResult
    return CallbackResult(payload=payload)


async def test_scope_fails_closed_on_server_error(settings) -> None:
    async with OrchestratorClient(settings) as c:
        with aioresponses() as m:
            m.post(SCOPE_URL, status=500)
            d = await c.scope_check("example.com")
        # fail-closed: deny
        assert d.allow is False
        assert "scope_check_error" in d.reason


async def test_post_assets_only_sends_allowed(settings) -> None:
    """The main loop filters allowed values into assets before bulk post.

    This test simulates that pipeline end-to-end.
    """
    from app.main import _push_result
    from app.context import ModuleContext
    from app.util.rate_limit import RateLimiter
    from app.modules import ModuleResult
    import aiohttp

    rl = RateLimiter()
    rl.register_sync("crtsh", 100)
    async with aiohttp.ClientSession() as http, OrchestratorClient(settings) as orc:
        ctx = ModuleContext(settings=settings, orchestrator=orc, rate_limiter=rl, http=http)

        result = ModuleResult(module="unit")
        result.assets = [
            {"kind": "subdomain", "value": "good.example.com", "source": "test", "metadata": {}},
            {"kind": "subdomain", "value": "other.com", "source": "test", "metadata": {}},
        ]
        result.edges = [
            {"src_kind": "subdomain", "src_value": "good.example.com",
             "dst_kind": "domain", "dst_value": "example.com", "kind": "contains"},
            {"src_kind": "subdomain", "src_value": "other.com",
             "dst_kind": "domain", "dst_value": "evil.net", "kind": "contains"},
        ]

        posted: list[list[dict]] = []
        from aioresponses import aioresponses as _ar, CallbackResult

        with _ar() as m:
            # Scope: good.example.com allowed; other.com denied.
            def scope_cb(url, **kw):
                v = (kw.get("json") or {}).get("target", "")
                allow = v == "good.example.com" or v == "example.com"
                return CallbackResult(payload={
                    "allow": allow, "normalized": v, "reason": "",
                })
            m.post(SCOPE_URL, callback=scope_cb, repeat=True)

            def assets_cb(url, **kw):
                body = kw.get("json") or {}
                posted.append(body.get("assets", []))
                return CallbackResult(payload={"accepted": len(body.get("assets", []))})
            m.post(ASSETS_URL, callback=assets_cb, repeat=True)

            counts = await _push_result(ctx, result)

    # Only `good.example.com` passes the scope gate.
    flat_values = [a["value"] for batch in posted for a in batch if a["kind"] != "_edge"]
    assert "good.example.com" in flat_values
    assert "other.com" not in flat_values
    assert counts["dropped_out_of_scope"] >= 1


async def test_scope_cache_ttl_zero_rechecks(settings) -> None:
    settings.scope_cache_ttl_s = 0  # disable caching
    async with OrchestratorClient(settings) as c:
        from aioresponses import CallbackResult
        hits = []
        with aioresponses() as m:
            def cb(url, **kw):
                hits.append(1)
                return CallbackResult(payload={
                    "allow": True, "normalized": "example.com", "reason": "",
                })
            m.post(SCOPE_URL, callback=cb, repeat=True)
            await c.scope_check("example.com")
            await c.scope_check("example.com")
        assert len(hits) == 2
