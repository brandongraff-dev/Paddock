from __future__ import annotations

import httpx
import pytest

from app.modules import exposed_file


pytestmark = pytest.mark.asyncio


async def test_detects_git_head(fake_orch, scope, politeness, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.git/HEAD":
            return httpx.Response(200, text="ref: refs/heads/main\n",
                                  headers={"content-type": "text/plain"})
        return httpx.Response(404)

    _patch_scope_client(monkeypatch, scope, handler)
    result = await exposed_file.scan(
        "https://example.com/", scope=scope, politeness=politeness, orchestrator=fake_orch,
    )
    rules = {f["rule_id"] for f in result["findings"]}
    assert "exposed-git-head" in rules


async def test_ignores_spa_catchall(fake_orch, scope, politeness, monkeypatch):
    """A SPA that returns 200+HTML for every path must NOT yield .env hits."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<!doctype html><html></html>",
                              headers={"content-type": "text/html"})

    _patch_scope_client(monkeypatch, scope, handler)
    result = await exposed_file.scan(
        "https://example.com/", scope=scope, politeness=politeness, orchestrator=fake_orch,
    )
    rules = {f["rule_id"] for f in result["findings"]}
    assert "exposed-env" not in rules
    assert "exposed-git-head" not in rules
    # robots and sitemap with text/html are also rejected by their patterns.


async def test_outbound_log_written(fake_orch, scope, politeness, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    _patch_scope_client(monkeypatch, scope, handler)
    await exposed_file.scan(
        "https://example.com/", scope=scope, politeness=politeness, orchestrator=fake_orch,
    )
    # Twelve sensitive paths probed = twelve audit rows.
    assert len(fake_orch.outbound_calls) == len(exposed_file.PATHS)


def _patch_scope_client(monkeypatch, scope, handler):
    """Replace ScopeGuard.build_client so it uses a MockTransport."""
    real_build = scope.build_client

    def build(**kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_build(**kwargs)

    monkeypatch.setattr(scope, "build_client", build)
