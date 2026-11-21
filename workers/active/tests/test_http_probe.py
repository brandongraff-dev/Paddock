from __future__ import annotations

import httpx
import pytest

from app.modules import http_probe
from app.scope_guard import ScopeDenied


pytestmark = pytest.mark.asyncio


async def test_http_probe_happy_path(fake_orch, scope, politeness, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text="<html><title>Home</title></html>",
            headers={"content-type": "text/html", "server": "nginx/1.25.3"},
        )
    _patch(monkeypatch, scope, handler)

    result = await http_probe.probe(
        "https://example.com/", scope=scope, politeness=politeness,
        orchestrator=fake_orch,
    )
    kinds = [a["kind"] for a in result["assets"]]
    assert "endpoint" in kinds
    assert "technology" in kinds
    # nginx technology got attached:
    assert any(a["canonical"].startswith("nginx@") for a in result["assets"] if a["kind"] == "technology")
    # outbound_log was written at least once (GET).
    assert any(r["tool"] == "http_probe" and r["method"] == "GET" for r in fake_orch.outbound_calls)


async def test_http_probe_refuses_out_of_scope(fake_orch, scope, politeness):
    fake_orch.set_decision("https://offscope.example.net/", {
        "allow": False, "normalized": "offscope.example.net",
        "matched_entry": None, "reason": "nope",
    })
    with pytest.raises(ScopeDenied):
        await http_probe.probe(
            "https://offscope.example.net/", scope=scope, politeness=politeness,
            orchestrator=fake_orch,
        )


def _patch(monkeypatch, scope, handler):
    real_build = scope.build_client

    def build(**kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_build(**kwargs)

    monkeypatch.setattr(scope, "build_client", build)
