from __future__ import annotations

import json

import httpx
import pytest

from app.modules import crawler
from tests.conftest import FakeProcess


pytestmark = pytest.mark.asyncio


async def test_crawler_drops_out_of_scope_links(fake_orch, scope, politeness, fake_subprocess, monkeypatch):
    fake_orch.set_decision("https://offscope.example.net/a.html", {
        "allow": False, "normalized": "offscope.example.net",
        "matched_entry": None, "reason": "no scope",
    })
    rows = [
        json.dumps({"endpoint": "https://example.com/a"}),
        json.dumps({"endpoint": "https://offscope.example.net/a.html"}),
        json.dumps({"request": {"endpoint": "https://example.com/js/app.js"}}),
    ]
    out = ("\n".join(rows) + "\n").encode()
    fake_subprocess.register("katana", lambda args: FakeProcess(stdout_bytes=out))

    # Stub the robots fetch and JS fetch via MockTransport on build_client.
    def handler(request):
        if "app.js" in str(request.url):
            return httpx.Response(200, text="var AWS_KEY = 'AKIA1234567890ABCDEF';")
        return httpx.Response(404)

    real_build = scope.build_client
    def build(**kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_build(**kwargs)
    monkeypatch.setattr(scope, "build_client", build)

    r = await crawler.crawl(
        "https://example.com/", scope=scope, politeness=politeness,
        orchestrator=fake_orch, depth=2, respect_robots=False,
    )
    endpoints = [a["canonical"] for a in r["assets"] if a["kind"] == "endpoint"]
    assert any(e.startswith("example.com") for e in endpoints)
    assert not any("offscope.example.net" in e for e in endpoints)

    # Secret detection emitted a finding.
    rules = {f["rule_id"] for f in r["findings"]}
    assert "secret-aws-access-key-id" in rules


async def test_crawler_tool_missing_yields_finding(fake_orch, scope, politeness, fake_subprocess):
    r = await crawler.crawl(
        "https://example.com/", scope=scope, politeness=politeness,
        orchestrator=fake_orch, depth=1, respect_robots=False,
    )
    rules = {f["rule_id"] for f in r["findings"]}
    assert "tool-unavailable-katana" in rules
