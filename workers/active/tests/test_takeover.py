"""Subdomain-takeover detection tests. No network: DNS + HTTP are mocked."""
from __future__ import annotations

import httpx
import pytest

from app.modules import takeover_check
from app.scope_guard import ScopeDenied


def _patch_scope_client(monkeypatch, scope, handler):
    """Replace ScopeGuard.build_client so it uses a MockTransport."""
    real_build = scope.build_client

    def build(**kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_build(**kwargs)

    monkeypatch.setattr(scope, "build_client", build)


def _patch_cname(monkeypatch, chain):
    async def fake_chain(host):
        return list(chain)

    monkeypatch.setattr(takeover_check, "_resolve_cname_chain", fake_chain)


# ---- CNAME -> service matching ---------------------------------------------


def test_match_service_by_suffix():
    fps = takeover_check._load_fingerprints()
    assert takeover_check._match_service("myapp.github.io", fps) == "GitHub Pages"
    assert takeover_check._match_service("bucket.s3.amazonaws.com", fps) == "AWS/S3"
    assert takeover_check._match_service("foo.herokudns.com", fps) == "Heroku"
    # A legitimate, non-third-party target matches nothing.
    assert takeover_check._match_service("origin.internal.example.com", fps) is None


# ---- unclaimed fingerprint match vs no-match -------------------------------


async def test_unclaimed_fingerprint_match(fake_orch, scope, politeness, monkeypatch):
    _patch_cname(monkeypatch, ["deleted-site.github.io"])

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="There isn't a GitHub Pages site here.")

    _patch_scope_client(monkeypatch, scope, handler)
    result = await takeover_check.check(
        "blog.example.com", scope=scope, politeness=politeness, orchestrator=fake_orch,
    )
    findings = result["findings"]
    assert len(findings) == 1
    f = findings[0]
    assert f["rule_source"] == "takeover"
    assert f["severity"] == "high"
    assert "GitHub Pages" in f["title"]
    assert f["evidence"]["service"] == "GitHub Pages"
    assert f["evidence"]["cname_target"] == "deleted-site.github.io"
    assert f["evidence"]["cname_chain"] == ["deleted-site.github.io"]
    assert result["summary"]["takeover"] is True


async def test_claimed_site_no_match(fake_orch, scope, politeness, monkeypatch):
    """CNAME points at GitHub Pages but the site is live -> no finding."""
    _patch_cname(monkeypatch, ["live-site.github.io"])

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html><body>Welcome to my blog</body></html>")

    _patch_scope_client(monkeypatch, scope, handler)
    result = await takeover_check.check(
        "blog.example.com", scope=scope, politeness=politeness, orchestrator=fake_orch,
    )
    assert result["findings"] == []
    assert result["summary"]["matched_service"] == "GitHub Pages"
    assert result["summary"]["takeover"] is False


async def test_cname_not_third_party_skips_http(fake_orch, scope, politeness, monkeypatch):
    """A CNAME to an unknown host does not even trigger the HTTP probe."""
    _patch_cname(monkeypatch, ["origin.internal.example.com"])

    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("HTTP probe must not run for a non-third-party CNAME")

    _patch_scope_client(monkeypatch, scope, handler)
    result = await takeover_check.check(
        "www.example.com", scope=scope, politeness=politeness, orchestrator=fake_orch,
    )
    assert result["findings"] == []
    assert result["summary"]["matched_service"] is None
    assert fake_orch.outbound_calls == []  # no HTTP emitted


async def test_no_cname_no_finding(fake_orch, scope, politeness, monkeypatch):
    _patch_cname(monkeypatch, [])
    result = await takeover_check.check(
        "apex.example.com", scope=scope, politeness=politeness, orchestrator=fake_orch,
    )
    assert result["findings"] == []
    assert result["summary"]["cname_chain"] == []


# ---- out-of-scope drop ------------------------------------------------------


async def test_out_of_scope_dropped(fake_orch, scope, politeness, monkeypatch):
    """An out-of-scope subdomain raises ScopeDenied before any DNS lookup."""
    fake_orch.set_decision("evil.example.com", {"allow": False, "reason": "not-in-scope"})

    called = {"dns": False}

    async def fake_chain(host):  # pragma: no cover - must not be reached
        called["dns"] = True
        return ["x.github.io"]

    monkeypatch.setattr(takeover_check, "_resolve_cname_chain", fake_chain)

    with pytest.raises(ScopeDenied):
        await takeover_check.check(
            "evil.example.com", scope=scope, politeness=politeness, orchestrator=fake_orch,
        )
    assert called["dns"] is False


# ---- prod -> critical escalation -------------------------------------------


async def test_prod_metadata_escalates_to_critical(fake_orch, scope, politeness, monkeypatch):
    _patch_cname(monkeypatch, ["gone.herokuapp.com"])

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="No such app\nThere's nothing here.")

    _patch_scope_client(monkeypatch, scope, handler)
    result = await takeover_check.check(
        "api.example.com", scope=scope, politeness=politeness, orchestrator=fake_orch,
        asset_metadata={"env": "prod"},
    )
    assert len(result["findings"]) == 1
    assert result["findings"][0]["severity"] == "critical"
    assert result["findings"][0]["evidence"]["service"] == "Heroku"


async def test_sensitive_flag_escalates_to_critical(fake_orch, scope, politeness, monkeypatch):
    _patch_cname(monkeypatch, ["gone.herokuapp.com"])

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="No such app")

    _patch_scope_client(monkeypatch, scope, handler)
    result = await takeover_check.check(
        "data.example.com", scope=scope, politeness=politeness, orchestrator=fake_orch,
        asset_metadata={"sensitive": True},
    )
    assert result["findings"][0]["severity"] == "critical"


async def test_non_prod_stays_high(fake_orch, scope, politeness, monkeypatch):
    _patch_cname(monkeypatch, ["gone.herokuapp.com"])

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="No such app")

    _patch_scope_client(monkeypatch, scope, handler)
    result = await takeover_check.check(
        "staging.example.com", scope=scope, politeness=politeness, orchestrator=fake_orch,
        asset_metadata={"env": "staging"},
    )
    assert result["findings"][0]["severity"] == "high"


def test_fingerprint_file_ships_and_is_well_formed():
    # The file once went missing (a stray gitignore rule) and every takeover
    # check crashed. Guard the data contract.
    fps = takeover_check._load_fingerprints()
    assert len(fps) >= 15
    for name, spec in fps.items():
        assert spec["cname_suffixes"], name
        assert spec.get("fingerprint_text") or spec.get("http_status") is not None, name
