"""LLM wrapper gating + helpers (no network; SDK not installed)."""
from __future__ import annotations

from app import llm as llm_module
from app.config import Config
from app.llm import LLM, _strip_sql, _extract_json


def _cfg(**kw) -> Config:
    return Config(**kw)


def test_disabled_without_key(monkeypatch):
    monkeypatch.setattr(llm_module, "_anthropic_available", lambda: True)
    assert LLM(_cfg(anthropic_api_key=None)).is_enabled() is False


def test_disabled_without_sdk(monkeypatch):
    # Key present but SDK not importable -> still disabled.
    monkeypatch.setattr(llm_module, "_anthropic_available", lambda: False)
    assert LLM(_cfg(anthropic_api_key="sk-test")).is_enabled() is False


def test_enabled_with_key_and_sdk(monkeypatch):
    monkeypatch.setattr(llm_module, "_anthropic_available", lambda: True)
    assert LLM(_cfg(anthropic_api_key="sk-test")).is_enabled() is True


def test_strip_sql_removes_fences_and_semicolon():
    assert _strip_sql("```sql\nSELECT 1 FROM ask_assets;\n```") == "SELECT 1 FROM ask_assets"
    assert _strip_sql("SELECT 1 FROM ask_assets") == "SELECT 1 FROM ask_assets"
    assert _strip_sql("") is None


def test_extract_json_handles_prose_and_fences():
    assert _extract_json('here you go: [{"label":"x"}]') == [{"label": "x"}]
    assert _extract_json('```json\n[{"a":1}]\n```') == [{"a": 1}]


# --- the key saved in the dashboard (fetched from the orchestrator) ----------

import asyncio

import pytest


def _svc_cfg(**kw) -> Config:
    return Config(orchestrator_url="http://orchestrator:8080", service_api_key="svc", **kw)


def test_saved_key_enables_ai_and_wins_over_the_environment(monkeypatch):
    monkeypatch.setattr(llm_module, "_anthropic_available", lambda: True)

    async def fetch(url, key, timeout_s=3.0):
        assert url == "http://orchestrator:8080" and key == "svc"
        return "sk-ant-saved"

    monkeypatch.setattr(llm_module, "_fetch_stored_key", fetch)
    llm = LLM(_svc_cfg(anthropic_api_key=None))
    assert llm.is_enabled() is False
    asyncio.run(llm.refresh_key())
    assert llm.is_enabled() is True and llm._api_key() == "sk-ant-saved"
    env_too = LLM(_svc_cfg(anthropic_api_key="sk-env"))
    asyncio.run(env_too.refresh_key())
    assert env_too._api_key() == "sk-ant-saved"


def test_removing_the_saved_key_falls_back_to_the_environment_then_to_nothing(monkeypatch):
    monkeypatch.setattr(llm_module, "_anthropic_available", lambda: True)
    answers = ["sk-ant-saved", None]

    async def fetch(*_a, **_k):
        return answers.pop(0)

    monkeypatch.setattr(llm_module, "_fetch_stored_key", fetch)
    llm = LLM(_svc_cfg(anthropic_api_key="sk-env"))
    asyncio.run(llm.refresh_key(force=True))
    assert llm._api_key() == "sk-ant-saved"
    asyncio.run(llm.refresh_key(force=True))
    assert llm._api_key() == "sk-env"
    only_saved = LLM(_svc_cfg(anthropic_api_key=None))
    only_saved._stored_key = "sk-ant-saved"
    answers.append(None)
    asyncio.run(only_saved.refresh_key(force=True))
    assert only_saved.is_enabled() is False


def test_a_failed_fetch_keeps_the_key_and_backs_off(monkeypatch):
    calls = []

    async def fetch(*_a, **_k):
        calls.append(1)
        if len(calls) == 1:
            return "sk-ant-saved"
        raise RuntimeError("orchestrator answered 503")

    monkeypatch.setattr(llm_module, "_fetch_stored_key", fetch)
    llm = LLM(_svc_cfg())
    asyncio.run(llm.refresh_key(force=True))
    asyncio.run(llm.refresh_key(force=True))              # fails: key kept
    assert llm._api_key() == "sk-ant-saved"
    asyncio.run(llm.refresh_key())                        # inside the back-off window: no new call
    assert len(calls) == 2


def test_fetches_are_cached_for_the_ttl(monkeypatch):
    calls = []

    async def fetch(*_a, **_k):
        calls.append(1)
        return None

    monkeypatch.setattr(llm_module, "_fetch_stored_key", fetch)
    llm = LLM(_svc_cfg(ai_key_ttl_s=60))
    for _ in range(5):
        asyncio.run(llm.refresh_key())
    assert len(calls) == 1


def test_no_orchestrator_settings_means_no_calls(monkeypatch):
    async def fetch(*_a, **_k):
        raise AssertionError("must not be called")

    monkeypatch.setattr(llm_module, "_fetch_stored_key", fetch)
    asyncio.run(LLM(Config(anthropic_api_key=None)).refresh_key())
    asyncio.run(LLM(Config(orchestrator_url="http://o:1", service_api_key=None)).refresh_key())


def test_fetch_sends_only_the_service_key_and_never_returns_junk(monkeypatch):
    import aiohttp
    from aiohttp import web

    seen = {}

    async def handler(req):
        seen["key"] = req.headers.get("X-API-Key")
        seen["path"] = req.path
        return web.json_response({"api_key": req.app["reply"]})

    async def run(reply, status=200):
        app = web.Application()
        app["reply"] = reply
        async def refuse(_req):
            return web.json_response({}, status=status)

        app.router.add_get("/v1/system/ai/credential", handler if status == 200 else refuse)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        try:
            return await llm_module._fetch_stored_key(f"http://127.0.0.1:{port}", "svc-key")
        finally:
            await runner.cleanup()

    assert asyncio.run(run("sk-ant-x")) == "sk-ant-x"
    assert seen == {"key": "svc-key", "path": "/v1/system/ai/credential"}
    assert asyncio.run(run(None)) is None and asyncio.run(run("")) is None and asyncio.run(run(123)) is None
    with pytest.raises(RuntimeError):
        asyncio.run(run(None, status=403))


def test_the_key_never_appears_in_logs(monkeypatch, caplog):
    import logging

    async def fetch(*_a, **_k):
        raise RuntimeError("boom sk-ant-secret-should-not-be-logged")

    monkeypatch.setattr(llm_module, "_fetch_stored_key", fetch)
    with caplog.at_level(logging.DEBUG):
        asyncio.run(LLM(_svc_cfg()).refresh_key(force=True))
    assert "sk-ant" not in caplog.text and "RuntimeError" in caplog.text
