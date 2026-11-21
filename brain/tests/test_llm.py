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
