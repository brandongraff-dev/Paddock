"""Config normalization + defaults, and that the service imports with no
anthropic SDK and no key present (graceful self-test)."""
from __future__ import annotations

from app.config import DEFAULT_MODEL, Config, _normalize_dsn, load


def test_normalize_dsn_strips_asyncpg_tag():
    assert _normalize_dsn("postgresql+asyncpg://u:p@h:5432/db") == "postgresql://u:p@h:5432/db"
    assert _normalize_dsn("postgres+asyncpg://u:p@h/db") == "postgres://u:p@h/db"
    assert _normalize_dsn("postgresql://u:p@h/db") == "postgresql://u:p@h/db"


def test_defaults(monkeypatch):
    for var in ("ANTHROPIC_API_KEY", "ANTHROPIC_MODEL", "MAX_ROWS", "STMT_TIMEOUT_MS"):
        monkeypatch.delenv(var, raising=False)
    cfg = load()
    assert cfg.anthropic_api_key is None
    assert cfg.anthropic_model == DEFAULT_MODEL
    assert cfg.anthropic_model.startswith("claude-")
    assert cfg.max_rows == 500
    assert cfg.stmt_timeout_ms == 4000
    assert cfg.http_port == 8095


def test_env_overrides(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_MODEL", "claude-sonnet-5-5")
    monkeypatch.setenv("MAX_ROWS", "100")
    cfg = load()
    assert cfg.anthropic_model == "claude-sonnet-5-5"
    assert cfg.max_rows == 100


def test_service_imports_without_sdk_or_key(monkeypatch):
    # Importing the service and constructing it must not require anthropic
    # or a key — the optional import is guarded.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    from app.main import BrainService
    svc = BrainService(Config(anthropic_api_key=None))
    assert svc.llm.is_enabled() is False
