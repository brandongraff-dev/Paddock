"""Runtime configuration, pulled from the environment.

Mirrors the intel/correlation config shape. The ANTHROPIC_API_KEY is read
from the environment ONLY and is never logged or echoed anywhere.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

# A current claude-* default. Override with ANTHROPIC_MODEL.
DEFAULT_MODEL = "claude-opus-5-5"


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value


def _env_int(name: str, default: int) -> int:
    raw = _env(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _normalize_dsn(dsn: str) -> str:
    """Strip the SQLAlchemy driver tag so asyncpg accepts the DSN directly."""
    if dsn.startswith("postgresql+asyncpg://"):
        return "postgresql://" + dsn[len("postgresql+asyncpg://"):]
    if dsn.startswith("postgres+asyncpg://"):
        return "postgres://" + dsn[len("postgres+asyncpg://"):]
    return dsn


@dataclass(frozen=True)
class Config:
    database_url: str = field(default_factory=lambda: _normalize_dsn(
        _env("DATABASE_URL", "postgresql://asm:asm_dev@postgres:5432/asm") or ""
    ))

    # LLM — all OPTIONAL. The key is read from env only, never logged.
    anthropic_api_key: str | None = field(
        default_factory=lambda: _env("ANTHROPIC_API_KEY")
    )
    anthropic_model: str = field(
        default_factory=lambda: _env("ANTHROPIC_MODEL", DEFAULT_MODEL) or DEFAULT_MODEL
    )
    llm_timeout_s: int = field(default_factory=lambda: _env_int("LLM_TIMEOUT_S", 20))
    llm_max_tokens: int = field(default_factory=lambda: _env_int("LLM_MAX_TOKENS", 1024))

    # NL-query safety knobs.
    max_rows: int = field(default_factory=lambda: _env_int("MAX_ROWS", 500))
    stmt_timeout_ms: int = field(default_factory=lambda: _env_int("STMT_TIMEOUT_MS", 4000))

    # Scheduling / server.
    triage_interval_min: int = field(
        default_factory=lambda: _env_int("TRIAGE_INTERVAL_MIN", 30)
    )
    http_port: int = field(default_factory=lambda: _env_int("BRAIN_HTTP_PORT", 8095))

    log_level: str = field(
        default_factory=lambda: (_env("LOG_LEVEL", "INFO") or "INFO").upper()
    )


def load() -> Config:
    return Config()
