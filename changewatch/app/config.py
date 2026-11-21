"""Runtime configuration, pulled from environment.

Mirrors ``intel/app/config.py`` — a frozen dataclass whose fields default so
the service boots with no extra env, and a DSN normaliser that accepts the
SQLAlchemy ``postgresql+asyncpg://`` form and hands asyncpg a plain DSN.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


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


def _env_bool(name: str, default: bool = False) -> bool:
    raw = _env(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _normalize_dsn(dsn: str) -> str:
    """Strip the SQLAlchemy driver tag so asyncpg accepts the DSN directly."""
    if dsn.startswith("postgresql+asyncpg://"):
        return "postgresql://" + dsn[len("postgresql+asyncpg://"):]
    if dsn.startswith("postgres+asyncpg://"):
        return "postgres://" + dsn[len("postgres+asyncpg://"):]
    return dsn


@dataclass(frozen=True)
class Config:
    # Connection strings
    database_url: str = field(default_factory=lambda: _normalize_dsn(
        _env("DATABASE_URL", "postgresql://asm:asm_dev@postgres:5432/asm") or ""
    ))
    redis_url: str = field(
        default_factory=lambda: _env("REDIS_URL", "redis://redis:6379/0") or ""
    )

    # Scheduling / serving
    interval_min: int = field(
        default_factory=lambda: _env_int("CHANGEWATCH_INTERVAL_MIN", 10)
    )
    http_port: int = field(
        default_factory=lambda: _env_int("CHANGEWATCH_HTTP_PORT", 8092)
    )

    # Detection thresholds
    stale_days: int = field(
        default_factory=lambda: _env_int("CHANGEWATCH_STALE_DAYS", 7)
    )
    cert_expiry_days: int = field(
        default_factory=lambda: _env_int("CHANGEWATCH_CERT_EXPIRY_DAYS", 30)
    )
    # Guard window for cursor-based change types so overlapping periodic +
    # event-driven passes don't double-insert the same change.
    dedupe_window_hours: int = field(
        default_factory=lambda: _env_int("CHANGEWATCH_DEDUPE_WINDOW_HOURS", 24)
    )

    # Alert delivery (the ONLY outbound traffic this service makes).
    webhook_timeout_s: int = field(
        default_factory=lambda: _env_int("CHANGEWATCH_WEBHOOK_TIMEOUT_S", 5)
    )
    user_agent: str = field(default_factory=lambda: _env(
        "CHANGEWATCH_USER_AGENT", "palantir-asm-changewatch/1.0"
    ) or "palantir-asm-changewatch/1.0")

    # Event stream
    events_stream: str = field(
        default_factory=lambda: _env("EVENTS_STREAM", "stream:events") or "stream:events"
    )
    consumer_group: str = field(
        default_factory=lambda: _env("CONSUMER_GROUP", "changewatch") or "changewatch"
    )
    consumer_name: str = field(default_factory=lambda: _env(
        "CONSUMER_NAME", f"changewatch-{os.getpid()}"
    ) or f"changewatch-{os.getpid()}")

    # Behaviour
    log_level: str = field(
        default_factory=lambda: (_env("LOG_LEVEL", "INFO") or "INFO").upper()
    )

    # The cursor row this service owns in intel_cursors.
    cursor_source: str = "changewatch"


def load() -> Config:
    """Build a Config from the current environment."""
    return Config()
