"""Runtime configuration, pulled from environment.

Mirrors ``changewatch/app/config.py`` — a frozen dataclass whose fields default
so the service boots with no extra env, and a DSN normaliser that accepts the
SQLAlchemy ``postgresql+asyncpg://`` form and hands asyncpg a plain DSN.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
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
        default_factory=lambda: _env_int("TRIAGE_INTERVAL_MIN", 10)
    )
    http_port: int = field(
        default_factory=lambda: _env_int("TRIAGE_HTTP_PORT", 8093)
    )

    # Triage thresholds / routing
    min_severity: str = field(
        default_factory=lambda: (_env("TRIAGE_MIN_SEVERITY", "medium") or "medium").lower()
    )

    # External ticket delivery (the ONLY outbound traffic this service makes).
    # Optional service-level fallback target used when a non-internal owner rule
    # has no http(s) contact of its own.
    webhook_url: Optional[str] = field(
        default_factory=lambda: _env("TRIAGE_WEBHOOK_URL", None)
    )
    webhook_timeout_s: int = field(
        default_factory=lambda: _env_int("TRIAGE_WEBHOOK_TIMEOUT_S", 5)
    )
    user_agent: str = field(default_factory=lambda: _env(
        "TRIAGE_USER_AGENT", "paddock-triage/1.0"
    ) or "paddock-triage/1.0")

    # Event stream
    events_stream: str = field(
        default_factory=lambda: _env("EVENTS_STREAM", "stream:events") or "stream:events"
    )
    consumer_group: str = field(
        default_factory=lambda: _env("CONSUMER_GROUP", "triage") or "triage"
    )
    consumer_name: str = field(default_factory=lambda: _env(
        "CONSUMER_NAME", f"triage-{os.getpid()}"
    ) or f"triage-{os.getpid()}")

    # Behaviour
    log_level: str = field(
        default_factory=lambda: (_env("LOG_LEVEL", "INFO") or "INFO").upper()
    )


def load() -> Config:
    """Build a Config from the current environment."""
    return Config()
