"""Runtime configuration, pulled from environment.

Mirrors the intel service's config shape (same ``_normalize_dsn`` and env
helpers) so the two services behave identically w.r.t. DSN handling.
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
    """Strip SQLAlchemy driver tag so asyncpg accepts the DSN directly."""
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
    # The orchestrator reads the ontology straight from the shared DB, so this
    # URL is only kept for parity/health probes; the projector never calls it.
    orchestrator_url: str = field(default_factory=lambda: _env(
        "ORCHESTRATOR_URL", "http://orchestrator:8080"
    ) or "")

    # Scheduling
    interval_min: int = field(default_factory=lambda: _env_int("ONTOLOGY_INTERVAL_MIN", 15))
    http_port: int = field(default_factory=lambda: _env_int("ONTOLOGY_HTTP_PORT", 8099))

    # Behaviour
    log_level: str = field(default_factory=lambda: (_env("LOG_LEVEL", "INFO") or "INFO").upper())
    project_on_start: bool = field(default_factory=lambda: _env_bool("PROJECT_ON_START", True))


def load() -> Config:
    """Build a Config from current environment."""
    return Config()
