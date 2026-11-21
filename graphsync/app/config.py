"""Runtime configuration, pulled from environment.

Mirrors the intel service's config shape, including `_normalize_dsn` so the
shared SQLAlchemy-style DATABASE_URL works with asyncpg directly.
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
    # Postgres (read-only source of truth)
    database_url: str = field(default_factory=lambda: _normalize_dsn(
        _env("DATABASE_URL", "postgresql://asm:asm_dev@postgres:5432/asm") or ""
    ))

    # Neo4j (mirror target)
    neo4j_uri: str = field(default_factory=lambda: _env("NEO4J_URI", "bolt://neo4j:7687") or "")
    neo4j_user: str = field(default_factory=lambda: _env("NEO4J_USER", "neo4j") or "")
    neo4j_password: str = field(default_factory=lambda: _env("NEO4J_PASSWORD", "neo4j") or "")
    neo4j_database: str = field(default_factory=lambda: _env("NEO4J_DATABASE", "neo4j") or "")

    # Scheduling
    sync_interval_min: int = field(default_factory=lambda: _env_int("SYNC_INTERVAL_MIN", 5))
    http_port: int = field(default_factory=lambda: _env_int("GRAPHSYNC_HTTP_PORT", 8096))

    # Degrade / retry behaviour
    neo4j_connect_timeout_s: int = field(
        default_factory=lambda: _env_int("NEO4J_CONNECT_TIMEOUT_S", 5)
    )
    neo4j_backoff_base_s: int = field(
        default_factory=lambda: _env_int("NEO4J_BACKOFF_BASE_S", 5)
    )
    neo4j_backoff_max_s: int = field(
        default_factory=lambda: _env_int("NEO4J_BACKOFF_MAX_S", 120)
    )

    # Query caps
    neighborhood_cap: int = field(default_factory=lambda: _env_int("NEIGHBORHOOD_CAP", 500))
    max_path_hops: int = field(default_factory=lambda: _env_int("MAX_PATH_HOPS", 8))

    # Behaviour
    log_level: str = field(default_factory=lambda: (_env("LOG_LEVEL", "INFO") or "INFO").upper())


def load() -> Config:
    """Build a Config from current environment."""
    return Config()
