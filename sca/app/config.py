"""Runtime configuration, pulled from environment (mirrors intel/changewatch)."""
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
    redis_url: str = field(default_factory=lambda: _env("REDIS_URL", "redis://redis:6379/0") or "")
    orchestrator_url: str = field(default_factory=lambda: _env(
        "ORCHESTRATOR_URL", "http://orchestrator:8080"
    ) or "")

    # Toggles
    enable_osv: bool = field(default_factory=lambda: _env_bool("ENABLE_OSV", True))
    enable_registry: bool = field(default_factory=lambda: _env_bool("ENABLE_REGISTRY", True))
    enable_scheduler: bool = field(default_factory=lambda: _env_bool("ENABLE_SCHEDULER", False))

    # Scheduling
    scan_interval_min: int = field(default_factory=lambda: _env_int("SCA_INTERVAL_MIN", 360))
    http_port: int = field(default_factory=lambda: _env_int("SCA_HTTP_PORT", 8094))

    # Networking / OSV
    http_timeout_s: int = field(default_factory=lambda: _env_int("HTTP_TIMEOUT_S", 60))
    osv_batch_size: int = field(default_factory=lambda: _env_int("OSV_BATCH_SIZE", 1000))
    user_agent: str = field(default_factory=lambda: _env(
        "SCA_USER_AGENT", "palantir-asm-sca/0.1 (+defensive-asm)"
    ) or "palantir-asm-sca/0.1")

    # Risk tuning
    typosquat_distance: int = field(default_factory=lambda: _env_int("TYPOSQUAT_DISTANCE", 2))
    abandoned_days: int = field(default_factory=lambda: _env_int("ABANDONED_DAYS", 730))

    # Behaviour
    log_level: str = field(default_factory=lambda: (_env("LOG_LEVEL", "INFO") or "INFO").upper())


def load() -> Config:
    """Build a Config from current environment."""
    return Config()
