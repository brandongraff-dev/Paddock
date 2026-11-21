"""Runtime configuration, pulled from environment (mirrors intel/app/config.py)."""
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

    # Scheduling
    poll_interval_min: int = field(default_factory=lambda: _env_int("TI_POLL_INTERVAL_MIN", 60))
    http_port: int = field(default_factory=lambda: _env_int("TI_HTTP_PORT", 8100))
    enable_scheduler: bool = field(default_factory=lambda: _env_bool("TI_ENABLE_SCHEDULER", True))

    # Networking. The TAXII/STIX poll timeout is intentionally short (10s):
    # a slow user feed must never stall the service.
    poll_timeout_s: int = field(default_factory=lambda: _env_int("TI_POLL_TIMEOUT_S", 10))
    http_timeout_s: int = field(default_factory=lambda: _env_int("HTTP_TIMEOUT_S", 30))
    max_poll_pages: int = field(default_factory=lambda: _env_int("TI_MAX_POLL_PAGES", 20))
    user_agent: str = field(default_factory=lambda: _env(
        "TI_USER_AGENT", "paddock-threatintel/0.1 (+defensive-asm)"
    ) or "paddock-threatintel/0.1")

    # Behaviour
    log_level: str = field(default_factory=lambda: (_env("LOG_LEVEL", "INFO") or "INFO").upper())
    # Cap how many assets/findings a single match pass pulls into memory.
    match_scan_limit: int = field(default_factory=lambda: _env_int("TI_MATCH_SCAN_LIMIT", 50000))


def load() -> Config:
    """Build a Config from current environment."""
    return Config()
