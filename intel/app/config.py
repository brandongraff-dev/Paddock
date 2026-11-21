"""Runtime configuration, pulled from environment."""
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

    # Source toggles + creds
    nvd_api_key: str | None = field(default_factory=lambda: _env("NVD_API_KEY"))
    enable_nvd: bool = field(default_factory=lambda: _env_bool("ENABLE_NVD", True))
    enable_epss: bool = field(default_factory=lambda: _env_bool("ENABLE_EPSS", True))
    enable_kev: bool = field(default_factory=lambda: _env_bool("ENABLE_KEV", True))
    enable_osv: bool = field(default_factory=lambda: _env_bool("ENABLE_OSV", False))

    # Scheduling
    sync_interval_min: int = field(default_factory=lambda: _env_int("SYNC_INTERVAL_MIN", 60))
    linker_interval_min: int = field(default_factory=lambda: _env_int("LINKER_INTERVAL_MIN", 15))
    http_port: int = field(default_factory=lambda: _env_int("INTEL_HTTP_PORT", 8090))

    # Networking
    http_timeout_s: int = field(default_factory=lambda: _env_int("HTTP_TIMEOUT_S", 60))
    user_agent: str = field(default_factory=lambda: _env(
        "INTEL_USER_AGENT", "paddock-intel/0.1 (+defensive-asm)"
    ) or "paddock-intel/0.1")

    # Behaviour
    log_level: str = field(default_factory=lambda: (_env("LOG_LEVEL", "INFO") or "INFO").upper())
    finding_min_confidence: int = field(
        default_factory=lambda: _env_int("FINDING_MIN_CONFIDENCE", 60)
    )
    nvd_bootstrap_days: int = field(
        default_factory=lambda: _env_int("NVD_BOOTSTRAP_DAYS", 7)
    )
    # NVD hard-caps an incremental page at 120 days.
    nvd_window_days: int = field(default_factory=lambda: _env_int("NVD_WINDOW_DAYS", 110))


def load() -> Config:
    """Build a Config from current environment."""
    return Config()
