"""Runtime configuration, pulled from environment (mirrors sca/config.py)."""
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
    orchestrator_url: str = field(default_factory=lambda: _env(
        "ORCHESTRATOR_URL", "http://orchestrator:8080"
    ) or "")

    # Toggles
    enable_semgrep: bool = field(default_factory=lambda: _env_bool("ENABLE_SEMGREP", True))
    enable_scheduler: bool = field(default_factory=lambda: _env_bool("ENABLE_SCHEDULER", False))

    # Networking
    http_port: int = field(default_factory=lambda: _env_int("CODEANALYSIS_HTTP_PORT", 8097))
    http_timeout_s: int = field(default_factory=lambda: _env_int("HTTP_TIMEOUT_S", 60))
    user_agent: str = field(default_factory=lambda: _env(
        "CODEANALYSIS_USER_AGENT", "paddock-codeanalysis/0.1 (+defensive-asm)"
    ) or "paddock-codeanalysis/0.1")

    # Semgrep
    semgrep_bin: str = field(default_factory=lambda: _env("SEMGREP_BIN", "semgrep") or "semgrep")
    semgrep_config: str = field(default_factory=lambda: _env("SEMGREP_CONFIG", "auto") or "auto")
    semgrep_timeout_s: int = field(default_factory=lambda: _env_int("SEMGREP_TIMEOUT_S", 300))

    # Scheduling
    scan_interval_min: int = field(default_factory=lambda: _env_int("CODEANALYSIS_INTERVAL_MIN", 360))

    # Behaviour
    log_level: str = field(default_factory=lambda: (_env("LOG_LEVEL", "INFO") or "INFO").upper())


def load() -> Config:
    """Build a Config from current environment."""
    return Config()
