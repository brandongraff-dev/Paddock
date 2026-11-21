"""Runtime configuration, pulled from the environment.

Mirrors sca/intel/changewatch: a frozen dataclass built from ``os.environ``
with safe defaults so the service boots in dev without a .env.
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
    orchestrator_url: str = field(default_factory=lambda: _env(
        "ORCHESTRATOR_URL", "http://orchestrator:8080"
    ) or "")

    # HTTP server
    http_port: int = field(default_factory=lambda: _env_int("OTDISCOVERY_HTTP_PORT", 8101))

    # Toggles
    enable_cve_match: bool = field(default_factory=lambda: _env_bool("ENABLE_CVE_MATCH", True))
    enable_db: bool = field(default_factory=lambda: _env_bool("ENABLE_DB", True))

    # Segment classification: group observed host IPs into /N subnets.
    ipv4_segment_prefix: int = field(
        default_factory=lambda: _env_int("IPV4_SEGMENT_PREFIX", 24)
    )
    ipv6_segment_prefix: int = field(
        default_factory=lambda: _env_int("IPV6_SEGMENT_PREFIX", 64)
    )

    # Networking
    http_timeout_s: int = field(default_factory=lambda: _env_int("HTTP_TIMEOUT_S", 30))
    user_agent: str = field(default_factory=lambda: _env(
        "OTDISCOVERY_USER_AGENT", "palantir-asm-otdiscovery/0.1 (+defensive-asm; passive)"
    ) or "palantir-asm-otdiscovery/0.1")

    # Safety limit for an uploaded pcap / observation body.
    max_capture_bytes: int = field(
        default_factory=lambda: _env_int("MAX_CAPTURE_BYTES", 64 * 1024 * 1024)
    )

    # Behaviour
    log_level: str = field(default_factory=lambda: (_env("LOG_LEVEL", "INFO") or "INFO").upper())


def load() -> Config:
    return Config()
