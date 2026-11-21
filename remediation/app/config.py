"""Runtime configuration, pulled from the environment.

Mirrors the intel/brain config shape. The ANTHROPIC_API_KEY and GITHUB_TOKEN
are read from the environment ONLY and are NEVER logged or echoed anywhere.

Opening a real PR is OFF by default (``REMEDIATION_OPEN_PR=false``). With it off
the service produces the verified diff + reports WITHOUT pushing anywhere; a
human then opens the PR. Turning it on additionally requires a repo + a
``GITHUB_TOKEN`` and the ``egress`` network.
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
    database_url: str = field(default_factory=lambda: _normalize_dsn(
        _env("DATABASE_URL", "postgresql://asm:asm_dev@postgres:5432/asm") or ""
    ))
    orchestrator_url: str = field(default_factory=lambda: _env(
        "ORCHESTRATOR_URL", "http://orchestrator:8080"
    ) or "")

    # LLM — all OPTIONAL. The key is read from env only, never logged. The LLM
    # is used ONLY for a prose explanation + an adversarial second-opinion
    # verify; its absence must not weaken the gate. The LLM NEVER writes code.
    anthropic_api_key: str | None = field(
        default_factory=lambda: _env("ANTHROPIC_API_KEY")
    )
    anthropic_model: str = field(
        default_factory=lambda: _env("ANTHROPIC_MODEL", DEFAULT_MODEL) or DEFAULT_MODEL
    )
    llm_timeout_s: int = field(default_factory=lambda: _env_int("LLM_TIMEOUT_S", 20))
    llm_max_tokens: int = field(default_factory=lambda: _env_int("LLM_MAX_TOKENS", 1024))

    # PR opening — OFF by default. Even when verified, no branch is pushed and
    # no PR is opened unless this is explicitly turned on AND a token is set.
    open_pr: bool = field(default_factory=lambda: _env_bool("REMEDIATION_OPEN_PR", False))
    github_token: str | None = field(default_factory=lambda: _env("GITHUB_TOKEN"))
    github_repo: str | None = field(default_factory=lambda: _env("GITHUB_REPO"))
    base_branch: str = field(
        default_factory=lambda: _env("REMEDIATION_BASE_BRANCH", "main") or "main"
    )

    # Hard safety bounds for a generated diff (belt-and-suspenders with gate.py).
    max_diff_bytes: int = field(default_factory=lambda: _env_int("MAX_DIFF_BYTES", 8192))
    max_changed_lines: int = field(default_factory=lambda: _env_int("MAX_CHANGED_LINES", 40))
    max_files: int = field(default_factory=lambda: _env_int("MAX_DIFF_FILES", 2))

    http_port: int = field(default_factory=lambda: _env_int("REMEDIATION_HTTP_PORT", 8102))
    log_level: str = field(
        default_factory=lambda: (_env("LOG_LEVEL", "INFO") or "INFO").upper()
    )


def load() -> Config:
    return Config()
