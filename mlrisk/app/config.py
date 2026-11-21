"""Runtime configuration, pulled from environment.

Mirrors ``intel/app/config.py`` (same ``_normalize_dsn`` + env helpers) and
adds the mlrisk knobs: ``MIN_LABELS``, ``CONTAMINATION`` and the retrain
interval.
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


def _env_float(name: str, default: float) -> float:
    raw = _env(name)
    if raw is None:
        return default
    try:
        return float(raw)
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

    # Scheduling
    interval_min: int = field(default_factory=lambda: _env_int("MLRISK_INTERVAL_MIN", 30))
    http_port: int = field(default_factory=lambda: _env_int("MLRISK_HTTP_PORT", 8098))

    # Model behaviour
    # Below MIN_LABELS labeled samples the risk ranker uses the transparent
    # heuristic prior and reports cold_start=true.
    min_labels: int = field(default_factory=lambda: _env_int("MIN_LABELS", 12))
    # If the rarer class has fewer than this many samples we fall back from a
    # GradientBoostingClassifier to a LogisticRegression (more stable on tiny,
    # imbalanced label sets).
    min_per_class: int = field(default_factory=lambda: _env_int("MIN_PER_CLASS", 5))
    # IsolationForest contamination (expected outlier fraction).
    contamination: float = field(default_factory=lambda: _env_float("CONTAMINATION", 0.1))
    # How many signals to list in each score's rationale.
    top_k: int = field(default_factory=lambda: _env_int("RATIONALE_TOP_K", 4))
    # Change-velocity anomaly: recent window (hours) vs trailing baseline.
    velocity_window_h: int = field(default_factory=lambda: _env_int("VELOCITY_WINDOW_H", 24))
    velocity_baseline_days: int = field(default_factory=lambda: _env_int("VELOCITY_BASELINE_DAYS", 14))

    # Behaviour
    log_level: str = field(default_factory=lambda: (_env("LOG_LEVEL", "INFO") or "INFO").upper())


def load() -> Config:
    """Build a Config from current environment."""
    return Config()
