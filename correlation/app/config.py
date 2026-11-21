"""Environment-driven configuration."""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional


def _asyncpg_dsn(raw: str) -> str:
    """Normalize SQLAlchemy-style async DSN to plain asyncpg DSN."""
    if raw.startswith("postgresql+asyncpg://"):
        return "postgresql://" + raw[len("postgresql+asyncpg://") :]
    return raw


def _bool_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    database_url: str
    redis_url: str
    orchestrator_url: str
    policies_dir: str
    builtin_rules_dir: str
    http_port: int
    sweep_interval_min: int
    attackpath_interval_min: int
    attackpath_debounce_sec: int
    log_level: str
    consumer_group: str
    consumer_name: str
    events_stream: str
    env: str
    attack_map_enabled: bool
    fusion_enabled: bool

    @classmethod
    def load(cls) -> "Settings":
        return cls(
            database_url=_asyncpg_dsn(
                os.environ.get(
                    "DATABASE_URL",
                    "postgresql://asm:asm_dev@postgres:5432/asm",
                )
            ),
            redis_url=os.environ.get("REDIS_URL", "redis://redis:6379/0"),
            orchestrator_url=os.environ.get(
                "ORCHESTRATOR_URL", "http://orchestrator:8080"
            ),
            policies_dir=os.environ.get("POLICIES_DIR", "/policies"),
            builtin_rules_dir=os.environ.get(
                "BUILTIN_RULES_DIR",
                os.path.join(os.path.dirname(__file__), "rules"),
            ),
            http_port=int(os.environ.get("HTTP_PORT", "8091")),
            sweep_interval_min=int(os.environ.get("SWEEP_INTERVAL_MIN", "15")),
            attackpath_interval_min=int(
                os.environ.get("ATTACKPATH_INTERVAL_MIN", "20")
            ),
            attackpath_debounce_sec=int(
                os.environ.get("ATTACKPATH_DEBOUNCE_SEC", "30")
            ),
            log_level=os.environ.get("LOG_LEVEL", "INFO").upper(),
            consumer_group=os.environ.get("CONSUMER_GROUP", "correlation"),
            consumer_name=os.environ.get(
                "CONSUMER_NAME", f"correlation-{os.getpid()}"
            ),
            events_stream=os.environ.get("EVENTS_STREAM", "stream:events"),
            env=os.environ.get("ENV", "dev"),
            attack_map_enabled=_bool_env("ATTACK_MAP_ENABLED", True),
            fusion_enabled=_bool_env("FUSION_ENABLED", True),
        )


_settings: Optional[Settings] = None


def settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings.load()
    return _settings
