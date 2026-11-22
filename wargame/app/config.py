"""Environment-driven configuration for the Proving Ground service."""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional


def _asyncpg_dsn(raw: str) -> str:
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
    http_port: int
    log_level: str
    consumer_group: str
    consumer_name: str
    events_stream: str
    env: str
    # Proving Ground is OFF by default: it builds and runs replicas, which needs
    # a sandbox backend, so an operator opts in explicitly.
    enabled: bool
    # Which sandbox backend drives replicas: "fake" (tests / dry-run, builds
    # nothing) or "docker" (real isolated containers).
    sandbox_backend: str
    # The signing key id + secret for proof MACs. In production this is a
    # hardware-bound / KMS key; here it comes from the environment.
    signing_key_id: str
    signing_secret: str
    # Hard caps the guard + backend enforce on every replica.
    max_replica_ttl_sec: int
    max_run_sec: int

    @classmethod
    def load(cls) -> "Settings":
        return cls(
            database_url=_asyncpg_dsn(
                os.environ.get("DATABASE_URL", "postgresql://asm:asm_dev@postgres:5432/asm")
            ),
            redis_url=os.environ.get("REDIS_URL", "redis://redis:6379/0"),
            orchestrator_url=os.environ.get("ORCHESTRATOR_URL", "http://orchestrator:8080"),
            http_port=int(os.environ.get("HTTP_PORT", "8103")),
            log_level=os.environ.get("LOG_LEVEL", "INFO").upper(),
            consumer_group=os.environ.get("CONSUMER_GROUP", "wargame"),
            consumer_name=os.environ.get("CONSUMER_NAME", f"wargame-{os.getpid()}"),
            events_stream=os.environ.get("EVENTS_STREAM", "stream:events"),
            env=os.environ.get("ENV", "dev"),
            enabled=_bool_env("WARGAME_ENABLED", False),
            sandbox_backend=os.environ.get("WARGAME_SANDBOX_BACKEND", "fake").strip().lower(),
            signing_key_id=os.environ.get("WARGAME_SIGNING_KEY_ID", "dev-local"),
            signing_secret=os.environ.get("WARGAME_SIGNING_SECRET", ""),
            max_replica_ttl_sec=int(os.environ.get("WARGAME_MAX_REPLICA_TTL_SEC", "300")),
            max_run_sec=int(os.environ.get("WARGAME_MAX_RUN_SEC", "600")),
        )


_settings: Optional[Settings] = None


def settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings.load()
    return _settings
