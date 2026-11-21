"""Service configuration.

Everything here can be overridden with environment variables. Nothing here
toggles evasion, rate-limit-bypass, stealth, or any such mode: by design
those flags do not exist.
"""
from __future__ import annotations

import os
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


# Names we explicitly refuse to carry as config toggles. If one of these
# turns up in env it's a loud mistake, not a feature.
_BANNED_CONFIG_SUBSTRINGS = (
    "bypass", "evade", "stealth", "rate_limit_bypass", "ratelimit_bypass",
    "hidden", "cloak", "decoy", "spoof_source", "frag",
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="", case_sensitive=False, extra="ignore")

    # Identity
    worker_id: str = Field(default="active-1", alias="WORKER_ID")
    user_agent: str = Field(
        default="paddock-scanner/1.0 (+defensive-scanner)",
        alias="USER_AGENT",
    )

    # Orchestrator
    orchestrator_url: str = Field(default="http://orchestrator:8080", alias="ORCHESTRATOR_URL")
    scope_cache_ttl_sec: int = Field(default=60, alias="SCOPE_CACHE_TTL_SEC")

    # Redis
    redis_url: str = Field(default="redis://redis:6379/0", alias="REDIS_URL")
    queue_stream: str = Field(default="queue:active", alias="QUEUE_STREAM")
    consumer_group: str = Field(default="active-workers", alias="CONSUMER_GROUP")
    event_stream: str = Field(default="stream:events", alias="EVENT_STREAM")

    # Concurrency
    max_concurrency: int = Field(default=8, alias="MAX_CONCURRENCY")
    max_concurrency_per_target: int = Field(default=2, alias="MAX_CONCURRENCY_PER_TARGET")

    # Politeness
    politeness_delay_ms: int = Field(default=250, alias="POLITENESS_DELAY_MS")
    politeness_delay_floor_ms: int = Field(default=100, alias="POLITENESS_DELAY_FLOOR_MS")
    robots_cache_ttl_sec: int = Field(default=600, alias="ROBOTS_CACHE_TTL_SEC")

    # Timeouts
    job_timeout_sec: int = Field(default=300, alias="JOB_TIMEOUT_SEC")
    http_timeout_sec: int = Field(default=20, alias="HTTP_TIMEOUT_SEC")
    subprocess_timeout_sec: int = Field(default=600, alias="SUBPROCESS_TIMEOUT_SEC")

    # Nuclei rate caps (fixed; raised only in non-prod with explicit code change).
    nuclei_rate_limit: int = Field(default=50, alias="NUCLEI_RATE_LIMIT")
    nuclei_rate_limit_minute: int = Field(default=500, alias="NUCLEI_RATE_LIMIT_MINUTE")
    nuclei_exclude_tags: str = Field(
        default="intrusive,fuzz,dos,miscellaneous",
        alias="NUCLEI_EXCLUDE_TAGS",
    )

    # Screenshots
    data_dir: str = Field(default="/data", alias="DATA_DIR")
    screenshot_viewport_width: int = Field(default=1280, alias="SCREENSHOT_VIEWPORT_WIDTH")
    screenshot_viewport_height: int = Field(default=800, alias="SCREENSHOT_VIEWPORT_HEIGHT")
    screenshot_device_scale: int = Field(default=2, alias="SCREENSHOT_DEVICE_SCALE")
    screenshot_timeout_ms: int = Field(default=15000, alias="SCREENSHOT_TIMEOUT_MS")

    # Logging
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(default="INFO", alias="LOG_LEVEL")

    # Sentinels
    env: Literal["dev", "staging", "prod"] = Field(default="dev", alias="ENV")

    @field_validator("politeness_delay_ms")
    @classmethod
    def _enforce_floor(cls, v: int, info):
        # The floor is enforced by PolitenessLimiter at runtime too; this is
        # just an earlier shout.
        if v < 100:
            raise ValueError("politeness_delay_ms must be >= 100 (defensive floor)")
        return v


def _refuse_banned_env() -> None:
    """Explicit refusal: if someone tries to set an evasion-flavored env var,
    raise at import time so the service does not start pretending.
    """
    for key in os.environ:
        low = key.lower()
        for banned in _BANNED_CONFIG_SUBSTRINGS:
            if banned in low:
                raise RuntimeError(
                    f"refused env var {key!r}: this service does not implement "
                    f"evasion/bypass/stealth modes"
                )


_refuse_banned_env()
settings = Settings()
