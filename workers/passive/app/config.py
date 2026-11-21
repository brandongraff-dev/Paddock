"""Environment-driven settings for the passive worker."""
from __future__ import annotations

from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Transport
    orchestrator_url: str = Field(default="http://orchestrator:8080")
    redis_url: str = Field(default="redis://redis:6379/0")

    # Identity
    worker_id: str = Field(default="passive-1")
    consumer_group: str = Field(default="passive-workers")
    stream: str = Field(default="queue:passive")

    # Concurrency / runtime
    max_concurrency: int = Field(default=4)
    poll_block_ms: int = Field(default=5000)
    scope_cache_ttl_s: int = Field(default=60)

    # HTTP client
    http_timeout_s: float = Field(default=30.0)
    http_user_agent: str = Field(default="paddock/passive-discovery (+defensive-asm)")

    # Optional source keys (all gracefully skipped when missing)
    github_token: Optional[str] = Field(default=None)
    shodan_api_key: Optional[str] = Field(default=None)
    censys_api_id: Optional[str] = Field(default=None)
    censys_api_secret: Optional[str] = Field(default=None)

    # Rate limits (requests per second, per public source)
    rate_crtsh_rps: float = Field(default=0.5)       # 1 req / 2s
    rate_github_rps: float = Field(default=1.0)
    rate_shodan_rps: float = Field(default=1.0)
    rate_internetdb_rps: float = Field(default=5.0)
    rate_wayback_rps: float = Field(default=1.0)
    rate_bgpview_rps: float = Field(default=1.0)
    rate_dns_rps: float = Field(default=20.0)

    # CertStream
    certstream_url: str = Field(default="wss://certstream.calidog.io")
    certstream_backoff_max_s: float = Field(default=60.0)

    # Logging
    log_level: str = Field(default="INFO")


def get_settings() -> Settings:
    return Settings()
