"""Settings for the integrations core (dispatcher + delivery worker).

Kept separate from ``app.config`` so the integrations framework owns its own
knobs. Every value is read from the environment (``INTEGRATIONS_*`` plus
``PADDOCK_DASHBOARD_URL``).
"""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class IntegrationSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Public base URL of the dashboard, used for deep links in notifications.
    paddock_dashboard_url: str = "http://localhost:3000"

    # Redis consumer group that turns stream:events into deliveries.
    integrations_consumer_group: str = "integrations"
    integrations_consumer_name: str = ""          # default: hostname-pid

    # Delivery loop.
    integrations_poll_sec: float = 2.0            # how often due deliveries are polled
    integrations_batch: int = 20                  # deliveries claimed per poll
    integrations_lease_sec: int = 300             # in-flight lease (crash safety)
    integrations_max_attempts: int = 8            # then dead-letter
    integrations_backoff_base_sec: float = 30.0   # 30s, 60s, 120s, ...
    integrations_backoff_max_sec: float = 3600.0  # capped at 1h
    integrations_http_timeout_sec: float = 10.0

    # Liveness file the compose healthcheck reads.
    integrations_heartbeat_path: str = "/tmp/integrations-heartbeat"


isettings = IntegrationSettings()
