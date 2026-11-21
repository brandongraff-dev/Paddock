"""Operations settings: migrations, metrics, data retention.

Kept separate from ``config.Settings`` so the production-operations knobs do
not collide with feature settings other streams add to ``config.py``. Every
value is read from the environment (case-insensitive) or ``.env``.
"""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class OpsSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # --- migrations (app/migrate.py) ---------------------------------------
    # Run `migrate up` from the orchestrator lifespan before the pool opens.
    # Safe with N replicas (Postgres advisory lock). Helm turns this off and
    # runs a pre-install/pre-upgrade Job instead.
    migrate_on_startup: bool = True
    # Optional direct (non-pgbouncer) DSN for migrations; the runner holds a
    # session-level advisory lock, which transaction-pooling proxies break.
    # Falls back to DATABASE_URL.
    migrate_database_url: str | None = None
    # Where the NNN_*.sql files live. Unset -> auto-detect (/app/schema in the
    # image, ../schema relative to the orchestrator package in a checkout).
    schema_dir: str | None = None
    # How long a runner waits for another replica's migration lock.
    migrate_lock_timeout_sec: int = 300
    # Comma-separated filenames whose checksum may differ from the recorded
    # one (or "*" for all). Use ONLY for edits proven harmless (comments,
    # whitespace) to historical, idempotent files. See docs/OPERATIONS.md.
    migrate_allow_checksum_drift: str = ""

    # --- metrics (app/metrics.py) ------------------------------------------
    # /metrics is served outside the user-auth middleware and protected by
    # this bearer token. Unset: open in AUTH_MODE=dev, 404 in enforce.
    metrics_token: str | None = None
    # Cache DB/Redis-derived gauges for this many seconds between scrapes.
    metrics_db_cache_sec: int = 15

    # --- retention (app/retention.py) --------------------------------------
    retention_enabled: bool = True
    retention_interval_sec: int = 6 * 3600
    retention_batch_size: int = 5000
    retention_scope_decisions_days: int = 180
    retention_outbound_log_days: int = 180
    retention_integration_deliveries_days: int = 90
    retention_observations_days: int = 30
    # Extra policies: "table:timestamp_column:days[,table:col:days...]".
    retention_extra: str = ""


ops_settings = OpsSettings()
