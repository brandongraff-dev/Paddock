"""Growth settings (env prefix ``GROWTH_``), kept out of the shared config."""
from __future__ import annotations

from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class GrowthSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="GROWTH_", env_file=".env", extra="ignore")

    # --- public exposure report ------------------------------------------
    public_enabled: bool = True
    cache_hours: int = 24                 # one assessment per domain per window
    ip_requests_per_hour: int = 10        # POSTs per client IP
    ip_reads_per_minute: int = 120        # GETs per client IP
    domain_requests_per_day: int = 5      # fresh assessments per domain
    global_daily_cap: int = 500           # fresh assessments per UTC day, all callers
    max_queue_depth: int = 200            # queued + running before new ones get 503
    # Salt for the IP hash stored with reports/leads. Set it in production.
    ip_hash_salt: str = "paddock-growth"

    # CAPTCHA hook: "none" (default, no-op) or "turnstile" (Cloudflare).
    captcha_provider: Literal["none", "turnstile"] = "none"
    turnstile_secret: str = ""
    turnstile_verify_url: str = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

    # --- passive engine --------------------------------------------------
    max_hosts: int = 150                  # CT names resolved per assessment
    dns_concurrency: int = 12
    dns_timeout_sec: float = 4.0
    ct_timeout_sec: float = 25.0
    ct_url: str = "https://crt.sh/"
    # Optional comma-separated resolver IPs; empty = the system resolver.
    dns_nameservers: str = ""
    expiry_warn_days: int = 14        # LE-style certs renew at ~30d left; 14d means renewal is failing
    expiry_critical_days: int = 3

    # --- runners ---------------------------------------------------------
    runner_enabled: bool = True
    runner_interval_sec: float = 3.0
    supplier_enabled: bool = True
    supplier_interval_sec: float = 30.0
    supplier_batch: int = 5               # assessments per tenant per tick
    supplier_lease_minutes: int = 30

    # --- trust pages -----------------------------------------------------
    trust_max_days: int = 365
    trust_max_password_attempts: int = 8   # per token+IP per 15 min

    # --- calls to action -------------------------------------------------
    signup_url: str = "/welcome"


growth_settings = GrowthSettings()
