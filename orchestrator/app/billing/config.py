"""Billing configuration (environment only; no secrets in code).

Billing is OFF unless ``STRIPE_SECRET_KEY`` is set. A self-hosted install
never sets it and keeps using signed license files (``app/licensing.py``).

Environment (all optional):

* ``STRIPE_SECRET_KEY``            -- enables billing (``sk_live_...`` / ``sk_test_...``).
* ``STRIPE_WEBHOOK_SECRET``        -- ``whsec_...``; comma-separate two to rotate.
* ``STRIPE_PRICE_TEAM`` / ``STRIPE_PRICE_ENTERPRISE`` -- placeholder price ids
  (``price_...``) of the recurring subscription price for each plan.
* ``STRIPE_METER_SITES_EVENT`` / ``STRIPE_METER_ASSETS_EVENT`` -- Stripe Billing
  Meter ``event_name`` values for the two usage dimensions.
* ``STRIPE_API_BASE``              -- override for tests / Stripe-compatible mocks.
* ``BILLING_PUBLIC_URL``           -- dashboard base URL used for Checkout/Portal
  return URLs and ``upgrade_url`` (e.g. ``https://app.example.com``).
* ``BILLING_TRIAL_DAYS`` (14), ``BILLING_GRACE_DAYS`` (7),
  ``BILLING_WEBHOOK_TOLERANCE_SEC`` (300).
* ``PADDOCK_ENFORCE_EDITIONS``     -- ``auto`` (default: enforce iff billing is on),
  ``on`` (always enforce paid-feature gates), ``off`` (never).
* Plan limits: ``BILLING_TEAM_SEATS|SITES|ASSETS`` and
  ``BILLING_COMMUNITY_SEATS|SITES|ASSETS``; ``-1`` means unlimited.
"""
from __future__ import annotations

from dataclasses import dataclass

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _env(name: str, default, **kw):
    return Field(default=default, validation_alias=AliasChoices(name), **kw)


class BillingSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", populate_by_name=True)

    stripe_secret_key: str | None = _env("STRIPE_SECRET_KEY", None)
    stripe_webhook_secret: str | None = _env("STRIPE_WEBHOOK_SECRET", None)
    stripe_api_base: str = _env("STRIPE_API_BASE", "https://api.stripe.com")
    stripe_price_team: str | None = _env("STRIPE_PRICE_TEAM", None)
    stripe_price_enterprise: str | None = _env("STRIPE_PRICE_ENTERPRISE", None)
    stripe_meter_sites_event: str = _env("STRIPE_METER_SITES_EVENT", "paddock_sites")
    stripe_meter_assets_event: str = _env("STRIPE_METER_ASSETS_EVENT", "paddock_assets_k")

    billing_public_url: str = _env("BILLING_PUBLIC_URL", "")
    billing_trial_days: int = _env("BILLING_TRIAL_DAYS", 14, ge=0, le=365)
    billing_grace_days: int = _env("BILLING_GRACE_DAYS", 7, ge=0, le=90)
    billing_webhook_tolerance_sec: int = _env("BILLING_WEBHOOK_TOLERANCE_SEC", 300, ge=30, le=3600)
    enforce_editions: str = _env("PADDOCK_ENFORCE_EDITIONS", "auto")
    # Seconds a resolved entitlement is cached per process.
    billing_cache_ttl_sec: float = _env("BILLING_CACHE_TTL_SEC", 15.0)

    billing_team_seats: int = _env("BILLING_TEAM_SEATS", 10)
    billing_team_sites: int = _env("BILLING_TEAM_SITES", 3)
    billing_team_assets: int = _env("BILLING_TEAM_ASSETS", 5000)
    billing_community_seats: int = _env("BILLING_COMMUNITY_SEATS", 3)
    billing_community_sites: int = _env("BILLING_COMMUNITY_SITES", 0)
    billing_community_assets: int = _env("BILLING_COMMUNITY_ASSETS", 250)

    @property
    def enabled(self) -> bool:
        return bool((self.stripe_secret_key or "").strip())

    def webhook_secrets(self) -> list[str]:
        return [s.strip() for s in (self.stripe_webhook_secret or "").split(",") if s.strip()]

    def enforcement_active(self) -> bool:
        mode = (self.enforce_editions or "auto").strip().lower()
        if mode in {"on", "true", "1", "yes", "always"}:
            return True
        if mode in {"off", "false", "0", "no", "never"}:
            return False
        return self.enabled


settings = BillingSettings()


def limit(value: int) -> int | None:
    """``-1`` (or any negative) means unlimited."""
    return None if value < 0 else value


@dataclass(frozen=True)
class Plan:
    key: str                 # team | enterprise
    edition: str
    name: str
    price_id: str | None
    seats: int | None
    sites: int | None
    assets: int | None


def plans(cfg: BillingSettings | None = None) -> dict[str, Plan]:
    """Purchasable plans, from configuration (price ids are placeholders)."""
    c = cfg or settings
    return {
        "team": Plan("team", "team", "Team", c.stripe_price_team,
                     limit(c.billing_team_seats), limit(c.billing_team_sites), limit(c.billing_team_assets)),
        # Enterprise is metered, not capped.
        "enterprise": Plan("enterprise", "enterprise", "Enterprise", c.stripe_price_enterprise, None, None, None),
    }


def plan_for_price(price_id: str | None, cfg: BillingSettings | None = None) -> Plan | None:
    if not price_id:
        return None
    for p in plans(cfg).values():
        if p.price_id and p.price_id == price_id:
            return p
    return None


def community_limits(cfg: BillingSettings | None = None) -> dict[str, int | None]:
    c = cfg or settings
    return {
        "seats": limit(c.billing_community_seats),
        "sites": limit(c.billing_community_sites),
        "assets": limit(c.billing_community_assets),
    }
