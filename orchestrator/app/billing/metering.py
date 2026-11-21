"""Usage-based reporting to Stripe (Billing Meter Events), from the scheduler.

Two dimensions, the same ones ``GET /v1/usage`` and docs/EDITIONS.md price on:

* ``sites``     -- distinct Sentry sites (otdiscovery);
* ``assets_k``  -- monitored assets in thousands, rounded UP (1..1000 -> 1).

One report per (tenant, dimension, UTC day). Idempotent three ways: the local
``billing_usage_reports`` unique key (a sent day is never re-sent), a
deterministic Stripe ``identifier`` (Stripe dedupes meter events by it), and
the same value as the ``Idempotency-Key`` header. A failed send stays
``failed`` and is retried on the next tick with the same identifier.

Configure the two Stripe meters with the ``last`` (or ``max``) aggregation:
each event carries the day's *level*, not a delta.
"""
from __future__ import annotations

import logging
from datetime import date, datetime, timezone
from typing import Any

from .. import tenancy
from . import service, store
from .config import BillingSettings, settings as default_settings
from .stripe import StripeClient, StripeError, make_client

logger = logging.getLogger(__name__)

_REPORTING_STATUSES = {"active", "trialing", "past_due"}


def identifier(tenant_id: str, dimension: str, day: date) -> str:
    return f"paddock-{tenant_id}-{dimension}-{day.isoformat()}"


def to_meter_value(dimension: str, raw: int) -> int:
    if dimension == "assets_k":
        return -(-max(raw, 0) // 1000)
    return max(raw, 0)


def event_name(dimension: str, cfg: BillingSettings) -> str:
    return cfg.stripe_meter_sites_event if dimension == "sites" else cfg.stripe_meter_assets_event


async def report_tenant(
    pool, client: StripeClient, tenant_id: str, *, day: date | None = None,
    now: datetime | None = None, cfg: BillingSettings | None = None,
) -> dict[str, str]:
    """Report today's usage for ONE tenant (caller sets the tenant context).

    Returns ``{dimension: sent | already_sent | skipped | failed}``.
    """
    c = cfg or default_settings
    now = now or datetime.now(timezone.utc)
    day = day or now.date()
    results: dict[str, str] = {}

    sub = await store.get_subscription(pool)
    customer = (sub or {}).get("stripe_customer_id") or await store.customer_for_tenant(pool, tenant_id)
    if not customer or not sub or sub.get("status") not in _REPORTING_STATUSES or not sub.get("plan"):
        return {"sites": "skipped", "assets_k": "skipped"}

    async with pool.acquire() as con:
        done = {
            r["dimension"] for r in await con.fetch(
                "SELECT dimension FROM billing_usage_reports WHERE day = $1 AND status = 'sent'", day)
        }
    if {"sites", "assets_k"} <= done:
        return {"sites": "already_sent", "assets_k": "already_sent"}

    raw = {
        "sites": await service.count_usage(pool, "sites"),
        "assets_k": await service.count_usage(pool, "assets"),
    }
    for dim, value in raw.items():
        if value is None:  # e.g. otdiscovery unreachable: never invent a number
            results[dim] = "skipped"
            continue
        qty = to_meter_value(dim, value)
        ident = identifier(tenant_id, dim, day)
        async with pool.acquire() as con:
            row = await con.fetchrow(
                """
                INSERT INTO billing_usage_reports (tenant_id, dimension, day, value, identifier)
                VALUES ($1::uuid, $2, $3, $4, $5)
                ON CONFLICT (tenant_id, dimension, day) DO UPDATE
                   SET value = CASE WHEN billing_usage_reports.status = 'sent'
                                    THEN billing_usage_reports.value ELSE EXCLUDED.value END
                RETURNING status, value
                """,
                tenant_id, dim, day, qty, ident,
            )
        if row["status"] == "sent":
            results[dim] = "already_sent"
            continue
        try:
            await client.send_meter_event(
                event_name=event_name(dim, c), customer=customer, value=int(row["value"]),
                identifier=ident, timestamp=int(now.timestamp()),
            )
        except StripeError as exc:
            async with pool.acquire() as con:
                await con.execute(
                    "UPDATE billing_usage_reports SET status = 'failed', attempts = attempts + 1, "
                    "last_error = $4 WHERE tenant_id = $1::uuid AND dimension = $2 AND day = $3",
                    tenant_id, dim, day, str(exc)[:300],
                )
            logger.warning("billing_meter_failed", extra={"tenant": tenant_id, "dimension": dim})
            results[dim] = "failed"
            continue
        async with pool.acquire() as con:
            await con.execute(
                "UPDATE billing_usage_reports SET status = 'sent', attempts = attempts + 1, "
                "last_error = NULL, reported_at = NOW() "
                "WHERE tenant_id = $1::uuid AND dimension = $2 AND day = $3",
                tenant_id, dim, day,
            )
        results[dim] = "sent"
    return results


async def tick(app, *, now: datetime | None = None, cfg: BillingSettings | None = None) -> dict[str, Any]:
    """Scheduler hook: report usage for every tenant. No-op when billing is off."""
    c = cfg or default_settings
    if not c.enabled:
        return {}
    pool = getattr(app.state, "pool", None)
    if pool is None:
        return {}
    client = make_client(app, c)
    out: dict[str, Any] = {}
    for tid in await tenancy.list_tenant_ids(pool):
        try:
            with tenancy.tenant_context(tid):
                out[tid] = await report_tenant(pool, client, tid, now=now, cfg=c)
        except Exception:  # noqa: BLE001 -- one tenant never blocks the others
            logger.exception("billing_usage_report_failed", extra={"tenant": tid})
            out[tid] = {"error": "exception"}
    return out

