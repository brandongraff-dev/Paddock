"""Database access for billing (schema 028).

Tenant scoping follows ``app/tenancy.py``: every ``pool.acquire()`` stamps the
context's tenant, so per-tenant tables need no WHERE clause. The two GLOBAL
tables (``billing_customers``, ``billing_events``) are writable only from the
platform (default) tenant, so those helpers run inside
``tenancy.tenant_context(DEFAULT_TENANT_ID)``.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from .. import tenancy

SUB_COLS = (
    "stripe_customer_id", "stripe_subscription_id", "plan", "status", "cancel_at_period_end",
    "current_period_end", "trial_end", "payment_failed_at", "grace_until",
)
_SELECT_SUB = (
    "SELECT stripe_customer_id, stripe_subscription_id, plan, status, cancel_at_period_end, "
    "current_period_end, trial_end, payment_failed_at, grace_until, last_event_at, last_event_id, updated_at "
    "FROM billing_subscriptions"
)


def valid_uuid(value: Any) -> str | None:
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, AttributeError, TypeError):
        return None


async def get_subscription(pool) -> dict[str, Any] | None:
    """The CURRENT tenant's subscription row (None = never subscribed)."""
    async with pool.acquire() as con:
        row = await con.fetchrow(_SELECT_SUB)
    return dict(row) if row else None


async def tenant_created_at(pool, tenant_id: str | None = None) -> datetime | None:
    tid = tenant_id or tenancy.current_tenant_id()
    if not tid:
        return None
    async with pool.acquire() as con:
        return await con.fetchval("SELECT created_at FROM tenants WHERE id = $1::uuid", tid)


async def tenant_exists(pool, tenant_id: str) -> bool:
    async with pool.acquire() as con:
        return bool(await con.fetchval("SELECT 1 FROM tenants WHERE id = $1::uuid AND status = 'active'", tenant_id))


# --------------------------------------------------------------------------- #
# Customer <-> tenant mapping (GLOBAL table; platform context)
# --------------------------------------------------------------------------- #

async def tenant_for_customer(pool, customer_id: str | None) -> str | None:
    if not customer_id:
        return None
    with tenancy.tenant_context(tenancy.DEFAULT_TENANT_ID):
        async with pool.acquire() as con:
            tid = await con.fetchval(
                "SELECT owner_tenant FROM billing_customers WHERE stripe_customer_id = $1", customer_id
            )
    return str(tid) if tid else None


async def customer_for_tenant(pool, tenant_id: str) -> str | None:
    with tenancy.tenant_context(tenancy.DEFAULT_TENANT_ID):
        async with pool.acquire() as con:
            return await con.fetchval(
                "SELECT stripe_customer_id FROM billing_customers WHERE owner_tenant = $1::uuid "
                "ORDER BY created_at DESC LIMIT 1",
                tenant_id,
            )


async def link_customer(pool, customer_id: str, tenant_id: str) -> None:
    """Record customer -> tenant. A customer already linked to ANOTHER tenant
    is never re-pointed (that would let one tenant capture another's billing)."""
    with tenancy.tenant_context(tenancy.DEFAULT_TENANT_ID):
        async with pool.acquire() as con:
            await con.execute(
                "INSERT INTO billing_customers (stripe_customer_id, owner_tenant) VALUES ($1, $2::uuid) "
                "ON CONFLICT (stripe_customer_id) DO NOTHING",
                customer_id, tenant_id,
            )


# --------------------------------------------------------------------------- #
# Webhook event ledger (GLOBAL table): replay protection
# --------------------------------------------------------------------------- #

#: A claimed-but-unfinished event may be re-claimed after this long (a crashed worker).
STALE_CLAIM_SECONDS = 300


async def claim_event(pool, event_id: str, etype: str, created: datetime | None) -> bool:
    """True when this delivery should be processed; False for a duplicate.

    First sight inserts the id. A redelivery is processed again only when the
    earlier attempt FAILED or its claim went stale; a processed (or still
    in-flight) event id is a no-op, so replays cannot re-run side effects.
    """
    with tenancy.tenant_context(tenancy.DEFAULT_TENANT_ID):
        async with pool.acquire() as con:
            row = await con.fetchrow(
                f"""
                INSERT INTO billing_events (event_id, type, event_created)
                VALUES ($1, $2, $3)
                ON CONFLICT (event_id) DO UPDATE
                   SET attempts = billing_events.attempts + 1,
                       status = 'processing', received_at = NOW(), error = NULL
                 WHERE billing_events.status = 'failed'
                    OR (billing_events.status = 'processing'
                        AND billing_events.received_at < NOW() - make_interval(secs => {STALE_CLAIM_SECONDS}))
                RETURNING event_id
                """,
                event_id, etype, created,
            )
    return row is not None


async def finish_event(
    pool, event_id: str, status: str, *, tenant_id: str | None = None, error: str | None = None,
) -> None:
    with tenancy.tenant_context(tenancy.DEFAULT_TENANT_ID):
        async with pool.acquire() as con:
            await con.execute(
                "UPDATE billing_events SET status = $2, owner_tenant = $3::uuid, error = $4, processed_at = NOW() "
                "WHERE event_id = $1",
                event_id, status, tenant_id, (error or None) and error[:500],
            )


# --------------------------------------------------------------------------- #
# Subscription writes (tenant scoped)
# --------------------------------------------------------------------------- #

async def write_subscription(
    pool, tenant_id: str, *, event_created: datetime | None, event_id: str | None,
    transition,
) -> dict[str, Any] | None:
    """Read-modify-write the tenant's subscription row under a per-tenant lock.

    ``transition(current_row_or_None) -> new_state_or_None`` is pure; ``None``
    means "nothing to change". Events older than the row's ``last_event_at``
    are dropped, so Stripe's out-of-order delivery cannot roll state back.
    """
    with tenancy.tenant_context(tenant_id):
        async with pool.acquire() as con:
            async with con.transaction():
                await con.execute("SELECT pg_advisory_xact_lock(hashtext($1))", f"billing:{tenant_id}")
                row = await con.fetchrow(_SELECT_SUB)
                cur = dict(row) if row else None
                if (
                    cur is not None and cur.get("last_event_at") is not None
                    and event_created is not None and event_created < cur["last_event_at"]
                ):
                    return None
                new = transition(cur)
                if new is None:
                    return None
                values = [new.get(c) for c in SUB_COLS]
                await con.execute(
                    """
                    INSERT INTO billing_subscriptions
                        (tenant_id, stripe_customer_id, stripe_subscription_id, plan, status,
                         cancel_at_period_end, current_period_end, trial_end, payment_failed_at,
                         grace_until, last_event_at, last_event_id)
                    VALUES ($1::uuid, $2, $3, $4, $5, COALESCE($6, FALSE), $7, $8, $9, $10, $11, $12)
                    ON CONFLICT (tenant_id) DO UPDATE SET
                        stripe_customer_id = EXCLUDED.stripe_customer_id,
                        stripe_subscription_id = EXCLUDED.stripe_subscription_id,
                        plan = EXCLUDED.plan, status = EXCLUDED.status,
                        cancel_at_period_end = EXCLUDED.cancel_at_period_end,
                        current_period_end = EXCLUDED.current_period_end,
                        trial_end = EXCLUDED.trial_end,
                        payment_failed_at = EXCLUDED.payment_failed_at,
                        grace_until = EXCLUDED.grace_until,
                        last_event_at = COALESCE(EXCLUDED.last_event_at, billing_subscriptions.last_event_at),
                        last_event_id = EXCLUDED.last_event_id,
                        updated_at = NOW()
                    """,
                    tenant_id, *values, event_created, event_id,
                )
                return new
