"""Resolve the effective entitlements of the current tenant.

Billing off  -> the signed license (``licensing.current_license``) only, i.e.
                today's self-hosted behaviour.
Billing on   -> subscription / trial state (``entitlements.compute_entitlements``)
                merged with any installed license (best edition wins).
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone

from fastapi import Request

from .. import licensing, tenancy
from . import store
from .config import BillingSettings, settings as default_settings
from .entitlements import Entitlements, Subscription, compute_entitlements, merge_with_license

logger = logging.getLogger(__name__)

_cache: dict[str, tuple[float, Entitlements]] = {}


def invalidate(tenant_id: str | None = None) -> None:
    """Drop cached entitlements (after a webhook changed a tenant's state)."""
    if tenant_id is None:
        _cache.clear()
    else:
        _cache.pop(tenant_id, None)


def from_license(lic: licensing.License) -> Entitlements:
    return Entitlements(
        edition=lic.edition, status=lic.status, source="license" if lic.edition != "community" else "default",
        features=lic.features, seats=lic.seats, sites=lic.sites, assets=lic.assets,
    )


async def resolve(
    pool, lic: licensing.License, *, now: datetime | None = None, cfg: BillingSettings | None = None,
    use_cache: bool = True,
) -> Entitlements:
    """Entitlements of the CURRENT tenant. Never raises: a DB blip degrades to
    the license-only view rather than locking the product."""
    c = cfg or default_settings
    if not c.enabled:
        return from_license(lic)
    tid = tenancy.current_tenant_id() or "-"
    mono = time.monotonic()
    hit = _cache.get(tid)
    if use_cache and now is None and hit and mono - hit[0] < c.billing_cache_ttl_sec:
        return hit[1]
    try:
        row = await store.get_subscription(pool)
        created = await store.tenant_created_at(pool)
        ent = compute_entitlements(
            Subscription.from_row(row) if row else None, created, now, c,
        )
        ent = merge_with_license(ent, lic)
    except Exception:  # noqa: BLE001
        logger.exception("billing_resolve_failed")
        return from_license(lic)
    if now is None:
        _cache[tid] = (mono, ent)
    return ent


async def current(request: Request, *, cfg: BillingSettings | None = None) -> Entitlements:
    lic = await licensing.current_license(request)
    return await resolve(request.app.state.pool, lic, cfg=cfg)


# --------------------------------------------------------------------------- #
# Light usage counts (the same definitions as GET /v1/usage)
# --------------------------------------------------------------------------- #

async def count_usage(pool, dimension: str) -> int | None:
    """Current usage of one quota dimension for the current tenant.

    ``sites`` comes from the otdiscovery service and is ``None`` when it is
    unreachable (an unknown number never blocks anyone).
    """
    from ..routers import licensing as usage

    if dimension == "seats":
        async with pool.acquire() as con:
            return int(await con.fetchval("SELECT COUNT(*) FROM app_users WHERE active") or 0)
    if dimension == "assets":
        since = datetime.now(timezone.utc) - timedelta(days=usage.MONITORED_WINDOW_DAYS)
        async with pool.acquire() as con:
            return int(
                await con.fetchval(
                    "SELECT COUNT(*) FROM assets WHERE kind = ANY($1::text[]) AND last_seen >= $2",
                    list(usage.BILLABLE_ASSET_KINDS), since,
                ) or 0
            )
    if dimension == "sites":
        sites, _sensors, _note = await usage._otdiscovery_sites()
        return sites
    raise ValueError(f"unknown quota dimension {dimension!r}")


def quota_state(ent: Entitlements, used: dict[str, int | None]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for dim in ("seats", "sites", "assets"):
        limit = ent.limit(dim)
        u = used.get(dim)
        out[dim] = {"used": u, "limit": limit, "over": bool(limit is not None and u is not None and u > limit)}
    return out
