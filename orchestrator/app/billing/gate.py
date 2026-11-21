"""One consistent gate for paid features and quotas.

``require_paid("scim")`` is a FastAPI dependency; ``await ensure_feature(request,
"sso_saml")`` is the same check for code that must branch on request data.
Both answer **402 Payment Required** with a machine-readable body::

    {"error": "payment_required", "feature": "scim", "required_edition": "enterprise",
     "upgrade_url": "https://app.example.com/settings/billing?feature=scim&plan=enterprise",
     "current_edition": "community", "reason": "trial_expired", ...,
     "detail": {...same object...}}

(``detail`` mirrors the body so clients written against FastAPI's default
error shape and ``licensing.require_feature`` keep working.)

When does a gate bite? Only when **enforcement is active**: billing is on
(``STRIPE_SECRET_KEY``) or the operator set ``PADDOCK_ENFORCE_EDITIONS=on``.
A plain self-hosted Community install enforces nothing, which is the "free
forever" promise of docs/EDITIONS.md. Gates never hide or delete data; they
refuse the paid *action* and leave reads alone.
"""
from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlencode

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

from .. import licensing
from . import service
from .config import settings

logger = logging.getLogger(__name__)

_NEXT_EDITION = {"community": "team", "team": "enterprise", "enterprise": "enterprise", "edge": "edge"}


class PaymentRequired(HTTPException):
    """HTTP 402 carrying the machine-readable upgrade body."""

    def __init__(self, payload: dict[str, Any]):
        super().__init__(status_code=402, detail=payload)
        self.payload = payload


async def payment_required_handler(_request: Request, exc: PaymentRequired) -> JSONResponse:
    return JSONResponse({**exc.payload, "detail": exc.payload}, status_code=402)


def upgrade_url(feature: str | None = None, plan: str | None = None) -> str:
    base = (settings.billing_public_url or "").rstrip("/")
    q = {k: v for k, v in (("feature", feature), ("plan", plan)) if v}
    return f"{base}/settings/billing" + (f"?{urlencode(q)}" if q else "")


def _plan_for_edition(edition: str) -> str | None:
    return edition if edition in ("team", "enterprise") else None


def feature_payload(feature: str, ent: service.Entitlements) -> dict[str, Any]:
    info = licensing.FEATURES[feature]
    return {
        "error": "payment_required",
        "feature": feature,
        "description": info.description,
        "required_edition": info.min_edition,
        "upgrade_url": upgrade_url(feature, _plan_for_edition(info.min_edition)),
        "current_edition": ent.edition,
        "reason": ent.status,
        "docs": "docs/BILLING.md",
    }


def quota_payload(dimension: str, ent: service.Entitlements, used: int, limit: int) -> dict[str, Any]:
    needed = _NEXT_EDITION.get(ent.edition, "enterprise")
    return {
        "error": "quota_exceeded",
        "feature": dimension,
        "description": f"Your plan's {dimension} allowance is used up; existing data stays readable.",
        "required_edition": needed,
        "upgrade_url": upgrade_url(dimension, _plan_for_edition(needed)),
        "current_edition": ent.edition,
        "reason": ent.status,
        "used": used,
        "limit": limit,
        "docs": "docs/BILLING.md",
    }


def enforcement_active() -> bool:
    return settings.enforcement_active()


async def ensure_feature(request: Request, feature: str) -> service.Entitlements | None:
    """Raise :class:`PaymentRequired` unless the tenant may use ``feature``."""
    if feature not in licensing.FEATURES:
        raise ValueError(f"unknown licensable feature {feature!r}; add it to licensing.FEATURES")
    if not enforcement_active():
        return None
    ent = await service.current(request)
    if not ent.has(feature):
        raise PaymentRequired(feature_payload(feature, ent))
    return ent


def require_paid(feature: str):
    """FastAPI dependency factory: 402 unless the tenant's plan includes ``feature``.

    Unknown names raise at import time (typos must not silently open or lock a route).
    """
    if feature not in licensing.FEATURES:
        raise ValueError(f"unknown licensable feature {feature!r}; add it to licensing.FEATURES")

    async def _dep(request: Request) -> None:
        await ensure_feature(request, feature)

    _dep.__name__ = f"require_paid_{feature}"
    return _dep


async def check_quota(request: Request, dimension: str, adding: int = 0) -> None:
    """Raise 402 ``quota_exceeded`` when ``used + adding`` is over the plan limit."""
    if not enforcement_active():
        return
    ent = await service.current(request)
    limit = ent.limit(dimension)
    if limit is None:
        return
    used = await service.count_usage(request.app.state.pool, dimension)
    if used is None:
        return  # unknown usage never blocks
    if used + adding > limit:
        raise PaymentRequired(quota_payload(dimension, ent, used, limit))


def require_quota(dimension: str, adding: int = 0):
    """Dependency: refuse GROWTH once a quota is exceeded (reads stay open).

    ``adding`` is how many units the request would add: ``1`` for creating a
    seat (so the Nth seat is allowed and the N+1th is not); ``0`` for actions
    whose yield is unknown (a scan) - those are refused only once usage is
    already strictly over the limit.
    """
    if dimension not in ("seats", "sites", "assets"):
        raise ValueError(f"unknown quota dimension {dimension!r}")

    async def _dep(request: Request) -> None:
        await check_quota(request, dimension, adding)

    _dep.__name__ = f"require_quota_{dimension}"
    return _dep


async def scans_allowed(pool) -> bool:
    """For the scheduler: False while the current tenant is over its asset
    quota under enforced billing. Fails open on any error."""
    if not enforcement_active():
        return True
    try:
        lic = await licensing.load_active_license(pool)
        ent = await service.resolve(pool, lic)
        limit = ent.limit("assets")
        if limit is None:
            return True
        used = await service.count_usage(pool, "assets")
        return used is None or used <= limit
    except Exception:  # noqa: BLE001
        logger.exception("scans_allowed_failed")
        return True
