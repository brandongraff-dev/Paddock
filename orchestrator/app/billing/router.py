"""Billing API (hosted edition).

* ``GET  /v1/billing``           -- plan, entitlements, usage vs quota, trial/dunning (read)
* ``POST /v1/billing/checkout``  -- Stripe Checkout Session for Team / Enterprise (admin)
* ``POST /v1/billing/portal``    -- Stripe Customer Portal session (admin)
* ``POST /v1/billing/webhook``   -- Stripe webhooks (public; authenticated by signature)

Billing is OFF unless ``STRIPE_SECRET_KEY`` is set: ``GET`` then reports
``enabled: false`` (plus the installed license), and the POSTs answer 503.
"""
from __future__ import annotations

import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .. import licensing, tenancy
from ..auth import current_principal
from ..db import get_pool
from . import events, service, store
from .config import plans, settings
from .gate import enforcement_active
from .stripe import StripeError, make_client

logger = logging.getLogger(__name__)

router = APIRouter(tags=["billing"])

_LIVE = {"active", "trialing", "past_due"}


class PlanOut(BaseModel):
    key: str
    name: str
    edition: str
    seats: int | None
    sites: int | None
    assets: int | None
    purchasable: bool = Field(description="True when a Stripe price id is configured for this plan.")


class QuotaOut(BaseModel):
    used: int | None
    limit: int | None
    over: bool


class BillingOut(BaseModel):
    enabled: bool
    enforcement: bool
    edition: str
    status: str
    source: str
    plan: str | None
    features: list[str]
    limits: dict[str, int | None]
    usage: dict[str, QuotaOut]
    trial_ends_at: datetime | None
    trial_days_left: int | None
    grace_ends_at: datetime | None
    current_period_end: datetime | None
    cancel_at_period_end: bool
    downgraded: bool
    dunning: bool
    read_only: bool = Field(description="Downgraded to Community limits AND over one of them: growth is refused.")
    can_manage: bool = Field(description="A Stripe customer exists, so the Customer Portal can be opened.")
    plans: list[PlanOut]
    upgrade_url: str


class CheckoutIn(BaseModel):
    plan: str = Field(pattern="^(team|enterprise)$")


class UrlOut(BaseModel):
    url: str


def _require_enabled() -> None:
    if not settings.enabled:
        raise HTTPException(status_code=503, detail={"error": "billing_not_configured"})


def _return_url(path: str) -> str:
    base = (settings.billing_public_url or "").rstrip("/")
    if not base.startswith(("https://", "http://")):
        raise HTTPException(status_code=503, detail={"error": "billing_public_url_not_set"})
    return base + path


@router.get("/v1/billing", response_model=BillingOut)
async def get_billing(request: Request, pool=Depends(get_pool)):
    lic = await licensing.current_license(request)
    ent = await service.resolve(pool, lic)
    used = {dim: await service.count_usage(pool, dim) for dim in ("seats", "sites", "assets")}
    quota = service.quota_state(ent, used)
    read_only = bool(ent.downgraded and any(q["over"] for q in quota.values()))
    d = ent.as_dict()
    return BillingOut(
        enabled=settings.enabled,
        enforcement=enforcement_active(),
        edition=d["edition"], status=d["status"], source=d["source"], plan=d["plan"],
        features=d["features"], limits=d["limits"],
        usage={k: QuotaOut(**v) for k, v in quota.items()},
        trial_ends_at=d["trial_ends_at"], trial_days_left=d["trial_days_left"],
        grace_ends_at=d["grace_ends_at"], current_period_end=d["current_period_end"],
        cancel_at_period_end=d["cancel_at_period_end"], downgraded=d["downgraded"],
        dunning=d["dunning"], read_only=read_only, can_manage=d["has_customer"],
        plans=[
            PlanOut(key=p.key, name=p.name, edition=p.edition, seats=p.seats, sites=p.sites,
                    assets=p.assets, purchasable=bool(p.price_id))
            for p in plans().values()
        ],
        upgrade_url=(settings.billing_public_url or "").rstrip("/") + "/settings/billing",
    )


async def _tenant_customer(request: Request, pool, tenant_id: str, create: bool) -> str | None:
    """The tenant's Stripe customer id, optionally creating (and linking) one."""
    sub = await store.get_subscription(pool)
    customer = (sub or {}).get("stripe_customer_id") or await store.customer_for_tenant(pool, tenant_id)
    if customer or not create:
        return customer
    client = make_client(request.app)
    async with pool.acquire() as con:
        name = await con.fetchval("SELECT name FROM tenants WHERE id = $1::uuid", tenant_id)
    created = await client.create_customer(
        tenant_id=tenant_id, name=name, idempotency_key=f"paddock-customer-{tenant_id}",
    )
    customer = created.get("id")
    if not customer:
        raise StripeError("stripe returned no customer id")
    await store.link_customer(pool, customer, tenant_id)
    return customer


def _stripe_failure(exc: StripeError) -> HTTPException:
    logger.warning("billing_stripe_error", extra={"status": exc.status, "code": exc.code})
    return HTTPException(status_code=502, detail={"error": "stripe_error", "message": str(exc)})


@router.post("/v1/billing/checkout", response_model=UrlOut)
async def create_checkout(body: CheckoutIn, request: Request, pool=Depends(get_pool)):
    _require_enabled()
    plan = plans()[body.plan]
    if not plan.price_id:
        raise HTTPException(status_code=503, detail={"error": "plan_not_configured", "plan": body.plan})
    success = _return_url("/settings/billing?checkout=success")
    cancel = _return_url("/settings/billing?checkout=canceled")
    tenant_id = current_principal(request).tenant_id or tenancy.current_tenant_id()
    if not tenant_id:
        raise HTTPException(status_code=400, detail={"error": "no_tenant"})
    sub = await store.get_subscription(pool)
    if sub and sub["status"] in _LIVE and sub.get("plan"):
        # Plan changes and payment updates happen in the Customer Portal; a
        # second Checkout would create a second, double-billed subscription.
        raise HTTPException(status_code=409, detail={"error": "already_subscribed", "use": "portal"})
    try:
        customer = await _tenant_customer(request, pool, tenant_id, create=True)
        session = await make_client(request.app).create_checkout_session(
            customer=customer or "", price_id=plan.price_id, plan=plan.key, tenant_id=tenant_id,
            success_url=success, cancel_url=cancel,
        )
    except StripeError as exc:
        raise _stripe_failure(exc) from exc
    url = session.get("url")
    if not isinstance(url, str) or not url.startswith("https://"):
        raise HTTPException(status_code=502, detail={"error": "stripe_error", "message": "no checkout url"})
    return UrlOut(url=url)


@router.post("/v1/billing/portal", response_model=UrlOut)
async def create_portal(request: Request, pool=Depends(get_pool)):
    _require_enabled()
    tenant_id = current_principal(request).tenant_id or tenancy.current_tenant_id()
    if not tenant_id:
        raise HTTPException(status_code=400, detail={"error": "no_tenant"})
    return_url = _return_url("/settings/billing")
    customer = await _tenant_customer(request, pool, tenant_id, create=False)
    if not customer:
        raise HTTPException(status_code=409, detail={"error": "no_customer", "use": "checkout"})
    try:
        session = await make_client(request.app).create_portal_session(customer=customer, return_url=return_url)
    except StripeError as exc:
        raise _stripe_failure(exc) from exc
    url = session.get("url")
    if not isinstance(url, str) or not url.startswith("https://"):
        raise HTTPException(status_code=502, detail={"error": "stripe_error", "message": "no portal url"})
    return UrlOut(url=url)


@router.post("/v1/billing/webhook", include_in_schema=True)
async def stripe_webhook(request: Request) -> JSONResponse:
    """Stripe -> Paddock. Public route: the ``Stripe-Signature`` header is the
    authentication (HMAC-SHA256 over ``timestamp.body``, tolerance window,
    replay protection by event id). Always answers fast; 5xx makes Stripe retry."""
    try:
        declared = int(request.headers.get("content-length") or 0)
    except ValueError:
        declared = 0
    if declared > events.MAX_BODY_BYTES:
        return JSONResponse({"error": "payload_too_large"}, status_code=413)
    # No Content-Length (chunked) must not mean no cap: this route is public and
    # the body is only authenticated AFTER it is read, so stop at the limit.
    buf = bytearray()
    async for chunk in request.stream():
        buf.extend(chunk)
        if len(buf) > events.MAX_BODY_BYTES:
            return JSONResponse({"error": "payload_too_large"}, status_code=413)
    raw = bytes(buf)
    result = await events.handle_webhook(request.app, raw, request.headers.get("stripe-signature"))
    return JSONResponse(result.body, status_code=result.status)

