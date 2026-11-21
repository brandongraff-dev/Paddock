"""MSP console API (schema 033). Design + threat model: docs/MSP.md.

* ``GET  /v1/msp/me``                          who am I (MSP user / delegated / ordinary tenant)
* ``GET  /v1/msp/customers``                   paginated customers with health (the caller's grants only)
* ``GET  /v1/msp/summary``                     fleet totals
* ``POST /v1/msp/customers``                   provision a customer + onboarding invite   (admin)
* ``POST /v1/msp/customers/{id}/switch``       exchange for a short-lived customer-scoped token
* ``POST /v1/msp/customers/{id}/suspend|reactivate|invites``                              (admin + admin grant)
* ``GET|POST /v1/msp/grants``, ``DELETE /v1/msp/grants/{id}``                             (admin)
* ``GET|POST /v1/msp/templates``, ``PUT|DELETE /v1/msp/templates/{id}``, ``POST .../apply`` (admin)
* ``GET  /v1/msp/usage`` (``?format=csv``), ``POST /v1/msp/usage/snapshot``               (admin)
* ``POST /v1/msp/invites/redeem``              public: the invite token is the credential
"""
from __future__ import annotations

import logging
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field

from .. import audit, tenancy
from ..auth import client_ip, current_principal, require
from ..db import get_pool
from ..msp import core, health, lifecycle
from ..msp.core import DelegationError, MspContext

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/msp", tags=["msp"])

_Clearance = Literal["public", "internal", "confidential", "restricted"]


# --------------------------------------------------------------------------- #
# Models
# --------------------------------------------------------------------------- #

class CustomerIn(BaseModel):
    slug: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,62}$")
    name: str = Field(min_length=1, max_length=200)
    invite_label: str | None = Field(default=None, max_length=200)


class InviteIn(BaseModel):
    label: str | None = Field(default=None, max_length=200)


class GrantIn(BaseModel):
    user_id: UUID
    customer_id: UUID | None = Field(default=None, description="null = every current and future customer")
    role: Literal["viewer", "analyst", "admin"]
    clearance: _Clearance = "internal"


class AlertRuleT(BaseModel):
    name: str = Field(min_length=1, max_length=256)
    match: dict[str, Any] = Field(default_factory=dict)
    channel: Literal["log", "webhook", "slack"]
    target: str | None = Field(default=None, max_length=2048)
    enabled: bool = True


class IntegrationT(BaseModel):
    kind: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=100)
    enabled: bool = True
    config: dict[str, Any] = Field(default_factory=dict)
    secrets: dict[str, str | None] = Field(default_factory=dict)
    events: list[str] = Field(default_factory=list)
    min_severity: str = "low"
    filters: dict[str, Any] = Field(default_factory=dict)
    allow_private: bool = False


class ScopeSuggestionT(BaseModel):
    kind: Literal["domain", "subdomain_wildcard", "ipv4_cidr", "ipv6_cidr", "asn"]
    value: str = Field(min_length=1, max_length=512)
    notes: str | None = Field(default=None, max_length=500)


class TemplateIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=1000)
    alert_rules: list[AlertRuleT] = Field(default_factory=list, max_length=50)
    integrations: list[IntegrationT] = Field(default_factory=list, max_length=20)
    scope_suggestions: list[ScopeSuggestionT] = Field(default_factory=list, max_length=100)


class ApplyIn(BaseModel):
    customer_ids: list[UUID] = Field(min_length=1, max_length=500)


class RedeemIn(BaseModel):
    token: str = Field(min_length=20, max_length=200)
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._@-]*$")
    password: str = Field(min_length=12, max_length=256)
    email: str | None = Field(default=None, max_length=320)
    display_name: str | None = Field(default=None, max_length=200)


# --------------------------------------------------------------------------- #
# Context
# --------------------------------------------------------------------------- #

def _rid(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


async def msp_context(request: Request, pool=Depends(get_pool)) -> MspContext:
    """The calling MSP user. Refuses delegated sessions (no nesting), tenants
    that are not an MSP, and principals that cannot hold grants."""
    p = current_principal(request)
    if p.msp_delegation:
        raise HTTPException(status_code=403, detail="MSP console routes cannot be used from inside a customer")
    if p.kind not in ("user", "apikey") or not p.user_id:
        raise HTTPException(status_code=403, detail="the MSP console needs a signed-in MSP user")
    tid = p.tenant_id or tenancy.current_tenant_id()
    org = await core.get_org(pool, tid) if tid else None
    if org is None:
        raise HTTPException(status_code=403, detail="this tenant is not an MSP organisation")
    return MspContext(msp_tenant_id=str(tid), user_id=p.user_id, username=p.actor, role=p.role, org=org)


# --------------------------------------------------------------------------- #
# Identity
# --------------------------------------------------------------------------- #

@router.get("/me")
async def msp_me(request: Request, pool=Depends(get_pool)) -> dict[str, Any]:
    p = current_principal(request)
    if p.msp_delegation:
        d = p.msp_delegation
        return {
            "mode": "delegated",
            "is_msp": False,
            "msp": {"name": d["msp_name"], "slug": d["msp_slug"]},
            "msp_user": d["msp_user"],
            "customer": {"id": d["child_tenant_id"], "slug": d["child_slug"], "name": d["child_name"]},
            "grant_role": d["grant_role"],
        }
    tid = p.tenant_id or tenancy.current_tenant_id()
    org = await core.get_org(pool, tid) if tid and p.user_id else None
    if org is None:
        return {"mode": "none", "is_msp": False}
    return {"mode": "msp", "is_msp": True, "org": {"name": org["name"], "max_customers": org["max_children"]}}


# --------------------------------------------------------------------------- #
# Customers: list / rollup
# --------------------------------------------------------------------------- #

@router.get("/customers")
async def list_customers(
    q: str | None = Query(default=None, max_length=100),
    sort: str = Query(default="name"),
    order: Literal["asc", "desc"] = "asc",
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    refresh: bool = False,
    ctx: MspContext = Depends(msp_context),
    pool=Depends(get_pool),
) -> dict[str, Any]:
    if sort not in health.SORTS:
        raise HTTPException(status_code=422, detail=f"sort must be one of {sorted(health.SORTS)}")
    return await health.list_customers(
        pool, ctx.msp_tenant_id, ctx.user_id, q=q, sort=sort, desc=order == "desc",
        limit=limit, offset=offset, refresh=refresh,
    )


@router.get("/summary")
async def customers_summary(ctx: MspContext = Depends(msp_context), pool=Depends(get_pool)) -> dict[str, Any]:
    return await health.summary(pool, ctx.msp_tenant_id, ctx.user_id)


@router.post("/customers", status_code=201)
async def create_customer(
    body: CustomerIn, request: Request, ctx: MspContext = Depends(msp_context), pool=Depends(get_pool),
) -> dict[str, Any]:
    return await lifecycle.create_customer(
        pool, ctx, slug=body.slug, name=body.name, request_id=_rid(request), ip=client_ip(request),
        invite_label=body.invite_label,
    )


# --------------------------------------------------------------------------- #
# Switch (token exchange)
# --------------------------------------------------------------------------- #

@router.post("/customers/{customer_id}/switch")
async def switch_customer(
    customer_id: UUID, request: Request, ctx: MspContext = Depends(msp_context), pool=Depends(get_pool),
) -> dict[str, Any]:
    p = current_principal(request)
    if p.kind != "user":
        # API keys carry scopes the child token could not honour; switching is
        # an interactive, session-bound act.
        raise HTTPException(status_code=403, detail="switching needs an interactive (signed-in) MSP session")
    cid = str(customer_id)
    try:
        facts = await core.resolve_delegation(pool, ctx.msp_tenant_id, ctx.user_id, cid)
    except DelegationError as exc:
        await audit.record(
            pool, tenant_id=ctx.msp_tenant_id, action="msp.switch_denied", actor=ctx.username,
            actor_role=ctx.role, resource_type="tenant", resource_id=cid, request_id=_rid(request),
            ip=client_ip(request), details={"reason": exc.detail, "status": exc.status},
        )
        raise HTTPException(status_code=exc.status, detail=exc.detail) from None
    token, ttl = core.issue_switch_token(facts=facts)
    child_actor = f"msp:{facts['msp_slug']}/{ctx.username}"
    await core.audit_both(
        pool, msp_tid=ctx.msp_tenant_id, child_tid=cid, action="msp.switch", actor=ctx.username,
        actor_role=ctx.role, child_actor=child_actor, resource_type="tenant", resource_id=cid,
        request_id=_rid(request), ip=client_ip(request),
        msp_details={"customer": facts["child_slug"], "grant_role": facts["role"], "ttl_sec": ttl},
        child_details={"msp": facts["msp_slug"], "msp_user": ctx.username, "grant_role": facts["role"],
                       "ttl_sec": ttl},
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": ttl,
        "role": facts["role"],
        "clearance": facts["clearance"],
        "customer": {"id": cid, "slug": facts["child_slug"], "name": facts["child_name"]},
        "msp": {"slug": facts["msp_slug"], "name": facts["msp_name"]},
    }


# --------------------------------------------------------------------------- #
# Lifecycle
# --------------------------------------------------------------------------- #

@router.post("/customers/{customer_id}/suspend")
async def suspend_customer(
    customer_id: UUID, request: Request, ctx: MspContext = Depends(msp_context), pool=Depends(get_pool),
) -> dict[str, Any]:
    return await lifecycle.set_customer_status(
        pool, ctx, str(customer_id), "suspended", request_id=_rid(request), ip=client_ip(request)
    )


@router.post("/customers/{customer_id}/reactivate")
async def reactivate_customer(
    customer_id: UUID, request: Request, ctx: MspContext = Depends(msp_context), pool=Depends(get_pool),
) -> dict[str, Any]:
    return await lifecycle.set_customer_status(
        pool, ctx, str(customer_id), "active", request_id=_rid(request), ip=client_ip(request)
    )


@router.post("/customers/{customer_id}/invites", status_code=201)
async def new_invite(
    customer_id: UUID, body: InviteIn, request: Request, ctx: MspContext = Depends(msp_context),
    pool=Depends(get_pool),
) -> dict[str, Any]:
    cid = str(customer_id)
    facts = await lifecycle.require_grant(pool, ctx, cid, "admin")
    return await lifecycle.create_invite(
        pool, msp_tid=ctx.msp_tenant_id, child_id=cid, created_by=f"msp:{facts['msp_slug']}/{ctx.username}",
        msp_user=ctx.username, actor_role=ctx.role, label=body.label, request_id=_rid(request),
        ip=client_ip(request),
    )


@router.post("/invites/redeem", status_code=201)
async def redeem_invite(body: RedeemIn, request: Request, pool=Depends(get_pool)) -> dict[str, Any]:
    """Public. The invite token is the credential; it is single use, expires,
    and only works while the customer is active."""
    return await lifecycle.redeem_invite(
        pool, token=body.token, username=body.username, password=body.password, email=body.email,
        display_name=body.display_name, request_id=_rid(request), ip=client_ip(request),
    )


# --------------------------------------------------------------------------- #
# Grants
# --------------------------------------------------------------------------- #

@router.get("/grants", dependencies=[Depends(require("admin"))])
async def list_grants(
    user_id: UUID | None = None, ctx: MspContext = Depends(msp_context), pool=Depends(get_pool),
) -> dict[str, Any]:
    items = await lifecycle.list_grants(pool, ctx, user_id=str(user_id) if user_id else None)
    return {"items": items, "total": len(items)}


@router.post("/grants", status_code=201)
async def set_grant(
    body: GrantIn, request: Request, ctx: MspContext = Depends(msp_context), pool=Depends(get_pool),
) -> dict[str, Any]:
    return await lifecycle.set_grant(
        pool, ctx, user_id=str(body.user_id), child_id=str(body.customer_id) if body.customer_id else None,
        role=body.role, clearance=body.clearance, request_id=_rid(request), ip=client_ip(request),
    )


@router.delete("/grants/{grant_id}")
async def revoke_grant(
    grant_id: UUID, request: Request, ctx: MspContext = Depends(msp_context), pool=Depends(get_pool),
) -> dict[str, Any]:
    return await lifecycle.revoke_grant(
        pool, ctx, str(grant_id), request_id=_rid(request), ip=client_ip(request)
    )


# --------------------------------------------------------------------------- #
# Templates
# --------------------------------------------------------------------------- #

@router.get("/templates", dependencies=[Depends(require("admin"))])
async def list_templates(ctx: MspContext = Depends(msp_context), pool=Depends(get_pool)) -> dict[str, Any]:
    with tenancy.tenant_context(ctx.msp_tenant_id):
        async with pool.acquire() as con:
            rows = await con.fetch("SELECT * FROM msp_templates ORDER BY name")
    return {"items": [lifecycle.template_out(r) for r in rows], "total": len(rows)}


@router.post("/templates", status_code=201)
async def create_template(
    body: TemplateIn, ctx: MspContext = Depends(msp_context), pool=Depends(get_pool),
) -> dict[str, Any]:
    return await lifecycle.save_template(pool, ctx, template_id=None, body=body.model_dump())


@router.put("/templates/{template_id}")
async def update_template(
    template_id: UUID, body: TemplateIn, ctx: MspContext = Depends(msp_context), pool=Depends(get_pool),
) -> dict[str, Any]:
    return await lifecycle.save_template(pool, ctx, template_id=str(template_id), body=body.model_dump())


@router.delete("/templates/{template_id}")
async def delete_template(
    template_id: UUID, ctx: MspContext = Depends(msp_context), pool=Depends(get_pool),
) -> dict[str, Any]:
    with tenancy.tenant_context(ctx.msp_tenant_id):
        async with pool.acquire() as con:
            res = await con.execute("DELETE FROM msp_templates WHERE id = $1", str(template_id))
    if res.endswith(" 0"):
        raise HTTPException(status_code=404, detail="template not found")
    return {"deleted": True}


@router.post("/templates/{template_id}/apply")
async def apply_template(
    template_id: UUID, body: ApplyIn, request: Request, ctx: MspContext = Depends(msp_context),
    pool=Depends(get_pool),
) -> dict[str, Any]:
    return await lifecycle.apply_template(
        pool, request.app, ctx, str(template_id), [str(c) for c in body.customer_ids],
        request_id=_rid(request), ip=client_ip(request),
    )


# --------------------------------------------------------------------------- #
# Usage (MSP billing)
# --------------------------------------------------------------------------- #

@router.get("/usage", dependencies=[Depends(require("admin"))])
async def usage(
    month: str | None = Query(default=None, pattern=r"^\d{4}-(0[1-9]|1[0-2])$"),
    format: Literal["json", "csv"] = "json",
    ctx: MspContext = Depends(msp_context),
    pool=Depends(get_pool),
):
    children = await core.granted_children(pool, ctx.msp_tenant_id, ctx.user_id)
    report = await health.usage_report(pool, ctx.msp_tenant_id, children, month)
    if format == "csv":
        return Response(
            content=health.usage_csv(report),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="paddock-msp-usage-{report["month"]}.csv"'},
        )
    return report


@router.post("/usage/snapshot")
async def usage_snapshot(ctx: MspContext = Depends(msp_context), pool=Depends(get_pool)) -> dict[str, Any]:
    """Record today's per-customer usage (cron-able). Idempotent per day."""
    children = await core.granted_children(pool, ctx.msp_tenant_id, ctx.user_id)
    n = await health.snapshot_usage(pool, ctx.msp_tenant_id, children)
    return {"snapshotted": n}
