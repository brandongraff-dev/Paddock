"""Shareable trust / posture pages for insurers and customers.

An admin mints a link (``POST /v1/trust-links``): a signed 256-bit random
token, an expiry, optional password, and the sections to include. The token
is shown ONCE and only its SHA-256 is stored. Anyone holding the URL can open
``/trust/<token>`` (``GET /v1/public/trust/<token>``) until it expires or is
revoked, and sees ONLY aggregates for the chosen sections -- counts,
percentages, grades -- never a finding, host name, address or asset value.

Cross-tenant lookup without a tenant: the viewer is anonymous, so the token
hash is resolved in a short transaction that sets two transaction-local GUCs
read by the ``trust_public_lookup`` RLS policy (schema 032). That policy can
return exactly one row (the matching hash); everything after the lookup runs
as the link's own tenant.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .. import audit, tenancy
from .. import auth as auth_svc
from ..auth import Principal, client_ip, current_principal
from ..db import get_pool
from . import abuse
from .config import growth_settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/trust-links", tags=["trust"])
public_router = APIRouter(prefix="/v1/public/trust", tags=["public"])

SECTIONS = ("grade", "verified_fixes", "sla", "compliance", "coverage")
SECTION_LABELS = {
    "grade": "Security grade",
    "verified_fixes": "Verified fixes",
    "sla": "Remediation SLA compliance",
    "compliance": "Compliance pack summary",
    "coverage": "Coverage",
}
TOKEN_PREFIX = "pt1"
_CACHE_SEC = 300


# --------------------------------------------------------------------------- #
# Tokens
# --------------------------------------------------------------------------- #

def _signing_keys() -> list[bytes]:
    keys: list[bytes] = []
    for var in ("PADDOCK_SECRET_KEY", "PADDOCK_SECRET_KEY_OLD"):
        for raw in filter(None, (os.environ.get(var) or "").split(",")):
            keys.append(hashlib.sha256(b"paddock-trust|" + raw.strip().encode()).digest())
    # No persistent key configured: the signature is a format check only (the
    # 256-bit random body is the secret). Set PADDOCK_SECRET_KEY to key it.
    return keys or [hashlib.sha256(b"paddock-trust|unkeyed").digest()]


def _sig(body: str, key: bytes) -> str:
    mac = hmac.new(key, f"{TOKEN_PREFIX}.{body}".encode(), hashlib.sha256).digest()[:16]
    return base64.urlsafe_b64encode(mac).decode().rstrip("=")


def new_token() -> str:
    body = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    return f"{TOKEN_PREFIX}.{body}.{_sig(body, _signing_keys()[0])}"


def token_well_formed(token: str) -> bool:
    """Cheap forgery filter before any database work."""
    if not isinstance(token, str) or len(token) > 128:
        return False
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != TOKEN_PREFIX or len(parts[1]) != 43:
        return False
    return any(hmac.compare_digest(parts[2], _sig(parts[1], k)) for k in _signing_keys())


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# --------------------------------------------------------------------------- #
# Models
# --------------------------------------------------------------------------- #

class TrustLinkIn(BaseModel):
    label: str = Field(..., min_length=1, max_length=120)
    sections: list[Literal["grade", "verified_fixes", "sla", "compliance", "coverage"]] = Field(
        default_factory=lambda: ["grade"], min_length=1
    )
    expires_in_days: int = Field(30, ge=1, le=365)
    period_days: int = Field(30, ge=1, le=365)
    password: Optional[str] = Field(None, min_length=8, max_length=200)


class TrustLinkOut(BaseModel):
    id: uuid.UUID
    label: str
    sections: list[str]
    period_days: int
    created_at: datetime
    created_by: Optional[str] = None
    expires_at: datetime
    revoked_at: Optional[datetime] = None
    password_protected: bool
    view_count: int
    last_viewed_at: Optional[datetime] = None
    token_hint: str
    status: Literal["active", "expired", "revoked"]


class TrustLinkCreated(TrustLinkOut):
    token: str
    path: str


class TrustUnlockIn(BaseModel):
    password: Optional[str] = Field(None, max_length=200)


def _out(r) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    status = "revoked" if r["revoked_at"] else ("expired" if r["expires_at"] <= now else "active")
    return {
        "id": r["id"], "label": r["label"], "sections": list(r["sections"]),
        "period_days": r["period_days"], "created_at": r["created_at"], "created_by": r["created_by"],
        "expires_at": r["expires_at"], "revoked_at": r["revoked_at"],
        "password_protected": bool(r["password_hash"]), "view_count": r["view_count"],
        "last_viewed_at": r["last_viewed_at"], "token_hint": r["token_hint"], "status": status,
    }


_COLS = ("id, label, sections, period_days, created_at, created_by, expires_at, revoked_at, "
         "password_hash, view_count, last_viewed_at, token_hint")


# --------------------------------------------------------------------------- #
# Management (admin)
# --------------------------------------------------------------------------- #

@router.post("", response_model=TrustLinkCreated, status_code=201)
async def create_link(body: TrustLinkIn, pool=Depends(get_pool), principal: Principal = Depends(current_principal)):
    token = new_token()
    h = hash_token(token)
    sections = [s for s in SECTIONS if s in set(body.sections)]
    pw = auth_svc.hash_password(body.password) if body.password else None
    expires = datetime.now(timezone.utc) + timedelta(days=min(body.expires_in_days, growth_settings.trust_max_days))
    async with pool.acquire() as con:
        r = await con.fetchrow(
            f"""INSERT INTO trust_links (label, token_hash, token_hint, sections, period_days, expires_at,
                                         password_hash, created_by)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING {_COLS}""",
            body.label.strip(), h, h[-4:], sections, body.period_days, expires, pw, principal.actor,
        )
    return {**_out(r), "token": token, "path": f"/trust/{token}"}


@router.get("", response_model=list[TrustLinkOut])
async def list_links(pool=Depends(get_pool)):
    async with pool.acquire() as con:
        rows = await con.fetch(f"SELECT {_COLS} FROM trust_links ORDER BY created_at DESC LIMIT 500")
    return [_out(r) for r in rows]


@router.get("/sections")
async def list_sections():
    return [{"key": k, "label": SECTION_LABELS[k]} for k in SECTIONS]


@router.delete("/{link_id}", response_model=TrustLinkOut)
async def revoke_link(link_id: uuid.UUID, pool=Depends(get_pool)):
    """Revoke (kept, with its view history, for the audit trail)."""
    async with pool.acquire() as con:
        r = await con.fetchrow(
            f"""UPDATE trust_links SET revoked_at = COALESCE(revoked_at, NOW())
                 WHERE id = $1 RETURNING {_COLS}""",
            link_id,
        )
    if r is None:
        raise HTTPException(status_code=404, detail="trust link not found")
    return _out(r)


# --------------------------------------------------------------------------- #
# Public viewing
# --------------------------------------------------------------------------- #

async def _lookup(pool, token: str) -> dict[str, Any] | None:
    """Resolve a token to its link row across tenants (see module docstring)."""
    h = hash_token(token)
    with tenancy.auth_lookup():  # no tenant stamped on the connection
        async with pool.acquire() as con:
            async with con.transaction():
                await con.execute(
                    "SELECT set_config('app.trust_lookup', 'on', true), set_config('app.trust_hash', $1, true)", h
                )
                r = await con.fetchrow(
                    f"SELECT {_COLS}, tenant_id FROM trust_links WHERE token_hash = $1", h
                )
    return dict(r) if r else None


def _unavailable() -> HTTPException:
    return HTTPException(status_code=404, detail="this link is not available")


async def build_sections(pool, sections: list[str], days: int) -> dict[str, Any]:
    """Aggregates only. Runs in the link's tenant context."""
    from ..reports import compliance
    from ..reports.config import report_settings
    from ..reports.metrics import build_report

    r = await build_report(pool, days=days, clearance="restricted", top=1)
    out: dict[str, Any] = {}
    if "grade" in sections:
        o = r.exposure.open_end
        w = {"critical": 15, "high": 6, "medium": 2, "low": 0.5, "info": 0}
        pen = sum(o.get(k, 0) * v for k, v in w.items())
        score = max(0, round(100 - min(100, pen)))
        grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 65 else "D" if score >= 50 else "F"
        trend = "stable"
        if r.exposure.delta < 0:
            trend = "improving"
        elif r.exposure.delta > 0:
            trend = "worsening"
        out["grade"] = {
            "grade": grade, "score": score, "trend": trend, "open_by_severity": dict(o),
            "open_critical_high": o.get("critical", 0) + o.get("high", 0),
        }
    if "verified_fixes" in sections:
        rs = r.resolutions
        out["verified_fixes"] = {
            "fixed": rs.fixed, "verified": rs.verified, "regressed": rs.regressed,
            "pending_verification": rs.pending_verification, "fixed_by_severity": dict(rs.fixed_by_severity),
            "median_hours_to_fix": r.mttr.overall.median_hours if r.mttr.overall else None,
        }
    if "sla" in sections:
        sl = r.sla
        out["sla"] = {
            "compliance_pct": sl.compliance_pct, "met": sl.met, "late": sl.late,
            "breached_open": sl.breached_open,
            "by_severity": [
                {"severity": x.severity, "policy_hours": x.policy_hours, "met": x.met, "late": x.late,
                 "breached_open": x.breached_open, "compliance_pct": x.compliance_pct}
                for x in sl.by_severity
            ],
        }
    if "compliance" in sections:
        sums = await compliance.summaries(pool, clearance="restricted")
        out["compliance"] = [
            {"id": f.id, "name": f.name, "version": f.version, "total": f.total, "automated": f.automated,
             "counts": dict(f.counts)}
            for f in sums
        ]
    if "coverage" in sections:
        c = r.coverage
        out["coverage"] = {
            "assets_total": c.assets_total,
            "by_kind": [{"kind": k.kind, "total": k.total, "seen_7d": k.seen_7d, "stale": k.stale} for k in c.by_kind],
            "scans_by_status": dict(c.scans_by_status),
            "last_completed_scan": c.last_completed_scan.isoformat() if c.last_completed_scan else None,
            "sbom_projects": c.sbom_projects, "tls_graded": c.tls_graded, "tls_below_b": c.tls_below_b,
            "fleet_agents": c.fleet_agents, "fleet_agents_recent": c.fleet_agents_recent,
        }
    out["_org"] = report_settings.org_name
    return out


async def _sections_cached(pool, redis, link: dict[str, Any]) -> dict[str, Any]:
    key = f"growth:trust:{link['id']}:{','.join(link['sections'])}:{link['period_days']}"
    try:
        raw = await redis.get(key)
        if raw:
            return json.loads(raw)
    except Exception:  # noqa: BLE001
        pass
    data = await build_sections(pool, list(link["sections"]), link["period_days"])
    try:
        await redis.set(key, json.dumps(data, default=str), ex=_CACHE_SEC)
    except Exception:  # noqa: BLE001
        pass
    return data


async def view(pool, redis, token: str, password: str | None, ip: str | None) -> dict[str, Any]:
    if not token_well_formed(token):
        raise _unavailable()
    link = await _lookup(pool, token)
    now = datetime.now(timezone.utc)
    if link is None or link["revoked_at"] is not None or link["expires_at"] <= now:
        raise _unavailable()
    tenant_id = str(link["tenant_id"])

    if link["password_hash"]:
        if not password:
            raise HTTPException(status_code=401, detail={"code": "password_required"})
        await abuse.hit(
            redis, f"growth:trustpw:{link['id']}:{abuse.ip_hash(ip)}",
            growth_settings.trust_max_password_attempts, 900, what="password attempts",
        )
        if not auth_svc.verify_password(password, link["password_hash"]):
            with tenancy.tenant_context(tenant_id):
                await audit.record(
                    pool, action="deny", actor=f"trust-link:{link['id']}", resource_type="trust_link",
                    resource_id=str(link["id"]), ip=ip, details={"reason": "bad_password"}, tenant_id=tenant_id,
                )
            raise HTTPException(status_code=401, detail={"code": "password_incorrect"})

    with tenancy.tenant_context(tenant_id):
        data = await _sections_cached(pool, redis, link)
        async with pool.acquire() as con:
            async with con.transaction():
                count = await con.fetchval(
                    """UPDATE trust_links SET view_count = view_count + 1, last_viewed_at = NOW()
                        WHERE id = $1 RETURNING view_count""",
                    link["id"],
                )
                await audit.record(
                    pool, action="read", actor=f"trust-link:{link['id']}", resource_type="trust_link",
                    resource_id=str(link["id"]), ip=ip,
                    details={"view_count": count, "sections": list(link["sections"])},
                    con=con, tenant_id=tenant_id,
                )
    org = data.pop("_org", None)
    return {
        "organization": org,
        "generated_at": now.isoformat(),
        "period_days": link["period_days"],
        "expires_at": link["expires_at"].isoformat(),
        "sections": [s for s in SECTIONS if s in data],
        "data": data,
    }


@public_router.get("/{token}")
async def public_view_get(token: str, request: Request, pool=Depends(get_pool)):
    redis = request.app.state.redis
    ip = client_ip(request)
    await abuse.limit_ip_get(redis, ip)
    body = await view(pool, redis, token, request.headers.get("x-trust-password"), ip)
    return JSONResponse(body, headers={"Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow"})


@public_router.post("/{token}")
async def public_view_post(token: str, body: TrustUnlockIn, request: Request, pool=Depends(get_pool)):
    redis = request.app.state.redis
    ip = client_ip(request)
    await abuse.limit_ip_get(redis, ip)
    out = await view(pool, redis, token, body.password, ip)
    return JSONResponse(out, headers={"Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow"})
