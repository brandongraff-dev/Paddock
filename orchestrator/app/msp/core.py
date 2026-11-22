"""MSP core: settings, grants, the child-scoped switch token, delegated audit.

Security model (docs/MSP.md has the long form):

* An MSP is a tenant with a row in ``msp_orgs``. Its customers are rows in
  ``msp_children`` (owned by the MSP tenant, invisible to the customers).
* An MSP user acts inside a customer only via a **switch token**: a short-lived
  JWT (``typ=msp_switch``) minted by ``POST /v1/msp/customers/{id}/switch``
  after the grant check. The token is only an *introduction*: on EVERY request
  ``principal_from_switch_token`` re-reads the user, the grant, the membership
  and both tenants' status from the database, and derives the role from the
  live grant. Revoking a grant, suspending the customer, deactivating the MSP
  user or suspending the MSP therefore takes effect on the very next request.
* The resulting Principal carries ``tenant_id = <customer>`` (so the ordinary
  request-scoped tenant context / RLS applies, one concrete tenant, no
  exceptions) and ``msp_delegation`` (who is really acting). The governance
  middleware writes every request of such a principal to BOTH audit chains.
* The token is NOT accepted as an ordinary access token (``verify_jwt``
  insists on ``typ=access``), and a delegated principal cannot reach
  ``/v1/msp/*`` (no chaining), mint API keys, or configure SSO/SCIM
  (``delegated_route_denied``): nothing the MSP does can outlive its grant.
"""
from __future__ import annotations

import logging
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any

import jwt
from pydantic_settings import BaseSettings, SettingsConfigDict

from .. import audit, tenancy
from ..auth import CLASS_RANK, CLASSIFICATIONS, Principal, capabilities_for
from ..config import settings

logger = logging.getLogger(__name__)

SWITCH_TYP = "msp_switch"
GRANT_ROLES = ("viewer", "analyst", "admin")


class MspSettings(BaseSettings):
    """Env-driven knobs (MSP_*); kept out of config.py on purpose."""

    model_config = SettingsConfigDict(env_prefix="MSP_", env_file=".env", extra="ignore")

    switch_ttl_sec: int = 900          # lifetime of a child-scoped token
    health_ttl_sec: int = 300          # how long cached per-customer health is fresh
    rollup_max_children: int = 500     # cap on children recomputed in one request
    invite_ttl_hours: int = 72
    max_apply_batch: int = 200         # customers per template application


msp_settings = MspSettings()


def switch_ttl() -> int:
    return max(60, min(int(msp_settings.switch_ttl_sec), 3600))


class DelegationError(Exception):
    """A switch / delegated request was refused. ``status`` is the HTTP code
    the API should answer with; ``detail`` is safe to show."""

    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


# --------------------------------------------------------------------------- #
# Organisation / grants (all reads run under the MSP's own tenant context)
# --------------------------------------------------------------------------- #

async def get_org(pool, msp_tid: str) -> dict[str, Any] | None:
    with tenancy.tenant_context(msp_tid):
        async with pool.acquire() as con:
            row = await con.fetchrow(
                "SELECT id, name, max_children, created_at FROM msp_orgs WHERE tenant_id = $1",
                msp_tid,
            )
    return dict(row) if row else None


async def tenant_status(pool, tenant_id: str) -> str | None:
    """Status from the global catalogue (readable by the app role)."""
    async with pool.acquire() as con:
        return await con.fetchval("SELECT status FROM tenants WHERE id = $1", tenant_id)


def min_clearance(a: str | None, b: str | None) -> str:
    ra = CLASS_RANK.get(a or "internal", 1)
    rb = CLASS_RANK.get(b or "internal", 1)
    return CLASSIFICATIONS[min(ra, rb)]


# The grant a user effectively holds on each customer: the per-customer row if
# there is one, else the "all customers" row. Parameter $1 = user id.
GRANTED_CHILDREN_SQL = """
SELECT c.child_tenant_id, c.slug, c.name, c.created_at,
       COALESCE(gs.role, ga.role)           AS role,
       COALESCE(gs.clearance, ga.clearance) AS clearance
  FROM msp_children c
  LEFT JOIN msp_grants gs ON gs.user_id = $1 AND gs.child_tenant_id = c.child_tenant_id
  LEFT JOIN msp_grants ga ON ga.user_id = $1 AND ga.child_tenant_id IS NULL
 WHERE COALESCE(gs.role, ga.role) IS NOT NULL
"""


async def granted_children(pool, msp_tid: str, user_id: str) -> list[dict[str, Any]]:
    """Every customer ``user_id`` holds an effective grant on (unpaginated ids;
    callers page/slice). Runs under the MSP's tenant context."""
    with tenancy.tenant_context(msp_tid):
        async with pool.acquire() as con:
            rows = await con.fetch(GRANTED_CHILDREN_SQL + " ORDER BY c.name, c.child_tenant_id", user_id)
    return [dict(r) for r in rows]


async def resolve_delegation(pool, msp_tid: str, user_id: str, child_id: str) -> dict[str, Any]:
    """Decide (live, from the database) whether ``user_id`` of MSP ``msp_tid``
    may act in ``child_id`` right now. Returns the delegation facts or raises
    :class:`DelegationError`. No caller-supplied role is trusted."""
    with tenancy.tenant_context(msp_tid):
        async with pool.acquire() as con:
            user = await con.fetchrow(
                "SELECT id, username, role, clearance, active, sessions_revoked_at "
                "  FROM app_users WHERE id = $1",
                user_id,
            )
            org = await con.fetchrow("SELECT name FROM msp_orgs WHERE tenant_id = $1", msp_tid)
            row = await con.fetchrow(
                GRANTED_CHILDREN_SQL + " AND c.child_tenant_id = $2", user_id, child_id
            )
            msp_slug = await con.fetchval("SELECT slug FROM tenants WHERE id = $1", msp_tid)
            child_status = await con.fetchval("SELECT status FROM tenants WHERE id = $1", child_id)
            msp_status = await con.fetchval("SELECT status FROM tenants WHERE id = $1", msp_tid)
    if user is None or not user["active"]:
        raise DelegationError(401, "MSP user not found or disabled")
    if org is None:
        raise DelegationError(403, "tenant is not an MSP")
    if msp_status != "active":
        raise DelegationError(403, "MSP tenant is suspended")
    if row is None:
        # Not a customer of this MSP, or no grant: one answer for both so a
        # caller cannot probe which tenant ids exist.
        raise DelegationError(403, "no access grant for this customer")
    if child_status != "active":
        raise DelegationError(409, "customer is suspended")
    return {
        "msp_tenant_id": str(msp_tid),
        "msp_slug": msp_slug,
        "msp_name": org["name"],
        "user_id": str(user["id"]),
        "username": user["username"],
        "user_role": user["role"],
        "sessions_revoked_at": user["sessions_revoked_at"],
        "child_tenant_id": str(row["child_tenant_id"]),
        "child_slug": row["slug"],
        "child_name": row["name"],
        "role": row["role"],
        "clearance": min_clearance(row["clearance"], user["clearance"]),
    }


# --------------------------------------------------------------------------- #
# Switch token
# --------------------------------------------------------------------------- #

def issue_switch_token(*, facts: dict[str, Any]) -> tuple[str, int]:
    from ..auth import _jwt_secret

    now = int(time.time())
    ttl = switch_ttl()
    claims = {
        "typ": SWITCH_TYP,
        "sub": facts["user_id"],
        "username": facts["username"],
        "mtid": facts["msp_tenant_id"],
        "tid": facts["child_tenant_id"],
        "role": facts["role"],           # informational: the live grant decides
        "jti": secrets.token_urlsafe(12),
        "iat": now,
        "nbf": now,
        "exp": now + ttl,
    }
    token = jwt.encode(claims, _jwt_secret(), algorithm=settings.jwt_algorithm)
    if isinstance(token, bytes):
        token = token.decode("ascii")
    return token, ttl


def is_switch_token(token: str) -> bool:
    """Routing only (which verifier runs); the claim is NOT trusted for access."""
    try:
        return jwt.decode(token, options={"verify_signature": False}).get("typ") == SWITCH_TYP
    except jwt.PyJWTError:
        return False


def verify_switch_token(token: str) -> dict[str, Any]:
    from ..auth import _jwt_secret

    claims = jwt.decode(
        token,
        _jwt_secret(),
        algorithms=[settings.jwt_algorithm],
        options={"require": ["exp", "iat", "sub", "mtid", "tid"]},
    )
    if claims.get("typ") != SWITCH_TYP:
        raise jwt.InvalidTokenError("not a switch token")
    return claims


def principal_from_facts(facts: dict[str, Any]) -> Principal:
    role = facts["role"]
    return Principal(
        actor=f"msp:{facts['msp_slug']}/{facts['username']}",
        role=role,
        clearance=facts["clearance"],
        capabilities=capabilities_for(role),
        kind="msp",
        user_id=facts["user_id"],
        tenant_id=facts["child_tenant_id"],
        msp_delegation={
            "msp_tenant_id": facts["msp_tenant_id"],
            "msp_slug": facts["msp_slug"],
            "msp_name": facts["msp_name"],
            "msp_user": facts["username"],
            "msp_user_id": facts["user_id"],
            "grant_role": role,
            "child_tenant_id": facts["child_tenant_id"],
            "child_slug": facts["child_slug"],
            "child_name": facts["child_name"],
        },
    )


async def principal_from_switch_token(request, token: str) -> Principal:
    """Resolve a switch token to a delegated Principal, re-checking everything
    against the database. Raises ``auth.AuthError`` (-> 401) on any failure."""
    from ..auth import AuthError

    try:
        claims = verify_switch_token(token)
    except jwt.PyJWTError as exc:
        raise AuthError(f"invalid token: {exc!s}") from exc
    pool = getattr(request.app.state, "pool", None)
    if pool is None:
        raise AuthError("auth backend unavailable")
    try:
        msp_tid = tenancy._norm(claims["mtid"])
        child_tid = tenancy._norm(claims["tid"])
        user_id = str(claims["sub"])
    except (ValueError, TypeError) as exc:
        raise AuthError("invalid token") from exc
    try:
        facts = await resolve_delegation(pool, msp_tid, user_id, child_tid)
    except DelegationError as exc:
        await _audit_refused(pool, msp_tid, user_id, child_tid, exc.detail, request)
        raise AuthError(exc.detail) from exc
    revoked = facts["sessions_revoked_at"]
    if revoked is not None and float(claims.get("iat", 0)) <= revoked.timestamp():
        raise AuthError("session revoked")
    return principal_from_facts(facts)


async def _audit_refused(pool, msp_tid: str, user_id: str, child_tid: str, reason: str, request) -> None:
    """A once-valid token was refused: leave a trace in the MSP's trail."""
    try:
        await audit.record(
            pool,
            tenant_id=msp_tid,
            action="msp.switch_refused",
            actor=str(user_id),
            resource_type="tenant",
            resource_id=child_tid,
            method=getattr(request, "method", None),
            path=request.url.path,
            status=401,
            request_id=getattr(request.state, "request_id", None),
            details={"reason": reason, "child_tenant_id": child_tid},
        )
    except Exception:  # noqa: BLE001 -- the refusal itself never depends on the trace
        logger.exception("msp_refusal_audit_failed")


# --------------------------------------------------------------------------- #
# Routes a delegated principal may NOT use
# --------------------------------------------------------------------------- #

_DELEGATED_DENY: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^/v1/msp(/.*)?$"), "MSP console routes cannot be used from inside a customer"),
    (re.compile(r"^/v1/auth/apikeys(/.*)?$"), "MSP sessions cannot mint or revoke customer API keys"),
    (re.compile(r"^/v1/auth/sso/admin(/.*)?$"), "MSP sessions cannot configure customer SSO"),
    (re.compile(r"^/scim/v2(/.*)?$"), "SCIM is not available to MSP sessions"),
    # The customer's own payment relationship and licence are theirs to change.
    (re.compile(r"^/v1/billing/(checkout|portal)$"), "MSP sessions cannot change a customer's billing"),
)
# Path patterns denied only for state-changing methods (reads stay allowed).
_DELEGATED_DENY_WRITES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^/v1/license(/.*)?$"), "MSP sessions cannot change a customer's licence"),
    # Sensor enrollment tokens mint sensor credentials that outlive the grant.
    (re.compile(r"^/v1/sensors/tokens(/.*)?$"), "MSP sessions cannot create customer sensor enrollment tokens"),
    # A trust link is a public bearer URL to the customer's posture.
    (re.compile(r"^/v1/trust-links(/.*)?$"), "MSP sessions cannot create or change customer trust links"),
    # Ingest tokens are persistent credentials, like API keys.
    (re.compile(r"^/v1/ingest/sources(/.*)?$"), "MSP sessions cannot mint or rotate customer ingest tokens"),
)
_READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
# /v1/msp/me is how the dashboard learns who it is; it is read-only.
_DELEGATED_ALLOW = frozenset({"/v1/msp/me"})


def delegated_route_denied(
    principal: Principal | None, path: str, method: str = "GET",
) -> str | None:
    """Reason a delegated principal may not call ``path`` (None = allowed)."""
    if principal is None or not principal.msp_delegation:
        return None
    p = path.rstrip("/") or "/"
    if p in _DELEGATED_ALLOW:
        return None
    for pat, why in _DELEGATED_DENY:
        if pat.match(p):
            return why
    if method.upper() not in _READ_METHODS:
        for pat, why in _DELEGATED_DENY_WRITES:
            if pat.match(p):
                return why
    return None


# --------------------------------------------------------------------------- #
# Audit: every delegated request lands in BOTH chains
# --------------------------------------------------------------------------- #

def delegation_details(principal: Principal) -> dict[str, Any]:
    d = principal.msp_delegation or {}
    return {
        "msp_tenant_id": d.get("msp_tenant_id"),
        "msp": d.get("msp_slug"),
        "msp_user": d.get("msp_user"),
        "msp_user_id": d.get("msp_user_id"),
        "grant_role": d.get("grant_role"),
    }


async def mirror_to_msp_trail(
    pool,
    principal: Principal,
    *,
    action: str,
    method: str | None,
    path: str | None,
    status: int | None,
    request_id: str | None,
    ip: str | None,
    details: dict[str, Any] | None,
) -> dict[str, Any]:
    """Append the MSP-side record of a delegated request (the customer-side row
    is written by the caller with the delegated actor + ``delegation_details``)."""
    d = principal.msp_delegation or {}
    return await audit.record(
        pool,
        tenant_id=d["msp_tenant_id"],
        action="msp.act",
        actor=d["msp_user"],
        actor_role=d.get("grant_role"),
        resource_type="tenant",
        resource_id=d["child_tenant_id"],
        method=method,
        path=path,
        status=status,
        ip=ip,
        request_id=request_id,
        details={
            "child": d.get("child_slug"),
            "child_tenant_id": d["child_tenant_id"],
            "customer_action": action,
            **(details or {}),
        },
    )


async def audit_both(
    pool,
    *,
    msp_tid: str,
    child_tid: str | None,
    action: str,
    actor: str,
    actor_role: str | None,
    child_actor: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    request_id: str | None = None,
    ip: str | None = None,
    msp_details: dict[str, Any] | None = None,
    child_details: dict[str, Any] | None = None,
) -> None:
    """Explicit lifecycle events (switch, provision, suspend, template apply)
    in the MSP trail and, when a customer is involved, in the customer's too."""
    await audit.record(
        pool,
        tenant_id=msp_tid,
        action=action,
        actor=actor,
        actor_role=actor_role,
        resource_type=resource_type,
        resource_id=resource_id,
        ip=ip,
        request_id=request_id,
        details=msp_details or {},
    )
    if child_tid:
        await audit.record(
            pool,
            tenant_id=child_tid,
            action=action,
            actor=child_actor or actor,
            actor_role=actor_role,
            resource_type=resource_type,
            resource_id=resource_id,
            ip=ip,
            request_id=request_id,
            details={"msp_tenant_id": msp_tid, **(child_details or msp_details or {})},
        )


@dataclass(frozen=True)
class MspContext:
    """The calling MSP user, as the console routes see it."""

    msp_tenant_id: str
    user_id: str
    username: str
    role: str
    org: dict[str, Any]
