"""Authentication, RBAC + ABAC, and the governance middleware.

This module is the security spine added by schema 011. It provides:

* Credential primitives -- API-key generation/hashing (``pak_<prefix>_<secret>``,
  only the sha256 is ever stored), JWT issue/verify (PyJWT, short-lived), and
  password hashing (bcrypt, with a stdlib ``scrypt`` fallback so the service
  still boots if the optional wheel is missing).
* ``Principal`` -- the resolved caller: actor, role, clearance, and the
  effective capability set (role capabilities unioned with API-key scopes).
* ``resolve_principal`` -- turns a request's credentials into a ``Principal``.
* The RBAC policy (``required_capability``) + ABAC helpers (classification
  ranks and the SQL rank expression the read queries filter on).
* ``GovernanceMiddleware`` -- resolves the principal, enforces RBAC deny-closed,
  and writes the tamper-evident audit trail for mutating / denied / restricted
  requests.
* FastAPI dependencies ``current_principal``, ``require(role)``,
  ``require_scope(scope)`` for defence-in-depth on individual routers.

Dev-vs-enforce: when ``AUTH_MODE=dev`` (the current default) an unauthenticated
request is given a synthetic admin principal -- loudly logged -- so the worker
fleet and the existing test-suite keep working. ``AUTH_MODE=enforce`` denies
closed. The default is intentionally NOT flipped here; the compose/hardening
stream owns that switch.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

import jwt
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from . import audit, job_binding, service_routes, tenancy
from .config import settings

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Classification (ABAC). rank: public < internal < confidential < restricted
# --------------------------------------------------------------------------- #

CLASSIFICATIONS: tuple[str, ...] = ("public", "internal", "confidential", "restricted")
CLASS_RANK: dict[str, int] = {c: i for i, c in enumerate(CLASSIFICATIONS)}
_DEFAULT_CLASS = "internal"


def clearance_rank(clearance: str | None) -> int:
    """Rank for a clearance/classification label (unknown -> internal)."""
    return CLASS_RANK.get(clearance or _DEFAULT_CLASS, CLASS_RANK[_DEFAULT_CLASS])


def classification_rank_sql(col: str) -> str:
    """A SQL CASE expression mapping a classification column to its int rank.

    ``col`` is always a hard-coded, internal column reference (e.g.
    ``"a.classification"``) -- never user input -- so building it as a string
    is injection-safe. Used to push the ABAC filter into the DB so that
    over-classified rows never leave Postgres.
    """
    whens = " ".join(f"WHEN {col} = '{c}' THEN {i}" for c, i in CLASS_RANK.items())
    return f"(CASE {whens} ELSE {CLASS_RANK[_DEFAULT_CLASS]} END)"


# --------------------------------------------------------------------------- #
# Roles -> capabilities (RBAC)
# --------------------------------------------------------------------------- #
#   read   : view non-restricted assets/findings/etc.
#   triage : patch findings/tickets/anomalies/changes
#   scan   : request scans, trigger recompute/retrain
#   ask     : natural-language "Ask" queries
#   write  : service ingest (bulk upserts, scan lifecycle)
#   audit  : read the audit log + run integrity verify
#   admin  : scope/owners/alerts/schedules/keys -- everything

ROLE_CAPABILITIES: dict[str, frozenset[str]] = {
    "viewer": frozenset({"read"}),
    "analyst": frozenset({"read", "triage", "scan", "ask"}),
    "auditor": frozenset({"read", "audit"}),
    "admin": frozenset({"read", "triage", "scan", "ask", "write", "audit", "admin"}),
    # `service` is not a DB role; it is the synthetic principal behind the
    # per-service API key (env SERVICE_API_KEY). It can ingest + run ops, but
    # never touches admin config or the audit log.
    "service": frozenset({"read", "write", "triage", "scan", "ask"}),
}

# API-key scope strings map 1:1 onto capabilities; anything else is ignored.
_VALID_SCOPES = frozenset({"read", "triage", "scan", "ask", "write", "audit", "admin"})


def capabilities_for(role: str, scopes: frozenset[str] | set[str] | None = None) -> frozenset[str]:
    """Capabilities of a principal.

    API-key scopes can only NARROW the owning user's role, never widen it:
    an admin's key minted with ["read"] is read-only, and a viewer's key
    minted with ["admin"] is still a viewer (and stays one after demotion).
    """
    caps = set(ROLE_CAPABILITIES.get(role, ROLE_CAPABILITIES["viewer"]))
    if scopes is not None:
        caps &= {s for s in scopes if s in _VALID_SCOPES}
    return frozenset(caps)


@dataclass(frozen=True)
class Principal:
    actor: str
    role: str
    clearance: str
    capabilities: frozenset[str]
    kind: str  # user | apikey | service | dev
    user_id: str | None = None
    api_key_id: str | None = None
    raw_scopes: tuple[str, ...] = field(default_factory=tuple)
    # The tenant every query of this principal is scoped to (Postgres RLS).
    # None = the context default (the default tenant unless TENANCY_STRICT).
    tenant_id: str | None = None
    # Set only for an MSP user acting inside a customer tenant (app/msp): who
    # is really acting and for which MSP. ``tenant_id`` is then the customer.
    msp_delegation: dict[str, Any] | None = None

    @property
    def clearance_rank(self) -> int:
        return clearance_rank(self.clearance)

    def has(self, capability: str) -> bool:
        return capability in self.capabilities


def dev_principal() -> Principal:
    return Principal(
        actor="dev-admin",
        role="admin",
        clearance="restricted",
        capabilities=capabilities_for("admin"),
        kind="dev",
        tenant_id=tenancy.DEFAULT_TENANT_ID,
    )


def service_principal(tenant_id: str | None = None) -> Principal:
    """The shared service key. It acts in the tenant named by the
    ``X-Paddock-Tenant`` header (resolved by ``resolve_principal``), else the
    context default."""
    return Principal(
        actor="service",
        role="service",
        clearance="restricted",
        capabilities=capabilities_for("service"),
        kind="service",
        tenant_id=tenant_id,
    )


# --------------------------------------------------------------------------- #
# Password hashing (bcrypt preferred; stdlib scrypt fallback)
# --------------------------------------------------------------------------- #

def _bcrypt():
    try:
        import bcrypt  # type: ignore

        return bcrypt
    except Exception:  # noqa: BLE001
        return None


def hash_password(password: str) -> str:
    """Return a self-describing password hash (``<scheme>$...``)."""
    pw = password.encode("utf-8")
    b = _bcrypt()
    if b is not None:
        # bcrypt caps the input at 72 bytes; pre-hash so long passwords keep
        # their full entropy and we stay under the limit.
        digest = hashlib.sha256(pw).digest()
        return "bcrypt$" + b.hashpw(digest, b.gensalt()).decode("ascii")
    salt = os.urandom(16)
    dk = hashlib.scrypt(pw, salt=salt, n=2**14, r=8, p=1, dklen=32)
    return "scrypt$" + salt.hex() + "$" + dk.hex()


def verify_password(password: str, stored: str | None) -> bool:
    if not stored:
        return False
    pw = password.encode("utf-8")
    try:
        if stored.startswith("bcrypt$"):
            b = _bcrypt()
            if b is None:
                return False
            digest = hashlib.sha256(pw).digest()
            return bool(b.checkpw(digest, stored[len("bcrypt$"):].encode("ascii")))
        if stored.startswith("scrypt$"):
            _, salt_hex, dk_hex = stored.split("$", 2)
            salt = bytes.fromhex(salt_hex)
            dk = hashlib.scrypt(pw, salt=salt, n=2**14, r=8, p=1, dklen=len(bytes.fromhex(dk_hex)))
            return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:  # noqa: BLE001
        return False
    return False


# --------------------------------------------------------------------------- #
# API keys: pak_<prefix>_<secret>, store only sha256(full)
# --------------------------------------------------------------------------- #

def hash_api_key(full_key: str) -> str:
    return hashlib.sha256(full_key.encode("utf-8")).hexdigest()


def generate_api_key() -> tuple[str, str, str]:
    """Return (full_key, prefix, key_hash). The full key is shown once."""
    prefix = secrets.token_hex(4)  # 8 hex chars, stored + shown in UI
    secret = secrets.token_urlsafe(32)
    full = f"pak_{prefix}_{secret}"
    return full, prefix, hash_api_key(full)


# SCIM bearer tokens (schema 020): pscim_<prefix>_<secret>, sha256 at rest.
# They resolve to a principal whose ONLY capability is `scim`.
SCIM_TOKEN_PREFIX = "pscim_"


def generate_scim_token() -> tuple[str, str, str]:
    """Return (full_token, prefix, token_hash). The full token is shown once."""
    prefix = secrets.token_hex(4)
    full = f"{SCIM_TOKEN_PREFIX}{prefix}_{secrets.token_urlsafe(32)}"
    return full, prefix, hash_api_key(full)


# --------------------------------------------------------------------------- #
# JWT
# --------------------------------------------------------------------------- #

_RUNTIME_JWT_SECRET = secrets.token_urlsafe(48)


def _jwt_secret() -> str:
    return settings.jwt_secret or _RUNTIME_JWT_SECRET


def issue_jwt(
    *,
    user_id: str | None,
    username: str,
    role: str,
    clearance: str,
    tenant_id: str | None = None,
) -> tuple[str, int]:
    now = int(time.time())
    ttl = int(settings.jwt_ttl_sec)
    payload = {
        "sub": user_id or username,
        "username": username,
        "role": role,
        "clearance": clearance,
        "typ": "access",
        "iat": now,
        "nbf": now,
        "exp": now + ttl,
    }
    if tenant_id:
        payload["tid"] = str(tenant_id)
    token = jwt.encode(payload, _jwt_secret(), algorithm=settings.jwt_algorithm)
    # PyJWT<2 returns bytes; normalise.
    if isinstance(token, bytes):
        token = token.decode("ascii")
    return token, ttl


def verify_jwt(token: str) -> dict[str, Any]:
    claims = jwt.decode(
        token,
        _jwt_secret(),
        algorithms=[settings.jwt_algorithm],
        options={"require": ["exp", "iat", "sub"]},
    )
    if claims.get("typ") != "access":
        raise jwt.InvalidTokenError("not an access token")
    return claims


# --------------------------------------------------------------------------- #
# Credential resolution
# --------------------------------------------------------------------------- #

class AuthError(Exception):
    """A presented credential was invalid (-> 401)."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


def _extract_credentials(request: Request) -> tuple[str | None, str | None]:
    """Return (api_key, jwt_token) pulled from the request headers."""
    api_key = request.headers.get("x-api-key")
    if api_key:
        api_key = api_key.strip()
    token: str | None = None
    auth = request.headers.get("authorization")
    if auth and auth.lower().startswith("bearer "):
        bearer = auth[7:].strip()
        if bearer.startswith("pak_"):
            api_key = api_key or bearer
        elif bearer.startswith("pdi_"):
            pass  # per-source ingest token: checked by POST /v1/ingest itself, not a principal
        else:
            token = bearer
    return api_key, token


async def _principal_from_api_key(request: Request, key: str) -> Principal:
    pool = getattr(request.app.state, "pool", None)
    if pool is None:
        raise AuthError("auth backend unavailable")
    key_hash = hash_api_key(key)
    # The tenant is unknown until the key row is read: look it up in
    # auth-lookup mode (app_users/api_keys readable across tenants; nothing
    # else is), then the principal carries the key's tenant.
    with tenancy.auth_lookup():
        async with pool.acquire() as con:
            row = await con.fetchrow(
                """
                SELECT k.id AS key_id, k.scopes, k.expires_at, k.revoked,
                       u.id AS user_id, u.username, u.role, u.clearance, u.active,
                       u.tenant_id, t.status AS tenant_status
                  FROM api_keys k
                  JOIN app_users u ON u.id = k.user_id AND u.tenant_id = k.tenant_id
                  LEFT JOIN tenants t ON t.id = u.tenant_id
                 WHERE k.key_hash = $1
                """,
                key_hash,
            )
            if row is None or row["revoked"] or not row["active"]:
                raise AuthError("invalid API key")
            if row["tenant_status"] != "active":
                raise AuthError("tenant suspended")
            exp = row["expires_at"]
            if exp is not None and exp <= datetime.now(timezone.utc):
                raise AuthError("API key expired")
            await con.execute("UPDATE api_keys SET last_used = NOW() WHERE id = $1", row["key_id"])
    scopes = frozenset(row["scopes"] or ["read"])
    return Principal(
        actor=row["username"],
        role=row["role"],
        clearance=row["clearance"],
        capabilities=capabilities_for(row["role"], scopes),
        kind="apikey",
        user_id=str(row["user_id"]),
        api_key_id=str(row["key_id"]),
        raw_scopes=tuple(row["scopes"] or ["read"]),
        tenant_id=str(row["tenant_id"]),
    )


async def _principal_from_jwt(request: Request, token: str) -> Principal:
    try:
        claims = verify_jwt(token)
    except jwt.PyJWTError as exc:  # expired, bad signature, etc.
        raise AuthError(f"invalid token: {exc!s}") from exc
    pool = getattr(request.app.state, "pool", None)
    username = claims.get("username") or claims.get("sub")
    role = claims.get("role", "viewer")
    clearance = claims.get("clearance", _DEFAULT_CLASS)
    user_id = claims.get("sub")
    tenant_id = claims.get("tid")
    # Prefer live DB state (role/clearance/active/tenant) over possibly-stale claims.
    if pool is not None and username:
        with tenancy.auth_lookup():
            async with pool.acquire() as con:
                row = await con.fetchrow(
                    "SELECT u.id, u.username, u.role, u.clearance, u.active, u.tenant_id, "
                    "       u.sessions_revoked_at, t.status AS tenant_status "
                    "  FROM app_users u LEFT JOIN tenants t ON t.id = u.tenant_id "
                    " WHERE u.username = $1",
                    username,
                )
        if row is None:
            # Deleted user: never fall back to trusting role claims in a token.
            raise AuthError("unknown user")
        if row is not None:
            if not row["active"]:
                raise AuthError("user disabled")
            # Session watermark (schema 020): SCIM deactivation etc. revokes
            # every token issued at or before it, even after re-activation.
            revoked = row["sessions_revoked_at"]
            if revoked is not None and float(claims.get("iat", 0)) <= revoked.timestamp():
                raise AuthError("session revoked")
            if row["tenant_status"] != "active":
                raise AuthError("tenant suspended")
            if tenant_id and str(tenant_id) != str(row["tenant_id"]):
                raise AuthError("token tenant mismatch")
            tenant_id = str(row["tenant_id"])
            role = row["role"]
            clearance = row["clearance"]
            user_id = str(row["id"])
            username = row["username"]
    return Principal(
        actor=str(username),
        role=role,
        clearance=clearance,
        capabilities=capabilities_for(role),
        kind="user",
        user_id=str(user_id) if user_id else None,
        tenant_id=str(tenant_id) if tenant_id else None,
    )


async def _principal_from_scim_token(request: Request, token: str) -> Principal:
    pool = getattr(request.app.state, "pool", None)
    if pool is None:
        raise AuthError("auth backend unavailable")
    # Like API keys: the tenant is unknown until the token row is read, so the
    # lookup runs in auth-lookup mode (schema 036 adds a SELECT-only policy on
    # scim_tokens for it). Before this the lookup ran in the DEFAULT tenant, so
    # SCIM tokens of every other tenant were rejected, and the principal named
    # no tenant at all.
    with tenancy.auth_lookup():
        async with pool.acquire() as con:
            row = await con.fetchrow(
                "SELECT s.id, s.name, s.expires_at, s.revoked, s.tenant_id, t.status AS tenant_status "
                "  FROM scim_tokens s LEFT JOIN tenants t ON t.id = s.tenant_id "
                " WHERE s.token_hash = $1",
                hash_api_key(token),
            )
    if row is None or row["revoked"]:
        raise AuthError("invalid SCIM token")
    if row["tenant_status"] != "active":
        raise AuthError("tenant suspended")
    if row["expires_at"] is not None and row["expires_at"] <= datetime.now(timezone.utc):
        raise AuthError("SCIM token expired")
    tid = str(row["tenant_id"])
    with tenancy.tenant_context(tid):
        async with pool.acquire() as con:
            await con.execute("UPDATE scim_tokens SET last_used = NOW() WHERE id = $1", row["id"])
    return Principal(
        actor=f"scim:{row['name']}",
        role="scim",
        clearance="public",
        capabilities=frozenset({"scim"}),  # SCIM only -- never capabilities_for()
        kind="scim",
        api_key_id=str(row["id"]),
        tenant_id=tid,
    )


# Service-key routes whose tenant comes from a second credential, not from the
# caller: otdiscovery brackets a managed sensor's upload with claim/done, and
# the orchestrator resolves the tenant from the sensor's own credential
# (X-Sensor-Token), then does all work inside that tenant. Under
# TENANCY_STRICT these may omit X-Paddock-Tenant; every other service call
# must still name one.
_TENANTLESS_SERVICE_PATHS = re.compile(r"^/v1/sensors/ingest/(claim|done)$")


async def resolve_principal(request: Request) -> Principal | None:
    """Resolve a request's credential to a Principal, or None if none presented.

    Raises ``AuthError`` when a credential IS presented but is invalid.
    """
    api_key, token = _extract_credentials(request)
    if token and token.startswith(SCIM_TOKEN_PREFIX):
        return await _principal_from_scim_token(request, token)
    if api_key:
        svc = settings.service_api_key
        # compare bytes: compare_digest(str, str) raises on non-ASCII input,
        # which used to surface as an unaudited 500.
        if svc and hmac.compare_digest(api_key.encode("utf-8"), svc.encode("utf-8")):
            ref = request.headers.get(tenancy.TENANT_HEADER)
            if not ref:
                if settings.tenancy_strict and not _TENANTLESS_SERVICE_PATHS.match(request.url.path):
                    # The service key is a fleet credential, not a tenant: in a
                    # multi-tenant deployment every call must say whose it is.
                    raise AuthError("service key requires X-Paddock-Tenant (TENANCY_STRICT)")
                return service_principal()
            pool = getattr(request.app.state, "pool", None)
            tid = await tenancy.resolve_tenant_ref(pool, ref) if pool is not None else None
            if tid is None:
                raise AuthError("unknown or inactive tenant")
            return service_principal(tid)
        return await _principal_from_api_key(request, api_key)
    if token:
        from . import msp as msp_svc

        if msp_svc.is_switch_token(token):  # MSP user acting in a customer (app/msp)
            return await msp_svc.principal_from_switch_token(request, token)
        return await _principal_from_jwt(request, token)
    return None


# --------------------------------------------------------------------------- #
# RBAC policy: (method, path) -> required capability
# --------------------------------------------------------------------------- #


# Ordered rules. First match wins. Patterns match the concrete request path
# (with real ids). `None` capability means the route is public (no auth).
_RULES: list[tuple[frozenset[str], re.Pattern[str], str | None]] = []


def _rule(methods: str, pattern: str, cap: str | None) -> None:
    _RULES.append((frozenset(methods.split()), re.compile("^" + pattern + "$"), cap))


_ANY = r"[^/]+"

# --- public ---------------------------------------------------------------- #
_rule("POST", r"/v1/auth/login", None)
# Two-way ticket sync callbacks (Jira/ServiceNow/Linear). Authenticated by the
# integration's inbound token / webhook signature inside the handler instead.
_rule("POST", rf"/v1/integrations/{_ANY}/inbound", None)
# Universal ingest: authenticated in the handler by a per-source ingest token
# (scoped to ingest only) or an API key with `scan`. Management is admin-only.
_rule("GET POST PATCH DELETE", r"/v1/ingest/(sources|log)(/.*)?", "admin")
_rule("POST", r"/v1/ingest", None)

# --- SSO (schema 020): admin config first, then the public login flow ------ #
_rule("GET POST PUT PATCH DELETE", r"/v1/auth/sso/admin(/.*)?", "admin")
_rule("GET", r"/v1/auth/sso/providers", None)
_rule("POST", r"/v1/auth/sso/exchange", None)
_rule("GET", rf"/v1/auth/sso/{_ANY}/(start|callback|metadata)", None)
_rule("POST", rf"/v1/auth/sso/{_ANY}/acs", None)
# SAML single logout: IdP messages are verified (signature) inside the handler;
# the SP-initiated logout needs a signed-in session.
_rule("GET", rf"/v1/auth/sso/{_ANY}/sls", None)
_rule("POST", r"/v1/auth/sso/logout", "read")

# --- SCIM 2.0: only a SCIM token carries the `scim` capability -------------- #
_rule("GET POST PUT PATCH DELETE", r"/scim/v2(/.*)?", "scim")

# --- read-only operational checks that use non-GET verbs ------------------- #
_rule("POST", r"/v1/scope/check", "read")

# --- auth self + key management -------------------------------------------- #
_rule("GET", r"/v1/auth/me", "read")
_rule("GET POST DELETE", rf"/v1/auth/apikeys(/{_ANY})?", "admin")

# --- audit log (auditor + admin) ------------------------------------------- #
_rule("GET", r"/v1/audit(/verify)?", "audit")

# --- provenance ------------------------------------------------------------ #
_rule("POST", r"/v1/provenance/backfill", "admin")
_rule("GET", r"/v1/provenance", "read")

# --- admin config: scope / owners / alert-rules / schedules / sla ---------- #
_rule("POST DELETE PATCH PUT", rf"/v1/scope(/{_ANY})?", "admin")
_rule("POST", rf"/v1/scope/{_ANY}/(challenge|verify)", "admin")  # proof-of-control (021)
_rule("PUT PATCH POST", r"/v1/onboarding", "admin")  # first-run wizard (021)
_rule("POST DELETE PATCH PUT", rf"/v1/owners(/{_ANY})?", "admin")
_rule("POST DELETE PATCH PUT", rf"/v1/alert-rules(/{_ANY})?", "admin")
_rule("POST DELETE PATCH PUT", rf"/v1/schedules(/{_ANY}(/run-now)?)?", "admin")
_rule("PATCH", rf"/v1/sla-policies/{_ANY}", "admin")

# --- integrations (reads: read; every write: admin) ------------------------ #
_rule("GET", r"/v1/integrations(/catalog|/health)?", "read")
_rule("GET", rf"/v1/integrations/{_ANY}(/deliveries)?", "read")
_rule("POST", r"/v1/integrations", "admin")
_rule("PATCH PUT DELETE", rf"/v1/integrations/{_ANY}", "admin")
_rule("POST", rf"/v1/integrations/{_ANY}/(test|enable|disable)", "admin")
_rule("POST", rf"/v1/integrations/{_ANY}/deliveries/{_ANY}/retry", "admin")

# --- triage (analyst + admin) ---------------------------------------------- #
_rule("PATCH", rf"/v1/findings/{_ANY}", "triage")
_rule("PATCH", rf"/v1/tickets/{_ANY}", "triage")
_rule("POST", rf"/v1/anomalies/{_ANY}/ack", "triage")
_rule("POST", rf"/v1/changes/{_ANY}/ack", "triage")
# finding lifecycle (schema 019): transitions + suppression rules
_rule("POST", rf"/v1/findings/{_ANY}/(accept|false-positive|reopen)", "triage")
_rule("POST PATCH DELETE", rf"/v1/suppressions(/{_ANY})?", "triage")

# --- scan / operational triggers (analyst + admin + service) --------------- #
_rule("POST", r"/v1/scans", "scan")
_rule("POST", r"/v1/attack-paths/recompute", "scan")
# Wargame change gate: read-only evaluation of a proposed plan (nothing stored
# or applied), usable from CI with a `scan`-scoped key. Other wargame writes
# (twin ingest, recompute) stay on the deny-closed admin default.
_rule("POST", r"/v1/wargame/change-impact", "scan")
_rule("POST", r"/v1/ml/retrain", "scan")

# --- ask -------------------------------------------------------------------- #
_rule("POST", r"/v1/ask", "ask")

# --- reports: read everywhere; sending a digest on demand is admin --------- #
_rule("POST", r"/v1/reports/digest/send", "admin")
_rule("GET", r"/v1/reports(/.*)?", "read")

# --- service ingest + worker lifecycle (write) ----------------------------- #
_rule("POST", r"/v1/assets/bulk", "write")
_rule("POST", r"/v1/edges/bulk", "write")
_rule("POST", r"/v1/findings/bulk", "write")
_rule("POST", r"/v1/outbound/bulk", "write")
_rule("POST", r"/v1/chains", "write")
_rule("POST", r"/v1/tls-grades/bulk", "write")
_rule("PATCH", rf"/v1/scans/{_ANY}", "write")
_rule("POST", rf"/v1/scans/{_ANY}/(start|complete|fail)", "write")

# --- standards exports (read) + SBOM / lockfile imports (scan) -------------- #
_rule("GET", r"/v1/export/(findings\.ocsf|sarif|sbom|vex)", "read")
_rule("POST", r"/v1/import/(sbom|lockfiles)", "scan")

# --- billing (schema 028): the Stripe webhook authenticates by signature ----- #
_rule("POST", r"/v1/billing/webhook", None)
# Public status page feed: fixed component names, up/degraded, nothing else.
_rule("GET", r"/status", None)
# --- verified findings (schema 026): safe checks are scans; the worker reports with `write` --- #
_rule("POST", rf"/v1/findings/{_ANY}/verify", "scan")
_rule("POST", r"/v1/findings/verify/bulk", "scan")
_rule("POST", rf"/v1/verifications/{_ANY}/result", "write")
_rule("POST", rf"/v1/remediation/{_ANY}/merged", "triage")
# --- MSP console (app/msp): switching needs only read (the grant decides the
# role inside the customer); invite redemption is public (the token is the
# credential); every other mutating /v1/msp route falls through to admin. ---- #
_rule("POST", rf"/v1/msp/customers/{_ANY}/switch", "read")
_rule("POST", r"/v1/msp/invites/redeem", None)
# --- growth (schema 032): public passive endpoints + admin management ------- #
# Unauthenticated BY DESIGN: passive-only (DNS + CT), rate limited, aggregate
# output. The handlers enforce their own abuse controls (app/growth/abuse.py).
_rule("POST", r"/v1/public/exposure-report", None)
_rule("GET", rf"/v1/public/exposure-report/{_ANY}", None)
_rule("GET POST", rf"/v1/public/trust/{_ANY}", None)
_rule("GET POST DELETE PATCH PUT", r"/v1/trust-links(/.*)?", "admin")
# --- Sentry sensors (schema 034) -------------------------------------------- #
# Sensor-facing: authenticated in-handler by the enrollment token / sensor
# credential (rate limited, hashed at rest), not by a principal.
_rule("POST", r"/v1/sensors/(enroll|heartbeat)", None)
# otdiscovery (service key) brackets each upload with claim/done.
_rule("POST", r"/v1/sensors/ingest/(claim|done)", "write")
# Token metadata is admin-only; the rest of GET /v1/sensors falls to `read`,
# every write to the deny-closed `admin` default.
_rule("GET", r"/v1/sensors/tokens", "admin")


def required_capability(method: str, path: str) -> str | None:
    """Return the capability a route needs, or None for public routes.

    Safe methods default to ``read``; any unclassified mutating method
    defaults to ``admin`` (deny-closed for anything new).
    """
    path = path.rstrip("/") or "/"
    for methods, pattern, cap in _RULES:
        if method in methods and pattern.match(path):
            return cap
    if method in ("GET", "HEAD", "OPTIONS"):
        return "read"
    return "admin"


# --------------------------------------------------------------------------- #
# Governance middleware: authenticate + authorize + audit
# --------------------------------------------------------------------------- #

_EXEMPT_EXACT = frozenset({
    "/healthz", "/readyz", "/openapi.json", "/docs", "/redoc",
    "/docs/oauth2-redirect", "/favicon.ico",
})
_EXEMPT_PREFIX = ("/docs", "/redoc", "/static")

_dev_warned = False


def _is_exempt(path: str) -> bool:
    if path in _EXEMPT_EXACT:
        return True
    return any(path.startswith(p + "/") for p in _EXEMPT_PREFIX)


def _action_for(method: str, denied: bool) -> str:
    if denied:
        return "deny"
    return {
        "POST": "create",
        "PUT": "update",
        "PATCH": "update",
        "DELETE": "delete",
    }.get(method, "read")


def _resource_from_path(path: str) -> tuple[str | None, str | None]:
    parts = [p for p in path.split("/") if p]
    # expect: v1 / <resource> / <id?> ...
    if len(parts) >= 2 and parts[0] == "v1":
        rtype = parts[1]
        rid = parts[2] if len(parts) >= 3 else None
        return rtype, rid
    return None, None


# Non-GET routes that do not mutate state: no write-ahead audit record (they
# are still audited after the fact, exactly as before).
_NO_WRITE_AHEAD = frozenset({"/v1/scope/check", "/v1/billing/webhook"})

# Sentry data-plane calls: a heartbeat per sensor per minute and a claim/done
# pair per upload (hundreds of thousands a day at fleet scale; measured with
# hardening/sentry_scale.py, they were ~90% of audit_log growth). Successful
# ones are not audited per request; rejected/denied ones still are, and the
# lifecycle actions (token create/revoke, enroll, sensor revoke/update) are
# audited by their handlers.
_SENSOR_DATA_PLANE = re.compile(r"^/v1/sensors/(heartbeat|ingest/(claim|done))/?$")


#: anonymous requests per client per minute on public routes (Stripe's webhook
#: gets a larger bucket: it is signature-checked and arrives from few addresses).
ANON_PUBLIC_PER_MIN = int(os.environ.get("PADDOCK_ANON_PUBLIC_PER_MIN", "240") or 240)
ANON_WEBHOOK_PER_MIN = int(os.environ.get("PADDOCK_ANON_WEBHOOK_PER_MIN", "1200") or 1200)


#: routes that read their own (larger) bodies with their own caps
_ANON_OWN_BODY_CAP = re.compile(r"^/v1/(ingest|billing/webhook|integrations/|auth/sso/[^/]+/acs)")
ANON_BODY_MAX = 256 * 1024


def _anon_body_too_large(request: Request) -> bool:
    """Declared body size for anonymous public routes whose payloads are tiny
    JSON documents (exposure report, enrollment, invite redemption, trust unlock)."""
    if _ANON_OWN_BODY_CAP.match(request.url.path):
        return False
    cl = request.headers.get("content-length")
    return bool(cl and cl.isdigit() and int(cl) > ANON_BODY_MAX)


def _anon_throttled(request: Request) -> bool:
    from .netkey import SlidingWindowLimiter, client_key

    state = request.app.state
    lim = getattr(state, "anon_public_limiter", None)
    if lim is None:
        lim = state.anon_public_limiter = SlidingWindowLimiter(limit=1, window_s=60)
    path = request.url.path.rstrip("/")
    webhook = path == "/v1/billing/webhook"
    lim.limit = ANON_WEBHOOK_PER_MIN if webhook else ANON_PUBLIC_PER_MIN
    key = ("w:" if webhook else "p:") + client_key(client_ip(request))
    return not lim.hit(key)


class GovernanceMiddleware(BaseHTTPMiddleware):
    """Authenticate, enforce RBAC deny-closed, scope to a tenant, and audit.

    Runs inside ``RequestContextMiddleware`` so ``request.state.request_id`` is
    already set.

    Tenancy: once the principal is resolved its tenant is bound to the request
    context (``tenancy.set_tenant``); every ``pool.acquire()`` made while
    handling the request stamps that tenant on the DB session, so Postgres RLS
    scopes every query.

    Fail-closed audit (``AUDIT_FAIL_CLOSED``, default on): before a mutating
    handler runs, a write-ahead ``phase=intent`` audit record is committed. If
    that append fails the request is refused with 503 and the handler never
    runs, so no mutation can happen unaudited. After the handler, a
    ``phase=outcome`` record with the response status links back to the intent
    (best-effort: if it fails, the intent record still proves the attempt).
    Handlers that want an audit row in the SAME transaction as their write can
    call ``audit.record(..., con=con)`` themselves.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        path = request.url.path
        if _is_exempt(path):
            return await call_next(request)

        required = required_capability(request.method, path)

        # 1. Authenticate (a presented-but-invalid credential is always a 401,
        #    even on a public route).
        try:
            principal = await resolve_principal(request)
        except AuthError as exc:
            return await self._deny(request, 401, exc.detail, None)

        if principal is None and settings.auth_mode == "dev":
            principal = dev_principal()
            global _dev_warned
            if not _dev_warned:
                _dev_warned = True
                logger.warning(
                    "AUTH_MODE=dev: injecting synthetic admin principal for "
                    "unauthenticated requests. DO NOT run this way in production."
                )

        # 1b. Anonymous callers of public routes: a cheap per-client throttle BEFORE
        #     anything is written. Without it every anonymous POST costs two audit
        #     rows (write-ahead + outcome) ahead of the handler's own limits, so
        #     the audit chain itself becomes the amplifier.
        if principal is None and required is None and _anon_body_too_large(request):
            return JSONResponse({"detail": "request body too large"}, status_code=413)
        if principal is None and required is None and _anon_throttled(request):
            resp = JSONResponse({"detail": "too many requests; slow down"}, status_code=429,
                                headers={"Retry-After": "60"})
            rid = getattr(request.state, "request_id", None)
            if rid:
                resp.headers["X-Request-ID"] = rid
            return resp

        # 2. Bind the principal's tenant for everything below (RLS scoping).
        #    (Only a service principal can pick its tenant, via X-Paddock-Tenant;
        #    resolve_principal already validated that it exists and is active.)
        tenant_token = tenancy.set_tenant(principal.tenant_id if principal else None)
        try:
            return await self._handle(request, call_next, principal, required)
        finally:
            tenancy.reset_tenant(tenant_token)

    async def _handle(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
        principal: Principal | None,
        required: str | None,
    ) -> Response:
        # 3a. An MSP user acting inside a customer has a narrower surface
        #     (no key minting / SSO / SCIM / nested MSP routes): app/msp.
        if principal is not None and principal.msp_delegation:
            from . import msp as msp_svc

            why = msp_svc.delegated_route_denied(principal, request.url.path, request.method)
            if why:
                return await self._deny(request, 403, why, principal)

        # 3. Authorize (RBAC, deny-closed) for non-public routes.
        if required is not None:
            if principal is None:
                return await self._deny(request, 401, "authentication required", None)
            if not principal.has(required):
                return await self._deny(
                    request, 403, f"requires capability '{required}'", principal
                )

        if principal is not None:
            request.state.principal = principal

        # 3b. A worker callback must belong to the tenant of the job it answers.
        if principal is not None and principal.kind == "service":
            if settings.tenancy_strict and not service_routes.permitted(request.method, request.url.path):
                # Strict mode: the fleet-wide key may only call the routes the
                # fleet really calls (app/service_routes.py); everything else
                # (users, keys, scope writes, integrations, audit, ...) is refused.
                return await self._deny(
                    request, 403,
                    "the service key may not call this route under TENANCY_STRICT", principal,
                )
            pool = getattr(request.app.state, "pool", None)
            if pool is not None:
                try:
                    mismatch = await job_binding.verify(request, pool, tenancy.current_tenant_id())
                except Exception:  # noqa: BLE001 -- fail closed
                    logger.exception("job_binding_check_failed")
                    mismatch = "job/tenant check unavailable"
                if mismatch:
                    return await self._deny(request, 409, f"job_tenant_mismatch: {mismatch}", principal)

        # 4. Write-ahead audit for mutations (fail-closed).
        intent_id: int | None = None
        if self._needs_write_ahead(request):
            try:
                intent = await self._record(
                    request, principal, None, denied=False, details={"phase": "intent"}
                )
                intent_id = intent["id"] if intent else None
            except Exception:  # noqa: BLE001
                logger.exception("audit_intent_failed", extra={"path": request.url.path})
                _count_audit_failure()
                rid = getattr(request.state, "request_id", None)
                resp = JSONResponse(
                    {"detail": "audit log unavailable; mutation refused (fail-closed)"},
                    status_code=503,
                )
                if rid:
                    resp.headers["X-Request-ID"] = rid
                return resp
            request.state.audit_intent_id = intent_id

        # 5. Handle.
        response = await call_next(request)

        # 6. Audit mutating + restricted-read requests (outcome; best-effort).
        details = {"phase": "outcome", "intent_id": intent_id} if intent_id is not None else None
        await self._audit(request, principal, response.status_code, details=details)
        return response

    @staticmethod
    def _needs_write_ahead(request: Request) -> bool:
        if not settings.audit_fail_closed:
            return False
        # An MSP user inside a customer is audited write-ahead on EVERY request,
        # reads included (the customer can see what its provider looked at).
        delegated = bool(getattr(getattr(request.state, "principal", None), "msp_delegation", None))
        if request.method not in ("POST", "PUT", "PATCH", "DELETE") and not delegated:
            return False
        if (request.url.path.rstrip("/") or "/") in _NO_WRITE_AHEAD:
            return False
        if _SENSOR_DATA_PLANE.match(request.url.path):
            return False
        # No database -> the handler cannot mutate persistent state either.
        return getattr(request.app.state, "pool", None) is not None

    async def _deny(
        self,
        request: Request,
        status_code: int,
        detail: str,
        principal: Principal | None,
    ) -> JSONResponse:
        rid = getattr(request.state, "request_id", None)
        if request.url.path.startswith("/scim/"):
            # SCIM clients (Okta, Entra) expect the RFC 7644 §3.12 error shape.
            resp = JSONResponse(
                {
                    "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                    "status": str(status_code),
                    "detail": detail,
                },
                status_code=status_code,
                media_type="application/scim+json",
                headers={"WWW-Authenticate": "Bearer"} if status_code == 401 else None,
            )
        else:
            resp = JSONResponse({"detail": detail}, status_code=status_code)
        if rid:
            resp.headers["X-Request-ID"] = rid
        await self._audit(request, principal, status_code, denied=True)
        return resp

    async def _audit(
        self,
        request: Request,
        principal: Principal | None,
        status_code: int,
        denied: bool = False,
        details: dict[str, Any] | None = None,
    ) -> None:
        method = request.method
        mutating = method in ("POST", "PUT", "PATCH", "DELETE")
        restricted_read = bool(getattr(request.state, "audit_restricted", False))
        delegated = bool(principal is not None and principal.msp_delegation)
        if not (denied or mutating or restricted_read or delegated):
            return
        if not denied and status_code < 400 and _SENSOR_DATA_PLANE.match(request.url.path):
            return
        try:
            await self._record(request, principal, status_code, denied=denied, details=details)
        except Exception:  # noqa: BLE001 -- the outcome record never fails the request
            logger.exception("audit_record_failed", extra={"path": request.url.path})
            _count_audit_failure()

    async def _record(
        self,
        request: Request,
        principal: Principal | None,
        status_code: int | None,
        *,
        denied: bool,
        details: dict[str, Any] | None,
    ) -> dict[str, Any] | None:
        pool = getattr(request.app.state, "pool", None)
        if pool is None:
            return None
        rtype, rid_val = _resource_from_path(request.url.path)
        classification = getattr(request.state, "audit_classification", None)
        ip = client_ip(request)
        if details is None:
            details = {"denied": True} if denied else {}
        if principal is not None and principal.kind == "service":
            # A shared service key acting in a tenant it named: record WHICH.
            details = {**details, "via": "service_key",
                       "acting_tenant": principal.tenant_id or tenancy.current_tenant_id(),
                       "job": request.headers.get(job_binding.SCAN_HEADER)}
        # Anonymous / tenant-less events go to the default (platform) chain.
        tenant = (principal.tenant_id if principal else None) or tenancy.current_tenant_id()
        if principal is not None and principal.msp_delegation:
            # MSP user inside a customer: the MSP's own trail gets its record
            # first (a failure here refuses a write-ahead request, fail-closed),
            # then the customer's row below names the acting MSP user.
            from . import msp as msp_svc

            await msp_svc.mirror_to_msp_trail(
                pool,
                principal,
                action=_action_for(request.method, denied),
                method=request.method,
                path=request.url.path,
                status=status_code,
                request_id=getattr(request.state, "request_id", None),
                ip=ip,
                details=details,
            )
            details = {**details, "msp": msp_svc.delegation_details(principal)}
        with tenancy.tenant_context(tenant or tenancy.DEFAULT_TENANT_ID):
            return await audit.record(
                pool,
                action=_action_for(request.method, denied),
                actor=principal.actor if principal else "anonymous",
                actor_role=principal.role if principal else None,
                resource_type=rtype,
                resource_id=rid_val,
                method=request.method,
                path=request.url.path,
                status=status_code,
                classification=classification,
                justification=request.headers.get("x-justification"),
                ip=ip,
                request_id=getattr(request.state, "request_id", None),
                details=details,
            )


def _count_audit_failure() -> None:
    """Prometheus counter (app/metrics.py); never let metrics break auditing."""
    try:
        from .metrics import audit_append_failed

        audit_append_failed()
    except Exception:  # noqa: BLE001
        pass


def _trusted_proxies() -> tuple:
    import ipaddress

    nets = []
    for c in settings.trusted_proxy_cidrs.split(","):
        c = c.strip()
        if c:
            try:
                nets.append(ipaddress.ip_network(c, strict=False))
            except ValueError:
                logger.warning("bad_trusted_proxy_cidr", extra={"cidr": c})
    return tuple(nets)


def client_ip(request: Request) -> str | None:
    """Socket peer, or the X-Forwarded-For client ONLY when the peer is a
    configured trusted proxy. Otherwise XFF is attacker-controlled."""
    import ipaddress

    peer = request.client.host if request.client else None
    fwd = request.headers.get("x-forwarded-for")
    if not (peer and fwd):
        return peer
    try:
        peer_ip = ipaddress.ip_address(peer)
    except ValueError:
        return peer
    if any(peer_ip.version == n.version and peer_ip in n for n in _trusted_proxies()):
        cand = fwd.split(",")[0].strip()
        try:
            return str(ipaddress.ip_address(cand))
        except ValueError:
            return peer
    return peer


# --------------------------------------------------------------------------- #
# FastAPI dependencies (defence-in-depth; middleware is the primary gate)
# --------------------------------------------------------------------------- #

def current_principal(request: Request) -> Principal:
    """Return the principal the middleware resolved for this request."""
    p = getattr(request.state, "principal", None)
    if p is None:
        # Middleware exempts a handful of paths; for anything using this
        # dependency the principal is always set. Fall back deny-closed.
        if settings.auth_mode == "dev":
            return dev_principal()
        raise HTTPException(status_code=401, detail="authentication required")
    return p


_ROLE_CAP = {"admin": "admin", "auditor": "audit", "analyst": "triage", "viewer": "read"}


def require(role: str):
    """Dependency factory: require a role (via its headline capability).

    ``require('admin')`` is the replacement for the old ``require_scope_admin``
    no-op. ``admin`` satisfies every role because its capability set is a
    superset.
    """
    needed = _ROLE_CAP.get(role, "admin")

    async def _dep(request: Request) -> Principal:
        p = current_principal(request)
        if not p.has(needed):
            raise HTTPException(status_code=403, detail=f"requires role '{role}'")
        return p

    return _dep


def require_scope(scope: str):
    """Dependency factory: require a specific capability/scope."""

    async def _dep(request: Request) -> Principal:
        p = current_principal(request)
        if not p.has(scope):
            raise HTTPException(status_code=403, detail=f"requires scope '{scope}'")
        return p

    return _dep


# --------------------------------------------------------------------------- #
# Startup bootstrap + DB hardening
# --------------------------------------------------------------------------- #

async def bootstrap_admin(pool) -> None:
    """Set the seeded admin's password on first boot if it has none.

    Uses ``ADMIN_BOOTSTRAP_PASSWORD`` when present, otherwise generates one and
    logs it exactly once. Never ships a known credential.
    """
    async with pool.acquire() as con:
        row = await con.fetchrow(
            "SELECT id, pw_hash FROM app_users WHERE username = 'admin'"
        )
        if row is None:
            row = await con.fetchrow(
                """
                INSERT INTO app_users (username, display_name, role, clearance)
                VALUES ('admin', 'Bootstrap Admin', 'admin', 'restricted')
                ON CONFLICT (username) DO NOTHING
                RETURNING id, pw_hash
                """
            )
            if row is None:
                row = await con.fetchrow(
                    "SELECT id, pw_hash FROM app_users WHERE username = 'admin'"
                )
        if row is not None and row["pw_hash"]:
            return  # already bootstrapped
        password = settings.admin_bootstrap_password
        generated = False
        if not password:
            password = secrets.token_urlsafe(18)
            generated = True
        await con.execute(
            "UPDATE app_users SET pw_hash = $1 WHERE username = 'admin'",
            hash_password(password),
        )
    if generated:
        logger.warning(
            "ADMIN_BOOTSTRAP_PASSWORD unset -- generated a one-time admin "
            "password (shown ONCE, set ADMIN_BOOTSTRAP_PASSWORD to control it): %s",
            password,
        )
    else:
        logger.info("admin password bootstrapped from ADMIN_BOOTSTRAP_PASSWORD")


async def harden_audit_table(pool) -> None:
    """Best-effort: revoke UPDATE/DELETE on audit_log from the app role.

    Belt-and-braces with the hash chain. Logged (not fatal) if we lack the
    privilege to do so (e.g. not a superuser / owner).
    """
    try:
        async with pool.acquire() as con:
            role = await con.fetchval("SELECT current_user")
            writable = await con.fetchval(
                "SELECT has_table_privilege(current_user, 'audit_log', 'UPDATE') "
                "    OR has_table_privilege(current_user, 'audit_log', 'DELETE')"
            )
            if not writable:
                # The normal case with the paddock_app role (schema 099).
                logger.info("audit_log is append-only for %s", role)
                return
            await con.execute(
                f'REVOKE UPDATE, DELETE ON audit_log FROM "{role}"'
            )
        logger.info("audit_log hardened: UPDATE/DELETE revoked from %s", role)
    except Exception as exc:  # noqa: BLE001
        logger.warning("could not revoke UPDATE/DELETE on audit_log: %s", exc)
