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

from . import audit
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
    )


def service_principal() -> Principal:
    return Principal(
        actor="service",
        role="service",
        clearance="restricted",
        capabilities=capabilities_for("service"),
        kind="service",
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


# --------------------------------------------------------------------------- #
# JWT
# --------------------------------------------------------------------------- #

_RUNTIME_JWT_SECRET = secrets.token_urlsafe(48)


def _jwt_secret() -> str:
    return settings.jwt_secret or _RUNTIME_JWT_SECRET


def issue_jwt(*, user_id: str | None, username: str, role: str, clearance: str) -> tuple[str, int]:
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
        else:
            token = bearer
    return api_key, token


async def _principal_from_api_key(request: Request, key: str) -> Principal:
    pool = getattr(request.app.state, "pool", None)
    if pool is None:
        raise AuthError("auth backend unavailable")
    key_hash = hash_api_key(key)
    async with pool.acquire() as con:
        row = await con.fetchrow(
            """
            SELECT k.id AS key_id, k.scopes, k.expires_at, k.revoked,
                   u.id AS user_id, u.username, u.role, u.clearance, u.active
              FROM api_keys k
              JOIN app_users u ON u.id = k.user_id
             WHERE k.key_hash = $1
            """,
            key_hash,
        )
        if row is None or row["revoked"] or not row["active"]:
            raise AuthError("invalid API key")
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
    # Prefer live DB state (role/clearance/active) over possibly-stale claims.
    if pool is not None and username:
        async with pool.acquire() as con:
            row = await con.fetchrow(
                "SELECT id, username, role, clearance, active FROM app_users WHERE username = $1",
                username,
            )
        if row is None:
            # Deleted user: never fall back to trusting role claims in a token.
            raise AuthError("unknown user")
        if row is not None:
            if not row["active"]:
                raise AuthError("user disabled")
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
    )


async def resolve_principal(request: Request) -> Principal | None:
    """Resolve a request's credential to a Principal, or None if none presented.

    Raises ``AuthError`` when a credential IS presented but is invalid.
    """
    api_key, token = _extract_credentials(request)
    if api_key:
        svc = settings.service_api_key
        # compare bytes: compare_digest(str, str) raises on non-ASCII input,
        # which used to surface as an unaudited 500.
        if svc and hmac.compare_digest(api_key.encode("utf-8"), svc.encode("utf-8")):
            return service_principal()
        return await _principal_from_api_key(request, api_key)
    if token:
        return await _principal_from_jwt(request, token)
    return None


# --------------------------------------------------------------------------- #
# RBAC policy: (method, path) -> required capability
# --------------------------------------------------------------------------- #

import re  # noqa: E402

# Ordered rules. First match wins. Patterns match the concrete request path
# (with real ids). `None` capability means the route is public (no auth).
_RULES: list[tuple[frozenset[str], re.Pattern[str], str | None]] = []


def _rule(methods: str, pattern: str, cap: str | None) -> None:
    _RULES.append((frozenset(methods.split()), re.compile("^" + pattern + "$"), cap))


_ANY = r"[^/]+"

# --- public ---------------------------------------------------------------- #
_rule("POST", r"/v1/auth/login", None)

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
_rule("POST DELETE PATCH PUT", rf"/v1/owners(/{_ANY})?", "admin")
_rule("POST DELETE PATCH PUT", rf"/v1/alert-rules(/{_ANY})?", "admin")
_rule("POST DELETE PATCH PUT", rf"/v1/schedules(/{_ANY}(/run-now)?)?", "admin")
_rule("PATCH", rf"/v1/sla-policies/{_ANY}", "admin")

# --- triage (analyst + admin) ---------------------------------------------- #
_rule("PATCH", rf"/v1/findings/{_ANY}", "triage")
_rule("PATCH", rf"/v1/tickets/{_ANY}", "triage")
_rule("POST", rf"/v1/anomalies/{_ANY}/ack", "triage")
_rule("POST", rf"/v1/changes/{_ANY}/ack", "triage")

# --- scan / operational triggers (analyst + admin + service) --------------- #
_rule("POST", r"/v1/scans", "scan")
_rule("POST", r"/v1/attack-paths/recompute", "scan")
_rule("POST", r"/v1/ml/retrain", "scan")

# --- ask -------------------------------------------------------------------- #
_rule("POST", r"/v1/ask", "ask")

# --- service ingest + worker lifecycle (write) ----------------------------- #
_rule("POST", r"/v1/assets/bulk", "write")
_rule("POST", r"/v1/edges/bulk", "write")
_rule("POST", r"/v1/findings/bulk", "write")
_rule("POST", r"/v1/outbound/bulk", "write")
_rule("POST", r"/v1/chains", "write")
_rule("POST", r"/v1/tls-grades/bulk", "write")
_rule("PATCH", rf"/v1/scans/{_ANY}", "write")
_rule("POST", rf"/v1/scans/{_ANY}/(start|complete|fail)", "write")


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


class GovernanceMiddleware(BaseHTTPMiddleware):
    """Authenticate, enforce RBAC deny-closed, and write the audit trail.

    Runs inside ``RequestContextMiddleware`` so ``request.state.request_id`` is
    already set. Audit writes are best-effort: a failure there never fails the
    request (the hash chain + verify endpoint remain the integrity authority).
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

        # 2. Authorize (RBAC, deny-closed) for non-public routes.
        if required is not None:
            if principal is None:
                return await self._deny(request, 401, "authentication required", None)
            if not principal.has(required):
                return await self._deny(
                    request, 403, f"requires capability '{required}'", principal
                )

        if principal is not None:
            request.state.principal = principal

        # 3. Handle.
        response = await call_next(request)

        # 4. Audit mutating + restricted-read requests (best-effort).
        await self._audit(request, principal, response.status_code)
        return response

    async def _deny(
        self,
        request: Request,
        status_code: int,
        detail: str,
        principal: Principal | None,
    ) -> JSONResponse:
        rid = getattr(request.state, "request_id", None)
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
    ) -> None:
        method = request.method
        mutating = method in ("POST", "PUT", "PATCH", "DELETE")
        restricted_read = bool(getattr(request.state, "audit_restricted", False))
        if not (denied or mutating or restricted_read):
            return
        pool = getattr(request.app.state, "pool", None)
        if pool is None:
            return
        rtype, rid_val = _resource_from_path(request.url.path)
        classification = getattr(request.state, "audit_classification", None)
        ip = client_ip(request)
        try:
            await audit.record(
                pool,
                action=_action_for(method, denied),
                actor=principal.actor if principal else "anonymous",
                actor_role=principal.role if principal else None,
                resource_type=rtype,
                resource_id=rid_val,
                method=method,
                path=request.url.path,
                status=status_code,
                classification=classification,
                justification=request.headers.get("x-justification"),
                ip=ip,
                request_id=getattr(request.state, "request_id", None),
                details={"denied": True} if denied else {},
            )
        except Exception:  # noqa: BLE001 -- never fail the request on audit
            logger.exception("audit_record_failed", extra={"path": request.url.path})


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
            await con.execute(
                f'REVOKE UPDATE, DELETE ON audit_log FROM "{role}"'
            )
        logger.info("audit_log hardened: UPDATE/DELETE revoked from %s", role)
    except Exception as exc:  # noqa: BLE001
        logger.warning("could not revoke UPDATE/DELETE on audit_log: %s", exc)
