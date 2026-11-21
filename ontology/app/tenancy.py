"""Tenant context for Paddock compute services (canonical source).

THIS FILE IS COPIED, verbatim, to ``<service>/app/tenancy.py`` by
``python scripts/sync_tenancy_helper.py`` (services build from their own
directory, so they cannot import a shared package). A test fails when a copy
drifts; edit only ``shared/paddock_tenancy.py`` and re-run the sync script.

The model (docs/trust/TENANCY.md, "Compute services and workers"):

* Every unit of work carries a tenant: stream events and queue jobs include
  ``tenant_id``; HTTP calls from the orchestrator carry ``X-Paddock-Tenant``
  next to the service key; periodic sweeps iterate the active tenants.
* The tenant lives in a ``ContextVar``. ``scoped(conn)`` opens a transaction on
  a pooled connection and runs ``set_config('app.tenant_id', <tenant>, true)``
  (``SET LOCAL`` semantics), so the setting dies with the transaction and can
  never leak to the next user of the pooled connection.
* The service connects as a non-superuser, NOBYPASSRLS role, so Postgres row
  level security (schema/099_tenancy.sql) enforces the tenant, whatever the
  service's SQL says.
* With no tenant bound the service runs in the default tenant (single-tenant
  installs keep working) -- unless ``TENANCY_STRICT=true``, in which case it
  runs in NO tenant: reads return nothing and writes fail the RLS check.
* Global catalogues (CVEs, KEV, ATT&CK, threat-intel feeds, ontology types) are
  writable only from the platform tenant: wrap those writes in
  ``platform_context()``.
"""
from __future__ import annotations

import contextlib
import contextvars
import hmac
import logging
import os
import uuid
from typing import Any, AsyncIterator, Awaitable, Callable, Iterator, Mapping

log = logging.getLogger("paddock.tenancy")

#: The tenant every pre-tenancy row (and every single-tenant install) belongs to.
DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001"
TENANT_HEADER = "X-Paddock-Tenant"
SERVICE_KEY_HEADER = "X-API-Key"

_tenant: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "paddock_service_tenant", default=None
)


class TenantError(Exception):
    """A tenant reference was malformed or not allowed for this caller."""


def _truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def strict() -> bool:
    """``TENANCY_STRICT=true``: no implicit default tenant."""
    return _truthy("TENANCY_STRICT")


def norm(tenant_id: Any) -> str | None:
    """Canonical lower-case UUID string; ``None``/'' -> ``None``; else TenantError."""
    if tenant_id is None or tenant_id == "":
        return None
    try:
        return str(uuid.UUID(str(tenant_id)))
    except (ValueError, AttributeError, TypeError) as exc:
        raise TenantError(f"invalid tenant id: {str(tenant_id)[:64]!r}") from exc


def requested_tenant() -> str | None:
    """The tenant explicitly bound in this context (no default fallback)."""
    return _tenant.get()


def current_tenant_id() -> str | None:
    """The tenant queries in this context run as; ``None`` means NO tenant."""
    t = _tenant.get()
    if t is not None:
        return t
    return None if strict() else DEFAULT_TENANT_ID


def set_tenant(tenant_id: Any) -> contextvars.Token:
    return _tenant.set(norm(tenant_id))


def reset_tenant(token: contextvars.Token) -> None:
    _tenant.reset(token)


@contextlib.contextmanager
def tenant_context(tenant_id: Any) -> Iterator[str | None]:
    """Run a block as ``tenant_id``."""
    token = set_tenant(tenant_id)
    try:
        yield _tenant.get()
    finally:
        _tenant.reset(token)


def platform_context():
    """Run a block as the platform (default) tenant: the only tenant allowed to
    write global catalogues (``@paddock:global`` tables)."""
    return tenant_context(DEFAULT_TENANT_ID)


# --------------------------------------------------------------------------- #
# Database
# --------------------------------------------------------------------------- #

@contextlib.asynccontextmanager
async def scoped(conn, *, readonly: bool = False) -> AsyncIterator[Any]:
    """Transaction-scoped tenant on ``conn`` (asyncpg).

    ``set_config(..., true)`` is ``SET LOCAL``: it lasts until the transaction
    ends and is discarded on commit AND rollback, so a pooled connection never
    carries a tenant between users. Nested use (already in a transaction) becomes
    a savepoint and re-stamps the tenant for its duration. NOTE: asyncpg ignores
    ``readonly`` on a nested transaction, so use ``readonly`` only on a
    connection that is not already inside one.
    """
    tid = current_tenant_id()
    async with conn.transaction(readonly=readonly):
        await conn.execute("SELECT set_config('app.tenant_id', $1, true)", tid or "")
        yield conn


async def list_tenant_ids(pool, *, active_only: bool = True) -> list[str]:
    """Active tenant ids (the ``tenants`` catalogue is readable by every role).

    Falls back to the default tenant when the catalogue is absent so a service
    keeps working on a not-yet-migrated single-tenant database.
    """
    sql = "SELECT id FROM tenants" + (" WHERE status = 'active'" if active_only else "") + " ORDER BY created_at, id"
    try:
        async with pool.acquire() as con:
            rows = await con.fetch(sql)
    except Exception as exc:  # noqa: BLE001
        log.warning("tenant list failed (%s); using the default tenant", exc)
        return [DEFAULT_TENANT_ID]
    return [str(r["id"]) for r in rows] or [DEFAULT_TENANT_ID]


async def for_each_tenant(
    pool, fn: Callable[[], Awaitable[Any]], *, tenants: list[str] | None = None
) -> dict[str, Any]:
    """Run ``fn()`` once per active tenant, each inside its own tenant context.

    One tenant's failure is logged and returned (as the exception) but never
    stops the others. Returns ``{tenant_id: result | Exception}``.
    """
    out: dict[str, Any] = {}
    for tid in tenants if tenants is not None else await list_tenant_ids(pool):
        with tenant_context(tid):
            try:
                out[tid] = await fn()
            except Exception as exc:  # noqa: BLE001
                log.exception("tenant %s: pass failed", tid)
                out[tid] = exc
    return out


async def run_for_request_or_all(
    pool, fn: Callable[[], Awaitable[Any]]
) -> dict[str, Any]:
    """HTTP trigger semantics: the tenant named by ``X-Paddock-Tenant`` if the
    request carried one, otherwise every active tenant."""
    t = requested_tenant()
    return await for_each_tenant(pool, fn, tenants=[t] if t else None)


def merge_counts(results: Mapping[str, Any]) -> dict[str, Any]:
    """Fold ``for_each_tenant`` results into one summary: numeric fields are
    summed, ``tenants`` counts the passes, ``failed`` the tenants that raised.
    Raises the first error only when EVERY tenant failed (so a caller's own
    error handling still fires for a wholly broken pass)."""
    out: dict[str, Any] = {"tenants": len(results), "failed": 0}
    first: Exception | None = None
    for res in results.values():
        if isinstance(res, Exception):
            out["failed"] += 1
            first = first or res
            continue
        if isinstance(res, Mapping):
            for k, v in res.items():
                if isinstance(v, bool) or not isinstance(v, (int, float)):
                    continue
                out[k] = out.get(k, 0) + v
    if first is not None and out["failed"] == len(results):
        raise first
    return out


async def check_role(conn_or_pool, *, require: bool | None = None) -> dict[str, Any]:
    """Refuse (or shout) when connected as a role that bypasses RLS.

    ``require`` defaults to ``REQUIRE_RLS_ROLE``. A superuser / BYPASSRLS role
    silently disables every tenant policy, so with ``require`` the service
    refuses to start instead of running unprotected.
    """
    if require is None:
        require = _truthy("REQUIRE_RLS_ROLE")
    sql = "SELECT current_user AS who, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"
    if hasattr(conn_or_pool, "acquire"):
        async with conn_or_pool.acquire() as con:
            row = await con.fetchrow(sql)
    else:
        row = await conn_or_pool.fetchrow(sql)
    info = {"role": row["who"], "superuser": bool(row["rolsuper"]), "bypassrls": bool(row["rolbypassrls"])}
    if info["superuser"] or info["bypassrls"]:
        msg = (
            f"database role {info['role']!r} is superuser/BYPASSRLS: row-level security "
            "tenant isolation is NOT enforced for this service. Connect as its "
            "paddock_svc_* role (schema/029_service_tenancy.sql)."
        )
        if require:
            raise RuntimeError(msg)
        log.error("SECURITY: %s", msg)
    return info


# --------------------------------------------------------------------------- #
# Units of work: events, jobs, results
# --------------------------------------------------------------------------- #

def event_tenant(payload: Mapping[str, Any]) -> str | None:
    """The tenant stamped on an event / job payload (``None`` if absent)."""
    return norm(payload.get("tenant_id")) if payload else None


@contextlib.contextmanager
def bind_event(payload: Mapping[str, Any]) -> Iterator[str | None]:
    """Bind the tenant of a stream event / job for the duration of its handling.

    An event with no tenant is treated as the default tenant in non-strict mode;
    in strict mode it is a ``TenantError`` (the caller should drop + log it):
    work that does not say whose it is must not run anywhere.
    """
    tid = event_tenant(payload)
    if tid is None:
        if strict():
            raise TenantError("event carries no tenant_id (TENANCY_STRICT)")
        tid = DEFAULT_TENANT_ID
    with tenant_context(tid) as t:
        yield t


def stamp_event(event: dict[str, Any]) -> dict[str, Any]:
    """Copy of ``event`` with the context's tenant as ``tenant_id`` -- every
    event a service publishes says whose it is (consumers refuse otherwise in
    strict mode). An event that already names a tenant is left alone."""
    if event.get("tenant_id"):
        return event
    t = current_tenant_id()
    return {**event, "tenant_id": t} if t else event


def echo_tenant(result: dict[str, Any]) -> dict[str, Any]:
    """Add the context's tenant to a result/summary payload (workers echo the
    job's tenant back so the orchestrator can verify it)."""
    t = requested_tenant()
    if t is not None and "tenant_id" not in result:
        return {**result, "tenant_id": t}
    return result


# --------------------------------------------------------------------------- #
# Outbound: the orchestrator API
# --------------------------------------------------------------------------- #

def outbound_headers() -> dict[str, str]:
    """``X-Paddock-Tenant`` for orchestrator calls made in this context.

    Only an explicitly bound tenant is sent; with none bound the orchestrator
    applies its own default (or, in strict mode, refuses the service key).
    """
    t = _tenant.get()
    return {TENANT_HEADER: t} if t else {}


def aiohttp_trace_config():
    """aiohttp ``TraceConfig`` that stamps the tenant header on every request,
    so a shared ``ClientSession`` stays correct under concurrent tenants."""
    import aiohttp

    async def _on_start(_session, _ctx, params) -> None:
        params.headers.update(outbound_headers())

    tc = aiohttp.TraceConfig()
    tc.on_request_start.append(_on_start)
    return tc


async def httpx_request_hook(request) -> None:
    """``httpx.AsyncClient(event_hooks={"request": [httpx_request_hook]})``."""
    for k, v in outbound_headers().items():
        request.headers[k] = v


# --------------------------------------------------------------------------- #
# Inbound HTTP (service endpoints called by the orchestrator)
# --------------------------------------------------------------------------- #

def request_tenant(headers: Mapping[str, str], *, service_key: str | None = None) -> str | None:
    """Tenant requested by an inbound HTTP call, or ``None`` if it named none.

    Naming a tenant is a privileged act: it needs the shared service key (the
    orchestrator sends both). With no ``SERVICE_API_KEY`` configured the header
    is honoured only outside strict mode (dev), never in strict mode.
    """
    ref = headers.get(TENANT_HEADER) or headers.get(TENANT_HEADER.lower())
    if not ref:
        return None
    key = service_key if service_key is not None else os.environ.get("SERVICE_API_KEY", "")
    if key:
        presented = headers.get(SERVICE_KEY_HEADER) or headers.get(SERVICE_KEY_HEADER.lower()) or ""
        if not hmac.compare_digest(presented.encode("utf-8"), key.encode("utf-8")):
            raise TenantError("tenant selection requires the service key")
    elif strict():
        raise TenantError("tenant selection requires SERVICE_API_KEY (TENANCY_STRICT)")
    return norm(ref)


def aiohttp_middleware():
    """aiohttp server middleware binding the caller-named tenant per request."""
    from aiohttp import web

    @web.middleware
    async def _mw(request, handler):
        try:
            tid = request_tenant(request.headers)
        except TenantError as exc:
            return web.json_response({"error": "tenant_forbidden", "detail": str(exc)}, status=403)
        if tid is None:
            return await handler(request)
        with tenant_context(tid):
            return await handler(request)

    return _mw
