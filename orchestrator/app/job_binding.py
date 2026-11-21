"""Verify that a worker's callback belongs to the tenant of the job it was given.

Every queued scan job carries ``tenant_id`` (``queue.enqueue_scan``) and a
worker echoes it back on every callback: ``X-Paddock-Tenant`` (which tenant the
callback acts in) and ``X-Paddock-Scan`` (which job it is a result of). The
shared service key could otherwise be used to claim ANY tenant, so for a
service principal that names a job we check that the job really was issued in
the tenant it claims -- ``scans`` is row-level-secured, so the lookup below runs
inside the claimed tenant and only finds a job that tenant owns. A job that is
not visible there (issued to another tenant, or never issued) is a mismatch and
the callback is rejected before any handler runs.

Under ``TENANCY_STRICT`` a service callback on a scan lifecycle route, and on
every worker-only route (``service_routes.JOB_ROUTES``: verification results,
child scans, tls-grades, outbound audit, scope check) or bulk write sent by a
worker (``X-Worker-Id``), MUST name its job.
"""
from __future__ import annotations

import re
import time
import uuid
from typing import Any

from . import service_routes
from .config import settings

SCAN_HEADER = "x-paddock-scan"
_SCAN_PATH = re.compile(r"^/v1/scans/([0-9a-fA-F-]{36})(?:/(?:start|complete|fail|status))?/?$")
_TTL_S = 300.0
_MAX = 10_000
_seen: dict[tuple[str, str], float] = {}


def _remember(tenant: str, scan_id: str) -> None:
    if len(_seen) >= _MAX:
        _seen.clear()
    _seen[(tenant, scan_id)] = time.monotonic()


def _known(tenant: str, scan_id: str) -> bool:
    ts = _seen.get((tenant, scan_id))
    return ts is not None and (time.monotonic() - ts) < _TTL_S


def reset_cache() -> None:
    _seen.clear()


async def verify(request: Any, pool: Any, tenant: str | None) -> str | None:
    """``None`` when the callback is consistent, else a reason to reject (409).

    Call only for service principals, after the tenant has been bound.
    """
    claimed = request.headers.get(SCAN_HEADER)
    m = _SCAN_PATH.match(request.url.path) if request.method in ("PATCH", "POST") else None
    path_id = m.group(1).lower() if m else None
    if not claimed:
        if settings.tenancy_strict and (
            path_id is not None or service_routes.requires_job(request.method, request.url.path, request.headers)
        ):
            return "worker callbacks must echo their job (X-Paddock-Scan) under TENANCY_STRICT"
        return None
    try:
        sid = str(uuid.UUID(claimed))
    except ValueError:
        return "malformed X-Paddock-Scan"
    if path_id is not None and path_id != sid:
        return "X-Paddock-Scan does not match the scan in the URL"
    if tenant is None:
        return "no tenant for this job callback"
    if _known(tenant, sid):
        return None
    async with pool.acquire() as con:  # scoped to ``tenant`` by the RLS context
        owned = await con.fetchval("SELECT 1 FROM scans WHERE id = $1", sid)
    if not owned:
        return f"job {sid} was not issued to tenant {tenant}"
    _remember(tenant, sid)
    return None
