"""Inbound half of two-way ticket sync.

``POST /v1/integrations/{integration_id}/inbound``

Public route (no session auth; see the explicit rule in ``app.auth``). The
caller is authenticated per integration by, in order:

* the integration's ``inbound_token`` in ``?token=`` or ``X-Paddock-Token``
  (constant-time compare; a presented-but-wrong token is always a 401), and/or
* the connector's own signature check (Jira ``X-Hub-Signature``, Linear
  ``Linear-Signature``, ServiceNow shared-secret header). When a signing
  secret is configured the signature is REQUIRED; otherwise the token is.

Unknown, disabled or non-ticketing integrations are a 404. Requests are
rate-limited per integration and capped at 1 MiB. The token is only ever
read from the query string or a header -- never the path -- because access
logs and the audit trail record the path.
"""
from __future__ import annotations

import hmac
import json
import logging
import os
import time
from collections import deque
from typing import Any, Optional
from uuid import UUID

import asyncpg
import httpx
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse

from ..auth import client_ip
from ..db import get_pool
from ..integrations import Capability, get_connector_class
from ..integrations import connectors as _connectors
from ..integrations import ticketing
from ..integrations.secrets import decrypt_secrets

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/integrations", tags=["integrations"])

MAX_BODY = 1024 * 1024
DEDUPE_TTL_DAYS = 7


class _RateLimiter:
    """Sliding one-minute window per key, in process memory.

    Good enough for a single orchestrator replica; behind several replicas
    the effective limit is ``limit * replicas`` (still bounded)."""

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = {}

    @property
    def limit(self) -> int:
        try:
            return max(1, int(os.environ.get("PADDOCK_INBOUND_RATE_PER_MIN", "120")))
        except ValueError:
            return 120

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        q = self._hits.setdefault(key, deque())
        while q and now - q[0] > 60.0:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        if len(self._hits) > 10_000:             # bound memory under id spraying
            for k in [k for k, v in self._hits.items() if not v or now - v[-1] > 60.0]:
                self._hits.pop(k, None)
        return True

    def reset(self) -> None:
        self._hits.clear()


rate_limiter = _RateLimiter()


def _err(status: int, detail: str) -> JSONResponse:
    return JSONResponse({"detail": detail}, status_code=status)


async def _seen_before(pool: Any, integration_id: UUID, delivery_id: Optional[str]) -> bool:
    """Record a sender delivery id; True if it was already processed."""
    if not delivery_id:
        return False
    try:
        async with pool.acquire() as con:
            inserted = await con.fetchval(
                "INSERT INTO integration_inbound_deliveries (integration_id, delivery_id) "
                "VALUES ($1, $2) ON CONFLICT DO NOTHING RETURNING 1",
                integration_id, str(delivery_id)[:200],
            )
            await con.execute(
                "DELETE FROM integration_inbound_deliveries "
                f"WHERE received_at < NOW() - INTERVAL '{DEDUPE_TTL_DAYS} days'"
            )
        return inserted is None
    except asyncpg.UndefinedTableError:          # 017 not applied: no replay dedupe
        return False


@router.post("/{integration_id}/inbound")
async def integration_inbound(
    integration_id: str,
    request: Request,
    token: Optional[str] = Query(None, description="The integration's inbound token"),
    pool=Depends(get_pool),
):
    try:
        iid = UUID(integration_id)
    except ValueError:
        return _err(404, "integration not found")

    if not rate_limiter.allow(str(iid)):
        return JSONResponse({"detail": "rate limit exceeded"}, status_code=429,
                            headers={"Retry-After": "60"})

    clen = request.headers.get("content-length")
    if clen and clen.isdigit() and int(clen) > MAX_BODY:
        return _err(413, "payload too large")

    async with pool.acquire() as con:
        row = await con.fetchrow(
            "SELECT id, kind, name, enabled, config, secrets, inbound_token, allow_private "
            "FROM integrations WHERE id = $1", iid,
        )
    if row is None or not row["enabled"]:
        return _err(404, "integration not found")
    _connectors.load_all()
    try:
        cls = get_connector_class(row["kind"])
    except KeyError:
        return _err(404, "integration not found")
    if Capability.TICKET not in cls.capabilities:
        return _err(404, "integration not found")

    presented = token or request.headers.get("x-paddock-token")
    expected = row["inbound_token"]
    token_ok = False
    if presented:
        if not (expected and hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8"))):
            return _err(401, "invalid inbound token")
        token_ok = True

    body = await request.body()
    if len(body) > MAX_BODY:
        return _err(413, "payload too large")

    config = row["config"]
    if isinstance(config, str):
        config = json.loads(config or "{}")
    try:
        secret_values = decrypt_secrets(row["secrets"])
    except Exception:  # noqa: BLE001 -- never echo why (could hint at key material)
        logger.error("inbound_secret_decrypt_failed", extra={"integration_id": str(iid)})
        return _err(503, "integration credentials unavailable")

    integration = {"id": str(iid), "kind": row["kind"], "name": row["name"], "config": config}
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as http:
        conn = cls(config, secret_values, http)
        if hasattr(conn, "bind"):
            conn.bind(integration_id=iid, pool=pool, allow_private=bool(row["allow_private"]))
        conn.inbound_token_verified = token_ok
        try:
            updates = await conn.handle_inbound(dict(request.headers), body)
        except PermissionError:
            return _err(401, "signature verification failed")
        except ValueError:
            return _err(400, "malformed payload")
        except NotImplementedError:
            return _err(404, "integration not found")
        except Exception:  # noqa: BLE001
            logger.exception("inbound_handler_failed", extra={"integration_id": str(iid),
                                                               "kind": row["kind"]})
            return _err(500, "inbound handler failed")
        delivery = getattr(conn, "delivery_id", lambda h, b: None)(dict(request.headers), body)

    if await _seen_before(pool, iid, delivery):
        return {"received": len(updates), "applied": 0, "ignored": len(updates),
                "duplicate": True, "results": []}

    try:
        result = await ticketing.apply_inbound(
            pool, integration, updates[:100],
            request_id=getattr(request.state, "request_id", None),
            ip=client_ip(request), path=request.url.path,
        )
    except Exception:
        # Let the sender's retry through: forget the delivery id.
        if delivery:
            async with pool.acquire() as con:
                await con.execute(
                    "DELETE FROM integration_inbound_deliveries "
                    "WHERE integration_id = $1 AND delivery_id = $2", iid, str(delivery)[:200],
                )
        raise
    await ticketing.emit_events(pool, result.events)
    redis = getattr(request.app.state, "redis", None)
    if redis is not None:
        from ..queue import publish_event

        for ev in result.events:
            try:
                await publish_event(redis, {
                    "event": "finding_closed" if ev.data.get("status") in
                    ("fixed", "wontfix", "false_positive", "accepted_risk", "accepted")
                    else "finding_updated",
                    "finding_id": ev.data.get("finding_id"),
                    "status": ev.data.get("status"),
                    "origin": ev.data.get("origin"),
                })
            except Exception:  # noqa: BLE001
                logger.exception("publish_event_failed")
    # A ticket closed as "fixed" is a claim: schedule the safe re-check that proves it.
    from ..verification import service as verification_service

    for ev in result.events:
        if ev.data.get("status") == "fixed" and ev.data.get("finding_id"):
            await verification_service.schedule_fix_check(
                pool, redis, ev.data["finding_id"], trigger="fix_ticket",
                actor=f"integration:{integration.get('kind') or 'ticket'}")
    return result.as_dict()
