"""AuthN + API-key management endpoints (schema 011).

- ``POST /v1/auth/login``   -- username/password -> short-lived JWT.
- ``GET  /v1/auth/me``      -- the current principal.
- ``POST /v1/auth/apikeys`` -- issue a key (admin). Raw key returned once.
- ``GET  /v1/auth/apikeys`` -- list keys (admin).
- ``DELETE /v1/auth/apikeys/{id}`` -- revoke a key (admin).
"""
from __future__ import annotations

import functools
import logging
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from starlette.concurrency import run_in_threadpool

from .. import auth as auth_svc
from ..auth import current_principal, require
from ..config import settings
from ..db import get_pool
from ..models import (
    ApiKeyCreateIn,
    ApiKeyCreateOut,
    ApiKeyOut,
    LoginIn,
    LoginOut,
    MeOut,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/auth", tags=["auth"])


# A real hash of a random secret: verifying against it costs exactly what a
# real verify costs, so "no such user" and "wrong password" take equal time.
@functools.cache
def _dummy_hash() -> str:
    return auth_svc.hash_password(secrets.token_urlsafe(32))

# Sliding-window failure counters, keyed by username and by client ip.
_failures: dict[str, deque[float]] = defaultdict(deque)


def _too_many(key: str, now: float) -> bool:
    q = _failures[key]
    while q and now - q[0] > settings.login_window_sec:
        q.popleft()
    return len(q) >= settings.login_max_failures


@router.post("/login", response_model=LoginOut)
async def login(body: LoginIn, request: Request, pool=Depends(get_pool)):
    now = time.monotonic()
    keys = (f"u:{body.username.lower()}", f"ip:{auth_svc.client_ip(request)}")
    if any(_too_many(k, now) for k in keys):
        raise HTTPException(
            status_code=429,
            detail="too many failed logins; try again later",
            headers={"Retry-After": str(settings.login_window_sec)},
        )
    async with pool.acquire() as con:
        row = await con.fetchrow(
            "SELECT id, username, role, clearance, pw_hash, active "
            "FROM app_users WHERE username = $1",
            body.username,
        )
    stored = (row["pw_hash"] if row else None) or _dummy_hash()
    # bcrypt is CPU-bound: run it off the event loop so a login flood can't
    # stall every other request (incl. workers' scope checks).
    ok = await run_in_threadpool(auth_svc.verify_password, body.password, stored)
    if row is None or not row["active"] or not row["pw_hash"] or not ok:
        for k in keys:
            _failures[k].append(now)
        raise HTTPException(status_code=401, detail="invalid credentials")
    for k in keys:
        _failures.pop(k, None)
    async with pool.acquire() as con:
        await con.execute("UPDATE app_users SET last_login = NOW() WHERE id = $1", row["id"])
    token, ttl = auth_svc.issue_jwt(
        user_id=str(row["id"]),
        username=row["username"],
        role=row["role"],
        clearance=row["clearance"],
    )
    return LoginOut(
        access_token=token,
        role=row["role"],
        clearance=row["clearance"],
        expires_in=ttl,
    )


@router.get("/me", response_model=MeOut)
async def me(principal=Depends(current_principal)):
    return MeOut(
        actor=principal.actor,
        role=principal.role,
        clearance=principal.clearance,
        capabilities=sorted(principal.capabilities),
        kind=principal.kind,
    )


@router.post(
    "/apikeys",
    response_model=ApiKeyCreateOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require("admin"))],
)
async def create_apikey(
    body: ApiKeyCreateIn,
    request: Request,
    pool=Depends(get_pool),
):
    principal = current_principal(request)
    owner = body.username or principal.actor
    async with pool.acquire() as con:
        user = await con.fetchrow(
            "SELECT id FROM app_users WHERE username = $1", owner
        )
        if user is None:
            raise HTTPException(status_code=404, detail=f"user '{owner}' not found")
        full, prefix, key_hash = auth_svc.generate_api_key()
        scopes = [s for s in body.scopes if s] or ["read"]
        row = await con.fetchrow(
            """
            INSERT INTO api_keys (user_id, name, prefix, key_hash, scopes, expires_at)
            VALUES ($1, $2, $3, $4, $5::text[], $6)
            RETURNING id, user_id, name, prefix, scopes, created_at, last_used,
                      expires_at, revoked
            """,
            user["id"],
            body.name,
            prefix,
            key_hash,
            scopes,
            body.expires_at,
        )
    d = dict(row)
    d["api_key"] = full
    logger.info("api_key_created", extra={"prefix": prefix, "owner": owner})
    return ApiKeyCreateOut.model_validate(d)


@router.get(
    "/apikeys",
    response_model=list[ApiKeyOut],
    dependencies=[Depends(require("admin"))],
)
async def list_apikeys(pool=Depends(get_pool)):
    async with pool.acquire() as con:
        rows = await con.fetch(
            """
            SELECT id, user_id, name, prefix, scopes, created_at, last_used,
                   expires_at, revoked
              FROM api_keys
             ORDER BY created_at DESC
            """
        )
    return [ApiKeyOut.model_validate(dict(r)) for r in rows]


@router.delete(
    "/apikeys/{key_id}",
    response_model=ApiKeyOut,
    dependencies=[Depends(require("admin"))],
)
async def revoke_apikey(key_id: UUID, pool=Depends(get_pool)):
    async with pool.acquire() as con:
        row = await con.fetchrow(
            """
            UPDATE api_keys SET revoked = TRUE
             WHERE id = $1
         RETURNING id, user_id, name, prefix, scopes, created_at, last_used,
                   expires_at, revoked
            """,
            key_id,
        )
    if row is None:
        raise HTTPException(status_code=404, detail="api key not found")
    logger.info("api_key_revoked", extra={"key_id": str(key_id)})
    return ApiKeyOut.model_validate(dict(row))
