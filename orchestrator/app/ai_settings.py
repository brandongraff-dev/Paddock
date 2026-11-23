"""AI features: the optional Anthropic API key, set from Settings -> System.

* ``GET    /v1/system/ai``             (admin)    configured? last four characters, is brain running
* ``PUT    /v1/system/ai``             (admin)    save the key (encrypted at rest)
* ``DELETE /v1/system/ai``             (admin)    remove it
* ``GET    /v1/system/ai/credential``  (service)  the key, for the brain service ONLY

The key is encrypted with ``PADDOCK_SECRET_KEY`` (AES-256-GCM, its own AAD) and
is never returned to a browser or written to a log or the audit trail. The only
route that returns it needs the fleet ``SERVICE_API_KEY`` (a user or an API key,
even an admin's, is refused) and is marked ``no-store``. Without a saved key the
brain falls back to the ``ANTHROPIC_API_KEY`` in its own environment, and
without either it runs its deterministic fallbacks, so nothing here is required.

The key belongs to the install, not to a tenant: ``ai_settings`` is a global
table (schema/039) and only the platform (default) tenant may change it.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from . import auth as auth_svc
from . import system as system_mod
from . import tenancy
from .config import settings
from .db import get_pool
from .integrations import secrets as secrets_mod

router = APIRouter(prefix="/v1/system/ai", tags=["system"])

AAD = b"paddock-ai-settings"
# Anthropic keys look like sk-ant-api03-<base64url>. Be strict about the alphabet
# (no whitespace, quotes or control characters) and loose about the length.
KEY_RE = re.compile(r"^sk-ant-[A-Za-z0-9_\-]{20,400}$")


class AiKeyIn(BaseModel):
    api_key: str = Field(min_length=1, max_length=512, repr=False)


class AiStatus(BaseModel):
    configured: bool
    hint: Optional[str] = None            # "…abcd": last four characters, never more
    updated_at: Optional[datetime] = None
    updated_by: Optional[str] = None
    editable: bool                        # only the platform tenant may change it
    brain: str                            # up | down | not_installed (is anything there to use the key)


class AiCredential(BaseModel):
    api_key: Optional[str] = Field(default=None, repr=False)


def clean_key(raw: str) -> str:
    """Trim the stray whitespace/quotes people copy along, then validate."""
    key = raw.strip().strip("'\"").strip()
    if not KEY_RE.match(key):
        raise HTTPException(
            status_code=422,
            detail="That does not look like an Anthropic API key. It starts with 'sk-ant-' "
                   "and has no spaces; create one at console.anthropic.com > API keys.",
        )
    return key


def hint_for(key: str) -> str:
    return "…" + key[-4:]


def _is_platform() -> bool:
    return tenancy.current_tenant_id() == tenancy.DEFAULT_TENANT_ID


async def _row(pool: asyncpg.Pool) -> Optional[asyncpg.Record]:
    async with pool.acquire() as con:
        return await con.fetchrow(
            "SELECT anthropic_secret, key_hint, updated_by, updated_at FROM ai_settings WHERE id")


async def _status(request: Request, pool: asyncpg.Pool) -> AiStatus:
    row = await _row(pool)
    brain = await system_mod._probe_service(settings.brain_url)
    return AiStatus(
        configured=bool(row and row["anthropic_secret"]),
        hint=row["key_hint"] if row and row["anthropic_secret"] else None,
        updated_at=row["updated_at"] if row and row["anthropic_secret"] else None,
        updated_by=row["updated_by"] if row and row["anthropic_secret"] else None,
        editable=_is_platform(),
        brain=brain,
    )


def _require_platform() -> None:
    if not _is_platform():
        raise HTTPException(status_code=403, detail="AI settings are managed by the platform operator")


@router.get("", response_model=AiStatus)
async def get_ai(request: Request, pool: asyncpg.Pool = Depends(get_pool)) -> AiStatus:
    return await _status(request, pool)


@router.put("", response_model=AiStatus)
async def put_ai(body: AiKeyIn, request: Request, pool: asyncpg.Pool = Depends(get_pool)) -> AiStatus:
    _require_platform()
    key = clean_key(body.api_key)
    if settings.auth_mode == "enforce" and not secrets_mod.has_persistent_key():
        raise HTTPException(
            status_code=503,
            detail="PADDOCK_SECRET_KEY is not configured, so the key cannot be stored safely. "
                   "Re-run the installer (it generates one) or set it in .env.")
    blob = secrets_mod.encrypt_secrets({"anthropic_api_key": key}, aad=AAD)
    actor = auth_svc.current_principal(request).actor
    async with pool.acquire() as con:
        await con.execute(
            """
            INSERT INTO ai_settings (id, anthropic_secret, key_hint, updated_by, updated_at)
            VALUES (TRUE, $1, $2, $3, now())
            ON CONFLICT (id) DO UPDATE
               SET anthropic_secret = EXCLUDED.anthropic_secret, key_hint = EXCLUDED.key_hint,
                   updated_by = EXCLUDED.updated_by, updated_at = now()
            """,
            blob, hint_for(key), actor,
        )
    return await _status(request, pool)


@router.delete("", response_model=AiStatus)
async def delete_ai(request: Request, pool: asyncpg.Pool = Depends(get_pool)) -> AiStatus:
    _require_platform()
    async with pool.acquire() as con:
        await con.execute("DELETE FROM ai_settings WHERE id")
    return await _status(request, pool)


@router.get("/credential", response_model=AiCredential)
async def get_credential(request: Request, response: Response,
                         pool: asyncpg.Pool = Depends(get_pool)) -> AiCredential:
    """The saved key, for the brain service. Only the fleet service key may call this."""
    principal = auth_svc.current_principal(request)
    if principal.kind != "service":
        raise HTTPException(status_code=403, detail="only the service key may read this")
    response.headers["Cache-Control"] = "no-store"
    row = await _row(pool)
    if not row or not row["anthropic_secret"]:
        return AiCredential(api_key=None)
    try:
        return AiCredential(api_key=secrets_mod.decrypt_secrets(row["anthropic_secret"], aad=AAD).get("anthropic_api_key"))
    except ValueError:
        # encrypted under a key that is no longer configured: behave as "not set"
        return AiCredential(api_key=None)
