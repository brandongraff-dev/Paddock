"""/v1/integrations -- the Integrations page API.

* ``GET  /catalog``                      every registered connector + the event catalogue
* ``GET  /health``                       summary for the page header / status checks
* ``GET  /`` / ``POST /``                list / create
* ``GET|PATCH|DELETE /{id}``             read / update / delete
* ``POST /{id}/enable`` ``/{id}/disable``
* ``POST /{id}/test``                    synchronous ``integration.test`` delivery (or ``mode=health``)
* ``GET  /{id}/deliveries``              paginated delivery log
* ``POST /{id}/deliveries/{did}/retry``  re-queue one delivery

Secrets are write-only: they are encrypted before they touch the database and
only ever returned redacted (``secrets.redact``). Writes need ``admin`` (see the
RBAC table in ``app.auth``) and are audited by the governance middleware.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime
from typing import Any, Literal, Optional

import asyncpg
from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from .. import auth as auth_svc
from ..config import settings
from ..db import get_pool
from ..integrations import netsafety, secrets as secrets_mod, service
from ..integrations.base import EVENT_TYPES, REGISTRY, SEVERITIES, Connector
from ..integrations.configschema import ConfigError, validate_config

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/integrations", tags=["integrations"])

service.load_connectors()

REDACTED = "********"


# --------------------------------------------------------------------------- #
# Models (kept here, not in app/models.py)
# --------------------------------------------------------------------------- #

class IntegrationIn(BaseModel):
    kind: str
    name: str = Field(min_length=1, max_length=100)
    enabled: bool = True
    config: dict[str, Any] = Field(default_factory=dict)
    secrets: dict[str, Optional[str]] = Field(default_factory=dict)
    events: list[str] = Field(default_factory=list)
    min_severity: str = "low"
    filters: dict[str, Any] = Field(default_factory=dict)
    allow_private: bool = False


class IntegrationPatch(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    enabled: Optional[bool] = None
    config: Optional[dict[str, Any]] = None
    # value -> set; "" or null -> clear; "********" (the redaction marker) -> keep
    secrets: Optional[dict[str, Optional[str]]] = None
    events: Optional[list[str]] = None
    min_severity: Optional[str] = None
    filters: Optional[dict[str, Any]] = None
    allow_private: Optional[bool] = None


class TestIn(BaseModel):
    mode: Literal["deliver", "health"] = "deliver"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

_COLS = ("id, kind, name, enabled, config, secrets, events, min_severity, filters, allow_private, "
         "created_by, created_at, updated_at, last_ok_at, last_error, last_error_at")


def _err(status: int, message: str, errors: list[str] | None = None) -> HTTPException:
    detail: Any = message if errors is None else {"message": message, "errors": errors}
    return HTTPException(status_code=status, detail=detail)


def _cls(kind: str) -> type[Connector]:
    cls = REGISTRY.get(kind)
    if cls is None:
        raise _err(422, f"unknown integration kind {kind!r}", [f"kind: must be one of {', '.join(sorted(REGISTRY))}"])
    return cls


def _json(v: Any, default: Any) -> Any:
    return service._as_json(v, default)


def _iso(v: Optional[datetime]) -> Optional[str]:
    return v.isoformat() if v else None


def _status(row: dict[str, Any]) -> str:
    if not row["enabled"]:
        return "disabled"
    ok, err = row.get("last_ok_at"), row.get("last_error_at")
    if err and (not ok or err > ok):
        return "error"
    if ok:
        return "ok"
    return "never"


def _decrypt_or_none(blob: Optional[str]) -> Optional[dict[str, str]]:
    try:
        return secrets_mod.decrypt_secrets(blob)
    except Exception:  # noqa: BLE001
        return None


def _out(row: Any, stats: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    r = dict(row)
    cls = REGISTRY.get(r["kind"])
    secret_fields = list(cls.secret_fields) if cls else []
    values = _decrypt_or_none(r.get("secrets"))
    present = values or {}
    redacted = secrets_mod.redact({f: present.get(f, "") for f in secret_fields})
    for extra in present:                       # stored fields a connector no longer declares
        redacted.setdefault(extra, REDACTED if present[extra] else "")
    out = {
        "id": str(r["id"]),
        "kind": r["kind"],
        "name": r["name"],
        "display_name": cls.display_name if cls else r["kind"],
        "category": cls.category if cls else "other",
        "capabilities": sorted(c.value for c in cls.capabilities) if cls else [],
        "enabled": r["enabled"],
        "config": _json(r["config"], {}),
        "secrets": redacted,
        "secret_fields": secret_fields,
        "secrets_error": (None if values is not None else
                          "stored credentials cannot be decrypted with the configured key; re-enter them"),
        "events": list(r["events"] or []),
        "min_severity": r["min_severity"],
        "filters": _json(r["filters"], {}),
        "allow_private": r["allow_private"],
        "created_by": r.get("created_by"),
        "created_at": _iso(r.get("created_at")),
        "updated_at": _iso(r.get("updated_at")),
        "last_ok_at": _iso(r.get("last_ok_at")),
        "last_error": r.get("last_error"),
        "last_error_at": _iso(r.get("last_error_at")),
        "status": _status(r),
        "available": cls is not None,
    }
    out["stats"] = stats or {"pending": 0, "failed": 0, "dead": 0, "sent_24h": 0}
    del values, present
    return out


_STATS_SQL = """
SELECT integration_id,
       COUNT(*) FILTER (WHERE status = 'pending')                                     AS pending,
       COUNT(*) FILTER (WHERE status = 'failed' AND next_attempt_at IS NOT NULL)      AS failed,
       COUNT(*) FILTER (WHERE status = 'dead')                                        AS dead,
       COUNT(*) FILTER (WHERE status = 'sent' AND updated_at > NOW() - INTERVAL '24 hours') AS sent_24h
  FROM integration_deliveries
 WHERE ($1::uuid IS NULL OR integration_id = $1)
 GROUP BY integration_id
"""


async def _stats(pool: Any, integration_id: Optional[uuid.UUID] = None) -> dict[Any, dict[str, int]]:
    rows = await pool.fetch(_STATS_SQL, integration_id)
    return {r["integration_id"]: {k: int(r[k]) for k in ("pending", "failed", "dead", "sent_24h")} for r in rows}


async def _load(pool: Any, integration_id: uuid.UUID) -> dict[str, Any]:
    row = await pool.fetchrow(f"SELECT {_COLS} FROM integrations WHERE id = $1", integration_id)
    if row is None:
        raise _err(404, "integration not found")
    return dict(row)


def _validate_events(events: list[str]) -> list[str]:
    bad = [e for e in events if e not in EVENT_TYPES]
    if bad:
        raise _err(422, "unknown event type(s)", [f"events: unknown {b!r}" for b in bad])
    return sorted(set(events), key=list(EVENT_TYPES).index)


def _validate_severity(sev: str) -> str:
    if sev not in SEVERITIES:
        raise _err(422, "invalid min_severity", [f"min_severity: must be one of {', '.join(SEVERITIES)}"])
    return sev


def _validate_filters(filters: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    out: dict[str, Any] = {}
    for k, v in (filters or {}).items():
        if k not in service.FILTER_KEYS:
            errors.append(f"filters.{k}: unknown filter (allowed: {', '.join(service.FILTER_KEYS)})")
            continue
        if v in (None, "", []):
            continue
        vals = v if isinstance(v, list) else [v]
        if not all(isinstance(x, str) and 0 < len(x) <= 200 for x in vals) or len(vals) > 100:
            errors.append(f"filters.{k}: must be a list of up to 100 non-empty strings")
            continue
        out[k] = [x.strip() for x in vals if x.strip()]
    if errors:
        raise _err(422, "invalid filters", errors)
    return out


def _merge_secrets(existing: dict[str, str], incoming: Optional[dict[str, Optional[str]]],
                   cls: type[Connector]) -> dict[str, str]:
    merged = dict(existing)
    if not incoming:
        return merged
    unknown = [k for k in incoming if k not in cls.secret_fields]
    if unknown:
        raise _err(422, "unknown secret field(s)", [f"secrets.{k}: not a secret field of {cls.kind}" for k in unknown])
    for k, v in incoming.items():
        if v == REDACTED:
            continue                              # the UI echoed the mask back: keep
        if v is None or v == "":
            merged.pop(k, None)
        else:
            merged[k] = v
    return merged


async def _validate_all(cls: type[Connector], config: dict[str, Any], secret_values: dict[str, str],
                        allow_private: bool) -> dict[str, Any]:
    try:
        cfg = validate_config(config, cls.config_schema)
    except ConfigError as exc:
        raise _err(422, "invalid configuration", [f"config.{e}" for e in exc.errors]) from None
    missing = [f for f in getattr(cls, "required_secrets", ()) if not secret_values.get(f)]
    if missing:
        raise _err(422, "missing credentials", [f"secrets.{f}: is required" for f in missing])
    for f in getattr(cls, "url_fields", ()):
        url = cfg.get(f) if f in cfg else secret_values.get(f)
        if not url:
            continue
        where = "config" if f in cfg else "secrets"
        try:
            await netsafety.validate_outbound_url(str(url), allow_private=allow_private)
        except netsafety.UnsafeURL as exc:
            raise _err(422, "URL refused by the outbound policy", [f"{where}.{f}: {exc}"]) from None
    return cfg


def _encrypt(values: dict[str, str]) -> Optional[str]:
    if not values:
        return None
    if settings.auth_mode == "enforce" and not secrets_mod.has_persistent_key():
        raise _err(503, "PADDOCK_SECRET_KEY is not configured; refusing to store credentials "
                        "(generate one: python -c \"import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode())\")")
    return secrets_mod.encrypt_secrets(values)


def _transport(request: Request) -> Any:
    return getattr(request.app.state, "integrations_transport", None)


# --------------------------------------------------------------------------- #
# Catalogue + health (declared before /{id} routes)
# --------------------------------------------------------------------------- #

@router.get("/catalog")
async def catalog() -> dict[str, Any]:
    service.load_connectors()
    connectors = []
    for kind in sorted(REGISTRY):
        cls = REGISTRY[kind]
        if kind.startswith("_"):
            continue                              # test doubles
        d = cls.describe()
        d["required_secrets"] = list(getattr(cls, "required_secrets", ()))
        connectors.append(d)
    return {
        "connectors": connectors,
        "events": [{"type": t, "description": d} for t, d in EVENT_TYPES.items()],
        "severities": list(SEVERITIES),
        "filters": list(service.FILTER_KEYS),
    }


@router.get("/health")
async def health(pool=Depends(get_pool)) -> dict[str, Any]:
    rows = [dict(r) for r in await pool.fetch(
        "SELECT id, kind, name, enabled, last_ok_at, last_error, last_error_at FROM integrations ORDER BY name")]
    agg = await pool.fetchrow(
        """
        SELECT COUNT(*) FILTER (WHERE status = 'pending')                                AS pending,
               COUNT(*) FILTER (WHERE status = 'failed' AND next_attempt_at IS NOT NULL) AS failed,
               COUNT(*) FILTER (WHERE status = 'dead')                                   AS dead,
               COUNT(*) FILTER (WHERE status = 'sent' AND updated_at > NOW() - INTERVAL '24 hours') AS sent_24h,
               MIN(next_attempt_at) FILTER (WHERE status IN ('pending', 'failed'))       AS oldest_due_at,
               BOOL_OR(status IN ('pending', 'failed') AND next_attempt_at < NOW() - INTERVAL '10 minutes') AS stalled
          FROM integration_deliveries
        """
    )
    counts = {"total": len(rows), "enabled": 0, "ok": 0, "error": 0, "never": 0, "disabled": 0}
    items = []
    for r in rows:
        st = _status(r)
        counts[st] += 1
        counts["enabled"] += int(r["enabled"])
        items.append({"id": str(r["id"]), "kind": r["kind"], "name": r["name"], "status": st,
                      "last_ok_at": _iso(r["last_ok_at"]), "last_error_at": _iso(r["last_error_at"]),
                      "last_error": r["last_error"]})
    stalled = bool(agg["stalled"])
    overall = "empty" if not rows else ("degraded" if counts["error"] or int(agg["dead"]) or stalled else "ok")
    return {
        "status": overall,
        "integrations": counts,
        "deliveries": {
            "pending": int(agg["pending"]), "failed": int(agg["failed"]), "dead": int(agg["dead"]),
            "sent_24h": int(agg["sent_24h"]), "oldest_due_at": _iso(agg["oldest_due_at"]),
            "stalled": stalled,
        },
        "secret_key_persistent": secrets_mod.has_persistent_key(),
        "items": items,
    }


# --------------------------------------------------------------------------- #
# CRUD
# --------------------------------------------------------------------------- #

@router.get("")
async def list_integrations(kind: Optional[str] = Query(None), pool=Depends(get_pool)) -> dict[str, Any]:
    rows = await pool.fetch(
        f"SELECT {_COLS} FROM integrations WHERE ($1::text IS NULL OR kind = $1) ORDER BY created_at, name", kind)
    stats = await _stats(pool)
    items = [_out(r, stats.get(r["id"])) for r in rows]
    return {"items": items, "total": len(items)}


@router.post("", status_code=201)
async def create_integration(body: IntegrationIn, request: Request, pool=Depends(get_pool)) -> dict[str, Any]:
    cls = _cls(body.kind)
    events = _validate_events(body.events)
    sev = _validate_severity(body.min_severity)
    filters = _validate_filters(body.filters)
    secret_values = _merge_secrets({}, body.secrets, cls)
    cfg = await _validate_all(cls, body.config, secret_values, body.allow_private)
    blob = _encrypt(secret_values)
    principal = auth_svc.current_principal(request)
    try:
        row = await pool.fetchrow(
            f"""
            INSERT INTO integrations (kind, name, enabled, config, secrets, events, min_severity,
                                      filters, allow_private, created_by)
            VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8::jsonb, $9, $10)
            RETURNING {_COLS}
            """,
            body.kind, body.name.strip(), body.enabled, json.dumps(cfg), blob, events, sev,
            json.dumps(filters), body.allow_private, principal.actor,
        )
    except asyncpg.UniqueViolationError:
        raise _err(409, f"a {body.kind} integration named {body.name!r} already exists") from None
    del secret_values
    logger.info("integration_created", extra={"integration_id": str(row["id"]), "kind": body.kind})
    return _out(row)


@router.get("/{integration_id}")
async def get_integration(integration_id: uuid.UUID, pool=Depends(get_pool)) -> dict[str, Any]:
    row = await _load(pool, integration_id)
    stats = await _stats(pool, integration_id)
    return _out(row, stats.get(integration_id))


@router.patch("/{integration_id}")
async def update_integration(integration_id: uuid.UUID, body: IntegrationPatch,
                             pool=Depends(get_pool)) -> dict[str, Any]:
    row = await _load(pool, integration_id)
    cls = _cls(row["kind"])
    existing = _decrypt_or_none(row["secrets"]) or {}
    secret_values = _merge_secrets(existing, body.secrets, cls)
    allow_private = row["allow_private"] if body.allow_private is None else body.allow_private
    config = _json(row["config"], {}) if body.config is None else body.config
    cfg = await _validate_all(cls, config, secret_values, allow_private)
    events = list(row["events"] or []) if body.events is None else _validate_events(body.events)
    sev = row["min_severity"] if body.min_severity is None else _validate_severity(body.min_severity)
    filters = _json(row["filters"], {}) if body.filters is None else _validate_filters(body.filters)
    secrets_changed = body.secrets is not None and secret_values != existing
    blob = _encrypt(secret_values) if secrets_changed else row["secrets"]
    try:
        new = await pool.fetchrow(
            f"""
            UPDATE integrations
               SET name = $2, enabled = $3, config = $4::jsonb, secrets = $5, events = $6,
                   min_severity = $7, filters = $8::jsonb, allow_private = $9, updated_at = NOW()
             WHERE id = $1
         RETURNING {_COLS}
            """,
            integration_id, (body.name or row["name"]).strip(),
            row["enabled"] if body.enabled is None else body.enabled,
            json.dumps(cfg), blob, events, sev, json.dumps(filters), allow_private,
        )
    except asyncpg.UniqueViolationError:
        raise _err(409, f"a {row['kind']} integration with that name already exists") from None
    del existing, secret_values
    stats = await _stats(pool, integration_id)
    return _out(new, stats.get(integration_id))


@router.delete("/{integration_id}")
async def delete_integration(integration_id: uuid.UUID, pool=Depends(get_pool)) -> dict[str, Any]:
    deleted = await pool.fetchval("DELETE FROM integrations WHERE id = $1 RETURNING id", integration_id)
    if deleted is None:
        raise _err(404, "integration not found")
    return {"ok": True, "id": str(deleted)}


async def _set_enabled(pool: Any, integration_id: uuid.UUID, enabled: bool) -> dict[str, Any]:
    row = await pool.fetchrow(
        f"UPDATE integrations SET enabled = $2, updated_at = NOW() WHERE id = $1 RETURNING {_COLS}",
        integration_id, enabled)
    if row is None:
        raise _err(404, "integration not found")
    stats = await _stats(pool, integration_id)
    return _out(row, stats.get(integration_id))


@router.post("/{integration_id}/enable")
async def enable_integration(integration_id: uuid.UUID, pool=Depends(get_pool)) -> dict[str, Any]:
    return await _set_enabled(pool, integration_id, True)


@router.post("/{integration_id}/disable")
async def disable_integration(integration_id: uuid.UUID, pool=Depends(get_pool)) -> dict[str, Any]:
    return await _set_enabled(pool, integration_id, False)


# --------------------------------------------------------------------------- #
# Test + delivery log
# --------------------------------------------------------------------------- #

@router.post("/{integration_id}/test")
async def test_integration(integration_id: uuid.UUID, request: Request,
                           body: Optional[TestIn] = Body(default=None),
                           pool=Depends(get_pool)) -> dict[str, Any]:
    row = await _load(pool, integration_id)
    mode = (body or TestIn()).mode
    if mode == "health":
        h = await service.health_check(row, transport=_transport(request))
        await service.mark_integration(pool, integration_id, service.DeliveryResult(ok=h.ok, detail=h.detail))
        return {"mode": "health", "ok": h.ok, "detail": h.detail, "status_code": None,
                "external_id": None, "external_url": None, "retryable": False, "delivery_id": None}
    event = service.make_test_event(row)
    res, did = await service.send_now(pool, row, event, transport=_transport(request))
    return {"mode": "deliver", "ok": res.ok, "status_code": res.status_code, "detail": res.detail,
            "external_id": res.external_id, "external_url": res.external_url,
            "retryable": res.retryable, "delivery_id": did, "event_id": event.id}


def _delivery_out(r: Any) -> dict[str, Any]:
    p = _json(r["payload"], {}) or {}
    return {
        "id": r["id"],
        "event_id": r["event_id"],
        "event_type": r["event_type"],
        "status": r["status"],
        "attempts": r["attempts"],
        "next_attempt_at": _iso(r["next_attempt_at"]),
        "status_code": r["status_code"],
        "detail": r["detail"],
        "created_at": _iso(r["created_at"]),
        "updated_at": _iso(r["updated_at"]),
        "title": p.get("title"),
        "severity": p.get("severity"),
        "url": p.get("url"),
    }


_DELIVERY_COLS = ("id, event_id, event_type, status, attempts, next_attempt_at, status_code, detail, "
                  "created_at, updated_at, payload")


@router.get("/{integration_id}/deliveries")
async def list_deliveries(
    integration_id: uuid.UUID,
    status: Optional[str] = Query(None, pattern="^(pending|sent|failed|dead|skipped)$"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    pool=Depends(get_pool),
) -> dict[str, Any]:
    await _load(pool, integration_id)
    total = await pool.fetchval(
        "SELECT COUNT(*) FROM integration_deliveries WHERE integration_id = $1 AND ($2::text IS NULL OR status = $2)",
        integration_id, status)
    rows = await pool.fetch(
        f"""SELECT {_DELIVERY_COLS} FROM integration_deliveries
             WHERE integration_id = $1 AND ($2::text IS NULL OR status = $2)
             ORDER BY created_at DESC, id DESC LIMIT $3 OFFSET $4""",
        integration_id, status, limit, offset)
    return {"items": [_delivery_out(r) for r in rows], "total": int(total), "limit": limit, "offset": offset}


@router.post("/{integration_id}/deliveries/{delivery_id}/retry")
async def retry_delivery(integration_id: uuid.UUID, delivery_id: int, pool=Depends(get_pool)) -> dict[str, Any]:
    row = await _load(pool, integration_id)
    if not row["enabled"]:
        raise _err(409, "integration is disabled; enable it before retrying")
    current = await pool.fetchval(
        "SELECT status FROM integration_deliveries WHERE id = $1 AND integration_id = $2",
        delivery_id, integration_id)
    if current is None:
        raise _err(404, "delivery not found")
    if current == "pending":
        raise _err(409, "delivery is already queued")
    updated = await pool.fetchrow(
        f"""UPDATE integration_deliveries
               SET status = 'pending', next_attempt_at = NOW(), detail = 'manual retry queued', updated_at = NOW()
             WHERE id = $1 AND integration_id = $2
         RETURNING {_DELIVERY_COLS}""",
        delivery_id, integration_id)
    return _delivery_out(updated)
