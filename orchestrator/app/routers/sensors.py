"""Sentry sensors: enrollment tokens, enrollment, heartbeat, listing, revoke.

Three audiences share this router (see ``auth._RULES``):

* **admins** (dashboard): create/list/revoke enrollment tokens, list/patch/
  revoke sensors. Reads need ``read``; every write needs ``admin``.
* **sensors** (``paddock-sentry``, via otdiscovery's thin proxy or directly):
  ``POST /enroll`` (enrollment token in the body) and ``POST /heartbeat``
  (``X-Sensor-Token``). Public to the middleware, authenticated in-handler.
* **otdiscovery** (service key): ``POST /ingest/claim`` and ``/ingest/done``
  wrap each upload so a retried batch is applied exactly once.

Logic lives in ``app/sensors.py``.
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field

from .. import audit, sensors as svc
from ..auth import Principal, client_ip, current_principal
from ..db import get_pool
from ..netkey import client_key

router = APIRouter(prefix="/v1/sensors", tags=["sensors"])

_SITE_RE = re.compile(r"^[\w .:/@#()+,-]{1,80}$")
_BATCH_RE = re.compile(r"^[A-Za-z0-9._:-]{8,100}$")


# --------------------------------------------------------------------------- #
# models
# --------------------------------------------------------------------------- #

class TokenCreateIn(BaseModel):
    model_config = {"extra": "forbid"}
    site: str = Field(min_length=1, max_length=80, description="site / location name")
    label: str | None = Field(default=None, max_length=120)
    ttl_minutes: int = Field(default=svc.DEFAULT_TTL_MINUTES, ge=5, le=svc.MAX_TTL_MINUTES)


class TokenOut(BaseModel):
    id: uuid.UUID
    token_prefix: str
    site: str
    label: str | None
    created_by: str | None
    created_at: datetime
    expires_at: datetime
    state: str = Field(description="pending | used | expired | revoked")
    used_by_sensor: uuid.UUID | None = None


class TokenCreated(TokenOut):
    token: str = Field(description="the enrollment token; shown ONCE")


class InterfaceIn(BaseModel):
    model_config = {"extra": "ignore"}
    name: str = Field(max_length=32)
    up: bool | None = None
    speed_mbps: int | None = Field(default=None, ge=0, le=1_000_000)
    mac: str | None = Field(default=None, max_length=17)


class EnrollIn(BaseModel):
    model_config = {"extra": "forbid"}
    token: str = Field(min_length=10, max_length=256)
    hostname: str | None = Field(default=None, max_length=253)
    name: str | None = Field(default=None, max_length=128)
    version: str | None = Field(default=None, max_length=64)
    interfaces: list[InterfaceIn] = Field(default_factory=list, max_length=32)


class EnrollOut(BaseModel):
    sensor_id: uuid.UUID
    name: str
    site: str
    credential: str = Field(description="per-sensor credential; shown ONCE, store 0600")
    credential_prefix: str
    heartbeat_interval_s: int


class HealthIn(BaseModel):
    """The ONLY telemetry a sensor sends: counters about itself, never traffic."""
    model_config = {"extra": "ignore"}
    sent_at: float | None = Field(default=None, description="sensor wall clock (epoch s), for skew")
    iface: str | None = Field(default=None, max_length=32)
    uptime_s: int | None = Field(default=None, ge=0)
    packets_seen: int | None = Field(default=None, ge=0)
    packets_dropped: int | None = Field(default=None, ge=0, description="kernel drops at capture")
    flows_dropped: int | None = Field(default=None, ge=0)
    buffer_fill_pct: float | None = Field(default=None, ge=0, le=100)
    buffer_bytes: int | None = Field(default=None, ge=0)
    buffer_batches: int | None = Field(default=None, ge=0)
    batches_dropped: int | None = Field(default=None, ge=0, description="evicted by the buffer cap")
    last_upload_ts: float | None = None
    last_upload_ok: bool | None = None


class HeartbeatIn(BaseModel):
    model_config = {"extra": "ignore"}
    version: str | None = Field(default=None, max_length=64)
    interfaces: list[InterfaceIn] | None = Field(default=None, max_length=32)
    health: HealthIn = Field(default_factory=HealthIn)


class SensorOut(BaseModel):
    id: uuid.UUID
    name: str
    site: str
    state: str = Field(description="online | degraded | offline | revoked")
    status: str
    version: str | None
    hostname: str | None
    interfaces: list[dict[str, Any]]
    enrolled_at: datetime
    last_seen_at: datetime | None
    last_heartbeat_at: datetime | None
    last_upload_at: datetime | None
    offline_since: datetime | None
    silent_after_s: int
    health: dict[str, Any]
    warnings: list[str]
    scope_declared: bool = Field(
        False, description="The sensor has a declared scope (`/v1/assurance/sensor-scopes`). Without one it covers "
                           "nothing for the reach graph, however much traffic it sees.")
    batches_total: int
    flows_total: int
    duplicates_total: int


class SensorPatch(BaseModel):
    model_config = {"extra": "forbid"}
    name: str | None = Field(default=None, min_length=1, max_length=128)
    site: str | None = Field(default=None, min_length=1, max_length=80)
    silent_after_s: int | None = Field(default=None, ge=30, le=86_400)


class ClaimIn(BaseModel):
    model_config = {"extra": "forbid"}
    batch_id: str
    client_ip: str | None = Field(default=None, max_length=64)


class DoneIn(BaseModel):
    model_config = {"extra": "forbid"}
    batch_id: str
    ok: bool = True
    flows: int = Field(default=0, ge=0)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _j(v: Any, default: Any) -> Any:
    if isinstance(v, str):
        try:
            return json.loads(v)
        except ValueError:
            return default
    return v if v is not None else default


def _token_out(row: Any) -> dict[str, Any]:
    return {
        "id": row["id"], "token_prefix": row["token_prefix"], "site": row["site"],
        "label": row["label"], "created_by": row["created_by"], "created_at": row["created_at"],
        "expires_at": row["expires_at"], "state": svc.token_state(row),
        "used_by_sensor": row["used_by_sensor"],
    }


def _sensor_out(row: Any) -> SensorOut:
    health = _j(row["health"], {})
    return SensorOut(
        id=row["id"], name=row["name"], site=row["site"], state=svc.sensor_state(row),
        status=row["status"], version=row["version"], hostname=row["hostname"],
        interfaces=_j(row["interfaces"], []), enrolled_at=row["enrolled_at"],
        last_seen_at=row["last_seen_at"], last_heartbeat_at=row["last_heartbeat_at"],
        last_upload_at=row["last_upload_at"], offline_since=row["offline_since"],
        silent_after_s=row["silent_after_s"], health=health, warnings=svc.warnings_for(row),
        scope_declared=bool(row["scope_declared"]),
        batches_total=row["batches_total"], flows_total=row["flows_total"],
        duplicates_total=row["duplicates_total"],
    )


_SENSOR_COLS = (
    "id, name, site, status, version, hostname, interfaces, enrolled_at, last_seen_at, "
    "last_heartbeat_at, last_upload_at, offline_since, silent_after_s, health, online, "
    "batches_total, flows_total, duplicates_total, "
    # P2.1 (6.5): does the sensor have a declared, non-empty scope? (RLS scopes the subquery to the tenant)
    "EXISTS (SELECT 1 FROM sensor_scopes ss WHERE ss.sensor_id = sensors.id "
    "AND cardinality(ss.cidrs) > 0) AS scope_declared"
)


def _client_ip(request: Request) -> str:
    """The caller's address. ``X-Sensor-Client-IP`` is honoured only when the
    request carries the service credential (otdiscovery proxying a sensor)."""
    p = getattr(request.state, "principal", None)
    fwd = request.headers.get("x-sensor-client-ip")
    if fwd and p is not None and getattr(p, "kind", "") == "service":
        return client_key(fwd[:64])
    # client_ip() honours X-Forwarded-For only from a configured trusted proxy;
    # keying on the raw socket peer would make every client behind the proxy
    # share one lockout bucket (one attacker locks every sensor out).
    return client_key(client_ip(request))


def _require_service(principal: Principal) -> None:
    if not principal.has("write"):
        raise HTTPException(status_code=403, detail="service credential required")


async def _audit(request: Request, pool: Any, *, action: str, actor: str, role: str | None,
                 resource_id: str, details: dict[str, Any]) -> None:
    await audit.record(
        pool, action=action, actor=actor, actor_role=role, resource_type="sensor",
        resource_id=resource_id, method=request.method, path=request.url.path, status=200,
        request_id=getattr(request.state, "request_id", None), details=details,
    )


# --------------------------------------------------------------------------- #
# admin: enrollment tokens
# --------------------------------------------------------------------------- #

@router.post("/tokens", response_model=TokenCreated, status_code=201)
async def create_token(body: TokenCreateIn, request: Request, pool=Depends(get_pool),
                       principal: Principal = Depends(current_principal)):
    """Create a one-time enrollment token. The token is returned ONCE."""
    site = body.site.strip()
    if not _SITE_RE.match(site):
        raise HTTPException(status_code=422, detail="site contains unsupported characters")
    full, row = await svc.create_token(pool, site=site, label=(body.label or "").strip() or None,
                                       ttl_minutes=body.ttl_minutes, actor=principal.actor)
    await _audit(request, pool, action="sensor.token.create", actor=principal.actor,
                 role=principal.role, resource_id=str(row["id"]),
                 details={"site": site, "ttl_minutes": body.ttl_minutes, "prefix": row["token_prefix"]})
    return TokenCreated(token=full, **_token_out(row))


@router.get("/tokens", response_model=list[TokenOut])
async def list_tokens(pool=Depends(get_pool), limit: int = Query(default=100, ge=1, le=500)):
    async with pool.acquire() as con:
        rows = await con.fetch(
            """SELECT id, token_prefix, site, label, created_by, created_at, expires_at,
                      used_at, used_by_sensor, revoked_at
                 FROM sensor_enroll_tokens ORDER BY created_at DESC LIMIT $1""", limit)
    return [TokenOut(**_token_out(r)) for r in rows]


@router.delete("/tokens/{token_id}", status_code=204)
async def revoke_token(token_id: uuid.UUID, request: Request, pool=Depends(get_pool),
                       principal: Principal = Depends(current_principal)):
    if not await svc.revoke_token(pool, token_id, principal.actor):
        raise HTTPException(status_code=404, detail="token not found, already used or already revoked")
    await _audit(request, pool, action="sensor.token.revoke", actor=principal.actor,
                 role=principal.role, resource_id=str(token_id), details={})


# --------------------------------------------------------------------------- #
# sensor-facing
# --------------------------------------------------------------------------- #

@router.post("/enroll", response_model=EnrollOut, status_code=201)
async def enroll(body: EnrollIn, request: Request, pool=Depends(get_pool)):
    """Redeem an enrollment token. Authenticated by the token itself; rate
    limited per client, with a lockout after repeated failures."""
    ip = _client_ip(request)
    if svc.enroll_fail_limiter.blocked(ip) or not svc.enroll_limiter.hit(ip):
        raise HTTPException(status_code=429, detail="too many enrollment attempts; wait and retry",
                            headers={"Retry-After": "60"})
    try:
        out = await svc.redeem_token(
            pool, body.token, hostname=body.hostname, version=body.version, name=body.name,
            interfaces=[i.model_dump(exclude_none=True) for i in body.interfaces])
    except svc.EnrollError as exc:
        svc.enroll_fail_limiter.hit(ip)
        raise HTTPException(status_code=exc.status, detail=exc.detail) from exc
    s = out["sensor"]
    return EnrollOut(sensor_id=s["id"], name=s["name"], site=s["site"], credential=out["credential"],
                     credential_prefix=out["credential_prefix"],
                     heartbeat_interval_s=svc.heartbeat_interval_s())


@router.post("/heartbeat")
async def heartbeat(body: HeartbeatIn, pool=Depends(get_pool),
                    x_sensor_token: str | None = Header(default=None, alias="X-Sensor-Token")):
    sensor = await svc.authenticate(pool, x_sensor_token)
    if not svc.heartbeat_limiter.hit(str(sensor["id"])):
        raise HTTPException(status_code=429, detail="heartbeat too frequent", headers={"Retry-After": "10"})
    return await svc.heartbeat(
        pool, sensor, version=body.version,
        interfaces=None if body.interfaces is None else [i.model_dump(exclude_none=True) for i in body.interfaces],
        health=body.health.model_dump(exclude_none=True))


# --------------------------------------------------------------------------- #
# service (otdiscovery): idempotent upload bracket
# --------------------------------------------------------------------------- #

@router.post("/ingest/claim")
async def ingest_claim(body: ClaimIn, pool=Depends(get_pool),
                       principal: Principal = Depends(current_principal),
                       x_sensor_token: str | None = Header(default=None, alias="X-Sensor-Token")):
    _require_service(principal)
    if not _BATCH_RE.match(body.batch_id):
        raise HTTPException(status_code=422, detail="batch_id must be 8-100 chars of [A-Za-z0-9._:-]")
    sensor = await svc.authenticate(pool, x_sensor_token)
    state = await svc.claim_batch(pool, sensor, body.batch_id)
    return {"state": state, "sensor_id": str(sensor["id"]), "tenant_id": str(sensor["tenant_id"]),
            "name": sensor["name"], "site": sensor["site"]}


@router.post("/ingest/done")
async def ingest_done(body: DoneIn, pool=Depends(get_pool),
                      principal: Principal = Depends(current_principal),
                      x_sensor_token: str | None = Header(default=None, alias="X-Sensor-Token")):
    _require_service(principal)
    sensor = await svc.authenticate(pool, x_sensor_token)
    await svc.complete_batch(pool, sensor, body.batch_id, ok=body.ok, flows=body.flows)
    return {"ok": True}


# --------------------------------------------------------------------------- #
# admin: sensors
# --------------------------------------------------------------------------- #

@router.get("", response_model=list[SensorOut])
async def list_sensors(pool=Depends(get_pool), include_revoked: bool = True):
    async with pool.acquire() as con:
        rows = await con.fetch(
            f"SELECT {_SENSOR_COLS} FROM sensors "
            "WHERE ($1 OR status = 'active') ORDER BY site, name LIMIT 1000", include_revoked)
    return [_sensor_out(r) for r in rows]


@router.get("/{sensor_id}", response_model=SensorOut)
async def get_sensor(sensor_id: uuid.UUID, pool=Depends(get_pool)):
    async with pool.acquire() as con:
        row = await con.fetchrow(f"SELECT {_SENSOR_COLS} FROM sensors WHERE id = $1", sensor_id)
    if row is None:
        raise HTTPException(status_code=404, detail="sensor not found")
    return _sensor_out(row)


@router.patch("/{sensor_id}", response_model=SensorOut)
async def patch_sensor(sensor_id: uuid.UUID, body: SensorPatch, request: Request, pool=Depends(get_pool),
                       principal: Principal = Depends(current_principal)):
    if body.site is not None and not _SITE_RE.match(body.site.strip()):
        raise HTTPException(status_code=422, detail="site contains unsupported characters")
    async with pool.acquire() as con:
        row = await con.fetchrow(
            f"""UPDATE sensors SET name = COALESCE($2, name), site = COALESCE($3, site),
                       silent_after_s = COALESCE($4, silent_after_s)
                 WHERE id = $1 RETURNING {_SENSOR_COLS}""",
            sensor_id, body.name, body.site.strip() if body.site else None, body.silent_after_s)
    if row is None:
        raise HTTPException(status_code=404, detail="sensor not found")
    await _audit(request, pool, action="sensor.update", actor=principal.actor, role=principal.role,
                 resource_id=str(sensor_id), details=body.model_dump(exclude_none=True))
    return _sensor_out(row)


@router.post("/{sensor_id}/revoke", response_model=SensorOut)
async def revoke_sensor(sensor_id: uuid.UUID, request: Request, pool=Depends(get_pool),
                        principal: Principal = Depends(current_principal)):
    """Revoke a sensor. Its credential stops working on the very next call."""
    done = await svc.revoke_sensor(pool, sensor_id, principal.actor)
    if done is None:
        raise HTTPException(status_code=404, detail="sensor not found or already revoked")
    await _audit(request, pool, action="sensor.revoke", actor=principal.actor, role=principal.role,
                 resource_id=str(sensor_id), details={"name": done["name"], "site": done["site"]})
    async with pool.acquire() as con:
        row = await con.fetchrow(f"SELECT {_SENSOR_COLS} FROM sensors WHERE id = $1", sensor_id)
    return _sensor_out(row)
