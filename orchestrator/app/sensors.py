"""Sentry sensor enrollment, credentials, health and liveness (schema 034).

The trust chain, in the order a sensor lives it:

1. An admin creates a one-time **enrollment token** (``pet_<prefix>_<secret>``)
   for a site. Only its sha256 is stored. It is single-use (redeemed with one
   atomic ``UPDATE ... WHERE used_at IS NULL``), short-lived and revocable.
2. ``paddock-sentry enroll`` redeems it and receives a per-sensor
   **credential** (``pst_<prefix>_<secret>``), shown once, stored hashed.
3. Every later call (heartbeat, upload) carries that credential. Revoking the
   sensor flips ``status`` and the very next lookup fails: nothing is cached.
4. Heartbeats carry health only (counters + versions, see ``HealthIn``);
   uploads are idempotent per ``batch_id``.
5. :func:`monitor_loop` raises ``sensor.offline`` / ``sensor.online``
   integration events when a sensor goes silent or comes back.

This module is pure logic + SQL; the HTTP surface is routers/sensors.py.
"""
from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import re
import secrets
import time
import uuid
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import HTTPException

from . import audit, tenancy
from . import auth as auth_svc
from .netkey import SlidingWindowLimiter  # noqa: F401 (re-exported)

logger = logging.getLogger(__name__)

TOKEN_SCHEME = "pet"        # paddock enrollment token
CRED_SCHEME = "pst"         # paddock sensor token
_TOKEN_RE = re.compile(r"^(pet|pst)_([0-9a-f]{8})_([A-Za-z0-9_-]{20,128})$")

MAX_TTL_MINUTES = 7 * 24 * 60
DEFAULT_TTL_MINUTES = 60
BATCH_CLAIM_STALE_S = 120   # a claim older than this with no completion is retryable
DEFAULT_SILENT_AFTER_S = 300


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name) or default)
    except ValueError:
        return default


def silent_after_default() -> int:
    return max(30, _env_int("SENSOR_SILENT_AFTER_S", DEFAULT_SILENT_AFTER_S))


def heartbeat_interval_s() -> int:
    return max(5, _env_int("SENSOR_HEARTBEAT_S", 60))


def monitor_interval_s() -> int:
    return max(1, _env_int("SENSOR_MONITOR_INTERVAL_S", 30))


def batch_retention_days() -> int:
    return max(1, _env_int("SENSOR_BATCH_RETENTION_DAYS", 3))


# --------------------------------------------------------------------------- #
# secrets
# --------------------------------------------------------------------------- #

def _mint(scheme: str) -> tuple[str, str, str]:
    prefix = secrets.token_hex(4)
    full = f"{scheme}_{prefix}_{secrets.token_urlsafe(32)}"
    return full, prefix, auth_svc.hash_api_key(full)


def new_enroll_token() -> tuple[str, str, str]:
    """(full, prefix, sha256). The full token is shown once."""
    return _mint(TOKEN_SCHEME)


def new_credential() -> tuple[str, str, str]:
    return _mint(CRED_SCHEME)


def split_secret(value: str | None, scheme: str) -> str | None:
    """Return the lookup prefix of a well-formed ``scheme_prefix_secret``."""
    m = _TOKEN_RE.match((value or "").strip())
    if not m or m.group(1) != scheme:
        return None
    return m.group(2)


def _hash_matches(stored: str | None, presented: str) -> bool:
    if not stored:
        return False
    return hmac.compare_digest(stored.encode(), auth_svc.hash_api_key(presented.strip()).encode())


# --------------------------------------------------------------------------- #
# rate limiting (in-process; see docs/SENTRY.md for the multi-replica note)
# --------------------------------------------------------------------------- #

# enroll attempts per client address, and *failed* redemptions (lockout).
enroll_limiter = SlidingWindowLimiter(limit=_env_int("SENSOR_ENROLL_PER_MIN", 20), window_s=60)
enroll_fail_limiter = SlidingWindowLimiter(limit=_env_int("SENSOR_ENROLL_FAILS", 5), window_s=600)
heartbeat_limiter = SlidingWindowLimiter(limit=_env_int("SENSOR_HEARTBEAT_PER_MIN", 30), window_s=60)


# --------------------------------------------------------------------------- #
# enrollment tokens
# --------------------------------------------------------------------------- #

def token_state(row: Any, now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    if row["revoked_at"] is not None:
        return "revoked"
    if row["used_at"] is not None:
        return "used"
    if row["expires_at"] <= now:
        return "expired"
    return "pending"


async def create_token(pool: Any, *, site: str, label: str | None, ttl_minutes: int,
                       actor: str) -> tuple[str, Any]:
    full, prefix, token_hash = new_enroll_token()
    expires = datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)
    async with pool.acquire() as con:
        row = await con.fetchrow(
            """INSERT INTO sensor_enroll_tokens
                   (token_prefix, token_hash, site, label, created_by, expires_at)
               VALUES ($1,$2,$3,$4,$5,$6)
               RETURNING id, token_prefix, site, label, created_by, created_at,
                         expires_at, used_at, used_by_sensor, revoked_at""",
            prefix, token_hash, site, label, actor, expires,
        )
    return full, row


async def revoke_token(pool: Any, token_id: uuid.UUID, actor: str) -> bool:
    async with pool.acquire() as con:
        row = await con.fetchrow(
            """UPDATE sensor_enroll_tokens SET revoked_at = NOW(), revoked_by = $2
                WHERE id = $1 AND revoked_at IS NULL AND used_at IS NULL RETURNING id""",
            token_id, actor,
        )
    return row is not None


class EnrollError(Exception):
    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status, self.detail = status, detail


async def redeem_token(pool: Any, token: str, *, hostname: str | None, version: str | None,
                       interfaces: list[dict[str, Any]], name: str | None) -> dict[str, Any]:
    """Exchange an enrollment token for a sensor + credential.

    Cross-tenant lookup first (the token is the only thing the caller has),
    then every write happens inside the token's own tenant. The single-use
    guarantee is the ``UPDATE ... WHERE used_at IS NULL`` in the same
    transaction as the sensor insert: of N concurrent redemptions exactly one
    gets a row back; the rest see a generic 401 (no oracle for which of
    unknown / used / expired / revoked it was).
    """
    bad = EnrollError(401, "invalid, expired or already-used enrollment token")
    prefix = split_secret(token, TOKEN_SCHEME)
    if prefix is None:
        raise bad
    with tenancy.auth_lookup():
        async with pool.acquire() as con:
            trow = await con.fetchrow(
                "SELECT id, tenant_id, token_hash, site FROM sensor_enroll_tokens WHERE token_prefix = $1",
                prefix,
            )
    if trow is None or not _hash_matches(trow["token_hash"], token):
        raise bad
    tenant_id = str(trow["tenant_id"])
    cred, cred_prefix, cred_hash = new_credential()
    sensor_name = (name or hostname or f"sensor-{cred_prefix}")[:128]
    with tenancy.tenant_context(tenant_id):
        async with pool.acquire() as con:
            async with con.transaction():
                claimed = await con.fetchrow(
                    """UPDATE sensor_enroll_tokens SET used_at = NOW()
                        WHERE id = $1 AND used_at IS NULL AND revoked_at IS NULL
                          AND expires_at > NOW()
                    RETURNING id, site, created_by""",
                    trow["id"],
                )
                if claimed is None:
                    raise bad
                sensor = await con.fetchrow(
                    """INSERT INTO sensors (name, site, cred_prefix, cred_hash, version, hostname,
                                            interfaces, token_id, enrolled_by, last_seen_at)
                       VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,NOW())
                       RETURNING id, name, site, enrolled_at""",
                    sensor_name, claimed["site"], cred_prefix, cred_hash, version, hostname,
                    json.dumps(interfaces), claimed["id"], claimed["created_by"],
                )
                await con.execute(
                    "UPDATE sensor_enroll_tokens SET used_by_sensor = $2 WHERE id = $1",
                    claimed["id"], sensor["id"],
                )
                await audit.record(
                    pool, action="sensor.enroll", actor=f"sensor:{sensor_name}",
                    actor_role="sensor", resource_type="sensor", resource_id=str(sensor["id"]),
                    details={"site": sensor["site"], "token_prefix": prefix, "version": version},
                    con=con, tenant_id=tenant_id,
                )
    return {"sensor": dict(sensor), "credential": cred, "credential_prefix": cred_prefix,
            "tenant_id": tenant_id}


# --------------------------------------------------------------------------- #
# sensor authentication (heartbeat, ingest)
# --------------------------------------------------------------------------- #

async def authenticate(pool: Any, credential: str | None) -> dict[str, Any]:
    """Resolve a sensor credential to its row (incl. ``tenant_id``).

    Raises HTTPException 401 (unknown / malformed) or 403 (revoked). Nothing
    is cached, so a revocation takes effect on the very next request.
    """
    prefix = split_secret(credential, CRED_SCHEME)
    if prefix is None:
        raise HTTPException(status_code=401, detail="invalid sensor credential")
    with tenancy.auth_lookup():
        async with pool.acquire() as con:
            row = await con.fetchrow(
                """SELECT id, tenant_id, name, site, status, cred_hash, online, silent_after_s
                     FROM sensors WHERE cred_prefix = $1""",
                prefix,
            )
    if row is None or not _hash_matches(row["cred_hash"], credential or ""):
        raise HTTPException(status_code=401, detail="invalid sensor credential")
    if row["status"] != "active":
        raise HTTPException(status_code=403, detail="sensor revoked")
    return dict(row)


# --------------------------------------------------------------------------- #
# heartbeat / uploads
# --------------------------------------------------------------------------- #

async def _emit(pool: Any, sensor: dict[str, Any], kind: str, **extra: Any) -> None:
    """Fire sensor.offline / sensor.online into the integrations fan-out."""
    from .integrations import service as isvc
    from .integrations.base import Event

    name, site = sensor["name"], sensor["site"]
    data = {"sensor_id": str(sensor["id"]), "sensor": name, "site": site, **extra}
    if kind == "offline":
        ev = Event(
            type="sensor.offline", severity="high",
            title=f"Sentry sensor {name} went silent",
            summary=f"No contact from {name} (site {site}) for {extra.get('silent_for_s', '?')}s.",
            data=data, url=isvc.dashboard_url("/sensors"), tenant_id=str(sensor["tenant_id"]),
            id=isvc.stable_event_id(f"sensor.offline:{sensor['id']}:{extra.get('since', '')}"),
        )
    else:
        ev = Event(
            type="sensor.online", severity="info",
            title=f"Sentry sensor {name} is back",
            summary=f"{name} (site {site}) is reporting again.",
            data=data, url=isvc.dashboard_url("/sensors"), tenant_id=str(sensor["tenant_id"]),
            id=isvc.stable_event_id(f"sensor.online:{sensor['id']}:{extra.get('at', '')}"),
        )
    with tenancy.tenant_context(str(sensor["tenant_id"])):
        await isvc.emit(pool, ev)


async def _mark_back_online(pool: Any, sensor: dict[str, Any]) -> None:
    """If the sensor was flagged offline, flip it (atomically) and emit."""
    if sensor.get("online", True):
        return
    with tenancy.tenant_context(str(sensor["tenant_id"])):
        async with pool.acquire() as con:
            row = await con.fetchrow(
                """UPDATE sensors SET online = TRUE, offline_since = NULL
                    WHERE id = $1 AND online = FALSE RETURNING offline_since""",
                sensor["id"],
            )
    if row is not None:
        await _emit(pool, sensor, "online", at=datetime.now(timezone.utc).isoformat())


def _clean_health(health: dict[str, Any], now: datetime) -> dict[str, Any]:
    out = {k: v for k, v in health.items() if v is not None}
    sent = out.pop("sent_at", None)
    if isinstance(sent, (int, float)) and sent > 0:
        out["clock_skew_s"] = round(float(sent) - now.timestamp(), 3)
    out["reported_at"] = now.isoformat()
    return out


async def heartbeat(pool: Any, sensor: dict[str, Any], *, version: str | None,
                    interfaces: list[dict[str, Any]] | None, health: dict[str, Any]) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    with tenancy.tenant_context(str(sensor["tenant_id"])):
        async with pool.acquire() as con:
            row = await con.fetchrow(
                """UPDATE sensors SET last_seen_at = NOW(), last_heartbeat_at = NOW(),
                          health = $2::jsonb,
                          version = COALESCE($3, version),
                          interfaces = COALESCE($4::jsonb, interfaces)
                    WHERE id = $1 AND status = 'active'
                RETURNING silent_after_s""",
                sensor["id"], json.dumps(_clean_health(health, now)), version,
                None if interfaces is None else json.dumps(interfaces),
            )
    if row is None:
        raise HTTPException(status_code=403, detail="sensor revoked")
    await _mark_back_online(pool, sensor)
    return {"ok": True, "server_time": now.timestamp(), "heartbeat_interval_s": heartbeat_interval_s(),
            "silent_after_s": row["silent_after_s"]}


async def claim_batch(pool: Any, sensor: dict[str, Any], batch_id: str) -> str:
    """Reserve ``batch_id``. Returns ``new`` | ``duplicate`` | ``in_progress``."""
    with tenancy.tenant_context(str(sensor["tenant_id"])):
        async with pool.acquire() as con:
            got = await con.fetchrow(
                """INSERT INTO sensor_batches (sensor_id, batch_id) VALUES ($1,$2)
                   ON CONFLICT (sensor_id, batch_id) DO UPDATE SET claimed_at = NOW()
                       WHERE sensor_batches.done_at IS NULL
                         AND sensor_batches.claimed_at < NOW() - make_interval(secs => $3)
                   RETURNING batch_id""",
                sensor["id"], batch_id, float(BATCH_CLAIM_STALE_S),
            )
            if got is not None:
                return "new"
            cur = await con.fetchrow(
                "SELECT done_at FROM sensor_batches WHERE sensor_id = $1 AND batch_id = $2",
                sensor["id"], batch_id,
            )
            if cur is not None and cur["done_at"] is not None:
                await con.execute(
                    "UPDATE sensors SET duplicates_total = duplicates_total + 1, last_seen_at = NOW() "
                    "WHERE id = $1", sensor["id"])
                return "duplicate"
            return "in_progress"


async def complete_batch(pool: Any, sensor: dict[str, Any], batch_id: str, *, ok: bool,
                         flows: int) -> None:
    with tenancy.tenant_context(str(sensor["tenant_id"])):
        async with pool.acquire() as con:
            async with con.transaction():
                if ok:
                    done = await con.fetchrow(
                        """UPDATE sensor_batches SET done_at = NOW(), flows = $3
                            WHERE sensor_id = $1 AND batch_id = $2 AND done_at IS NULL
                        RETURNING batch_id""",
                        sensor["id"], batch_id, max(0, int(flows)),
                    )
                    if done is not None:
                        await con.execute(
                            """UPDATE sensors SET last_upload_at = NOW(), last_seen_at = NOW(),
                                      batches_total = batches_total + 1,
                                      flows_total = flows_total + $2
                                WHERE id = $1""",
                            sensor["id"], max(0, int(flows)),
                        )
                else:  # processing failed: release the claim so the retry is accepted
                    await con.execute(
                        "DELETE FROM sensor_batches WHERE sensor_id = $1 AND batch_id = $2 AND done_at IS NULL",
                        sensor["id"], batch_id,
                    )
    if ok:
        await _mark_back_online(pool, sensor)


# --------------------------------------------------------------------------- #
# revocation
# --------------------------------------------------------------------------- #

async def revoke_sensor(pool: Any, sensor_id: uuid.UUID, actor: str) -> dict[str, Any] | None:
    async with pool.acquire() as con:
        row = await con.fetchrow(
            """UPDATE sensors SET status = 'revoked', revoked_at = NOW(), revoked_by = $2
                WHERE id = $1 AND status = 'active' RETURNING id, name, site""",
            sensor_id, actor,
        )
    return dict(row) if row else None


# --------------------------------------------------------------------------- #
# view helpers
# --------------------------------------------------------------------------- #

def warnings_for(row: Any) -> list[str]:
    """Human-readable health problems derived from the latest heartbeat."""
    health = row["health"]
    if isinstance(health, str):
        health = json.loads(health or "{}")
    health = health or {}
    out: list[str] = []
    if (health.get("packets_dropped") or 0) > 0:
        out.append(f"{int(health['packets_dropped'])} packets dropped by the kernel")
    fill = health.get("buffer_fill_pct")
    if isinstance(fill, (int, float)) and fill >= 80:
        out.append(f"upload buffer {fill:.0f}% full (server unreachable?)")
    if (health.get("batches_dropped") or 0) > 0:
        out.append("buffer overflowed: oldest batches were dropped")
    skew = health.get("clock_skew_s")
    if isinstance(skew, (int, float)) and abs(skew) > 30:
        out.append(f"clock is {skew:+.0f}s off the server (fix NTP)")
    return out


def sensor_state(row: Any) -> str:
    if row["status"] == "revoked":
        return "revoked"
    if not row["online"]:
        return "offline"
    return "degraded" if warnings_for(row) else "online"


# --------------------------------------------------------------------------- #
# liveness monitor
# --------------------------------------------------------------------------- #

async def sweep_silent(pool: Any) -> dict[str, int]:
    """Flag sensors that stopped reporting; purge old batch ids. One tenant
    at a time (RLS): call inside ``tenancy.tenant_context``."""
    went_offline = 0
    async with pool.acquire() as con:
        rows = await con.fetch(
            """UPDATE sensors SET online = FALSE, offline_since = NOW()
                WHERE status = 'active' AND online = TRUE
                  AND COALESCE(last_seen_at, enrolled_at) < NOW() - make_interval(secs => silent_after_s)
            RETURNING id, tenant_id, name, site, last_seen_at, enrolled_at, silent_after_s""",
        )
        await con.execute(
            "DELETE FROM sensor_batches WHERE claimed_at < NOW() - make_interval(days => $1)",
            batch_retention_days(),
        )
    for r in rows:
        went_offline += 1
        seen = r["last_seen_at"] or r["enrolled_at"]
        silent_for = int((datetime.now(timezone.utc) - seen).total_seconds())
        await _emit(pool, dict(r), "offline", since=seen.isoformat(), silent_for_s=silent_for,
                    silent_after_s=r["silent_after_s"], last_seen=seen.isoformat())
    return {"offline": went_offline}


async def sweep_all_tenants(pool: Any) -> int:
    n = 0
    for tid in await tenancy.list_tenant_ids(pool):
        with tenancy.tenant_context(tid):
            n += (await sweep_silent(pool))["offline"]
    return n


async def monitor_loop(app: Any) -> None:
    """Background task (started from the lifespan): never dies on an error."""
    interval = monitor_interval_s()
    logger.info("sensor_monitor_started", extra={"interval_sec": interval})
    while True:
        try:
            await asyncio.sleep(interval)
            pool = getattr(app.state, "pool", None)
            if pool is not None:
                await sweep_all_tenants(pool)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            logger.exception("sensor_monitor_failed")
