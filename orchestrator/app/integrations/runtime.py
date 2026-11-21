"""Run integrations from the orchestrator: build a connector from its DB row,
pull SOURCE integrations on their interval, and execute approved ACTIONs.

* ``connector_for(row, http)`` -- decrypts secrets, injects the row's
  ``allow_private`` into the connector config (the column wins over anything
  in ``config``), and instantiates the registered class.
* ``run_source_sync`` -- one pull + ingest, bookkept in
  ``integration_sync_runs`` (schema 025) with a multi-replica-safe claim, and
  ``integrations.last_ok_at`` / ``last_error`` updated. Error text is built
  from our own messages and scrubbed of every secret value.
* ``run_due_source_syncs`` / ``kick_source_syncs`` -- the scheduler hook. The
  scheduler loop calls ``kick_source_syncs`` every tick; it starts ONE
  background sweep if none is running, so a slow cloud never delays scans.

Interval: ``config.sync_interval_minutes`` (default 360, floor 15).
``PADDOCK_SOURCE_SYNC=0`` disables the scheduled pulls (manual still works).
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Mapping, Optional
from uuid import UUID

from .base import Capability, Connector, get_connector_class
from .secrets import decrypt_secrets

log = logging.getLogger(__name__)

DEFAULT_INTERVAL_MIN = 360
MIN_INTERVAL_MIN = 15
DEFAULT_TIMEOUT_SEC = 900
STALE_RUNNING = timedelta(hours=2)
USER_AGENT = "Paddock-Integrations/0.1 (+defensive ASM; read-only)"

HttpFactory = Callable[[Mapping[str, Any]], Any]


def _json(v: Any) -> dict[str, Any]:
    if isinstance(v, str):
        try:
            v = json.loads(v)
        except ValueError:
            return {}
    return dict(v) if isinstance(v, Mapping) else {}


def sync_enabled() -> bool:
    return os.environ.get("PADDOCK_SOURCE_SYNC", "1").strip().lower() not in {"0", "false", "no", "off"}


def default_http(config: Mapping[str, Any]):
    """A fresh client per run: no redirects, bounded timeouts, TLS verified.

    ``verify_tls: false`` is honoured ONLY for an integration that also has the
    deliberate ``allow_private`` opt-in (a LAN controller with a self-signed
    certificate); public endpoints are always verified.
    """
    import httpx

    from .pinned import pinned_client

    verify = not (config.get("allow_private") and config.get("verify_tls") is False)
    return pinned_client(allow_private=bool(config.get("allow_private")), verify=verify,
                         timeout=httpx.Timeout(30.0, connect=10.0),
                         headers={"User-Agent": USER_AGENT})


def connector_class(kind: str) -> type[Connector]:
    from .connectors import load_all

    load_all()
    return get_connector_class(kind)


def connector_for(row: Mapping[str, Any], http: Any) -> Connector:
    cls = connector_class(row["kind"])
    config = _json(row.get("config"))
    config["allow_private"] = bool(row.get("allow_private"))
    return cls(config, decrypt_secrets(row.get("secrets")), http)


def scrub(text: str, secrets: Mapping[str, str]) -> str:
    out = text or ""
    for v in secrets.values():
        if isinstance(v, str) and len(v) >= 4:
            out = out.replace(v, "********")
    return out[:500]


def interval_minutes(config: Mapping[str, Any]) -> int:
    try:
        v = int(config.get("sync_interval_minutes", DEFAULT_INTERVAL_MIN))
    except (TypeError, ValueError):
        v = DEFAULT_INTERVAL_MIN
    return max(MIN_INTERVAL_MIN, v)


def _error_text(exc: BaseException) -> str:
    from .connectors._common import SourceError

    if isinstance(exc, SourceError):
        return str(exc)
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        return "sync timed out"
    if isinstance(exc, KeyError) and "unknown integration kind" in str(exc):
        return str(exc).strip("'\"")
    # Unknown failure: type only. Its message could carry anything.
    return f"internal error ({type(exc).__name__})"


async def _fetch_row(pool, integration_id: UUID | str) -> Optional[dict[str, Any]]:
    async with pool.acquire() as con:
        row = await con.fetchrow(
            "SELECT id, kind, name, enabled, config, secrets, allow_private "
            "FROM integrations WHERE id = $1",
            integration_id if isinstance(integration_id, UUID) else UUID(str(integration_id)),
        )
    return dict(row) if row else None


async def run_source_sync(pool, redis, integration_id: UUID | str, *, trigger: str = "schedule",
                          actor: str = "system:scheduler",
                          http_factory: HttpFactory | None = None) -> dict[str, Any]:
    """Pull one SOURCE integration and ingest it. Never raises for remote errors."""
    from .. import audit
    from .ingest import apply_source_batch

    row = await _fetch_row(pool, integration_id)
    if row is None:
        return {"status": "error", "detail": "integration not found"}
    try:
        cls = connector_class(row["kind"])
    except KeyError:
        return {"status": "error", "detail": f"unknown integration kind {row['kind']!r}"}
    if Capability.SOURCE not in cls.capabilities:
        return {"status": "error", "detail": f"{row['kind']} is not a SOURCE integration"}

    async with pool.acquire() as con:
        await con.execute(
            "UPDATE integration_sync_runs SET status = 'abandoned', finished_at = NOW(), "
            "detail = 'worker did not finish' WHERE integration_id = $1 AND status = 'running' "
            "AND started_at < $2",
            row["id"], datetime.now(timezone.utc) - STALE_RUNNING,
        )
        run_id = await con.fetchval(
            "INSERT INTO integration_sync_runs (integration_id, trigger) VALUES ($1, $2) "
            "ON CONFLICT DO NOTHING RETURNING id",
            row["id"], trigger,
        )
    if run_id is None:
        return {"status": "skipped", "detail": "a sync for this integration is already running"}

    config = _json(row.get("config"))
    config["allow_private"] = bool(row.get("allow_private"))
    secrets: dict[str, str] = {}
    counts: dict[str, Any] = {}
    status, detail = "ok", ""
    try:
        secrets = decrypt_secrets(row.get("secrets"))
        timeout = float(config.get("sync_timeout_sec") or DEFAULT_TIMEOUT_SEC)
        async with (http_factory or default_http)(config) as http:
            conn = cls(config, secrets, http)
            batch = await asyncio.wait_for(conn.pull(), timeout=timeout)
            counts = await apply_source_batch(pool, redis, batch, source=f"integration:{row['kind']}")
            warnings = list(getattr(conn, "last_warnings", []) or [])
        if warnings:
            counts["warnings"] = len(warnings)
            detail = "partial: " + "; ".join(warnings[:8])
    except Exception as exc:  # noqa: BLE001 - one bad integration never kills the sweep
        status = "error"
        detail = _error_text(exc)
        log.warning("source_sync_failed", extra={"integration_id": str(row["id"]),
                                                 "kind": row["kind"], "error": scrub(detail, secrets)})
    detail = scrub(detail, secrets)

    async with pool.acquire() as con:
        await con.execute(
            "UPDATE integration_sync_runs SET status = $2, finished_at = NOW(), "
            "counts = $3::jsonb, detail = $4 WHERE id = $1",
            run_id, status, json.dumps(counts), detail or None,
        )
        if status == "ok":
            await con.execute("UPDATE integrations SET last_ok_at = NOW() WHERE id = $1", row["id"])
        else:
            await con.execute(
                "UPDATE integrations SET last_error = $2, last_error_at = NOW() WHERE id = $1",
                row["id"], detail,
            )
    try:
        await audit.record(pool, action="integration_sync", actor=actor, actor_role="system"
                           if actor.startswith("system:") else None,
                           resource_type="integration", resource_id=str(row["id"]),
                           details={"kind": row["kind"], "trigger": trigger, "status": status,
                                    "counts": counts})
    except Exception:  # noqa: BLE001
        log.exception("integration_sync_audit_failed")
    return {"status": status, "detail": detail, "counts": counts, "run_id": run_id}


async def due_source_integrations(pool, now: datetime | None = None) -> list[UUID]:
    now = now or datetime.now(timezone.utc)
    async with pool.acquire() as con:
        rows = await con.fetch(
            """
            SELECT i.id, i.kind, i.config,
                   (SELECT MAX(r.started_at) FROM integration_sync_runs r
                     WHERE r.integration_id = i.id) AS last_started
              FROM integrations i
             WHERE i.enabled = TRUE
             ORDER BY i.created_at
            """
        )
    due: list[UUID] = []
    for r in rows:
        try:
            cls = connector_class(r["kind"])
        except KeyError:
            continue
        if Capability.SOURCE not in cls.capabilities:
            continue
        last = r["last_started"]
        if last is None or last + timedelta(minutes=interval_minutes(_json(r["config"]))) <= now:
            due.append(r["id"])
    return due


async def run_due_source_syncs(pool, redis, now: datetime | None = None,
                               http_factory: HttpFactory | None = None) -> int:
    ran = 0
    for iid in await due_source_integrations(pool, now):
        try:
            await run_source_sync(pool, redis, iid, http_factory=http_factory)
            ran += 1
        except Exception:  # noqa: BLE001
            log.exception("source_sync_crashed", extra={"integration_id": str(iid)})
    return ran


_sweep: asyncio.Task | None = None


def kick_source_syncs(pool, redis, runner: Callable[..., Awaitable[int]] | None = None) -> bool:
    """Start one background sweep unless disabled or one is still running."""
    global _sweep
    if not sync_enabled() or pool is None:
        return False
    if _sweep is not None and not _sweep.done():
        return False

    async def _go() -> None:
        try:
            await (runner or run_due_source_syncs)(pool, redis)
        except Exception:  # noqa: BLE001
            log.exception("source_sync_sweep_failed")

    _sweep = asyncio.create_task(_go())
    return True
