"""Prometheus metrics for the orchestrator (``GET /metrics``).

What is exported
----------------
* ``paddock_http_requests_total{method,route,status}`` and
  ``paddock_http_request_duration_seconds{method,route}``: labelled by the
  route TEMPLATE (``/v1/assets/{asset_id}``), never the raw path, so label
  cardinality is bounded. Unmatched paths are labelled ``route="<unmatched>"``.
* ``paddock_scope_decisions_total{decision}``: every allow/deny the scope
  service records.
* ``paddock_audit_append_failures_total``: hash-chain appends that raised.
* ``paddock_retention_purged_rows_total{table}`` and
  ``paddock_retention_last_run_timestamp_seconds``.
* Scrape-time gauges (cached ``METRICS_DB_CACHE_SEC``): Redis queue depths
  and consumer-group pending/lag, scans by status + oldest queued age, DB pool
  size/idle/max, integration deliveries by status (when that table exists),
  latest asset ``last_seen`` per source (Sentry/otdiscovery freshness), and
  the count of pending schema migrations.

Access control (documented in docs/OPERATIONS.md)
-------------------------------------------------
``/metrics`` is answered by an outermost ASGI middleware, before the user
auth/RBAC/audit middleware (a scraper is not a user and must not fill the
audit log). It is protected by a bearer token instead:

* ``METRICS_TOKEN`` set   -> ``Authorization: Bearer <token>`` required (401).
* unset, AUTH_MODE=dev    -> open (local development).
* unset, AUTH_MODE=enforce -> 404: fail closed until an operator opts in.

Instrumentation hooks (``observe_scope_decision``, ``audit_append_failed``)
never raise, so metrics can never break a request.
"""
from __future__ import annotations

import hmac
import logging
import time
from typing import Any

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

logger = logging.getLogger(__name__)

REGISTRY = CollectorRegistry(auto_describe=True)

HTTP_REQUESTS = Counter(
    "paddock_http_requests_total",
    "HTTP requests handled, by route template and status code.",
    ["method", "route", "status"],
    registry=REGISTRY,
)
HTTP_LATENCY = Histogram(
    "paddock_http_request_duration_seconds",
    "HTTP request latency by route template (includes auth + audit).",
    ["method", "route"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30),
    registry=REGISTRY,
)
SCOPE_DECISIONS = Counter(
    "paddock_scope_decisions_total",
    "Scope decisions recorded by the scope service.",
    ["decision"],
    registry=REGISTRY,
)
AUDIT_FAILURES = Counter(
    "paddock_audit_append_failures_total",
    "Audit hash-chain appends that raised (request still served).",
    registry=REGISTRY,
)
RETENTION_PURGED = Counter(
    "paddock_retention_purged_rows_total",
    "Rows deleted by the retention job.",
    ["table"],
    registry=REGISTRY,
)
RETENTION_LAST_RUN = Gauge(
    "paddock_retention_last_run_timestamp_seconds",
    "Unix time the retention job last completed.",
    registry=REGISTRY,
)

# Scrape-time gauges (set by _refresh()).
QUEUE_DEPTH = Gauge(
    "paddock_queue_depth", "Entries in a Redis job stream (XLEN).", ["queue"], registry=REGISTRY
)
QUEUE_PENDING = Gauge(
    "paddock_queue_pending",
    "Delivered-but-unacknowledged entries summed over consumer groups.",
    ["queue"],
    registry=REGISTRY,
)
QUEUE_LAG = Gauge(
    "paddock_queue_lag",
    "Entries not yet delivered to the consumer group (Redis >= 7).",
    ["queue"],
    registry=REGISTRY,
)
SCANS = Gauge("paddock_scans", "Scans by status.", ["status"], registry=REGISTRY)
SCAN_OLDEST_QUEUED = Gauge(
    "paddock_scan_oldest_queued_age_seconds",
    "Age of the oldest scan still in status=queued (0 when none).",
    registry=REGISTRY,
)
DB_POOL = Gauge(
    "paddock_db_pool_connections", "asyncpg pool connections.", ["state"], registry=REGISTRY
)
INTEGRATION_DELIVERIES = Gauge(
    "paddock_integration_deliveries",
    "Integration deliveries by status (table integration_deliveries).",
    ["status"],
    registry=REGISTRY,
)
SOURCE_LAST_SEEN = Gauge(
    "paddock_asset_source_last_seen_timestamp_seconds",
    "Newest asset last_seen per discovery source (ingest freshness).",
    ["source"],
    registry=REGISTRY,
)
MIGRATIONS_PENDING = Gauge(
    "paddock_schema_migrations_pending",
    "Schema files on disk not yet recorded in schema_migrations.",
    registry=REGISTRY,
)
SCRAPE_ERRORS = Counter(
    "paddock_metrics_collect_errors_total",
    "Errors while collecting a scrape-time gauge group.",
    ["group"],
    registry=REGISTRY,
)

_last_refresh = 0.0
_migration_files: int | None = None
UNMATCHED = "<unmatched>"


# --------------------------------------------------------------------------- #
# Hooks used by other modules (never raise)
# --------------------------------------------------------------------------- #

def observe_scope_decision(allow: bool) -> None:
    try:
        SCOPE_DECISIONS.labels("allow" if allow else "deny").inc()
    except Exception:  # noqa: BLE001
        pass


def audit_append_failed() -> None:
    try:
        AUDIT_FAILURES.inc()
    except Exception:  # noqa: BLE001
        pass


# --------------------------------------------------------------------------- #
# Scrape-time collection
# --------------------------------------------------------------------------- #

async def _refresh_queues(app: Any) -> None:
    from .config import settings

    r = getattr(app.state, "redis", None)
    if r is None:
        return
    for q in (settings.queue_passive, settings.queue_active, settings.queue_correlate):
        name = q.split(":", 1)[-1]
        try:
            QUEUE_DEPTH.labels(name).set(int(await r.xlen(q)))
        except Exception:  # noqa: BLE001 -- key missing / wrong type
            QUEUE_DEPTH.labels(name).set(0)
        pending = 0
        lag = 0
        try:
            for g in await r.xinfo_groups(q):
                pending += int(g.get("pending") or 0)
                lag += int(g.get("lag") or 0)
        except Exception:  # noqa: BLE001 -- no stream / no groups yet
            pass
        QUEUE_PENDING.labels(name).set(pending)
        QUEUE_LAG.labels(name).set(lag)


async def _refresh_db(app: Any) -> None:
    pool = getattr(app.state, "pool", None)
    if pool is None:
        return
    try:
        DB_POOL.labels("size").set(pool.get_size())
        DB_POOL.labels("idle").set(pool.get_idle_size())
        DB_POOL.labels("in_use").set(pool.get_size() - pool.get_idle_size())
        DB_POOL.labels("max").set(pool.get_max_size())
    except Exception:  # noqa: BLE001
        SCRAPE_ERRORS.labels("db_pool").inc()

    async with pool.acquire() as con:
        try:
            rows = await con.fetch("SELECT status, count(*) AS n FROM scans GROUP BY status")
            seen = {r["status"]: int(r["n"]) for r in rows}
            for s in ("queued", "running", "completed", "failed", "cancelled"):
                SCANS.labels(s).set(seen.get(s, 0))
            age = await con.fetchval(
                "SELECT EXTRACT(EPOCH FROM (NOW() - min(queued_at))) FROM scans "
                "WHERE status = 'queued'"
            )
            SCAN_OLDEST_QUEUED.set(float(age or 0))
        except Exception:  # noqa: BLE001
            SCRAPE_ERRORS.labels("scans").inc()

        try:
            if await con.fetchval("SELECT to_regclass('integration_deliveries') IS NOT NULL"):
                rows = await con.fetch(
                    "SELECT status, count(*) AS n FROM integration_deliveries GROUP BY status"
                )
                seen = {r["status"]: int(r["n"]) for r in rows}
                for s in ("pending", "sent", "failed", "dead", "skipped", *seen):
                    INTEGRATION_DELIVERIES.labels(s).set(seen.get(s, 0))
        except Exception:  # noqa: BLE001
            SCRAPE_ERRORS.labels("integration_deliveries").inc()

        try:
            # Bounded: one row per source (low cardinality by construction).
            rows = await con.fetch(
                "SELECT source, EXTRACT(EPOCH FROM max(last_seen)) AS ts "
                "FROM assets GROUP BY source ORDER BY source LIMIT 50"
            )
            for r in rows:
                SOURCE_LAST_SEEN.labels(str(r["source"])[:64]).set(float(r["ts"] or 0))
        except Exception:  # noqa: BLE001
            SCRAPE_ERRORS.labels("asset_sources").inc()

        try:
            global _migration_files
            if _migration_files is None:
                from .migrate import MigrationError, discover

                try:
                    _migration_files = len(discover())
                except MigrationError:
                    _migration_files = -1  # no schema dir in this pod (Helm: the Job has it)
            if _migration_files >= 0 and await con.fetchval(
                "SELECT to_regclass('schema_migrations') IS NOT NULL"
            ):
                done = await con.fetchval("SELECT count(*) FROM schema_migrations")
                MIGRATIONS_PENDING.set(max(0, _migration_files - int(done)))
        except Exception:  # noqa: BLE001 -- schema dir absent in some images
            SCRAPE_ERRORS.labels("migrations").inc()


async def refresh(app: Any, force: bool = False) -> None:
    from .opsconfig import ops_settings

    global _last_refresh
    now = time.monotonic()
    if not force and now - _last_refresh < ops_settings.metrics_db_cache_sec:
        return
    _last_refresh = now
    for group, fn in (("queues", _refresh_queues), ("db", _refresh_db)):
        try:
            await fn(app)
        except Exception:  # noqa: BLE001
            SCRAPE_ERRORS.labels(group).inc()
            logger.warning("metrics_refresh_failed", extra={"group": group})


# --------------------------------------------------------------------------- #
# ASGI middleware: request instrumentation + the /metrics endpoint
# --------------------------------------------------------------------------- #

def _authorised(headers: list[tuple[bytes, bytes]]) -> int:
    """200 ok, 401 bad/missing token, 404 disabled."""
    from .config import settings
    from .opsconfig import ops_settings

    token = ops_settings.metrics_token
    if not token:
        return 200 if settings.auth_mode == "dev" else 404
    for k, v in headers:
        if k.lower() == b"authorization":
            val = v.decode("latin-1")
            if val[:7].lower() == "bearer " and hmac.compare_digest(
                val[7:].strip().encode(), token.encode()
            ):
                return 200
    return 401


class MetricsMiddleware:
    """Outermost middleware. Serves /metrics; times every other request."""

    def __init__(self, app: Any, path: str = "/metrics") -> None:
        self.app = app
        self.path = path

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        if scope["path"] == self.path:
            await self._serve(scope, send)
            return

        status_holder = {"code": 500}

        async def _send(message: dict) -> None:
            if message["type"] == "http.response.start":
                status_holder["code"] = int(message["status"])
            await send(message)

        t0 = time.perf_counter()
        try:
            await self.app(scope, receive, _send)
        finally:
            route = scope.get("route")
            template = getattr(route, "path", None) or UNMATCHED
            method = scope.get("method", "GET")
            try:
                HTTP_LATENCY.labels(method, template).observe(time.perf_counter() - t0)
                HTTP_REQUESTS.labels(method, template, str(status_holder["code"])).inc()
            except Exception:  # noqa: BLE001
                pass

    async def _serve(self, scope: dict, send: Any) -> None:
        code = _authorised(scope.get("headers") or [])
        if code != 200:
            body = b'{"detail":"not found"}' if code == 404 else b'{"detail":"metrics token required"}'
            headers = [(b"content-type", b"application/json")]
            if code == 401:
                headers.append((b"www-authenticate", b'Bearer realm="metrics"'))
            await send({"type": "http.response.start", "status": code, "headers": headers})
            await send({"type": "http.response.body", "body": body})
            return
        app = scope.get("app")
        if app is not None:
            await refresh(app)
        payload = generate_latest(REGISTRY)
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", CONTENT_TYPE_LATEST.encode())],
        })
        await send({"type": "http.response.body", "body": payload})


def install(app: Any) -> None:
    """Add the metrics middleware (call LAST in create_app -> outermost)."""
    app.add_middleware(MetricsMiddleware)
