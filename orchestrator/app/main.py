"""FastAPI app entrypoint.

Wires lifespan (asyncpg pool + redis client), middleware, routers, and
the health endpoints. The SSE endpoint `/v1/events` tails the Redis
events stream. No endpoint here performs an outbound probe; that is
workers' job.
"""
from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

from . import audit as audit_svc
from . import auth as auth_svc
from . import metrics as metrics_svc
from .auth import GovernanceMiddleware
from .config import settings
from .audit_anchor import sink_from_settings
from .db import create_pool, warn_if_privileged
from .middleware import RequestContextMiddleware, configure_logging
from .migrate import run_startup_migrations
from .opsconfig import ops_settings
from .queue import create_redis, read_events
from .routers import ask as ask_router
from .routers import assets as assets_router
from .routers import audit as audit_router
from .routers import auth as auth_router
from .routers import attack as attack_router
from .routers import attackpaths as attackpaths_router
from .routers import changes as changes_router
from .routers import code as code_router
from .routers import findings as findings_router
from .routers import integrations_inbound as integrations_inbound_router
from .routers import licensing as licensing_router
from .routers import lifecycle as lifecycle_router
from .routers import ml as ml_router
from .routers import monitoring as monitoring_router
from .routers import onboarding as onboarding_router
from .routers import devices as devices_router
from .routers import exports as exports_router
from .routers import fleet as fleet_router
from .routers import integrations as integrations_router
from .routers import integration_sync as integration_sync_router
from .routers import network_actions as network_actions_router
from .routers import ontology as ontology_router
from .routers import remediation as remediation_router
from .routers import posture as posture_router
from .routers import threatintel as threatintel_router
from .routers import provenance as provenance_router
from .routers import sbom as sbom_router
from .routers import scans as scans_router
from .routers import scope as scope_router
from .routers import scim as scim_router
from .routers import sso as sso_router
from .routers import tickets as tickets_router
from .routers import timeline as timeline_router
from .verification import router as verification_router
from .reports import router as reports_router
from .routers import ingest as ingest_router
from .scheduler import scheduler_loop
from .billing import gate as billing_gate
from .billing import router as billing_router
from .billing import status as billing_status
from . import ai_settings as ai_settings_router
from . import system as system_router
from .growth import exposure as growth_exposure
from .growth import suppliers as growth_suppliers
from .growth import trust as growth_trust
from .growth.config import growth_settings
from .growth.runner import growth_loop
from . import sensors as sensors_svc
from . import tenancy
from .routers import sensors as sensors_router

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    configure_logging()
    logger.info("orchestrator_startup", extra={"version": "0.1.0", "auth_mode": settings.auth_mode})
    # Versioned schema migrations (app/migrate.py). Advisory-locked, so N
    # replicas starting at once is safe; a failure (e.g. checksum drift)
    # aborts startup rather than serving against an unknown schema.
    if ops_settings.migrate_on_startup:
        await run_startup_migrations()
    app.state.pool = await create_pool()
    app.state.redis = await create_redis()

    # Enterprise trust: shout if RLS is bypassed (superuser), note an unkeyed
    # audit chain, and start anchoring the chain head if a sink is configured.
    try:
        await warn_if_privileged(app.state.pool)
    except Exception:  # noqa: BLE001
        logger.exception("db_role_check_failed")
    if audit_svc.keyring()[0] is None:
        logger.warning(
            "AUDIT_HMAC_KEY unset: the audit chain is unkeyed sha256 (tamper-evident "
            "only against non-owners). Set AUDIT_HMAC_KEY for a keyed chain."
        )
    app.state.audit_anchor_sink = sink_from_settings()
    anchor_task: asyncio.Task | None = None
    if app.state.audit_anchor_sink is not None:
        anchor_task = asyncio.create_task(audit_svc.anchor_loop(app))
    else:
        logger.warning("AUDIT_ANCHOR_SINKS unset: audit chain head is not anchored externally")

    # Governance bootstrap: set the admin password on first boot, and try to
    # revoke UPDATE/DELETE on the audit log at the DB layer (best-effort).
    try:
        await auth_svc.bootstrap_admin(app.state.pool)
    except Exception:  # noqa: BLE001 -- never block startup on bootstrap
        logger.exception("admin_bootstrap_failed")
    try:
        await auth_svc.harden_audit_table(app.state.pool)
    except Exception:  # noqa: BLE001
        logger.exception("audit_harden_failed")
    if settings.auth_mode == "dev":
        logger.warning(
            "AUTH_MODE=dev -- unauthenticated requests resolve to a synthetic "
            "admin. Set AUTH_MODE=enforce for production."
        )

    # Continuous-monitoring scheduler: a single background task that enqueues
    # due scans. It never probes anything itself (see app/scheduler.py).
    scheduler_task: asyncio.Task | None = None
    if settings.scheduler_enabled:
        scheduler_task = asyncio.create_task(scheduler_loop(app))
        app.state.scheduler_task = scheduler_task

    # Growth runner (schema 032): public exposure jobs + supplier assessments.
    # Passive only: DNS + CT, never a packet to the assessed domain.
    growth_task: asyncio.Task | None = None
    if growth_settings.runner_enabled:
        growth_task = asyncio.create_task(growth_loop(app))
        app.state.growth_task = growth_task
    # Sentry liveness: flags silent sensors and emits sensor.offline/online.
    sensor_task: asyncio.Task | None = asyncio.create_task(sensors_svc.monitor_loop(app))

    try:
        yield
    finally:
        for task in (scheduler_task, anchor_task, growth_task, sensor_task):
            if task is None:
                continue
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        try:
            await app.state.redis.aclose()
        except Exception:
            pass
        try:
            await app.state.pool.close()
        except Exception:
            pass
        logger.info("orchestrator_shutdown")


def create_app() -> FastAPI:
    app = FastAPI(
        title="paddock orchestrator",
        description=(
            "Defensive ASM orchestrator: scope service, job dispatch, and the "
            "asset/finding/timeline API. Workers in this platform perform "
            "discovery and polite probing only -- no exploit launchers, no "
            "credential testers, no stealth modes."
        ),
        version="0.1.0",
        lifespan=lifespan,
    )

    # Middleware stack (added inner-first; the last added runs outermost).
    #   GovernanceMiddleware  -- authenticate + RBAC + audit (innermost).
    #   RequestContextMiddleware -- sets request_id BEFORE governance runs.
    #   CORSMiddleware        -- outermost.
    app.add_middleware(GovernanceMiddleware)
    app.add_middleware(RequestContextMiddleware)
    # Dev CORS: dashboard served on :3000, orchestrator on :8080. Lock this
    # down to a specific origin list (or a reverse-proxied same-origin deploy)
    # before external exposure.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[o.strip() for o in settings.cors_origins.split(",") if o.strip() and o.strip() != "*"],
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Justification", "X-Request-ID"],
    )
    # Prometheus: outermost, so it times auth + audit too and serves /metrics
    # (METRICS_TOKEN-protected) without touching the user-auth middleware.
    metrics_svc.install(app)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz(request: Request) -> JSONResponse:
        checks: dict[str, str] = {}
        ok = True
        try:
            async with request.app.state.pool.acquire() as con:
                await con.execute("SELECT 1")
            checks["db"] = "ok"
        except Exception as exc:  # noqa: BLE001
            checks["db"] = f"fail: {exc!s}"
            ok = False
        try:
            await request.app.state.redis.ping()
            checks["redis"] = "ok"
        except Exception as exc:  # noqa: BLE001
            checks["redis"] = f"fail: {exc!s}"
            ok = False
        return JSONResponse(
            {"status": "ok" if ok else "degraded", "checks": checks},
            status_code=200 if ok else 503,
        )

    @app.get("/v1/events")
    async def events_sse(
        request: Request,
        since: str = Query("$", description="Redis stream id. '$' = new only."),
    ):
        """Server-Sent Events: tail stream:events.

        One `data: <json>\\n\\n` chunk per event. Comments (`:keepalive`)
        are sent every ~15s so intermediaries don't drop idle streams.
        """
        r = request.app.state.redis
        # The stream is shared by every tenant; a caller only ever sees events
        # stamped with its own tenant (queue.publish_event stamps them).
        caller_tenant = tenancy.current_tenant_id()

        async def gen() -> AsyncIterator[bytes]:
            async for sid, payload in read_events(r, since=since, block_ms=15000):
                if await request.is_disconnected():
                    return
                if payload.get("event") == "keepalive":
                    yield b": keepalive\n\n"
                    continue
                if not tenancy.event_visible_to(payload, caller_tenant):
                    continue
                body = json.dumps({"id": sid, **payload}, default=str)
                yield f"id: {sid}\ndata: {body}\n\n".encode("utf-8")

        return StreamingResponse(
            gen(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
                "Connection": "keep-alive",
            },
        )

    # Governance (schema 011): auth, audit, provenance.
    app.include_router(auth_router.router)
    app.include_router(audit_router.router)
    app.include_router(provenance_router.router)
    # Enterprise identity (schema 020): OIDC/SAML SSO + SCIM 2.0 provisioning.
    app.include_router(sso_router.router)
    app.include_router(scim_router.router)

    app.include_router(scope_router.router)
    app.include_router(scans_router.router)
    app.include_router(assets_router.router)
    app.include_router(assets_router.edges_router)
    app.include_router(findings_router.router)
    app.include_router(findings_router.outbound_router)
    app.include_router(timeline_router.router)
    app.include_router(attackpaths_router.router)
    app.include_router(changes_router.router)
    app.include_router(changes_router.alerts_router)
    app.include_router(monitoring_router.router)
    app.include_router(posture_router.router)
    app.include_router(tickets_router.router)
    app.include_router(tickets_router.owners_router)
    app.include_router(tickets_router.sla_router)
    # Tier 3: SCA/SBOM, ATT&CK mapping, Ask + clusters + graph proxy.
    app.include_router(sbom_router.router)
    app.include_router(sbom_router.risks_router)
    app.include_router(attack_router.router)
    app.include_router(attack_router.finding_tech_router)
    app.include_router(ask_router.router)
    # Tier 4: code findings (SAST) + reachability rollup, adaptive ML risk /
    # models / anomalies, and the retrain proxy.
    app.include_router(code_router.router)
    app.include_router(ml_router.router)
    app.include_router(ml_router.anomalies_router)
    # Semantic layer + threat-intel fusion
    app.include_router(ontology_router.router)
    app.include_router(threatintel_router.router)
    # Fleet agents + gated enforcement, auto-remediation, IoT/OT devices
    app.include_router(devices_router.router)
    app.include_router(fleet_router.router)
    app.include_router(sensors_router.router)
    app.include_router(remediation_router.router)
    # Two-way ticketing: inbound callbacks from Jira / ServiceNow / Linear.
    app.include_router(integrations_inbound_router.router)
    # Integrations: connector catalogue, CRUD, test, delivery log
    app.include_router(integrations_router.router)
    # Standards exports/imports: OCSF, SARIF, CycloneDX/SPDX, VEX
    app.include_router(exports_router.export_router)
    app.include_router(exports_router.import_router)
    # Context SOURCE sync status + network quarantine via the fleet gate (schema 025)
    app.include_router(integration_sync_router.router)
    app.include_router(network_actions_router.router)
    # Editions/licensing + usage metering (schema 024)
    app.include_router(licensing_router.router)
    # Finding lifecycle (schema 019): accept / false-positive / reopen + suppressions
    app.include_router(lifecycle_router.router)
    app.include_router(lifecycle_router.suppressions_router)
    # First-run wizard state + optional-service status (schema 021).
    app.include_router(onboarding_router.router)
    app.include_router(onboarding_router.system_router)
    # Reporting: executive report, weekly digest, compliance evidence packs
    app.include_router(reports_router.router)
    # Hosted-edition billing (schema 028): Stripe checkout/portal/webhook, the
    # 402 upgrade body, and the public /status endpoint.
    app.include_router(billing_router.router)
    app.include_router(billing_status.router)
    app.include_router(system_router.router)
    app.include_router(ai_settings_router.router)
    app.add_exception_handler(billing_gate.PaymentRequired, billing_gate.payment_required_handler)
    app.include_router(verification_router.router)
    # MSP console (schema 033): customers, switching, rollup, templates, usage
    from .routers import msp as msp_router

    app.include_router(msp_router.router)
    # Universal ingest + per-source ingest tokens (schema 027).
    app.include_router(ingest_router.router)
    # Growth (schema 032): free exposure report (public), shareable trust pages,
    # supplier monitoring. All passive: DNS + certificate transparency only.
    app.include_router(growth_exposure.router)
    app.include_router(growth_trust.router)
    app.include_router(growth_trust.public_router)
    app.include_router(growth_suppliers.router)

    return app


app = create_app()
