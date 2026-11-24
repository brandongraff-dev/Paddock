"""First-run onboarding state + optional-service status.

* ``GET  /v1/onboarding``       -- wizard progress (schema 021 ``onboarding``)
  plus everything the wizard shows live: the chosen scope entry and its
  proof-of-control status, the first scan, and asset/finding counts for the
  domain. ``needs_setup`` tells the dashboard to open ``/setup`` for an admin.
* ``PUT  /v1/onboarding``       -- record progress (admin).
* ``GET  /v1/system/services``  -- which optional services this deployment
  runs, so the UI can say "not enabled" (lite mode) instead of erroring.

Nothing here probes a target; the wizard drives the existing scope / scan
endpoints, which keep every scope and proof check.
"""
from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from .. import scope_proof as proof_svc
from ..auth import current_principal, require
from ..config import settings
from ..db import get_pool

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/onboarding", tags=["onboarding"])
system_router = APIRouter(prefix="/v1/system", tags=["system"])

STEPS = ("workspace", "domain", "verify", "scan", "results", "team", "done")
Step = Literal["workspace", "domain", "verify", "scan", "results", "team", "done"]


class ScanBrief(BaseModel):
    id: UUID
    kind: str
    target: str
    status: str
    queued_at: datetime | None = None
    finished_at: datetime | None = None
    error: str | None = None


class OnboardingCounts(BaseModel):
    assets: int = 0
    findings: int = 0
    domain_assets: int = 0
    domain_findings: int = 0


class OnboardingOut(BaseModel):
    available: bool = True
    workspace_name: str | None = None
    current_step: str = "workspace"
    steps_done: list[str] = Field(default_factory=list)
    dismissed: bool = False
    completed_at: datetime | None = None
    scope_entry: proof_svc.ScopeEntryWithProofOut | None = None
    first_scan: ScanBrief | None = None
    counts: OnboardingCounts = Field(default_factory=OnboardingCounts)
    has_verified_scope: bool = False
    needs_setup: bool = False
    require_scope_proof: bool = False
    deployment_mode: str = "full"


class OnboardingPatch(BaseModel):
    workspace_name: str | None = Field(default=None, min_length=1, max_length=120)
    current_step: Step | None = None
    step_done: Step | None = None
    scope_entry_id: int | None = None
    first_scan_id: UUID | None = None
    dismissed: bool | None = None
    completed: bool | None = None


_SCOPE_COLS = (
    "id, kind, value, added_by, added_at, expires_at, "
    "auth_doc_ref, active, notes, metadata"
)


async def _build(con) -> OnboardingOut:
    out = OnboardingOut(
        require_scope_proof=bool(settings.require_scope_proof),
        deployment_mode=settings.deployment_mode,
    )
    try:
        row = await con.fetchrow("SELECT * FROM onboarding WHERE id = 1")
    except asyncpg.UndefinedTableError:
        logger.warning("onboarding table missing; apply schema/021_scope_proof.sql")
        out.available = False
        return out
    if row is None:
        await con.execute("INSERT INTO onboarding (id) VALUES (1) ON CONFLICT (tenant_id, id) DO NOTHING")
        row = await con.fetchrow("SELECT * FROM onboarding WHERE id = 1")

    out.workspace_name = row["workspace_name"]
    out.current_step = row["current_step"]
    out.steps_done = list(row["steps_done"] or [])
    out.dismissed = row["dismissed"]
    out.completed_at = row["completed_at"]

    out.has_verified_scope = bool(await con.fetchval(
        """
        SELECT EXISTS (
          SELECT 1 FROM scope_entries e JOIN scope_proofs p ON p.scope_entry_id = e.id
           WHERE e.active AND p.status IN ('verified', 'attested')
             AND (e.expires_at IS NULL OR e.expires_at > NOW()))
        """
    ))

    if row["scope_entry_id"] is not None:
        from .scope import _row_to_scope

        erow = await con.fetchrow(
            f"SELECT {_SCOPE_COLS} FROM scope_entries WHERE id = $1", row["scope_entry_id"]
        )
        if erow is not None:
            entry = _row_to_scope(erow)
            prow = await proof_svc.fetch_proof_row(con, entry.id)
            out.scope_entry = proof_svc.ScopeEntryWithProofOut(
                **entry.model_dump(), proof=proof_svc.proof_out(entry.kind, entry.active, prow)
            )

    if row["first_scan_id"] is not None:
        srow = await con.fetchrow(
            "SELECT id, kind, target, status, queued_at, finished_at, error "
            "FROM scans WHERE id = $1",
            row["first_scan_id"],
        )
        if srow is not None:
            out.first_scan = ScanBrief.model_validate(dict(srow))

    counts = OnboardingCounts(
        assets=await con.fetchval("SELECT COUNT(*) FROM assets"),
        findings=await con.fetchval("SELECT COUNT(*) FROM findings"),
    )
    if out.scope_entry is not None and out.scope_entry.kind in ("domain", "subdomain_wildcard"):
        base = proof_svc.base_domain(out.scope_entry.value)
        # Suffix match without LIKE ('_' is a LIKE wildcard and legal in labels).
        match = "(a.canonical = $1 OR right(a.canonical, length($1) + 1) = '.' || $1)"
        counts.domain_assets = await con.fetchval(
            f"SELECT COUNT(*) FROM assets a WHERE {match}", base
        )
        counts.domain_findings = await con.fetchval(
            f"SELECT COUNT(*) FROM findings f JOIN assets a ON a.id = f.asset_id WHERE {match}",
            base,
        )
    out.counts = counts
    out.needs_setup = (
        not out.dismissed and out.completed_at is None and not out.has_verified_scope
    )
    return out


@router.get("", response_model=OnboardingOut)
async def get_onboarding(pool=Depends(get_pool)):
    async with pool.acquire() as con:
        return await _build(con)


@router.put("", response_model=OnboardingOut, dependencies=[Depends(require("admin"))])
async def put_onboarding(body: OnboardingPatch, request: Request, pool=Depends(get_pool)):
    actor = current_principal(request).actor
    sets: list[str] = []
    args: list[Any] = []

    def add(sql: str, value: Any) -> None:
        args.append(value)
        sets.append(sql.replace("$?", f"${len(args)}"))

    fields = body.model_fields_set
    if body.workspace_name is not None:
        add("workspace_name = $?", body.workspace_name.strip())
    if body.current_step is not None:
        add("current_step = $?", body.current_step)
    if body.step_done is not None:
        add("steps_done = CASE WHEN $?::text = ANY(steps_done) THEN steps_done "
            "ELSE array_append(steps_done, $?::text) END", body.step_done)
    if "scope_entry_id" in fields:
        add("scope_entry_id = $?", body.scope_entry_id)
    if "first_scan_id" in fields:
        add("first_scan_id = $?", body.first_scan_id)
    if body.dismissed is not None:
        add("dismissed = $?", body.dismissed)
    if body.completed is not None:
        sets.append("completed_at = " + ("COALESCE(completed_at, NOW())" if body.completed else "NULL"))
    add("updated_by = $?", actor)
    sets.append("updated_at = NOW()")

    async with pool.acquire() as con:
        try:
            await con.execute("INSERT INTO onboarding (id) VALUES (1) ON CONFLICT (tenant_id, id) DO NOTHING")
            await con.execute(f"UPDATE onboarding SET {', '.join(sets)} WHERE id = 1", *args)
        except asyncpg.UndefinedTableError:
            raise HTTPException(
                status_code=503, detail="onboarding unavailable: apply schema/021_scope_proof.sql"
            )
        except asyncpg.ForeignKeyViolationError:
            raise HTTPException(status_code=404, detail="scope entry not found")
        return await _build(con)


# --------------------------------------------------------------------------- #
# Optional services
# --------------------------------------------------------------------------- #

class ServiceStatus(BaseModel):
    name: str
    feature: str
    enabled: bool
    status: Literal["ok", "down", "not_enabled"]


class ServicesOut(BaseModel):
    mode: str
    services: list[ServiceStatus]


# name -> (feature it powers, base URL). URLs for the orchestrator's proxy
# targets come from settings; the rest are the compose health ports.
def _optional_services() -> dict[str, tuple[str, str]]:
    return {
        "correlation": ("CVE matching, chains, attack paths", settings.correlation_url),
        "intel": ("NVD / EPSS / KEV feeds", "http://intel:8090"),
        "brain": ("Ask (LLM triage)", settings.brain_url),
        "graphsync": ("Neo4j graph paths", settings.graphsync_url),
        "mlrisk": ("Adaptive risk model", settings.mlrisk_url),
        "codeanalysis": ("SAST + reachability", settings.codeanalysis_url),
        "sca": ("Dependencies / SBOM", "http://sca:8094"),
        "changewatch": ("Surface change alerts", "http://changewatch:8092"),
        "triage": ("Owner routing + tickets", "http://triage:8093"),
        "ontology": ("Semantic layer", settings.ontology_url),
        "threatintel": ("STIX/TAXII threat intel", settings.threatintel_url),
        "otdiscovery": ("Devices / Sentry ingest", settings.otdiscovery_url),
        "remediation": ("Auto-remediation", settings.remediation_url),
    }


# Optional services the lite compose file DOES run. Everything else is reported
# "not_enabled" in lite without being probed; these are probed like in full mode.
LITE_INCLUDED = frozenset({"brain"})

_cache: tuple[float, ServicesOut] | None = None
_CACHE_SEC = 30.0


async def _probe(url: str) -> bool:
    """TCP-connect to the service's port (internal network, no request body)."""
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    host, port = parts.hostname, parts.port or (443 if parts.scheme == "https" else 80)
    if not host:
        return False
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=1.0)
    except Exception:  # noqa: BLE001
        return False
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:  # noqa: BLE001
        pass
    return True


@system_router.get("/services", response_model=ServicesOut)
async def services_status():
    global _cache
    if _cache is not None and time.monotonic() - _cache[0] < _CACHE_SEC:
        return _cache[1]
    svcs = _optional_services()
    lite = settings.deployment_mode == "lite"
    names = list(svcs)
    # in lite only LITE_INCLUDED are probed; the rest are "not enabled"
    off = {n for n in names if lite and n not in LITE_INCLUDED}
    probed = [n for n in names if n not in off]
    found = dict(zip(probed, await asyncio.gather(*(_probe(svcs[n][1]) for n in probed))))
    out = ServicesOut(
        mode=settings.deployment_mode,
        services=[
            ServiceStatus(
                name=n,
                feature=svcs[n][0],
                enabled=n not in off,
                status="not_enabled" if n in off else ("ok" if found[n] else "down"),
            )
            for n in names
        ],
    )
    _cache = (time.monotonic(), out)
    return out
