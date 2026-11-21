"""License + usage-metering endpoints (schema 024).

* ``GET    /v1/license``           -- effective edition, limits, features (read)
* ``POST   /v1/license``           -- upload a signed license key (admin)
* ``DELETE /v1/license``           -- revert to env/file license or Community (admin)
* ``GET    /v1/usage``             -- live usage vs license limits (read)
* ``POST   /v1/usage/snapshot``    -- write today's billing snapshot (admin; cron-able)
* ``GET    /v1/usage/snapshots``   -- daily snapshot history (read)

Usage counts are best-effort: every source that might be absent (another
service, a table owned by another feature) degrades to ``null``/``0`` with a
note, and limits are reported -- never enforced by blocking anything.
"""
from __future__ import annotations

import json
import logging
from datetime import date, datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from .. import licensing as lic_svc
from ..auth import current_principal, require
from ..config import settings
from ..db import get_pool
from ..service_client import service_headers

logger = logging.getLogger(__name__)

router = APIRouter(tags=["licensing"])

# Asset kinds that count toward the "monitored assets" pricing metric: things
# an operator would call a host/asset. Ports, services, technologies,
# certificates, endpoints and secret candidates are facets of those assets.
BILLABLE_ASSET_KINDS: tuple[str, ...] = (
    "domain", "subdomain", "ipv4", "ipv6", "cloud_resource",
    "repository", "iot_device", "ot_device",
)
# An asset is "monitored" when it was seen inside this window.
MONITORED_WINDOW_DAYS = 30
_OTD_TIMEOUT = 3.0


# --------------------------------------------------------------------------- #
# Models
# --------------------------------------------------------------------------- #

class LicenseLimits(BaseModel):
    seats: int | None = None
    sites: int | None = None
    assets: int | None = None


class FeatureState(BaseModel):
    name: str
    description: str
    min_edition: str
    enabled: bool


class LicenseOut(BaseModel):
    edition: str = Field(description="Effective edition after expiry/validation.")
    status: str = Field(description="community | active | grace | expired | invalid")
    source: str = Field(description="default | db | env | file")
    licensed_edition: str | None = None
    license_id: str | None = None
    licensee: str | None = None
    limits: LicenseLimits
    issued_at: datetime | None = None
    expires_at: datetime | None = None
    days_remaining: int | None = None
    features: list[str]
    catalogue: list[FeatureState]
    error: str | None = None


class LicenseUploadIn(BaseModel):
    key: str = Field(min_length=10, max_length=16384, description="A PDK1.<payload>.<signature> key.")


class UsageLimitState(BaseModel):
    used: int | None
    limit: int | None
    over: bool


class UsageOut(BaseModel):
    generated_at: datetime
    edition: str
    license_id: str | None = None
    monitored_assets: int
    total_assets: int
    assets_by_kind: dict[str, int]
    sites: int | None = Field(description="Distinct Sentry sites seen by otdiscovery; null when unreachable.")
    sensors: int | None = None
    fleet_agents: int
    users: int
    scans_this_month: int
    integrations: int
    limits: dict[str, UsageLimitState]
    notes: list[str] = Field(default_factory=list)


class UsageSnapshotOut(BaseModel):
    day: date
    monitored_assets: int
    total_assets: int
    sites: int | None
    sensors: int | None
    fleet_agents: int
    users: int
    scans_month: int
    integrations: int
    edition: str
    license_id: str | None
    taken_at: datetime


# --------------------------------------------------------------------------- #
# License
# --------------------------------------------------------------------------- #

def _license_out(lic: lic_svc.License) -> LicenseOut:
    d = lic.as_dict()
    d["limits"] = LicenseLimits(**d["limits"])
    d["catalogue"] = [
        FeatureState(name=f.name, description=f.description, min_edition=f.min_edition, enabled=lic.has(f.name))
        for f in lic_svc.FEATURES.values()
    ]
    return LicenseOut(**d)


@router.get("/v1/license", response_model=LicenseOut)
async def get_license(request: Request):
    return _license_out(await lic_svc.current_license(request))


@router.post("/v1/license", response_model=LicenseOut, dependencies=[Depends(require("admin"))])
async def upload_license(body: LicenseUploadIn, request: Request, pool=Depends(get_pool)):
    try:
        lic = lic_svc.verify_license_key(body.key, source="db")
    except lic_svc.LicenseError as exc:
        raise HTTPException(status_code=422, detail=f"license rejected: {exc}") from exc
    if lic.status == "expired":
        raise HTTPException(status_code=422, detail="license rejected: expired")
    principal = current_principal(request)
    async with pool.acquire() as con:
        await con.execute(
            """
            INSERT INTO license_keys (license_id, edition, licensee, key_text, expires_at, uploaded_by)
            VALUES ($1, $2, $3, $4, $5, $6)
            """,
            lic.license_id, lic.licensed_edition, lic.licensee, body.key.strip(),
            lic.expires_at, principal.actor,
        )
    lic_svc.invalidate_cache(request.app)
    return _license_out(await lic_svc.current_license(request))


@router.delete("/v1/license", response_model=LicenseOut, dependencies=[Depends(require("admin"))])
async def remove_license(request: Request, pool=Depends(get_pool)):
    async with pool.acquire() as con:
        await con.execute("UPDATE license_keys SET removed_at = NOW() WHERE removed_at IS NULL")
    lic_svc.invalidate_cache(request.app)
    return _license_out(await lic_svc.current_license(request))


# --------------------------------------------------------------------------- #
# Usage
# --------------------------------------------------------------------------- #

async def _table_exists(con, name: str) -> bool:
    return bool(await con.fetchval("SELECT to_regclass($1) IS NOT NULL", f"public.{name}"))


async def _otdiscovery_sites() -> tuple[int | None, int | None, str | None]:
    """(sites, sensors, note) from otdiscovery /stats; (None, None, note) if absent."""
    try:
        import httpx

        async with httpx.AsyncClient(timeout=_OTD_TIMEOUT) as http:
            resp = await http.get(settings.otdiscovery_url.rstrip("/") + "/stats", headers=service_headers())
        if resp.status_code != 200:
            return None, None, f"otdiscovery /stats returned {resp.status_code}"
        sensors = (resp.json() or {}).get("sensors") or {}
        if not isinstance(sensors, dict):
            return None, None, "otdiscovery /stats: unexpected sensors shape"
        sites = {str(v.get("site") or k) for k, v in sensors.items() if isinstance(v, dict)}
        return len(sites), len(sensors), None
    except Exception as exc:  # noqa: BLE001 -- absent service is normal
        return None, None, f"otdiscovery unreachable ({type(exc).__name__}); sites/sensors unknown"


async def collect_usage(pool, lic: lic_svc.License) -> UsageOut:
    notes: list[str] = []
    since = datetime.now(timezone.utc) - timedelta(days=MONITORED_WINDOW_DAYS)
    month_start = datetime.now(timezone.utc).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    async with pool.acquire() as con:
        rows = await con.fetch(
            "SELECT kind, COUNT(*) AS n, COUNT(*) FILTER (WHERE last_seen >= $1) AS recent "
            "FROM assets GROUP BY kind",
            since,
        )
        by_kind = {r["kind"]: int(r["n"]) for r in rows}
        monitored = sum(int(r["recent"]) for r in rows if r["kind"] in BILLABLE_ASSET_KINDS)
        users = int(await con.fetchval("SELECT COUNT(*) FROM app_users WHERE active") or 0)
        scans = int(await con.fetchval("SELECT COUNT(*) FROM scans WHERE queued_at >= $1", month_start) or 0)
        integrations = 0
        if await _table_exists(con, "integrations"):
            integrations = int(await con.fetchval("SELECT COUNT(*) FROM integrations WHERE enabled") or 0)
        else:
            notes.append("integrations table absent")
        agents = 0
        if await _table_exists(con, "fleet_agents"):
            agents = int(await con.fetchval("SELECT COUNT(*) FROM fleet_agents") or 0)

    sites, sensors, note = await _otdiscovery_sites()
    if note:
        notes.append(note)

    def lim(used: int | None, limit: int | None) -> UsageLimitState:
        return UsageLimitState(used=used, limit=limit, over=bool(limit is not None and used is not None and used > limit))

    limits = {
        "seats": lim(users, lic.seats),
        "sites": lim(sites, lic.sites),
        "assets": lim(monitored, lic.assets),
    }
    if any(v.over for v in limits.values()):
        notes.append("usage exceeds license limits (reported only; nothing is blocked)")
    return UsageOut(
        generated_at=datetime.now(timezone.utc),
        edition=lic.edition,
        license_id=lic.license_id,
        monitored_assets=monitored,
        total_assets=sum(by_kind.values()),
        assets_by_kind=dict(sorted(by_kind.items())),
        sites=sites,
        sensors=sensors,
        fleet_agents=agents,
        users=users,
        scans_this_month=scans,
        integrations=integrations,
        limits=limits,
        notes=notes,
    )


_SNAPSHOT_COLS = (
    "day, monitored_assets, total_assets, sites, sensors, fleet_agents, users, "
    "scans_month, integrations, edition, license_id, taken_at"
)


async def write_snapshot(pool, usage: UsageOut, *, overwrite: bool) -> UsageSnapshotOut | None:
    day = usage.generated_at.date()
    conflict = (
        "DO UPDATE SET monitored_assets=EXCLUDED.monitored_assets, total_assets=EXCLUDED.total_assets, "
        "sites=EXCLUDED.sites, sensors=EXCLUDED.sensors, fleet_agents=EXCLUDED.fleet_agents, "
        "users=EXCLUDED.users, scans_month=EXCLUDED.scans_month, integrations=EXCLUDED.integrations, "
        "edition=EXCLUDED.edition, license_id=EXCLUDED.license_id, detail=EXCLUDED.detail, taken_at=NOW()"
        if overwrite else "DO NOTHING"
    )
    detail = {"assets_by_kind": usage.assets_by_kind, "notes": usage.notes}
    async with pool.acquire() as con:
        row = await con.fetchrow(
            f"""
            INSERT INTO usage_snapshots (day, monitored_assets, total_assets, sites, sensors,
                fleet_agents, users, scans_month, integrations, edition, license_id, detail)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb)
            ON CONFLICT (tenant_id, day) {conflict}
            RETURNING {_SNAPSHOT_COLS}
            """,
            day, usage.monitored_assets, usage.total_assets, usage.sites, usage.sensors,
            usage.fleet_agents, usage.users, usage.scans_this_month, usage.integrations,
            usage.edition, usage.license_id, json.dumps(detail),
        )
    return UsageSnapshotOut(**dict(row)) if row is not None else None


@router.get("/v1/usage", response_model=UsageOut)
async def get_usage(request: Request, pool=Depends(get_pool)):
    usage = await collect_usage(pool, await lic_svc.current_license(request))
    # Metering hook: the first read of the day records the day's snapshot so
    # billing history exists even without a cron. Best-effort.
    try:
        await write_snapshot(pool, usage, overwrite=False)
    except Exception:  # noqa: BLE001
        logger.exception("usage_snapshot_failed")
    return usage


@router.post("/v1/usage/snapshot", response_model=UsageSnapshotOut, dependencies=[Depends(require("admin"))])
async def take_snapshot(request: Request, pool=Depends(get_pool)):
    usage = await collect_usage(pool, await lic_svc.current_license(request))
    snap = await write_snapshot(pool, usage, overwrite=True)
    assert snap is not None
    return snap


@router.get("/v1/usage/snapshots", response_model=list[UsageSnapshotOut])
async def list_snapshots(days: int = Query(90, ge=1, le=1100), pool=Depends(get_pool)):
    since = datetime.now(timezone.utc).date() - timedelta(days=days)
    async with pool.acquire() as con:
        rows = await con.fetch(
            f"SELECT {_SNAPSHOT_COLS} FROM usage_snapshots WHERE day >= $1 ORDER BY day DESC",
            since,
        )
    return [UsageSnapshotOut(**dict(r)) for r in rows]

