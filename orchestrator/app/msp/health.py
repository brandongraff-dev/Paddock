"""MSP rollup (per-customer health) and per-customer usage for billing.

The cross-tenant read is an explicit loop: for each customer id the caller is
granted, run ONE small set of queries inside ``tenancy.tenant_context(child)``
and take the numbers back out. Row-level security is never disabled and no
query ever spans tenants; every query additionally repeats ``tenant_id = $1``
(belt and braces: the numbers stay right even if a deployment runs a role that
bypasses RLS, as the default test pool does).

Contexts are never mixed on one connection: each ``pool.acquire()`` stamps the
tenant that is current at acquire time (see ``tenancy.setup_connection``), so
the child queries run on their own connection, and the cached result is
written afterwards under the MSP's context.
"""
from __future__ import annotations

import csv
import io
import logging
from datetime import date, datetime, timedelta, timezone
from typing import Any, Iterable

from .. import licensing as lic_svc
from .. import tenancy
from .core import GRANTED_CHILDREN_SQL, msp_settings

logger = logging.getLogger(__name__)

# Same weights as the Overview page / reports (reports/metrics.py SEV_WEIGHT).
_W_SQL = (
    "CASE f.severity WHEN 'critical' THEN 10 WHEN 'high' THEN 5 "
    "WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END"
)
VERIFY_GRACE_SEC = 60  # reports/metrics.py VERIFY_GRACE
VERIFIED_WINDOW_DAYS = 30

GRADES = ("A", "B", "C", "D", "F")
SORTS = {
    "name": "c.name",
    "created": "c.created_at",
    "grade": "h.exposure_index",
    "exposure": "h.exposure_index",
    "criticals": "h.open_criticals",
    "sla_breaches": "h.sla_breaches",
    "verified_fixes": "h.verified_fixes",
    "last_scan": "h.last_scan_at",
    "assets": "h.monitored_assets",
}
_METRIC_SORTS = frozenset(SORTS) - {"name", "created"}


def grade_for(exposure_index: int, open_criticals: int) -> str:
    """Letter grade from the exposure index (the Overview formula), capped by
    open criticals. Documented in docs/MSP.md; deliberately simple so an MSP
    can explain it to a customer.

    index <=10 A, <=40 B, <=100 C, <=250 D, else F; any open critical caps the
    grade at C, five or more at D.
    """
    if exposure_index <= 10:
        g = 0
    elif exposure_index <= 40:
        g = 1
    elif exposure_index <= 100:
        g = 2
    elif exposure_index <= 250:
        g = 3
    else:
        g = 4
    if open_criticals >= 5:
        g = max(g, 3)
    elif open_criticals >= 1:
        g = max(g, 2)
    return GRADES[g]


# --------------------------------------------------------------------------- #
# One customer, under that customer's tenant context
# --------------------------------------------------------------------------- #

async def compute_child_metrics(pool, child_id: str) -> dict[str, Any]:
    """Health + licence numbers of ONE customer. Must be called with no other
    tenant context assumed: it binds ``child_id`` itself."""
    from ..routers.licensing import BILLABLE_ASSET_KINDS, MONITORED_WINDOW_DAYS

    now = datetime.now(timezone.utc)
    since_assets = now - timedelta(days=MONITORED_WINDOW_DAYS)
    since_fixes = now - timedelta(days=VERIFIED_WINDOW_DAYS)
    with tenancy.tenant_context(child_id):
        async with pool.acquire() as con:
            f = await con.fetchrow(
                f"""
                SELECT COALESCE(SUM({_W_SQL}), 0)::int                       AS exposure,
                       COUNT(*)                                                AS open_total,
                       COUNT(*) FILTER (WHERE f.severity = 'critical')         AS crit
                  FROM findings f
                 WHERE f.tenant_id = $1 AND f.status IN ('open', 'triaged')
                """,
                child_id,
            )
            sla = await con.fetchval(
                """
                SELECT COUNT(*)
                  FROM findings f
                  LEFT JOIN tickets t ON t.finding_id = f.id AND t.tenant_id = $1
                  LEFT JOIN sla_policies p ON p.severity = f.severity
                 WHERE f.tenant_id = $1 AND f.status IN ('open', 'triaged')
                   AND COALESCE(t.sla_due,
                                CASE WHEN p.hours > 0
                                     THEN f.first_seen + make_interval(hours => p.hours) END) < NOW()
                """,
                child_id,
            )
            verified = await con.fetchval(
                """
                SELECT COUNT(*)
                  FROM findings f
                  JOIN finding_resolutions r ON r.finding_id = f.id AND r.tenant_id = $1
                  JOIN assets a ON a.id = f.asset_id AND a.tenant_id = $1
                 WHERE f.tenant_id = $1 AND f.status = 'fixed' AND r.status = 'fixed'
                   AND r.resolved_at >= $2
                   AND f.last_seen <= r.resolved_at + make_interval(secs => $3)
                   AND a.last_seen  >  r.resolved_at + make_interval(secs => $3)
                """,
                child_id, since_fixes, float(VERIFY_GRACE_SEC),
            )
            last_scan = await con.fetchval(
                "SELECT MAX(COALESCE(finished_at, started_at, queued_at)) FROM scans "
                " WHERE tenant_id = $1 AND status = 'completed'",
                child_id,
            )
            assets = await con.fetchrow(
                "SELECT COUNT(*) AS total, "
                "       COUNT(*) FILTER (WHERE last_seen >= $2 AND kind = ANY($3::text[])) AS monitored "
                "  FROM assets WHERE tenant_id = $1",
                child_id, since_assets, list(BILLABLE_ASSET_KINDS),
            )
            users = await con.fetchval(
                "SELECT COUNT(*) FROM app_users WHERE tenant_id = $1 AND active", child_id
            )
        lic = await lic_svc.load_active_license(pool)
    exposure = int(f["exposure"])
    crit = int(f["crit"])
    return {
        "grade": grade_for(exposure, crit),
        "exposure_index": exposure,
        "open_findings": int(f["open_total"]),
        "open_criticals": crit,
        "sla_breaches": int(sla or 0),
        "verified_fixes": int(verified or 0),
        "last_scan_at": last_scan,
        "monitored_assets": int(assets["monitored"]),
        "total_assets": int(assets["total"]),
        "seats_used": int(users or 0),
        "seats_limit": lic.seats,
        "assets_limit": lic.assets,
        "edition": lic.edition,
    }


async def compute_child_usage(pool, child_id: str) -> dict[str, Any]:
    """Billing counters of ONE customer (same definitions as /v1/usage, minus
    the otdiscovery sites probe, which is not tenant-aware)."""
    from ..routers.licensing import BILLABLE_ASSET_KINDS, MONITORED_WINDOW_DAYS

    now = datetime.now(timezone.utc)
    since = now - timedelta(days=MONITORED_WINDOW_DAYS)
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    with tenancy.tenant_context(child_id):
        async with pool.acquire() as con:
            a = await con.fetchrow(
                "SELECT COUNT(*) AS total, "
                "       COUNT(*) FILTER (WHERE last_seen >= $2 AND kind = ANY($3::text[])) AS monitored "
                "  FROM assets WHERE tenant_id = $1",
                child_id, since, list(BILLABLE_ASSET_KINDS),
            )
            users = await con.fetchval(
                "SELECT COUNT(*) FROM app_users WHERE tenant_id = $1 AND active", child_id
            )
            scans = await con.fetchval(
                "SELECT COUNT(*) FROM scans WHERE tenant_id = $1 AND queued_at >= $2", child_id, month_start
            )
            integrations = await con.fetchval(
                "SELECT COUNT(*) FROM integrations WHERE tenant_id = $1 AND enabled", child_id
            )
            agents = await con.fetchval("SELECT COUNT(*) FROM fleet_agents WHERE tenant_id = $1", child_id)
        lic = await lic_svc.load_active_license(pool)
    return {
        "monitored_assets": int(a["monitored"]),
        "total_assets": int(a["total"]),
        "users": int(users or 0),
        "scans_month": int(scans or 0),
        "integrations": int(integrations or 0),
        "fleet_agents": int(agents or 0),
        "edition": lic.edition,
        "seats_limit": lic.seats,
        "assets_limit": lic.assets,
    }


# --------------------------------------------------------------------------- #
# Cache + paginated listing (MSP tenant context)
# --------------------------------------------------------------------------- #

_HEALTH_COLS = (
    "grade, exposure_index, open_findings, open_criticals, sla_breaches, verified_fixes, "
    "last_scan_at, monitored_assets, seats_used, seats_limit, assets_limit, computed_at"
)


async def refresh_health(pool, msp_tid: str, child_ids: Iterable[str]) -> int:
    """Recompute and cache the health of the given customers: one explicit
    ``tenant_context(child)`` per customer, then the cache write under the MSP.
    A customer whose computation fails keeps its previous cache row."""
    n = 0
    for cid in child_ids:
        try:
            m = await compute_child_metrics(pool, cid)
        except Exception:  # noqa: BLE001 -- one broken customer must not hide the rest
            logger.exception("msp_health_failed", extra={"child": cid})
            continue
        with tenancy.tenant_context(msp_tid):
            async with pool.acquire() as con:
                await con.execute(
                    """
                    INSERT INTO msp_child_health (child_tenant_id, tenant_id, grade, exposure_index,
                        open_findings, open_criticals, sla_breaches, verified_fixes, last_scan_at,
                        monitored_assets, seats_used, seats_limit, assets_limit, computed_at)
                    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,NOW())
                    ON CONFLICT (child_tenant_id) DO UPDATE SET
                        grade=EXCLUDED.grade, exposure_index=EXCLUDED.exposure_index,
                        open_findings=EXCLUDED.open_findings, open_criticals=EXCLUDED.open_criticals,
                        sla_breaches=EXCLUDED.sla_breaches, verified_fixes=EXCLUDED.verified_fixes,
                        last_scan_at=EXCLUDED.last_scan_at, monitored_assets=EXCLUDED.monitored_assets,
                        seats_used=EXCLUDED.seats_used, seats_limit=EXCLUDED.seats_limit,
                        assets_limit=EXCLUDED.assets_limit, computed_at=NOW()
                    """,
                    cid, msp_tid, m["grade"], m["exposure_index"], m["open_findings"],
                    m["open_criticals"], m["sla_breaches"], m["verified_fixes"], m["last_scan_at"],
                    m["monitored_assets"], m["seats_used"], m["seats_limit"], m["assets_limit"],
                )
        n += 1
    return n


def _row_out(r) -> dict[str, Any]:
    d = dict(r)
    out = {
        "id": str(d["child_tenant_id"]),
        "slug": d["slug"],
        "name": d["name"],
        "status": d.get("status"),
        "role": d["role"],
        "created_at": d["created_at"],
        "health": None,
    }
    if d.get("grade") is not None:
        out["health"] = {
            "grade": d["grade"],
            "exposure_index": d["exposure_index"],
            "open_findings": d["open_findings"],
            "open_criticals": d["open_criticals"],
            "sla_breaches": d["sla_breaches"],
            "verified_fixes": d["verified_fixes"],
            "last_scan_at": d["last_scan_at"],
            "monitored_assets": d["monitored_assets"],
            "seats_used": d["seats_used"],
            "seats_limit": d["seats_limit"],
            "assets_limit": d["assets_limit"],
            "computed_at": d["computed_at"],
        }
    return out


async def list_customers(
    pool,
    msp_tid: str,
    user_id: str,
    *,
    q: str | None = None,
    sort: str = "name",
    desc: bool = False,
    limit: int = 25,
    offset: int = 0,
    refresh: bool = False,
) -> dict[str, Any]:
    """Paginated customer list with health, for the customers ``user_id`` is
    granted. Search matches name / slug (case-insensitive substring)."""
    sort = sort if sort in SORTS else "name"
    ttl = float(max(0, int(msp_settings.health_ttl_sec)))
    where = ""
    args: list[Any] = [user_id]
    if q:
        args.append("%" + q.strip().lower().replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_") + "%")
        where = f" AND (lower(c.name) LIKE ${len(args)} OR lower(c.slug) LIKE ${len(args)})"
    base = GRANTED_CHILDREN_SQL + where

    n = len(args)

    def _page_sql(order: str) -> str:
        return (
            "SELECT c.*, t.status, h.grade, h.exposure_index, h.open_findings, h.open_criticals, "
            "       h.sla_breaches, h.verified_fixes, h.last_scan_at, h.monitored_assets, "
            "       h.seats_used, h.seats_limit, h.assets_limit, h.computed_at "
            f"  FROM ({base}) c "
            "  JOIN tenants t ON t.id = c.child_tenant_id "
            "  LEFT JOIN msp_child_health h ON h.child_tenant_id = c.child_tenant_id "
            f" ORDER BY {order} LIMIT ${n + 1} OFFSET ${n + 2}"
        )

    # Customers (optionally restricted to $n+1) whose cached health is missing
    # or older than the TTL ($n+3 forces everything).
    stale_sql = (
        f"SELECT g.child_tenant_id FROM ({base}) g "
        "  LEFT JOIN msp_child_health h ON h.child_tenant_id = g.child_tenant_id "
        f" WHERE (${n + 1}::uuid[] IS NULL OR g.child_tenant_id = ANY(${n + 1}::uuid[])) "
        f"   AND (${n + 3}::bool OR h.computed_at IS NULL "
        f"        OR h.computed_at < NOW() - make_interval(secs => ${n + 2}))"
    )

    direction = "DESC" if desc else "ASC"
    order = f"{SORTS[sort]} {direction} NULLS LAST, c.name ASC, c.child_tenant_id"

    with tenancy.tenant_context(msp_tid):
        async with pool.acquire() as con:
            total = await con.fetchval(f"SELECT COUNT(*) FROM ({base}) c", *args)
            restrict: list[str] | None = None
            if sort not in _METRIC_SORTS:
                # Name / created ordering needs no metrics: refresh only the page.
                page = await con.fetch(_page_sql(order), *args, limit, offset)
                restrict = [str(r["child_tenant_id"]) for r in page]
            stale = [
                str(r["child_tenant_id"])
                for r in await con.fetch(stale_sql, *args, restrict, ttl, refresh)
            ]
    # Ordering by a metric needs every candidate fresh; bounded so one request
    # cannot recompute an unbounded fleet (the rest keep their cached values).
    stale = stale[: msp_settings.rollup_max_children]
    if stale:
        await refresh_health(pool, msp_tid, stale)
    with tenancy.tenant_context(msp_tid):
        async with pool.acquire() as con:
            rows = await con.fetch(_page_sql(order), *args, limit, offset)
    items = [_row_out(r) for r in rows]
    return {"items": items, "total": int(total), "limit": limit, "offset": offset, "sort": sort,
            "order": "desc" if desc else "asc"}


async def summary(pool, msp_tid: str, user_id: str) -> dict[str, Any]:
    """Fleet-level totals over the cached health of the caller's customers."""
    with tenancy.tenant_context(msp_tid):
        async with pool.acquire() as con:
            r = await con.fetchrow(
                f"""
                SELECT COUNT(*) AS customers,
                       COUNT(h.child_tenant_id) AS with_health,
                       COALESCE(SUM(h.open_criticals), 0) AS open_criticals,
                       COALESCE(SUM(h.sla_breaches), 0)   AS sla_breaches,
                       COALESCE(SUM(h.verified_fixes), 0) AS verified_fixes,
                       COUNT(*) FILTER (WHERE h.grade IN ('D','F')) AS at_risk
                  FROM ({GRANTED_CHILDREN_SQL}) c
                  LEFT JOIN msp_child_health h ON h.child_tenant_id = c.child_tenant_id
                """,
                user_id,
            )
    return {k: int(v) for k, v in dict(r).items()}


# --------------------------------------------------------------------------- #
# Usage for MSP billing
# --------------------------------------------------------------------------- #

def _month_bounds(month: str | None) -> tuple[date, date, str]:
    today = datetime.now(timezone.utc).date()
    if month:
        try:
            y, m = month.split("-")
            first = date(int(y), int(m), 1)
        except (ValueError, TypeError) as exc:
            raise ValueError("month must be YYYY-MM") from exc
    else:
        first = today.replace(day=1)
    nxt = (first.replace(day=28) + timedelta(days=4)).replace(day=1)
    return first, nxt, first.strftime("%Y-%m")


async def snapshot_usage(pool, msp_tid: str, children: list[dict[str, Any]]) -> int:
    """Write today's per-customer usage snapshot (idempotent per day)."""
    day = datetime.now(timezone.utc).date()
    n = 0
    for c in children:
        cid = str(c["child_tenant_id"])
        u = await compute_child_usage(pool, cid)
        with tenancy.tenant_context(msp_tid):
            async with pool.acquire() as con:
                await con.execute(
                    """
                    INSERT INTO msp_usage_snapshots (child_tenant_id, day, tenant_id, monitored_assets,
                        total_assets, users, scans_month, integrations, fleet_agents, edition)
                    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
                    ON CONFLICT (child_tenant_id, day) DO UPDATE SET
                        monitored_assets=EXCLUDED.monitored_assets, total_assets=EXCLUDED.total_assets,
                        users=EXCLUDED.users, scans_month=EXCLUDED.scans_month,
                        integrations=EXCLUDED.integrations, fleet_agents=EXCLUDED.fleet_agents,
                        edition=EXCLUDED.edition, taken_at=NOW()
                    """,
                    cid, day, msp_tid, u["monitored_assets"], u["total_assets"], u["users"],
                    u["scans_month"], u["integrations"], u["fleet_agents"], u["edition"],
                )
        n += 1
    return n


async def usage_report(pool, msp_tid: str, children: list[dict[str, Any]], month: str | None) -> dict[str, Any]:
    """Per-customer billing rows for ``month`` (default: this month).

    ``monitored_assets`` is the live figure (current month) or the month's last
    snapshot (past months); ``peak_monitored_assets`` / ``avg`` come from the
    daily snapshots taken in that month (``POST /v1/msp/usage/snapshot``), and
    fall back to the live value when no snapshot exists.
    """
    first, nxt, label = _month_bounds(month)
    current = first == datetime.now(timezone.utc).date().replace(day=1)
    ids = [str(c["child_tenant_id"]) for c in children]
    snaps: dict[str, Any] = {}
    last: dict[str, Any] = {}
    if ids:
        with tenancy.tenant_context(msp_tid):
            async with pool.acquire() as con:
                for r in await con.fetch(
                    "SELECT child_tenant_id, MAX(monitored_assets) AS peak, "
                    "       ROUND(AVG(monitored_assets))::int AS avg, COUNT(*) AS days "
                    "  FROM msp_usage_snapshots WHERE child_tenant_id = ANY($1::uuid[]) "
                    "   AND day >= $2 AND day < $3 GROUP BY child_tenant_id",
                    ids, first, nxt,
                ):
                    snaps[str(r["child_tenant_id"])] = dict(r)
                for r in await con.fetch(
                    "SELECT DISTINCT ON (child_tenant_id) child_tenant_id, monitored_assets, total_assets, "
                    "       users, scans_month, integrations, fleet_agents, edition "
                    "  FROM msp_usage_snapshots WHERE child_tenant_id = ANY($1::uuid[]) "
                    "   AND day >= $2 AND day < $3 ORDER BY child_tenant_id, day DESC",
                    ids, first, nxt,
                ):
                    last[str(r["child_tenant_id"])] = dict(r)
    rows = []
    for c in children:
        cid = str(c["child_tenant_id"])
        if current or cid not in last:
            u = await compute_child_usage(pool, cid)
            source = "live" if current else "live (no snapshot for this month)"
        else:
            u = {**last[cid], "seats_limit": None, "assets_limit": None}
            source = "snapshot"
        s = snaps.get(cid)
        rows.append({
            "customer_id": cid,
            "slug": c["slug"],
            "name": c["name"],
            "month": label,
            "source": source,
            "edition": u["edition"],
            "monitored_assets": u["monitored_assets"],
            "peak_monitored_assets": max(u["monitored_assets"], s["peak"]) if s else u["monitored_assets"],
            "avg_monitored_assets": s["avg"] if s else u["monitored_assets"],
            "snapshot_days": s["days"] if s else 0,
            "total_assets": u["total_assets"],
            "users": u["users"],
            "scans_month": u["scans_month"],
            "integrations": u["integrations"],
            "fleet_agents": u["fleet_agents"],
            "seats_limit": u.get("seats_limit"),
            "assets_limit": u.get("assets_limit"),
        })
    totals = {k: sum(int(r[k] or 0) for r in rows) for k in
              ("monitored_assets", "peak_monitored_assets", "total_assets", "users", "scans_month",
               "integrations", "fleet_agents")}
    return {"month": label, "customers": len(rows), "items": rows, "totals": totals}


CSV_COLUMNS = (
    "customer_id", "slug", "name", "month", "source", "edition", "monitored_assets",
    "peak_monitored_assets", "avg_monitored_assets", "snapshot_days", "total_assets", "users",
    "seats_limit", "assets_limit", "scans_month", "integrations", "fleet_agents",
)


def _csv_cell(v: Any) -> Any:
    """Neutralise spreadsheet formula injection (customer names are
    attacker-influenced): a leading = + - @ tab or CR gets a quote prefix."""
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return "" if v is None else v


def usage_csv(report: dict[str, Any]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(CSV_COLUMNS)
    for r in report["items"]:
        w.writerow([_csv_cell(r.get(c)) for c in CSV_COLUMNS])
    return buf.getvalue()


def json_default(o: Any) -> str:
    if isinstance(o, (datetime, date)):
        return o.isoformat()
    return str(o)


__all__ = [
    "grade_for", "compute_child_metrics", "compute_child_usage", "refresh_health",
    "list_customers", "summary", "snapshot_usage", "usage_report", "usage_csv",
]
