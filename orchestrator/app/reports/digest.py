"""Weekly digest: build per workspace and hand it to the integrations framework.

Delivery (Slack / Teams / email / webhook) belongs to the integrations
framework: we emit one ``report.digest`` event and every integration
subscribed to that event type renders it in its own channel. The event's
``data`` carries ready-made renderings so connectors need no report logic:

    data = {
      "workspace": "default",
      "period": {"start": iso, "end": iso, "days": 7, "label": "14 – 21 Nov 2026"},
      "highlights": [str, ...],            # the plain-English bullets
      "metrics": {...},                    # compact numbers (see _metrics)
      "text": str,                         # plain-text email / chat body
      "html": str,                         # email-safe HTML (inline styles, no SVG/JS)
      "report_url": str | None,            # dashboard deep link (REPORTS_PUBLIC_URL)
    }

Scheduling: `run_due_digests` is called from the scheduler loop each tick. A
digest slot is the most recent ``REPORTS_DIGEST_WEEKDAY`` at
``REPORTS_DIGEST_HOUR`` UTC; a unique index on ``report_digests`` makes the
claim atomic, so several orchestrator replicas never send twice. Slots older
than 36h are skipped (no surprise stale digest after a long outage).

Digests leave Paddock, so they are built at ``REPORTS_DIGEST_CLEARANCE``
(default ``internal``): confidential/restricted rows never reach a channel.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from html import escape
from typing import Any

from .config import report_settings
from .metrics import SEV_WEIGHT, build_report, fmt_hours
from .models import DigestRunOut, ReportData

logger = logging.getLogger(__name__)

_SPARK = "▁▂▃▄▅▆▇█"
STALE_SLOT = timedelta(hours=36)


def sparkline(values: list[int]) -> str:
    if not values:
        return ""
    lo, hi = min(values), max(values)
    if hi == lo:
        return _SPARK[3] * len(values)
    return "".join(_SPARK[round((v - lo) / (hi - lo) * (len(_SPARK) - 1))] for v in values)


def _metrics(r: ReportData) -> dict[str, Any]:
    return {
        "exposure": {
            "start": r.exposure.start_value,
            "end": r.exposure.end_value,
            "delta": r.exposure.delta,
            "delta_pct": r.exposure.delta_pct,
        },
        "open": r.exposure.open_end,
        "new": {
            "critical": r.new_findings.critical,
            "high": r.new_findings.high,
            "previous_critical_high": r.new_findings.previous_critical_high,
        },
        "fixed": r.resolutions.fixed,
        "verified": r.resolutions.verified,
        "regressed": r.resolutions.regressed,
        "mttr_median_hours": r.mttr.overall.median_hours if r.mttr.overall else None,
        "sla_compliance_pct": r.sla.compliance_pct,
        "sla_breaches": r.sla.late + r.sla.breached_open,
        "attack_paths": {
            "opened": r.attack_paths.opened,
            "closed": r.attack_paths.closed,
            "open": r.attack_paths.open_end,
        },
        "surface_changes": r.changes.total,
        "device_behaviour": sum(b.opened for b in r.devices.behaviour),
    }


def _url(path: str = "/reports") -> str | None:
    base = report_settings.public_url.rstrip("/")
    return f"{base}{path}" if base else None


def render_text(r: ReportData) -> str:
    ex = r.exposure
    lines = [
        f"Paddock weekly digest — {r.org_name}",
        f"{r.window.label}",
        "",
        *[f"• {h}" for h in r.highlights],
        "",
        f"Exposure index  {ex.end_value} ({ex.delta:+d})  {sparkline([p.value for p in ex.points])}",
        "Open now        "
        + "  ".join(f"{k} {ex.open_end[k]}" for k in ("critical", "high", "medium", "low")),
        f"Fixed           {r.resolutions.fixed} ({r.resolutions.verified} verified)",
        f"Median to fix   {fmt_hours(r.mttr.overall.median_hours if r.mttr.overall else None)}",
        "SLA compliance  "
        + (f"{r.sla.compliance_pct:.0f}%" if r.sla.compliance_pct is not None else "—"),
    ]
    if r.new_findings.top:
        lines += ["", "New critical & high:"]
        for f in r.new_findings.top[:5]:
            lines.append(f"  [{f.severity.upper()}] {f.title} — {f.asset_value}")
    if r.sla.breaches:
        lines += ["", "Overdue:"]
        for b in r.sla.breaches[:5]:
            lines.append(
                f"  [{b.severity.upper()}] {b.title} — {b.team}, {fmt_hours(b.overdue_hours)} over"
            )
    if r.attack_paths.top_closed:
        lines += ["", "Attack paths closed:"]
        lines += [f"  ✓ {p.title}" for p in r.attack_paths.top_closed[:3]]
    url = _url()
    if url:
        lines += ["", f"Full report: {url}"]
    lines += ["", f"Contains data classified up to {r.clearance}."]
    return "\n".join(lines)


_SEV_HEX = {
    "critical": "#8f3226",
    "high": "#b55837",
    "medium": "#c97a4f",
    "low": "#d49a72",
    "info": "#b3aa9e",
}


def render_email_html(r: ReportData) -> str:
    """Email-safe HTML: tables + inline styles only (no SVG, no web fonts)."""
    e = escape
    ex = r.exposure
    serif = "Georgia,'Times New Roman',serif"
    sans = "-apple-system,'Segoe UI',Helvetica,Arial,sans-serif"
    kpis = [
        ("Exposure", f"{ex.end_value}", f"{ex.delta:+d} vs start"),
        (
            "New crit / high",
            f"{r.new_findings.critical} / {r.new_findings.high}",
            f"prev {r.new_findings.previous_critical_high}",
        ),
        ("Fixed", f"{r.resolutions.fixed}", f"{r.resolutions.verified} verified"),
        (
            "SLA",
            f"{r.sla.compliance_pct:.0f}%" if r.sla.compliance_pct is not None else "—",
            f"{r.sla.late + r.sla.breached_open} breached",
        ),
    ]
    kpi_cells = "".join(
        f'<td style="padding:10px 12px 10px {0 if i == 0 else 12}px;border-left:{"0" if i == 0 else "1px solid #e4dccd"};vertical-align:top">'
        f'<div style="font:600 10px {sans};letter-spacing:.08em;text-transform:uppercase;color:#7a7064">{e(lab)}</div>'
        f'<div style="font:400 26px {serif};color:#1b1712;line-height:1.2">{e(v)}</div>'
        f'<div style="font:12px {sans};color:#4a4239">{e(s)}</div></td>'
        for i, (lab, v, s) in enumerate(kpis)
    )
    total = sum(ex.open_end[k] * 1 for k in ex.open_end) or 1
    strip = (
        "".join(
            f'<td style="background:{_SEV_HEX[k]};height:8px;width:{max(1, round(100 * ex.open_end[k] / total))}%"></td>'
            for k in ("critical", "high", "medium", "low", "info")
            if ex.open_end[k]
        )
        or '<td style="background:#ece5d8;height:8px"></td>'
    )
    items = ""
    for f in r.new_findings.top[:5]:
        items += (
            f'<tr><td style="padding:6px 0;border-bottom:1px solid #ece5d8;font:12px {sans};color:#1b1712">'
            f'<span style="display:inline-block;width:8px;height:8px;border-radius:4px;background:{_SEV_HEX[f.severity]};margin-right:6px"></span>'
            f'<b style="font-weight:600;text-transform:uppercase;font-size:10px;color:#4a4239">{e(f.severity)}</b> '
            f'{e(f.title)}<br><span style="font:11px Menlo,monospace;color:#7a7064">{e(f.asset_value or "")}</span></td></tr>'
        )
    url = _url()
    cta = (
        f'<p style="margin:20px 0 0"><a href="{e(url)}" style="font:600 13px {sans};color:#fbf8f2;background:#1b1712;'
        f'padding:9px 16px;border-radius:6px;text-decoration:none">Open the full report</a></p>'
        if url
        else ""
    )
    bullets = "".join(
        f'<li style="margin:0 0 6px;font:16px/1.4 {serif};color:#1b1712">{e(h)}</li>'
        for h in r.highlights
    )
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Paddock weekly digest</title></head>
<body style="margin:0;padding:0;background:#efe9de">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#efe9de"><tr><td align="center" style="padding:24px 12px">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px;background:#fbf8f2;border-radius:10px">
<tr><td style="padding:28px 32px 8px">
<div style="font:400 18px {serif};color:#1b1712">Paddock</div>
<div style="font:600 10px {sans};letter-spacing:.12em;text-transform:uppercase;color:#7a7064;margin-top:14px">Weekly digest · {e(r.window.label)}</div>
<h1 style="margin:6px 0 16px;font:400 28px/1.15 {serif};color:#1b1712">{e(r.org_name)}</h1>
<ul style="padding-left:18px;margin:0 0 18px">{bullets}</ul>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-top:1px solid #1b1712;border-bottom:1px solid #d6cbb8"><tr>{kpi_cells}</tr></table>
<div style="font:12px {sans};color:#4a4239;margin:14px 0 6px">Exposure trend <span style="font:14px Menlo,monospace;color:#3f6a85">{e(sparkline([p.value for p in ex.points]))}</span></div>
<div style="font:600 10px {sans};letter-spacing:.08em;text-transform:uppercase;color:#7a7064;margin:16px 0 6px">Open by severity</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="2"><tr>{strip}</tr></table>
<div style="font:11px {sans};color:#4a4239;margin-top:4px">{" · ".join(f"{k} {ex.open_end[k]}" for k in ("critical", "high", "medium", "low", "info"))}</div>
{f'<div style="font:600 10px {sans};letter-spacing:.08em;text-transform:uppercase;color:#7a7064;margin:18px 0 2px">New critical and high</div><table role="presentation" width="100%" cellpadding="0" cellspacing="0">{items}</table>' if items else ""}
{cta}
</td></tr>
<tr><td style="padding:18px 32px 24px;font:11px {sans};color:#7a7064;border-top:1px solid #e4dccd">
Generated by Paddock for {e(r.org_name)}. Contains data classified up to {e(r.clearance)}. Exposure index = Σ open findings × severity weight ({", ".join(f"{k} {v}" for k, v in SEV_WEIGHT.items() if v)}).
</td></tr></table></td></tr></table></body></html>"""


async def build_digest(
    pool, *, days: int | None = None, end: datetime | None = None, clearance: str | None = None
) -> tuple[ReportData, str, str]:
    r = await build_report(
        pool,
        days=days or report_settings.digest_period_days,
        end=end,
        clearance=clearance or report_settings.digest_clearance,
        top=5,
    )
    return r, render_text(r), render_email_html(r)


def digest_event(
    r: ReportData, text: str, html: str, workspace: str = "default", tenant_id: str | None = None
):
    from ..integrations.base import Event

    return Event(
        type="report.digest",
        title=f"Paddock weekly digest · {r.window.label}",
        summary="\n".join(r.highlights),
        data={
            "workspace": workspace,
            "period": {
                "start": r.window.start.isoformat(),
                "end": r.window.end.isoformat(),
                "days": r.window.days,
                "label": r.window.label,
            },
            "highlights": list(r.highlights),
            "metrics": _metrics(r),
            "text": text,
            "html": html,
            "report_url": _url(),
        },
        url=_url(),
        tenant_id=tenant_id,
    )


async def emit_digest(pool, event) -> tuple[str, str | None]:
    """Hand the event to the integrations framework. Returns (status, detail)."""
    try:
        from ..integrations.service import emit  # lazy: built by the integrations stream
    except Exception as exc:  # noqa: BLE001 -- ImportError until integrations ships
        logger.warning("digest_emit_unavailable", extra={"error": str(exc)})
        return "emit_unavailable", f"integrations service unavailable: {exc}"
    try:
        res = await emit(pool, event)
    except Exception as exc:  # noqa: BLE001 -- never let delivery break the scheduler
        logger.exception("digest_emit_failed")
        return "emit_failed", str(exc)[:500]
    return "emitted", (str(res)[:500] if res is not None else None)


async def list_workspaces(pool) -> list[tuple[str, str | None]]:
    """(workspace, tenant_id) pairs to digest.

    One ``default`` workspace PER ACTIVE TENANT. ``send_digest`` binds the
    tenant for the whole run, so RLS scopes the report queries and the claim
    row; before this a multi-tenant install digested only the default tenant.
    """
    from .. import tenancy

    return [("default", tid) for tid in await tenancy.list_tenant_ids(pool)]


def current_slot(now: datetime) -> datetime:
    """The most recent configured weekday/hour at or before `now` (UTC)."""
    wd = report_settings.digest_weekday % 7
    hr = max(0, min(23, report_settings.digest_hour))
    base = now.astimezone(timezone.utc).replace(hour=hr, minute=0, second=0, microsecond=0)
    base -= timedelta(days=(base.weekday() - wd) % 7)
    if base > now:
        base -= timedelta(days=7)
    return base


async def send_digest(
    pool,
    *,
    workspace: str = "default",
    tenant_id: str | None = None,
    kind: str = "manual",
    slot: datetime | None = None,
    days: int | None = None,
) -> DigestRunOut | None:
    """Build, record and emit one digest. For kind='weekly' the slot is claimed
    atomically; returns None when another run already claimed it."""
    if tenant_id is not None:
        from .. import tenancy

        with tenancy.tenant_context(tenant_id):
            return await _send_digest(pool, workspace, tenant_id, kind, slot, days)
    return await _send_digest(pool, workspace, tenant_id, kind, slot, days)


async def _send_digest(pool, workspace, tenant_id, kind, slot, days) -> DigestRunOut | None:
    end = slot or datetime.now(timezone.utc)
    days = days or report_settings.digest_period_days
    start = end - timedelta(days=days)
    async with pool.acquire() as con:
        row_id = await con.fetchval(
            """INSERT INTO report_digests (workspace, kind, period_start, period_end)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (tenant_id, workspace, kind, period_end) WHERE kind = 'weekly' DO NOTHING
               RETURNING id""",
            workspace,
            kind,
            start,
            end,
        )
    if row_id is None:
        return None
    try:
        r, text, html = await build_digest(pool, days=days, end=end)
        event = digest_event(r, text, html, workspace=workspace, tenant_id=tenant_id)
        status, detail = await emit_digest(pool, event)
        event_id = event.id
        summary = {"highlights": r.highlights, "metrics": _metrics(r)}
    except Exception as exc:  # noqa: BLE001
        logger.exception("digest_build_failed", extra={"workspace": workspace})
        status, detail, event_id, summary = "emit_failed", f"build failed: {exc}"[:500], None, {}
    async with pool.acquire() as con:
        await con.execute(
            """UPDATE report_digests SET status = $2, detail = $3, event_id = $4, summary = $5::jsonb
                WHERE id = $1""",
            row_id,
            status,
            detail,
            event_id,
            json.dumps(summary, default=str),
        )
    return DigestRunOut(
        id=row_id,
        workspace=workspace,
        status=status,
        event_id=event_id,
        detail=detail,
        period_start=start,
        period_end=end,
    )


async def run_due_digests(pool, now: datetime | None = None) -> list[DigestRunOut]:
    """Scheduler hook: send this week's digest for every workspace, once."""
    if not report_settings.digest_enabled:
        return []
    now = now or datetime.now(timezone.utc)
    slot = current_slot(now)
    if now - slot > STALE_SLOT:
        return []
    out: list[DigestRunOut] = []
    for ws, tenant in await list_workspaces(pool):
        try:
            res = await send_digest(pool, workspace=ws, tenant_id=tenant, kind="weekly", slot=slot)
            if res is not None:
                out.append(res)
        except Exception:  # noqa: BLE001 -- one workspace never blocks the rest
            logger.exception("digest_failed", extra={"workspace": ws})
    return out
