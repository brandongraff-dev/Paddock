"""Report data layer: every metric a report needs, for one time window.

Pure SQL + Python. All finding-based metrics run against ONE temporary table
(`_rpt_fl`) built in a single pass over `findings`, holding only the findings
that were open at some point in the window (or the comparison window before
it). Every later aggregate reads that small table, so a 30-day report over a
million findings costs one indexed scan, not ten.

Definitions (also in docs/REPORTS.md):

* **closed_at** -- when a finding left open/triaged: `finding_resolutions`
  (trigger-maintained, schema 023), else the ticket's `closed_at`, else the
  finding's `last_seen` (best effort for rows closed before 023).
* **open at T** -- `first_seen < T AND (closed_at IS NULL OR closed_at >= T)`.
  Time-aware, so a historical report is not skewed by what happened later.
* **exposure index** -- Σ over open findings of the severity weight
  (critical 10, high 5, medium 2, low 1, info 0); same formula the Overview
  page shows. The trend is `start` plus one point per day of the window.
* **verified fix** -- the asset was re-observed more than 60s after the fix and
  the finding was not, OR a safe-check re-verification (schema 026,
  ``findings.fix_verified_at``) could not reproduce it after the fix;
  **regressed** -- the finding was re-observed after it.
* **SLA due** -- the ticket's `sla_due`, else `first_seen + sla_policies.hours`.
  *met/late*: fixed in the window before/after due; *breached_open*: still
  open at the window end with its due time inside the window. Compliance =
  met / (met + late + breached_open).
* **MTTR** -- `closed_at - first_seen` over findings FIXED in the window.

ABAC: the caller's clearance rank is pushed into every query (finding AND
asset classification), so over-classified rows never leave Postgres.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

from ..auth import CLASSIFICATIONS, classification_rank_sql
from .config import report_settings
from .models import (
    SEVERITIES,
    AttackPaths,
    ChangeBrief,
    ChangeRow,
    Coverage,
    CoverageKind,
    DeviceRuleRow,
    Devices,
    ExposureTrend,
    FindingBrief,
    Mttr,
    MttrRow,
    NewFindings,
    PathBrief,
    ReportData,
    Resolutions,
    RiskyAsset,
    Sla,
    SlaBreach,
    SlaRow,
    SurfaceChanges,
    TrendPoint,
    Window,
)

SEV_WEIGHT: dict[str, int] = {"critical": 10, "high": 5, "medium": 2, "low": 1, "info": 0}
_W_SQL = (
    "CASE f.severity WHEN 'critical' THEN 10 WHEN 'high' THEN 5 "
    "WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END"
)
_SEV_RANK_SQL = (
    "CASE {c} WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 "
    "WHEN 'low' THEN 1 ELSE 0 END"
)

# Paddock Sentry behaviour detectors + the OT exposure policies (docs/SENTRY.md).
# "Reporting" (compliance internal_visibility, executive coverage) means an agent that CAN and DOES send signed
# evidence inside the window: not revoked, not a v1 (legacy) row, online, an ACTIVE key that has signed at least one
# accepted envelope (``last_seq > 0``; enrollment and re-keying set ``last_seen`` without any signature), and a
# signed posture or heartbeat inside the window. ``{win}`` is a SQL timestamp expression. Enrolled is not reporting.
REPORTING_AGENT_SQL = (
    "(a.status <> 'revoked' AND a.legacy = FALSE AND a.online = TRUE "
    "AND EXISTS (SELECT 1 FROM fleet_agent_keys k WHERE k.agent_id = a.id AND k.status = 'active' "
    "AND k.last_seq > 0) "
    "AND (a.last_posture_at >= {win} OR a.last_seen >= {win}))"
)

SENTRY_RULES: dict[str, str] = {
    "device_lateral_scan": "Device scanning laterally",
    "ot_internet_egress": "OT device reaching the internet",
    "iot_crosses_segment": "IoT device crossing segments",
    "cleartext_management": "Cleartext device management",
    "behavior_drift": "Behaviour drift from model baseline",
    "ot_it_exposure": "OT not isolated from IT",
    "ot_public_exposure": "OT on a public address",
}

VERIFY_GRACE = timedelta(seconds=60)

_PERIOD_RE = re.compile(r"^\s*(\d{1,3})\s*([dw]?)\s*$", re.IGNORECASE)


def parse_period(period: str | int | None, default: int = 30) -> int:
    """'7d' / '30d' / '2w' / 14 -> number of days (1..366)."""
    if period is None or period == "":
        return default
    if isinstance(period, int):
        days = period
    else:
        m = _PERIOD_RE.match(period)
        if not m:
            raise ValueError(f"bad period {period!r}: use e.g. 7d, 30d, 12w")
        days = int(m.group(1)) * (7 if m.group(2).lower() == "w" else 1)
    if not 1 <= days <= 366:
        raise ValueError("period must be between 1 and 366 days")
    return days


def make_window(days: int, end: datetime | None = None) -> Window:
    end = end or datetime.now(timezone.utc)
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    start = end - timedelta(days=days)
    s, e = start.date(), end.date()
    label = f"{s:%-d %b} – {e:%-d %b %Y}" if s.year == e.year else f"{s:%-d %b %Y} – {e:%-d %b %Y}"
    return Window(
        start=start, end=end, days=days, prev_start=start - timedelta(days=days), label=label
    )


def clearance_rank_of(clearance: str) -> int:
    return CLASSIFICATIONS.index(clearance) if clearance in CLASSIFICATIONS else 1


def _abac(col: str) -> str:
    return f"{classification_rank_sql(col)}"


def _sev_zero() -> dict[str, int]:
    return {s: 0 for s in SEVERITIES}


def _hours(x: Any) -> float:
    return round(float(x or 0.0), 2)


def _pct(num: int, den: int) -> float | None:
    return round(100.0 * num / den, 1) if den else None


# --------------------------------------------------------------------------- #
# The working set
# --------------------------------------------------------------------------- #

_FL_SQL = f"""
CREATE TEMP TABLE _rpt_fl ON COMMIT DROP AS
SELECT x.*, CASE WHEN x.closed_raw IS NOT NULL THEN GREATEST(x.closed_raw, x.first_seen) END AS closed_at
  FROM (
    SELECT f.id, f.asset_id, f.severity, f.status, f.title, f.rule_id, f.rule_source,
           f.first_seen, f.last_seen, f.fix_verified_at,
           CASE WHEN f.status IN ('open', 'triaged') THEN NULL
                ELSE COALESCE(r.resolved_at, t.closed_at, f.last_seen) END AS closed_raw,
           COALESCE(NULLIF(t.owner_team, ''), NULLIF(f.assigned_to, ''), 'Unassigned') AS team,
           t.sla_due,
           a.value AS asset_value, a.kind AS asset_kind, a.last_seen AS asset_last_seen,
           {_W_SQL} AS w,
           {_SEV_RANK_SQL.format(c="f.severity")} AS sev_rank
      FROM findings f
      JOIN assets a ON a.id = f.asset_id
      LEFT JOIN finding_resolutions r ON r.finding_id = f.id
      LEFT JOIN tickets t ON t.finding_id = f.id
     WHERE {_abac("f.classification")} <= $3
       AND {_abac("a.classification")} <= $3
       AND f.first_seen < $2
       AND (f.status IN ('open', 'triaged')
            OR COALESCE(r.resolved_at, t.closed_at, f.last_seen) >= $1)
  ) x
"""


def _open_at(p: str) -> str:
    return f"(closed_at IS NULL OR closed_at >= {p})"


_OPEN_END = _open_at("$2")


def _brief(r) -> FindingBrief:
    return FindingBrief(
        id=r["id"],
        title=r["title"],
        severity=r["severity"],
        status=r["status"],
        rule_id=r["rule_id"],
        rule_source=r["rule_source"],
        asset_value=r["asset_value"],
        asset_kind=r["asset_kind"],
        first_seen=r["first_seen"],
        team=r["team"],
    )


async def _exposure(con, w: Window) -> ExposureTrend:
    base = await con.fetchrow(
        """
        SELECT COALESCE(SUM(w) FILTER (WHERE first_seen < $1
                         AND (closed_at IS NULL OR closed_at >= $1)), 0) AS start_v,
               COALESCE(SUM(w) FILTER (WHERE closed_at IS NULL OR closed_at >= $2), 0) AS end_v
          FROM _rpt_fl
        """,
        w.start,
        w.end,
    )
    deltas = await con.fetch(
        """
        SELECT d, SUM(dw)::bigint AS dw FROM (
          SELECT floor(extract(epoch FROM first_seen - $1::timestamptz) / 86400)::int AS d, w AS dw
            FROM _rpt_fl WHERE first_seen >= $1 AND first_seen < $2
          UNION ALL
          SELECT floor(extract(epoch FROM closed_at - $1::timestamptz) / 86400)::int, -w
            FROM _rpt_fl WHERE closed_at >= $1 AND closed_at < $2
        ) x GROUP BY d
        """,
        w.start,
        w.end,
    )
    by_day = {int(r["d"]): int(r["dw"]) for r in deltas}
    v = int(base["start_v"])
    points = [TrendPoint(at=w.start, value=v)]
    for i in range(w.days):
        v += by_day.get(i, 0)
        points.append(TrendPoint(at=w.start + timedelta(days=i + 1), value=v))
    end_v = int(base["end_v"])
    sev = await con.fetch(
        f"""
        SELECT severity,
               COUNT(*) FILTER (WHERE first_seen < $1 AND (closed_at IS NULL OR closed_at >= $1)) AS s,
               COUNT(*) FILTER (WHERE {_OPEN_END}) AS e
          FROM _rpt_fl GROUP BY severity
        """,
        w.start,
        w.end,
    )
    open_start, open_end = _sev_zero(), _sev_zero()
    for r in sev:
        open_start[r["severity"]] = int(r["s"])
        open_end[r["severity"]] = int(r["e"])
    start_v = points[0].value
    return ExposureTrend(
        points=points,
        start_value=start_v,
        end_value=end_v,
        delta=end_v - start_v,
        delta_pct=_pct(end_v - start_v, start_v),
        open_start=open_start,
        open_end=open_end,
    )


async def _new_findings(con, w: Window, top: int) -> NewFindings:
    rows = await con.fetch(
        """
        SELECT severity,
               COUNT(*) FILTER (WHERE first_seen >= $1) AS cur,
               COUNT(*) FILTER (WHERE first_seen >= $2 AND first_seen < $1) AS prev
          FROM _rpt_fl GROUP BY severity
        """,
        w.start,
        w.prev_start,
    )
    cur, prev = _sev_zero(), _sev_zero()
    for r in rows:
        cur[r["severity"]] = int(r["cur"])
        prev[r["severity"]] = int(r["prev"])
    tops = await con.fetch(
        """
        SELECT * FROM _rpt_fl
         WHERE first_seen >= $1 AND severity IN ('critical', 'high')
         ORDER BY sev_rank DESC, first_seen DESC, id LIMIT $2
        """,
        w.start,
        top,
    )
    return NewFindings(
        by_severity=cur,
        previous_by_severity=prev,
        critical=cur["critical"],
        high=cur["high"],
        previous_critical_high=prev["critical"] + prev["high"],
        top=[_brief(r) for r in tops],
    )


async def _resolutions(con, w: Window) -> Resolutions:
    rows = await con.fetch(
        """
        SELECT status, severity, COUNT(*) AS n,
               COUNT(*) FILTER (WHERE last_seen > closed_at + $3) AS regressed,
               COUNT(*) FILTER (WHERE last_seen <= closed_at + $3
                                  AND (asset_last_seen > closed_at + $3
                                       OR fix_verified_at >= closed_at)) AS verified
          FROM _rpt_fl
         WHERE closed_at >= $1 AND closed_at < $2
         GROUP BY status, severity
        """,
        w.start,
        w.end,
        VERIFY_GRACE,
    )
    agg: dict[str, int] = {}
    fixed_sev = _sev_zero()
    verified = regressed = 0
    for r in rows:
        agg[r["status"]] = agg.get(r["status"], 0) + int(r["n"])
        if r["status"] == "fixed":
            fixed_sev[r["severity"]] += int(r["n"])
            verified += int(r["verified"])
            regressed += int(r["regressed"])
    fixed = agg.get("fixed", 0)
    return Resolutions(
        fixed=fixed,
        verified=verified,
        regressed=regressed,
        pending_verification=fixed - verified - regressed,
        accepted_risk=agg.get("accepted_risk", 0),
        false_positive=agg.get("false_positive", 0),
        wontfix=agg.get("wontfix", 0),
        fixed_by_severity=fixed_sev,
    )


_MTTR_COLS = """
    COUNT(*) AS n,
    AVG(extract(epoch FROM closed_at - first_seen)) / 3600.0 AS mean_h,
    percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM closed_at - first_seen)) / 3600.0 AS med_h,
    COUNT(*) FILTER (WHERE severity IN ('critical', 'high')) AS ch
"""
_FIXED_IN = "status = 'fixed' AND closed_at >= $1 AND closed_at < $2"


def _mttr_row(key: str, r) -> MttrRow:
    return MttrRow(
        key=key,
        count=int(r["n"]),
        mean_hours=_hours(r["mean_h"]),
        median_hours=_hours(r["med_h"]),
        critical_high=int(r["ch"]),
    )


async def _mttr(con, w: Window) -> Mttr:
    overall = await con.fetchrow(
        f"SELECT {_MTTR_COLS} FROM _rpt_fl WHERE {_FIXED_IN}", w.start, w.end
    )
    by_sev = await con.fetch(
        f"SELECT severity AS k, {_MTTR_COLS} FROM _rpt_fl WHERE {_FIXED_IN} GROUP BY severity",
        w.start,
        w.end,
    )
    by_team = await con.fetch(
        f"""SELECT team AS k, {_MTTR_COLS} FROM _rpt_fl WHERE {_FIXED_IN}
             GROUP BY team ORDER BY COUNT(*) DESC, team LIMIT 25""",
        w.start,
        w.end,
    )
    order = {s: i for i, s in enumerate(SEVERITIES)}
    sev_rows = sorted((_mttr_row(r["k"], r) for r in by_sev), key=lambda m: order.get(m.key, 9))
    return Mttr(
        overall=_mttr_row("all", overall) if overall and int(overall["n"]) else None,
        by_severity=sev_rows,
        by_team=[_mttr_row(r["k"], r) for r in by_team],
    )


_SLA_CTE = """
WITH s AS (
  SELECT fl.*, p.hours AS policy_hours,
         COALESCE(fl.sla_due,
                  CASE WHEN p.hours > 0 THEN fl.first_seen + make_interval(hours => p.hours) END) AS due_at
    FROM _rpt_fl fl LEFT JOIN sla_policies p ON p.severity = fl.severity
)
"""


async def _sla(con, w: Window, top: int) -> Sla:
    rows = await con.fetch(
        _SLA_CTE
        + f"""
        SELECT severity, MAX(policy_hours) AS policy_hours,
          COUNT(*) FILTER (WHERE {_FIXED_IN} AND closed_at <= due_at) AS met,
          COUNT(*) FILTER (WHERE {_FIXED_IN} AND closed_at > due_at) AS late,
          COUNT(*) FILTER (WHERE {_OPEN_END} AND due_at >= $1 AND due_at < $2) AS breached_open,
          COUNT(*) FILTER (WHERE {_OPEN_END} AND due_at < $2) AS overdue_end,
          COUNT(*) FILTER (WHERE {_OPEN_END} AND due_at >= $2) AS open_within
          FROM s WHERE due_at IS NOT NULL GROUP BY severity
        """,
        w.start,
        w.end,
    )
    order = {s: i for i, s in enumerate(SEVERITIES)}
    out: list[SlaRow] = []
    met = late = bo = od = 0
    for r in sorted(rows, key=lambda r: order.get(r["severity"], 9)):
        m, lt, b = int(r["met"]), int(r["late"]), int(r["breached_open"])
        met, late, bo, od = met + m, late + lt, bo + b, od + int(r["overdue_end"])
        out.append(
            SlaRow(
                severity=r["severity"],
                policy_hours=r["policy_hours"],
                met=m,
                late=lt,
                breached_open=b,
                overdue_end=int(r["overdue_end"]),
                open_within_sla=int(r["open_within"]),
                compliance_pct=_pct(m, m + lt + b),
            )
        )
    breaches = await con.fetch(
        _SLA_CTE
        + f"""
        SELECT id, title, severity, asset_value, team, due_at,
               extract(epoch FROM $1::timestamptz - due_at) / 3600.0 AS over_h
          FROM s WHERE {_open_at("$1")} AND due_at < $1
         ORDER BY sev_rank DESC, due_at ASC, id LIMIT $2
        """,
        w.end,
        top,
    )
    return Sla(
        met=met,
        late=late,
        breached_open=bo,
        overdue_end=od,
        compliance_pct=_pct(met, met + late + bo),
        by_severity=out,
        breaches=[
            SlaBreach(
                finding_id=r["id"],
                title=r["title"],
                severity=r["severity"],
                asset_value=r["asset_value"],
                team=r["team"],
                due_at=r["due_at"],
                overdue_hours=_hours(r["over_h"]),
            )
            for r in breaches
        ],
    )


def _path_abac(cr_param: str) -> str:
    return (
        "LEFT JOIN assets sa ON sa.id = l.source_asset_id "
        "LEFT JOIN assets ta ON ta.id = l.target_asset_id "
        f"WHERE (sa.id IS NULL OR {_abac('sa.classification')} <= {cr_param}) "
        f"AND (ta.id IS NULL OR {_abac('ta.classification')} <= {cr_param})"
    )


def _path(r) -> PathBrief:
    return PathBrief(
        fingerprint=r["fingerprint"],
        title=r["title"],
        severity=r["severity"],
        exploitability=float(r["exploitability"]) if r["exploitability"] is not None else None,
        kev_on_path=bool(r["kev_on_path"]),
        length=r["length"],
        opened_at=r["opened_at"],
        closed_at=r["closed_at"],
        open_days=round((r["closed_at"] - r["opened_at"]).total_seconds() / 86400, 1)
        if r["closed_at"]
        else None,
    )


async def _attack_paths(con, w: Window, cr: int, top: int) -> AttackPaths:
    j = _path_abac("$3")
    counts = await con.fetchrow(
        f"""
        SELECT COUNT(*) FILTER (WHERE l.opened_at >= $1 AND l.opened_at < $2) AS opened,
               COUNT(*) FILTER (WHERE l.closed_at >= $1 AND l.closed_at < $2) AS closed,
               COUNT(*) FILTER (WHERE l.opened_at < $1 AND (l.closed_at IS NULL OR l.closed_at >= $1)) AS o_s,
               COUNT(*) FILTER (WHERE l.opened_at < $2 AND (l.closed_at IS NULL OR l.closed_at >= $2)) AS o_e
          FROM attack_path_ledger l {j}
        """,
        w.start,
        w.end,
        cr,
    )
    order = (
        f"ORDER BY {_SEV_RANK_SQL.format(c='l.severity')} DESC, "
        "l.exploitability DESC NULLS LAST, l.id LIMIT $4"
    )
    cols = (
        "l.fingerprint, l.title, l.severity, l.exploitability, l.kev_on_path, l.length, l.opened_at"
    )
    opened = await con.fetch(
        f"SELECT {cols}, CASE WHEN l.closed_at < $2 THEN l.closed_at END AS closed_at "
        f"FROM attack_path_ledger l {j} AND l.opened_at >= $1 AND l.opened_at < $2 {order}",
        w.start,
        w.end,
        cr,
        top,
    )
    closed = await con.fetch(
        f"SELECT {cols}, l.closed_at FROM attack_path_ledger l {j} "
        f"AND l.closed_at >= $1 AND l.closed_at < $2 {order}",
        w.start,
        w.end,
        cr,
        top,
    )
    return AttackPaths(
        opened=int(counts["opened"]),
        closed=int(counts["closed"]),
        open_start=int(counts["o_s"]),
        open_end=int(counts["o_e"]),
        top_opened=[_path(r) for r in opened],
        top_closed=[_path(r) for r in closed],
    )


async def _risky_assets(con, w: Window, top: int) -> list[RiskyAsset]:
    rows = await con.fetch(
        f"""
        SELECT asset_id, asset_value, asset_kind, SUM(w)::int AS score, COUNT(*) AS n,
               COUNT(*) FILTER (WHERE severity = 'critical') AS c,
               COUNT(*) FILTER (WHERE severity = 'high') AS h
          FROM _rpt_fl WHERE {_open_at("$1")}
         GROUP BY asset_id, asset_value, asset_kind
        HAVING SUM(w) > 0
         ORDER BY SUM(w) DESC, COUNT(*) DESC, asset_value LIMIT $2
        """,
        w.end,
        top,
    )
    return [
        RiskyAsset(
            asset_id=r["asset_id"],
            value=r["asset_value"],
            kind=r["asset_kind"],
            score=int(r["score"]),
            open_findings=int(r["n"]),
            critical=int(r["c"]),
            high=int(r["h"]),
        )
        for r in rows
    ]


async def _changes(con, w: Window, cr: int, top: int) -> SurfaceChanges:
    j = (
        "FROM surface_changes c LEFT JOIN assets a ON a.id = c.asset_id "
        f"WHERE c.detected_at >= $1 AND c.detected_at < $2 "
        f"AND (a.id IS NULL OR {_abac('a.classification')} <= $3)"
    )
    by_type = await con.fetch(
        f"SELECT c.change_type, COUNT(*) AS n {j} GROUP BY 1 ORDER BY 2 DESC, 1", w.start, w.end, cr
    )
    notable = await con.fetch(
        f"""SELECT c.change_type, c.severity, c.summary, c.asset_value, c.detected_at {j}
              AND c.severity IN ('critical', 'high', 'medium')
            ORDER BY {_SEV_RANK_SQL.format(c="c.severity")} DESC, c.detected_at DESC LIMIT $4""",
        w.start,
        w.end,
        cr,
        top,
    )
    new_assets = await con.fetch(
        f"""SELECT kind, COUNT(*) AS n FROM assets a
             WHERE a.first_seen >= $1 AND a.first_seen < $2 AND {_abac("a.classification")} <= $3
             GROUP BY kind ORDER BY 2 DESC, 1""",
        w.start,
        w.end,
        cr,
    )
    rows = [ChangeRow(change_type=r["change_type"], count=int(r["n"])) for r in by_type]
    return SurfaceChanges(
        total=sum(r.count for r in rows),
        by_type=rows,
        new_assets_by_kind={r["kind"]: int(r["n"]) for r in new_assets},
        notable=[
            ChangeBrief(
                change_type=r["change_type"],
                severity=r["severity"],
                summary=r["summary"],
                asset_value=r["asset_value"],
                detected_at=r["detected_at"],
            )
            for r in notable
        ],
    )


async def _devices(con, w: Window, cr: int, top: int) -> Devices:
    ab = f"{_abac('a.classification')} <= $3"
    kinds = await con.fetch(
        f"""SELECT kind, COUNT(*) AS total,
                   COUNT(*) FILTER (WHERE first_seen >= $1) AS new
              FROM assets a WHERE kind IN ('iot_device', 'ot_device', 'network_segment')
               AND first_seen < $2 AND {ab} GROUP BY kind""",
        w.start,
        w.end,
        cr,
    )
    k = {r["kind"]: r for r in kinds}
    edges = await con.fetchval(
        f"""SELECT COUNT(*) FROM asset_edges e
              JOIN assets a ON a.id = e.src_id JOIN assets b ON b.id = e.dst_id
             WHERE e.kind = 'can_reach_observed' AND e.first_seen < $1
               AND {_abac("a.classification")} <= $2
               AND {_abac("b.classification")} <= $2""",
        w.end,
        cr,
    )
    rules = list(SENTRY_RULES)
    beh = await con.fetch(
        f"""SELECT rule_id, COUNT(*) FILTER (WHERE first_seen >= $1) AS opened,
                   COUNT(*) FILTER (WHERE {_OPEN_END}) AS open_end
              FROM _rpt_fl WHERE rule_id = ANY($3::text[]) GROUP BY rule_id""",
        w.start,
        w.end,
        rules,
    )
    b = {r["rule_id"]: r for r in beh}
    tops = await con.fetch(
        """SELECT * FROM _rpt_fl WHERE rule_id = ANY($2::text[]) AND first_seen >= $1
            ORDER BY sev_rank DESC, first_seen DESC, id LIMIT $3""",
        w.start,
        rules,
        top,
    )

    def n(kind: str, col: str) -> int:
        return int(k[kind][col]) if kind in k else 0

    return Devices(
        iot_total=n("iot_device", "total"),
        ot_total=n("ot_device", "total"),
        new_devices=n("iot_device", "new") + n("ot_device", "new"),
        segments=n("network_segment", "total"),
        observed_reachability=int(edges or 0),
        behaviour=[
            DeviceRuleRow(
                rule_id=r,
                label=SENTRY_RULES[r],
                opened=int(b[r]["opened"]) if r in b else 0,
                open_end=int(b[r]["open_end"]) if r in b else 0,
            )
            for r in rules
        ],
        top=[_brief(r) for r in tops],
    )


async def _coverage(con, w: Window, cr: int) -> Coverage:
    kinds = await con.fetch(
        f"""SELECT kind, COUNT(*) AS total,
                   COUNT(*) FILTER (WHERE last_seen >= $1::timestamptz - interval '1 day') AS d1,
                   COUNT(*) FILTER (WHERE last_seen >= $1::timestamptz - interval '7 days') AS d7,
                   COUNT(*) FILTER (WHERE last_seen >= $1::timestamptz - interval '30 days') AS d30
              FROM assets a WHERE first_seen < $1 AND {_abac("a.classification")} <= $2
             GROUP BY kind ORDER BY 2 DESC, 1""",
        w.end,
        cr,
    )
    scans = await con.fetch(
        "SELECT status, COUNT(*) AS n FROM scans WHERE queued_at >= $1 AND queued_at < $2 GROUP BY 1",
        w.start,
        w.end,
    )
    last_scan = await con.fetchval(
        "SELECT MAX(finished_at) FROM scans WHERE status = 'completed' AND finished_at < $1", w.end
    )
    sbom = await con.fetchrow(
        """SELECT (SELECT COUNT(*) FROM sca_projects) AS p,
                  (SELECT COUNT(*) FROM sbom_components) AS c,
                  (SELECT MAX(last_scanned) FROM sca_projects WHERE last_scanned < $1) AS last""",
        w.end,
    )
    tls = await con.fetchrow(
        "SELECT COUNT(*) AS n, COUNT(*) FILTER (WHERE grade NOT IN ('A+','A','B')) AS bad FROM tls_grades"
    )
    reporting = REPORTING_AGENT_SQL.format(win="($1::timestamptz - interval '1 day')")
    fleet = await con.fetchrow(
        f"""SELECT COUNT(*) FILTER (WHERE a.status <> 'revoked') AS n,
                   COUNT(*) FILTER (WHERE {reporting}) AS recent
              FROM fleet_agents a""",
        w.end,
    )
    rows = [
        CoverageKind(
            kind=r["kind"],
            total=int(r["total"]),
            seen_24h=int(r["d1"]),
            seen_7d=int(r["d7"]),
            seen_30d=int(r["d30"]),
            stale=int(r["total"]) - int(r["d30"]),
        )
        for r in kinds
    ]
    return Coverage(
        assets_total=sum(r.total for r in rows),
        by_kind=rows,
        scans_by_status={r["status"]: int(r["n"]) for r in scans},
        last_completed_scan=last_scan,
        sbom_projects=int(sbom["p"]),
        sbom_components=int(sbom["c"]),
        sbom_last_scanned=sbom["last"],
        tls_graded=int(tls["n"]),
        tls_below_b=int(tls["bad"]),
        fleet_agents=int(fleet["n"]),
        fleet_agents_recent=int(fleet["recent"]),
    )


# --------------------------------------------------------------------------- #
# Plain-English highlights (digest + exec summary)
# --------------------------------------------------------------------------- #


def _fmt_h(h: float) -> str:
    if h < 1:
        return f"{round(h * 60)}m"
    if h < 48:
        return f"{h:.1f}h".replace(".0h", "h")
    return f"{h / 24:.1f}d".replace(".0d", "d")


def fmt_hours(h: float | None) -> str:
    return "—" if h is None else _fmt_h(h)


def highlights(d: dict[str, Any]) -> list[str]:
    """A few sentences a busy reader can act on. Pure; takes model_dump()s."""
    out: list[str] = []
    ex = d["exposure"]
    if ex["start_value"] or ex["end_value"]:
        if ex["delta"] < 0:
            pct = f" {abs(ex['delta_pct']):.0f}%" if ex["delta_pct"] is not None else ""
            out.append(f"Exposure fell{pct}, from {ex['start_value']} to {ex['end_value']}.")
        elif ex["delta"] > 0:
            pct = f" {ex['delta_pct']:.0f}%" if ex["delta_pct"] is not None else ""
            out.append(f"Exposure rose{pct}, from {ex['start_value']} to {ex['end_value']}.")
        else:
            out.append(f"Exposure held steady at {ex['end_value']}.")
    nf = d["new_findings"]
    if nf["critical"] or nf["high"]:
        out.append(
            f"{nf['critical']} new critical and {nf['high']} new high findings "
            f"(previous period: {nf['previous_critical_high']})."
        )
    else:
        out.append("No new critical or high findings.")
    rs = d["resolutions"]
    if rs["fixed"]:
        s = f"{rs['fixed']} fixed, {rs['verified']} verified by a later scan"
        if rs["regressed"]:
            s += f", {rs['regressed']} came back"
        out.append(s + ".")
    mt = d["mttr"]
    crit = next((m for m in mt["by_severity"] if m["key"] == "critical"), None)
    if crit:
        out.append(f"Criticals were fixed in {fmt_hours(crit['median_hours'])} (median).")
    sla = d["sla"]
    if sla["compliance_pct"] is not None:
        b = sla["late"] + sla["breached_open"]
        out.append(
            f"SLA compliance {sla['compliance_pct']:.0f}%"
            + (f" with {b} breach{'es' if b != 1 else ''}." if b else ", no breaches.")
        )
    ap = d["attack_paths"]
    if ap["opened"] or ap["closed"]:
        out.append(
            f"{ap['closed']} attack path{'s' if ap['closed'] != 1 else ''} to crown jewels closed, "
            f"{ap['opened']} opened; {ap['open_end']} remain."
        )
    dv = d["devices"]
    beh = sum(r["opened"] for r in dv["behaviour"])
    if beh:
        out.append(f"Sentry flagged {beh} device behaviour finding{'s' if beh != 1 else ''}.")
    return out


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


async def build_report(
    pool,
    *,
    days: int = 30,
    end: datetime | None = None,
    clearance: str = "internal",
    top: int = 10,
    org_name: str | None = None,
) -> ReportData:
    """Compute every report metric for the `days` ending at `end` (default now)."""
    w = make_window(days, end)
    cr = clearance_rank_of(clearance)
    async with pool.acquire() as con:
        async with con.transaction():
            await con.execute(_FL_SQL, w.prev_start, w.end, cr)
            await con.execute("ANALYZE _rpt_fl")
            exposure = await _exposure(con, w)
            new = await _new_findings(con, w, top)
            res = await _resolutions(con, w)
            mttr = await _mttr(con, w)
            sla = await _sla(con, w, top)
            paths = await _attack_paths(con, w, cr, top)
            risky = await _risky_assets(con, w, top)
            changes = await _changes(con, w, cr, top)
            devices = await _devices(con, w, cr, top)
            coverage = await _coverage(con, w, cr)
    data = dict(
        generated_at=datetime.now(timezone.utc),
        org_name=org_name or report_settings.org_name,
        clearance=clearance,
        window=w,
        highlights=[],
        exposure=exposure,
        new_findings=new,
        resolutions=res,
        mttr=mttr,
        sla=sla,
        attack_paths=paths,
        risky_assets=risky,
        changes=changes,
        devices=devices,
        coverage=coverage,
    )
    report = ReportData(**data)
    report.highlights = highlights(report.model_dump())
    return report
