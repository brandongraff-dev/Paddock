"""Compliance evidence packs.

A control catalogue (``controls/<framework>.json``) lists controls and, for
each, the Paddock *evidence keys* that bear on it. This module computes every
evidence key once (SQL over the live data, ABAC-filtered by the caller's
clearance) and folds the results into a per-control status:

* ``requires_attestation`` -- a manual control (policy, process, people).
  Paddock never claims these.
* ``satisfied`` -- every evidence item passes. Capped at ``partial`` when the
  catalogue says Paddock can only ever partially evidence the control
  (``max_status: "partial"``), e.g. a PCI segmentation *penetration test*
  that Sentry's observed segmentation map supports but does not replace.
* ``partial`` -- some evidence passes or is incomplete.
* ``gap`` -- no supporting evidence in Paddock, or the evidence shows a
  failure (e.g. open segmentation violations). A gap is a gap *in evidence*;
  it is not an auditor's finding of non-compliance.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Awaitable, Callable

from .. import audit
from ..auth import classification_rank_sql
from .config import report_settings
from .metrics import REPORTING_AGENT_SQL, SENTRY_RULES, build_report, clearance_rank_of
from .models import (
    CompliancePack,
    ControlOut,
    EvidenceOut,
    FrameworkSummary,
    ReportData,
)

CONTROLS_DIR = Path(__file__).resolve().parent / "controls"
STATUSES = ("satisfied", "partial", "gap", "requires_attestation")

SEGMENTATION_RULES = (
    "ot_it_exposure",
    "ot_public_exposure",
    "iot_crosses_segment",
    "ot_internet_egress",
    "device_lateral_scan",
)
EXPOSURE_SOURCES = ("exposed_file", "takeover")
EXPOSURE_RULES = ("no_public_dev", "ot_public_exposure")
CONFIG_SOURCES = ("header_check", "tls_check", "tls_grade", "policy")

DISCLAIMER = (
    "This pack maps evidence Paddock observes to the framework's controls. It "
    "supports, and does not replace, an assessment by a qualified assessor. "
    "'Gap' means Paddock holds no supporting evidence, not that the control is "
    "absent. Controls marked 'requires attestation' are organisational and "
    "must be evidenced outside Paddock. Control titles are paraphrased; refer "
    "to the official publication for normative text."
)


def _abac(col: str) -> str:
    return classification_rank_sql(col)


# --------------------------------------------------------------------------- #
# Catalogues
# --------------------------------------------------------------------------- #


@lru_cache(maxsize=None)
def load_catalogue(framework: str) -> dict[str, Any]:
    p = CONTROLS_DIR / f"{framework}.json"
    if not p.is_file() or p.parent != CONTROLS_DIR:
        raise KeyError(framework)
    return json.loads(p.read_text())


def framework_ids() -> list[str]:
    return sorted(p.stem for p in CONTROLS_DIR.glob("*.json"))


# --------------------------------------------------------------------------- #
# Evidence providers
# --------------------------------------------------------------------------- #


@dataclass
class Ctx:
    pool: Any
    now: datetime
    cr: int
    clearance: str
    fresh: timedelta
    _report: ReportData | None = None
    cache: dict[str, EvidenceOut] = field(default_factory=dict)

    async def report90(self) -> ReportData:
        if self._report is None:
            self._report = await build_report(
                self.pool, days=90, end=self.now, clearance=self.clearance
            )
        return self._report


Provider = Callable[[Any, Ctx], Awaitable[EvidenceOut]]
PROVIDERS: dict[str, tuple[str, Provider]] = {}


def provider(key: str, title: str):
    def deco(fn: Provider) -> Provider:
        PROVIDERS[key] = (title, fn)
        return fn

    return deco


def _ev(
    key: str, status: str, detail: str, metrics: dict | None = None, rows: list | None = None
) -> EvidenceOut:
    return EvidenceOut(
        key=key,
        title=PROVIDERS[key][0],
        status=status,
        detail=detail,
        metrics=metrics or {},
        rows=rows or [],
    )


def _iso(v: datetime | None) -> str | None:
    return v.isoformat() if v else None


async def _open_findings(con, ctx: Ctx, where: str, *args) -> list:
    n = len(args)
    return await con.fetch(
        f"""SELECT f.id, f.rule_id, f.rule_source, f.severity, f.title, a.value AS asset, f.first_seen
              FROM findings f JOIN assets a ON a.id = f.asset_id
             WHERE f.status IN ('open', 'triaged') AND ({where})
               AND {_abac("f.classification")} <= ${n + 1} AND {_abac("a.classification")} <= ${n + 1}
             ORDER BY CASE f.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2
                      WHEN 'low' THEN 1 ELSE 0 END DESC, f.first_seen
             LIMIT 200""",
        *args,
        ctx.cr,
    )


def _frows(rows, limit: int = 15) -> list[dict[str, Any]]:
    return [
        {
            "severity": r["severity"],
            "title": r["title"],
            "asset": r["asset"],
            "rule_id": r["rule_id"],
            "first_seen": _iso(r["first_seen"]),
        }
        for r in rows[:limit]
    ]


@provider("asset_inventory", "Asset inventory")
async def _asset_inventory(con, ctx: Ctx) -> EvidenceOut:
    rows = await con.fetch(
        f"""SELECT kind, COUNT(*) AS n, COUNT(*) FILTER (WHERE last_seen >= $1) AS fresh
              FROM assets a WHERE {_abac("a.classification")} <= $2
               AND kind NOT IN ('iot_device', 'ot_device', 'network_segment')
             GROUP BY kind ORDER BY 2 DESC""",
        ctx.now - ctx.fresh,
        ctx.cr,
    )
    total = sum(int(r["n"]) for r in rows)
    fresh = sum(int(r["fresh"]) for r in rows)
    out = [
        {"kind": r["kind"], "assets": int(r["n"]), "seen_recently": int(r["fresh"])} for r in rows
    ]
    if not total:
        return _ev("asset_inventory", "none", "No assets discovered yet.")
    pct = 100.0 * fresh / total
    st = "pass" if pct >= 80 else "partial"
    return _ev(
        "asset_inventory",
        st,
        f"{total} assets inventoried across {len(rows)} kinds; {pct:.0f}% observed in the last "
        f"{ctx.fresh.days} days.",
        {"assets": total, "fresh_pct": round(pct, 1)},
        out,
    )


@provider("device_inventory", "IoT/OT device inventory (Sentry)")
async def _device_inventory(con, ctx: Ctx) -> EvidenceOut:
    r = await con.fetchrow(
        f"""SELECT COUNT(*) AS n, COUNT(*) FILTER (WHERE kind = 'ot_device') AS ot,
                   COUNT(*) FILTER (WHERE metadata ? 'vendor' OR metadata ? 'model') AS fp,
                   MAX(last_seen) AS last
              FROM assets a WHERE kind IN ('iot_device', 'ot_device') AND {_abac("a.classification")} <= $1""",
        ctx.cr,
    )
    n = int(r["n"])
    if not n:
        return _ev("device_inventory", "none", "No devices reported by a Sentry sensor.")
    recent = r["last"] and r["last"] >= ctx.now - ctx.fresh
    byv = await con.fetch(
        f"""SELECT kind, COALESCE(metadata->>'vendor', 'unknown') AS vendor, COUNT(*) AS n
              FROM assets a WHERE kind IN ('iot_device', 'ot_device') AND {_abac("a.classification")} <= $1
             GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 15""",
        ctx.cr,
    )
    return _ev(
        "device_inventory",
        "pass" if recent else "partial",
        f"{n} devices ({int(r['ot'])} OT), {int(r['fp'])} fingerprinted; last observation "
        f"{r['last']:%Y-%m-%d}." + ("" if recent else " Sensor data is stale."),
        {
            "devices": n,
            "ot": int(r["ot"]),
            "fingerprinted": int(r["fp"]),
            "last_seen": _iso(r["last"]),
        },
        [{"kind": x["kind"], "vendor": x["vendor"], "devices": int(x["n"])} for x in byv],
    )


@provider("software_inventory", "Software bill of materials (SBOM)")
async def _software_inventory(con, ctx: Ctx) -> EvidenceOut:
    rows = await con.fetch(
        """SELECT p.name, p.last_scanned, p.ecosystems,
                  (SELECT COUNT(*) FROM sbom_components c WHERE c.project_id = p.id) AS n,
                  (SELECT COUNT(*) FROM sbom_components c WHERE c.project_id = p.id AND c.direct) AS direct
             FROM sca_projects p ORDER BY p.last_scanned DESC NULLS LAST LIMIT 50"""
    )
    comps = sum(int(r["n"]) for r in rows)
    if not comps:
        return _ev("software_inventory", "none", "No SBOM: no projects have been analysed.")
    stale = [r for r in rows if not r["last_scanned"] or r["last_scanned"] < ctx.now - ctx.fresh]
    return _ev(
        "software_inventory",
        "partial" if stale else "pass",
        f"{comps} components across {len(rows)} projects, machine-readable via /v1/sbom."
        + (f" {len(stale)} project(s) not re-analysed in {ctx.fresh.days} days." if stale else ""),
        {"projects": len(rows), "components": comps},
        [
            {
                "project": r["name"],
                "components": int(r["n"]),
                "direct": int(r["direct"]),
                "last_scanned": _iso(r["last_scanned"]),
            }
            for r in rows[:15]
        ],
    )


@provider("component_vulns", "Vulnerabilities in SBOM components")
async def _component_vulns(con, ctx: Ctx) -> EvidenceOut:
    comps = await con.fetchval("SELECT COUNT(*) FROM sbom_components")
    if not comps:
        return _ev("component_vulns", "none", "No SBOM to monitor.")
    rows = await con.fetch(
        """SELECT v.severity, COUNT(*) AS n FROM sbom_component_vulns v GROUP BY 1"""
    )
    by = {r["severity"]: int(r["n"]) for r in rows}
    top = await con.fetch(
        """SELECT v.osv_id, v.cve_id, v.severity, c.name, c.version, v.fixed_version
             FROM sbom_component_vulns v JOIN sbom_components c ON c.id = v.component_id
            WHERE v.severity IN ('critical', 'high') ORDER BY v.severity, c.name LIMIT 15"""
    )
    crit = by.get("critical", 0)
    st = "fail" if crit else "partial" if by.get("high", 0) else "pass"
    return _ev(
        "component_vulns",
        st,
        f"Components are matched against OSV continuously: {crit} critical, {by.get('high', 0)} high "
        "known vulnerabilities currently matched.",
        {"by_severity": by},
        [
            {
                "id": r["cve_id"] or r["osv_id"],
                "severity": r["severity"],
                "component": f"{r['name']}@{r['version']}",
                "fixed_in": r["fixed_version"],
            }
            for r in top
        ],
    )


async def _scan_state(con, ctx: Ctx):
    return await con.fetchrow(
        """SELECT MAX(finished_at) FILTER (WHERE status = 'completed') AS last,
                  COUNT(*) FILTER (WHERE status = 'completed' AND finished_at >= $1) AS n90,
                  COUNT(DISTINCT date_trunc('month', finished_at))
                       FILTER (WHERE status = 'completed' AND finished_at >= $1) AS months
             FROM scans""",
        ctx.now - timedelta(days=90),
    )


@provider("external_scanning", "External vulnerability scanning")
async def _external_scanning(con, ctx: Ctx) -> EvidenceOut:
    s = await _scan_state(con, ctx)
    if not s["last"]:
        return _ev("external_scanning", "none", "No completed scans on record.")
    rows = await con.fetch(
        """SELECT to_char(date_trunc('month', finished_at), 'YYYY-MM') AS month, kind, COUNT(*) AS n
             FROM scans WHERE status = 'completed' AND finished_at >= $1
            GROUP BY 1, 2 ORDER BY 1 DESC, 3 DESC LIMIT 24""",
        ctx.now - timedelta(days=90),
    )
    age = (ctx.now - s["last"]).days
    st = "pass" if age <= 31 and int(s["n90"]) else "partial" if age <= 92 else "fail"
    return _ev(
        "external_scanning",
        st,
        f"{int(s['n90'])} completed scans in the last 90 days; last completed {s['last']:%Y-%m-%d} "
        f"({age} days ago).",
        {"completed_90d": int(s["n90"]), "last_completed": _iso(s["last"])},
        [{"month": r["month"], "kind": r["kind"], "scans": int(r["n"])} for r in rows],
    )


@provider("internal_visibility", "Internal visibility (Sentry, fleet agents)")
async def _internal_visibility(con, ctx: Ctx) -> EvidenceOut:
    r = await con.fetchrow(
        f"""SELECT (SELECT COUNT(*) FROM fleet_agents a WHERE {REPORTING_AGENT_SQL.format(win='$1')}) AS agents,
                   (SELECT COUNT(*) FROM assets a WHERE kind IN ('iot_device','ot_device')
                       AND last_seen >= $1 AND {_abac("a.classification")} <= $2) AS devices,
                   (SELECT COUNT(*) FROM findings f JOIN assets a ON a.id = f.asset_id
                     WHERE f.rule_source = 'cve_match' AND a.kind IN ('iot_device','ot_device')
                       AND {_abac("a.classification")} <= $2) AS device_cves""",
        ctx.now - ctx.fresh,
        ctx.cr,
    )
    agents, devices = int(r["agents"]), int(r["devices"])
    if not (agents or devices):
        return _ev("internal_visibility", "none", "No fleet agents or Sentry sensors reporting.")
    return _ev(
        "internal_visibility",
        "partial",
        f"{agents} fleet agent(s) and {devices} passively observed device(s) reporting; "
        f"{int(r['device_cves'])} device CVE matches. Passive/inventory based: not an "
        "authenticated internal vulnerability scan.",
        {"agents": agents, "devices": devices, "device_cve_matches": int(r["device_cves"])},
    )


@provider("vuln_management", "Vulnerabilities identified and risk-ranked")
async def _vuln_management(con, ctx: Ctx) -> EvidenceOut:
    s = await _scan_state(con, ctx)
    rows = await con.fetch(
        f"""SELECT f.severity, COUNT(*) AS n FROM findings f JOIN assets a ON a.id = f.asset_id
             WHERE f.status IN ('open', 'triaged') AND {_abac("f.classification")} <= $1
               AND {_abac("a.classification")} <= $1 GROUP BY 1""",
        ctx.cr,
    )
    intel = await con.fetchrow(
        "SELECT COUNT(*) AS cves, COUNT(*) FILTER (WHERE known_exploited) AS kev, "
        "COUNT(*) FILTER (WHERE epss IS NOT NULL) AS epss FROM cves"
    )
    by = {r["severity"]: int(r["n"]) for r in rows}
    if not s["last"] and not by:
        return _ev("vuln_management", "none", "No scans or findings on record.")
    recent = s["last"] and s["last"] >= ctx.now - ctx.fresh
    return _ev(
        "vuln_management",
        "pass" if recent else "partial",
        f"Findings are severity-ranked and enriched with NVD/EPSS/CISA KEV ({int(intel['cves'])} CVEs, "
        f"{int(intel['kev'])} KEV). Open: "
        + ", ".join(f"{k} {v}" for k, v in sorted(by.items()))
        + "."
        + ("" if recent else " Scanning is not current."),
        {"open_by_severity": by, "cves": int(intel["cves"]), "kev": int(intel["kev"])},
    )


@provider("remediation_sla", "Remediation within SLA (90 days)")
async def _remediation_sla(con, ctx: Ctx) -> EvidenceOut:
    r = await ctx.report90()
    sla = r.sla
    if sla.compliance_pct is None:
        return _ev(
            "remediation_sla", "none", "No findings reached an SLA outcome in the last 90 days."
        )
    crit_over = next((s.overdue_end for s in sla.by_severity if s.severity == "critical"), 0)
    pct = sla.compliance_pct
    st = (
        "pass"
        if pct >= report_settings.sla_pass_pct and not crit_over
        else "partial"
        if pct >= 50
        else "fail"
    )
    return _ev(
        "remediation_sla",
        st,
        f"SLA compliance {pct:.0f}% over 90 days ({sla.met} met, {sla.late} fixed late, "
        f"{sla.breached_open} breached and open); {crit_over} critical overdue now. "
        f"Median time to fix {r.mttr.overall.median_hours if r.mttr.overall else 0:.0f}h.",
        {
            "compliance_pct": pct,
            "met": sla.met,
            "late": sla.late,
            "breached_open": sla.breached_open,
            "critical_overdue": crit_over,
        },
        [s.model_dump() for s in sla.by_severity],
    )


@provider("critical_overdue", "No critical vulnerabilities past SLA")
async def _critical_overdue(con, ctx: Ctx) -> EvidenceOut:
    r = await ctx.report90()
    rows = [b for b in r.sla.breaches if b.severity == "critical"]
    crit = next((s.overdue_end for s in r.sla.by_severity if s.severity == "critical"), 0)
    s = await _scan_state(con, ctx)
    if not s["last"] and not crit:
        return _ev("critical_overdue", "none", "No scanning on record to evidence this.")
    return _ev(
        "critical_overdue",
        "fail" if crit else "pass",
        f"{crit} critical finding(s) open past their SLA."
        if crit
        else "No open critical finding is past its SLA.",
        {"critical_overdue": crit},
        [
            {"title": b.title, "asset": b.asset_value, "overdue_hours": b.overdue_hours}
            for b in rows
        ],
    )


@provider("kev_open", "No open known-exploited (KEV) vulnerabilities")
async def _kev_open(con, ctx: Ctx) -> EvidenceOut:
    rows = await _open_findings(
        con,
        ctx,
        "COALESCE((f.metadata->>'kev')::boolean, FALSE) OR EXISTS (SELECT 1 FROM cves c "
        "WHERE c.id = f.rule_id AND c.known_exploited)",
    )
    s = await _scan_state(con, ctx)
    if not s["last"] and not rows:
        return _ev("kev_open", "none", "No scanning on record to evidence this.")
    return _ev(
        "kev_open",
        "fail" if rows else "pass",
        f"{len(rows)} open finding(s) on the CISA KEV list."
        if rows
        else "No open finding matches the CISA Known Exploited Vulnerabilities list.",
        {"open_kev": len(rows)},
        _frows(rows),
    )


@provider("segmentation_map", "Observed segmentation map (Sentry)")
async def _segmentation_map(con, ctx: Ctx) -> EvidenceOut:
    segs = await con.fetch(
        f"""SELECT a.value, a.last_seen FROM assets a WHERE kind = 'network_segment'
               AND {_abac("a.classification")} <= $1 ORDER BY a.value LIMIT 50""",
        ctx.cr,
    )
    if not segs:
        return _ev("segmentation_map", "none", "No network segments observed (no Sentry sensor).")
    edges = await con.fetch(
        f"""SELECT s.value AS src, d.value AS dst, e.last_seen, e.metadata
              FROM asset_edges e JOIN assets s ON s.id = e.src_id JOIN assets d ON d.id = e.dst_id
             WHERE e.kind = 'can_reach_observed' AND {_abac("s.classification")} <= $1
               AND {_abac("d.classification")} <= $1 ORDER BY s.value, d.value LIMIT 100""",
        ctx.cr,
    )
    recent = max(r["last_seen"] for r in segs) >= ctx.now - ctx.fresh
    st = "pass" if len(segs) >= 2 and recent else "partial"
    return _ev(
        "segmentation_map",
        st,
        f"{len(segs)} segments observed; {len(edges)} observed segment-to-segment reachability "
        "path(s) (zones and conduits as seen on the wire, from passive traffic)."
        + ("" if recent else " Observations are stale."),
        {"segments": len(segs), "observed_conduits": len(edges)},
        [{"from": e["src"], "to": e["dst"], "last_seen": _iso(e["last_seen"])} for e in edges[:20]],
    )


@provider("segmentation_violations", "No open segmentation violations")
async def _segmentation_violations(con, ctx: Ctx) -> EvidenceOut:
    segs = await con.fetchval("SELECT COUNT(*) FROM assets WHERE kind = 'network_segment'")
    rows = await _open_findings(con, ctx, "f.rule_id = ANY($1::text[])", list(SEGMENTATION_RULES))
    if not segs and not rows:
        return _ev(
            "segmentation_violations", "none", "No Sentry sensor data to evidence segmentation."
        )
    return _ev(
        "segmentation_violations",
        "fail" if rows else "pass",
        (
            f"{len(rows)} open segmentation violation(s): "
            + ", ".join(
                sorted({SENTRY_RULES.get(r["rule_id"], r["rule_id"]).lower() for r in rows})
            )
            + "."
        )
        if rows
        else "No device crossed a segment boundary or reached the internet unexpectedly.",
        {"open_violations": len(rows)},
        _frows(rows),
    )


@provider("cleartext_protocols", "No cleartext management or weak transport")
async def _cleartext(con, ctx: Ctx) -> EvidenceOut:
    rows = await _open_findings(
        con, ctx, "f.rule_id = 'cleartext_management' OR f.rule_source IN ('tls_check')"
    )
    s = await _scan_state(con, ctx)
    if not s["last"] and not rows:
        return _ev("cleartext_protocols", "none", "No scanning or sensor data to evidence this.")
    return _ev(
        "cleartext_protocols",
        "fail"
        if any(r["severity"] in ("critical", "high") for r in rows)
        else "partial"
        if rows
        else "pass",
        f"{len(rows)} open cleartext-management / weak-TLS finding(s)."
        if rows
        else "No cleartext device management or weak TLS protocol observed.",
        {"open": len(rows)},
        _frows(rows),
    )


@provider("tls_posture", "TLS configuration grades")
async def _tls_posture(con, ctx: Ctx) -> EvidenceOut:
    rows = await con.fetch("SELECT grade, COUNT(*) AS n FROM tls_grades GROUP BY 1 ORDER BY 1")
    total = sum(int(r["n"]) for r in rows)
    if not total:
        return _ev("tls_posture", "none", "No TLS endpoints graded yet.")
    bad = sum(int(r["n"]) for r in rows if r["grade"] not in ("A+", "A", "B"))
    return _ev(
        "tls_posture",
        "partial" if bad else "pass",
        f"{total} TLS endpoints graded; {bad} below B.",
        {"graded": total, "below_b": bad},
        [{"grade": r["grade"], "endpoints": int(r["n"])} for r in rows],
    )


@provider("certificate_inventory", "Certificate inventory and expiry")
async def _certs(con, ctx: Ctx) -> EvidenceOut:
    n = await con.fetchval(
        f"SELECT COUNT(*) FROM assets a WHERE kind = 'certificate' AND {_abac('a.classification')} <= $1",
        ctx.cr,
    )
    g = await con.fetchval("SELECT COUNT(*) FROM tls_grades WHERE cert_expires IS NOT NULL")
    rows = await _open_findings(con, ctx, "f.rule_id ILIKE '%cert%expir%'")
    if not (n or g):
        return _ev("certificate_inventory", "none", "No certificates inventoried.")
    return _ev(
        "certificate_inventory",
        "partial" if rows else "pass",
        f"{int(n)} certificates inventoried, {int(g)} endpoint expiry dates tracked; "
        f"{len(rows)} open expiry finding(s).",
        {"certificates": int(n), "expiring_open": len(rows)},
        _frows(rows),
    )


@provider("exposure_hygiene", "No unnecessary public exposure")
async def _exposure(con, ctx: Ctx) -> EvidenceOut:
    rows = await _open_findings(
        con,
        ctx,
        "f.rule_source = ANY($1::text[]) OR f.rule_id = ANY($2::text[])",
        list(EXPOSURE_SOURCES),
        list(EXPOSURE_RULES),
    )
    s = await _scan_state(con, ctx)
    if not s["last"] and not rows:
        return _ev("exposure_hygiene", "none", "No scanning on record to evidence this.")
    hi = [r for r in rows if r["severity"] in ("critical", "high")]
    return _ev(
        "exposure_hygiene",
        "fail" if hi else "partial" if rows else "pass",
        f"{len(rows)} open exposure finding(s) (exposed files, takeovers, dev hosts public), "
        f"{len(hi)} high/critical."
        if rows
        else "No exposed files, dangling DNS or public dev hosts open.",
        {"open": len(rows), "high_critical": len(hi)},
        _frows(rows),
    )


@provider("secure_configuration", "Secure configuration checks")
async def _secure_config(con, ctx: Ctx) -> EvidenceOut:
    rows = await _open_findings(con, ctx, "f.rule_source = ANY($1::text[])", list(CONFIG_SOURCES))
    s = await _scan_state(con, ctx)
    if not s["last"] and not rows:
        return _ev("secure_configuration", "none", "No configuration checks have run.")
    hi = [r for r in rows if r["severity"] in ("critical", "high")]
    return _ev(
        "secure_configuration",
        "fail" if hi else "partial" if rows else "pass",
        f"Headers, TLS and policy-as-code checks run on every scan; {len(rows)} open "
        f"configuration finding(s), {len(hi)} high/critical.",
        {"open": len(rows), "high_critical": len(hi)},
        _frows(rows),
    )


@provider("secrets_exposure", "No exposed secrets")
async def _secrets(con, ctx: Ctx) -> EvidenceOut:
    rows = await _open_findings(con, ctx, "f.rule_source = 'secret_scan'")
    s = await _scan_state(con, ctx)
    if not s["last"] and not rows:
        return _ev("secrets_exposure", "none", "No secret scanning on record.")
    return _ev(
        "secrets_exposure",
        "fail" if rows else "pass",
        f"{len(rows)} open exposed-secret finding(s)."
        if rows
        else "No open exposed-secret findings.",
        {"open": len(rows)},
        _frows(rows),
    )


@provider("code_analysis", "Code-level security checks (SAST)")
async def _code(con, ctx: Ctx) -> EvidenceOut:
    r = await con.fetchrow(
        """SELECT (SELECT COUNT(*) FROM code_findings WHERE detected_at >= $1) AS recent,
                  (SELECT COUNT(*) FROM code_findings) AS total,
                  (SELECT COUNT(DISTINCT project_id) FROM code_findings) AS projects""",
        ctx.now - timedelta(days=90),
    )
    if not int(r["total"]):
        return _ev("code_analysis", "none", "No code analysis results on record.")
    return _ev(
        "code_analysis",
        "pass" if int(r["recent"]) else "partial",
        f"Taint-tracking SAST results for {int(r['projects'])} project(s); {int(r['recent'])} "
        "results in the last 90 days.",
        {"projects": int(r["projects"]), "results_90d": int(r["recent"])},
    )


@provider("threat_intel", "Threat intelligence integrated")
async def _ti(con, ctx: Ctx) -> EvidenceOut:
    feeds = await con.fetch(
        "SELECT name, kind, enabled, last_poll, indicator_count FROM ti_feeds ORDER BY name"
    )
    kev = await con.fetchval("SELECT COUNT(*) FROM cves WHERE known_exploited")
    live = [
        f
        for f in feeds
        if f["enabled"] and f["last_poll"] and f["last_poll"] >= ctx.now - ctx.fresh
    ]
    if not feeds and not kev:
        return _ev("threat_intel", "none", "No threat-intelligence feeds or KEV data loaded.")
    return _ev(
        "threat_intel",
        "pass" if live or kev else "partial",
        f"{len(feeds)} STIX/TAXII feed(s) ({len(live)} polled recently); {int(kev)} CISA KEV entries "
        "used to prioritise findings.",
        {"feeds": len(feeds), "kev": int(kev)},
        [
            {
                "feed": f["name"],
                "kind": f["kind"],
                "indicators": f["indicator_count"],
                "last_poll": _iso(f["last_poll"]),
            }
            for f in feeds[:15]
        ],
    )


@provider("audit_log", "Tamper-evident audit log (Paddock operations)")
async def _audit(con, ctx: Ctx) -> EvidenceOut:
    n = int(await con.fetchval("SELECT COUNT(*) FROM audit_log"))
    if not n:
        return _ev("audit_log", "none", "The Paddock audit log is empty.")
    if n > 200_000:
        return _ev(
            "audit_log",
            "partial",
            f"{n} entries; chain verification skipped in the pack (run GET /v1/audit/verify).",
            {"entries": n},
        )
    res = await audit.verify(ctx.pool)
    return _ev(
        "audit_log",
        "pass" if res["ok"] else "fail",
        f"{n} hash-chained entries; verification {'passed' if res['ok'] else 'FAILED at #' + str(res['first_broken_id'])}. "
        "Covers actions taken in Paddock only.",
        {"entries": n, "verified": res["ok"]},
    )


@provider("continuous_monitoring", "Continuous monitoring and change detection")
async def _monitoring(con, ctx: Ctx) -> EvidenceOut:
    r = await con.fetchrow(
        """SELECT (SELECT COUNT(*) FROM schedules WHERE enabled) AS sched,
                  (SELECT MAX(last_run_at) FROM schedules WHERE enabled) AS last_run,
                  (SELECT COUNT(*) FROM surface_changes WHERE detected_at >= $1) AS changes""",
        ctx.now - ctx.fresh,
    )
    s = await _scan_state(con, ctx)
    sched, changes = int(r["sched"]), int(r["changes"])
    active = sched and r["last_run"] and r["last_run"] >= ctx.now - timedelta(days=7)
    if not (sched or changes or s["last"]):
        return _ev("continuous_monitoring", "none", "No scheduled scanning or change detection.")
    return _ev(
        "continuous_monitoring",
        "pass" if active else "partial",
        f"{sched} enabled schedule(s){'' if active else ' (none ran in the last 7 days)'}; "
        f"{changes} surface changes detected in the last {ctx.fresh.days} days.",
        {"schedules": sched, "changes": changes, "last_run": _iso(r["last_run"])},
    )


@provider("behaviour_detection", "Network behaviour detection (Sentry)")
async def _behaviour(con, ctx: Ctx) -> EvidenceOut:
    last = await con.fetchval(
        f"SELECT MAX(last_seen) FROM assets a WHERE kind IN ('iot_device','ot_device') "
        f"AND {_abac('a.classification')} <= $1",
        ctx.cr,
    )
    if not last:
        return _ev("behaviour_detection", "none", "No Sentry sensor reporting.")
    rows = await con.fetch(
        """SELECT rule_id, COUNT(*) AS n FROM findings WHERE rule_id = ANY($1::text[])
             AND first_seen >= $2 GROUP BY 1 ORDER BY 2 DESC""",
        list(SENTRY_RULES),
        ctx.now - timedelta(days=90),
    )
    recent = last >= ctx.now - ctx.fresh
    return _ev(
        "behaviour_detection",
        "pass" if recent else "partial",
        f"Passive detectors (lateral scanning, OT egress, segment crossing, cleartext management, "
        f"behaviour drift) active; {sum(int(r['n']) for r in rows)} detections in 90 days.",
        {"last_observation": _iso(last)},
        [{"detector": r["rule_id"], "detections_90d": int(r["n"])} for r in rows],
    )


@provider("attack_path_analysis", "Attack-path analysis")
async def _paths(con, ctx: Ctx) -> EvidenceOut:
    r = await con.fetchrow(
        """SELECT COUNT(*) FILTER (WHERE closed_at IS NULL) AS open,
                  COUNT(*) FILTER (WHERE closed_at >= $1) AS closed90,
                  MAX(last_seen_at) AS last FROM attack_path_ledger""",
        ctx.now - timedelta(days=90),
    )
    if not r["last"]:
        return _ev("attack_path_analysis", "none", "Attack paths have not been computed.")
    return _ev(
        "attack_path_analysis",
        "pass" if r["last"] >= ctx.now - ctx.fresh else "partial",
        f"{int(r['open'])} open attack path(s) to crown jewels; {int(r['closed90'])} closed in 90 days.",
        {"open": int(r["open"]), "closed_90d": int(r["closed90"])},
    )


@provider("ownership", "Asset ownership and routing")
async def _ownership(con, ctx: Ctx) -> EvidenceOut:
    r = await con.fetchrow(
        """SELECT (SELECT COUNT(*) FROM asset_owners WHERE enabled) AS rules,
                  (SELECT COUNT(*) FROM tickets) AS tickets,
                  (SELECT COUNT(*) FROM tickets WHERE NULLIF(owner_team, '') IS NOT NULL) AS owned"""
    )
    rules, tickets, owned = int(r["rules"]), int(r["tickets"]), int(r["owned"])
    if not (rules or owned):
        return _ev("ownership", "none", "No ownership rules or owned tickets.")
    pct = 100.0 * owned / tickets if tickets else 0.0
    return _ev(
        "ownership",
        "pass" if tickets and pct >= 80 else "partial",
        f"{rules} ownership rule(s); {pct:.0f}% of {tickets} remediation tickets routed to a team.",
        {"rules": rules, "tickets": tickets, "owned_pct": round(pct, 1)},
    )


@provider("classification", "Asset classification labels")
async def _classification(con, ctx: Ctx) -> EvidenceOut:
    rows = await con.fetch(
        f"SELECT classification, COUNT(*) AS n FROM assets a WHERE {_abac('a.classification')} <= $1 GROUP BY 1",
        ctx.cr,
    )
    if not rows:
        return _ev("classification", "none", "No assets.")
    labelled = sum(int(r["n"]) for r in rows if r["classification"] != "internal")
    return _ev(
        "classification",
        "partial" if labelled else "none",
        f"Assets carry a classification (public/internal/confidential/restricted) enforced by ABAC; "
        f"{labelled} assets labelled beyond the default.",
        {},
        [{"classification": r["classification"], "assets": int(r["n"])} for r in rows],
    )


# --------------------------------------------------------------------------- #
# Folding evidence into control status
# --------------------------------------------------------------------------- #


def control_status(mode: str, statuses: list[str], max_status: str) -> str:
    if mode == "manual" or not statuses:
        return "requires_attestation"
    if all(s == "pass" for s in statuses):
        st = "satisfied"
    elif any(s in ("pass", "partial") for s in statuses):
        st = "partial"
    else:
        st = "gap"
    if st == "satisfied" and max_status == "partial":
        st = "partial"
    return st


def _ctx(pool, clearance: str, now: datetime | None) -> Ctx:
    return Ctx(
        pool=pool,
        now=now or datetime.now(timezone.utc),
        cr=clearance_rank_of(clearance),
        clearance=clearance,
        fresh=timedelta(days=report_settings.evidence_fresh_days),
    )


async def _evidence(ctx: Ctx, keys: set[str]) -> None:
    unknown = sorted(k for k in keys if k not in PROVIDERS)
    if unknown:
        raise ValueError(f"unknown evidence keys {unknown}")
    todo = sorted(k for k in keys if k not in ctx.cache)
    if not todo:
        return
    async with ctx.pool.acquire() as con:
        for k in todo:
            ctx.cache[k] = await PROVIDERS[k][1](con, ctx)


def _keys(cat: dict[str, Any]) -> set[str]:
    return {
        k
        for c in cat["controls"]
        if c.get("mode", "automated") != "manual"
        for k in c.get("evidence", [])
    }


async def build_pack(
    pool,
    framework: str,
    *,
    clearance: str = "internal",
    now: datetime | None = None,
    org_name: str | None = None,
    ctx: Ctx | None = None,
) -> CompliancePack:
    cat = load_catalogue(framework)
    ctx = ctx or _ctx(pool, clearance, now)
    await _evidence(ctx, _keys(cat))
    now = ctx.now

    controls: list[ControlOut] = []
    counts = {s: 0 for s in STATUSES}
    for c in cat["controls"]:
        mode = c.get("mode", "automated")
        ev = [ctx.cache[k] for k in c.get("evidence", [])] if mode != "manual" else []
        max_status = c.get("max_status", "satisfied")
        st = control_status(mode, [e.status for e in ev], max_status)
        counts[st] += 1
        controls.append(
            ControlOut(
                id=c["id"],
                title=c["title"],
                family=c.get("family", ""),
                summary=c.get("summary", ""),
                mode=mode,
                status=st,
                max_status=max_status,
                rationale=c.get("rationale", ""),
                attestation=c.get("attestation"),
                evidence=ev,
            )
        )
    fw = FrameworkSummary(
        id=framework,
        name=cat["name"],
        version=cat["version"],
        publisher=cat["publisher"],
        url=cat.get("url"),
        description=cat.get("description", ""),
        counts=counts,
        total=len(controls),
        automated=sum(1 for c in controls if c.mode == "automated"),
    )
    return CompliancePack(
        framework=fw,
        generated_at=now,
        org_name=org_name or report_settings.org_name,
        clearance=clearance,
        disclaimer=cat.get("disclaimer") or DISCLAIMER,
        controls=controls,
    )


async def summaries(pool, *, clearance: str = "internal") -> list[FrameworkSummary]:
    """Every framework's status counts (shares one evidence computation)."""
    ctx = _ctx(pool, clearance, None)
    out = []
    for fw in framework_ids():
        out.append((await build_pack(pool, fw, clearance=clearance, ctx=ctx)).framework)
    return out


def render_pack_html(pack: CompliancePack) -> str:
    from .render import footer_text, render_template

    families: dict[str, list[ControlOut]] = {}
    evidence: dict[str, EvidenceOut] = {}
    for c in pack.controls:
        families.setdefault(c.family, []).append(c)
        for e in c.evidence:
            evidence.setdefault(e.key, e)
    return render_template(
        "compliance.html.j2",
        p=pack,
        families=families,
        evidence=evidence,
        footer_left=footer_text(pack.org_name, pack.clearance),
    )
