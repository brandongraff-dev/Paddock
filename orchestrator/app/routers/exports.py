"""Standards exports + SBOM/lockfile imports (interoperability).

Read-only exports (``read`` capability):

- ``GET /v1/export/findings.ocsf``  NDJSON, one OCSF 1.3 object per finding
  (Vulnerability Finding 2002 when a CVE is attached, else Detection Finding
  2004). Filters: ``severity`` (repeatable), ``min_severity``, ``status``
  (repeatable), ``rule_source`` (repeatable), ``since`` (last_seen >=),
  ``limit``. ABAC: rows above the caller's clearance never leave Postgres.
- ``GET /v1/export/sarif``  SARIF 2.1.0 for code findings (SAST /
  codeanalysis) and, with ``include_sca=true`` (default), the project's
  dependency vulnerabilities placed on their lockfile -- the shape GitHub
  code scanning ingests via ``github/codeql-action/upload-sarif``.
- ``GET /v1/export/sbom?project=&format=cyclonedx|spdx``  CycloneDX 1.5 /
  SPDX 2.3 JSON from ``sbom_components``.
- ``GET /v1/export/vex?project=&format=cyclonedx|openvex``  VEX statements
  for every vulnerability match, with reachability-derived status
  (unreachable -> not_affected / code_not_reachable).

Imports (``scan`` capability -- analysts, admins and the service key; a CI
pipeline uses an analyst-scoped API key):

- ``POST /v1/import/sbom``  CycloneDX or SPDX JSON -> an ``sca_projects`` row
  + ``sbom_components`` (+ CycloneDX ``vulnerabilities`` when present).
  Size-limited (``PADDOCK_SBOM_IMPORT_MAX_BYTES``, default 10 MiB) and
  component-count limited.
- ``POST /v1/import/lockfiles``  ``{project, files: {path: content}}`` proxied
  to the SCA service's ``/scan`` (parse -> SBOM -> OSV -> risks); the paths
  are recorded in ``sca_project_manifests`` so SARIF results land on the
  right file.

Every export is flagged for the audit trail (bulk data egress).
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from datetime import datetime
from typing import Any, AsyncIterator, Literal, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse

from .. import standards
from ..auth import CLASS_RANK, Principal, classification_rank_sql, current_principal
from ..db import get_pool
from ..integrations import ocsf
from ..models import FindingStatus, RuleSource, Severity

logger = logging.getLogger(__name__)
export_router = APIRouter(prefix="/v1/export", tags=["export"])
import_router = APIRouter(prefix="/v1/import", tags=["import"])

_SEV_ARRAY = "ARRAY['info','low','medium','high','critical']"
_ABAC_F = classification_rank_sql("f.classification")
_RESTRICTED = CLASS_RANK["restricted"]
_SUPPRESSED = {"false_positive", "accepted_risk", "wontfix"}

CDX_MEDIA = "application/vnd.cyclonedx+json; version=1.5"
SPDX_MEDIA = "application/spdx+json"
SARIF_MEDIA = "application/sarif+json"
NDJSON_MEDIA = "application/x-ndjson"

_PROJECT_NAME_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,200}$")


def _int_env(name: str, default: int) -> int:
    try:
        return max(1024, int(os.environ.get(name, default)))
    except ValueError:
        return default


def sbom_import_max_bytes() -> int:
    return _int_env("PADDOCK_SBOM_IMPORT_MAX_BYTES", 10 * 1024 * 1024)


def lockfile_import_max_bytes() -> int:
    return _int_env("PADDOCK_LOCKFILE_IMPORT_MAX_BYTES", 25 * 1024 * 1024)


MAX_LOCKFILES = 200


def _sca_url() -> str:
    return os.environ.get("SCA_URL", "http://sca:8094").rstrip("/")


def _try_uuid(v: str) -> UUID | None:
    try:
        return UUID(v)
    except (ValueError, TypeError):
        return None


def _json_field(v: Any, default: Any) -> Any:
    if isinstance(v, str):
        try:
            return json.loads(v)
        except ValueError:
            return default
    return default if v is None else v


def _audit_export(request: Request, classification: Optional[str] = None) -> None:
    request.state.audit_restricted = True
    if classification:
        request.state.audit_classification = classification


def _attachment(name: str) -> dict[str, str]:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", name)[:150] or "export"
    return {"Content-Disposition": f'attachment; filename="{safe}"'}


async def _project(con, project: str) -> dict[str, Any]:
    pid = _try_uuid(project)
    sql = ("SELECT id, name, source_ref, ecosystems, asset_id, created_at, last_scanned "
           "FROM sca_projects WHERE " + ("id = $1" if pid else "name = $1"))
    row = await con.fetchrow(sql, pid or project)
    if row is None:
        raise HTTPException(status_code=404, detail="project not found")
    return dict(row)


# --------------------------------------------------------------------------- #
# OCSF NDJSON
# --------------------------------------------------------------------------- #

_OCSF_SQL_COLS = """
    f.id, f.asset_id, f.rule_id, f.rule_source, f.severity, f.title, f.description,
    f.impact, f.remediation, f.evidence, f.cvss, f.epss, f."references", f.status,
    f.first_seen, f.last_seen, f.assigned_to, f.metadata, f.classification,
    a.value AS asset_value, a.kind AS asset_kind, a.canonical AS asset_canonical,
    CASE WHEN jsonb_typeof(f.metadata->'blast_score') = 'number'
         THEN (f.metadata->>'blast_score')::float ELSE NULL END AS blast_score,
    c.id AS cve_row_id, c.cvss_v3, c.cvss_v3_vector, c.epss AS cve_epss, c.epss_percentile,
    c.cwe_ids, c.known_exploited, c.published_at, c.modified_at, c.description AS cve_description
"""


def _ocsf_from_row(row: Any) -> dict[str, Any]:
    d = dict(row)
    d["evidence"] = _json_field(d.get("evidence"), {})
    d["metadata"] = _json_field(d.get("metadata"), {})
    d["references"] = list(d.get("references") or [])
    for k in ("cvss", "epss"):
        if d.get(k) is not None:
            d[k] = float(d[k])
    cve = None
    if d.get("cve_row_id"):
        cve = {
            "id": d["cve_row_id"], "cvss_v3": d.get("cvss_v3"), "cvss_v3_vector": d.get("cvss_v3_vector"),
            "epss": d.get("cve_epss"), "epss_percentile": d.get("epss_percentile"),
            "cwe_ids": list(d.get("cwe_ids") or []), "known_exploited": d.get("known_exploited"),
            "published_at": d.get("published_at"), "modified_at": d.get("modified_at"),
            "description": d.get("cve_description"),
        }
    asset = {"id": d.get("asset_id"), "value": d.get("asset_value"), "kind": d.get("asset_kind"),
             "canonical": d.get("asset_canonical")}
    return ocsf.finding_to_ocsf(d, asset=asset, cve=cve)


@export_router.get("/findings.ocsf")
async def export_findings_ocsf(
    request: Request,
    severity: list[Severity] | None = Query(None, description="repeatable"),
    min_severity: Severity | None = None,
    status: list[FindingStatus] | None = Query(None, description="repeatable"),
    rule_source: list[RuleSource] | None = Query(None, description="repeatable"),
    since: datetime | None = Query(None, description="only findings with last_seen >= since"),
    limit: int = Query(10_000, ge=1, le=100_000),
    pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    clauses: list[str] = []
    args: list[Any] = []
    if severity:
        args.append(list(severity))
        clauses.append(f"f.severity = ANY(${len(args)}::text[])")
    if min_severity:
        args.append(min_severity)
        clauses.append(f"array_position({_SEV_ARRAY}, f.severity) >= array_position({_SEV_ARRAY}, ${len(args)}::text)")
    if status:
        args.append(list(status))
        clauses.append(f"f.status = ANY(${len(args)}::text[])")
    if rule_source:
        args.append(list(rule_source))
        clauses.append(f"f.rule_source = ANY(${len(args)}::text[])")
    if since is not None:
        args.append(since)
        clauses.append(f"f.last_seen >= ${len(args)}")
    args.append(principal.clearance_rank)
    clauses.append(f"{_ABAC_F} <= ${len(args)}")
    where = "WHERE " + " AND ".join(clauses)

    classification = None
    if principal.clearance_rank >= _RESTRICTED:
        async with pool.acquire() as con:
            if await con.fetchval(
                f"SELECT EXISTS (SELECT 1 FROM findings f {where} AND f.classification = 'restricted')",
                *args,
            ):
                classification = "restricted"
    _audit_export(request, classification)

    sql = f"""
        SELECT {_OCSF_SQL_COLS}
          FROM findings f
          LEFT JOIN assets a ON a.id = f.asset_id
          LEFT JOIN cves c ON c.id = upper(f.rule_id)
          {where}
         ORDER BY f.last_seen DESC, f.id
         LIMIT ${len(args) + 1}
    """
    qargs = [*args, limit]

    async def gen() -> AsyncIterator[bytes]:
        async with pool.acquire() as con:
            async with con.transaction(readonly=True):
                async for row in con.cursor(sql, *qargs, prefetch=500):
                    yield (json.dumps(_ocsf_from_row(row), separators=(",", ":"), default=str)
                           + "\n").encode("utf-8")

    return StreamingResponse(gen(), media_type=NDJSON_MEDIA,
                             headers=_attachment("paddock-findings.ocsf.ndjson"))


# --------------------------------------------------------------------------- #
# SARIF
# --------------------------------------------------------------------------- #

def _sev_clause(col: str, min_severity: Optional[str], args: list[Any]) -> str:
    if not min_severity:
        return ""
    args.append(min_severity)
    return (f" AND array_position({_SEV_ARRAY}, {col}) >= "
            f"array_position({_SEV_ARRAY}, ${len(args)}::text)")


def _sast_hit(*, rule: str, title: str, message: str, description: Optional[str], severity: str,
              file: str, start_line: Any, end_line: Any, cwe: Optional[str], dataflow: Any,
              remediation: Optional[str], finding_id: Any, status: Optional[str],
              source: Any = None, sink: Any = None, engine: Any = None) -> dict[str, Any]:
    props: dict[str, Any] = {}
    if source:
        props["source"] = str(source)
    if sink:
        props["sink"] = str(sink)
    if engine:
        props["engine"] = str(engine)
    return {
        "kind": "sast",
        "rule_id": rule,
        "rule_name": rule.rsplit(".", 1)[-1],
        "title": title,
        "message": message,
        "description": description or message,
        "help": remediation or description or message,
        "severity": severity,
        "file": file,
        "start_line": start_line if isinstance(start_line, int) else None,
        "end_line": end_line if isinstance(end_line, int) else None,
        "cwe": cwe,
        "dataflow": dataflow,
        "finding_id": finding_id,
        "suppressed": status if status in _SUPPRESSED else None,
        "tags": ["sast"],
        "properties": props,
        "fingerprint": hashlib.sha256(f"sast|{rule}|{file}|{start_line}".encode()).hexdigest(),
    }


@export_router.get("/sarif")
async def export_sarif(
    request: Request,
    project: str | None = Query(None, max_length=512, description="project id (uuid) or name"),
    min_severity: Severity | None = None,
    include_sca: bool = Query(True, description="include dependency vulnerabilities"),
    include_suppressed: bool = Query(False, description="emit accepted/false-positive results with SARIF suppressions"),
    strip_prefix: str | None = Query(None, max_length=1024,
                                     description="path prefix to strip so URIs are repo-relative"),
    limit: int = Query(5000, ge=1, le=25_000),
    pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    hits: list[dict[str, Any]] = []
    proj: Optional[dict[str, Any]] = None
    async with pool.acquire() as con:
        if project:
            proj = await _project(con, project)

        # (a) code_findings rows (codeanalysis service), with their unified mirror
        args: list[Any] = [principal.clearance_rank]
        q = f"""
            SELECT cf.id, cf.finding_id, cf.engine, cf.rule, cf.message, cf.severity, cf.file,
                   cf.start_line, cf.end_line, cf.source, cf.sink, cf.dataflow, cf.cwe,
                   f.status, f.title, f.description, f.remediation
              FROM code_findings cf
              LEFT JOIN findings f ON f.id = cf.finding_id
             WHERE (f.id IS NULL OR {_ABAC_F} <= $1)
               AND COALESCE(f.status, 'open') <> 'fixed'
        """
        if proj:
            args.append(proj["id"])
            q += f" AND cf.project_id = ${len(args)}"
        q += _sev_clause("cf.severity", min_severity, args)
        q += f" ORDER BY array_position({_SEV_ARRAY}, cf.severity) DESC, cf.file, cf.start_line LIMIT {limit}"
        for r in await con.fetch(q, *args):
            if r["status"] in _SUPPRESSED and not include_suppressed:
                continue
            hits.append(_sast_hit(
                rule=str(r["rule"]), title=r["title"] or str(r["message"])[:200],
                message=str(r["message"]), description=r["description"], severity=r["severity"],
                file=str(r["file"]), start_line=r["start_line"], end_line=r["end_line"],
                cwe=r["cwe"], dataflow=_json_field(r["dataflow"], []), remediation=r["remediation"],
                finding_id=r["finding_id"], status=r["status"], source=r["source"], sink=r["sink"],
                engine=r["engine"]))

        # (b) unified sast findings without a code_findings row (e.g. posted
        #     straight to /v1/findings/bulk): location comes from evidence.
        args = [principal.clearance_rank]
        q = f"""
            SELECT f.id, f.rule_id, f.severity, f.title, f.description, f.remediation,
                   f.evidence, f.status, f.metadata
              FROM findings f
             WHERE f.rule_source = 'sast' AND {_ABAC_F} <= $1 AND f.status <> 'fixed'
               AND NOT EXISTS (SELECT 1 FROM code_findings cf WHERE cf.finding_id = f.id)
        """
        if proj:
            args.append(proj["name"])
            q += f" AND f.metadata->>'project' = ${len(args)}"
        q += _sev_clause("f.severity", min_severity, args)
        q += f" ORDER BY array_position({_SEV_ARRAY}, f.severity) DESC, f.last_seen DESC LIMIT {limit}"
        for r in await con.fetch(q, *args):
            if r["status"] in _SUPPRESSED and not include_suppressed:
                continue
            ev = _json_field(r["evidence"], {}) or {}
            md = _json_field(r["metadata"], {}) or {}
            file = ev.get("file")
            if not file:
                continue  # SARIF needs a location; nothing to anchor it to
            rule = str(ev.get("rule") or str(r["rule_id"]).removeprefix("sast:"))
            hits.append(_sast_hit(
                rule=rule, title=r["title"], message=r["description"], description=r["description"],
                severity=r["severity"], file=str(file), start_line=ev.get("start_line"),
                end_line=ev.get("end_line"), cwe=ev.get("cwe") or md.get("cwe"),
                dataflow=ev.get("dataflow"), remediation=r["remediation"], finding_id=r["id"],
                status=r["status"], source=ev.get("source"), sink=ev.get("sink"),
                engine=ev.get("engine")))

        # (c) dependency vulnerabilities, placed on the project's lockfile
        if include_sca:
            args = []
            q = """
                SELECT v.id, v.osv_id, v.cve_id, v.severity, v.cvss, v.summary, v.fixed_version,
                       v.reachability, v.reachable_symbol,
                       c.ecosystem, c.name, c.version, c.purl, c.direct,
                       p.id AS project_id, p.name AS project_name, fs.status
                  FROM sbom_component_vulns v
                  JOIN sbom_components c ON c.id = v.component_id
                  JOIN sca_projects p ON p.id = c.project_id
                  LEFT JOIN LATERAL (
                        SELECT f.status FROM findings f
                         WHERE f.rule_source = 'sca'
                           AND f.rule_id = 'sca:' || c.ecosystem || ':' || c.name
                         ORDER BY f.last_seen DESC LIMIT 1) fs ON TRUE
                 WHERE COALESCE(fs.status, 'open') <> 'fixed'
            """
            if proj:
                args.append(proj["id"])
                q += f" AND p.id = ${len(args)}"
            q += _sev_clause("v.severity", min_severity, args)
            q += (f" ORDER BY array_position({_SEV_ARRAY}, v.severity) DESC, c.name, v.osv_id"
                  f" LIMIT {limit}")
            rows = await con.fetch(q, *args)
            man_rows = await con.fetch(
                "SELECT project_id, ecosystem, path FROM sca_project_manifests "
                "WHERE kind = 'lockfile'" + (" AND project_id = $1" if proj else ""),
                *([proj["id"]] if proj else []))
            manifests: dict[Any, dict[str, list[str]]] = {}
            for m in man_rows:
                manifests.setdefault(m["project_id"], {}).setdefault(m["ecosystem"] or "", []).append(m["path"])
            for r in rows:
                if r["status"] in _SUPPRESSED and not include_suppressed:
                    continue
                vid = r["cve_id"] or r["osv_id"]
                file = standards.sca_manifest_for(r["ecosystem"], manifests.get(r["project_id"], {}))
                reach = r["reachability"] or "unknown"
                msg = f"{r['name']}@{r['version']} ({r['ecosystem']}) is affected by {vid}"
                if r["summary"]:
                    msg += f": {r['summary']}"
                msg += "." if not msg.endswith(".") else ""
                if r["fixed_version"]:
                    msg += f" Fixed in {r['fixed_version']}."
                msg += f" Reachability: {reach}."
                hits.append({
                    "kind": "sca",
                    "rule_id": str(r["osv_id"]),
                    "rule_name": str(vid),
                    "title": f"{vid} in {r['name']}",
                    "message": msg,
                    "description": r["summary"] or f"Known vulnerability {vid}",
                    "help": (f"Upgrade {r['name']} to {r['fixed_version']} or later."
                             if r["fixed_version"] else "See the advisory for remediation."),
                    "help_uri": f"https://osv.dev/vulnerability/{r['osv_id']}",
                    "severity": r["severity"],
                    "cvss": float(r["cvss"]) if r["cvss"] is not None else None,
                    "level": "note" if reach == "unreachable" else None,
                    "file": file,
                    "finding_id": None,
                    "suppressed": r["status"] if r["status"] in _SUPPRESSED else None,
                    "tags": ["dependency", "sca", str(r["ecosystem"])],
                    "properties": {"purl": r["purl"], "reachability": reach,
                                   "fixedVersion": r["fixed_version"], "direct": r["direct"],
                                   **({"cve": r["cve_id"]} if r["cve_id"] else {})},
                    "fingerprint": hashlib.sha256(
                        f"sca|{r['project_id']}|{r['osv_id']}|{r['ecosystem']}|{r['name']}|{r['version']}"
                        .encode()).hexdigest(),
                })

    _audit_export(request)
    hits = hits[:limit]
    name = proj["name"] if proj else "all"
    log = standards.sarif_log(hits, automation_id=f"paddock/{name}/", strip_prefix=strip_prefix)
    return JSONResponse(log, media_type=SARIF_MEDIA, headers=_attachment(f"paddock-{name}.sarif"))


# --------------------------------------------------------------------------- #
# SBOM + VEX
# --------------------------------------------------------------------------- #

@export_router.get("/sbom")
async def export_sbom(
    request: Request,
    project: str = Query(..., min_length=1, max_length=512, description="project id (uuid) or name"),
    format: Literal["cyclonedx", "spdx"] = "cyclonedx",
    pool=Depends(get_pool),
):
    async with pool.acquire() as con:
        proj = await _project(con, project)
        rows = await con.fetch(
            "SELECT id, ecosystem, name, version, purl, direct, depth, paths FROM sbom_components "
            "WHERE project_id = $1 ORDER BY ecosystem, name, version", proj["id"])
    comps = []
    for r in rows:
        d = dict(r)
        d["paths"] = _json_field(d.get("paths"), [])
        comps.append(d)
    _audit_export(request)
    if format == "spdx":
        return JSONResponse(standards.spdx_sbom(proj, comps), media_type=SPDX_MEDIA,
                            headers=_attachment(f"{proj['name']}.spdx.json"))
    return JSONResponse(standards.cyclonedx_sbom(proj, comps), media_type=CDX_MEDIA,
                        headers=_attachment(f"{proj['name']}.cdx.json"))


@export_router.get("/vex")
async def export_vex(
    request: Request,
    project: str = Query(..., min_length=1, max_length=512, description="project id (uuid) or name"),
    format: Literal["cyclonedx", "openvex"] = "cyclonedx",
    pool=Depends(get_pool),
):
    async with pool.acquire() as con:
        proj = await _project(con, project)
        rows = await con.fetch(
            f"""
            SELECT v.id, v.osv_id, v.cve_id, v.severity, v.cvss, v.summary, v.fixed_version,
                   v.reachability, v.reachable_symbol,
                   c.id AS component_id, c.ecosystem, c.name, c.version, c.purl, c.direct, c.depth
              FROM sbom_component_vulns v
              JOIN sbom_components c ON c.id = v.component_id
             WHERE c.project_id = $1
             ORDER BY array_position({_SEV_ARRAY}, v.severity) DESC, c.name, v.osv_id
            """, proj["id"])
    vulns = [dict(r) for r in rows]
    _audit_export(request)
    if format == "openvex":
        return JSONResponse(standards.openvex(proj, vulns), media_type="application/json",
                            headers=_attachment(f"{proj['name']}.openvex.json"))
    return JSONResponse(standards.cyclonedx_vex(proj, vulns), media_type=CDX_MEDIA,
                        headers=_attachment(f"{proj['name']}.vex.cdx.json"))


# --------------------------------------------------------------------------- #
# Imports
# --------------------------------------------------------------------------- #

async def _read_limited(request: Request, max_bytes: int) -> bytes:
    cl = request.headers.get("content-length")
    if cl is not None:
        try:
            if int(cl) > max_bytes:
                raise HTTPException(status_code=413, detail=f"body exceeds {max_bytes} bytes")
        except ValueError:
            raise HTTPException(status_code=400, detail="bad Content-Length") from None
    buf = bytearray()
    async for chunk in request.stream():
        buf.extend(chunk)
        if len(buf) > max_bytes:
            raise HTTPException(status_code=413, detail=f"body exceeds {max_bytes} bytes")
    return bytes(buf)


def _loads(raw: bytes) -> Any:
    try:
        return json.loads(raw)
    except RecursionError:
        raise HTTPException(status_code=422, detail="JSON nested too deeply") from None
    except ValueError:
        raise HTTPException(status_code=400, detail="body is not valid JSON") from None


def _check_project_name(name: Optional[str]) -> str:
    if not name or not _PROJECT_NAME_RE.match(name) or not name.strip():
        raise HTTPException(status_code=422, detail="a valid project name (1-200 printable chars) is required")
    return name.strip()


_UPSERT_PROJECT = """
    INSERT INTO sca_projects (name, source_ref, ecosystems, last_scanned)
    VALUES ($1, $2, $3::text[], NOW())
    ON CONFLICT (tenant_id, name) DO UPDATE SET
        source_ref   = COALESCE(EXCLUDED.source_ref, sca_projects.source_ref),
        ecosystems   = (SELECT ARRAY(SELECT DISTINCT unnest(sca_projects.ecosystems || EXCLUDED.ecosystems) ORDER BY 1)),
        last_scanned = NOW()
    RETURNING id, name
"""

_UPSERT_COMPONENTS = """
    INSERT INTO sbom_components
        (project_id, ecosystem, name, version, purl, direct, depth, paths, metadata, last_seen)
    SELECT $1, t.e, t.n, t.v, t.p, t.d, t.dp::smallint, t.pa::jsonb, t.md::jsonb, NOW()
      FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::bool[], $7::int[],
                  $8::text[], $9::text[]) AS t(e, n, v, p, d, dp, pa, md)
    ON CONFLICT (project_id, ecosystem, name, version) DO UPDATE SET
        direct    = EXCLUDED.direct,
        depth     = EXCLUDED.depth,
        purl      = COALESCE(EXCLUDED.purl, sbom_components.purl),
        paths     = EXCLUDED.paths,
        metadata  = sbom_components.metadata || EXCLUDED.metadata,
        last_seen = NOW()
    RETURNING id, ecosystem, name, version
"""

_UPSERT_VULN = """
    INSERT INTO sbom_component_vulns
        (component_id, osv_id, cve_id, severity, cvss, summary, refs, reachability)
    VALUES ($1, $2, $3, $4, $5, $6, '[]'::jsonb, COALESCE($7, 'unknown'))
    ON CONFLICT (component_id, osv_id) DO UPDATE SET
        cve_id       = COALESCE(EXCLUDED.cve_id, sbom_component_vulns.cve_id),
        severity     = EXCLUDED.severity,
        cvss         = COALESCE(EXCLUDED.cvss, sbom_component_vulns.cvss),
        summary      = COALESCE(EXCLUDED.summary, sbom_component_vulns.summary),
        reachability = COALESCE($7, sbom_component_vulns.reachability),
        matched_at   = NOW()
"""

_UPSERT_MANIFEST = """
    INSERT INTO sca_project_manifests (project_id, path, ecosystem, kind, sha256, size_bytes, uploaded_by)
    VALUES ($1, $2, $3, $4, $5, $6, $7)
    ON CONFLICT (project_id, path) DO UPDATE SET
        ecosystem = EXCLUDED.ecosystem, kind = EXCLUDED.kind, sha256 = EXCLUDED.sha256,
        size_bytes = EXCLUDED.size_bytes, uploaded_by = EXCLUDED.uploaded_by, uploaded_at = NOW()
"""


@import_router.post("/sbom", status_code=201)
async def import_sbom(
    request: Request,
    project: str | None = Query(None, max_length=200,
                                description="project name (default: the SBOM's root component / document name)"),
    replace: bool = Query(False, description="delete project components that are not in this SBOM"),
    pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    raw = await _read_limited(request, sbom_import_max_bytes())
    doc = _loads(raw)
    try:
        parsed = standards.parse_sbom(doc)
    except standards.ImportError_ as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    name = _check_project_name(project or parsed.get("name"))
    comps = parsed["components"]
    if not comps:
        raise HTTPException(status_code=422, detail="the SBOM contains no usable components (name+version or purl)")
    fmt = parsed["format"]
    ecosystems = sorted({c["ecosystem"] for c in comps})
    digest = hashlib.sha256(raw).hexdigest()

    async with pool.acquire() as con:
        async with con.transaction():
            prow = await con.fetchrow(_UPSERT_PROJECT, name, f"import:{fmt}", ecosystems)
            pid = prow["id"]
            rows = await con.fetch(
                _UPSERT_COMPONENTS, pid,
                [c["ecosystem"] for c in comps], [c["name"] for c in comps],
                [c["version"] for c in comps], [c.get("purl") for c in comps],
                [bool(c.get("direct")) for c in comps],
                [min(int(c.get("depth") or 0), 32767) for c in comps],
                [json.dumps(c.get("paths") or []) for c in comps],
                [json.dumps(c.get("metadata") or {}) for c in comps],
            )
            ids = {(r["ecosystem"], r["name"], r["version"]): r["id"] for r in rows}
            removed = 0
            if replace:
                res = await con.execute(
                    "DELETE FROM sbom_components WHERE project_id = $1 AND NOT (id = ANY($2::uuid[]))",
                    pid, list(ids.values()))
                removed = int(res.split()[-1]) if res.startswith("DELETE") else 0
            vulns = 0
            for v in parsed.get("vulns") or []:
                cid = ids.get(tuple(v["key"]))
                if cid is None:
                    continue
                await con.execute(_UPSERT_VULN, cid, v["osv_id"], v.get("cve_id"), v["severity"],
                                  v.get("cvss"), v.get("summary"), v.get("reachability"))
                vulns += 1
            await con.execute(_UPSERT_MANIFEST, pid, f"import:{fmt}", None, fmt, digest, len(raw),
                              principal.actor)
    return {
        "project": name,
        "project_id": str(pid),
        "format": fmt,
        "components": len(ids),
        "ecosystems": ecosystems,
        "vulnerabilities": vulns,
        "removed": removed,
        "sha256": digest,
    }


@import_router.post("/lockfiles")
async def import_lockfiles(
    request: Request,
    pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    """Upload a repo's lockfiles: ``{"project": "...", "files": {"path": "content"},
    "source_ref": "..."}``. Unsupported file names are ignored (and listed)."""
    raw = await _read_limited(request, lockfile_import_max_bytes())
    body = _loads(raw)
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="body must be a JSON object")
    name = _check_project_name(body.get("project"))
    files = body.get("files")
    if not isinstance(files, dict) or not files:
        raise HTTPException(status_code=422, detail="files must be a non-empty {path: content} object")
    if len(files) > MAX_LOCKFILES:
        raise HTTPException(status_code=422, detail=f"at most {MAX_LOCKFILES} files per upload")
    source_ref = body.get("source_ref")
    if source_ref is not None and (not isinstance(source_ref, str) or len(source_ref) > 1024):
        raise HTTPException(status_code=422, detail="source_ref must be a string of <= 1024 chars")
    accepted: dict[str, str] = {}
    ignored: list[str] = []
    for path, content in files.items():
        p = str(path)
        base = p.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if (not isinstance(content, str) or len(p) > 512 or "\x00" in p
                or base not in standards.LOCKFILE_ECOSYSTEM or ".." in p.split("/")):
            ignored.append(p[:512])
            continue
        accepted[p] = content
    if not accepted:
        raise HTTPException(status_code=422, detail={
            "error": "no supported lockfiles", "supported": sorted(standards.LOCKFILE_ECOSYSTEM),
            "ignored": ignored[:50]})

    import httpx

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(300.0, connect=5.0)) as http:
            resp = await http.post(f"{_sca_url()}/scan", json={
                "project_name": name, "files": accepted, "source_ref": source_ref})
    except httpx.HTTPError as exc:
        logger.warning("sca proxy failed: %s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="SCA service unavailable") from None
    if resp.status_code != 200:
        try:
            err = resp.json().get("error")
        except (ValueError, AttributeError):
            err = None
        raise HTTPException(status_code=502, detail=f"SCA scan failed: {err or resp.status_code}")
    counts = resp.json()
    pid = _try_uuid(str(counts.get("project_id") or ""))
    async with pool.acquire() as con:
        if pid is None:
            pid = await con.fetchval("SELECT id FROM sca_projects WHERE name = $1", name)
        if pid is not None:
            for p, content in accepted.items():
                base = p.replace("\\", "/").rsplit("/", 1)[-1].lower()
                data = content.encode("utf-8", "replace")
                await con.execute(_UPSERT_MANIFEST, pid, p, standards.LOCKFILE_ECOSYSTEM[base],
                                  "lockfile", hashlib.sha256(data).hexdigest(), len(data),
                                  principal.actor)
    return {**counts, "project": name, "project_id": str(pid) if pid else None,
            "files": sorted(accepted), "ignored": ignored[:50]}
