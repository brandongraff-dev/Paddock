"""SCA / SBOM read API (Tier 3).

The SCA service (`sca/`) parses lockfiles, builds an SBOM into
`sbom_components` under a `sca_projects` row, matches vulns into
`sbom_component_vulns`, and writes `supply_chain_risks`. This router is
*read-only*: it serves projects, components (with vuln roll-ups), component
detail, supply-chain risks, and a summary. Nothing here scans, resolves, or
reaches a registry -- that is the SCA service's job.

- `GET /v1/sbom/projects`                      list projects + component/vuln counts.
- `GET /v1/sbom/components`                     paged; each row carries vuln_count
                                                and max_vuln_severity (one grouped
                                                LEFT JOIN, no N+1).
- `GET /v1/sbom/components/{id}`                component + its vulns.
- `GET /v1/sbom/summary`                        counts (components, vulnerable,
                                                by_risk_type, by_severity).
- `GET /v1/supply-chain-risks`                  paged; filter type/severity/project.

No endpoint aids a supply-chain *attack*; these surface where YOU are exposed.
"""
from __future__ import annotations

import json
import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from ..db import get_pool
from ..models import (
    RiskType,
    SbomComponentDetailOut,
    SbomComponentOut,
    SbomComponentPage,
    SbomProjectOut,
    SbomSummary,
    SbomVulnOut,
    Severity,
    SupplyChainRiskOut,
    SupplyChainRiskPage,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/sbom", tags=["sbom"])
risks_router = APIRouter(prefix="/v1/supply-chain-risks", tags=["sbom"])

# Severity rank array, shared by the max-severity roll-up and summary buckets.
_SEV_ARRAY = "ARRAY['info','low','medium','high','critical']"
_SEV_BUCKETS: tuple[str, ...] = ("info", "low", "medium", "high", "critical")

# Reachability rank array (worst-first index): reachable > potential >
# unreachable > unknown. Same array_position trick as the severity roll-up.
_REACH_ARRAY = "ARRAY['unknown','unreachable','potential','reachable']"


def _try_uuid(v: str) -> UUID | None:
    try:
        return UUID(v)
    except (ValueError, TypeError):
        return None


# --------------------------------------------------------------------------- #
# Row helpers
# --------------------------------------------------------------------------- #

def _row_to_component(row) -> SbomComponentOut:
    d = dict(row)
    if isinstance(d.get("paths"), str):
        d["paths"] = json.loads(d["paths"])
    elif d.get("paths") is None:
        d["paths"] = []
    if isinstance(d.get("metadata"), str):
        d["metadata"] = json.loads(d["metadata"])
    elif d.get("metadata") is None:
        d["metadata"] = {}
    if d.get("vuln_count") is not None:
        d["vuln_count"] = int(d["vuln_count"])
    if d.get("reachable_vuln_count") is not None:
        d["reachable_vuln_count"] = int(d["reachable_vuln_count"])
    return SbomComponentOut.model_validate(d)


def _row_to_vuln(row) -> SbomVulnOut:
    d = dict(row)
    if isinstance(d.get("refs"), str):
        d["refs"] = json.loads(d["refs"])
    elif d.get("refs") is None:
        d["refs"] = []
    if isinstance(d.get("call_path"), str):
        d["call_path"] = json.loads(d["call_path"])
    elif d.get("call_path") is None:
        d["call_path"] = []
    if d.get("cvss") is not None:
        d["cvss"] = float(d["cvss"])
    return SbomVulnOut.model_validate(d)


def _row_to_risk(row) -> SupplyChainRiskOut:
    d = dict(row)
    if isinstance(d.get("detail"), str):
        d["detail"] = json.loads(d["detail"])
    elif d.get("detail") is None:
        d["detail"] = {}
    return SupplyChainRiskOut.model_validate(d)


# --------------------------------------------------------------------------- #
# Projects
# --------------------------------------------------------------------------- #

@router.get("/projects", response_model=list[SbomProjectOut])
async def list_projects(
    limit: int = Query(200, ge=1, le=500),
    offset: int = Query(0, ge=0),
    pool=Depends(get_pool),
):
    """All SCA projects, each with its component + vuln counts.

    Counts are resolved with two grouped sub-selects joined on project_id, so
    the whole list costs one query (no per-project follow-ups).
    """
    sql = """
        SELECT p.id, p.name, p.source_ref, p.ecosystems, p.asset_id,
               p.created_at, p.last_scanned,
               COALESCE(cc.component_count, 0) AS component_count,
               COALESCE(vc.vuln_count, 0) AS vuln_count
          FROM sca_projects p
          LEFT JOIN (
                SELECT project_id, COUNT(*) AS component_count
                  FROM sbom_components GROUP BY project_id
          ) cc ON cc.project_id = p.id
          LEFT JOIN (
                SELECT c.project_id, COUNT(v.id) AS vuln_count
                  FROM sbom_components c
                  JOIN sbom_component_vulns v ON v.component_id = c.id
                 GROUP BY c.project_id
          ) vc ON vc.project_id = p.id
         ORDER BY p.created_at DESC
         LIMIT $1 OFFSET $2
    """
    async with pool.acquire() as con:
        rows = await con.fetch(sql, limit, offset)
    out: list[SbomProjectOut] = []
    for r in rows:
        d = dict(r)
        if d.get("ecosystems") is None:
            d["ecosystems"] = []
        d["component_count"] = int(d["component_count"])
        d["vuln_count"] = int(d["vuln_count"])
        out.append(SbomProjectOut.model_validate(d))
    return out


# --------------------------------------------------------------------------- #
# Summary (declared before /components/{id} isn't needed -- different prefix,
# but kept near the top for readability).
# --------------------------------------------------------------------------- #

@router.get("/summary", response_model=SbomSummary)
async def sbom_summary(pool=Depends(get_pool)):
    async with pool.acquire() as con:
        components = await con.fetchval("SELECT COUNT(*) FROM sbom_components")
        vulnerable = await con.fetchval(
            "SELECT COUNT(DISTINCT component_id) FROM sbom_component_vulns"
        )
        risk_rows = await con.fetch(
            "SELECT risk_type, COUNT(*) AS c FROM supply_chain_risks GROUP BY risk_type"
        )
        sev_rows = await con.fetch(
            "SELECT severity, COUNT(*) AS c FROM sbom_component_vulns GROUP BY severity"
        )
    by_severity = {s: 0 for s in _SEV_BUCKETS}
    for r in sev_rows:
        by_severity[r["severity"]] = int(r["c"])
    return SbomSummary(
        components=int(components or 0),
        vulnerable_components=int(vulnerable or 0),
        by_risk_type={r["risk_type"]: int(r["c"]) for r in risk_rows},
        by_severity=by_severity,
    )


# --------------------------------------------------------------------------- #
# Components (paged, with vuln roll-up) + detail
# --------------------------------------------------------------------------- #

_COMPONENT_COLS = (
    "c.id, c.project_id, c.ecosystem, c.name, c.version, c.purl, c.direct, "
    "c.depth, c.paths, c.first_seen, c.last_seen, c.metadata"
)
# Highest vuln severity among a component's vulns: rank each severity via
# array_position, take the max, and index back into the array. Null when the
# component has no vulns.
_MAX_SEV_EXPR = (
    f"({_SEV_ARRAY})[MAX(array_position({_SEV_ARRAY}, v.severity))] AS max_vuln_severity"
)
# Worst reachability among the component's vulns (null when it has none), and a
# count of vulns that are actually `reachable`. Same grouped LEFT JOIN -- no N+1.
_REACH_ROLLUP_EXPR = (
    f"({_REACH_ARRAY})[MAX(array_position({_REACH_ARRAY}, v.reachability))] "
    "AS reachability, "
    "COUNT(v.id) FILTER (WHERE v.reachability = 'reachable') AS reachable_vuln_count"
)


def _component_filters(
    project: str | None,
    ecosystem: str | None,
) -> tuple[list[str], list[Any]]:
    clauses: list[str] = []
    args: list[Any] = []
    if project is not None:
        pid = _try_uuid(project)
        if pid is not None:
            args.append(pid)
            clauses.append(f"c.project_id = ${len(args)}")
        else:
            # match by project name
            args.append(project)
            clauses.append(
                f"c.project_id = (SELECT id FROM sca_projects WHERE name = ${len(args)})"
            )
    if ecosystem is not None:
        args.append(ecosystem)
        clauses.append(f"c.ecosystem = ${len(args)}")
    return clauses, args


@router.get("/components", response_model=SbomComponentPage)
async def list_components(
    project: str | None = Query(None, description="project id (uuid) or name"),
    vulnerable: bool | None = Query(None, description="only vulnerable / only clean"),
    ecosystem: str | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    pool=Depends(get_pool),
):
    clauses, args = _component_filters(project, ecosystem)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""

    # vulnerable filter is a HAVING on the grouped vuln count.
    having = ""
    if vulnerable is True:
        having = "HAVING COUNT(v.id) > 0"
    elif vulnerable is False:
        having = "HAVING COUNT(v.id) = 0"

    # total counts grouped rows (so the HAVING filter is honoured).
    sql_count = f"""
        SELECT COUNT(*) FROM (
            SELECT c.id
              FROM sbom_components c
              LEFT JOIN sbom_component_vulns v ON v.component_id = c.id
              {where}
             GROUP BY c.id
             {having}
        ) sub
    """
    args_list = list(args)
    args_list.extend([limit, offset])
    sql = f"""
        SELECT {_COMPONENT_COLS},
               COUNT(v.id) AS vuln_count,
               {_MAX_SEV_EXPR},
               {_REACH_ROLLUP_EXPR}
          FROM sbom_components c
          LEFT JOIN sbom_component_vulns v ON v.component_id = c.id
          {where}
         GROUP BY c.id
         {having}
         ORDER BY COUNT(v.id) DESC, c.ecosystem ASC, c.name ASC
         LIMIT ${len(args_list) - 1} OFFSET ${len(args_list)}
    """
    async with pool.acquire() as con:
        total = await con.fetchval(sql_count, *args)
        rows = await con.fetch(sql, *args_list)
    items = [_row_to_component(r) for r in rows]
    return SbomComponentPage(
        items=items, total=int(total or 0), limit=limit, offset=offset
    )


@router.get("/components/{component_id}", response_model=SbomComponentDetailOut)
async def get_component(component_id: UUID, pool=Depends(get_pool)):
    async with pool.acquire() as con:
        row = await con.fetchrow(
            f"""
            SELECT {_COMPONENT_COLS},
                   COUNT(v.id) AS vuln_count,
                   {_MAX_SEV_EXPR},
                   {_REACH_ROLLUP_EXPR}
              FROM sbom_components c
              LEFT JOIN sbom_component_vulns v ON v.component_id = c.id
             WHERE c.id = $1
             GROUP BY c.id
            """,
            component_id,
        )
        if row is None:
            raise HTTPException(status_code=404, detail="component not found")
        vuln_rows = await con.fetch(
            """
            SELECT id, component_id, osv_id, cve_id, severity, cvss, summary,
                   fixed_version, refs, matched_at,
                   reachability, reachable_symbol, call_path
              FROM sbom_component_vulns
             WHERE component_id = $1
             ORDER BY array_position(""" + _REACH_ARRAY + """, reachability) DESC,
                      array_position(""" + _SEV_ARRAY + """, severity) DESC,
                      osv_id ASC
            """,
            component_id,
        )
    component = _row_to_component(row)
    vulns = [_row_to_vuln(r) for r in vuln_rows]
    return SbomComponentDetailOut(component=component, vulns=vulns)


# --------------------------------------------------------------------------- #
# Supply-chain risks (paged)
# --------------------------------------------------------------------------- #

@risks_router.get("", response_model=SupplyChainRiskPage)
async def list_supply_chain_risks(
    type: RiskType | None = Query(None, description="risk_type filter"),
    severity: Severity | None = None,
    project: str | None = Query(None, description="project id (uuid) or name"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    pool=Depends(get_pool),
):
    clauses: list[str] = []
    args: list[Any] = []
    if type is not None:
        args.append(type)
        clauses.append(f"r.risk_type = ${len(args)}")
    if severity is not None:
        args.append(severity)
        clauses.append(f"r.severity = ${len(args)}")
    if project is not None:
        pid = _try_uuid(project)
        if pid is not None:
            args.append(pid)
            clauses.append(f"r.project_id = ${len(args)}")
        else:
            args.append(project)
            clauses.append(
                f"r.project_id = (SELECT id FROM sca_projects WHERE name = ${len(args)})"
            )
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""

    sql_count = f"SELECT COUNT(*) FROM supply_chain_risks r {where}"
    args_list = list(args)
    args_list.extend([limit, offset])
    sql = f"""
        SELECT r.id, r.project_id, r.component_id, r.risk_type, r.severity,
               r.summary, r.detail, r.detected_at,
               c.name AS component_name, c.ecosystem AS component_ecosystem,
               p.name AS project_name
          FROM supply_chain_risks r
          LEFT JOIN sbom_components c ON c.id = r.component_id
          LEFT JOIN sca_projects p ON p.id = r.project_id
          {where}
         ORDER BY array_position({_SEV_ARRAY}, r.severity) DESC,
                  r.detected_at DESC
         LIMIT ${len(args_list) - 1} OFFSET ${len(args_list)}
    """
    async with pool.acquire() as con:
        total = await con.fetchval(sql_count, *args)
        rows = await con.fetch(sql, *args_list)
    items = [_row_to_risk(r) for r in rows]
    return SupplyChainRiskPage(
        items=items, total=int(total or 0), limit=limit, offset=offset
    )
