"""Code findings (SAST) read API (Tier 4).

The codeanalysis service (`codeanalysis/`, HTTP :8097) runs Semgrep (or a
bundled fallback taint scanner) over first-party source and writes each hit to
`code_findings` (plus a mirrored unified `findings` row). It also re-grades
`sbom_component_vulns.reachability`. This router is *read-only*: it serves the
code findings list (paged, with the source->sink dataflow trace) and detail.

- `GET /v1/code-findings?project=&severity=&limit=&offset=`  paged envelope.
- `GET /v1/code-findings/{id}`                                full row + dataflow.

The reachability roll-up itself rides on `GET /v1/sbom/components` (see
`sbom.py`): each component row carries the worst reachability among its vulns
plus a `reachable_vuln_count`, computed in the same grouped query (no N+1).

Nothing here scans or executes anything -- the codeanalysis service reads
source as inert data; this surface only reads what it wrote.
"""
from __future__ import annotations

import json
import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from ..db import get_pool
from ..models import CodeFindingOut, CodeFindingPage, Severity

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/code-findings", tags=["code"])

_SEV_ARRAY = "ARRAY['info','low','medium','high','critical']"

_CODE_COLS = (
    "cf.id, cf.project_id, cf.asset_id, cf.finding_id, cf.engine, cf.rule, "
    "cf.message, cf.severity, cf.file, cf.start_line, cf.end_line, cf.source, "
    "cf.sink, cf.dataflow, cf.cwe, cf.detected_at, cf.metadata, "
    "p.name AS project_name"
)
_CODE_FROM = "FROM code_findings cf LEFT JOIN sca_projects p ON p.id = cf.project_id"


def _try_uuid(v: str) -> UUID | None:
    try:
        return UUID(v)
    except (ValueError, TypeError):
        return None


def _row_to_code_finding(row) -> CodeFindingOut:
    d = dict(row)
    for col in ("dataflow",):
        if isinstance(d.get(col), str):
            d[col] = json.loads(d[col])
        elif d.get(col) is None:
            d[col] = []
    if isinstance(d.get("metadata"), str):
        d["metadata"] = json.loads(d["metadata"])
    elif d.get("metadata") is None:
        d["metadata"] = {}
    return CodeFindingOut.model_validate(d)


def _code_filters(
    project: str | None,
    severity: Severity | None,
) -> tuple[list[str], list[Any]]:
    clauses: list[str] = []
    args: list[Any] = []
    if project is not None:
        pid = _try_uuid(project)
        if pid is not None:
            args.append(pid)
            clauses.append(f"cf.project_id = ${len(args)}")
        else:
            args.append(project)
            clauses.append(
                f"cf.project_id = (SELECT id FROM sca_projects WHERE name = ${len(args)})"
            )
    if severity is not None:
        args.append(severity)
        clauses.append(f"cf.severity = ${len(args)}")
    return clauses, args


@router.get("", response_model=CodeFindingPage)
async def list_code_findings(
    project: str | None = Query(None, description="project id (uuid) or name"),
    severity: Severity | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    pool=Depends(get_pool),
):
    """Paged code findings, highest severity first then newest."""
    clauses, args = _code_filters(project, severity)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    sql_count = f"SELECT COUNT(*) FROM code_findings cf {where}"
    args_list = list(args)
    args_list.extend([limit, offset])
    sql = f"""
        SELECT {_CODE_COLS}
          {_CODE_FROM}
          {where}
         ORDER BY array_position({_SEV_ARRAY}, cf.severity) DESC,
                  cf.detected_at DESC
         LIMIT ${len(args_list) - 1} OFFSET ${len(args_list)}
    """
    async with pool.acquire() as con:
        total = await con.fetchval(sql_count, *args)
        rows = await con.fetch(sql, *args_list)
    items = [_row_to_code_finding(r) for r in rows]
    return CodeFindingPage(
        items=items, total=int(total or 0), limit=limit, offset=offset
    )


@router.get("/{code_finding_id}", response_model=CodeFindingOut)
async def get_code_finding(code_finding_id: UUID, pool=Depends(get_pool)):
    """A single code finding with its full source->sink dataflow trace."""
    async with pool.acquire() as con:
        row = await con.fetchrow(
            f"SELECT {_CODE_COLS} {_CODE_FROM} WHERE cf.id = $1",
            code_finding_id,
        )
    if row is None:
        raise HTTPException(status_code=404, detail="code finding not found")
    return _row_to_code_finding(row)
