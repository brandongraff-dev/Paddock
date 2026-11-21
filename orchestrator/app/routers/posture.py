"""TLS posture grades.

- `GET  /v1/tls-grades`         paged, newest first, joins the asset for value.
- `GET  /v1/tls-grades/summary` count per grade bucket (A+..F, T).
- `POST /v1/tls-grades/bulk`    upsert by asset_id (the active worker's sink).

No endpoint here probes TLS; the active worker computes grades and posts them
through the bulk sink. This router only persists and serves them.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, Query

from ..db import get_pool
from ..models import (
    TlsGrade,
    TlsGradeBulkIn,
    TlsGradeBulkOut,
    TlsGradeOut,
    TlsGradePage,
    TlsGradeSummary,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/tls-grades", tags=["posture"])

# Every grade bucket, in report-card order, so /summary is zero-filled.
_GRADE_BUCKETS: tuple[str, ...] = ("A+", "A", "B", "C", "D", "E", "F", "T")

_LIST_COLS = (
    "g.id, g.asset_id, g.host, g.grade, g.score, g.protocols, g.weak_ciphers, "
    "g.issues, g.cert_expires, g.graded_at, a.value AS asset_value"
)

_BULK_SQL = """
INSERT INTO tls_grades (
    asset_id, host, grade, score, protocols, weak_ciphers, issues, cert_expires
) VALUES ($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7::jsonb,$8)
ON CONFLICT (asset_id) DO UPDATE SET
    host = EXCLUDED.host,
    grade = EXCLUDED.grade,
    score = EXCLUDED.score,
    protocols = EXCLUDED.protocols,
    weak_ciphers = EXCLUDED.weak_ciphers,
    issues = EXCLUDED.issues,
    cert_expires = EXCLUDED.cert_expires,
    graded_at = NOW()
RETURNING (xmax = 0) AS was_inserted
"""


def _row_to_grade(row) -> TlsGradeOut:
    d = dict(row)
    for col in ("protocols", "weak_ciphers", "issues"):
        if isinstance(d.get(col), str):
            d[col] = json.loads(d[col])
        elif d.get(col) is None:
            d[col] = []
    return TlsGradeOut.model_validate(d)


@router.post("/bulk", response_model=TlsGradeBulkOut)
async def bulk_upsert_grades(body: TlsGradeBulkIn, pool=Depends(get_pool)):
    inserted = 0
    updated = 0
    async with pool.acquire() as con:
        async with con.transaction():
            for item in body.items:
                was_inserted = await con.fetchval(
                    _BULK_SQL,
                    item.asset_id,
                    item.host,
                    item.grade,
                    item.score,
                    json.dumps(item.protocols),
                    json.dumps(item.weak_ciphers),
                    json.dumps(item.issues),
                    item.cert_expires,
                )
                if was_inserted:
                    inserted += 1
                else:
                    updated += 1
    return TlsGradeBulkOut(inserted=inserted, updated=updated)


# Declared before any dynamic path so the literal matches first.
@router.get("/summary", response_model=TlsGradeSummary)
async def grades_summary(pool=Depends(get_pool)):
    async with pool.acquire() as con:
        rows = await con.fetch(
            "SELECT grade, COUNT(*) AS c FROM tls_grades GROUP BY grade"
        )
    counts = {g: 0 for g in _GRADE_BUCKETS}
    total = 0
    for r in rows:
        counts[r["grade"]] = int(r["c"])
        total += int(r["c"])
    return TlsGradeSummary(counts=counts, total=total)


@router.get("", response_model=TlsGradePage)
async def list_grades(
    grade: TlsGrade | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    pool=Depends(get_pool),
):
    clauses: list[str] = []
    args: list[Any] = []
    if grade is not None:
        args.append(grade)
        clauses.append(f"g.grade = ${len(args)}")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    sql_count = f"SELECT COUNT(*) FROM tls_grades g {where}"
    args_list = list(args)
    args_list.extend([limit, offset])
    sql = f"""
        SELECT {_LIST_COLS}
          FROM tls_grades g
          LEFT JOIN assets a ON a.id = g.asset_id
          {where}
         ORDER BY g.score ASC, g.graded_at DESC
         LIMIT ${len(args_list) - 1} OFFSET ${len(args_list)}
    """
    async with pool.acquire() as con:
        total = await con.fetchval(sql_count, *args)
        rows = await con.fetch(sql, *args_list)
    items = [_row_to_grade(r) for r in rows]
    return TlsGradePage(items=items, total=int(total or 0), limit=limit, offset=offset)
