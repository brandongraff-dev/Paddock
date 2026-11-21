"""Provenance / lineage endpoints (schema 011).

- ``GET  /v1/provenance?subject_type=&subject_id=`` -- lineage for one item.
- ``POST /v1/provenance``                           -- record a lineage row.
- ``POST /v1/provenance/backfill`` (admin)          -- one-time backfill from
  existing ``source`` columns on assets/findings.
"""
from __future__ import annotations

import json
import logging
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from .. import provenance as prov_svc
from ..auth import require, require_scope
from ..db import get_pool
from ..models import (
    ProvenanceBackfillOut,
    ProvenanceIn,
    ProvenanceOut,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/provenance", tags=["provenance"])


@router.get("", response_model=list[ProvenanceOut])
async def get_provenance(
    subject_type: str = Query(..., min_length=1),
    subject_id: UUID = Query(...),
    pool=Depends(get_pool),
):
    rows = await prov_svc.fetch_for_subject(pool, subject_type, subject_id)
    return [ProvenanceOut.model_validate(r) for r in rows]


@router.post(
    "",
    response_model=ProvenanceOut,
    status_code=201,
    dependencies=[Depends(require_scope("write"))],
)
async def record_provenance(body: ProvenanceIn, pool=Depends(get_pool)):
    async with pool.acquire() as con:
        async with con.transaction():
            row = await prov_svc.record_one(
                con,
                subject_type=body.subject_type,
                subject_id=body.subject_id,
                source_service=body.source_service,
                source_detail=body.source_detail,
                method=body.method,
                evidence=body.evidence,
                confidence=body.confidence,
            )
    d = dict(row)
    if isinstance(d.get("evidence"), str):
        d["evidence"] = json.loads(d["evidence"])
    return ProvenanceOut.model_validate(d)


@router.post(
    "/backfill",
    response_model=ProvenanceBackfillOut,
    dependencies=[Depends(require("admin"))],
)
async def backfill_provenance(pool=Depends(get_pool)):
    created = await prov_svc.backfill(pool)
    return ProvenanceBackfillOut(created=created)
