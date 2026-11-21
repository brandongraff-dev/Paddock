"""MITRE ATT&CK mapping read API (Tier 3).

The correlation service maps each finding to ATT&CK techniques
(`finding_techniques`) and seeds the known-technique catalog
(`attack_technique_map`). This router is read-only.

- `GET /v1/attack/coverage`          tactic/technique coverage, counting DISTINCT
                                      findings per technique and per tactic.
- `GET /v1/attack/catalog`           the known-technique catalog rows.
- `GET /v1/findings/{id}/techniques` techniques mapped to one finding.

Nothing here describes how to execute a technique; it reports which of our
findings map to which ATT&CK coverage (defensive posture only).
"""
from __future__ import annotations

import json
import logging
from uuid import UUID

from fastapi import APIRouter, Depends

from ..db import get_pool
from ..models import (
    AttackCatalogOut,
    AttackCoverageOut,
    AttackTechniqueCoverage,
    FindingTechniqueOut,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/attack", tags=["attack"])
# `GET /v1/findings/{id}/techniques` lives under the findings path but is
# ATT&CK-owned, so it rides its own router (distinct path depth from the
# findings router's `/{finding_id}`, so there is no route collision).
finding_tech_router = APIRouter(prefix="/v1/findings", tags=["attack"])


@router.get("/coverage", response_model=AttackCoverageOut)
async def attack_coverage(pool=Depends(get_pool)):
    """ATT&CK coverage across all mapped findings.

    `by_technique` and `by_tactic` count DISTINCT findings (a finding mapped to
    the same tactic by two techniques counts once per tactic), and
    `total_findings_mapped` is the distinct finding count overall.
    """
    async with pool.acquire() as con:
        tech_rows = await con.fetch(
            """
            SELECT technique_id, technique, tactic,
                   COUNT(DISTINCT finding_id) AS c
              FROM finding_techniques
             GROUP BY technique_id, technique, tactic
             ORDER BY c DESC, technique_id ASC
            """
        )
        tactic_rows = await con.fetch(
            """
            SELECT tactic, COUNT(DISTINCT finding_id) AS c
              FROM finding_techniques
             GROUP BY tactic
             ORDER BY c DESC
            """
        )
        total = await con.fetchval(
            "SELECT COUNT(DISTINCT finding_id) FROM finding_techniques"
        )
    by_technique = [
        AttackTechniqueCoverage(
            technique_id=r["technique_id"],
            technique=r["technique"],
            tactic=r["tactic"],
            count=int(r["c"]),
        )
        for r in tech_rows
    ]
    by_tactic = {r["tactic"]: int(r["c"]) for r in tactic_rows}
    return AttackCoverageOut(
        by_tactic=by_tactic,
        by_technique=by_technique,
        total_findings_mapped=int(total or 0),
    )


@router.get("/catalog", response_model=list[AttackCatalogOut])
async def attack_catalog(pool=Depends(get_pool)):
    """The known-technique catalog (attack_technique_map), priority order."""
    async with pool.acquire() as con:
        rows = await con.fetch(
            """
            SELECT id, match, technique_id, technique, tactic, cwe,
                   priority, enabled
              FROM attack_technique_map
             ORDER BY priority ASC, technique_id ASC
            """
        )
    out: list[AttackCatalogOut] = []
    for r in rows:
        d = dict(r)
        if isinstance(d.get("match"), str):
            d["match"] = json.loads(d["match"])
        elif d.get("match") is None:
            d["match"] = {}
        out.append(AttackCatalogOut.model_validate(d))
    return out


@finding_tech_router.get(
    "/{finding_id}/techniques", response_model=list[FindingTechniqueOut]
)
async def finding_techniques(finding_id: UUID, pool=Depends(get_pool)):
    """ATT&CK techniques mapped to a single finding (highest confidence first)."""
    async with pool.acquire() as con:
        rows = await con.fetch(
            """
            SELECT id, finding_id, technique_id, technique, tactic, cwe,
                   confidence, mapped_at
              FROM finding_techniques
             WHERE finding_id = $1
             ORDER BY confidence DESC, technique_id ASC
            """,
            finding_id,
        )
    return [FindingTechniqueOut.model_validate(dict(r)) for r in rows]
