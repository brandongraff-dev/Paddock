"""Blast-radius scorer.

Score ∈ [0, 100]. Components:

* severity base (info=5, low=20, medium=50, high=75, critical=95)
* +1 per reachable neighbor within depth 2 (edge kinds restricted to
  hosts/runs/resolves_to/references), capped at +15
* +10 if the finding's KEV flag is set OR epss ≥ 0.5
* +10 if any incoming edge (depth ≤ 2) has metadata.public=true, or the
  finding's asset is itself reachable from an endpoint

The result is written to findings.metadata.blast_score via the
orchestrator PATCH endpoint, so the audit log picks it up.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from ..db import Database
from ..orchestrator import OrchestratorClient
from .graph import BLAST_EDGE_KINDS, Graph

log = logging.getLogger(__name__)


SEVERITY_BASE: dict[str, int] = {
    "info": 5,
    "low": 20,
    "medium": 50,
    "high": 75,
    "critical": 95,
}


class BlastScorer:
    def __init__(self, db: Database, orch: Optional[OrchestratorClient] = None) -> None:
        self._db = db
        self._graph = Graph(db)
        self._orch = orch

    async def score_finding(
        self, finding: dict[str, Any]
    ) -> dict[str, Any]:
        """Return a dict {score, components, finding_id}."""
        base = SEVERITY_BASE.get(finding.get("severity", "info"), 20)

        # Neighborhood bonus
        neighbors = await self._graph.neighbors(
            finding["asset_id"], depth=2, kinds=BLAST_EDGE_KINDS, limit=256
        )
        neigh_bonus = min(len(neighbors), 15)

        # KEV / EPSS bonus
        md = finding.get("metadata") or {}
        kev = bool(md.get("kev") or md.get("known_exploited"))
        epss = finding.get("epss")
        try:
            epss_v = float(epss) if epss is not None else 0.0
        except (TypeError, ValueError):
            epss_v = 0.0
        kev_bonus = 10 if (kev or epss_v >= 0.5) else 0

        # Public exposure bonus
        public_bonus = (
            10
            if await self._graph.public_exposure(finding["asset_id"])
            else 0
        )

        raw = base + neigh_bonus + kev_bonus + public_bonus
        score = max(0, min(100, raw))

        return {
            "finding_id": str(finding["id"]),
            "asset_id": str(finding["asset_id"]),
            "score": score,
            "components": {
                "severity_base": base,
                "neighbor_bonus": neigh_bonus,
                "kev_bonus": kev_bonus,
                "public_bonus": public_bonus,
                "neighbor_count": len(neighbors),
                "kev": kev,
                "epss": epss_v,
            },
        }

    async def score_and_persist(self, finding_id: str) -> Optional[dict[str, Any]]:
        row = await self._db.fetchrow(
            """
            SELECT id::text, asset_id::text, severity, cvss, epss,
                   status, metadata, evidence
            FROM findings WHERE id = $1::uuid
            """,
            finding_id,
        )
        if row is None:
            return None
        result = await self.score_finding(dict(row))
        if self._orch is not None:
            # merge-patch into metadata
            md = dict(row["metadata"] or {})
            md["blast_score"] = result["score"]
            md["blast_components"] = result["components"]
            await self._orch.patch_finding(
                str(row["id"]), {"metadata": md}
            )
        return result

    async def recompute_all_open(self, limit: int = 2000) -> int:
        """Re-score every open finding. Returns count scored."""
        rows = await self._db.fetch(
            """
            SELECT id::text FROM findings
            WHERE status = 'open'
            ORDER BY last_seen DESC
            LIMIT $1
            """,
            limit,
        )
        n = 0
        for r in rows:
            try:
                await self.score_and_persist(r["id"])
                n += 1
            except Exception:
                log.exception("blast score failed for finding %s", r["id"])
        return n
