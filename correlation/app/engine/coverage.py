"""Path-coverage engine: the headline "have we shut the door?" number.

Attack-surface tools hand you a pile of *possible* problems. The question a
CISO, board or insurer actually pays for is the inverse: of all the routes an
attacker could take to our crown jewels, what share have we PROVEN closed,
watched with a tripwire, or consciously risk-accepted -- versus still open?

This engine turns the correlation service's attack paths into that number.

For every current attack path (an internet-facing source -> crown-jewel route,
007_tier1 attack_paths) it reads the verification + lifecycle state of the
findings ON that path and classifies the path:

  proven_closed   every flagged hop has been re-checked non-destructively and
                  is no longer reproducible (findings.exploitability =
                  'not_reproducible'): the door at each known hole is shut.
  risk_accepted   every flagged hop is a consciously accepted / false-positive /
                  won't-fix finding (findings.status in the suppressed set).
  tripwired       a decoy / canary watches the still-open route. (Reserved;
                  always 0 until the tripwire feature lands -- the column exists
                  so the metric is stable when it does.)
  open            anything else, including a structurally reachable path with no
                  known hole yet (reachable but unproven).

coverage_pct = (proven_closed + tripwired + risk_accepted) / total * 100.

It also labels each HOP as `proven` or `inferred` evidence, so a path can show
which hops are backed by a confirmed check / observed traffic and which are
only structural inference -- the "evidence per hop" story. `proven_hop_paths`
counts paths with at least one proven hop.

Writes one append-only row to coverage_snapshots per run (a time series, like
usage_snapshots). Pure classification is unit-testable with no database.
"""
from __future__ import annotations

import json
import logging
import time
from decimal import Decimal
from typing import Any, Optional

from ..db import Database

log = logging.getLogger(__name__)

# Finding states that mean "a human consciously decided to live with this".
SUPPRESSED_STATUSES: frozenset[str] = frozenset(
    {"accepted", "accepted_risk", "false_positive", "wontfix"}
)
# Verification verdicts (schema/026_verification).
VERDICT_CONFIRMED = "confirmed"
VERDICT_NOT_REPRODUCIBLE = "not_reproducible"


# ----------------------------------------------------------------------------
# Pure classification (no DB)
# ----------------------------------------------------------------------------

def _onpath_finding_ids(path: dict[str, Any]) -> list[str]:
    """All finding ids referenced by a path's hops, de-duplicated, ordered."""
    seen: dict[str, None] = {}
    for hop in path.get("hops") or []:
        for fid in hop.get("finding_ids") or []:
            seen.setdefault(str(fid), None)
    return list(seen)


def classify_path(
    path: dict[str, Any], findings: dict[str, dict[str, Any]]
) -> str:
    """Return one of: proven_closed | risk_accepted | tripwired | open.

    ``findings`` maps finding_id -> {"status", "exploitability"} for every
    on-path finding (missing ids are treated as open/unverified).
    """
    fids = _onpath_finding_ids(path)
    onpath = [findings[f] for f in fids if f in findings]

    # Tripwire feature not yet shipped; the hook stays so the metric is stable.
    if path.get("tripwired") is True:
        return "tripwired"

    if onpath:
        if all(f.get("exploitability") == VERDICT_NOT_REPRODUCIBLE for f in onpath):
            return "proven_closed"
        if all((f.get("status") or "") in SUPPRESSED_STATUSES for f in onpath):
            return "risk_accepted"
    return "open"


def path_has_proven_hop(
    path: dict[str, Any], findings: dict[str, dict[str, Any]]
) -> bool:
    """True if any on-path finding has been CONFIRMED by a safe check
    (evidence-backed hop) rather than merely inferred from graph structure."""
    for fid in _onpath_finding_ids(path):
        f = findings.get(fid)
        if f and f.get("exploitability") == VERDICT_CONFIRMED:
            return True
    return False


def label_hop_evidence(
    hop: dict[str, Any], findings: dict[str, dict[str, Any]]
) -> dict[str, str]:
    """Label a single hop as proven vs inferred, with a basis string.

    proven  -- a finding on this hop is CONFIRMED (safe-check reproduced it) or
               NOT_REPRODUCIBLE (safe-check shut it): either way the hop's state
               is backed by evidence, not just topology.
    inferred -- the hop is known only from the asset graph.
    """
    for fid in hop.get("finding_ids") or []:
        f = findings.get(str(fid))
        if not f:
            continue
        verdict = f.get("exploitability")
        if verdict == VERDICT_CONFIRMED:
            return {"evidence": "proven", "basis": "safe_check_confirmed"}
        if verdict == VERDICT_NOT_REPRODUCIBLE:
            return {"evidence": "proven", "basis": "safe_check_not_reproducible"}
    return {"evidence": "inferred", "basis": "graph_structure"}


def summarize(
    paths: list[dict[str, Any]],
    findings: dict[str, dict[str, Any]],
    *,
    crown_jewels_total: int = 0,
    crown_jewels_exposed: int = 0,
    choke_point_count: int = 0,
) -> dict[str, Any]:
    """Fold a set of paths into a coverage_snapshots row (minus tenant/time)."""
    total = len(paths)
    buckets = {"proven_closed": 0, "risk_accepted": 0, "tripwired": 0, "open": 0}
    proven_hop_paths = 0
    for p in paths:
        buckets[classify_path(p, findings)] += 1
        if path_has_proven_hop(p, findings):
            proven_hop_paths += 1
    covered = buckets["proven_closed"] + buckets["tripwired"] + buckets["risk_accepted"]
    coverage_pct = round(100.0 * covered / total, 2) if total else 0.0
    return {
        "total_paths": total,
        "open_paths": buckets["open"],
        "proven_closed_paths": buckets["proven_closed"],
        "tripwired_paths": buckets["tripwired"],
        "risk_accepted_paths": buckets["risk_accepted"],
        "coverage_pct": coverage_pct,
        "crown_jewels_total": crown_jewels_total,
        "crown_jewels_exposed": crown_jewels_exposed,
        "choke_point_count": choke_point_count,
        "proven_hop_paths": proven_hop_paths,
    }


# ----------------------------------------------------------------------------
# Engine (DB-backed)
# ----------------------------------------------------------------------------

class CoverageEngine:
    def __init__(
        self,
        db: Database,
        redis: Any = None,
        events_stream: str = "stream:events",
    ) -> None:
        self._db = db
        self._redis = redis
        self._events_stream = events_stream

    def set_redis(self, redis: Any) -> None:
        self._redis = redis

    async def _load(self) -> dict[str, Any]:
        path_rows = await self._db.fetch(
            "SELECT id::text AS id, target_asset_id::text AS target_asset_id, "
            "hops, exploitability, kev_on_path FROM attack_paths"
        )
        paths: list[dict[str, Any]] = []
        finding_ids: set[str] = set()
        for r in path_rows:
            hops = r["hops"]
            if isinstance(hops, str):
                try:
                    hops = json.loads(hops)
                except (ValueError, TypeError):
                    hops = []
            p = {
                "id": r["id"],
                "target_asset_id": r["target_asset_id"],
                "hops": hops or [],
                "exploitability": r["exploitability"],
                "kev_on_path": r["kev_on_path"],
            }
            paths.append(p)
            for hop in p["hops"]:
                for fid in hop.get("finding_ids") or []:
                    finding_ids.add(str(fid))

        findings: dict[str, dict[str, Any]] = {}
        if finding_ids:
            frows = await self._db.fetch(
                "SELECT id::text AS id, status, exploitability FROM findings "
                "WHERE id = ANY($1::uuid[])",
                list(finding_ids),
            )
            findings = {
                r["id"]: {"status": r["status"], "exploitability": r["exploitability"]}
                for r in frows
            }

        cj_total = await self._db.fetchval(
            "SELECT COUNT(*) FROM crown_jewel_exposure"
        )
        cj_exposed = await self._db.fetchval(
            "SELECT COUNT(*) FROM crown_jewel_exposure WHERE proven_closed IS FALSE"
        )
        choke = await self._db.fetchval(
            "SELECT COUNT(*) FROM choke_points WHERE in_min_cut IS TRUE"
        )
        return {
            "paths": paths,
            "findings": findings,
            "crown_jewels_total": int(cj_total or 0),
            "crown_jewels_exposed": int(cj_exposed or 0),
            "choke_point_count": int(choke or 0),
        }

    async def _persist(self, snapshot: dict[str, Any]) -> str:
        """Append one coverage_snapshots row (time series). RLS fills tenant_id."""
        async with self._db.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO coverage_snapshots (
                  total_paths, open_paths, proven_closed_paths, tripwired_paths,
                  risk_accepted_paths, coverage_pct, crown_jewels_total,
                  crown_jewels_exposed, choke_point_count, proven_hop_paths,
                  snapshot_at
                ) VALUES ($1,$2,$3,$4,$5,$6::numeric,$7,$8,$9,$10,NOW())
                RETURNING id::text AS id
                """,
                snapshot["total_paths"],
                snapshot["open_paths"],
                snapshot["proven_closed_paths"],
                snapshot["tripwired_paths"],
                snapshot["risk_accepted_paths"],
                Decimal(str(snapshot["coverage_pct"])),
                snapshot["crown_jewels_total"],
                snapshot["crown_jewels_exposed"],
                snapshot["choke_point_count"],
                snapshot["proven_hop_paths"],
            )
        return row["id"] if row else ""

    async def run(self) -> dict[str, Any]:
        started = time.monotonic()
        data = await self._load()
        snapshot = summarize(
            data["paths"],
            data["findings"],
            crown_jewels_total=data["crown_jewels_total"],
            crown_jewels_exposed=data["crown_jewels_exposed"],
            choke_point_count=data["choke_point_count"],
        )
        snap_id = await self._persist(snapshot)
        elapsed_ms = round((time.monotonic() - started) * 1000.0, 2)
        log.info(
            "coverage: %d paths, %.1f%% covered (%d open) in %.1fms",
            snapshot["total_paths"],
            snapshot["coverage_pct"],
            snapshot["open_paths"],
            elapsed_ms,
        )
        return {**snapshot, "snapshot_id": snap_id, "elapsed_ms": elapsed_ms}

    async def latest(self) -> Optional[dict[str, Any]]:
        row = await self._db.fetchrow(
            "SELECT total_paths, open_paths, proven_closed_paths, tripwired_paths, "
            "risk_accepted_paths, coverage_pct, crown_jewels_total, "
            "crown_jewels_exposed, choke_point_count, proven_hop_paths, snapshot_at "
            "FROM coverage_snapshots ORDER BY snapshot_at DESC LIMIT 1"
        )
        if row is None:
            return None
        d = dict(row)
        if d.get("coverage_pct") is not None:
            d["coverage_pct"] = float(d["coverage_pct"])
        return d
