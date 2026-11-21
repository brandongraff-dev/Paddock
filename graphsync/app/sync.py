"""Mirror the Postgres asset graph into Neo4j.

Reads assets, asset_edges and open-finding severities from Postgres and
upserts them into Neo4j with idempotent MERGE:

    (:Asset {id, kind, value, blast_score, env, cost, crown, entry,
             max_severity, kev})
    (:Asset)-[:EDGE {kind, weight}]->(:Asset)     # both directions written
    (:Asset)-[:HAS_FINDING]->(:Finding {id, severity, kev})

* ``cost`` is the exploit entry-cost of the node (mirrors attackpath.py),
  computed from the node's open-finding severities. Each directed EDGE carries
  ``weight`` = the entry-cost of the node it *enters*, so a directed path's
  summed weight equals the node-weighted path cost (sources excluded).
* Incremental sync uses the ``neo4j_sync`` cursor: assets/edges/findings whose
  ``last_seen``/``first_seen`` advanced past the cursor. ``full=True`` rebuilds
  everything (used by ``POST /resync``).

The mapping helpers are pure and unit-testable; the orchestration touches the
DB + Neo4j wrapper. Nothing here exploits or mutates the source graph.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Iterable

from . import queries

log = logging.getLogger(__name__)

# Crown-jewel / source classification tokens (mirror attackpath.py).
DATA_STORE_TOKENS: tuple[str, ...] = (
    "mongodb",
    "elasticsearch",
    "redis",
    "postgresql",
    "postgres",
    "mysql",
)


# ---------------------------------------------------------------------------
# pure classification + mapping
# ---------------------------------------------------------------------------
def is_kev_finding(finding: dict[str, Any]) -> bool:
    md = finding.get("metadata") or {}
    return bool(md.get("kev") or md.get("known_exploited"))


def classify_crown(asset: dict[str, Any]) -> bool:
    """True if the asset is a crown-jewel target. Mirrors classify_target."""
    kind = asset.get("kind")
    md = asset.get("metadata") or {}
    value = (asset.get("value") or "").lower()
    if kind == "secret_candidate":
        return True
    if md.get("sensitive") is True or md.get("crown_jewel") is True:
        return True
    if kind == "technology" and any(tok in value for tok in DATA_STORE_TOKENS):
        return True
    if kind == "endpoint" and md.get("env") == "prod" and md.get("sensitive") is True:
        return True
    return False


def classify_entry(asset: dict[str, Any]) -> bool:
    """True if the asset is an internet-facing entry point. Mirrors
    classify_source (graph-available signals only)."""
    kind = asset.get("kind")
    md = asset.get("metadata") or {}
    if kind == "endpoint":
        return True
    if md.get("public") is True:
        return True
    return False


def finding_node_props(row: dict[str, Any]) -> dict[str, Any]:
    """Postgres finding row -> Finding MERGE params."""
    return {
        "id": row["id"],
        "asset_id": row["asset_id"],
        "severity": row.get("severity"),
        "kev": is_kev_finding(row),
    }


def group_finding_severities(
    findings: Iterable[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """asset_id -> {severities:[...], kev:bool} over open findings."""
    out: dict[str, dict[str, Any]] = {}
    for f in findings:
        aid = f["asset_id"]
        agg = out.setdefault(aid, {"severities": [], "kev": False})
        sev = f.get("severity")
        if sev:
            agg["severities"].append(sev)
        if is_kev_finding(f):
            agg["kev"] = True
    return out


def asset_node_props(
    row: dict[str, Any], severities: list[str], kev: bool
) -> dict[str, Any]:
    """Postgres asset row + its finding severities -> Asset MERGE params."""
    md = row.get("metadata") or {}
    blast = md.get("blast_score")
    try:
        blast = float(blast) if blast is not None else None
    except (TypeError, ValueError):
        blast = None
    entry = classify_entry(row)
    return {
        "id": row["id"],
        "kind": row.get("kind"),
        "value": row.get("value"),
        "blast_score": blast,
        "env": md.get("env"),
        "crown": classify_crown(row),
        "entry": entry,
        "max_severity": queries.max_severity(severities),
        "kev": kev,
        # Entry-cost from the shared model; sources still store their real
        # cost (query-time reduce excludes the source node anyway).
        "cost": queries.node_entry_cost(severities, kev),
    }


def edge_rows(
    edges: Iterable[dict[str, Any]], cost_map: dict[str, int]
) -> list[dict[str, Any]]:
    """Expand each undirected Postgres edge into two directed MERGE rows, each
    weighted by the entry-cost of the node it enters."""
    out: list[dict[str, Any]] = []
    for e in edges:
        src, dst, kind = e["src"], e["dst"], e["kind"]
        if src == dst:
            continue
        out.append({
            "src": src, "dst": dst, "kind": kind,
            "weight": float(cost_map.get(dst, queries.BASE_ENTRY_COST)),
        })
        out.append({
            "src": dst, "dst": src, "kind": kind,
            "weight": float(cost_map.get(src, queries.BASE_ENTRY_COST)),
        })
    return out


# ---------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------
class SyncEngine:
    def __init__(self, db: Any, neo: Any) -> None:
        self._db = db
        self._neo = neo

    async def run(self, *, full: bool = False) -> dict[str, Any]:
        """One sync pass. Returns a summary dict. Raises if Neo4j is down so
        the caller can apply backoff; the service itself stays up."""
        started = datetime.now(timezone.utc)
        since: datetime | None = None
        if not full:
            cursor = await self._db.get_cursor()
            since = cursor.get("last_synced") if cursor else None

        assets = await self._db.fetch_assets(since)
        edges = await self._db.fetch_edges(since)

        # Universe of assets we must cost: changed assets + every edge endpoint
        # (an unchanged endpoint still needs a node + correct edge weight).
        universe: set[str] = {a["id"] for a in assets}
        for e in edges:
            universe.add(e["src"])
            universe.add(e["dst"])

        # Open findings: for a full rebuild take all; incrementally take the
        # findings for the whole universe so costs are always consistent.
        if full:
            findings = await self._db.fetch_open_findings(since=None)
        else:
            findings = await self._db.fetch_findings_for_assets(sorted(universe))

        sev_by_asset = group_finding_severities(findings)
        cost_map: dict[str, int] = {}
        for aid in universe:
            agg = sev_by_asset.get(aid, {"severities": [], "kev": False})
            cost_map[aid] = queries.node_entry_cost(agg["severities"], agg["kev"])

        # Build MERGE payloads.
        asset_payload: list[dict[str, Any]] = []
        by_id = {a["id"]: a for a in assets}
        for aid in sorted(universe):
            agg = sev_by_asset.get(aid, {"severities": [], "kev": False})
            row = by_id.get(aid)
            if row is None:
                # Edge endpoint we didn't fetch as "changed": fetch-less stub
                # so MERGE at least creates the node with a correct cost.
                row = {"id": aid, "kind": None, "value": None, "metadata": {}}
            asset_payload.append(
                asset_node_props(row, agg["severities"], agg["kev"])
            )

        finding_payload = [finding_node_props(f) for f in findings]
        edge_payload = edge_rows(edges, cost_map)

        if full:
            await self._neo.wipe()
        await self._neo.ensure_schema()
        await self._neo.merge_assets(asset_payload)
        await self._neo.merge_findings(finding_payload)
        await self._neo.merge_edges(edge_payload)

        await self._db.set_cursor(
            last_synced=started,
            stats={
                "last_sync": started.isoformat(),
                "mode": "full" if full else "incremental",
                "assets": len(asset_payload),
                "edges": len(edge_payload),
                "findings": len(finding_payload),
            },
        )
        summary = {
            "mode": "full" if full else "incremental",
            "assets": len(asset_payload),
            "edges": len(edge_payload),
            "findings": len(finding_payload),
            "since": since.isoformat() if since else None,
        }
        log.info("sync pass: %s", summary)
        return summary
