"""Pure Cypher builders + the exploit-cost / weight model.

Everything here is a *pure* function: given inputs it returns a
``(cypher, params)`` pair (or a number). No Neo4j, no I/O. This keeps the
cost model and the generated Cypher unit-testable with no live database and
makes query behaviour deterministic.

The node-weight model mirrors ``correlation/app/engine/attackpath.py``:

    entry_cost(node) = max(1, BASE_ENTRY_COST - bonus)
    bonus = KEV(8) else critical(6) else high(4) else 0   (capped at BONUS_CAP)

Sources (query origins) contribute no cost — the path total sums the entry
cost of every node *after* the source, which is exactly the sum of the
per-relationship ``weight`` (= entry cost of the node the edge enters) that
``sync.py`` writes onto each directed EDGE relationship.

SAFETY: user-supplied values (asset ids, kinds) are ALWAYS passed as Cypher
parameters, never concatenated into the query string. The only values
interpolated into the query text are integer hop bounds — Cypher forbids
parameterised variable-length bounds — and those are coerced to ``int`` and
clamped first, so they can never carry injection.
"""
from __future__ import annotations

from typing import Any, Optional

# ---------------------------------------------------------------------------
# Cost model constants (mirror attackpath.py)
# ---------------------------------------------------------------------------
BASE_ENTRY_COST = 10
BONUS_KEV = 8
BONUS_CRITICAL = 6
BONUS_HIGH = 4
BONUS_CAP = 9
FLOOR_COST = 1

SEVERITY_RANK: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
_RANK_TO_SEVERITY: dict[int, str] = {v: k for k, v in SEVERITY_RANK.items()}

# Hard caps so an integer bound interpolated into Cypher is always sane.
MAX_HOPS_CAP = 12
MAX_DEPTH_CAP = 6
DEFAULT_MAX_HOPS = 8
DEFAULT_DEPTH = 2
NEIGHBORHOOD_CAP = 500


# ---------------------------------------------------------------------------
# Weight model (pure)
# ---------------------------------------------------------------------------
def severity_bonus(severities: list[str], kev: bool) -> int:
    """The single strongest severity signal among a node's open findings.

    KEV dominates (8), else critical (6), else high (4), else 0. Capped at
    BONUS_CAP. Mirrors ``node_entry_bonus`` in attackpath.py (graph nodes
    carry severity + a kev flag only, so the exposed-file stack bonus is not
    represented here).
    """
    bonus = 0
    if kev:
        bonus = BONUS_KEV
    elif "critical" in severities:
        bonus = BONUS_CRITICAL
    elif "high" in severities:
        bonus = BONUS_HIGH
    return min(BONUS_CAP, bonus)


def node_entry_cost(severities: list[str], kev: bool, *, is_source: bool = False) -> int:
    """Cost to step onto a node. Sources are free; otherwise floored at 1."""
    if is_source:
        return 0
    return max(FLOOR_COST, BASE_ENTRY_COST - severity_bonus(severities, kev))


def max_severity(severities: list[str]) -> Optional[str]:
    """Highest severity label in a list, or None when empty."""
    best = -1
    for s in severities:
        best = max(best, SEVERITY_RANK.get(s, -1))
    return _RANK_TO_SEVERITY.get(best)


# ---------------------------------------------------------------------------
# bound helpers
# ---------------------------------------------------------------------------
def _clamp_hops(value: Any, default: int = DEFAULT_MAX_HOPS) -> int:
    try:
        v = int(value)
    except (TypeError, ValueError):
        v = default
    return max(1, min(MAX_HOPS_CAP, v))


def _clamp_depth(value: Any, default: int = DEFAULT_DEPTH) -> int:
    try:
        v = int(value)
    except (TypeError, ValueError):
        v = default
    return max(1, min(MAX_DEPTH_CAP, v))


# ---------------------------------------------------------------------------
# /paths
# ---------------------------------------------------------------------------
def build_paths_cypher(
    *,
    source: Optional[str] = None,
    target: Optional[str] = None,
    source_kinds: Optional[list[str]] = None,
    max_hops: Any = DEFAULT_MAX_HOPS,
    limit: int = 10,
    apoc: bool = False,
) -> tuple[str, dict[str, Any]]:
    """Exploit-weighted shortest paths between a source and a target.

    * ``source``/``target`` given  -> paths between those two asset ids.
    * ``source`` omitted           -> any internet-facing entry node
      (optionally restricted to ``source_kinds``).
    * ``target`` omitted           -> any crown-jewel node.

    When ``apoc`` is true the query uses ``apoc.algo.dijkstra`` over the
    directed EDGE relationships weighted by the per-edge ``weight`` property
    (true node-weighted shortest path). Otherwise it uses a bounded
    ``allShortestPaths`` (hop-shortest) and orders the results by the summed
    exploit weight — the APOC-free fallback the contract calls for.

    Ordering is fully deterministic (cost, then hop count, then the node-id
    sequence) so tests over a fixed graph are stable.
    """
    hops = _clamp_hops(max_hops)
    params: dict[str, Any] = {"limit": int(limit)}

    # --- endpoint anchors (all user values go through params) --------------
    if source is not None:
        src_pat = "(s:Asset {id: $source})"
        params["source"] = source
    elif source_kinds:
        src_pat = "(s:Asset)"
        params["source_kinds"] = list(source_kinds)
    else:
        src_pat = "(s:Asset)"

    if target is not None:
        dst_pat = "(t:Asset {id: $target})"
        params["target"] = target
    else:
        dst_pat = "(t:Asset)"

    where: list[str] = []
    if source is None:
        if source_kinds:
            where.append("s.kind IN $source_kinds")
        where.append("s.entry = true")
    if target is None:
        where.append("t.crown = true")
    # Never let source == target when anchoring by class.
    if source is None or target is None:
        where.append("s <> t")
    where_clause = ("WHERE " + " AND ".join(where) + "\n") if where else ""

    if apoc:
        cypher = (
            f"MATCH {src_pat}, {dst_pat}\n"
            f"{where_clause}"
            "CALL apoc.algo.dijkstra(s, t, 'EDGE>', 'weight') "
            "YIELD path AS p, weight AS total_cost\n"
            "WITH p, total_cost, nodes(p) AS ns\n"
            "WHERE length(p) <= " + str(hops) + "\n"
            "RETURN [n IN ns | n.id] AS node_ids,\n"
            "       [n IN ns | {id: n.id, kind: n.kind, value: n.value, "
            "blast_score: n.blast_score, env: n.env, "
            "max_severity: n.max_severity, kev: coalesce(n.kev, false)}] AS hops,\n"
            "       total_cost AS total_cost,\n"
            "       length(p) AS hop_count\n"
            "ORDER BY total_cost ASC, hop_count ASC, node_ids ASC\n"
            "LIMIT $limit"
        )
    else:
        cypher = (
            "MATCH p = allShortestPaths("
            f"{src_pat}-[:EDGE*1.." + str(hops) + f"]->{dst_pat})\n"
            f"{where_clause}"
            "WITH p, nodes(p) AS ns,\n"
            "     reduce(c = 0.0, r IN relationships(p) | "
            "c + coalesce(r.weight, 1.0)) AS total_cost\n"
            "RETURN [n IN ns | n.id] AS node_ids,\n"
            "       [n IN ns | {id: n.id, kind: n.kind, value: n.value, "
            "blast_score: n.blast_score, env: n.env, "
            "max_severity: n.max_severity, kev: coalesce(n.kev, false)}] AS hops,\n"
            "       total_cost AS total_cost,\n"
            "       length(p) AS hop_count\n"
            "ORDER BY total_cost ASC, hop_count ASC, node_ids ASC\n"
            "LIMIT $limit"
        )
    return cypher, params


# ---------------------------------------------------------------------------
# /blast/{asset_id}
# ---------------------------------------------------------------------------
def build_blast_cypher(asset_id: str, depth: Any = DEFAULT_DEPTH) -> tuple[str, dict[str, Any]]:
    """k-hop neighborhood size + severities + reachable crown-jewel count.

    Undirected reachability (blast radius does not care about edge direction).
    Severity aggregation is returned as a raw list so the caller reduces the
    max via the shared cost model (deterministic, no Cypher severity ordering).
    """
    d = _clamp_depth(depth)
    cypher = (
        "MATCH (a:Asset {id: $asset_id})\n"
        "OPTIONAL MATCH (a)-[:EDGE*1.." + str(d) + "]-(n:Asset)\n"
        "WITH a, collect(DISTINCT n) AS reached\n"
        "WITH a, reached, [x IN reached WHERE x.crown = true] AS crowns\n"
        "OPTIONAL MATCH (m:Asset)-[:HAS_FINDING]->(f:Finding)\n"
        "WHERE m = a OR m IN reached\n"
        "RETURN size(reached) AS neighborhood_size,\n"
        "       size(crowns) AS reachable_crown_jewels,\n"
        "       collect(DISTINCT f.severity) AS severities,\n"
        "       any(x IN collect(DISTINCT f.kev) WHERE x = true) AS kev_present\n"
    )
    return cypher, {"asset_id": asset_id}


# ---------------------------------------------------------------------------
# /neighborhood/{asset_id}
# ---------------------------------------------------------------------------
def build_neighborhood_cypher(
    asset_id: str, depth: Any = DEFAULT_DEPTH, cap: int = NEIGHBORHOOD_CAP
) -> tuple[str, dict[str, Any]]:
    """Nodes + edges subgraph for visualization, capped at `cap` nodes.

    Returns node rows and the undirected edge list (deduplicated by emitting
    each pair once, ``x.id < y.id``). Deterministic ordering throughout.
    """
    d = _clamp_depth(depth)
    cap = max(1, min(NEIGHBORHOOD_CAP, int(cap)))
    cypher = (
        "MATCH (a:Asset {id: $asset_id})\n"
        "OPTIONAL MATCH (a)-[:EDGE*1.." + str(d) + "]-(m:Asset)\n"
        "WITH collect(DISTINCT a) + collect(DISTINCT m) AS raw\n"
        "WITH [x IN raw WHERE x IS NOT NULL] AS allnodes\n"
        "WITH allnodes[0.." + str(cap) + "] AS nodes\n"
        "WITH nodes, [n IN nodes | n.id] AS node_ids\n"
        "UNWIND nodes AS n\n"
        "WITH node_ids,\n"
        "     collect({id: n.id, kind: n.kind, value: n.value, "
        "blast_score: n.blast_score, env: n.env, crown: coalesce(n.crown, false), "
        "max_severity: n.max_severity}) AS node_rows\n"
        "OPTIONAL MATCH (x:Asset)-[r:EDGE]->(y:Asset)\n"
        "WHERE x.id IN node_ids AND y.id IN node_ids AND x.id < y.id\n"
        "RETURN node_rows AS nodes,\n"
        "       collect(DISTINCT {source: x.id, target: y.id, kind: r.kind}) AS edges\n"
        "ORDER BY size(node_rows) DESC\n"
    )
    return cypher, {"asset_id": asset_id}


# ---------------------------------------------------------------------------
# /stats helpers
# ---------------------------------------------------------------------------
STATS_CYPHER = (
    "MATCH (a:Asset) WITH count(a) AS assets\n"
    "OPTIONAL MATCH ()-[e:EDGE]->() WITH assets, count(e) AS edges\n"
    "OPTIONAL MATCH (:Asset)-[hf:HAS_FINDING]->(:Finding) "
    "WITH assets, edges, count(hf) AS findings\n"
    "RETURN assets AS asset_nodes, edges AS edge_rels, findings AS finding_rels"
)

APOC_PROBE_CYPHER = (
    "RETURN apoc.version() AS version"
)
