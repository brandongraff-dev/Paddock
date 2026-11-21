"""Attack-path analysis engine.

DEFENSIVE feature. Computes how an intrusion *could* traverse the owner's
own asset graph, from an internet-facing source to a crown-jewel target,
so defenders can cut the paths. It reasons purely over graph structure +
existing open findings. It never generates exploitation steps, payloads,
or commands — the narrative describes the route and impact only, and is
passed through the same reject filter the chain narrative writer uses.

Algorithm (see docs/TIER1_CONTRACT.md "Attack-path engine"):

* Load the full asset graph + per-asset open-finding severities in bulk
  (no N+1).
* Classify sources (internet-facing) and targets (crown jewels).
* Give every node an *entry cost* (base 10 minus an exploitability bonus
  from its open findings; floor 1; sources cost 0).
* Run Dijkstra (heapq) over the UNDIRECTED edge set from every source,
  keeping the cheapest path to each reachable target (≤ 8 hops).
* Score each path, keep the top 50 by exploitability, and upsert them
  into `attack_paths` by fingerprint. Paths whose fingerprint was not
  seen in the latest run are pruned, all in one transaction, so the
  table always reflects the current graph.
* Publish an `attack_path_found` event for every newly-inserted path.

Everything is async; all SQL is parameterized asyncpg (no string-built
SQL with user data). Output is deterministic for a fixed graph.
"""
from __future__ import annotations

import hashlib
import heapq
import ipaddress
import json
import logging
import time
from decimal import Decimal
from typing import Any, Optional

from ..db import Database
from .policy import UnsafeRuleError, validate_narrative_text

log = logging.getLogger(__name__)


# ----------------------------------------------------------------------------
# Contract constants
# ----------------------------------------------------------------------------

# Well-known ports that make a `port` asset internet-facing when its parent
# IP sits inside a public scope CIDR.
WELL_KNOWN_PORTS: frozenset[str] = frozenset(
    {"80", "443", "8080", "8443", "22", "3389", "5432", "27017", "9200", "6379"}
)

# `technology` assets whose value names one of these are crown-jewel data
# stores.
DATA_STORE_TOKENS: tuple[str, ...] = (
    "mongodb",
    "elasticsearch",
    "redis",
    "postgresql",
    "postgres",
    "mysql",
)

SEVERITY_RANK: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
_RANK_TO_SEVERITY: dict[int, str] = {v: k for k, v in SEVERITY_RANK.items()}

# Node entry cost.
BASE_ENTRY_COST = 10
BONUS_KEV = 8
BONUS_CRITICAL = 6
BONUS_HIGH = 4
BONUS_EXPOSED_FILE = 5
BONUS_CAP = 9
MAX_HOPS = 8
TOP_N = 50

# Finding rule sources that add the "exposed file / leaked secret" bonus.
_FILE_BONUS_SOURCES: frozenset[str] = frozenset({"exposed_file", "secret_scan"})

# Narrative reject filter. The narrative must describe the route + impact,
# never exploitation. These tokens (plus the chain writer's own regex via
# validate_narrative_text) force a neutral fallback.
_REJECT_TOKENS: tuple[str, ...] = (
    "exploit",
    "payload",
    "shell",
    "cmd",
    "reverse shell",
    "union select",
    "/bin/",
    "nc -e",
    "msfvenom",
    "powershell -enc",
)


# ----------------------------------------------------------------------------
# Pure helpers (unit-testable without a database)
# ----------------------------------------------------------------------------

def is_kev_finding(finding: dict[str, Any]) -> bool:
    """A finding is KEV if its metadata flags it as known-exploited."""
    md = finding.get("metadata") or {}
    return bool(md.get("kev") or md.get("known_exploited"))


def node_entry_bonus(findings: list[dict[str, Any]]) -> int:
    """Exploitability bonus for a node, from its open findings.

    The severity tier contributes the single strongest signal (KEV 8, else
    critical 6, else high 4); an exposed_file/secret_scan finding adds a
    stackable 5. Total bonus is capped at 9.
    """
    sev_bonus = 0
    file_bonus = 0
    for f in findings:
        if is_kev_finding(f):
            sev_bonus = max(sev_bonus, BONUS_KEV)
        elif f.get("severity") == "critical":
            sev_bonus = max(sev_bonus, BONUS_CRITICAL)
        elif f.get("severity") == "high":
            sev_bonus = max(sev_bonus, BONUS_HIGH)
        if (f.get("rule_source") or "") in _FILE_BONUS_SOURCES:
            file_bonus = BONUS_EXPOSED_FILE
    return min(BONUS_CAP, sev_bonus + file_bonus)


def entry_cost(findings: list[dict[str, Any]], *, is_source: bool = False) -> int:
    """Cost to step onto a node. Sources are free; otherwise floor 1."""
    if is_source:
        return 0
    return max(1, BASE_ENTRY_COST - node_entry_bonus(findings))


def exploitability_score(total_cost: float, length: int) -> float:
    """0-100; shorter and more-exploitable paths score higher."""
    if length <= 0:
        return 0.0
    raw = 100.0 * (1.0 - (float(total_cost) / (10.0 * length)))
    return round(max(0.0, min(100.0, raw)), 2)


def path_fingerprint(asset_ids: list[str]) -> str:
    """Stable hash of the ordered hop asset_id sequence."""
    h = hashlib.sha256("|".join(asset_ids).encode("utf-8"))
    return h.hexdigest()


def max_severity(findings: list[dict[str, Any]]) -> Optional[str]:
    """Highest severity among a node's findings, or None when it has none."""
    best = -1
    for f in findings:
        best = max(best, SEVERITY_RANK.get(f.get("severity", "info"), -1))
    return _RANK_TO_SEVERITY.get(best)


def classify_source(
    asset: dict[str, Any],
    *,
    parent_ip: Optional[str] = None,
    public_nets: tuple[Any, ...] = (),
) -> tuple[bool, Optional[str]]:
    """Return (is_source, reason). See contract "Sources"."""
    kind = asset.get("kind")
    md = asset.get("metadata") or {}
    if kind == "endpoint":
        return True, "endpoint"
    if md.get("public") is True:
        return True, "public_metadata"
    if kind == "port" and str(asset.get("value")) in WELL_KNOWN_PORTS:
        if parent_ip and _ip_in_any(parent_ip, public_nets):
            return True, "public_port"
    return False, None


def classify_target(asset: dict[str, Any]) -> tuple[bool, Optional[str]]:
    """Return (is_target, reason). See contract "Targets"."""
    kind = asset.get("kind")
    md = asset.get("metadata") or {}
    value = (asset.get("value") or "").lower()
    if kind == "secret_candidate":
        return True, "secret_candidate"
    if md.get("sensitive") is True or md.get("crown_jewel") is True:
        return True, "sensitive"
    if kind == "technology" and any(tok in value for tok in DATA_STORE_TOKENS):
        return True, "data_store"
    if kind == "endpoint" and md.get("env") == "prod" and md.get("sensitive") is True:
        return True, "prod_sensitive"
    return False, None


def contains_unsafe_token(text: str) -> bool:
    """True if the text reads like exploitation guidance rather than impact."""
    if not text:
        return False
    low = text.lower()
    if any(tok in low for tok in _REJECT_TOKENS):
        return True
    try:
        validate_narrative_text(text)
    except UnsafeRuleError:
        return True
    return False


def safe_narrative(text: str, fallback: str) -> str:
    """Return `text` only if it is safe; otherwise the neutral fallback."""
    return fallback if contains_unsafe_token(text) else text


def _ip_in_any(ip: str, nets: tuple[Any, ...]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in nets)


# ----------------------------------------------------------------------------
# Engine
# ----------------------------------------------------------------------------

class AttackPathEngine:
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

    # -- bulk loaders -------------------------------------------------------

    async def _load_graph(self) -> dict[str, Any]:
        """Four bulk queries; no per-node round trips."""
        asset_rows = await self._db.fetch(
            "SELECT id::text AS id, kind, value, metadata FROM assets"
        )
        edge_rows = await self._db.fetch(
            "SELECT src_id::text AS src, dst_id::text AS dst, kind "
            "FROM asset_edges"
        )
        finding_rows = await self._db.fetch(
            """
            SELECT id::text AS id, asset_id::text AS asset_id, severity,
                   rule_source, metadata
            FROM findings
            WHERE status = 'open'
            """
        )
        scope_rows = await self._db.fetch(
            "SELECT value FROM scope_entries "
            "WHERE active IS TRUE AND kind = 'ipv4_cidr'"
        )

        assets: dict[str, dict[str, Any]] = {
            r["id"]: {
                "id": r["id"],
                "kind": r["kind"],
                "value": r["value"],
                "metadata": r["metadata"] or {},
            }
            for r in asset_rows
        }

        findings_by_asset: dict[str, list[dict[str, Any]]] = {}
        for r in finding_rows:
            findings_by_asset.setdefault(r["asset_id"], []).append(
                {
                    "id": r["id"],
                    "severity": r["severity"],
                    "rule_source": r["rule_source"],
                    "metadata": r["metadata"] or {},
                }
            )

        # Undirected adjacency + a deterministic edge-kind lookup.
        adj: dict[str, set[str]] = {aid: set() for aid in assets}
        edge_kind: dict[tuple[str, str], str] = {}
        for r in edge_rows:
            s, d, k = r["src"], r["dst"], r["kind"]
            if s not in assets or d not in assets or s == d:
                continue
            adj[s].add(d)
            adj[d].add(s)
            key = (s, d) if s < d else (d, s)
            # Deterministic when several edges connect the same pair.
            cur = edge_kind.get(key)
            if cur is None or k < cur:
                edge_kind[key] = k

        public_nets: list[Any] = []
        for r in scope_rows:
            try:
                net = ipaddress.ip_network(r["value"], strict=False)
            except ValueError:
                continue
            if net.is_global or not net.is_private:
                public_nets.append(net)

        return {
            "assets": assets,
            "adj": {k: sorted(v) for k, v in adj.items()},
            "edge_kind": edge_kind,
            "findings_by_asset": findings_by_asset,
            "public_nets": tuple(public_nets),
        }

    @staticmethod
    def _edge_kind_between(
        edge_kind: dict[tuple[str, str], str], a: str, b: str
    ) -> Optional[str]:
        key = (a, b) if a < b else (b, a)
        return edge_kind.get(key)

    def _parent_ip(
        self, graph: dict[str, Any], port_id: str
    ) -> Optional[str]:
        """Nearest ipv4 asset to a port, via the undirected graph (≤2 hops)."""
        assets = graph["assets"]
        adj = graph["adj"]
        visited = {port_id}
        frontier = [port_id]
        for _ in range(2):
            nxt: list[str] = []
            for node in frontier:
                for nb in adj.get(node, ()):
                    if nb in visited:
                        continue
                    visited.add(nb)
                    if assets[nb]["kind"] == "ipv4":
                        return assets[nb]["value"]
                    nxt.append(nb)
            frontier = nxt
        return None

    # -- node costing -------------------------------------------------------

    def _node_info(
        self, graph: dict[str, Any], aid: str, is_source: bool
    ) -> dict[str, Any]:
        findings = graph["findings_by_asset"].get(aid, [])
        return {
            "entry_cost": entry_cost(findings, is_source=is_source),
            "finding_ids": sorted(f["id"] for f in findings),
            "max_severity": max_severity(findings),
            "kev": any(is_kev_finding(f) for f in findings),
        }

    # -- Dijkstra -----------------------------------------------------------

    def _dijkstra(
        self,
        graph: dict[str, Any],
        source: str,
        costs: dict[str, int],
    ) -> tuple[dict[str, float], dict[str, Optional[str]], dict[str, int]]:
        """Node-weighted shortest paths from `source` over undirected edges.

        Cost of a path = sum of entry costs of the nodes after the source.
        Deterministic: the heap breaks ties by node id, and predecessors by
        (depth, predecessor id).
        """
        adj = graph["adj"]
        dist: dict[str, float] = {source: 0.0}
        prev: dict[str, Optional[str]] = {source: None}
        depth: dict[str, int] = {source: 0}
        heap: list[tuple[float, int, str]] = [(0.0, 0, source)]

        while heap:
            d, hops, u = heapq.heappop(heap)
            if d > dist.get(u, float("inf")):
                continue
            if hops >= MAX_HOPS:
                # Do not expand beyond the hop cap.
                continue
            for v in adj.get(u, ()):
                nd = d + costs[v]
                nh = hops + 1
                better = v not in dist or nd < dist[v]
                tie = (
                    v in dist
                    and nd == dist[v]
                    and (nh, u) < (depth.get(v, 1 << 30), prev.get(v) or "")
                )
                if better or tie:
                    dist[v] = nd
                    prev[v] = u
                    depth[v] = nh
                    heapq.heappush(heap, (nd, nh, v))
        return dist, prev, depth

    @staticmethod
    def _reconstruct(
        prev: dict[str, Optional[str]], target: str
    ) -> list[str]:
        out: list[str] = []
        cur: Optional[str] = target
        while cur is not None:
            out.append(cur)
            cur = prev.get(cur)
        out.reverse()
        return out

    # -- path assembly ------------------------------------------------------

    def _build_path(
        self,
        graph: dict[str, Any],
        nodes: list[str],
        node_info: dict[str, dict[str, Any]],
        source_reason: Optional[str],
        target_reason: Optional[str],
    ) -> dict[str, Any]:
        assets = graph["assets"]
        edge_kind = graph["edge_kind"]

        hops: list[dict[str, Any]] = []
        total_cost = 0
        path_rank = -1
        kev_on_path = False
        prev_node: Optional[str] = None
        for aid in nodes:
            info = node_info[aid]
            a = assets[aid]
            edge_in = (
                None
                if prev_node is None
                else self._edge_kind_between(edge_kind, prev_node, aid)
            )
            hops.append(
                {
                    "asset_id": aid,
                    "kind": a["kind"],
                    "value": a["value"],
                    "edge_kind_in": edge_in,
                    "entry_cost": info["entry_cost"],
                    "finding_ids": info["finding_ids"],
                    "max_severity": info["max_severity"],
                }
            )
            if prev_node is not None:
                total_cost += info["entry_cost"]
            if info["max_severity"] is not None:
                path_rank = max(path_rank, SEVERITY_RANK[info["max_severity"]])
            kev_on_path = kev_on_path or info["kev"]
            prev_node = aid

        length = len(nodes) - 1
        severity = _RANK_TO_SEVERITY.get(path_rank, "info")
        exploit = exploitability_score(total_cost, length)
        fingerprint = path_fingerprint(nodes)

        src_a = assets[nodes[0]]
        tgt_a = assets[nodes[-1]]
        title = self._make_title(src_a, tgt_a, length)
        narrative = self._make_narrative(assets, nodes, length)

        return {
            "source_asset_id": nodes[0],
            "target_asset_id": nodes[-1],
            "hops": hops,
            "length": length,
            "total_cost": total_cost,
            "exploitability": exploit,
            "severity": severity,
            "title": title,
            "narrative": narrative,
            "kev_on_path": kev_on_path,
            "fingerprint": fingerprint,
            "metadata": {
                "source_kind": src_a["kind"],
                "target_kind": tgt_a["kind"],
                "source_reason": source_reason,
                "target_reason": target_reason,
                "hop_count": length,
            },
        }

    @staticmethod
    def _label(asset: dict[str, Any], limit: int = 48) -> str:
        val = (asset.get("value") or "").strip()
        if len(val) > limit:
            val = val[: limit - 1] + "…"
        return val or asset.get("kind") or "asset"

    def _make_title(
        self, src: dict[str, Any], tgt: dict[str, Any], length: int
    ) -> str:
        candidate = f"{self._label(src)} → {self._label(tgt)}"
        fallback = f"{src['kind']} → {tgt['kind']} ({length} hops)"
        return safe_narrative(candidate, fallback)

    def _make_narrative(
        self, assets: dict[str, dict[str, Any]], nodes: list[str], length: int
    ) -> str:
        src = assets[nodes[0]]
        tgt = assets[nodes[-1]]
        route = " → ".join(
            f"{assets[n]['kind']}:{self._label(assets[n], limit=32)}"
            for n in nodes
        )
        candidate = (
            f"Reachable path: {route}. An intrusion beginning at the "
            f"internet-facing {src['kind']} could traverse {length} hop(s) "
            f"to reach the crown-jewel {tgt['kind']}. Segment or remediate "
            f"the intermediate assets to break the path."
        )
        # Fallback uses only enum-safe asset kinds and counts, never values.
        fallback = (
            f"An internet-facing {src['kind']} can reach a crown-jewel "
            f"{tgt['kind']} through {length} hop(s) in the asset graph. "
            f"Review and segment the highlighted route to cut the path."
        )
        return safe_narrative(candidate, fallback)

    # -- main entry ---------------------------------------------------------

    def compute_paths(self, graph: dict[str, Any]) -> list[dict[str, Any]]:
        """Pure computation over an in-memory graph. Returns ranked paths."""
        assets = graph["assets"]

        source_reason: dict[str, str] = {}
        target_reason: dict[str, str] = {}
        for aid, a in assets.items():
            parent_ip = (
                self._parent_ip(graph, aid) if a["kind"] == "port" else None
            )
            is_src, sreason = classify_source(
                a, parent_ip=parent_ip, public_nets=graph["public_nets"]
            )
            if is_src:
                source_reason[aid] = sreason  # type: ignore[assignment]
            is_tgt, treason = classify_target(a)
            if is_tgt:
                target_reason[aid] = treason  # type: ignore[assignment]

        if not source_reason or not target_reason:
            return []

        # Entry cost for every node (sources are free).
        costs: dict[str, int] = {}
        node_info: dict[str, dict[str, Any]] = {}
        for aid in assets:
            info = self._node_info(graph, aid, is_source=aid in source_reason)
            node_info[aid] = info
            costs[aid] = info["entry_cost"]

        targets = set(target_reason)
        candidates: dict[str, dict[str, Any]] = {}
        for source in sorted(source_reason):
            dist, prev, depth = self._dijkstra(graph, source, costs)
            for tgt in sorted(targets):
                if tgt == source or tgt not in dist:
                    continue
                if depth.get(tgt, MAX_HOPS + 1) > MAX_HOPS:
                    continue
                nodes = self._reconstruct(prev, tgt)
                if len(nodes) < 2:
                    continue
                path = self._build_path(
                    graph,
                    nodes,
                    node_info,
                    source_reason.get(source),
                    target_reason.get(tgt),
                )
                # Fingerprint is unique per node sequence; keep the best.
                fp = path["fingerprint"]
                existing = candidates.get(fp)
                if existing is None or (
                    path["exploitability"],
                    fp,
                ) > (existing["exploitability"], fp):
                    candidates[fp] = path

        ranked = sorted(
            candidates.values(),
            key=lambda p: (-p["exploitability"], p["fingerprint"]),
        )
        return ranked[:TOP_N]

    async def _persist(
        self, paths: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Upsert all paths and prune stale ones in a single transaction.

        Returns the subset that were newly inserted (for event publishing).
        """
        inserted: list[dict[str, Any]] = []
        seen = [p["fingerprint"] for p in paths]
        async with self._db.acquire() as conn:
            async with conn.transaction():
                for p in paths:
                    row = await conn.fetchrow(
                        """
                        INSERT INTO attack_paths (
                          source_asset_id, target_asset_id, hops, length,
                          total_cost, exploitability, severity, title,
                          narrative, kev_on_path, fingerprint, computed_at,
                          metadata
                        ) VALUES (
                          $1::uuid, $2::uuid, $3::jsonb, $4, $5::numeric,
                          $6::numeric, $7, $8, $9, $10, $11, NOW(), $12::jsonb
                        )
                        ON CONFLICT (fingerprint) DO UPDATE SET
                          source_asset_id = EXCLUDED.source_asset_id,
                          target_asset_id = EXCLUDED.target_asset_id,
                          hops            = EXCLUDED.hops,
                          length          = EXCLUDED.length,
                          total_cost      = EXCLUDED.total_cost,
                          exploitability  = EXCLUDED.exploitability,
                          severity        = EXCLUDED.severity,
                          title           = EXCLUDED.title,
                          narrative       = EXCLUDED.narrative,
                          kev_on_path     = EXCLUDED.kev_on_path,
                          computed_at     = NOW(),
                          metadata        = EXCLUDED.metadata
                        RETURNING id::text AS id, (xmax = 0) AS inserted
                        """,
                        p["source_asset_id"],
                        p["target_asset_id"],
                        p["hops"],
                        p["length"],
                        Decimal(str(p["total_cost"])),
                        Decimal(str(p["exploitability"])),
                        p["severity"],
                        p["title"],
                        p["narrative"],
                        p["kev_on_path"],
                        p["fingerprint"],
                        p["metadata"],
                    )
                    if row is not None and row["inserted"]:
                        inserted.append({**p, "id": row["id"]})
                # Stale cleanup: anything not seen this run. With an empty
                # `seen`, `<> ALL('{}')` is vacuously true, so the table is
                # cleared — it always reflects the current graph.
                await conn.execute(
                    "DELETE FROM attack_paths WHERE fingerprint <> ALL($1::text[])",
                    seen,
                )
        return inserted

    async def _publish_new(self, inserted: list[dict[str, Any]]) -> None:
        if self._redis is None or not inserted:
            return
        for p in inserted:
            event = {
                "event": "attack_path_found",
                "path_id": p.get("id"),
                "fingerprint": p["fingerprint"],
                "source_asset_id": p["source_asset_id"],
                "target_asset_id": p["target_asset_id"],
                "exploitability": p["exploitability"],
                "severity": p["severity"],
                "kev_on_path": p["kev_on_path"],
                "title": p["title"],
            }
            try:
                await self._redis.xadd(
                    self._events_stream,
                    {"event": json.dumps(event, default=str)},
                )
            except Exception:
                log.exception("failed to publish attack_path_found event")

    async def run(self) -> dict[str, Any]:
        """Load the graph, compute paths, persist, publish. Returns a summary."""
        started = time.monotonic()
        graph = await self._load_graph()
        paths = self.compute_paths(graph)
        inserted = await self._persist(paths)
        await self._publish_new(inserted)
        elapsed_ms = round((time.monotonic() - started) * 1000.0, 2)
        log.info(
            "attack-path run: %d paths (%d new) in %.1fms",
            len(paths),
            len(inserted),
            elapsed_ms,
        )
        return {
            "computed": len(paths),
            "inserted": len(inserted),
            "elapsed_ms": elapsed_ms,
        }

    async def count(self) -> int:
        val = await self._db.fetchval("SELECT COUNT(*) FROM attack_paths")
        return int(val or 0)
