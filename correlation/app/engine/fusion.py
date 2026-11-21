"""Reachability × attack-path fusion engine.

DEFENSIVE feature. Fuses two independent signals the platform already
computes:

* **Code reachability** — a dependency vuln graded `reachability='reachable'`
  on `sbom_component_vulns` (the vulnerable symbol is actually callable from
  first-party code, not just present in a lockfile).
* **Attack-surface reachability** — the host that runs that code sits on an
  `attack_paths` row, i.e. a route from an internet-facing source to a
  crown-jewel target.

When BOTH hold for the same host, the dependency vuln is reachable in code
*and* reachable on the surface: a materially higher-confidence risk than
either signal alone. The engine emits a `finding_chains` row with
`chain_rule_id='reachable_on_path'`, severity escalated one step above the
underlying vuln, and an impact narrative describing the compound risk.

Like the attack-path engine, this:

* bulk-loads reachable vulns + attack paths + the asset graph (no N+1),
* is deterministic for a fixed input,
* upserts by a stable fingerprint and prunes stale fusion chains (ONLY
  rows with `chain_rule_id='reachable_on_path'`) in one transaction, so the
  fusion set always reflects the current graph, and
* publishes a `chain_detected` event for every newly-inserted chain.

The narrative passes the SAME safety guard the attack-path / chain
narratives use (`safe_narrative` → reject tokens + `validate_narrative_text`):
anything that reads like exploitation guidance forces a neutral fallback.

Everything is async; all SQL is parameterized asyncpg.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from collections import deque
from decimal import Decimal
from typing import Any, Optional

from .. import tenancy
from ..db import Database
# REUSE the existing narrative safety guard + severity ranking from the
# attack-path engine rather than reimplementing them.
from .attackpath import SEVERITY_RANK, safe_narrative

log = logging.getLogger(__name__)


# ----------------------------------------------------------------------------
# Contract constants
# ----------------------------------------------------------------------------

FUSION_RULE_ID = "reachable_on_path"

FUSION_TITLE = "Reachable dependency vuln on an internet-facing path"

# Asset kinds that count as a "host" (mirrors graph.Graph.host_of).
HOST_KINDS: frozenset[str] = frozenset(
    {"ipv4", "ipv6", "subdomain", "domain"}
)

# How far to walk incoming edges looking for a host ancestor (mirrors
# graph.Graph.host_of's 3-hop budget).
HOST_LOOKUP_HOPS = 3

_RANK_TO_SEVERITY: dict[int, str] = {v: k for k, v in SEVERITY_RANK.items()}

# One-step severity escalation, capped at critical. medium→high, high→
# critical, critical stays critical (info/low included for completeness).
ESCALATION: dict[str, str] = {
    "info": "low",
    "low": "medium",
    "medium": "high",
    "high": "critical",
    "critical": "critical",
}


# ----------------------------------------------------------------------------
# Pure helpers (unit-testable without a database)
# ----------------------------------------------------------------------------

def escalate_severity(severity: Optional[str]) -> str:
    """Escalate a vuln severity one step (capped at critical).

    Unknown/empty severities fall back to the underlying value if it is a
    known rank, else 'high' (a reachable+on-path issue is never trivial).
    """
    if severity in ESCALATION:
        return ESCALATION[severity]
    return "high"


def worst_severity(severities: list[str]) -> str:
    """Highest-ranked severity in the list (default 'medium' when empty)."""
    best = -1
    for s in severities:
        best = max(best, SEVERITY_RANK.get(s or "", -1))
    return _RANK_TO_SEVERITY.get(best, "medium")


def fusion_fingerprint(host_asset_id: str, path_fingerprint: str) -> str:
    """Stable fingerprint for a (host, path) fusion unit.

    Deterministic for a fixed (host, path): the same host sitting on the
    same path always upserts the same row, and it survives path recompute
    because the path fingerprint is itself the ordered-hop hash.
    """
    h = hashlib.sha256(
        f"{FUSION_RULE_ID}|{host_asset_id}|{path_fingerprint}".encode("utf-8")
    )
    return h.hexdigest()


def path_qualifies(path: dict[str, Any]) -> bool:
    """A path is an internet-facing route to a crown jewel.

    Every `attack_paths` row is such a route by construction (the engine
    only emits internet-facing-source → crown-jewel-target paths), so this
    just guards against malformed rows missing a source/target/hops.
    """
    return bool(
        path.get("source_asset_id")
        and path.get("target_asset_id")
        and path.get("hops")
    )


def path_hop_asset_ids(path: dict[str, Any]) -> list[str]:
    """Ordered hop asset ids of a path."""
    return [
        str(h["asset_id"])
        for h in (path.get("hops") or [])
        if h.get("asset_id")
    ]


def path_hop_finding_ids(path: dict[str, Any]) -> list[str]:
    """Every open-finding id recorded across a path's hops."""
    out: list[str] = []
    for h in path.get("hops") or []:
        for fid in h.get("finding_ids") or []:
            out.append(str(fid))
    return out


def resolve_host(
    asset_id: str,
    kinds: dict[str, str],
    in_adj: dict[str, set[str]],
) -> Optional[str]:
    """Nearest host-ish ancestor of `asset_id` (≤ HOST_LOOKUP_HOPS hops).

    Pure mirror of graph.Graph.host_of over in-memory adjacency: if the
    asset is itself host-like, it is its own host; otherwise walk incoming
    edges for a few hops looking for an ipv4/ipv6/subdomain/domain.
    """
    if kinds.get(asset_id) in HOST_KINDS:
        return asset_id
    visited = {asset_id}
    frontier = {asset_id}
    for _ in range(HOST_LOOKUP_HOPS):
        nxt: set[str] = set()
        for node in sorted(frontier):
            for src in sorted(in_adj.get(node, ())):
                if src in visited:
                    continue
                visited.add(src)
                if kinds.get(src) in HOST_KINDS:
                    return src
                nxt.add(src)
        if not nxt:
            break
        frontier = nxt
    return None


def descendants(root: str, out_adj: dict[str, set[str]]) -> set[str]:
    """All assets reachable from `root` via outgoing edges (incl. root)."""
    seen = {root}
    q: deque[str] = deque([root])
    while q:
        cur = q.popleft()
        for dst in out_adj.get(cur, ()):
            if dst not in seen:
                seen.add(dst)
                q.append(dst)
    return seen


def host_scope(
    project_asset_id: str,
    kinds: dict[str, str],
    in_adj: dict[str, set[str]],
    out_adj: dict[str, set[str]],
) -> tuple[str, set[str]]:
    """Return (anchor_host_id, scope_asset_ids) for a project asset.

    `anchor_host_id` is the nearest host ancestor (or the asset itself when
    none is found). `scope_asset_ids` is everything on that host — the host
    plus its descendants plus the project asset — matching the `same_host`
    scope used by the chain matcher.
    """
    host = resolve_host(project_asset_id, kinds, in_adj)
    anchor = host or project_asset_id
    scope = descendants(anchor, out_adj)
    scope.add(project_asset_id)
    return anchor, scope


def resolve_scopes(
    project_asset_ids: list[str],
    kinds: dict[str, str],
    in_adj: dict[str, set[str]],
    out_adj: dict[str, set[str]],
) -> dict[str, dict[str, Any]]:
    """Resolve host scope for each distinct project asset (pure)."""
    out: dict[str, dict[str, Any]] = {}
    for pa in sorted(set(project_asset_ids)):
        anchor, scope = host_scope(pa, kinds, in_adj, out_adj)
        out[pa] = {"host": anchor, "scope": scope}
    return out


def _compose_narrative(
    anchor_label: str,
    packages: list[str],
    path_length: int,
    target_kind: str,
) -> str:
    """Build the compound-risk narrative, guarded to a neutral fallback.

    The candidate names the reachable packages (from untrusted SBOM data,
    so it is run through the same safety guard as the other narratives);
    the fallback uses only counts and enum-safe asset kinds.
    """
    pkg_list = ", ".join(packages[:5]) if packages else "a dependency"
    candidate = (
        f"Reachable dependency vulnerability in {pkg_list} runs on "
        f"{anchor_label}, which sits on an internet-facing attack path "
        f"reaching a crown-jewel {target_kind} in {path_length} hop(s). "
        "The vulnerable code is reachable in first-party call paths AND the "
        "host is reachable from the internet, so both prerequisites for "
        "real-world impact hold at once. Prioritise upgrading the "
        "dependency and segmenting the path."
    )
    fallback = (
        f"A reachable dependency vulnerability ({len(packages)} package(s)) "
        f"runs on a host that also sits on an internet-facing path reaching "
        f"a crown-jewel {target_kind} in {path_length} hop(s). It is "
        "reachable in code and reachable on the surface at once; upgrade the "
        "dependency and segment the path."
    )
    return safe_narrative(candidate, fallback)


def build_fusion_chain(
    anchor_host_id: str,
    path: dict[str, Any],
    contributing: list[dict[str, Any]],
) -> dict[str, Any]:
    """Assemble a finding_chains payload for one (host, path) fusion unit.

    `contributing` is the list of reachable-vuln records (each with a
    resolved open `sca_finding_id`) whose host scope intersects this path.
    Pure: no DB access.
    """
    underlying = worst_severity([c.get("vuln_severity") for c in contributing])
    severity = escalate_severity(underlying)

    packages = sorted({c.get("package") for c in contributing if c.get("package")})
    sca_finding_ids = [
        c["sca_finding_id"] for c in contributing if c.get("sca_finding_id")
    ]
    finding_ids = sorted(set(sca_finding_ids) | set(path_hop_finding_ids(path)))

    fp = fusion_fingerprint(anchor_host_id, str(path["fingerprint"]))
    target_kind = str((path.get("metadata") or {}).get("target_kind") or "target")
    path_length = int(path.get("length") or len(path_hop_asset_ids(path)) or 0)

    narrative = _compose_narrative(
        anchor_label=anchor_host_id,
        packages=packages,
        path_length=path_length,
        target_kind=target_kind,
    )

    osv_ids = sorted({c.get("osv_id") for c in contributing if c.get("osv_id")})
    cve_ids = sorted({c.get("cve_id") for c in contributing if c.get("cve_id")})
    pkgs_desc = ", ".join(packages) if packages else "a dependency"
    description = (
        f"Reachable dependency vulnerability in {pkgs_desc} is deployed on a "
        f"host on an internet-facing attack path to a crown-jewel "
        f"{target_kind}. Underlying vuln severity {underlying}, escalated to "
        f"{severity} because the risk is reachable in code and on the surface."
    )

    return {
        "chain_rule_id": FUSION_RULE_ID,
        "severity": severity,
        "title": FUSION_TITLE,
        "description": description,
        "impact_narrative": narrative,
        "blast_radius_score": float(path.get("exploitability") or 0.0),
        "finding_ids": finding_ids,
        "anchor_asset_id": anchor_host_id,
        "fingerprint": fp,
        "metadata": {
            "fingerprint": fp,
            "rule_source": FUSION_RULE_ID,
            "underlying_severity": underlying,
            "escalated_severity": severity,
            "path_id": path.get("id"),
            "path_fingerprint": str(path["fingerprint"]),
            "path_exploitability": float(path.get("exploitability") or 0.0),
            "path_severity": path.get("severity"),
            "path_length": path_length,
            "source_asset_id": path.get("source_asset_id"),
            "target_asset_id": path.get("target_asset_id"),
            "anchor_host_id": anchor_host_id,
            "packages": packages,
            "osv_ids": osv_ids,
            "cve_ids": cve_ids,
            "sca_finding_ids": sorted(set(sca_finding_ids)),
        },
    }


def compute_fusions(
    reachable: list[dict[str, Any]],
    paths: list[dict[str, Any]],
    scope_by_asset: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Pure fusion computation.

    `reachable` : reachable-vuln records, each carrying `project_asset_id`
                  and a resolved open `sca_finding_id`.
    `paths`     : attack-path rows (hops with asset_ids + finding_ids).
    `scope_by_asset` : project_asset_id → {host, scope:set(asset_ids)}.

    A reachable vuln fuses with a path when the host scope of its project
    asset contains any hop of that path. Fusions are grouped per
    (anchor host, path) and returned deterministically ordered by
    fingerprint.
    """
    usable_paths = [p for p in paths if path_qualifies(p)]
    if not usable_paths or not reachable:
        return []

    # groups: (host, path_fingerprint) -> {"path": path, "contrib": [vuln,...]}
    groups: dict[tuple[str, str], dict[str, Any]] = {}

    for vuln in sorted(
        reachable,
        key=lambda v: (
            str(v.get("project_asset_id") or ""),
            str(v.get("osv_id") or ""),
            str(v.get("sca_finding_id") or ""),
        ),
    ):
        if not vuln.get("sca_finding_id"):
            continue  # need the sca finding for finding_ids
        pa = str(vuln.get("project_asset_id") or "")
        sc = scope_by_asset.get(pa)
        if not sc:
            continue
        scope: set[str] = sc["scope"]
        host: str = sc["host"]
        for path in usable_paths:
            hop_ids = set(path_hop_asset_ids(path))
            if scope & hop_ids:
                key = (host, str(path["fingerprint"]))
                grp = groups.get(key)
                if grp is None:
                    grp = {"path": path, "contrib": []}
                    groups[key] = grp
                grp["contrib"].append(vuln)

    chains = [
        build_fusion_chain(host, grp["path"], grp["contrib"])
        for (host, _fp), grp in groups.items()
    ]
    chains.sort(key=lambda c: c["fingerprint"])
    return chains


# ----------------------------------------------------------------------------
# Engine
# ----------------------------------------------------------------------------

class FusionEngine:
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

    async def _load_reachable(self) -> list[dict[str, Any]]:
        """Reachable dependency vulns joined to their project asset + the
        open `sca` finding that mirrors the component. One query, no N+1."""
        rows = await self._db.fetch(
            """
            SELECT scv.id::text        AS vuln_id,
                   scv.osv_id          AS osv_id,
                   scv.cve_id          AS cve_id,
                   scv.severity        AS vuln_severity,
                   sc.name             AS package,
                   sc.ecosystem        AS ecosystem,
                   sc.version          AS version,
                   sp.name             AS project_name,
                   sp.asset_id::text   AS project_asset_id,
                   f.id::text          AS sca_finding_id
            FROM sbom_component_vulns scv
            JOIN sbom_components sc ON sc.id = scv.component_id
            JOIN sca_projects    sp ON sp.id = sc.project_id
            LEFT JOIN findings   f
              ON f.rule_source = 'sca'
             AND f.asset_id = sp.asset_id
             AND f.rule_id = 'sca:' || sc.ecosystem || ':' || sc.name
             AND f.status = 'open'
            WHERE scv.reachability = 'reachable'
              AND sp.asset_id IS NOT NULL
            """
        )
        return [dict(r) for r in rows]

    async def _load_paths(self) -> list[dict[str, Any]]:
        """All attack paths (each is internet-facing → crown jewel)."""
        rows = await self._db.fetch(
            """
            SELECT id::text              AS id,
                   source_asset_id::text AS source_asset_id,
                   target_asset_id::text AS target_asset_id,
                   hops, length, exploitability, severity, narrative,
                   fingerprint, metadata
            FROM attack_paths
            """
        )
        return [dict(r) for r in rows]

    async def _load_adjacency(
        self, project_asset_ids: list[str]
    ) -> dict[str, dict[str, Any]]:
        """Resolve host scope for each project asset from a bulk edge load.

        Two queries (asset kinds + edges); scope resolution is in-memory, so
        there is no per-asset round trip.
        """
        if not project_asset_ids:
            return {}
        kind_rows = await self._db.fetch(
            "SELECT id::text AS id, kind FROM assets"
        )
        edge_rows = await self._db.fetch(
            "SELECT src_id::text AS src, dst_id::text AS dst FROM asset_edges"
        )
        kinds = {r["id"]: r["kind"] for r in kind_rows}
        out_adj: dict[str, set[str]] = {}
        in_adj: dict[str, set[str]] = {}
        for r in edge_rows:
            s, d = r["src"], r["dst"]
            out_adj.setdefault(s, set()).add(d)
            in_adj.setdefault(d, set()).add(s)
        return resolve_scopes(project_asset_ids, kinds, in_adj, out_adj)

    # -- persistence --------------------------------------------------------

    async def _persist(
        self, chains: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Upsert all fusion chains and prune stale ones in one transaction.

        Stale cleanup only touches rows with
        `chain_rule_id='reachable_on_path'`, never chains produced by other
        rules. Returns the subset newly inserted (for event publishing).
        """
        inserted: list[dict[str, Any]] = []
        seen = [c["fingerprint"] for c in chains]
        async with self._db.acquire() as conn:
            async with conn.transaction():
                for c in chains:
                    fp = c["fingerprint"]
                    brs = (
                        Decimal(str(c["blast_radius_score"]))
                        if c.get("blast_radius_score") is not None
                        else None
                    )
                    existing = await conn.fetchrow(
                        """
                        SELECT id FROM finding_chains
                         WHERE chain_rule_id = $1
                           AND (metadata->>'fingerprint') = $2
                         LIMIT 1
                        """,
                        FUSION_RULE_ID,
                        fp,
                    )
                    if existing is None:
                        row = await conn.fetchrow(
                            """
                            INSERT INTO finding_chains (
                              chain_rule_id, severity, title, description,
                              impact_narrative, blast_radius_score,
                              finding_ids, anchor_asset_id, metadata
                            ) VALUES (
                              $1, $2, $3, $4, $5, $6::numeric,
                              $7::uuid[], $8::uuid, $9::jsonb
                            )
                            RETURNING id::text AS id
                            """,
                            FUSION_RULE_ID,
                            c["severity"],
                            c["title"],
                            c["description"],
                            c["impact_narrative"],
                            brs,
                            c["finding_ids"],
                            c["anchor_asset_id"],
                            c["metadata"],
                        )
                        inserted.append({**c, "id": row["id"]})
                    else:
                        await conn.execute(
                            """
                            UPDATE finding_chains SET
                              severity           = $2,
                              title              = $3,
                              description        = $4,
                              impact_narrative   = $5,
                              blast_radius_score = $6::numeric,
                              finding_ids        = $7::uuid[],
                              anchor_asset_id    = $8::uuid,
                              metadata           = metadata || $9::jsonb
                             WHERE id = $1
                            """,
                            existing["id"],
                            c["severity"],
                            c["title"],
                            c["description"],
                            c["impact_narrative"],
                            brs,
                            c["finding_ids"],
                            c["anchor_asset_id"],
                            c["metadata"],
                        )
                # Stale cleanup: fusion chains not seen this run. With an
                # empty `seen`, `<> ALL('{}')` is vacuously true, so every
                # fusion chain is cleared — but ONLY fusion chains, never
                # rows from other chain rules.
                await conn.execute(
                    """
                    DELETE FROM finding_chains
                     WHERE chain_rule_id = $1
                       AND (metadata->>'fingerprint') <> ALL($2::text[])
                    """,
                    FUSION_RULE_ID,
                    seen,
                )
        return inserted

    async def _publish_new(self, inserted: list[dict[str, Any]]) -> None:
        if self._redis is None or not inserted:
            return
        for c in inserted:
            event = {
                "event": "chain_detected",
                "chain_id": c.get("id"),
                "chain_rule_id": FUSION_RULE_ID,
                "severity": c["severity"],
                "anchor_asset_id": c.get("anchor_asset_id"),
                "finding_count": len(c.get("finding_ids") or []),
            }
            try:
                await self._redis.xadd(
                    self._events_stream,
                    {"event": json.dumps(tenancy.stamp_event(event), default=str)},
                )
            except Exception:
                log.exception("failed to publish chain_detected (fusion) event")

    # -- main entry ---------------------------------------------------------

    async def run(self) -> dict[str, Any]:
        """Load signals, compute fusions, persist, publish. Returns a summary."""
        started = time.monotonic()
        reachable = await self._load_reachable()
        paths = await self._load_paths()
        project_asset_ids = [
            str(v["project_asset_id"])
            for v in reachable
            if v.get("project_asset_id")
        ]
        scope_by_asset = await self._load_adjacency(project_asset_ids)
        chains = compute_fusions(reachable, paths, scope_by_asset)
        inserted = await self._persist(chains)
        await self._publish_new(inserted)
        elapsed_ms = round((time.monotonic() - started) * 1000.0, 2)
        log.info(
            "fusion run: %d chains (%d new) from %d reachable vulns, "
            "%d paths in %.1fms",
            len(chains),
            len(inserted),
            len(reachable),
            len(paths),
            elapsed_ms,
        )
        return {
            "computed": len(chains),
            "inserted": len(inserted),
            "reachable": len(reachable),
            "paths": len(paths),
            "elapsed_ms": elapsed_ms,
        }

    async def count(self) -> int:
        val = await self._db.fetchval(
            "SELECT COUNT(*) FROM finding_chains WHERE chain_rule_id = $1",
            FUSION_RULE_ID,
        )
        return int(val or 0)
