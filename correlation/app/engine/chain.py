"""Chain detector.

For each incoming finding (or during a sweep, for each open finding):

1. For every loaded ChainRule, identify which predicates match the
   finding directly (there can be more than one in theory).
2. For each other predicate, run a scoped query to see if another
   finding (or asset) satisfies it within `window_days` under the chain's
   `scope` (same_host / same_domain / same_cidr / same_org).
3. If every predicate is satisfied, assemble the evidence, build an
   impact narrative, and upsert a finding_chains row via the orchestrator.

Scope resolution is based on the asset graph:

* same_host    — same host asset id (service/tech/endpoint roll up to
                 their ipv4/ipv6/subdomain parent).
* same_domain  — same registrable domain (longest domain ancestor).
* same_cidr    — same /24 for IPv4 (a stand-in for "network"); same host
                 for IPv6 since we don't ship v6 subnet math.
* same_org     — any asset under the same org root.

All SQL uses parameterized asyncpg queries.
"""
from __future__ import annotations

import ipaddress
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

from ..db import Database
from ..orchestrator import OrchestratorClient
from .graph import Graph
from .policy import (
    ChainPredicate,
    ChainRule,
    FindingPredicate,
    PolicyRule,
    RuleLoader,
    asset_matches,
    finding_matches,
)

log = logging.getLogger(__name__)


# ----------------------------------------------------------------------------
# Scope resolver
# ----------------------------------------------------------------------------

class ScopeResolver:
    """Translates a predicate `scope` into a set of candidate asset_ids."""

    def __init__(self, db: Database) -> None:
        self._db = db
        self._graph = Graph(db)

    async def candidate_asset_ids(
        self, anchor_asset_id: str, scope: str
    ) -> list[str]:
        anchor = await self._graph.get_asset(anchor_asset_id)
        if anchor is None:
            return []

        if scope == "same_host":
            host = await self._graph.host_of(anchor_asset_id)
            if host is None:
                return [anchor_asset_id]
            return await self._descendants_of(host)

        if scope == "same_domain":
            domain_id = await self._registrable_domain(anchor_asset_id)
            if domain_id is None:
                return [anchor_asset_id]
            return await self._descendants_of(domain_id)

        if scope == "same_cidr":
            return await self._same_cidr(anchor)

        if scope == "same_org":
            org_id = await self._org_root(anchor_asset_id)
            if org_id is None:
                return [anchor_asset_id]
            return await self._descendants_of(org_id)

        return [anchor_asset_id]

    async def _descendants_of(self, root_id: str) -> list[str]:
        rows = await self._db.fetch(
            """
            WITH RECURSIVE reach(id) AS (
              SELECT id FROM assets WHERE id = $1::uuid
              UNION
              SELECT e.dst_id FROM asset_edges e
              JOIN reach r ON r.id = e.src_id
            )
            SELECT id::text FROM reach
            """,
            root_id,
        )
        return [r["id"] for r in rows]

    async def _registrable_domain(
        self, asset_id: str
    ) -> Optional[str]:
        """Walk incoming edges looking for the shortest-dotted 'domain' asset."""
        asset = await self._graph.get_asset(asset_id)
        if asset is None:
            return None
        if asset["kind"] == "domain":
            return asset_id

        frontier = {asset_id}
        visited: set[str] = {asset_id}
        best: Optional[tuple[int, str]] = None  # (dot count, id)
        for _ in range(4):
            rows = await self._db.fetch(
                """
                SELECT a.id::text AS id, a.kind, a.value
                FROM asset_edges e
                JOIN assets a ON a.id = e.src_id
                WHERE e.dst_id = ANY($1::uuid[])
                """,
                list(frontier),
            )
            if not rows:
                break
            next_frontier: set[str] = set()
            for r in rows:
                if r["id"] in visited:
                    continue
                visited.add(r["id"])
                if r["kind"] == "domain":
                    dots = (r["value"] or "").count(".")
                    if best is None or dots < best[0]:
                        best = (dots, r["id"])
                next_frontier.add(r["id"])
            frontier = next_frontier
        return best[1] if best else None

    async def _org_root(self, asset_id: str) -> Optional[str]:
        """Find the org that owns this asset (longest incoming path)."""
        row = await self._db.fetchrow(
            """
            WITH RECURSIVE up(id, kind) AS (
              SELECT a.id, a.kind FROM assets a WHERE a.id = $1::uuid
              UNION
              SELECT a.id, a.kind FROM asset_edges e
              JOIN assets a ON a.id = e.src_id
              JOIN up ON up.id = e.dst_id
            )
            SELECT id::text FROM up WHERE kind = 'org' LIMIT 1
            """,
            asset_id,
        )
        return row["id"] if row else None

    async def _same_cidr(self, anchor: dict[str, Any]) -> list[str]:
        """Return asset_ids of IPv4 hosts in the same /24, plus their descendants.
        For IPv6 or non-IP assets, falls back to same_host."""
        # We need an IPv4 ancestor.
        ip = None
        if anchor["kind"] == "ipv4":
            ip = anchor["value"]
        else:
            # Walk up for an ipv4 ancestor.
            row = await self._db.fetchrow(
                """
                WITH RECURSIVE up(id, kind, value) AS (
                  SELECT a.id, a.kind, a.value FROM assets a
                  WHERE a.id = $1::uuid
                  UNION
                  SELECT a.id, a.kind, a.value FROM asset_edges e
                  JOIN assets a ON a.id = e.src_id
                  JOIN up ON up.id = e.dst_id
                )
                SELECT value FROM up WHERE kind = 'ipv4' LIMIT 1
                """,
                anchor["id"],
            )
            if row:
                ip = row["value"]
        if ip is None:
            return [anchor["id"]]
        try:
            net = ipaddress.ip_network(f"{ip}/24", strict=False)
        except ValueError:
            return [anchor["id"]]

        # We can't do CIDR match in SQL without a function, so fetch all
        # ipv4 assets and filter in Python; the set is small for an ASM.
        rows = await self._db.fetch(
            "SELECT id::text AS id, value FROM assets WHERE kind = 'ipv4'"
        )
        host_ids: list[str] = []
        for r in rows:
            try:
                if ipaddress.ip_address(r["value"]) in net:
                    host_ids.append(r["id"])
            except ValueError:
                continue
        # Expand each ip to its descendants.
        out: set[str] = set()
        for hid in host_ids:
            out.update(await self._descendants_of(hid))
        return list(out) if out else [anchor["id"]]


# ----------------------------------------------------------------------------
# Predicate search
# ----------------------------------------------------------------------------

SEVERITY_MIN_SQL = {
    "info": ["info", "low", "medium", "high", "critical"],
    "low": ["low", "medium", "high", "critical"],
    "medium": ["medium", "high", "critical"],
    "high": ["high", "critical"],
    "critical": ["critical"],
}


def _window_cutoff(window_days: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=int(window_days))


class ChainMatcher:
    def __init__(
        self,
        db: Database,
        loader: RuleLoader,
        orch: Optional[OrchestratorClient] = None,
    ) -> None:
        self._db = db
        self._loader = loader
        self._orch = orch
        self._scope = ScopeResolver(db)

    # ------------------------------------------------------------------
    # Candidate-fetching queries. Each returns rows that *could* match
    # the predicate; the Python-level matcher then filters precisely.
    # ------------------------------------------------------------------

    async def _findings_for_predicate(
        self,
        pred: FindingPredicate,
        scope_asset_ids: list[str],
        window_days: int,
    ) -> list[dict[str, Any]]:
        cutoff = _window_cutoff(window_days)
        clauses = [
            "f.asset_id = ANY($1::uuid[])",
            "f.last_seen >= $2",
        ]
        args: list[Any] = [scope_asset_ids, cutoff]

        def ph() -> str:
            return f"${len(args) + 1}"

        if pred.rule_source:
            clauses.append(f"f.rule_source = {ph()}")
            args.append(pred.rule_source)
        if pred.rule_id:
            clauses.append(f"f.rule_id = {ph()}")
            args.append(pred.rule_id)
        if pred.rule_id_match:
            clauses.append(f"f.rule_id ~ {ph()}")
            args.append(pred.rule_id_match)
        if pred.severity_min:
            clauses.append(f"f.severity = ANY({ph()}::text[])")
            args.append(SEVERITY_MIN_SQL[pred.severity_min])
        if pred.cvss_min is not None:
            clauses.append(f"f.cvss >= {ph()}")
            args.append(pred.cvss_min)
        if pred.epss_min is not None:
            clauses.append(f"f.epss >= {ph()}")
            args.append(pred.epss_min)
        if pred.known_exploited is True:
            clauses.append("COALESCE((f.metadata->>'kev')::bool, false) IS TRUE")
        if pred.status:
            clauses.append(f"f.status = {ph()}")
            args.append(pred.status)

        sql = f"""
            SELECT f.id::text, f.asset_id::text, f.rule_id, f.rule_source,
                   f.severity, f.cvss, f.epss, f.status, f.title,
                   f.evidence, f.metadata, f.first_seen, f.last_seen,
                   a.kind AS asset_kind, a.value AS asset_value,
                   a.metadata AS asset_metadata
            FROM findings f
            JOIN assets a ON a.id = f.asset_id
            WHERE {' AND '.join(clauses)}
            ORDER BY f.last_seen DESC
            LIMIT 200
        """
        rows = await self._db.fetch(sql, *args)
        out: list[dict[str, Any]] = []
        for r in rows:
            row = dict(r)
            if pred.asset_kind and row["asset_kind"] != pred.asset_kind:
                continue
            if pred.asset_metadata:
                md = row.get("asset_metadata") or {}
                if not all(md.get(k) == v for k, v in pred.asset_metadata.items()):
                    continue
            if finding_matches(pred, row):
                out.append(row)
        return out

    async def _assets_for_predicate(
        self, pred: dict[str, Any], scope_asset_ids: list[str]
    ) -> list[dict[str, Any]]:
        clauses = ["id = ANY($1::uuid[])"]
        args: list[Any] = [scope_asset_ids]
        if "kind" in pred:
            clauses.append(f"kind = ${len(args) + 1}")
            args.append(pred["kind"])
        if "value_match" in pred:
            clauses.append(f"value ~ ${len(args) + 1}")
            args.append(pred["value_match"])
        sql = f"""
            SELECT id::text, kind, value, canonical, metadata
            FROM assets
            WHERE {' AND '.join(clauses)}
            LIMIT 200
        """
        rows = await self._db.fetch(sql, *args)
        return [dict(r) for r in rows if asset_matches(pred, dict(r))]

    # ------------------------------------------------------------------
    # Main entry points
    # ------------------------------------------------------------------

    async def match_for_finding(
        self, finding_id: str
    ) -> list[dict[str, Any]]:
        """Given a new finding, return the full chains it participates in.
        Each returned dict is suitable for passing to upsert_chain()."""
        row = await self._db.fetchrow(
            """
            SELECT f.id::text, f.asset_id::text, f.rule_id, f.rule_source,
                   f.severity, f.cvss, f.epss, f.status, f.title,
                   f.evidence, f.metadata, f.last_seen,
                   a.kind AS asset_kind, a.value AS asset_value,
                   a.metadata AS asset_metadata
            FROM findings f
            JOIN assets a ON a.id = f.asset_id
            WHERE f.id = $1::uuid
            """,
            finding_id,
        )
        if row is None:
            return []
        finding = dict(row)
        return await self._evaluate_anchor(finding)

    async def _evaluate_anchor(
        self, anchor_finding: dict[str, Any]
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for rule in self._loader.chains.values():
            # Find which predicate positions this finding could occupy.
            anchor_positions = [
                i
                for i, p in enumerate(rule.all_of)
                if p.finding is not None
                and finding_matches(p.finding, anchor_finding)
            ]
            if not anchor_positions:
                continue
            # For every such position, see if we can satisfy the rest.
            for anchor_idx in anchor_positions:
                chain = await self._satisfy_rule(
                    rule, anchor_idx, anchor_finding
                )
                if chain is not None:
                    results.append(chain)
                    break  # one hit per rule per finding is enough
        return results

    async def _satisfy_rule(
        self,
        rule: ChainRule,
        anchor_idx: int,
        anchor_finding: dict[str, Any],
    ) -> Optional[dict[str, Any]]:
        matched_findings: list[dict[str, Any]] = []
        matched_assets: list[dict[str, Any]] = []
        anchor_asset_id = anchor_finding["asset_id"]

        matched_findings.append(anchor_finding)

        for i, pred in enumerate(rule.all_of):
            if i == anchor_idx:
                continue
            scope_ids = await self._scope.candidate_asset_ids(
                anchor_asset_id, pred.scope
            )
            if not scope_ids:
                return None

            if pred.finding is not None:
                candidates = await self._findings_for_predicate(
                    pred.finding, scope_ids, rule.window_days
                )
                # Skip the anchor itself.
                candidates = [
                    c
                    for c in candidates
                    if c["id"] != anchor_finding["id"]
                ]
                if not candidates:
                    return None
                matched_findings.append(candidates[0])
            elif pred.asset is not None:
                candidates = await self._assets_for_predicate(
                    pred.asset, scope_ids
                )
                if not candidates:
                    return None
                matched_assets.append(candidates[0])
            else:
                return None

        return self._build_chain_payload(
            rule, anchor_finding, matched_findings, matched_assets
        )

    def _build_chain_payload(
        self,
        rule: ChainRule,
        anchor: dict[str, Any],
        findings: list[dict[str, Any]],
        assets: list[dict[str, Any]],
    ) -> dict[str, Any]:
        host_value = anchor.get("asset_value", "")
        title = f"{rule.name} on {host_value}" if host_value else rule.name
        description = self._compose_description(rule, findings, assets)
        return {
            "chain_rule_id": rule.id,
            "severity": rule.severity,
            "title": title,
            "description": description,
            "finding_ids": sorted({f["id"] for f in findings}),
            "anchor_asset_id": anchor["asset_id"],
            "metadata": {
                "rule_source": rule.source_path,
                "window_days": rule.window_days,
                "matched_asset_ids": [a["id"] for a in assets],
                "evidence_summary": self._evidence_summary(findings, assets),
            },
        }

    @staticmethod
    def _compose_description(
        rule: ChainRule,
        findings: list[dict[str, Any]],
        assets: list[dict[str, Any]],
    ) -> str:
        parts = [rule.name + "."]
        for f in findings:
            parts.append(
                f"  - finding {f['rule_source']}/{f['rule_id']} "
                f"({f['severity']}) on {f.get('asset_value', '?')}"
            )
        for a in assets:
            parts.append(
                f"  - asset {a['kind']}={a['value']}"
            )
        return "\n".join(parts)

    @staticmethod
    def _evidence_summary(
        findings: list[dict[str, Any]], assets: list[dict[str, Any]]
    ) -> dict[str, Any]:
        return {
            "findings": [
                {
                    "id": f["id"],
                    "rule_id": f["rule_id"],
                    "severity": f["severity"],
                    "cvss": float(f["cvss"]) if f.get("cvss") is not None else None,
                    "asset_value": f.get("asset_value"),
                }
                for f in findings
            ],
            "assets": [
                {"id": a["id"], "kind": a["kind"], "value": a["value"]}
                for a in assets
            ],
        }

    # ------------------------------------------------------------------
    # Sweep: re-run matcher across every open finding.
    # ------------------------------------------------------------------

    async def sweep_open_findings(
        self, limit: int = 5000
    ) -> list[dict[str, Any]]:
        rows = await self._db.fetch(
            """
            SELECT id::text FROM findings
            WHERE status = 'open'
            ORDER BY last_seen DESC
            LIMIT $1
            """,
            limit,
        )
        out: list[dict[str, Any]] = []
        for r in rows:
            try:
                chains = await self.match_for_finding(r["id"])
                out.extend(chains)
            except Exception:
                log.exception("sweep: match for %s failed", r["id"])
        return out


# ----------------------------------------------------------------------------
# Policy evaluator (runs the user-written SELECT)
# ----------------------------------------------------------------------------

_SAFE_IDENT_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


class PolicyEvaluator:
    def __init__(
        self, db: Database, orch: Optional[OrchestratorClient] = None
    ) -> None:
        self._db = db
        self._orch = orch

    async def evaluate(self, rule: PolicyRule) -> list[dict[str, Any]]:
        """Run the policy's SELECT and build findings for each returned row.

        The query is already validated SELECT-only by the loader; we run
        it inside a read-only transaction as a second line of defense."""
        rows: list[dict[str, Any]] = []
        async with self._db.acquire() as conn:
            tx = conn.transaction(readonly=True)
            await tx.start()
            try:
                recs = await conn.fetch(rule.query)
                rows = [dict(r) for r in recs]
            finally:
                await tx.rollback()

        findings_payload: list[dict[str, Any]] = []
        for row in rows:
            aid = row.get("id") or row.get("asset_id")
            if aid is None:
                continue
            tmpl = rule.on_hit.create_finding or {}
            payload = {
                "asset_id": str(aid),
                "rule_source": "policy",
                "rule_id": rule.id,
                "severity": tmpl.get("severity", rule.severity),
                "title": tmpl.get("title", rule.name),
                "description": tmpl.get("description", rule.description or rule.name),
                "evidence": {"policy_row": {k: str(v) for k, v in row.items()}},
                "metadata": {"policy_source": rule.source_path},
                "status": "open",
            }
            findings_payload.append(payload)

        if self._orch is not None and findings_payload:
            await self._orch.upsert_findings(findings_payload)

        return findings_payload

    async def evaluate_all(self, rules: Iterable[PolicyRule]) -> int:
        n = 0
        for r in rules:
            try:
                n += len(await self.evaluate(r))
            except Exception:
                log.exception("policy %s failed", r.id)
        return n
