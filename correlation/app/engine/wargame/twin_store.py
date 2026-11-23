"""The Wargame *twin* store (schema/042_wargame_twin.sql).

The twin is the persisted, rule-aware model an assessment runs over: the
parsed vendor-neutral rule sets plus the declared topology (segments and
edges). The correlation service writes it when config is ingested;
``/compute-wargame`` loads it back into a searchable
:class:`~app.engine.wargame.environment.Environment`, so routes are proved
by config rather than merely inferred from the asset graph.

Two layers, mirroring :mod:`.store`:

* **Pure** ser/de (``*_to_row`` / ``row_to_*``). Plain dicts/lists matching
  the 042 columns; no I/O, deterministic, and round-trip exact — a
  :class:`RuleSet` or :class:`EdgeSpec` serialised to rows and rebuilt is
  equal to the original.
* **Async** persistence. Each writer runs in one transaction
  (``db.acquire()`` + ``conn.transaction()``) with parameterized asyncpg and
  JSONB columns passed as Python objects (``Database`` registers a
  ``json.dumps`` codec, so no manual dumps). ``replace=True`` deletes the
  tenant's rows first; RLS (retrofitted by 099_tenancy.sql) scopes every
  statement to the current tenant, so a twin is replaced in place.

DEFENSIVE: pure data and DB read/write only. Nothing here executes, emits,
or represents an exploit.
"""
from __future__ import annotations

from typing import Any, Optional

from ...db import Database
from .environment import Environment
from .fabric import EdgeSpec, SegmentSpec, TopologySpec
from .model import (
    Action,
    EvidenceLabel,
    NodeRole,
    PortRange,
    Proto,
    Rule,
    RuleSet,
)
from . import topology


# ---------------------------------------------------------------------------
# Pure ser/de (round-trip exact)
# ---------------------------------------------------------------------------

def portrange_to_json(pr: Optional[PortRange]) -> Optional[dict[str, Any]]:
    """A :class:`PortRange` as ``{"proto", "low", "high"}``; ``None`` → ``None``."""
    if pr is None:
        return None
    return {"proto": pr.proto.value, "low": pr.low, "high": pr.high}


def portrange_from_json(d: Optional[dict[str, Any]]) -> Optional[PortRange]:
    """Inverse of :func:`portrange_to_json`."""
    if d is None:
        return None
    return PortRange(Proto(d["proto"]), int(d["low"]), int(d["high"]))


def rule_to_row(rule: Rule) -> dict[str, Any]:
    """One :class:`Rule` as a ``wargame_rules`` row (without ``ruleset_key``,
    which :func:`ruleset_to_rows` stamps on)."""
    return {
        "rule_id": rule.id,
        "ord": rule.order,
        "action": rule.action.value,
        "src_cidrs": list(rule.src_cidrs),
        "dst_cidrs": list(rule.dst_cidrs),
        "ports": [portrange_to_json(p) for p in rule.ports],
        "conditional": bool(rule.conditional),
        "vendor": rule.vendor,
        "raw_ref": rule.raw_ref,
        "cost_class": rule.cost_class,
    }


def row_to_rule(row: dict[str, Any]) -> Rule:
    """Inverse of :func:`rule_to_row`."""
    return Rule(
        id=row["rule_id"],
        action=Action(row["action"]),
        order=int(row["ord"]),
        src_cidrs=tuple(row["src_cidrs"]),
        dst_cidrs=tuple(row["dst_cidrs"]),
        ports=tuple(portrange_from_json(p) for p in row["ports"]),
        vendor=row.get("vendor", ""),
        conditional=bool(row["conditional"]),
        raw_ref=row.get("raw_ref", ""),
        cost_class=row.get("cost_class", "network_rule"),
    )


def ruleset_to_rows(rs: RuleSet) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """A :class:`RuleSet` as ``(ruleset_row, rule_rows)``; each rule row carries
    the parent ``ruleset_key`` so the writer can insert them independently."""
    ruleset_row = {
        "ruleset_key": rs.id,
        "vendor": rs.vendor,
        "default_action": rs.default_action.value,
        "name": rs.id,
    }
    rule_rows: list[dict[str, Any]] = []
    for r in rs.rules:
        row = rule_to_row(r)
        row["ruleset_key"] = rs.id
        rule_rows.append(row)
    return ruleset_row, rule_rows


def rows_to_ruleset(
    ruleset_row: dict[str, Any], rule_rows: list[dict[str, Any]]
) -> RuleSet:
    """Inverse of :func:`ruleset_to_rows`; rules are (re)sorted by ``ord``."""
    ordered = sorted(rule_rows, key=lambda r: (int(r["ord"]), r["rule_id"]))
    return RuleSet(
        id=ruleset_row["ruleset_key"],
        rules=[row_to_rule(r) for r in ordered],
        default_action=Action(ruleset_row["default_action"]),
        vendor=ruleset_row.get("vendor", ""),
    )


def segment_to_row(seg: SegmentSpec) -> dict[str, Any]:
    """A :class:`SegmentSpec` as a ``wargame_segments`` row."""
    return {
        "seg_key": seg.id,
        "cidrs": list(seg.cidrs),
        "role": seg.role.value,
        "reason": seg.reason,
        "jewel_kind": seg.jewel_kind,
        "metadata": dict(seg.metadata),
    }


def row_to_segment(row: dict[str, Any]) -> SegmentSpec:
    """Inverse of :func:`segment_to_row`."""
    return SegmentSpec(
        id=row["seg_key"],
        cidrs=tuple(row["cidrs"]),
        role=NodeRole(row["role"]),
        reason=row.get("reason", ""),
        jewel_kind=row.get("jewel_kind", ""),
        metadata=dict(row["metadata"] or {}),
    )


def edge_to_row(e: EdgeSpec) -> dict[str, Any]:
    """An :class:`EdgeSpec` as a ``wargame_edges`` row (labels sorted for a
    deterministic payload)."""
    return {
        "src": e.src,
        "dst": e.dst,
        "rule_set_id": e.rule_set_id,
        "port": portrange_to_json(e.port),
        "base_labels": sorted(lb.value for lb in e.base_labels),
        "fix_candidate_id": e.fix_candidate_id,
        "metadata": dict(e.metadata),
    }


def row_to_edge(row: dict[str, Any]) -> EdgeSpec:
    """Inverse of :func:`edge_to_row`."""
    return EdgeSpec(
        src=row["src"],
        dst=row["dst"],
        rule_set_id=row["rule_set_id"],
        port=portrange_from_json(row["port"]),
        base_labels=frozenset(EvidenceLabel(x) for x in row["base_labels"]),
        fix_candidate_id=row["fix_candidate_id"],
        metadata=dict(row["metadata"] or {}),
    )


# ---------------------------------------------------------------------------
# Async persistence
# ---------------------------------------------------------------------------

async def persist_rulesets(
    db: Database,
    rulesets: dict[str, RuleSet],
    *,
    replace: bool = True,
    snapshots: list[dict[str, Any]] = (),
    source: str = "",
) -> None:
    """Write the parsed rule sets (and optional config snapshots).

    ``replace=True`` deletes the tenant's whole rule-set twin first (RLS scopes
    every DELETE to the tenant), snapshots included.

    ``replace=False`` is the incremental ingest: it **replaces by identity, it
    never appends a second copy**. Any stored rule set with the same
    ``ruleset_key`` as one being written is deleted first, as is every rule set
    previously ingested from the same non-empty ``source`` (so a device whose
    config dropped a rule set loses it). Re-ingesting the same device is
    therefore idempotent. Snapshots for the same ``(vendor, source)`` are
    replaced the same way, so certificate provenance only ever names configs
    that are still in the twin.

    ``snapshots`` is a list of ``{vendor, source, sha256}`` dicts recorded for
    certificate provenance. All of it runs in one transaction.
    """
    async with db.acquire() as conn:
        async with conn.transaction():
            if replace:
                await conn.execute("DELETE FROM wargame_rules")
                await conn.execute("DELETE FROM wargame_rulesets")
                await conn.execute("DELETE FROM wargame_config_snapshots")
            else:
                keys = sorted(rulesets)
                stale = await conn.fetch(
                    "SELECT ruleset_key FROM wargame_rulesets "
                    "WHERE ruleset_key = ANY($1::text[]) "
                    "   OR ($2::text <> '' AND metadata->>'source' = $2)",
                    keys,
                    source,
                )
                stale_keys = sorted({r["ruleset_key"] for r in stale})
                if stale_keys:
                    await conn.execute(
                        "DELETE FROM wargame_rules WHERE ruleset_key = ANY($1::text[])",
                        stale_keys,
                    )
                    await conn.execute(
                        "DELETE FROM wargame_rulesets WHERE ruleset_key = ANY($1::text[])",
                        stale_keys,
                    )
                for snap in snapshots:
                    if snap.get("source"):
                        await conn.execute(
                            "DELETE FROM wargame_config_snapshots "
                            "WHERE vendor = $1 AND source = $2",
                            snap.get("vendor", ""),
                            snap["source"],
                        )

            for key in sorted(rulesets):
                ruleset_row, rule_rows = ruleset_to_rows(rulesets[key])
                await conn.execute(
                    """
                    INSERT INTO wargame_rulesets
                      (ruleset_key, vendor, default_action, name, metadata)
                    VALUES ($1, $2, $3, $4, $5::jsonb)
                    """,
                    ruleset_row["ruleset_key"],
                    ruleset_row["vendor"],
                    ruleset_row["default_action"],
                    ruleset_row["name"],
                    {"source": source} if source else {},
                )
                if rule_rows:
                    await conn.executemany(
                        """
                        INSERT INTO wargame_rules
                          (ruleset_key, rule_id, ord, action, src_cidrs,
                           dst_cidrs, ports, conditional, vendor, raw_ref,
                           cost_class)
                        VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb,
                                $7::jsonb, $8, $9, $10, $11)
                        """,
                        [
                            (
                                r["ruleset_key"], r["rule_id"], r["ord"],
                                r["action"], r["src_cidrs"], r["dst_cidrs"],
                                r["ports"], r["conditional"], r["vendor"],
                                r["raw_ref"], r["cost_class"],
                            )
                            for r in rule_rows
                        ],
                    )

            for snap in snapshots:
                # Identical (vendor, source, hash) is recorded once.
                await conn.execute(
                    """
                    INSERT INTO wargame_config_snapshots (vendor, source, sha256)
                    SELECT $1::text, $2::text, $3::text
                     WHERE NOT EXISTS (
                       SELECT 1 FROM wargame_config_snapshots
                        WHERE vendor = $1 AND source = $2 AND sha256 = $3)
                    """,
                    snap.get("vendor", ""),
                    snap.get("source", ""),
                    snap["sha256"],
                )


async def persist_topology(
    db: Database,
    segments: list[SegmentSpec],
    edges: list[EdgeSpec],
    *,
    replace: bool = True,
) -> None:
    """Write the declared topology. ``replace`` deletes the tenant's existing
    ``wargame_segments`` + ``wargame_edges`` first (RLS-scoped)."""
    seg_rows = [segment_to_row(s) for s in segments]
    edge_rows = [edge_to_row(e) for e in edges]
    async with db.acquire() as conn:
        async with conn.transaction():
            if replace:
                await conn.execute("DELETE FROM wargame_edges")
                await conn.execute("DELETE FROM wargame_segments")
            if seg_rows:
                await conn.executemany(
                    """
                    INSERT INTO wargame_segments
                      (seg_key, cidrs, role, reason, jewel_kind, metadata)
                    VALUES ($1, $2::jsonb, $3, $4, $5, $6::jsonb)
                    """,
                    [
                        (
                            r["seg_key"], r["cidrs"], r["role"], r["reason"],
                            r["jewel_kind"], r["metadata"],
                        )
                        for r in seg_rows
                    ],
                )
            if edge_rows:
                await conn.executemany(
                    """
                    INSERT INTO wargame_edges
                      (src, dst, rule_set_id, port, base_labels,
                       fix_candidate_id, metadata)
                    VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6, $7::jsonb)
                    """,
                    [
                        (
                            r["src"], r["dst"], r["rule_set_id"], r["port"],
                            r["base_labels"], r["fix_candidate_id"],
                            r["metadata"],
                        )
                        for r in edge_rows
                    ],
                )


async def has_twin(db: Database) -> bool:
    """True if a twin exists — any segment or any rule set is stored."""
    val = await db.fetchval(
        "SELECT EXISTS(SELECT 1 FROM wargame_segments) "
        "OR EXISTS(SELECT 1 FROM wargame_rulesets)"
    )
    return bool(val)


async def load_twin(db: Database) -> tuple[dict[str, RuleSet], TopologySpec]:
    """Read every twin row and rebuild the rule sets dict + a
    :class:`TopologySpec`. Deterministic ordering throughout."""
    ruleset_rows = await db.fetch(
        "SELECT ruleset_key, vendor, default_action, name "
        "FROM wargame_rulesets ORDER BY ruleset_key"
    )
    rule_rows = await db.fetch(
        "SELECT ruleset_key, rule_id, ord, action, src_cidrs, dst_cidrs, "
        "ports, conditional, vendor, raw_ref, cost_class "
        "FROM wargame_rules ORDER BY ruleset_key, ord"
    )
    by_key: dict[str, list[dict[str, Any]]] = {}
    for r in rule_rows:
        by_key.setdefault(r["ruleset_key"], []).append(dict(r))

    rulesets: dict[str, RuleSet] = {}
    for rs_row in ruleset_rows:
        rsr = dict(rs_row)
        key = rsr["ruleset_key"]
        rulesets[key] = rows_to_ruleset(rsr, by_key.get(key, []))

    seg_rows = await db.fetch(
        "SELECT seg_key, cidrs, role, reason, jewel_kind, metadata "
        "FROM wargame_segments ORDER BY seg_key"
    )
    edge_rows = await db.fetch(
        "SELECT src, dst, rule_set_id, port, base_labels, fix_candidate_id, "
        "metadata FROM wargame_edges ORDER BY src, dst"
    )
    spec = TopologySpec(
        segments=[row_to_segment(dict(r)) for r in seg_rows],
        edges=[row_to_edge(dict(r)) for r in edge_rows],
    )
    return rulesets, spec


async def load_environment(db: Database) -> Optional[Environment]:
    """Load the twin and assemble it into a searchable
    :class:`~app.engine.wargame.environment.Environment`.

    Returns ``None`` when no topology is declared (no segments), so callers
    can fall back to the inferred asset graph.
    """
    rulesets, spec = await load_twin(db)
    if not spec.segments:
        return None
    return topology.build_topology(spec, rulesets).environment


async def config_hashes(db: Database) -> list[str]:
    """The distinct snapshot hashes behind the twin, for certificate
    provenance. Sorted for determinism."""
    rows = await db.fetch(
        "SELECT DISTINCT sha256 FROM wargame_config_snapshots ORDER BY sha256"
    )
    return [r["sha256"] for r in rows]
