"""Findings + chains + outbound-audit routers.

- `POST /v1/findings/bulk` -- upsert by (asset_id, rule_id, rule_source).
  Also accepts `asset_value` (+ optional `asset_kind`) and resolves /
  upserts the asset by (kind, canonical) when no asset_id is given.
- `GET  /v1/findings` -- paged response `{items,total,limit,offset}` with
  severity, status, asset_id, rule_source, kev and `q` filters. Lifecycle
  (schema 019, app/lifecycle.py): suppressed findings and collapsed
  duplicates are hidden by default (`suppressed=include|only`,
  `include_duplicates=true`) and counted in `suppressed_total` /
  `duplicates_total`; `sla_breached`, `fingerprint` and `sort` filters; every
  item carries `priority_score`, `why`, `sources`, `due_at`, `sla_breached`.
- `GET  /v1/findings/list` -- legacy bare-list response for callers that
  don't want the envelope (kept for dashboard back-compat).
- `GET  /v1/findings/{id}` -- finding + its asset + any chain it is in.
- `PATCH /v1/findings/{id}` -- status/notes/assigned_to. Publishes
  `finding_closed` on a transition to a terminal status. `accepted` /
  `false_positive` require a reason (`notes`); prefer the dedicated
  accept / false-positive / reopen endpoints in routers/lifecycle.py.
- `POST /v1/findings/recompute-identity` -- admin backfill of dedupe identity.
- `GET  /v1/chains` -- list correlated finding chains.
- `POST /v1/chains` -- upsert from the correlator.
- `POST /v1/outbound/bulk` -- the active worker's audit sink.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from .. import audit
from .. import lifecycle
from ..auth import Principal, classification_rank_sql, current_principal
from ..db import get_pool
from ..models import (
    AssetOut,
    ChainIn,
    ChainOut,
    FindingBulkIn,
    FindingIn,
    FindingPatch,
    FindingStatus,
    OutboundBulkIn,
    OutboundBulkOut,
    RuleSource,
    Severity,
)
from ..queue import get_redis, publish_event
from ..scope import normalize

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1", tags=["findings"])
outbound_router = APIRouter(prefix="/v1/outbound", tags=["audit"])


# --------------------------------------------------------------------------- #
# Findings bulk
# --------------------------------------------------------------------------- #

_BULK_SQL = """
INSERT INTO findings (
    asset_id, rule_id, rule_source, severity, title, description,
    impact, remediation, evidence, cvss, epss, "references", metadata
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11, $12::text[], $13::jsonb
)
ON CONFLICT (asset_id, rule_id, rule_source) DO UPDATE SET
    last_seen = NOW(),
    severity = EXCLUDED.severity,
    title = EXCLUDED.title,
    description = EXCLUDED.description,
    impact = COALESCE(EXCLUDED.impact, findings.impact),
    remediation = COALESCE(EXCLUDED.remediation, findings.remediation),
    evidence = findings.evidence || EXCLUDED.evidence,
    cvss = COALESCE(EXCLUDED.cvss, findings.cvss),
    epss = COALESCE(EXCLUDED.epss, findings.epss),
    "references" = EXCLUDED."references",
    metadata = findings.metadata || EXCLUDED.metadata
RETURNING id, asset_id, rule_id, rule_source, severity, title, description,
          impact, remediation, evidence, cvss, epss, "references", status,
          first_seen, last_seen, assigned_to, metadata, (xmax = 0) AS was_inserted,
          status_reason, status_by, status_changed_at, accepted_until,
          suppressed_by, suppressed_at, fingerprint, vuln_keys, duplicate_of
"""


_ASSET_UPSERT_FOR_FINDING_SQL = """
INSERT INTO assets (kind, value, canonical, source, confidence, metadata)
VALUES ($1, $2, $3, 'finding-bulk', 100, '{}'::jsonb)
ON CONFLICT (tenant_id, kind, canonical) DO UPDATE SET
    last_seen = NOW()
RETURNING id, kind, value, canonical, first_seen, last_seen, confidence,
          source, metadata, (xmax = 0) AS was_inserted
"""


async def _resolve_or_upsert_asset(
    con, item: FindingIn
) -> tuple[UUID, dict[str, Any] | None]:
    """Return (asset_id, insert_event_or_None) for a finding item.

    Prefer `asset_id` on the payload. Otherwise look up / upsert by
    (asset_kind, canonical(asset_value)); default kind is `endpoint`.
    """
    if item.asset_id is not None:
        return item.asset_id, None
    if not item.asset_value:
        raise HTTPException(
            status_code=422,
            detail="finding requires asset_id or asset_value",
        )
    kind = item.asset_kind or "endpoint"
    v = item.asset_value.strip()
    if kind in {"domain", "subdomain", "ipv4", "ipv6", "endpoint"}:
        canonical = normalize(v) or v.lower()
    else:
        canonical = v.lower()

    row = await con.fetchrow(
        _ASSET_UPSERT_FOR_FINDING_SQL, kind, v, canonical
    )
    event = None
    if row["was_inserted"]:
        event = {
            "event": "asset_added",
            "asset_id": str(row["id"]),
            "kind": row["kind"],
            "value": row["value"],
            "canonical": row["canonical"],
            "source": "finding-bulk",
            "ts": row["first_seen"].isoformat(),
        }
    return row["id"], event


@router.post("/findings/bulk", response_model=lifecycle.FindingBulkLifecycleOut)
async def bulk_upsert(
    body: FindingBulkIn,
    pool=Depends(get_pool),
    r=Depends(get_redis),
):
    inserted = 0
    updated = 0
    n_suppressed = 0
    n_duplicates = 0
    out: list[lifecycle.FindingLifecycleOut] = []
    events: list[dict[str, Any]] = []

    async with pool.acquire() as con:
        async with con.transaction():
            # Lifecycle (schema 019): suppression rules are loaded once per
            # batch; identity/dedupe/suppression are stamped per row below.
            suppressions = await lifecycle.load_active_suppressions(con)
            asset_cache: dict[UUID, dict[str, Any]] = {}
            for item in body.items:
                asset_id, ev_asset = await _resolve_or_upsert_asset(con, item)
                if ev_asset is not None:
                    events.append(ev_asset)
                row = await con.fetchrow(
                    _BULK_SQL,
                    asset_id,
                    item.rule_id,
                    item.rule_source,
                    item.severity,
                    item.title,
                    item.description,
                    item.impact,
                    item.remediation,
                    json.dumps(item.evidence),
                    item.cvss,
                    item.epss,
                    list(item.references),
                    json.dumps(item.metadata),
                )
                d = _coerce_finding_row(row)
                was_inserted = d.pop("was_inserted")
                d.update(await lifecycle.apply_ingest(con, d, suppressions, asset_cache))
                d["suppressed"] = d.get("suppressed_by") is not None
                n_suppressed += 1 if d["suppressed"] else 0
                n_duplicates += 1 if d.get("duplicate_of") else 0
                if was_inserted:
                    inserted += 1
                    # A suppressed finding is stored but must not page anyone:
                    # it gets its own event instead of `finding_opened`.
                    events.append(
                        {
                            "event": "finding_suppressed" if d["suppressed"] else "finding_opened",
                            "finding_id": str(d["id"]),
                            "asset_id": str(d["asset_id"]),
                            "severity": d["severity"],
                            "rule_id": d["rule_id"],
                            "rule_source": d["rule_source"],
                            "duplicate_of": (
                                str(d["duplicate_of"]) if d.get("duplicate_of") else None
                            ),
                            "ts": d["first_seen"].isoformat(),
                        }
                    )
                else:
                    updated += 1
                out.append(lifecycle.FindingLifecycleOut.model_validate(d))

    for ev in events:
        try:
            await publish_event(r, ev)
        except Exception:
            logger.exception("publish_event_failed", extra=ev)

    return lifecycle.FindingBulkLifecycleOut(
        inserted=inserted, updated=updated, items=out,
        suppressed=n_suppressed, duplicates=n_duplicates,
    )


# --------------------------------------------------------------------------- #
# Findings list (paged envelope + legacy bare list) + detail
# --------------------------------------------------------------------------- #

_FINDING_LIST_COLS = (
    'f.id, f.asset_id, f.rule_id, f.rule_source, f.severity, f.title, '
    'f.description, f.impact, f.remediation, f.evidence, f.cvss, f.epss, '
    'f."references", f.status, f.first_seen, f.last_seen, f.assigned_to, '
    'f.metadata, f.classification, '
    # lifecycle (schema 019)
    'f.status_reason, f.status_by, f.status_changed_at, f.accepted_until, '
    'f.suppressed_by, f.suppressed_at, f.fingerprint, f.vuln_keys, f.duplicate_of'
)

# ABAC: SQL expression comparing a finding's classification rank to the
# caller's clearance rank. Applied in every list/detail read so over-classified
# findings never leave the DB.
_FINDING_ABAC = f"{classification_rank_sql('f.classification')} <= "

# Blast score read off the finding's own metadata; null when absent or not a
# JSON number. Kept as a safe cast (jsonb_typeof guard) so a non-numeric value
# never raises instead of returning null.
_BLAST_FINDING_EXPR = (
    "CASE WHEN jsonb_typeof(f.metadata->'blast_score') = 'number' "
    "THEN (f.metadata->>'blast_score')::float ELSE NULL END"
)

# Extra columns surfaced on every list/detail finding row via a LEFT JOIN to
# the finding's asset. Additive to the response shape.
_FINDING_EXTRA_COLS = (
    "a.value AS asset_value, a.kind AS asset_kind, "
    f"{_BLAST_FINDING_EXPR} AS blast_score, "
    # lifecycle enrichment inputs (consumed by lifecycle.enrich, not returned raw)
    "a.metadata AS asset_metadata, sp.hours AS sla_hours, "
    "t.owner_team AS ticket_owner, t.sla_due AS ticket_due"
)

# FROM clause shared by the list/detail queries: finding joined to its asset,
# its severity's SLA policy and its ticket (UNIQUE(finding_id): no fan-out).
_FINDING_FROM = (
    "FROM findings f LEFT JOIN assets a ON a.id = f.asset_id "
    "LEFT JOIN sla_policies sp ON sp.severity = f.severity "
    "LEFT JOIN tickets t ON t.finding_id = f.id"
)

# SLA due date in SQL (mirrors lifecycle.compute_due) so it can be filtered.
_DUE_EXPR = (
    "COALESCE(t.sla_due, CASE WHEN sp.hours > 0 "
    "THEN f.first_seen + make_interval(hours => sp.hours) END)"
)
_BREACHED_EXPR = f"(f.status IN ('open','triaged') AND {_DUE_EXPR} < NOW())"


def _build_find_where(
    severity: Severity | None,
    status: FindingStatus | None,
    asset_id: UUID | None,
    rule_source: RuleSource | None,
    kev: bool | None,
    q: str | None,
    sla_breached: bool | None = None,
    fingerprint: str | None = None,
) -> tuple[list[str], list[Any], bool]:
    clauses: list[str] = []
    args: list[Any] = []
    needs_cve_join = False
    if severity is not None:
        args.append(severity)
        clauses.append(f"f.severity = ${len(args)}")
    if status is not None:
        args.append(status)
        clauses.append(f"f.status = ${len(args)}")
    if asset_id is not None:
        args.append(asset_id)
        clauses.append(f"f.asset_id = ${len(args)}")
    if rule_source is not None:
        args.append(rule_source)
        clauses.append(f"f.rule_source = ${len(args)}")
    if kev:
        needs_cve_join = True
        clauses.append(
            "(COALESCE((f.metadata->>'kev')::boolean, FALSE) = TRUE"
            " OR EXISTS ("
            "   SELECT 1 FROM cve_matches m JOIN cves c ON c.id = m.cve_id"
            "    WHERE m.asset_id = f.asset_id"
            "      AND (c.known_exploited = TRUE)"
            "      AND (m.cve_id = f.rule_id OR f.rule_source = 'cve_match')"
            "))"
        )
    if q:
        args.append(f"%{q}%")
        clauses.append(
            f"(f.title ILIKE ${len(args)} OR f.description ILIKE ${len(args)})"
        )
    if sla_breached is not None:
        clauses.append(
            _BREACHED_EXPR if sla_breached else f"NOT COALESCE({_BREACHED_EXPR}, FALSE)"
        )
    if fingerprint:
        args.append(fingerprint)
        clauses.append(f"f.fingerprint = ${len(args)}")
    return clauses, args, needs_cve_join


# Default reads hide suppressed findings and collapsed duplicates; both stay
# countable via `suppressed_total` / `duplicates_total` on the page envelope.
_SUPPRESSED_CLAUSE = {
    "exclude": "f.suppressed_by IS NULL",
    "only": "f.suppressed_by IS NOT NULL",
    "include": None,
}
_SORTS = {
    "last_seen": "f.last_seen DESC",
    "due_at": f"{_DUE_EXPR} ASC NULLS LAST, f.last_seen DESC",
    "severity": (
        "CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
        "WHEN 'low' THEN 3 ELSE 4 END, f.last_seen DESC"
    ),
}


async def _query_findings(
    pool,
    principal: Principal,
    *,
    severity: Severity | None,
    status: FindingStatus | None,
    asset_id: UUID | None,
    rule_source: RuleSource | None,
    kev: bool | None,
    q: str | None,
    limit: int,
    offset: int,
    suppressed: str = "exclude",
    include_duplicates: bool = False,
    sla_breached: bool | None = None,
    fingerprint: str | None = None,
    sort: str = "last_seen",
    with_counts: bool = False,
) -> tuple[list[lifecycle.FindingLifecycleOut], int, int, int]:
    """Shared list query. Returns (items, total, suppressed_total, duplicates_total)."""
    await lifecycle.maybe_sweep(pool)
    base, args, _needs_join = _build_find_where(
        severity, status, asset_id, rule_source, kev, q, sla_breached, fingerprint
    )
    args.append(principal.clearance_rank)
    base.append(f"{_FINDING_ABAC}${len(args)}")
    clauses = list(base)
    sup = _SUPPRESSED_CLAUSE.get(suppressed)
    if sup:
        clauses.append(sup)
    if not include_duplicates:
        clauses.append("f.duplicate_of IS NULL")
    where = "WHERE " + " AND ".join(clauses)
    args_list = list(args)
    args_list.extend([limit, offset])
    sql = f"""
        SELECT {_FINDING_LIST_COLS}, {_FINDING_EXTRA_COLS}
          {_FINDING_FROM}
          {where}
         ORDER BY {_SORTS.get(sort, _SORTS["last_seen"])}
         LIMIT ${len(args_list) - 1} OFFSET ${len(args_list)}
    """
    async with pool.acquire() as con:
        total = sup_total = dup_total = 0
        if with_counts:
            row = await con.fetchrow(
                f"""
                SELECT COUNT(*) FILTER (WHERE {' AND '.join(clauses)}) AS total,
                       COUNT(*) FILTER (WHERE f.suppressed_by IS NOT NULL
                                          AND f.duplicate_of IS NULL) AS sup,
                       COUNT(*) FILTER (WHERE f.duplicate_of IS NOT NULL) AS dup
                  {_FINDING_FROM} WHERE {' AND '.join(base)}
                """,
                *args,
            )
            total, sup_total, dup_total = int(row["total"]), int(row["sup"]), int(row["dup"])
        rows = await con.fetch(sql, *args_list)
        items = await lifecycle.enrich(con, [_coerce_finding_row(r) for r in rows])
    return items, total, sup_total, dup_total


async def fetch_enriched(con, ids: list[UUID]) -> list[lifecycle.FindingLifecycleOut]:
    """Re-read findings by id with the full list projection + enrichment."""
    rows = await con.fetch(
        f"SELECT {_FINDING_LIST_COLS}, {_FINDING_EXTRA_COLS} {_FINDING_FROM} "
        "WHERE f.id = ANY($1::uuid[])",
        ids,
    )
    return await lifecycle.enrich(con, [_coerce_finding_row(r) for r in rows])


@router.get("/findings", response_model=lifecycle.FindingLifecyclePage)
async def list_findings_paged(
    severity: Severity | None = None,
    status: FindingStatus | None = None,
    asset_id: UUID | None = None,
    rule_source: RuleSource | None = None,
    kev: bool | None = None,
    q: str | None = Query(None, max_length=256),
    suppressed: lifecycle.SuppressedFilter = Query(
        "exclude", description="exclude (default) | include | only"),
    include_duplicates: bool = Query(
        False, description="also return findings collapsed into a primary"),
    sla_breached: bool | None = None,
    fingerprint: str | None = Query(None, max_length=64),
    sort: str = Query("last_seen", pattern="^(last_seen|due_at|severity)$"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    items, total, sup_total, dup_total = await _query_findings(
        pool, principal, severity=severity, status=status, asset_id=asset_id,
        rule_source=rule_source, kev=kev, q=q, limit=limit, offset=offset,
        suppressed=suppressed, include_duplicates=include_duplicates,
        sla_breached=sla_breached, fingerprint=fingerprint, sort=sort, with_counts=True,
    )
    return lifecycle.FindingLifecyclePage(
        items=items, total=total, limit=limit, offset=offset,
        suppressed_total=sup_total, duplicates_total=dup_total,
    )


@router.get("/findings/list", response_model=list[lifecycle.FindingLifecycleOut])
async def list_findings_legacy(
    severity: Severity | None = None,
    status: FindingStatus | None = None,
    asset_id: UUID | None = None,
    rule_source: RuleSource | None = None,
    kev: bool | None = None,
    q: str | None = Query(None, max_length=256),
    suppressed: lifecycle.SuppressedFilter = "exclude",
    include_duplicates: bool = False,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    """Legacy bare-list response for pre-pagination clients."""
    items, *_ = await _query_findings(
        pool, principal, severity=severity, status=status, asset_id=asset_id,
        rule_source=rule_source, kev=kev, q=q, limit=limit, offset=offset,
        suppressed=suppressed, include_duplicates=include_duplicates,
    )
    return items


@router.post("/findings/recompute-identity")
async def recompute_identity(pool=Depends(get_pool)):
    """Admin: stamp dedupe identity on rows that predate schema 019 (or were
    inserted directly) and collapse duplicates among them."""
    async with pool.acquire() as con:
        async with con.transaction():
            return await lifecycle.backfill_identity(con)


@router.get("/findings/{finding_id}", response_model=lifecycle.FindingLifecycleDetailOut)
async def get_finding(
    finding_id: UUID,
    request: Request,
    pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    """Finding + its asset + any chain it participates in (+ lifecycle)."""
    await lifecycle.maybe_sweep(pool)
    async with pool.acquire() as con:
        row = await con.fetchrow(
            f"""
            SELECT {_FINDING_LIST_COLS}, {_FINDING_EXTRA_COLS}
              {_FINDING_FROM} WHERE f.id = $1
              AND {_FINDING_ABAC}$2
            """,
            finding_id,
            principal.clearance_rank,
        )
        if row is None:
            # Either missing or above the caller's clearance -- same answer so
            # existence of over-classified findings is not disclosed.
            raise HTTPException(status_code=404, detail="finding not found")
        # Flag restricted-data reads for the audit middleware.
        if row["classification"] == "restricted":
            request.state.audit_restricted = True
            request.state.audit_classification = "restricted"
        asset_row = await con.fetchrow(
            """
            SELECT id, kind, value, canonical, first_seen, last_seen,
                   confidence, source, metadata
              FROM assets WHERE id = $1
            """,
            row["asset_id"],
        )
        chain_rows = await con.fetch(
            """
            SELECT id, chain_rule_id, severity, title, description,
                   impact_narrative, blast_radius_score, created_at,
                   finding_ids, anchor_asset_id, metadata
              FROM finding_chains
             WHERE $1::uuid = ANY(finding_ids)
             ORDER BY created_at DESC
            """,
            finding_id,
        )
        history_rows = await con.fetch(
            """
            SELECT id, from_status, to_status, reason, accepted_until, actor, at
              FROM finding_status_history WHERE finding_id = $1
             ORDER BY at DESC LIMIT 50
            """,
            finding_id,
        )
        (finding,) = await lifecycle.enrich(con, [_coerce_finding_row(row)])

    asset = None
    if asset_row is not None:
        d = dict(asset_row)
        if isinstance(d.get("metadata"), str):
            d["metadata"] = json.loads(d["metadata"])
        asset = AssetOut.model_validate(d)
    chains = [_coerce_chain_row(r) for r in chain_rows]
    history = [lifecycle.StatusHistoryOut.model_validate(dict(h)) for h in history_rows]
    return lifecycle.FindingLifecycleDetailOut(
        finding=finding, asset=asset, chains=chains, history=history
    )


@router.patch("/findings/{finding_id}", response_model=lifecycle.FindingLifecycleOut)
async def patch_finding(
    finding_id: UUID,
    patch: FindingPatch,
    request: Request,
    pool=Depends(get_pool),
    r=Depends(get_redis),
    principal: Principal = Depends(current_principal),
):
    set_parts: list[str] = []
    args: list[Any] = []
    if patch.status is not None:
        # Dismissals need a reason (schema 019); PATCH carries it as `notes`.
        reason = (patch.notes or "").strip()
        if patch.status in lifecycle.DISMISSED_STATUSES and not reason:
            raise HTTPException(
                status_code=422,
                detail=f"status '{patch.status}' requires a reason (send it as notes)",
            )
        args.append(patch.status)
        set_parts.append(f"status = ${len(args)}")
        args.append(reason or None)
        set_parts.append(f"status_reason = ${len(args)}")
        args.append(principal.actor)
        set_parts.append(f"status_by = ${len(args)}")
        set_parts.append("status_changed_at = NOW()")
        if patch.status not in lifecycle.EXPIRING_STATUSES:
            set_parts.append("accepted_until = NULL")
    if patch.assigned_to is not None:
        args.append(patch.assigned_to)
        set_parts.append(f"assigned_to = ${len(args)}")
    if patch.notes is not None:
        args.append(json.dumps({"notes": patch.notes}))
        set_parts.append(f"metadata = metadata || ${len(args)}::jsonb")
    if not set_parts:
        raise HTTPException(status_code=422, detail="no patch fields supplied")

    args.append(finding_id)
    sql = f"""
        UPDATE findings
           SET {", ".join(set_parts)}, last_seen = NOW()
         WHERE id = ${len(args)}
     RETURNING id, asset_id, rule_id, rule_source, severity, title,
               description, impact, remediation, evidence, cvss, epss,
               "references", status, first_seen, last_seen, assigned_to,
               metadata, status_reason, status_by, status_changed_at,
               accepted_until, suppressed_by, suppressed_at, fingerprint,
               vuln_keys, duplicate_of
    """
    async with pool.acquire() as con:
        async with con.transaction():
            prev = await con.fetchval("SELECT status FROM findings WHERE id = $1", finding_id)
            row = await con.fetchrow(sql, *args)
            changed = row is not None and patch.status is not None and prev != patch.status
            if changed:
                await lifecycle.record_history(
                    con, finding_id, prev, patch.status, (patch.notes or "").strip() or None,
                    None, principal.actor,
                )
    if row is None:
        raise HTTPException(status_code=404, detail="finding not found")
    if changed:
        try:
            await audit.record(
                pool, action="update", actor=principal.actor, actor_role=principal.role,
                resource_type="findings", resource_id=str(finding_id),
                method="PATCH", path=request.url.path, status=200,
                request_id=getattr(request.state, "request_id", None),
                details={"transition": "patch", "from": prev, "to": patch.status,
                         "reason": (patch.notes or "").strip() or None},
            )
        except Exception:  # noqa: BLE001
            logger.exception("finding_audit_failed")

    if patch.status in ("fixed", "wontfix", "false_positive", "accepted_risk", "accepted"):
        try:
            await publish_event(
                r,
                {
                    "event": "finding_closed",
                    "finding_id": str(finding_id),
                    "status": patch.status,
                },
            )
        except Exception:
            logger.exception("publish_event_failed")
    d = _coerce_finding_row(row)
    d["suppressed"] = d.get("suppressed_by") is not None
    return lifecycle.FindingLifecycleOut.model_validate(d)


# --------------------------------------------------------------------------- #
# Chains
# --------------------------------------------------------------------------- #

@router.get("/chains", response_model=list[ChainOut])
async def list_chains(
    severity: Severity | None = None,
    anchor_asset_id: UUID | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    pool=Depends(get_pool),
):
    clauses: list[str] = []
    args: list[Any] = []
    if severity is not None:
        args.append(severity)
        clauses.append(f"c.severity = ${len(args)}")
    if anchor_asset_id is not None:
        args.append(anchor_asset_id)
        clauses.append(f"c.anchor_asset_id = ${len(args)}")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    args.extend([limit, offset])
    sql = f"""
        SELECT c.id, c.chain_rule_id, c.severity, c.title, c.description,
               c.impact_narrative, c.blast_radius_score, c.created_at,
               c.finding_ids, c.anchor_asset_id, c.metadata
          FROM finding_chains c
          {where}
         ORDER BY c.created_at DESC
         LIMIT ${len(args) - 1} OFFSET ${len(args)}
    """
    async with pool.acquire() as con:
        rows = await con.fetch(sql, *args)
        if not rows:
            return []
        all_anchor_ids = {r["anchor_asset_id"] for r in rows if r["anchor_asset_id"]}
        all_finding_ids: set[UUID] = set()
        for r in rows:
            for fid in r["finding_ids"] or []:
                all_finding_ids.add(fid)
        asset_map: dict[UUID, AssetOut] = {}
        if all_anchor_ids:
            arows = await con.fetch(
                """
                SELECT id, kind, value, canonical, first_seen, last_seen,
                       confidence, source, metadata
                  FROM assets WHERE id = ANY($1::uuid[])
                """,
                list(all_anchor_ids),
            )
            for ar in arows:
                d = dict(ar)
                if isinstance(d.get("metadata"), str):
                    d["metadata"] = json.loads(d["metadata"])
                asset_map[ar["id"]] = AssetOut.model_validate(d)
        severity_map: dict[UUID, str] = {}
        if all_finding_ids:
            frows = await con.fetch(
                "SELECT id, severity FROM findings WHERE id = ANY($1::uuid[])",
                list(all_finding_ids),
            )
            severity_map = {fr["id"]: fr["severity"] for fr in frows}

    out: list[ChainOut] = []
    for r in rows:
        chain = _coerce_chain_row(r)
        if chain.anchor_asset_id is not None:
            chain.anchor_asset = asset_map.get(chain.anchor_asset_id)
        chain.finding_severities = [
            severity_map[fid]  # type: ignore[misc]
            for fid in chain.finding_ids
            if fid in severity_map
        ]
        out.append(chain)
    return out


@router.post("/chains", response_model=ChainOut, status_code=201)
async def create_chain(
    body: ChainIn,
    pool=Depends(get_pool),
    r=Depends(get_redis),
):
    """Upsert a chain from the correlator.

    - If `anchor_asset_id` is set: upsert by (chain_rule_id, anchor_asset_id).
    - Otherwise: upsert by (chain_rule_id, metadata.fingerprint) where
      `fingerprint` is a stable hash the correlator chooses (usually from
      sorted finding_ids).
    Returns 400 if any finding_id doesn't exist. Publishes `chain_detected`
    on insert.
    """
    async with pool.acquire() as con:
        async with con.transaction():
            # Validate that every finding_id exists.
            existing = await con.fetchval(
                "SELECT COUNT(*) FROM findings WHERE id = ANY($1::uuid[])",
                list(body.finding_ids),
            )
            if int(existing or 0) != len(body.finding_ids):
                raise HTTPException(
                    status_code=400, detail="one or more finding_ids not found"
                )

            metadata = dict(body.metadata)

            existing_row = None
            if body.anchor_asset_id is not None:
                existing_row = await con.fetchrow(
                    """
                    SELECT id FROM finding_chains
                     WHERE chain_rule_id = $1
                       AND anchor_asset_id = $2
                     LIMIT 1
                    """,
                    body.chain_rule_id,
                    body.anchor_asset_id,
                )
            else:
                fingerprint = metadata.get("fingerprint")
                if fingerprint is None:
                    # Provide a stable fallback fingerprint from the sorted
                    # finding_ids so repeat posts still upsert cleanly.
                    fingerprint = ",".join(sorted(str(f) for f in body.finding_ids))
                    metadata["fingerprint"] = fingerprint
                existing_row = await con.fetchrow(
                    """
                    SELECT id FROM finding_chains
                     WHERE chain_rule_id = $1
                       AND anchor_asset_id IS NULL
                       AND (metadata->>'fingerprint') = $2
                     LIMIT 1
                    """,
                    body.chain_rule_id,
                    fingerprint,
                )

            is_insert: bool
            if existing_row is None:
                row = await con.fetchrow(
                    """
                    INSERT INTO finding_chains (
                        chain_rule_id, severity, title, description,
                        impact_narrative, blast_radius_score, finding_ids,
                        anchor_asset_id, metadata
                    ) VALUES ($1,$2,$3,$4,$5,$6,$7::uuid[],$8,$9::jsonb)
                    RETURNING id, chain_rule_id, severity, title, description,
                              impact_narrative, blast_radius_score, created_at,
                              finding_ids, anchor_asset_id, metadata
                    """,
                    body.chain_rule_id,
                    body.severity,
                    body.title,
                    body.description,
                    body.impact_narrative,
                    body.blast_radius_score,
                    list(body.finding_ids),
                    body.anchor_asset_id,
                    json.dumps(metadata),
                )
                is_insert = True
            else:
                row = await con.fetchrow(
                    """
                    UPDATE finding_chains SET
                        severity = $2,
                        title = $3,
                        description = $4,
                        impact_narrative = COALESCE($5, impact_narrative),
                        blast_radius_score = COALESCE($6, blast_radius_score),
                        finding_ids = $7::uuid[],
                        metadata = metadata || $8::jsonb
                     WHERE id = $1
                 RETURNING id, chain_rule_id, severity, title, description,
                           impact_narrative, blast_radius_score, created_at,
                           finding_ids, anchor_asset_id, metadata
                    """,
                    existing_row["id"],
                    body.severity,
                    body.title,
                    body.description,
                    body.impact_narrative,
                    body.blast_radius_score,
                    list(body.finding_ids),
                    json.dumps(metadata),
                )
                is_insert = False

    chain = _coerce_chain_row(row)
    if is_insert:
        try:
            await publish_event(
                r,
                {
                    "event": "chain_detected",
                    "chain_id": str(chain.id),
                    "chain_rule_id": chain.chain_rule_id,
                    "severity": chain.severity,
                    "anchor_asset_id": (
                        str(chain.anchor_asset_id) if chain.anchor_asset_id else None
                    ),
                    "finding_count": len(chain.finding_ids),
                },
            )
        except Exception:
            logger.exception("publish_event_failed")
    return chain


# --------------------------------------------------------------------------- #
# Outbound audit bulk (active worker sink)
# --------------------------------------------------------------------------- #

@outbound_router.post("/bulk", response_model=OutboundBulkOut)
async def bulk_outbound(
    body: OutboundBulkIn,
    pool=Depends(get_pool),
):
    """Bulk-insert audit rows into outbound_log.

    `started_at` may be a float epoch (what workers emit by default) or a
    datetime; either is converted to a timestamptz.
    """
    def _ts(v: Any) -> datetime:
        if isinstance(v, datetime):
            if v.tzinfo is None:
                return v.replace(tzinfo=timezone.utc)
            return v
        # float epoch seconds
        return datetime.fromtimestamp(float(v), tz=timezone.utc)

    rows_payload: list[tuple[Any, ...]] = []
    for e in body.entries:
        rows_payload.append(
            (
                e.worker,
                e.target,
                e.tool,
                e.method,
                e.request_summary,
                e.response_code,
                e.scope_matched,
                e.scope_entry_id,
                _ts(e.started_at),
                e.duration_ms,
                e.bytes_in,
                e.bytes_out,
                e.error,
            )
        )

    sql = """
        INSERT INTO outbound_log (
            worker, target, tool, method, request_summary, response_code,
            scope_matched, scope_entry_id, started_at, duration_ms,
            bytes_in, bytes_out, error
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
    """
    async with pool.acquire() as con:
        async with con.transaction():
            await con.executemany(sql, rows_payload)
    return OutboundBulkOut(inserted=len(rows_payload))


# --------------------------------------------------------------------------- #
# Row helpers
# --------------------------------------------------------------------------- #

def _coerce_finding_row(row) -> dict[str, Any]:
    d = dict(row)
    for col in ("evidence", "metadata"):
        if isinstance(d.get(col), str):
            d[col] = json.loads(d[col])
    for col in ("cvss", "epss"):
        if d.get(col) is not None:
            d[col] = float(d[col])
    if d.get("references") is None:
        d["references"] = []
    return d


def _coerce_chain_row(row) -> ChainOut:
    d = dict(row)
    if isinstance(d.get("metadata"), str):
        d["metadata"] = json.loads(d["metadata"])
    if d.get("blast_radius_score") is not None:
        d["blast_radius_score"] = float(d["blast_radius_score"])
    return ChainOut.model_validate(d)
