"""Persistence for Wargame assessments (schema/041_wargame.sql, plus
043_wargame_verdicts.sql: the ``proved_config`` verdict and certificate
``key_id``).

Two layers:

* :func:`assemble_bundle` is a **pure** assembler. It turns engine objects
  (reachability result, scorecard, agreement reports, certificates, fix set,
  evidence packs) into plain dicts/lists matching the 041 columns. No I/O,
  deterministic: the same inputs always give an equal bundle.
* :func:`persist` is the async writer. It inserts the assessment row, then
  bulk-inserts the child rows with that ``assessment_id``, all inside one
  transaction (``db.acquire()`` + ``conn.transaction()``), mirroring the
  parameterized-asyncpg style of ``engine/attackpath.py``. JSONB columns are
  passed as Python objects with a ``$n::jsonb`` cast: ``Database`` registers a
  ``json.dumps`` codec on every pooled connection, so no manual dumps.

DEFENSIVE: stores engine results only. Nothing here executes or emits anything.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Iterable, Mapping, Optional

from ...db import Database
from .model import FixCandidate, FixSet, PortRange, Proto


# ---------------------------------------------------------------------------
# Bundle
# ---------------------------------------------------------------------------

@dataclass
class AssessmentBundle:
    """Every row to persist for one assessment, as plain dicts."""

    assessment: dict[str, Any]
    routes: list[dict[str, Any]] = field(default_factory=list)
    boundaries: list[dict[str, Any]] = field(default_factory=list)
    certificates: list[dict[str, Any]] = field(default_factory=list)
    fix_set: Optional[dict[str, Any]] = None
    evidence: list[dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Pure assembler
# ---------------------------------------------------------------------------

def format_port(port: Optional[PortRange]) -> str:
    """Stable string for a port class.

    ``None`` or a protocol-agnostic full range -> ``"any"``; a single port ->
    ``"tcp/5432"``; a range -> ``"tcp/1000-2000"``; a full range on a real
    protocol -> ``"tcp/any"``.
    """
    if port is None:
        return "any"
    full = port.low == 0 and port.high == 65535
    if port.proto is Proto.ANY and full:
        return "any"
    if full:
        span = "any"
    elif port.low == port.high:
        span = str(port.low)
    else:
        span = f"{port.low}-{port.high}"
    return f"{port.proto.value}/{span}"


def _hop_dict(h: Any) -> dict[str, Any]:
    return {
        "src": h.src,
        "dst": h.dst,
        "labels": sorted(lb.value for lb in h.labels),
        "port": format_port(h.port),
        "rule_ref": h.rule_ref,
        "fix_candidate_ids": sorted(h.fix_candidate_ids),
    }


def _route_dict(r: Any) -> dict[str, Any]:
    hops = [_hop_dict(h) for h in r.hops]
    return {
        "entry": r.entry,
        "jewel": r.jewel,
        "length": r.length,
        "weakest_label": r.weakest_label.value,
        "hops": hops,
        # Deterministic identity of the route (hop sequence + ports).
        "fingerprint": _route_fingerprint(r.entry, r.jewel, hops),
    }


def _route_fingerprint(entry: str, jewel: str, hops: list[dict[str, Any]]) -> str:
    # rule_ref and fix ids are part of the identity: parallel-edge route
    # variants share src/dst/port but are distinct routes to cut.
    seq = "|".join(
        f"{h['src']}>{h['dst']}:{h['port']}:{h.get('rule_ref', '')}:"
        f"{','.join(sorted(h.get('fix_candidate_ids') or ()))}"
        for h in hops
    )
    return hashlib.sha256(f"{entry}|{jewel}|{seq}".encode("utf-8")).hexdigest()


def _route_sort_key(d: dict[str, Any]) -> tuple[Any, ...]:
    return (d["entry"], d["jewel"], d["length"], d["fingerprint"])


#: Every boundary verdict the 043 CHECK accepts (mirrors
#: ``agreement.VERDICTS``; a test keeps them in sync). ``pass`` = config and a
#: real active probe agree; ``proved_config`` = config-proved closed, not yet
#: tested by a probe.
BOUNDARY_VERDICTS: tuple[str, ...] = (
    "pass", "proved_config", "conditional", "insufficient", "fail_open",
)


def _boundary_dict(r: Any) -> dict[str, Any]:
    verdict = str(r.verdict)
    if verdict not in BOUNDARY_VERDICTS:
        # Fail at assembly, not as a CHECK violation mid-transaction.
        raise ValueError(f"unknown boundary verdict {verdict!r}")
    return {
        "boundary_src": r.boundary_src,
        "boundary_dst": r.boundary_dst,
        "port": format_port(getattr(r, "port", None)),
        "verdict": verdict,
        "disagreements": sorted(str(d) for d in (r.disagreements or [])),
        "note": str(getattr(r, "note", "") or ""),
    }


def _cert_dict(c: Any) -> dict[str, Any]:
    return {
        "boundary_src": c.boundary_src,
        "boundary_dst": c.boundary_dst,
        "port": format_port(c.port),
        "claim": c.claim,
        "assumptions": [{"key": a.key, "text": a.text} for a in c.assumptions],
        "config_hashes": sorted(c.config_hashes),
        "status": c.status,
        "issued_at": c.issued_at or None,
        "expires_at": c.expires_at or None,
        "fingerprint": c.fingerprint,
        # Which key made the fingerprint ("unsigned-dev" = public dev key).
        "key_id": str(getattr(c, "key_id", "") or ""),
        # Signed fields too: without them a stored certificate could not be
        # re-verified, and an auditor could not see whether a probe backed it.
        "corroboration": _corroboration_dict(getattr(c, "corroboration", None)),
    }


def _corroboration_dict(co: Any) -> dict[str, Any]:
    if co is None:
        return {}
    return {
        "observed_flows": int(co.observed_flows),
        "window_days": int(co.window_days),
        "sensor_on_protected_side": bool(co.sensor_on_protected_side),
        "probe_tested": bool(co.probe_tested),
    }


def _fix_dict(
    fix_set: FixSet, fix_candidates: Optional[Mapping[str, FixCandidate]]
) -> dict[str, Any]:
    cands = fix_candidates or {}
    selected: list[dict[str, Any]] = []
    for cid in fix_set.selected:
        c = cands.get(cid)
        if c is None:
            # Unknown candidate: keep the id so the selection is never lost.
            selected.append(
                {"id": cid, "kind": "", "cost_class": "", "description": "", "cost": 0.0}
            )
        else:
            selected.append(
                {
                    "id": c.id,
                    "kind": c.kind,
                    "cost_class": c.cost_class,
                    "description": c.description,
                    "cost": float(c.cost),
                }
            )
    return {
        "total_cost": float(fix_set.total_cost),
        "optimality": fix_set.optimality,
        "cuts_all": bool(fix_set.cuts_all),
        "selected": selected,
    }


def _evidence_rows(packs: Iterable[Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for pack in packs:
        for ordinal, item in enumerate(pack.items):
            rows.append(
                {
                    "framework": pack.framework,
                    "control_id": item.control_id,
                    "status": item.status.value,
                    "statement": item.statement,
                    "evidence": item.evidence,
                    "item_hash": item.item_hash,
                    "ordinal": ordinal,
                }
            )
    return rows


def assemble_bundle(
    *,
    reachability: Any,
    scorecard: Any,
    agreement_reports: Iterable[Any] = (),
    certificates: Iterable[Any] = (),
    fix_set: Optional[FixSet] = None,
    fix_candidates: Optional[Mapping[str, FixCandidate]] = None,
    evidence_packs: Iterable[Any] = (),
    label: str = "",
    false_closed_rate: Optional[float] = None,
    metadata: Optional[Mapping[str, Any]] = None,
) -> AssessmentBundle:
    """Serialise engine outputs into the rows :func:`persist` writes.

    Pure and deterministic. ``coverage_pct`` comes from the scorecard
    (``None`` = not measured); ``false_closed_rate`` is optional (``None`` =
    eval not run).
    """
    closure = scorecard.closure
    coverage = scorecard.coverage
    assessment = {
        "label": label,
        "crownjewel_total": closure.total_pairs,
        "crownjewel_open": closure.open_pairs,
        "crownjewel_closed": closure.closed_pairs,
        "crownjewel_conditional": closure.conditional_pairs,
        "closure_pct": closure.closure_pct,
        "coverage_pct": coverage.coverage_pct,
        "false_closed_rate": false_closed_rate,
        "board_line": scorecard.board_line,
        "blind_spots": sorted(coverage.blind_spots),
        "metadata": dict(metadata or {}),
    }

    routes = sorted((_route_dict(r) for r in reachability.routes), key=_route_sort_key)
    boundaries = sorted(
        (_boundary_dict(r) for r in agreement_reports),
        key=lambda d: (d["boundary_src"], d["boundary_dst"], d["port"]),
    )
    certs = sorted(
        (_cert_dict(c) for c in certificates),
        key=lambda d: (d["boundary_src"], d["boundary_dst"], d["port"], d["fingerprint"]),
    )
    return AssessmentBundle(
        assessment=assessment,
        routes=routes,
        boundaries=boundaries,
        certificates=certs,
        fix_set=_fix_dict(fix_set, fix_candidates) if fix_set is not None else None,
        evidence=_evidence_rows(evidence_packs),
    )


# ---------------------------------------------------------------------------
# Async writer / readers
# ---------------------------------------------------------------------------

def _dec(x: Optional[float], places: int) -> Optional[Decimal]:
    if x is None:
        return None
    return Decimal(str(round(float(x), places)))


def _ts(s: Optional[str]) -> Optional[datetime]:
    """ISO-8601 string -> aware datetime (naive input is taken as UTC)."""
    if not s:
        return None
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


async def persist(db: Database, bundle: AssessmentBundle) -> str:
    """Write the whole bundle in one transaction; return the assessment id."""
    a = bundle.assessment
    async with db.acquire() as conn:
        async with conn.transaction():
            aid = await conn.fetchval(
                """
                INSERT INTO wargame_assessments (
                  label, crownjewel_total, crownjewel_open, crownjewel_closed,
                  crownjewel_conditional, closure_pct, coverage_pct,
                  false_closed_rate, board_line, blind_spots, metadata
                ) VALUES (
                  $1, $2, $3, $4, $5, $6::numeric, $7::numeric, $8::numeric,
                  $9, $10::jsonb, $11::jsonb
                )
                RETURNING id::text
                """,
                a["label"],
                a["crownjewel_total"],
                a["crownjewel_open"],
                a["crownjewel_closed"],
                a["crownjewel_conditional"],
                _dec(a["closure_pct"], 2),
                _dec(a["coverage_pct"], 2),
                _dec(a["false_closed_rate"], 4),
                a["board_line"],
                a["blind_spots"],
                a["metadata"],
            )

            if bundle.routes:
                await conn.executemany(
                    """
                    INSERT INTO wargame_routes
                      (assessment_id, entry, jewel, length, weakest_label,
                       hops, fingerprint)
                    VALUES ($1::uuid, $2, $3, $4, $5, $6::jsonb, $7)
                    """,
                    [
                        (aid, r["entry"], r["jewel"], r["length"],
                         r["weakest_label"], r["hops"], r["fingerprint"])
                        for r in bundle.routes
                    ],
                )

            if bundle.boundaries:
                await conn.executemany(
                    """
                    INSERT INTO wargame_boundaries
                      (assessment_id, boundary_src, boundary_dst, port,
                       verdict, disagreements, note)
                    VALUES ($1::uuid, $2, $3, $4, $5, $6::jsonb, $7)
                    """,
                    [
                        (aid, b["boundary_src"], b["boundary_dst"], b["port"],
                         b["verdict"], b["disagreements"], b["note"])
                        for b in bundle.boundaries
                    ],
                )

            if bundle.certificates:
                await conn.executemany(
                    """
                    INSERT INTO wargame_certificates
                      (assessment_id, boundary_src, boundary_dst, port, claim,
                       assumptions, config_hashes, status, issued_at,
                       expires_at, fingerprint, key_id, corroboration)
                    VALUES ($1::uuid, $2, $3, $4, $5, $6::jsonb, $7::jsonb,
                            $8, $9::timestamptz, $10::timestamptz, $11, $12,
                            $13::jsonb)
                    """,
                    [
                        (aid, c["boundary_src"], c["boundary_dst"], c["port"],
                         c["claim"], c["assumptions"], c["config_hashes"],
                         c["status"], _ts(c["issued_at"]), _ts(c["expires_at"]),
                         c["fingerprint"], c.get("key_id", ""),
                         c.get("corroboration", {}))
                        for c in bundle.certificates
                    ],
                )

            if bundle.fix_set is not None:
                f = bundle.fix_set
                await conn.execute(
                    """
                    INSERT INTO wargame_fix_sets
                      (assessment_id, total_cost, optimality, cuts_all, selected)
                    VALUES ($1::uuid, $2::numeric, $3, $4, $5::jsonb)
                    """,
                    aid,
                    _dec(f["total_cost"], 2),
                    f["optimality"],
                    f["cuts_all"],
                    f["selected"],
                )

            if bundle.evidence:
                await conn.executemany(
                    """
                    INSERT INTO wargame_evidence
                      (assessment_id, framework, control_id, status, statement,
                       evidence, item_hash, ordinal)
                    VALUES ($1::uuid, $2, $3, $4, $5, $6::jsonb, $7, $8)
                    """,
                    [
                        (aid, e["framework"], e["control_id"], e["status"],
                         e["statement"], e["evidence"], e["item_hash"],
                         e["ordinal"])
                        for e in bundle.evidence
                    ],
                )
    return aid


_ASSESS_COLS = (
    "id::text AS id, label, crownjewel_total, crownjewel_open, "
    "crownjewel_closed, crownjewel_conditional, closure_pct::float8 AS closure_pct, "
    "coverage_pct::float8 AS coverage_pct, "
    "false_closed_rate::float8 AS false_closed_rate, board_line, blind_spots, "
    "computed_at, metadata"
)


async def _children(db: Database, aid: str) -> dict[str, Any]:
    routes = await db.fetch(
        "SELECT entry, jewel, length, weakest_label, hops, fingerprint "
        "FROM wargame_routes WHERE assessment_id = $1::uuid "
        "ORDER BY entry, jewel, fingerprint",
        aid,
    )
    bounds = await db.fetch(
        "SELECT boundary_src, boundary_dst, port, verdict, disagreements, note "
        "FROM wargame_boundaries WHERE assessment_id = $1::uuid "
        "ORDER BY boundary_src, boundary_dst, port",
        aid,
    )
    certs = await db.fetch(
        "SELECT boundary_src, boundary_dst, port, claim, assumptions, "
        "config_hashes, status, issued_at, expires_at, fingerprint, key_id, "
        "corroboration "
        "FROM wargame_certificates WHERE assessment_id = $1::uuid "
        "ORDER BY boundary_src, boundary_dst, port, fingerprint",
        aid,
    )
    fix = await db.fetchrow(
        "SELECT total_cost::float8 AS total_cost, optimality, cuts_all, selected "
        "FROM wargame_fix_sets WHERE assessment_id = $1::uuid",
        aid,
    )
    evid = await db.fetch(
        "SELECT framework, control_id, status, statement, evidence, item_hash, "
        "ordinal FROM wargame_evidence WHERE assessment_id = $1::uuid "
        "ORDER BY framework, ordinal",
        aid,
    )
    return {
        "routes": [dict(r) for r in routes],
        "boundaries": [dict(r) for r in bounds],
        "certificates": [dict(r) for r in certs],
        "fix_set": dict(fix) if fix is not None else None,
        "evidence": [dict(r) for r in evid],
    }


async def load(db: Database, assessment_id: str) -> Optional[dict[str, Any]]:
    """One assessment with all its child rows, or ``None``."""
    row = await db.fetchrow(
        f"SELECT {_ASSESS_COLS} FROM wargame_assessments WHERE id = $1::uuid",
        assessment_id,
    )
    if row is None:
        return None
    out = dict(row)
    out.update(await _children(db, out["id"]))
    return out


async def latest(db: Database) -> Optional[dict[str, Any]]:
    """The most recently computed assessment (with children), or ``None``."""
    row = await db.fetchrow(
        f"SELECT {_ASSESS_COLS} FROM wargame_assessments "
        "ORDER BY computed_at DESC, id LIMIT 1"
    )
    if row is None:
        return None
    out = dict(row)
    out.update(await _children(db, out["id"]))
    return out
