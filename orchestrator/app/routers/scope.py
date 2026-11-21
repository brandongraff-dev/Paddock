"""Scope allowlist CRUD, scope-check, and the decisions audit lookup.

This router is deliberately narrow: list, add, deactivate, the fast
check, and the decisions lookup for an entry. There is no bulk-mutation
endpoint (every scope change is meant to be reviewable one row at a time
against an auth_doc_ref).
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from .. import scope as scope_svc
from ..db import get_pool
from ..middleware import require_scope_admin
from ..models import (
    ScopeCheckIn,
    ScopeCheckOut,
    ScopeDecisionOut,
    ScopeEntryIn,
    ScopeEntryOut,
)
from ..queue import get_redis, publish_event

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/scope", tags=["scope"])


_SCOPE_COLS = (
    "id, kind, value, added_by, added_at, expires_at, "
    "auth_doc_ref, active, notes, metadata"
)


def _row_to_scope(row) -> ScopeEntryOut:
    d = dict(row)
    md = d.get("metadata")
    if isinstance(md, str):
        d["metadata"] = json.loads(md)
    elif md is None:
        d["metadata"] = {}
    return ScopeEntryOut.model_validate(d)


@router.get("", response_model=list[ScopeEntryOut])
async def list_scope(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    active_only: bool = Query(True),
    pool=Depends(get_pool),
):
    sql = f"""
        SELECT {_SCOPE_COLS}
          FROM scope_entries
         WHERE ($1::bool IS FALSE) OR active = TRUE
         ORDER BY added_at DESC
         LIMIT $2 OFFSET $3
    """
    async with pool.acquire() as con:
        rows = await con.fetch(sql, active_only, limit, offset)
    return [_row_to_scope(r) for r in rows]


@router.post(
    "",
    response_model=ScopeEntryOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scope_admin)],
)
async def add_scope(
    body: ScopeEntryIn,
    pool=Depends(get_pool),
    r=Depends(get_redis),
):
    canonical_value = _validate_entry_value(body.kind, body.value)

    sql = f"""
        INSERT INTO scope_entries
            (kind, value, added_by, auth_doc_ref, expires_at, notes, metadata)
        VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
        ON CONFLICT (tenant_id, kind, value)
            DO UPDATE SET active = TRUE,
                          added_by = EXCLUDED.added_by,
                          auth_doc_ref = EXCLUDED.auth_doc_ref,
                          expires_at = EXCLUDED.expires_at,
                          notes = EXCLUDED.notes,
                          metadata = scope_entries.metadata || EXCLUDED.metadata
        RETURNING {_SCOPE_COLS}, (xmax = 0) AS was_inserted
    """
    async with pool.acquire() as con:
        row = await con.fetchrow(
            sql,
            body.kind,
            canonical_value,
            body.added_by,
            body.auth_doc_ref,
            body.expires_at,
            body.notes,
            json.dumps(body.metadata or {}),
        )
    scope_svc.scope_cache.invalidate()

    entry = _row_to_scope({k: v for k, v in dict(row).items() if k != "was_inserted"})
    try:
        await publish_event(
            r,
            {
                "event": "scope_added",
                "scope_entry_id": entry.id,
                "kind": entry.kind,
                "value": entry.value,
                "added_by": entry.added_by,
            },
        )
    except Exception:
        logger.exception("publish_event_failed")
    return entry


@router.delete(
    "/{entry_id}",
    response_model=ScopeEntryOut,
    dependencies=[Depends(require_scope_admin)],
)
async def deactivate_scope(
    entry_id: int,
    pool=Depends(get_pool),
    r=Depends(get_redis),
):
    sql = f"""
        UPDATE scope_entries SET active = FALSE
         WHERE id = $1
     RETURNING {_SCOPE_COLS}
    """
    async with pool.acquire() as con:
        row = await con.fetchrow(sql, entry_id)
    if row is None:
        raise HTTPException(status_code=404, detail="scope entry not found")
    scope_svc.scope_cache.invalidate()
    entry = _row_to_scope(row)
    try:
        await publish_event(
            r,
            {
                "event": "scope_removed",
                "scope_entry_id": entry.id,
                "kind": entry.kind,
                "value": entry.value,
            },
        )
    except Exception:
        logger.exception("publish_event_failed")
    return entry


@router.post("/check", response_model=ScopeCheckOut)
async def check_scope(body: ScopeCheckIn, pool=Depends(get_pool)):
    decision = await scope_svc.check(
        pool, target=body.target, worker=body.worker, reason=body.reason
    )
    # Pull matched entry metadata if a match happened. This is a tiny
    # second round-trip on the hot path; the scope cache has already
    # resolved the id so this is bounded.
    matched_metadata: dict[str, Any] = {}
    if decision.matched_entry_id is not None:
        async with pool.acquire() as con:
            row = await con.fetchrow(
                "SELECT metadata FROM scope_entries WHERE id = $1",
                decision.matched_entry_id,
            )
        if row is not None:
            md = row["metadata"]
            if isinstance(md, str):
                md = json.loads(md)
            matched_metadata = md or {}
    return ScopeCheckOut(
        allow=decision.allow,
        normalized=decision.normalized,
        reason=decision.reason,
        matched_entry=decision.matched_entry_id,
        matched_entry_metadata=matched_metadata,
    )


@router.get("/{entry_id}/decisions", response_model=list[ScopeDecisionOut])
async def list_scope_decisions(
    entry_id: int,
    limit: int = Query(10, ge=1, le=500),
    offset: int = Query(0, ge=0),
    pool=Depends(get_pool),
):
    """Return the most recent `scope_decisions` rows for a scope entry."""
    async with pool.acquire() as con:
        rows = await con.fetch(
            """
            SELECT id, target, normalized, decision, matched_entry,
                   worker, reason, decided_at
              FROM scope_decisions
             WHERE matched_entry = $1
             ORDER BY decided_at DESC
             LIMIT $2 OFFSET $3
            """,
            entry_id,
            limit,
            offset,
        )
    return [ScopeDecisionOut.model_validate(dict(r)) for r in rows]


# Multi-label public suffixes a wildcard must never be rooted at. Single-label
# TLDs ("com", "io") are refused structurally; this covers the common
# two-label registry suffixes without pulling in the full PSL.
_PUBLIC_SUFFIXES_2 = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz", "net.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "co.kr", "or.kr", "com.br", "com.cn",
    "net.cn", "org.cn", "gov.cn", "com.mx", "com.ar", "com.tr", "com.tw", "com.hk",
    "com.sg", "com.my", "co.in", "net.in", "org.in", "co.za", "org.za", "co.il",
    "com.pl", "com.ua", "com.ru", "co.id", "or.id", "com.vn", "com.ph", "com.pk",
    "github.io", "herokuapp.com", "azurewebsites.net", "cloudfront.net",
    "amazonaws.com", "appspot.com", "vercel.app", "netlify.app", "pages.dev",
    "workers.dev", "web.app", "firebaseapp.com", "blogspot.com", "s3.amazonaws.com",
})

# Broadest CIDR an operator can authorise in one entry.
_MIN_PREFIX = {4: 16, 6: 32}


def _validate_entry_value(kind: str, value: str) -> str:
    """Validate a scope entry and return its CANONICAL stored form.

    Refuses entries that would authorise far more than any one organisation
    owns (a wildcard on a public suffix, 0.0.0.0/0), entries that are never a
    legitimate target (cloud metadata), and anything the matcher would read
    differently from the operator (control characters, IDN spoofing).
    """
    import ipaddress

    v = value.strip()
    if kind in {"domain", "subdomain_wildcard"}:
        raw = v[2:] if kind == "subdomain_wildcard" and v.startswith("*.") else v
        canon = scope_svc.normalize(raw)
        if not canon or scope_svc._is_ip(canon) is not None or "/" in raw or "@" in raw:
            raise HTTPException(status_code=422, detail=f"invalid {kind} value: {value!r}")
        if kind == "subdomain_wildcard":
            labels = canon.split(".")
            if len(labels) < 2 or canon in _PUBLIC_SUFFIXES_2:
                raise HTTPException(
                    status_code=422,
                    detail=f"refusing wildcard on public suffix {canon!r}: "
                    "authorise the registrable domain you own instead",
                )
        return canon
    if kind in {"ipv4_cidr", "ipv6_cidr"}:
        want = 4 if kind == "ipv4_cidr" else 6
        try:
            net = ipaddress.ip_network(v, strict=False)
            if net.version != want:
                raise ValueError
        except ValueError:
            raise HTTPException(status_code=422, detail=f"invalid {kind} value")
        if net.prefixlen < _MIN_PREFIX[want]:
            raise HTTPException(
                status_code=422,
                detail=f"{kind} broader than /{_MIN_PREFIX[want]} refused; split it "
                "into the ranges you are actually authorised for",
            )
        if any(
            net.version == bad.version and net.overlaps(bad)
            for bad in scope_svc.HARD_DENY_NETS
        ):
            raise HTTPException(
                status_code=422,
                detail=f"{kind} overlaps a protected range (cloud metadata / multicast / "
                "reserved) that is never a scan target",
            )
        return str(net)
    if kind == "asn":
        m = re.fullmatch(r"(?:AS)?([0-9]{1,10})", v, flags=re.IGNORECASE | re.ASCII)
        if not m or int(m.group(1)) > 4294967295:
            raise HTTPException(status_code=422, detail="invalid asn value")
        return f"AS{int(m.group(1))}"
    raise HTTPException(status_code=422, detail=f"unknown scope kind {kind!r}")
