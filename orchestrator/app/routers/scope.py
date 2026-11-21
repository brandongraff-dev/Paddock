"""Scope allowlist CRUD, scope-check, and the decisions audit lookup.

This router is deliberately narrow: list, add, deactivate, the fast
check, the decisions lookup for an entry, and proof-of-control
(``/{id}/challenge``, ``/{id}/verify``, ``/{id}/proof``; see
``app/scope_proof.py`` and schema 021). There is no bulk-mutation
endpoint (every scope change is meant to be reviewable one row at a time
against an auth_doc_ref).
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from .. import scope as scope_svc
from .. import scope_proof as proof_svc
from ..auth import current_principal
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


async def _with_proofs(con, entries: list[ScopeEntryOut]) -> list[proof_svc.ScopeEntryWithProofOut]:
    proofs = await proof_svc.fetch_proof_rows(con, [e.id for e in entries])
    return [
        proof_svc.ScopeEntryWithProofOut(
            **e.model_dump(),
            proof=proof_svc.proof_out(e.kind, e.active, proofs.get(e.id)),
        )
        for e in entries
    ]


@router.get("", response_model=list[proof_svc.ScopeEntryWithProofOut])
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
        return await _with_proofs(con, [_row_to_scope(r) for r in rows])


async def _load_entry(pool, entry_id: int) -> ScopeEntryOut:
    async with pool.acquire() as con:
        row = await con.fetchrow(
            f"SELECT {_SCOPE_COLS} FROM scope_entries WHERE id = $1", entry_id
        )
    if row is None:
        raise HTTPException(status_code=404, detail="scope entry not found")
    return _row_to_scope(row)


@router.get("/{entry_id}/proof", response_model=proof_svc.ScopeEntryWithProofOut)
async def get_scope_proof(entry_id: int, pool=Depends(get_pool)):
    """One scope entry with its proof-of-control status."""
    entry = await _load_entry(pool, entry_id)
    async with pool.acquire() as con:
        return (await _with_proofs(con, [entry]))[0]


@router.post(
    "/{entry_id}/challenge",
    response_model=proof_svc.ChallengeOut,
    dependencies=[Depends(require_scope_admin)],
)
async def issue_challenge(entry_id: int, pool=Depends(get_pool)):
    """Issue (or return the existing) ownership challenge for a domain entry.

    Publish EITHER the DNS TXT record or (exact domains only) the HTTPS file,
    then call ``POST /v1/scope/{id}/verify``. IP ranges and ASNs cannot be
    checked automatically; record an attestation via ``/verify`` instead.
    """
    entry = await _load_entry(pool, entry_id)
    if not proof_svc.is_automatic(entry.kind):
        raise HTTPException(
            status_code=422,
            detail=f"{entry.kind} entries are proven by attestation: POST "
            f"/v1/scope/{entry_id}/verify with method=attestation, loa_ref and approver",
        )
    token, row = await proof_svc.ensure_challenge(pool, entry.model_dump())
    base = proof_svc.base_domain(entry.value)
    http_file = None
    if "http_file" in proof_svc.methods_for(entry.kind):
        http_file = {"url": proof_svc.challenge_url(base, token), "body": token}
    return proof_svc.ChallengeOut(
        scope_entry_id=entry.id,
        kind=entry.kind,
        domain=base,
        token=token,
        methods=list(proof_svc.methods_for(entry.kind)),
        dns_txt={"name": proof_svc.challenge_name(base), "type": "TXT", "value": token},
        http_file=http_file,
        proof=proof_svc.proof_out(entry.kind, entry.active, row),
    )


@router.post(
    "/{entry_id}/verify",
    response_model=proof_svc.VerifyOut,
    dependencies=[Depends(require_scope_admin)],
)
async def verify_scope(
    entry_id: int,
    request: Request,
    body: proof_svc.VerifyIn | None = None,
    pool=Depends(get_pool),
    r=Depends(get_redis),
):
    """Check ownership now (domains) or record an attestation (IP ranges/ASN)."""
    body = body or proof_svc.VerifyIn()
    entry = await _load_entry(pool, entry_id)
    actor = current_principal(request).actor
    allowed = proof_svc.methods_for(entry.kind)

    if body.method == "attestation" or not proof_svc.is_automatic(entry.kind):
        if "attestation" not in allowed:
            raise HTTPException(
                status_code=422,
                detail=f"{entry.kind} entries must be proven by DNS TXT or HTTPS file, "
                "not attestation",
            )
        loa_ref = (body.loa_ref or "").strip()
        approver = (body.approver or "").strip()
        if not loa_ref or not approver:
            raise HTTPException(
                status_code=422,
                detail="attestation requires loa_ref (the authorization document) and approver",
            )
        row, old = await proof_svc.attest_entry(
            pool, entry.model_dump(), loa_ref=loa_ref, approver=approver, actor=actor,
            valid_until=body.valid_until,
        )
        check = proof_svc.CheckOut(
            ok=True, method="attestation", detail=f"attested by {actor}, approver {approver}"
        )
        new = "attested"
    else:
        try:
            res, row, old, new = await proof_svc.verify_entry(
                pool, entry.model_dump(), body.method, actor
            )
        except LookupError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        except proof_svc.TooSoon as exc:
            raise HTTPException(
                status_code=429,
                detail=f"checked moments ago; retry in {exc.retry_after:.0f}s",
                headers={"Retry-After": str(max(1, int(exc.retry_after + 0.999)))},
            )
        check = proof_svc.CheckOut(ok=res.ok, method=res.method, detail=res.detail)

    if new != old:
        try:
            await publish_event(r, {
                "event": "scope_proof_changed", "scope_entry_id": entry.id,
                "value": entry.value, "from": old, "to": new,
            })
        except Exception:
            logger.exception("publish_event_failed")
    return proof_svc.VerifyOut(
        scope_entry_id=entry.id,
        check=check,
        proof=proof_svc.proof_out(entry.kind, entry.active, row),
    )


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
        ON CONFLICT (kind, value)
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
