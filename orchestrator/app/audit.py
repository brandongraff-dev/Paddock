"""Tamper-evident, keyed, anchored, per-tenant audit chain.

Chain
    Each tenant has its own linear chain. A row stores ``prev_hash`` (the
    previous row's ``entry_hash`` in the same tenant; genesis = 64 zeros) and
    ``entry_hash`` computed with the algorithm named in its ``hash_alg``:

    * ``sha256`` (legacy, unkeyed) --
      ``sha256(prev_hash || canonical(row))``. Anyone with DB write access can
      recompute it, so it is tamper-evident only against a non-owner.
    * ``hmac-sha256:<kid>`` --
      ``HMAC-SHA256(key, hash_alg \\n tenant_id \\n prev_hash \\n canonical(row))``
      with ``AUDIT_HMAC_KEY`` held OUTSIDE the database. A DB superuser can no
      longer forge a consistent chain. ``<kid>`` identifies the key, so
      rotating keys (``AUDIT_HMAC_PREVIOUS_KEYS``) keeps old rows verifiable.

    ``canonical(row)`` is a deterministic JSON serialisation of the content
    columns (everything except id / tenant_id / hashes). Existing unkeyed rows
    keep verifying. Once a chain contains a keyed row, a later unkeyed row is
    rejected (no silent downgrade).

Anchoring
    :func:`anchor_head` publishes the chain head ``(max_id, head_hash)`` -- signed
    with the HMAC key when one is configured -- to an append-only sink
    (``app.audit_anchor``). :func:`verify` checks the chain AND that the row at
    the latest anchor's ``max_id`` still exists with the anchored hash, which
    detects tail truncation and whole-chain rewrites.

Appends are serialised per tenant with a transaction-scoped advisory lock;
``verify`` streams rows in keyset-paginated batches.
"""
from __future__ import annotations

import asyncio
import functools
import hashlib
import hmac
import json
import logging
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import tenancy
from .audit_anchor import Anchor, AnchorSinkError, sink_from_settings
from .config import settings

logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64

ALG_SHA256 = "sha256"
ALG_HMAC_PREFIX = "hmac-sha256:"

# A fixed advisory-lock key ("ASMAUDIT"-ish) serialising audit appends for the
# default tenant; other tenants get a key derived from their id.
_AUDIT_LOCK_KEY = 0x4155_4449_5401

# The content columns, in a fixed order, that the hash commits to.
_CONTENT_COLS = (
    "ts",
    "actor",
    "actor_role",
    "action",
    "resource_type",
    "resource_id",
    "method",
    "path",
    "status",
    "classification",
    "justification",
    "ip",
    "request_id",
    "details",
)

_SELECT_COLS = (
    "id, ts, actor, actor_role, action, resource_type, resource_id, method, path, "
    "status, classification, justification, ip, request_id, details, prev_hash, "
    "entry_hash, hash_alg"
)


class AuditIntegrityError(RuntimeError):
    """The chain failed verification; refusing to anchor it."""


# --------------------------------------------------------------------------- #
# Canonicalisation (unchanged from the unkeyed chain -- old rows still verify)
# --------------------------------------------------------------------------- #

def _canon_ts(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    return str(value)


def _canon_details(value: Any) -> Any:
    if value is None:
        return {}
    if isinstance(value, (str, bytes)):
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return {}
    return value


def canonical_payload(row: dict[str, Any]) -> str:
    """Deterministic JSON for the row's content columns.

    Identical whether called at append time (from Python values) or at verify
    time (from the values read back out of Postgres), so the recomputed hash
    matches the stored one byte-for-byte.
    """
    payload: dict[str, Any] = {}
    for col in _CONTENT_COLS:
        v = row.get(col)
        if col == "ts":
            v = _canon_ts(v)
        elif col == "details":
            v = _canon_details(v)
        payload[col] = v
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


# --------------------------------------------------------------------------- #
# Keys
# --------------------------------------------------------------------------- #

def key_id(key: bytes) -> str:
    """Public identifier of an HMAC key (an HMAC of a constant, not the key)."""
    return hmac.new(key, b"paddock-audit-key-id/v1", hashlib.sha256).hexdigest()[:16]


@functools.lru_cache(maxsize=8)
def _keyring_cached(
    key: str | None, key_file: str | None, previous: str
) -> tuple[tuple[str, bytes] | None, dict[str, bytes]]:
    current: bytes | None = None
    if key_file:
        current = Path(key_file).read_text(encoding="utf-8").strip().encode("utf-8") or None
    elif key:
        current = key.encode("utf-8")
    ring: dict[str, bytes] = {}
    cur: tuple[str, bytes] | None = None
    if current:
        if len(current) < 32:
            logger.warning("AUDIT_HMAC_KEY is shorter than 32 bytes; use `openssl rand -hex 32`")
        cur = (key_id(current), current)
        ring[cur[0]] = current
    for old in previous.replace(",", " ").split():
        b = old.encode("utf-8")
        ring.setdefault(key_id(b), b)
    return cur, ring


def keyring() -> tuple[tuple[str, bytes] | None, dict[str, bytes]]:
    """(current ``(kid, key)`` or None, ``{kid: key}`` incl. previous keys)."""
    return _keyring_cached(
        settings.audit_hmac_key, settings.audit_hmac_key_file, settings.audit_hmac_previous_keys
    )


def current_hash_alg() -> str:
    cur, _ = keyring()
    return f"{ALG_HMAC_PREFIX}{cur[0]}" if cur else ALG_SHA256


def compute_entry_hash(
    prev_hash: str,
    row: dict[str, Any],
    *,
    hash_alg: str = ALG_SHA256,
    key: bytes | None = None,
    tenant_id: str | None = None,
) -> str:
    """Entry hash of ``row`` chained to ``prev_hash`` under ``hash_alg``."""
    if hash_alg == ALG_SHA256:
        material = prev_hash + canonical_payload(row)
        return hashlib.sha256(material.encode("utf-8")).hexdigest()
    if not hash_alg.startswith(ALG_HMAC_PREFIX) or key is None:
        raise ValueError(f"cannot compute {hash_alg!r} without its key")
    material = "\n".join((hash_alg, str(tenant_id or ""), prev_hash, canonical_payload(row)))
    return hmac.new(key, material.encode("utf-8"), hashlib.sha256).hexdigest()


def _lock_key(tenant_id: str) -> int:
    if tenant_id == tenancy.DEFAULT_TENANT_ID:
        return _AUDIT_LOCK_KEY
    digest = hashlib.sha256(b"paddock-audit/" + tenant_id.encode()).digest()
    return int.from_bytes(digest[:7], "big")


def _sanitize(value: Any) -> Any:
    """Make a value safe to store AND hash-stable across a JSONB round trip.

    * NUL bytes are stripped: Postgres rejects them, which used to make the
      INSERT fail and the action go unaudited.
    * Floats become strings: JSONB re-renders numbers (1e16 -> 10000000000000000),
      which made verify() report a permanently broken chain.
    """
    if isinstance(value, str):
        return value.replace("\x00", "")
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, dict):
        return {_sanitize(str(k)): _sanitize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize(v) for v in value]
    return value


# --------------------------------------------------------------------------- #
# Append
# --------------------------------------------------------------------------- #

async def record(
    pool,
    *,
    action: str,
    actor: str,
    actor_role: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    method: str | None = None,
    path: str | None = None,
    status: int | None = None,
    classification: str | None = None,
    justification: str | None = None,
    ip: str | None = None,
    request_id: str | None = None,
    details: dict[str, Any] | None = None,
    con=None,
    tenant_id: str | None = None,
) -> dict[str, Any]:
    """Append one row to the current tenant's chain and return it.

    ``con``: append on the caller's connection. Inside the caller's open
    transaction the audit row commits or rolls back WITH the caller's write
    (the per-tenant advisory lock is then held until that commit).
    """
    ts = datetime.now(timezone.utc)
    details = _sanitize(details or {})
    actor, actor_role, action, method, path, classification, justification, request_id = (
        _sanitize(v) for v in (
            actor, actor_role, action, method, path, classification, justification, request_id,
        )
    )
    if resource_id is not None:
        resource_id = _sanitize(str(resource_id))
    tenant = str(tenant_id or tenancy.current_tenant_id() or "")
    if not tenant:
        raise RuntimeError("audit.record: no tenant in context (TENANCY_STRICT)")
    cur, _ = keyring()
    hash_alg = f"{ALG_HMAC_PREFIX}{cur[0]}" if cur else ALG_SHA256
    row = {
        "ts": ts,
        "actor": actor,
        "actor_role": actor_role,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "method": method,
        "path": path,
        "status": status,
        "classification": classification,
        "justification": justification,
        "ip": ip,
        "request_id": request_id,
        "details": details,
    }

    async def _append(c) -> Any:
        async with c.transaction():
            # Serialise appends per tenant: held until the transaction commits.
            await c.execute("SELECT pg_advisory_xact_lock($1)", _lock_key(tenant))
            prev_hash = await c.fetchval(
                "SELECT entry_hash FROM audit_log WHERE tenant_id = $1 ORDER BY id DESC LIMIT 1",
                tenant,
            )
            prev_hash = prev_hash or GENESIS_HASH
            entry_hash = compute_entry_hash(
                prev_hash, row, hash_alg=hash_alg, key=cur[1] if cur else None, tenant_id=tenant
            )
            return await c.fetchrow(
                """
                INSERT INTO audit_log (
                    ts, actor, actor_role, action, resource_type, resource_id,
                    method, path, status, classification, justification, ip,
                    request_id, details, prev_hash, entry_hash, hash_alg, tenant_id
                ) VALUES (
                    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb,$15,$16,$17,$18
                )
                RETURNING id, ts, entry_hash, prev_hash
                """,
                ts,
                actor,
                actor_role,
                action,
                resource_type,
                resource_id,
                method,
                path,
                status,
                classification,
                justification,
                ip,
                request_id,
                json.dumps(details, default=str),
                prev_hash,
                entry_hash,
                hash_alg,
                tenant,
            )

    if con is not None:
        rec = await _append(con)
    else:
        with tenancy.tenant_context(tenant):
            async with pool.acquire() as c:
                rec = await _append(c)
    return {
        "id": rec["id"],
        "entry_hash": rec["entry_hash"],
        "prev_hash": rec["prev_hash"],
        "hash_alg": hash_alg,
    }


# --------------------------------------------------------------------------- #
# Verify (streamed)
# --------------------------------------------------------------------------- #

class _Walk:
    __slots__ = ("checked", "last_id", "prev", "keyed_seen", "broken_id", "reason", "seen")

    def __init__(self, last_id: int, prev: str, keyed_seen: bool) -> None:
        self.checked = 0
        self.last_id = last_id
        self.prev = prev
        self.keyed_seen = keyed_seen
        self.broken_id: int | None = None
        self.reason: str | None = None
        self.seen: dict[int, str] = {}


async def _walk(
    pool,
    tenant: str,
    *,
    after_id: int,
    prev_hash: str,
    upto_id: int,
    keyed_seen: bool,
    watch: set[int] | None = None,
    batch_size: int | None = None,
) -> _Walk:
    """Verify rows ``(after_id, upto_id]`` of ``tenant``'s chain, one batch at a time."""
    _, ring = keyring()
    w = _Walk(after_id, prev_hash, keyed_seen)
    batch = max(1, int(batch_size or settings.audit_verify_batch))
    watch = watch or set()
    while True:
        with tenancy.tenant_context(tenant):
            async with pool.acquire() as con:
                rows = await con.fetch(
                    f"SELECT {_SELECT_COLS} FROM audit_log "
                    "WHERE tenant_id = $1 AND id > $2 AND id <= $3 ORDER BY id LIMIT $4",
                    tenant,
                    w.last_id,
                    upto_id,
                    batch,
                )
        for r in rows:
            w.checked += 1
            rid = int(r["id"])
            alg = r["hash_alg"] or ALG_SHA256
            row = {col: r[col] for col in _CONTENT_COLS}
            reason = None
            expected = None
            if alg == ALG_SHA256:
                if w.keyed_seen:
                    reason = "downgrade"  # unkeyed row after a keyed one
                else:
                    expected = compute_entry_hash(w.prev, row)
            elif alg.startswith(ALG_HMAC_PREFIX):
                key = ring.get(alg[len(ALG_HMAC_PREFIX):])
                if key is None:
                    reason = "unknown_key"
                else:
                    w.keyed_seen = True
                    expected = compute_entry_hash(
                        w.prev, row, hash_alg=alg, key=key, tenant_id=tenant
                    )
            else:
                reason = "unknown_alg"
            if reason is None and r["prev_hash"] != w.prev:
                reason = "chain_link"
            if reason is None and r["entry_hash"] != expected:
                reason = "row_hash"
            if reason is not None:
                w.broken_id, w.reason = rid, reason
                return w
            if rid in watch:
                w.seen[rid] = r["entry_hash"]
            w.prev = r["entry_hash"]
            w.last_id = rid
        if len(rows) < batch:
            return w


async def _head(pool, tenant: str) -> tuple[int | None, str | None, str | None]:
    with tenancy.tenant_context(tenant):
        async with pool.acquire() as con:
            row = await con.fetchrow(
                "SELECT id, entry_hash, hash_alg FROM audit_log WHERE tenant_id = $1 "
                "ORDER BY id DESC LIMIT 1",
                tenant,
            )
    if row is None:
        return None, None, None
    return int(row["id"]), row["entry_hash"], row["hash_alg"]


async def _row_hash(pool, tenant: str, row_id: int) -> str | None:
    with tenancy.tenant_context(tenant):
        async with pool.acquire() as con:
            return await con.fetchval(
                "SELECT entry_hash FROM audit_log WHERE tenant_id = $1 AND id = $2", tenant, row_id
            )


# --------------------------------------------------------------------------- #
# Anchor signing
# --------------------------------------------------------------------------- #

_ANCHOR_CTX = b"paddock-anchor/v1\n"


def sign_anchor(anchor: Anchor) -> Anchor:
    """Sign with the current HMAC key (no-op without one)."""
    cur, _ = keyring()
    if cur is None:
        anchor.kid, anchor.sig = None, None
        return anchor
    anchor.kid = cur[0]
    anchor.sig = hmac.new(cur[1], _ANCHOR_CTX + anchor.signed_body(), hashlib.sha256).hexdigest()
    return anchor


def check_anchor(anchor: Anchor) -> str:
    """``ok`` | ``unsigned`` | ``unknown_key`` | ``bad_signature``."""
    if not anchor.sig:
        return "unsigned"
    _, ring = keyring()
    key = ring.get(anchor.kid or "")
    if key is None:
        return "unknown_key"
    want = hmac.new(key, _ANCHOR_CTX + anchor.signed_body(), hashlib.sha256).hexdigest()
    return "ok" if hmac.compare_digest(want, anchor.sig) else "bad_signature"


_UNSET: Any = object()


def _resolve_sink(sink: Any) -> Any:
    return sink_from_settings() if sink is _UNSET else sink


async def verify(
    pool,
    *,
    tenant_id: str | None = None,
    sink: Any = _UNSET,
    batch_size: int | None = None,
) -> dict[str, Any]:
    """Verify the current tenant's chain, then its head against the latest anchor.

    Returns ``{ok, checked, first_broken_id, reason, tenant_id, head_id,
    head_hash, anchor}``. ``anchor.status`` is one of ``not_configured``,
    ``none`` (no anchor published yet), ``ok``, ``truncated`` (the chain ends
    before the anchored id), ``mismatch`` (the anchored row is gone or its hash
    differs: rewritten history), ``bad_signature`` / ``unknown_key`` /
    ``unsigned`` (anchor authenticity), ``unavailable`` (sink unreachable) or
    ``skipped`` (the chain itself is already broken). Only ``not_configured``,
    ``none`` and ``ok`` leave ``ok`` true: verification fails closed.
    """
    tenant = str(tenant_id or tenancy.current_tenant_id() or tenancy.DEFAULT_TENANT_ID)
    sink = _resolve_sink(sink)
    anchor_info: dict[str, Any] = {"status": "not_configured"}
    anchor: Anchor | None = None
    if sink is not None:
        try:
            anchor = await sink.latest(tenant)
        except Exception as exc:  # noqa: BLE001 -- fail closed below
            logger.warning("audit_anchor_unavailable", extra={"error": str(exc)})
            anchor_info = {"status": "unavailable", "error": str(exc)}
        else:
            anchor_info = {"status": "none"}
            if anchor is not None:
                anchor_info = {
                    "status": "pending",
                    "max_id": anchor.max_id,
                    "head_hash": anchor.head_hash,
                    "ts": anchor.ts,
                    "sink": getattr(sink, "name", None),
                }

    head_id, head_hash, _ = await _head(pool, tenant)
    w = await _walk(
        pool,
        tenant,
        after_id=0,
        prev_hash=GENESIS_HASH,
        upto_id=head_id or 0,
        keyed_seen=False,
        watch={anchor.max_id} if anchor else None,
        batch_size=batch_size,
    )
    result: dict[str, Any] = {
        "ok": w.broken_id is None,
        "checked": w.checked,
        "first_broken_id": w.broken_id,
        "reason": w.reason,
        "tenant_id": tenant,
        "head_id": head_id,
        "head_hash": head_hash,
        "anchor": anchor_info,
    }
    if w.broken_id is not None:
        if anchor is not None:
            anchor_info["status"] = "skipped"
        return result

    if anchor is not None:
        status = check_anchor(anchor)
        _, ring = keyring()
        if status == "unsigned" and not ring:
            status = "ok"  # no key configured anywhere: unsigned is all there is
        if status == "ok":
            if head_id is None or head_id < anchor.max_id:
                status = "truncated"
            elif w.seen.get(anchor.max_id) != anchor.head_hash:
                status = "mismatch"
        anchor_info["status"] = status
    if anchor_info["status"] not in ("not_configured", "none", "ok"):
        result["ok"] = False
        result["reason"] = f"anchor_{anchor_info['status']}"
    return result


# --------------------------------------------------------------------------- #
# Anchoring
# --------------------------------------------------------------------------- #

async def anchor_head(pool, sink: Any = _UNSET, *, tenant_id: str | None = None) -> dict[str, Any]:
    """Publish the current tenant's chain head to the anchor sink.

    The rows appended since the previous anchor are verified first (and the
    previously anchored row must still be intact), so a tampered chain is never
    "blessed" by a fresh anchor. Raises :class:`AuditIntegrityError` if not.
    """
    tenant = str(tenant_id or tenancy.current_tenant_id() or tenancy.DEFAULT_TENANT_ID)
    sink = _resolve_sink(sink)
    if sink is None:
        return {"anchored": False, "reason": "no anchor sink configured"}
    prev = await sink.latest(tenant)
    head_id, head_hash, head_alg = await _head(pool, tenant)
    if head_id is None:
        if prev is not None:
            raise AuditIntegrityError(f"chain is empty but was anchored at id {prev.max_id}")
        return {"anchored": False, "reason": "empty chain"}
    if prev is not None and prev.max_id == head_id and prev.head_hash == head_hash:
        return {"anchored": False, "reason": "head already anchored", "anchor": asdict(prev)}

    after_id, prev_hash, keyed = 0, GENESIS_HASH, False
    if prev is not None:
        if check_anchor(prev) == "bad_signature":
            raise AuditIntegrityError("previous anchor has a bad signature")
        if head_id < prev.max_id or await _row_hash(pool, tenant, prev.max_id) != prev.head_hash:
            raise AuditIntegrityError(
                f"chain no longer matches the anchor at id {prev.max_id} (truncated or rewritten)"
            )
        after_id, prev_hash = prev.max_id, prev.head_hash
        keyed = prev.hash_alg.startswith(ALG_HMAC_PREFIX)
    w = await _walk(
        pool, tenant, after_id=after_id, prev_hash=prev_hash, upto_id=head_id, keyed_seen=keyed
    )
    if w.broken_id is not None:
        raise AuditIntegrityError(f"chain broken at id {w.broken_id} ({w.reason}); not anchoring")

    anchor = sign_anchor(
        Anchor(
            tenant_id=tenant,
            max_id=head_id,
            head_hash=head_hash or "",
            hash_alg=head_alg or ALG_SHA256,
            ts=datetime.now(timezone.utc).isoformat(),
        )
    )
    receipt = await sink.publish(anchor)
    logger.info("audit_anchored", extra={"tenant_id": tenant, "max_id": head_id})
    return {"anchored": True, "anchor": asdict(anchor), "receipt": receipt}


async def anchor_all_tenants(pool, sink: Any = _UNSET) -> list[dict[str, Any]]:
    """Anchor every active tenant's chain; failures are logged, not raised."""
    sink = _resolve_sink(sink)
    out: list[dict[str, Any]] = []
    if sink is None:
        return out
    for tid in await tenancy.list_tenant_ids(pool):
        try:
            res = await anchor_head(pool, sink, tenant_id=tid)
        except (AuditIntegrityError, AnchorSinkError) as exc:
            logger.error("audit_anchor_failed", extra={"tenant_id": tid, "error": str(exc)})
            res = {"anchored": False, "reason": str(exc)}
        out.append({"tenant_id": tid, **res})
    return out


async def anchor_loop(app) -> None:
    """Background task: anchor every tenant's chain head once per interval."""
    interval = max(60, int(settings.audit_anchor_interval_sec))
    logger.info("audit_anchor_loop_started", extra={"interval_sec": interval})
    while True:
        try:
            pool = getattr(app.state, "pool", None)
            sink = getattr(app.state, "audit_anchor_sink", None)
            if pool is not None and sink is not None:
                await anchor_all_tenants(pool, sink)
        except asyncio.CancelledError:
            logger.info("audit_anchor_loop_stopped")
            raise
        except Exception:  # noqa: BLE001 - never let the loop die
            logger.exception("audit_anchor_tick_failed")
        await asyncio.sleep(interval)
