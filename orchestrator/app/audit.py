"""Tamper-evident, hash-chained audit log.

Each appended row stores ``entry_hash = sha256(prev_hash || canonical(row))``
where ``prev_hash`` is the previous row's ``entry_hash`` (genesis = 64 zeros)
and ``canonical(row)`` is a deterministic JSON serialisation of the row's
content columns (everything except ``id``, ``prev_hash`` and ``entry_hash``).

Because every row's hash commits to its predecessor, editing or deleting any
historical row breaks the chain from that point on -- which ``verify()`` walks
the chain to detect, returning the id of the first broken row.

Appends are serialised with a transaction-scoped Postgres advisory lock so the
chain stays strictly linear even under concurrent writers.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64

# A fixed advisory-lock key ("ASMAUDIT"-ish) serialising audit appends.
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


def compute_entry_hash(prev_hash: str, row: dict[str, Any]) -> str:
    material = prev_hash + canonical_payload(row)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


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
) -> dict[str, Any]:
    """Append one row to the hash chain and return it. Serialised via advisory lock."""
    ts = datetime.now(timezone.utc)
    details = _sanitize(details or {})
    actor, actor_role, action, method, path, classification, justification, request_id = (
        _sanitize(v) for v in (
            actor, actor_role, action, method, path, classification, justification, request_id,
        )
    )
    if resource_id is not None:
        resource_id = _sanitize(str(resource_id))
    async with pool.acquire() as con:
        async with con.transaction():
            # Serialise appends: the lock is held until the transaction commits.
            await con.execute("SELECT pg_advisory_xact_lock($1)", _AUDIT_LOCK_KEY)
            prev_hash = await con.fetchval(
                "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1"
            )
            prev_hash = prev_hash or GENESIS_HASH
            row = {
                "ts": ts,
                "actor": actor,
                "actor_role": actor_role,
                "action": action,
                "resource_type": resource_type,
                "resource_id": str(resource_id) if resource_id is not None else None,
                "method": method,
                "path": path,
                "status": status,
                "classification": classification,
                "justification": justification,
                "ip": ip,
                "request_id": request_id,
                "details": details,
            }
            entry_hash = compute_entry_hash(prev_hash, row)
            rec = await con.fetchrow(
                """
                INSERT INTO audit_log (
                    ts, actor, actor_role, action, resource_type, resource_id,
                    method, path, status, classification, justification, ip,
                    request_id, details, prev_hash, entry_hash
                ) VALUES (
                    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb,$15,$16
                )
                RETURNING id, ts, entry_hash, prev_hash
                """,
                ts,
                actor,
                actor_role,
                action,
                resource_type,
                row["resource_id"],
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
            )
    return {"id": rec["id"], "entry_hash": rec["entry_hash"], "prev_hash": rec["prev_hash"]}


async def verify(pool) -> dict[str, Any]:
    """Walk the whole chain. Return {ok, checked, first_broken_id?}.

    A row is broken if either its stored ``prev_hash`` does not match the
    previous row's ``entry_hash`` (chain linkage) or its ``entry_hash`` does
    not match the recomputation from its own content (row integrity).
    """
    checked = 0
    prev = GENESIS_HASH
    async with pool.acquire() as con:
        rows = await con.fetch(
            """
            SELECT id, ts, actor, actor_role, action, resource_type, resource_id,
                   method, path, status, classification, justification, ip,
                   request_id, details, prev_hash, entry_hash
              FROM audit_log
             ORDER BY id ASC
            """
        )
    for r in rows:
        checked += 1
        row = {col: r[col] for col in _CONTENT_COLS}
        expected = compute_entry_hash(prev, row)
        if r["prev_hash"] != prev or r["entry_hash"] != expected:
            return {"ok": False, "checked": checked, "first_broken_id": int(r["id"])}
        prev = r["entry_hash"]
    return {"ok": True, "checked": checked, "first_broken_id": None}
