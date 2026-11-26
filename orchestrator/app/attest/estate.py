"""Estate bootstrap (docs/ASSURANCE_P3.md 5.1): the random estate id and the sealed ``commit_key``.

An *estate* is one row per tenant (``attest_estates``) created lazily and idempotently on the first attestation action:

* ``estate_id``: ``e_`` + base32-lowercase of 16 random bytes (26 characters). It is random, never derived from the
  tenant id, so a statement or an anchor can name an estate without naming (or letting anyone brute-force) the tenant.
* ``commit_key``: 32 random bytes that blind every Merkle leaf (D10). It is sealed under the attestation KEK exactly
  like a signing seed (kind ``commit``, AAD bound to the tenant) and is returned only by :func:`get_commit_key`, which
  never caches it. Losing it loses the ability to prove leaves, never the validity of a root (D29), so a missing key is
  an error here, never silently replaced.

Without the KEK or the platform issuer/revoker material the estate is ``not_configured`` and nothing is created.
This module creates **no keys and no publications**: the first ``attest`` and ``anchor`` keys with certificates are
P3.3's, the default publication is P3.6's, and both build on the row made here.

``conn`` is an asyncpg connection acquired inside ``tenancy.tenant_context(tenant)`` (the pool stamps the tenant). The
tenant used for sealing is read from the connection itself and checked against the context, so a context that
disagrees with its connection is refused instead of sealing for the wrong tenant.
"""
from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .. import tenancy
from . import crypto
from .config import settings

_COMMIT_KIND = "commit"
_COMMIT_KID = "commit"
_COMMIT_USAGE = "commit"
_COMMIT_ALG = "hmac-sha256"
COMMIT_KEY_BYTES = 32


class EstateError(Exception):
    """The estate cannot be created or read. The message never contains key material."""


class EstateNotConfigured(EstateError):
    """The attestation KEK or the platform issuer/revoker material is missing: nothing is created."""

    def __init__(self, missing: tuple[str, ...]) -> None:
        super().__init__("attestation is not configured: missing " + ", ".join(missing))
        self.missing = tuple(missing)


class CommitKeyMissing(EstateError):
    """There is no commit key for this tenant (no estate yet, or the sealed row was erased)."""


@dataclass(frozen=True)
class EstateInfo:
    tenant_id: str
    estate_id: str
    ttl_h: int
    issuing_suspended: bool
    hold_reason: str
    hold_requires_ack: bool
    created_at: datetime


@dataclass(frozen=True)
class EstateStatus:
    """``state`` is ``not_configured`` (KEK or platform material missing), ``pending`` (configured, no estate yet) or
    ``ready``."""

    state: str
    missing: tuple[str, ...]
    estate_id: str | None


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

def _present(path: str | None) -> bool:
    if not path or not path.strip():
        return False
    try:
        return os.path.isfile(path) and os.path.getsize(path) > 0
    except OSError:
        return False


def configuration_gaps() -> list[str]:
    """What is missing for attestation to run: ``kek`` and/or ``issuer_key``, ``issuer_cert``, ``revoker_key``,
    ``revoker_cert`` (a path that is unset, absent or empty counts as missing). Empty list = configured. This only
    checks presence: the platform material is loaded and verified by ``attest.platform_keys`` (P3.3)."""
    gaps: list[str] = []
    try:
        if not crypto.kek_configured():
            gaps.append("kek")
    except crypto.SealError:
        gaps.append("kek")
    for gap, value in (
        ("issuer_key", settings.issuer_key_file), ("issuer_cert", settings.issuer_cert_file),
        ("revoker_key", settings.revoker_key_file), ("revoker_cert", settings.revoker_cert_file),
    ):
        if not _present(value):
            gaps.append(gap)
    return gaps


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def new_estate_id() -> str:
    """``e_`` + base32-lowercase of 16 random bytes, padding stripped: 26 characters of ``[a-z2-7]``."""
    return "e_" + base64.b32encode(os.urandom(16)).decode("ascii").lower().rstrip("=")


async def _tenant_of(conn: Any) -> str:
    """The tenant this connection acts for (what row-level security and the column default will use), checked
    against the tenant context so the two can never disagree."""
    db = await conn.fetchval("SELECT COALESCE(paddock_current_tenant(), paddock_default_tenant())::text")
    ctx = tenancy.current_tenant_id()
    if ctx and crypto.normalize_tenant(ctx) != crypto.normalize_tenant(db):
        raise EstateError("the tenant context does not match the connection's tenant")
    return crypto.normalize_tenant(db)


def _info(tenant: str, row: Any) -> EstateInfo:
    return EstateInfo(
        tenant_id=tenant, estate_id=row["estate_id"], ttl_h=row["ttl_h"],
        issuing_suspended=row["issuing_suspended"], hold_reason=row["hold_reason"],
        hold_requires_ack=row["hold_requires_ack"], created_at=row["created_at"],
    )


_SELECT = ("SELECT estate_id, ttl_h, issuing_suspended, hold_reason, hold_requires_ack, created_at "
           "FROM attest_estates WHERE tenant_id = $1::uuid")


# --------------------------------------------------------------------------- #
# Public interface
# --------------------------------------------------------------------------- #

async def get_estate(conn: Any) -> EstateInfo | None:
    """The tenant's estate, or None if none has been created. Never creates anything, needs no configuration."""
    tenant = await _tenant_of(conn)
    row = await conn.fetchrow(_SELECT, tenant)
    if row is None or not row["estate_id"]:
        return None
    return _info(tenant, row)


async def status(conn: Any) -> EstateStatus:
    gaps = tuple(configuration_gaps())
    info = await get_estate(conn)
    state = "not_configured" if gaps else ("ready" if info else "pending")
    return EstateStatus(state=state, missing=gaps, estate_id=info.estate_id if info else None)


async def ensure_estate(conn: Any) -> EstateInfo:
    """Create the tenant's estate if it does not exist (estate id and sealed commit key, in one transaction, one audit
    row) and return it. Idempotent and safe under concurrency. Raises :class:`EstateNotConfigured` and creates nothing
    when the KEK or the platform issuer material is missing."""
    gaps = tuple(configuration_gaps())
    if gaps:
        raise EstateNotConfigured(gaps)
    tenant = await _tenant_of(conn)
    async with conn.transaction():
        await conn.execute(
            "INSERT INTO attest_estates (tenant_id) VALUES ($1::uuid) ON CONFLICT (tenant_id) DO NOTHING", tenant)
        row = await conn.fetchrow(_SELECT + " FOR UPDATE", tenant)
        if row is None:  # RLS hid the row we just inserted: the connection is not this tenant's
            raise EstateError("the estate row is not visible to this connection")
        if not row["estate_id"]:
            estate_id = new_estate_id()
            commit_key = bytearray(os.urandom(COMMIT_KEY_BYTES))
            try:
                await conn.execute(
                    "UPDATE attest_estates SET estate_id = $2 WHERE tenant_id = $1::uuid AND estate_id = ''",
                    tenant, estate_id)
                try:
                    await crypto.store_secret(
                        conn, plaintext=commit_key, tenant_id=tenant, kind=_COMMIT_KIND, kid=_COMMIT_KID,
                        usage=_COMMIT_USAGE, alg=_COMMIT_ALG)
                except crypto.KekNotConfigured:
                    raise EstateNotConfigured(("kek",)) from None
                except crypto.SealError:
                    raise EstateError("the commit key could not be sealed") from None
            finally:
                crypto.zero(commit_key)
            from .. import audit as audit_svc   # lazy: audit pulls in the whole app

            await audit_svc.record(
                None, action="attest.estate.created", actor="system", actor_role="system",
                resource_type="attest_estate", resource_id=estate_id, details={"estate": estate_id},
                con=conn, tenant_id=tenant)
            row = await conn.fetchrow(_SELECT, tenant)
    return _info(tenant, row)


async def get_commit_key(conn: Any) -> bytes:
    """The tenant's 32-byte commit key, unsealed for this call only (never cached). ``CommitKeyMissing`` if there is
    none; ``EstateNotConfigured`` without a KEK; ``EstateError`` if the sealed row cannot be opened (a rotated-away
    KEK, a row moved from another tenant)."""
    tenant = await _tenant_of(conn)
    try:
        buf = await crypto.load_secret(
            conn, tenant_id=tenant, kind=_COMMIT_KIND, kid=_COMMIT_KID, usage=_COMMIT_USAGE, alg=_COMMIT_ALG)
    except crypto.KekNotConfigured:
        raise EstateNotConfigured(("kek",)) from None
    except crypto.SealError:
        raise EstateError("the commit key cannot be opened (rotated-away KEK, or a row moved between tenants)") from None
    if buf is None:
        raise CommitKeyMissing("no commit key for this tenant")
    try:
        return bytes(buf)
    finally:
        crypto.zero(buf)
