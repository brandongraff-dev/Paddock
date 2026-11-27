"""Estate key lifecycle (docs/ASSURANCE_P3.md 3.3, 3.8, D16, D17).

Every estate has an ``attest`` key (signs statements) and an ``anchor`` key (signs audit anchors), both Ed25519, held by
a ``KeyBackend`` (hosted: sealed under the attestation KEK) and certified online by the platform issuer
(``platform_keys``, ``certs``). This module owns the ``attest_keys`` rows and their state machine::

    pending -> active -> retiring -> retired          any state -> revoked (terminal)

``attest_keys`` rows are never deleted and status only moves forward (trigger 064). At most one key per usage is
``active`` (unique index) and at most three are live at once (active, next, previous: the DNS budget, 4.1).

* :func:`create_key` generates the key through the backend, certifies it and inserts the row in ONE transaction, so a
  failure anywhere leaves neither a sealed secret nor a row. It refuses (creating nothing, no ephemeral key) when the
  KEK or the platform issuer material is missing or unverifiable.
* :func:`activate` makes a pending key the signing key; the previous active key becomes ``retiring``. Observing the new
  key in DNS (attest keys) is the caller's precondition (``attest/dns_binding``); this module does not look at DNS.
* :func:`sweep` retires a ``retiring`` key once its last statement's ``valid_until`` plus 48 h has passed, and erases the
  sealed secret of a ``retired`` key 7 days later (revoked keys are erased at once).
* :func:`renew_certs` renews a certificate (same key, new serial) when 30 days of its 90 remain; the window start never
  moves, so older statements keep verifying.
* :func:`rotate_due` prepares the successor 30 days before the 300-day rotation point.
* :func:`revoke` is the emergency path (3.8 level 3): status, append-only revocation row, hold, public objects off,
  sealed secret destroyed, replacement key, re-signed list.

``conn`` is an asyncpg connection acquired inside ``tenancy.tenant_context(<tenant>)``; the tenant is read from the
connection (see ``estate``) and the backend refuses a context that disagrees with it. Key material never appears in
a return value, a log line or an audit row: a ``KeyRecord`` carries identity and the (public) certificate only.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from . import certs, crypto, estate, platform_keys
from .backend import AwsKmsBackend, BackendError, KeyHandle
from .backend_local import LocalAesGcmBackend
from .estate import _tenant_of

logger = logging.getLogger(__name__)

DAY = 86400
KEY_LIFE_S = 365 * DAY            # an estate key
CERT_LIFE_S = 90 * DAY            # a certificate
RENEW_WHEN_LEFT_S = 30 * DAY      # renewed at 60 days
PREPARE_ROTATION_S = 270 * DAY    # create the successor (30 days before the rotation point)
ROTATE_AFTER_S = 300 * DAY        # the successor takes over (30 days of overlap before expiry)
RETIRE_GRACE_S = 48 * 3600        # after the last statement's valid_until
ERASE_AFTER_RETIRE_S = 7 * DAY
MIN_KEY_LIFE_S = 7 * DAY          # a key whose window the issuer cannot cover for this long is not created
MAX_LIVE_KEYS = 3                 # active + next + previous (what DNS carries at once)
USAGES = ("attest", "anchor")
LIVE = ("pending", "active", "retiring")


class KeysError(Exception):
    """A key operation is refused. ``code`` is a spec reason code or ``keys.*``; the message never has key material."""

    def __init__(self, message: str, code: str = "keys.refused") -> None:
        super().__init__(message)
        self.code = code


class KeyStateError(KeysError):
    """The key is not in a state that allows this operation."""


class KeyNotFound(KeysError):
    """No such key for this tenant (a foreign kid is indistinguishable from an unknown one)."""

    def __init__(self, message: str = "no such key") -> None:
        super().__init__(message, "keys.not_found")


# --------------------------------------------------------------------------- #
# Values
# --------------------------------------------------------------------------- #

def _epoch(value: Any) -> Optional[int]:
    return None if value is None else int(value.timestamp())


def _dt(epoch: int) -> datetime:
    return datetime.fromtimestamp(epoch, timezone.utc)


@dataclass(frozen=True)
class KeyRecord:
    tenant_id: str
    kid: str
    usage: str
    alg: str
    custody: str
    backend: str
    key_ref: str
    status: str
    public_key: bytes = field(repr=False)
    publication_id: Optional[str]
    not_before: Optional[int]
    not_after: Optional[int]
    cert: Optional[certs.Cert] = field(repr=False)
    cert_serial: int
    cert_expires_at: Optional[int]
    created_at: Optional[int]
    activated_at: Optional[int]
    retired_at: Optional[int]
    revoked_at: Optional[int]

    @property
    def handle(self) -> KeyHandle:
        return KeyHandle(self.backend, self.tenant_id, self.kid, self.usage, self.alg, self.key_ref)

    def usable_at(self, t: int) -> bool:
        """Active and inside both the key window and the certificate window at ``t`` (end-exclusive)."""
        return (self.status == "active" and self.cert is not None and self.cert.window_contains(t)
                and (self.not_before is None or self.not_before <= t) and (self.not_after is None or t < self.not_after))


_COLUMNS = ("kid, usage, alg, custody, backend, key_ref, status, public_key, publication_id, not_before, not_after, "
            "cert, cert_serial, cert_expires_at, created_at, activated_at, retired_at, revoked_at")


def _record(tenant: str, row: Any) -> KeyRecord:
    raw = row["cert"]
    cert = None
    try:
        doc = json.loads(raw) if isinstance(raw, str) else raw
        if doc:
            cert = certs.parse_cert(doc)
    except (ValueError, certs.CertError):
        cert = None                                  # an unparseable cert makes the key unusable, never usable
    return KeyRecord(
        tenant_id=tenant, kid=row["kid"], usage=row["usage"], alg=row["alg"], custody=row["custody"],
        backend=row["backend"], key_ref=row["key_ref"], status=row["status"], public_key=bytes(row["public_key"]),
        publication_id=str(row["publication_id"]) if row["publication_id"] else None,
        not_before=_epoch(row["not_before"]), not_after=_epoch(row["not_after"]), cert=cert,
        cert_serial=row["cert_serial"], cert_expires_at=_epoch(row["cert_expires_at"]),
        created_at=_epoch(row["created_at"]), activated_at=_epoch(row["activated_at"]),
        retired_at=_epoch(row["retired_at"]), revoked_at=_epoch(row["revoked_at"]))


async def db_now(conn: Any) -> int:
    """The database clock in whole seconds (the one clock the issuer uses, D13)."""
    return int(await conn.fetchval("SELECT floor(extract(epoch from now()))::bigint"))


async def _clock(conn: Any, now: Any) -> int:
    return await db_now(conn) if now is None else certs.epoch_of(now)


def backend_for(name: str, pool: Any = None) -> Any:
    """The backend that holds keys of that name. ``aws-kms`` is a stub that fails closed."""
    if name == LocalAesGcmBackend.name:
        return LocalAesGcmBackend(pool)
    if name == AwsKmsBackend.name:
        return AwsKmsBackend()
    raise KeysError(f"unknown key backend {name!r}", "keys.backend")


async def _estate_id(conn: Any, tenant: str) -> str:
    info = await estate.get_estate(conn)
    if info is None:
        raise KeysError("this tenant has no estate yet", "keys.no_estate")
    return info.estate_id


async def _audit(conn: Any, tenant: str, action: str, kid: str, actor: str, details: dict, justification: str = "") -> None:
    from .. import audit as audit_svc   # lazy: audit pulls in the whole app

    await audit_svc.record(
        None, action=action, actor=actor, actor_role="system", resource_type="attest_key", resource_id=kid,
        details=details, justification=justification or None, con=conn, tenant_id=tenant)


# --------------------------------------------------------------------------- #
# Reads
# --------------------------------------------------------------------------- #

async def get_key(conn: Any, kid: str) -> Optional[KeyRecord]:
    tenant = await _tenant_of(conn)
    row = await conn.fetchrow(f"SELECT {_COLUMNS} FROM attest_keys WHERE tenant_id = $1::uuid AND kid = $2", tenant, kid)
    return _record(tenant, row) if row else None


async def list_keys(conn: Any, usage: Optional[str] = None, statuses: Optional[tuple] = None) -> list:
    tenant = await _tenant_of(conn)
    rows = await conn.fetch(
        f"SELECT {_COLUMNS} FROM attest_keys WHERE tenant_id = $1::uuid AND ($2::text IS NULL OR usage = $2) "
        "AND ($3::text[] IS NULL OR status = ANY($3)) ORDER BY created_at, kid", tenant, usage,
        list(statuses) if statuses else None)
    return [_record(tenant, r) for r in rows]


async def active_key(conn: Any, usage: str, *, now: Any = None, publication_id: Optional[str] = None,
                     check_window: bool = True) -> Optional[KeyRecord]:
    """The estate's active signing key for ``usage``, or ``None`` when there is none or (with ``check_window``, the
    default) its key or certificate window does not contain ``now``: an expired key never signs. Rollover logic asks
    with ``check_window=False`` (an active key whose certificate lapsed still needs its successor)."""
    if publication_id is not None:
        raise KeysError("per-publication keys are reserved", "keys.reserved")
    tenant = await _tenant_of(conn)
    t = await _clock(conn, now)
    row = await conn.fetchrow(
        f"SELECT {_COLUMNS} FROM attest_keys WHERE tenant_id = $1::uuid AND usage = $2 AND status = 'active' "
        "AND publication_id IS NULL", tenant, usage)
    if row is None:
        return None
    rec = _record(tenant, row)
    return rec if (not check_window or rec.usable_at(t)) else None


# --------------------------------------------------------------------------- #
# Create / activate / rotate
# --------------------------------------------------------------------------- #

async def create_key(conn: Any, usage: str, *, platform: Any = None, backend: Any = None, pool: Any = None,
                     publication_id: Optional[str] = None, created_by: Optional[str] = None,
                     now: Any = None) -> KeyRecord:
    """Create a ``pending`` key of ``usage`` with its certificate. Refuses without a KEK or verified platform issuer
    material (nothing is created: no ephemeral keys) and when a pending key already exists or three are live."""
    if usage not in USAGES:
        raise KeysError(f"usage must be one of {USAGES}", "keys.usage")
    if publication_id is not None:
        raise KeysError("per-publication keys are reserved (D31)", "keys.reserved")
    gaps = estate.configuration_gaps()
    if gaps:
        raise estate.EstateNotConfigured(tuple(gaps))
    t = await _clock(conn, now)
    platform = platform or platform_keys.load(now=t)
    backend = backend or LocalAesGcmBackend(pool)
    key_na = min(t + KEY_LIFE_S, platform.issuer.cert.not_after)
    if key_na - t < MIN_KEY_LIFE_S:
        raise KeysError("the issuer certificate expires too soon to certify a new key", "issuer.outside_validity")
    cert_na = min(t + CERT_LIFE_S, key_na)
    async with conn.transaction():
        info = await estate.ensure_estate(conn)
        tenant = info.tenant_id
        live = await conn.fetch(
            "SELECT status FROM attest_keys WHERE tenant_id = $1::uuid AND usage = $2 AND publication_id IS NULL "
            "AND status = ANY($3::text[]) FOR UPDATE", tenant, usage, list(LIVE))
        if any(r["status"] == "pending" for r in live):
            raise KeyStateError("a pending key already exists for this usage", "keys.pending_exists")
        if len(live) >= MAX_LIVE_KEYS:
            raise KeyStateError(f"{MAX_LIVE_KEYS} keys are already live for this usage", "keys.too_many")
        handle, public = await backend.generate(tenant, usage, "ed25519", conn=conn)
        cert = certs.issue_cert(platform.issuer, usage=usage, public_key=public, estate=info.estate_id, not_before=t,
                                not_after=cert_na, serial=1, custody=backend.custody)
        await conn.execute(
            "INSERT INTO attest_keys (tenant_id, kid, usage, alg, public_key, custody, backend, key_ref, status, "
            "not_before, not_after, cert, cert_serial, cert_expires_at, created_by) "
            "VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, 'pending', $9, $10, $11::jsonb, $12, $13, $14)",
            tenant, handle.kid, usage, handle.alg, public, backend.custody, handle.backend, handle.key_ref,
            _dt(t), _dt(key_na), cert.envelope.decode("ascii"), cert.serial, _dt(cert.not_after), created_by)
        await _audit(conn, tenant, "attest.key.created", handle.kid, created_by or "system",
                     {"kid": handle.kid, "usage": usage, "custody": backend.custody, "backend": backend.name,
                      "estate": info.estate_id, "cert_serial": cert.serial})
        await _audit(conn, tenant, "attest.cert.issued", handle.kid, created_by or "system",
                     {"kid": handle.kid, "serial": cert.serial, "issuer_kid": cert.issuer_kid, "not_after": cert.not_after})
    rec = await get_key(conn, handle.kid)
    assert rec is not None
    return rec


async def activate(conn: Any, kid: str, *, platform: Any = None, backend: Any = None, pool: Any = None,
                   actor: Optional[str] = None, now: Any = None) -> KeyRecord:
    """Make the pending key ``kid`` the signing key of its usage. The key's certificate must verify now and its
    backend must report it healthy; the previously active key becomes ``retiring`` in the same transaction."""
    t = await _clock(conn, now)
    platform = platform or platform_keys.load(now=t)
    tenant = await _tenant_of(conn)
    async with conn.transaction():
        row = await conn.fetchrow(
            f"SELECT {_COLUMNS} FROM attest_keys WHERE tenant_id = $1::uuid AND kid = $2 FOR UPDATE", tenant, kid)
        if row is None:
            raise KeyNotFound()
        rec = _record(tenant, row)
        if rec.status != "pending":
            raise KeyStateError(f"only a pending key can be activated (this one is {rec.status})", "keys.state")
        if rec.publication_id is not None:
            raise KeysError("per-publication keys are reserved (D31)", "keys.reserved")
        estate_id = await _estate_id(conn, tenant)
        if rec.cert is None:
            raise KeyStateError("the key has no usable certificate", "key.cert_missing")
        try:
            certs.verify_chain(rec.cert, issuers=[platform.issuer.cert], roots=platform.roots, at=t,
                               expect_usage=rec.usage, expect_estate=estate_id)
        except certs.CertError as exc:
            raise KeyStateError(f"the key's certificate does not verify now: {exc.detail}", exc.code) from None
        if rec.cert.public_key != rec.public_key or rec.cert.kid != rec.kid:
            raise KeyStateError("the key's certificate does not match the key", "key.cert_subject_mismatch")
        health = await (backend or backend_for(rec.backend, pool)).health(rec.handle, conn=conn)
        if not health.ok:
            raise KeyStateError(f"the key cannot sign ({health.state})", "keys.unhealthy")
        previous = await conn.fetch(
            "SELECT kid FROM attest_keys WHERE tenant_id = $1::uuid AND usage = $2 AND publication_id IS NULL "
            "AND status = 'active' FOR UPDATE", tenant, rec.usage)
        await conn.execute(
            "UPDATE attest_keys SET status = 'retiring' WHERE tenant_id = $1::uuid AND usage = $2 "
            "AND publication_id IS NULL AND status = 'active'", tenant, rec.usage)
        await conn.execute(
            "UPDATE attest_keys SET status = 'active', activated_at = $3 WHERE tenant_id = $1::uuid AND kid = $2",
            tenant, kid, _dt(t))
        for p in previous:
            await _audit(conn, tenant, "attest.key.retiring", p["kid"], actor or "system",
                         {"kid": p["kid"], "usage": rec.usage, "successor": kid})
        await _audit(conn, tenant, "attest.key.activated", kid, actor or "system",
                     {"kid": kid, "usage": rec.usage, "previous": [p["kid"] for p in previous]})
    out = await get_key(conn, kid)
    assert out is not None
    return out


async def rotate(conn: Any, usage: str, **kw: Any) -> KeyRecord:
    """Start a rollover: create the successor of the active ``usage`` key as ``pending`` (its TXT record is the
    "second record" the owner publishes). It becomes the signing key with :func:`activate`."""
    if await active_key(conn, usage, now=kw.get("now"), check_window=False) is None:
        raise KeyStateError("there is no active key to roll over; create the first key instead", "keys.state")
    return await create_key(conn, usage, **kw)


async def rotate_due(conn: Any, platform: Any = None, *, backend: Any = None, pool: Any = None, now: Any = None) -> dict:
    """Prepare and perform automatic rollovers: 30 days before the 300-day rotation point the successor is created
    (``pending``); an ``anchor`` successor needs no DNS and takes over at 300 days, an ``attest`` successor waits for
    the DNS observation that only the caller can make. Returns ``{"created": [...], "activated": [...]}``."""
    t = await _clock(conn, now)
    out: dict = {"created": [], "activated": []}
    for usage in USAGES:
        cur = await active_key(conn, usage, now=t, check_window=False)
        if cur is None:
            continue
        age = t - (cur.activated_at if cur.activated_at is not None else (cur.not_before or t))
        pending = [k for k in await list_keys(conn, usage, ("pending",))]
        if age >= PREPARE_ROTATION_S and not pending:
            created = await create_key(conn, usage, platform=platform, backend=backend, pool=pool, now=t)
            out["created"].append(created.kid)
            pending = [created]
        if usage == "anchor" and age >= ROTATE_AFTER_S and pending:
            await activate(conn, pending[0].kid, platform=platform, backend=backend, pool=pool, now=t)
            out["activated"].append(pending[0].kid)
    return out


# --------------------------------------------------------------------------- #
# Certificates and keys.json
# --------------------------------------------------------------------------- #

async def renew_certs(conn: Any, platform: Any = None, *, now: Any = None) -> list:
    """Renew the certificates of this tenant's ``pending`` and ``active`` keys with 30 days or less left (a new
    serial, the same key, the same window start so older statements keep verifying, a new end capped by the key's own
    365-day end and the issuer's). Returns the kids renewed."""
    t = await _clock(conn, now)
    platform = platform or platform_keys.load(now=t)
    tenant = await _tenant_of(conn)
    renewed: list = []
    async with conn.transaction():
        rows = await conn.fetch(
            f"SELECT {_COLUMNS} FROM attest_keys WHERE tenant_id = $1::uuid AND publication_id IS NULL "
            "AND status IN ('pending','active') ORDER BY kid FOR UPDATE", tenant)
        estate_id = await _estate_id(conn, tenant) if rows else ""
        for row in rows:
            rec = _record(tenant, row)
            if rec.cert is None or rec.not_after is None:
                logger.warning("attest_key_without_cert", extra={"kid": rec.kid})
                continue
            if rec.cert.not_after - t > RENEW_WHEN_LEFT_S:
                continue
            new_na = min(t + CERT_LIFE_S, rec.not_after, platform.issuer.cert.not_after)
            if new_na <= rec.cert.not_after:
                continue                                  # nothing to gain: the key's or the issuer's end binds
            cert = certs.issue_cert(platform.issuer, usage=rec.usage, public_key=rec.public_key, estate=estate_id,
                                    not_before=rec.cert.not_before, not_after=new_na, serial=rec.cert.serial + 1,
                                    custody=rec.custody)
            await conn.execute(
                "UPDATE attest_keys SET cert = $3::jsonb, cert_serial = $4, cert_expires_at = $5 "
                "WHERE tenant_id = $1::uuid AND kid = $2", tenant, rec.kid, cert.envelope.decode("ascii"),
                cert.serial, _dt(cert.not_after))
            await _audit(conn, tenant, "attest.cert.renewed", rec.kid, "system",
                         {"kid": rec.kid, "serial": cert.serial, "not_after": cert.not_after})
            renewed.append(rec.kid)
    return renewed


def _fit(recs: list) -> list:
    """At most ``certs.MAX_KEYS`` entries (what the open verifier reads). Live keys (pending, active, retiring) are
    never dropped; room is made by dropping retired keys first, then revoked ones, oldest first."""
    room = certs.MAX_KEYS
    live = [r for r in recs if r.status in LIVE]
    if len(recs) <= room:
        return recs
    other = [r for r in recs if r.status not in LIVE]

    def rank(r: KeyRecord) -> tuple:
        return (0 if r.status == "retired" else 1, r.retired_at or r.revoked_at or r.created_at or 0, r.kid)

    keep = sorted(other, key=rank, reverse=True)[: max(0, room - len(live))]
    return live + keep


async def keys_document(conn: Any, platform: Any = None, *, now: Any = None) -> bytes:
    """``keys.json`` for this tenant's estate: the platform issuer (and earlier ones from the drop-in directory) and
    revoker certificates and every key's certificate, in every status except those whose issuer cannot be listed.
    The entry fields are derived from the certificate payloads (``certs.build_keys_json``)."""
    t = await _clock(conn, now)
    platform = platform or platform_keys.load(now=t)
    tenant = await _tenant_of(conn)
    estate_id = await _estate_id(conn, tenant)
    issuers = [platform.issuer.cert]
    for old in platform_keys.previous_issuer_certs():
        if old.kid != platform.issuer.kid:
            try:
                certs.verify_chain(old, issuers=[], roots=platform.roots, at=None, expect_usage="issue-cert")
                issuers.append(old)
            except certs.CertError:
                logger.warning("attest_previous_issuer_cert_unverifiable", extra={"kid": old.kid})
    listed = {c.kid for c in issuers}
    listable: list = []
    for rec in await list_keys(conn):
        if rec.cert is None or rec.cert.kid != rec.kid or rec.cert.public_key != rec.public_key:
            logger.error("attest_key_cert_mismatch", extra={"kid": rec.kid})
            continue                                      # never publish a certificate that disagrees with its key
        if rec.cert.issuer_kid not in listed:
            logger.warning("attest_key_issuer_not_listable", extra={"kid": rec.kid})
            continue
        listable.append(rec)
    return certs.build_keys_json(estate_id, issuers=issuers, revoker=platform.revoker.cert,
                                 certs_=[r.cert for r in _fit(listable)])


# --------------------------------------------------------------------------- #
# Retirement and erasure
# --------------------------------------------------------------------------- #

async def _last_use(conn: Any, tenant: str, rec: KeyRecord) -> int:
    if rec.usage == "attest":
        v = await conn.fetchval("SELECT max(valid_until) FROM attest_statements WHERE tenant_id = $1::uuid AND kid = $2",
                                tenant, rec.kid)
    else:
        v = await conn.fetchval("SELECT max(at) FROM attest_anchors WHERE tenant_id = $1::uuid AND doc->>'kid' = $2",
                                tenant, rec.kid)
    fallback = rec.activated_at if rec.activated_at is not None else (rec.created_at or 0)
    return max(_epoch(v) or 0, fallback)


async def sweep(conn: Any, *, backend: Any = None, pool: Any = None, now: Any = None) -> dict:
    """Retire ``retiring`` keys whose last statement's ``valid_until`` (last anchor for anchor keys) plus 48 h has
    passed, erase the sealed secret of keys retired for 7 days, and finish erasing any revoked key. Returns
    ``{"retired": [...], "erased": [...]}``. Idempotent."""
    t = await _clock(conn, now)
    tenant = await _tenant_of(conn)
    out: dict = {"retired": [], "erased": []}
    async with conn.transaction():
        for rec in await list_keys(conn, statuses=("retiring",)):
            if t >= await _last_use(conn, tenant, rec) + RETIRE_GRACE_S:
                await conn.execute(
                    "UPDATE attest_keys SET status = 'retired', retired_at = $3 WHERE tenant_id = $1::uuid AND kid = $2",
                    tenant, rec.kid, _dt(t))
                await _audit(conn, tenant, "attest.key.retired", rec.kid, "system", {"kid": rec.kid, "usage": rec.usage})
                out["retired"].append(rec.kid)
        for rec in await list_keys(conn, statuses=("retired", "revoked")):
            when = rec.retired_at if rec.status == "retired" else rec.revoked_at
            if rec.status == "retired" and (when is None or t < when + ERASE_AFTER_RETIRE_S):
                continue
            if await crypto.secret_exists(conn, tenant_id=tenant, kind="signing", kid=rec.kid):
                await (backend or backend_for(rec.backend, pool)).destroy(rec.handle, conn=conn)
                await _audit(conn, tenant, "attest.key.erased", rec.kid, "system", {"kid": rec.kid, "status": rec.status})
                out["erased"].append(rec.kid)
    return out


# --------------------------------------------------------------------------- #
# Revocation
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class RevokeResult:
    key: KeyRecord
    already_revoked: bool = False
    replacement: Optional[KeyRecord] = None
    replacement_error: Optional[str] = None
    destroy_error: Optional[str] = None
    list: Any = None
    list_error: Optional[str] = None


async def revoke(conn: Any, kid: str, *, reason: str = "key_compromise", actor: str = "system", justification: str = "",
                 platform: Any = None, backend: Any = None, pool: Any = None, now: Any = None,
                 resign: bool = True) -> RevokeResult:
    """Emergency revoke (3.8 level 3), idempotent. In ONE transaction: the key becomes ``revoked`` (terminal), an
    append-only ``attest_revocations`` row is written, a ``key_compromise`` sets the estate hold (an admin must
    acknowledge it), every public bundle object except ``keys.json`` and ``revoked.json`` is switched off at once (fail
    safe: stop serving statements of that key before the new list is signed), the sealed secret is destroyed through
    the backend and an audit row is written. A pending replacement key is then created (an ``anchor`` replacement is
    activated at once: it needs no DNS; an ``attest`` replacement waits for DNS and an admin acknowledgement). Finally the
    revocation list is re-signed (callers push it first). A problem with the replacement, the backend's ``destroy`` or
    the list never undoes the revocation: it is reported in the result and retried by :func:`sweep` and
    ``revocation.resign_if_due``."""
    from . import revocation

    if reason not in revocation.REASONS:
        raise KeysError(f"reason must be one of {revocation.REASONS}", "keys.reason")
    t = await _clock(conn, now)
    tenant = await _tenant_of(conn)
    destroy_error: Optional[str] = None
    async with conn.transaction():
        row = await conn.fetchrow(
            f"SELECT {_COLUMNS} FROM attest_keys WHERE tenant_id = $1::uuid AND kid = $2 FOR UPDATE", tenant, kid)
        if row is None:
            raise KeyNotFound()
        rec = _record(tenant, row)
        if rec.status == "revoked":
            return RevokeResult(key=rec, already_revoked=True)
        await conn.execute(
            "UPDATE attest_keys SET status = 'revoked', revoked_at = $3 WHERE tenant_id = $1::uuid AND kid = $2",
            tenant, kid, _dt(t))
        await conn.execute(
            "INSERT INTO attest_revocations (tenant_id, kid, reason_code, revoked_at, actor, justification) "
            "VALUES ($1::uuid, $2, $3, $4, $5, $6) ON CONFLICT (tenant_id, kid) DO NOTHING",
            tenant, kid, reason, _dt(t), actor, justification)
        if reason == "key_compromise":
            await conn.execute(
                "UPDATE attest_estates SET hold_reason = 'key_compromise', hold_requires_ack = TRUE, hold_set_at = $2 "
                "WHERE tenant_id = $1::uuid", tenant, _dt(t))
            await _audit(conn, tenant, "attest.hold.set", kid, actor,
                         {"reason": "key_compromise", "requires_ack": True, "kid": kid}, justification)
            await conn.execute(
                "UPDATE attest_bundle_objects SET public = FALSE, updated_at = $2 WHERE tenant_id = $1::uuid AND public "
                "AND path NOT IN ('keys.json', 'revoked.json')", tenant, _dt(t))
        try:
            async with conn.transaction():              # a savepoint: a failing destroy never undoes the revocation
                await (backend or backend_for(rec.backend, pool)).destroy(rec.handle, conn=conn)
        except BackendError as exc:
            destroy_error = type(exc).__name__
            logger.error("attest_key_destroy_failed", extra={"kid": kid, "error": destroy_error})
        await _audit(conn, tenant, "attest.key.revoked", kid, actor,
                     {"kid": kid, "usage": rec.usage, "reason": reason, "was": rec.status,
                      "destroy_error": destroy_error}, justification)
    replacement, replacement_error = await _replace(conn, rec, platform=platform, backend=backend, pool=pool, now=t,
                                                    actor=actor)
    signed, list_error = None, None
    if resign:
        try:
            signed = await revocation.sign_list(conn, platform, now=t)
        except Exception as exc:  # noqa: BLE001 -- the revocation stands; the loop re-signs (resign_if_due)
            list_error = type(exc).__name__
            logger.error("attest_revocation_list_not_signed", extra={"kid": kid, "error": list_error})
    key = await get_key(conn, kid)
    assert key is not None
    return RevokeResult(key=key, replacement=replacement, replacement_error=replacement_error,
                        destroy_error=destroy_error, list=signed, list_error=list_error)


async def _replace(conn: Any, revoked: KeyRecord, *, platform: Any, backend: Any, pool: Any, now: int,
                   actor: str) -> tuple:
    """Make sure the usage has a successor after ``revoked`` is gone. Returns ``(record or None, error or None)``."""
    try:
        remaining = await list_keys(conn, revoked.usage, ("pending", "active"))
        pending = [k for k in remaining if k.status == "pending"]
        active = [k for k in remaining if k.status == "active"]
        successor = pending[0] if pending else None
        if successor is None and not active:
            successor = await create_key(conn, revoked.usage, platform=platform, backend=backend, pool=pool,
                                         created_by=actor, now=now)
        if successor is not None and revoked.usage == "anchor" and not active:
            successor = await activate(conn, successor.kid, platform=platform, backend=backend, pool=pool,
                                       actor=actor, now=now)
        return successor, None
    except Exception as exc:  # noqa: BLE001 -- the revocation stands; the operator creates the key later
        logger.error("attest_replacement_key_failed", extra={"usage": revoked.usage, "error": type(exc).__name__})
        return None, type(exc).__name__
