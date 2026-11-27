"""The signed revocation list ``revoked.json`` and supersession (docs/ASSURANCE_P3.md 3.4, D20).

One DSSE-signed list per estate (``payloadType`` ``application/vnd.paddock.revocation-list+json``), signed by the
platform **revoker** key (or the issuer key), re-signed at least daily even when unchanged::

    {"_type":"https://paddock.dev/revocation-list/v1","estate":"e_...","seq":42,"issued_at":"<T>","next_update":"<T+24h>",
     "revoked":[{"kid":"..","reason":"key_compromise"|"superseded"|"cessation","revoked_at":"<T>"}],
     "superseded":[{"subject":"dns:example.com","min_seq":1843,"at":"<T>"}]}

* ``key_compromise`` rejects **every** statement of that key whatever its claimed ``issued_at``; ``superseded`` and
  ``cessation`` reject only statements with ``issued_at >= revoked_at`` (older ones warn).
* ``superseded[]`` rejects statements of a subject with ``seq < min_seq``. It is signed on every downgrade flip and when
  the issuer loses the ability to evaluate (``min_seq = last_seq + 1``). One entry per subject, at most 11, and a
  subject's ``min_seq`` never goes down.
* The list's own ``seq`` increases by one per signing (the estate row is locked, so concurrent signers cannot repeat or
  skip one) and a verifier never accepts one below a cached copy. A list is **stale** once ``now > next_update + 48 h``:
  that is UNVERIFIABLE, never "accept" (it stops an attacker who controls the host from freezing an old list).

Everything byte-level is the verifier's own code (``paddock_verify``). The issuer verifies each list it signs with the
same rules a consumer applies before storing it, so a list that would not verify is never persisted.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Iterable, Optional

from paddock_verify import b64, canon, dsse, ed25519, limits, timefmt
from paddock_verify.jsonstrict import JsonError

from . import certs, platform_keys
from .estate import _tenant_of
from .keys import db_now

LIST_TYPE = "https://paddock.dev/revocation-list/v1"
ISSUER_LIST_TYPE = "https://paddock.dev/issuer-revocation-list/v1"
PAYLOAD_TYPE = dsse.PAYLOAD_TYPE_REVOCATION
REASONS = ("key_compromise", "superseded", "cessation")
MAX_SUPERSEDED = 11
MAX_REVOKED = 64          # entries in one list: what the open verifier reads
LIFETIME_S = 24 * 3600
RESIGN_AFTER_S = 6 * 3600
SKEW_S = limits.SKEW_SECONDS
STALE_GRACE_S = limits.REVOCATION_STALE_GRACE_SECONDS

_ESTATE = re.compile(r"e_[a-z2-7]{26}\Z", re.ASCII)
_KID = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_SUBJECT = re.compile(r"(?:dns:" + _LABEL + r"(?:\." + _LABEL + r")+|paddock-estate:e_[a-z2-7]{26})\Z", re.ASCII)
_DOC_KEYS = {"_type", "estate", "seq", "issued_at", "next_update", "revoked", "superseded"}


class RevocationError(Exception):
    """The list cannot be built, signed or verified. ``code`` is a spec reason code or ``revocation.*``."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class SignedList:
    envelope: bytes
    doc: dict
    seq: int


@dataclass(frozen=True)
class Revoked:
    reason: str
    revoked_at: int


@dataclass(frozen=True)
class RevocationList:
    """A verified list. ``key_status`` and ``superseded`` are the consumer-side rules of section 3.4."""

    estate: str
    seq: int
    issued_at: int
    next_update: int
    revoked: dict
    superseded_by_subject: dict
    signer_kid: str
    signer_usage: str

    def key_status(self, kid: str, statement_issued_at: int) -> Optional[str]:
        """``key.revoked`` (reject), ``key.revoked_superseded`` (warn) or ``None``."""
        r = self.revoked.get(kid)
        if r is None:
            return None
        if r.reason == "key_compromise" or statement_issued_at >= r.revoked_at:
            return "key.revoked"
        return "key.revoked_superseded"

    def min_seq(self, subject: str) -> Optional[int]:
        entry = self.superseded_by_subject.get(subject)
        return entry[0] if entry else None

    def is_superseded(self, subject: str, seq: int) -> bool:
        m = self.min_seq(subject)
        return m is not None and seq < m


# --------------------------------------------------------------------------- #
# Verification (what a consumer does; the issuer runs it on its own output)
# --------------------------------------------------------------------------- #

def _bad(detail: str) -> RevocationError:
    return RevocationError("revocation.unverifiable", detail)


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _time(v: Any, what: str) -> int:
    try:
        return timefmt.parse(v)
    except JsonError:
        raise _bad(f"{what} is not a YYYY-MM-DDTHH:MM:SSZ instant") from None


def verify_list(envelope: Any, *, issuers: Iterable = (), revoker: Any = None, roots: Iterable, estate: str, now: int,
                cached_seq: Optional[int] = None, revoked_issuers: Iterable = ()) -> RevocationList:
    """Verify a revocation list. ``issuers`` and ``revoker`` are certificate envelopes (from ``keys.json``); the signer
    must be one of them (usage ``revoke`` or ``issue-cert``) and chain to a pinned root, valid at the list's own
    ``issued_at``. Raises ``RevocationError`` with ``revocation.unverifiable`` or ``revocation.stale``."""
    try:
        data = certs._as_bytes(envelope)
    except certs.CertError:
        raise _bad("the list is not an envelope") from None
    try:
        env = dsse.parse_envelope(data, expected_type=PAYLOAD_TYPE)
        doc = canon.roundtrip(env.payload)
    except JsonError as exc:
        raise _bad(f"the list is not a strict canonical DSSE envelope ({exc.code})") from None
    if not isinstance(doc, dict) or set(doc) != _DOC_KEYS or doc["_type"] != LIST_TYPE:
        raise _bad("the list has the wrong shape")
    if doc["estate"] != estate or not isinstance(doc["estate"], str) or not _ESTATE.match(doc["estate"]):
        raise _bad("the list belongs to another estate")
    if not _is_int(doc["seq"]) or doc["seq"] < 1:
        raise _bad("seq is a positive integer")
    issued_at, next_update = _time(doc["issued_at"], "issued_at"), _time(doc["next_update"], "next_update")
    if not issued_at < next_update <= issued_at + limits.MAX_TTL_SECONDS:
        raise _bad("next_update is not after issued_at (or is too far)")
    if not isinstance(doc["revoked"], list) or not isinstance(doc["superseded"], list):
        raise _bad("revoked and superseded are lists")
    revoked: dict = {}
    if len(doc["revoked"]) > MAX_REVOKED:
        raise _bad(f"more than {MAX_REVOKED} revoked keys")
    for item in doc["revoked"]:
        if not isinstance(item, dict) or set(item) != {"kid", "reason", "revoked_at"}:
            raise _bad("a revoked entry has exactly kid, reason and revoked_at")
        if not isinstance(item["kid"], str) or not _KID.match(item["kid"]) or item["reason"] not in REASONS:
            raise _bad("a revoked entry has a bad kid or reason")
        if item["kid"] in revoked:
            raise _bad("a kid is listed twice")
        revoked[item["kid"]] = Revoked(item["reason"], _time(item["revoked_at"], "revoked_at"))
    superseded: dict = {}
    if len(doc["superseded"]) > MAX_SUPERSEDED:
        raise _bad(f"more than {MAX_SUPERSEDED} superseded subjects")
    for item in doc["superseded"]:
        if not isinstance(item, dict) or set(item) != {"subject", "min_seq", "at"}:
            raise _bad("a superseded entry has exactly subject, min_seq and at")
        if not isinstance(item["subject"], str) or not _SUBJECT.match(item["subject"]) or len(item["subject"]) > 260:
            raise _bad("a superseded entry has a bad subject")
        if not _is_int(item["min_seq"]) or not 1 <= item["min_seq"] <= limits.MAX_INT:
            raise _bad("min_seq is a positive integer")
        if item["subject"] in superseded:
            raise _bad("a subject is listed twice")
        superseded[item["subject"]] = (item["min_seq"], _time(item["at"], "at"))

    candidates = list(issuers) + ([revoker] if revoker is not None else [])
    signer = None
    for c in candidates:
        try:
            cert = c if isinstance(c, certs.Cert) else certs.parse_cert(c)
        except certs.CertError:
            continue
        if cert.kid == env.keyid:
            signer = cert
            break
    if signer is None:
        raise _bad("the list is signed by a key that is not a listed revoker or issuer")
    if signer.usage not in ("revoke", "issue-cert"):
        raise _bad("the signing certificate is neither a revoker nor an issuer")
    try:
        certs.verify_chain(signer, issuers=candidates, roots=roots, at=issued_at, revoked_issuers=revoked_issuers)
    except certs.CertError as exc:
        raise _bad(f"the signer's certificate does not verify ({exc.code})") from None
    code = ed25519.verify_code(signer.public_key, dsse.pae(env.payload_type, env.payload), env.sig)
    if code is not None:
        raise _bad(f"the signature does not verify ({code})")

    if issued_at > now + SKEW_S:
        raise _bad("the list is issued in the future")
    if now > next_update + STALE_GRACE_S:
        raise RevocationError("revocation.stale", "the list is older than next_update plus 48 hours")
    if cached_seq is not None and doc["seq"] < cached_seq:
        raise _bad("the list's seq is lower than a copy seen before")
    return RevocationList(estate=doc["estate"], seq=doc["seq"], issued_at=issued_at, next_update=next_update,
                          revoked=revoked, superseded_by_subject=superseded, signer_kid=signer.kid,
                          signer_usage=signer.usage)


def verify_issuer_revocations(data: Any, roots: Iterable, *, now: Optional[int] = None) -> dict:
    """The root-signed issuer revocation list that ships with a verifier release (3.8 level 5, ``issuer.revoked``):
    a DSSE envelope signed by a pinned ``root`` with payload ``{"_type":".../issuer-revocation-list/v1","issued_at",
    "revoked":[{"kid","reason","revoked_at"}],"seq"}``. Returns ``{kid: Revoked}``. Raises ``RevocationError``."""
    try:
        env = dsse.parse_envelope(certs._as_bytes(data), expected_type=PAYLOAD_TYPE)
        doc = canon.roundtrip(env.payload)
    except (JsonError, certs.CertError) as exc:
        raise _bad(f"the issuer revocation list is not a strict canonical DSSE envelope ({getattr(exc, 'code', '')})") from None
    if not isinstance(doc, dict) or set(doc) != {"_type", "issued_at", "revoked", "seq"} or doc["_type"] != ISSUER_LIST_TYPE \
            or not isinstance(doc["revoked"], list) or not _is_int(doc["seq"]) or doc["seq"] < 1:
        raise _bad("the issuer revocation list has the wrong shape")
    issued = _time(doc["issued_at"], "issued_at")
    root = next((r for r in roots if r.kid == env.keyid and r.usage == "root"), None)
    if root is None:
        raise _bad("the issuer revocation list is not signed by a pinned root")
    if ed25519.verify_code(root.public_key, dsse.pae(env.payload_type, env.payload), env.sig) is not None:
        raise _bad("the issuer revocation list signature does not verify")
    if now is not None and not root.window_contains(now):
        raise _bad("the signing root is not valid now")
    out: dict = {}
    for item in doc["revoked"]:
        if not isinstance(item, dict) or set(item) != {"kid", "reason", "revoked_at"} \
                or not isinstance(item["kid"], str) or not _KID.match(item["kid"]) or item["reason"] not in REASONS \
                or item["kid"] in out:
            raise _bad("a revoked issuer entry is malformed")
        out[item["kid"]] = Revoked(item["reason"], _time(item["revoked_at"], "revoked_at"))
    if issued < root.not_before:
        raise _bad("the list predates the root")
    return out


# --------------------------------------------------------------------------- #
# Signing (the issuer side)
# --------------------------------------------------------------------------- #

_ROW = ("SELECT estate_id, revocation_seq, revocation_doc, revocation_signed_at FROM attest_estates "
        "WHERE tenant_id = $1::uuid")


def _stored(raw: Any) -> dict:
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return {}
    return raw if isinstance(raw, dict) else {}


async def _live_subjects(conn: Any, tenant: str, estate_id: str) -> set:
    rows = await conn.fetch(
        "SELECT subject_kind, domain FROM attest_publications WHERE tenant_id = $1::uuid AND archived_at IS NULL", tenant)
    return {(f"paddock-estate:{estate_id}" if r["subject_kind"] == "estate" else f"dns:{r['domain']}") for r in rows}


async def _revoked_entries(conn: Any, tenant: str) -> list:
    rows = await conn.fetch(
        "SELECT kid, reason_code, revoked_at FROM attest_revocations WHERE tenant_id = $1::uuid "
        "ORDER BY revoked_at, kid", tenant)
    return [{"kid": r["kid"], "reason": r["reason_code"], "revoked_at": timefmt.format(int(r["revoked_at"].timestamp()))}
            for r in rows]


async def _build(conn: Any, platform: Any, *, now: Any, signer: str, extra: dict) -> Optional[SignedList]:
    """Sign a new list inside the caller's transaction. ``extra`` maps subject -> min_seq to merge in."""
    t = await db_now(conn) if now is None else certs.epoch_of(now)
    tenant = await _tenant_of(conn)
    row = await conn.fetchrow(_ROW + " FOR UPDATE", tenant)
    if row is None or not row["estate_id"]:
        raise RevocationError("revocation.no_estate", "this tenant has no estate yet")
    estate_id = row["estate_id"]
    stored = _stored(row["revocation_doc"])
    previous = {e["subject"]: e for e in stored.get("superseded", []) if isinstance(e, dict)}
    merged = {s: dict(e) for s, e in previous.items()}
    changed = False
    for subject, min_seq in extra.items():
        cur = merged.get(subject)
        if cur is None or min_seq > cur["min_seq"]:
            merged[subject] = {"subject": subject, "min_seq": min_seq, "at": timefmt.format(t)}
            changed = True
    if not changed and extra:
        return None                                         # nothing new to say: the current list stands
    if len(merged) > MAX_SUPERSEDED:
        live = await _live_subjects(conn, tenant, estate_id)
        for subject in sorted(merged, key=lambda s: merged[s]["at"]):
            if len(merged) <= MAX_SUPERSEDED:
                break
            if subject not in live and subject not in extra:
                del merged[subject]                          # the subject has no live publication left
        if len(merged) > MAX_SUPERSEDED:
            raise RevocationError("revocation.too_many_subjects", f"more than {MAX_SUPERSEDED} live superseded subjects")
    issued_at = max(t, int(stored.get("issued_at", 0)))
    seq = int(row["revocation_seq"]) + 1
    revoked = await _revoked_entries(conn, tenant)
    if len(revoked) > MAX_REVOKED:
        raise RevocationError("revocation.too_many_revoked", f"more than {MAX_REVOKED} revoked keys: a new estate is needed")
    doc = {
        "_type": LIST_TYPE, "estate": estate_id, "seq": seq, "issued_at": timefmt.format(issued_at),
        "next_update": timefmt.format(issued_at + LIFETIME_S), "revoked": revoked,
        "superseded": sorted(merged.values(), key=lambda e: e["subject"]),
    }
    try:
        payload = canon.dumps(doc)
    except JsonError as exc:
        raise RevocationError("revocation.unverifiable", f"the list is not PCJ-encodable ({exc.code})") from None
    if len(payload) > limits.MAX_AUX_FILE_BYTES:
        raise RevocationError("revocation.too_large", "the revocation list is over the size limit")
    key = platform.issuer if signer == "issuer" else platform.revoker
    sig = key.sign(dsse.pae(PAYLOAD_TYPE, payload))
    envelope = dsse.build_envelope(PAYLOAD_TYPE, payload, key.kid, sig)
    # the same rules a consumer applies: a list that would not verify is never stored
    verify_list(envelope, issuers=[platform.issuer.cert], revoker=platform.revoker.cert, roots=platform.roots,
                estate=estate_id, now=issued_at)
    await conn.execute(
        "UPDATE attest_estates SET revocation_seq = $2, revocation_doc = $3::jsonb, revocation_signed_at = $4 "
        "WHERE tenant_id = $1::uuid", tenant, seq,
        json.dumps({"envelope": envelope.decode("ascii"), "superseded": doc["superseded"], "issued_at": issued_at}),
        _dt(issued_at))
    from .. import audit as audit_svc   # lazy: audit pulls in the whole app

    await audit_svc.record(
        None, action="attest.revocation.signed", actor="system", actor_role="system", resource_type="attest_estate",
        resource_id=estate_id, con=conn, tenant_id=tenant,
        details={"seq": seq, "estate": estate_id, "revoked": len(doc["revoked"]), "superseded": len(doc["superseded"]),
                 "signer": key.kid})
    return SignedList(envelope=envelope, doc=doc, seq=seq)


def _dt(epoch: int):
    from datetime import datetime, timezone

    return datetime.fromtimestamp(epoch, timezone.utc)


async def sign_list(conn: Any, platform: Any = None, *, now: Any = None, signer: str = "revoker") -> SignedList:
    """Sign (and store) the next list: ``seq`` + 1, every revocation of this tenant, the stored supersessions, a fresh
    24 h ``next_update``. ``signer`` is ``revoker`` (default) or ``issuer``. Raises ``RevocationError`` /
    ``platform_keys.PlatformKeysError``; on any failure nothing is stored and ``seq`` does not move."""
    if signer not in ("revoker", "issuer"):
        raise RevocationError("revocation.signer", "signer is 'revoker' or 'issuer'")
    when = await db_now(conn) if now is None else certs.epoch_of(now)
    platform = platform or platform_keys.load(now=when)
    async with conn.transaction():
        out = await _build(conn, platform, now=when, signer=signer, extra={})
    assert out is not None
    return out


async def supersede(conn: Any, subject: str, min_seq: int, *, platform: Any = None, now: Any = None,
                    signer: str = "revoker") -> Optional[SignedList]:
    """Record "statements of ``subject`` with ``seq < min_seq`` are superseded" and sign a new list at once (3.4, 5.5).
    ``min_seq`` only ever increases per subject: a call that adds nothing returns ``None`` and signs nothing."""
    if not isinstance(subject, str) or not _SUBJECT.match(subject) or len(subject) > 260:
        raise RevocationError("revocation.subject", "not a dns: or paddock-estate: subject")
    if not _is_int(min_seq) or not 1 <= min_seq <= limits.MAX_INT:
        raise RevocationError("revocation.min_seq", "min_seq is a positive integer")
    when = await db_now(conn) if now is None else certs.epoch_of(now)
    platform = platform or platform_keys.load(now=when)
    async with conn.transaction():
        return await _build(conn, platform, now=when, signer=signer, extra={subject: min_seq})


async def current_list(conn: Any) -> Optional[SignedList]:
    """The last signed list of this tenant, byte for byte, or ``None``."""
    tenant = await _tenant_of(conn)
    row = await conn.fetchrow(_ROW, tenant)
    if row is None or not row["estate_id"]:
        return None
    env = _stored(row["revocation_doc"]).get("envelope")
    if not env:
        return None
    data = env.encode("ascii")
    parsed = dsse.parse_envelope(data, expected_type=PAYLOAD_TYPE)
    return SignedList(envelope=data, doc=json.loads(parsed.payload), seq=int(row["revocation_seq"]))


async def resign_if_due(conn: Any, platform: Any = None, *, now: Any = None,
                        max_age_s: int = RESIGN_AFTER_S) -> Optional[SignedList]:
    """Re-sign when there is no list yet, the list is older than ``max_age_s`` (the list must be re-signed at least
    daily; the default re-signs every 6 hours so a missed tick never lets it go stale) or a revocation was recorded
    that the list does not carry yet. Returns the new list or ``None``."""
    when = await db_now(conn) if now is None else certs.epoch_of(now)
    tenant = await _tenant_of(conn)
    row = await conn.fetchrow(_ROW, tenant)
    if row is None or not row["estate_id"]:
        return None
    cur = await current_list(conn)
    if cur is None or when - int(_stored(row["revocation_doc"]).get("issued_at", 0)) >= max_age_s:
        return await sign_list(conn, platform, now=when)
    listed = {e["kid"] for e in cur.doc["revoked"]}
    kids = {r["kid"] for r in await conn.fetch("SELECT kid FROM attest_revocations WHERE tenant_id = $1::uuid", tenant)}
    if kids - listed:
        return await sign_list(conn, platform, now=when)
    return None
