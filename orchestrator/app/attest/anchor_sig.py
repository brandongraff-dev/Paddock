"""Audit anchor v2: the Ed25519 signing hook, the public anchor document and the status check
(docs/ASSURANCE_P3.md 3.7, D15, spec Appendix B).

An audit anchor ``(tenant, max_id, head, hash_alg, ts)`` is published to an append-only sink, HMAC-signed with a key that
never leaves the orchestrator. v2 adds a **detached** list ``Anchor.sigs`` so an outsider can attribute and order anchors
without learning anything private::

    {"v":2,"alg":"ed25519","kid":"<32 hex>","estate":"e_...","at":"<T>","sig":"<b64>"}

The signature is Ed25519 by the estate's ``anchor`` key over ``b"paddock-anchor/v2\\n" + PCJ(public document without
sig)`` where the public document is ``{"alg","at","estate","hash_alg","head","kid","max_id","v":2}`` (``at`` = ``ts``
floored to whole seconds, ``hash_alg`` the family only, ``estate`` instead of the tenant id). That context shares no
prefix with ``DSSEv1 ``, so an anchor signature can never verify as a statement, certificate or list signature.

* **Signing is best effort** (D15): :func:`sign_hook` (registered in ``audit.ANCHOR_SIGNERS``) enters the anchor's tenant
  context itself, signs with the estate's active ``anchor`` key through its backend, stores the public document in
  ``attest_anchors`` and sets ``attest_estates.anchor_v2_since`` (sticky). On ANY failure it attaches nothing and the
  legacy-only anchor is published: anchoring never depends on attestation infrastructure or a customer KMS. The anchor key
  is always hosted.
* **No silent downgrade** (:func:`anchor_sig_status`, called by ``audit.verify``): with ``sigs`` present every listed
  signature from a known key must verify under the pinned vendor chain (the certificate is verified with
  ``certs.verify_chain``, never trusted from the database row) and at least one must be from a known key; with ``sigs``
  absent the anchor is accepted only while ``AUDIT_ANCHOR_ALLOW_LEGACY`` is true (default) AND the estate has never
  published a v2 anchor. The environment flag lives outside the database, so a database writer cannot undo it.
"""
from __future__ import annotations

import hashlib
import logging
import re
from datetime import datetime, timezone
from typing import Any, Optional

from paddock_verify import b64, canon, ed25519
from paddock_verify.jsonstrict import JsonError

from .. import audit, tenancy
from ..audit_anchor import Anchor
from . import certs, estate, keys, platform_keys
from .estate import _tenant_of

logger = logging.getLogger(__name__)

CONTEXT = b"paddock-anchor/v2\n"
ENTRY_KEYS = {"v", "alg", "kid", "estate", "at", "sig"}
_KID = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)


# --------------------------------------------------------------------------- #
# The public document
# --------------------------------------------------------------------------- #

def signing_input(doc_without_sig: dict) -> bytes:
    """What the anchor key signs: the context plus the PCJ encoding of the document without ``sig``."""
    return CONTEXT + canon.dumps({k: v for k, v in doc_without_sig.items() if k != "sig"})


def public_doc(anchor: Anchor, sig_entry: Optional[dict] = None, *, estate: Optional[str] = None) -> dict:
    """The public anchor document for ``anchor``, including ``sig`` (from ``sig_entry`` or the anchor's first v2
    entry). ``estate`` overrides the entry's estate id."""
    entry = sig_entry
    if entry is None:
        entry = next((e for e in (anchor.sigs or []) if isinstance(e, dict) and e.get("v") == 2 and e.get("sig")), None)
    if entry is None:
        raise ValueError("the anchor carries no v2 signature")
    return anchor.to_public(estate or entry["estate"], entry["kid"], sig=entry["sig"])


def public_bytes(doc: dict) -> bytes:
    """The PCJ bytes of a public document (what the bundle serves as ``anchors/<max_id>.json``)."""
    return canon.dumps(doc)


def public_digest(doc: dict) -> str:
    """``audit_anchor.digest`` of a statement: ``sha256:`` of the PCJ of the document INCLUDING ``sig``."""
    return "sha256:" + hashlib.sha256(public_bytes(doc)).hexdigest()


async def latest_public(conn: Any) -> Optional[dict]:
    """The tenant's newest stored public anchor document (highest ``max_id``, then latest ``at``), or ``None``."""
    import json

    tenant = await _tenant_of(conn)
    raw = await conn.fetchval(
        "SELECT doc::text FROM attest_anchors WHERE tenant_id = $1::uuid ORDER BY max_id DESC, at DESC LIMIT 1", tenant)
    return json.loads(raw) if raw else None


# --------------------------------------------------------------------------- #
# Signing
# --------------------------------------------------------------------------- #

def _at(moment: str) -> datetime:
    text = moment[:-1] + "+00:00" if moment.endswith("Z") else moment
    d = datetime.fromisoformat(text)
    return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)


async def _sign(pool: Any, anchor: Anchor) -> None:
    tenant = anchor.tenant_id
    with tenancy.tenant_context(tenant):
        async with pool.acquire() as con:
            info = await estate.get_estate(con)
            if info is None:
                return
            now = await keys.db_now(con)
            key = await keys.active_key(con, "anchor", now=now)
            if key is None:
                logger.info("attest_anchor_no_active_key", extra={"tenant_id": tenant})
                return
            doc = anchor.to_public(info.estate_id, key.kid)
            sig = await keys.backend_for(key.backend, pool).sign(key.handle, signing_input(doc), conn=con)
            if not ed25519.verify(key.public_key, signing_input(doc), sig):
                raise RuntimeError("the anchor signature failed its self-check")
            doc["sig"] = b64.encode(sig)
            at = _at(anchor.ts)
            async with con.transaction():
                import json

                await con.execute(
                    "INSERT INTO attest_anchors (tenant_id, max_id, at, doc) VALUES ($1::uuid, $2, $3, $4::jsonb) "
                    "ON CONFLICT (tenant_id, max_id, at) DO NOTHING", tenant, anchor.max_id, at, json.dumps(doc, sort_keys=True))
                await con.execute(
                    "UPDATE attest_estates SET anchor_v2_since = COALESCE(anchor_v2_since, $2) WHERE tenant_id = $1::uuid",
                    tenant, anchor.max_id)
    # attached only after the document is stored: a signature the statement could not cite is never published
    anchor.sigs = [{"v": 2, "alg": "ed25519", "kid": key.kid, "estate": info.estate_id, "at": doc["at"], "sig": doc["sig"]}]


async def sign_hook(pool: Any, anchor: Anchor) -> None:
    """The ``audit.ANCHOR_SIGNERS`` entry. Never raises for anything but cancellation: a failure of any kind (no estate,
    no key, an expired certificate, a backend or KEK outage, a database error) leaves ``anchor.sigs`` unset so the
    legacy-only anchor is published."""
    try:
        await _sign(pool, anchor)
    except Exception as exc:  # noqa: BLE001 -- best effort by contract
        anchor.sigs = None
        logger.warning("attest_anchor_not_signed", extra={"tenant_id": anchor.tenant_id, "error": type(exc).__name__})


def register() -> None:
    """Add :func:`sign_hook` to ``audit.ANCHOR_SIGNERS`` (idempotent)."""
    if sign_hook not in audit.ANCHOR_SIGNERS:
        audit.ANCHOR_SIGNERS.append(sign_hook)


# --------------------------------------------------------------------------- #
# Verification (audit.verify)
# --------------------------------------------------------------------------- #

#: Each listed signature costs a database lookup and a verification: a hostile sink line must not choose that bill.
MAX_SIGS = 8


def _shape_ok(entry: Any) -> bool:
    return (isinstance(entry, dict) and set(entry) == ENTRY_KEYS and entry["v"] == 2 and not isinstance(entry["v"], bool)
            and entry["alg"] == "ed25519" and isinstance(entry["kid"], str) and bool(_KID.match(entry["kid"]))
            and isinstance(entry["estate"], str) and isinstance(entry["at"], str) and isinstance(entry["sig"], str))


async def anchor_sig_status(pool: Any, anchor: Anchor, *, tenant_id: Optional[str] = None) -> str:
    """``ok`` | ``downgrade`` | ``bad_signature`` | ``unknown_key``. Anything but ``ok`` fails ``audit.verify`` closed."""
    tenant = str(tenant_id or anchor.tenant_id)
    if anchor.sigs is None:
        return await audit.legacy_anchor_status(pool, tenant)
    if not isinstance(anchor.sigs, list) or not 0 < len(anchor.sigs) <= MAX_SIGS or not all(_shape_ok(e) for e in anchor.sigs):
        return "bad_signature"
    try:
        roots = platform_keys.load_roots()
        issuers = platform_keys.issuer_certificates()
    except platform_keys.PlatformKeysError:
        return "bad_signature"                               # no pinned roots: nothing can be verified
    with tenancy.tenant_context(tenant):
        async with pool.acquire() as con:
            info = await estate.get_estate(con)
            if info is None:
                return "unknown_key"
            known = 0
            for entry in anchor.sigs:
                row = await con.fetchrow(
                    "SELECT usage, status, cert FROM attest_keys WHERE tenant_id = $1::uuid AND kid = $2",
                    tenant, entry["kid"])
                if row is None:
                    continue                                 # a key this estate does not know: ignored, but see below
                known += 1
                if entry["estate"] != info.estate_id:
                    return "bad_signature"
                if not await _entry_valid(con, tenant, anchor, entry, row, info.estate_id, roots, issuers):
                    return "bad_signature"
    return "ok" if known else "unknown_key"


async def _entry_valid(con: Any, tenant: str, anchor: Anchor, entry: dict, row: Any, estate_id: str, roots: list,
                       issuers: list) -> bool:
    import json

    try:
        at = _at(anchor.ts)
        if entry["at"] != at.strftime("%Y-%m-%dT%H:%M:%SZ"):
            return False
        at_epoch = int(at.timestamp())
        raw = row["cert"]
        cert = certs.parse_cert(json.loads(raw) if isinstance(raw, str) else raw)
        if cert.kid != entry["kid"] or row["usage"] != "anchor":
            return False
        # the certificate, not the row, is authoritative: chain to a pinned root, usage anchor, this estate, valid at `at`
        certs.verify_chain(cert, issuers=issuers, roots=roots, at=at_epoch, expect_usage="anchor", expect_estate=estate_id)
        revoked = await con.fetchrow(
            "SELECT reason_code, revoked_at FROM attest_revocations WHERE tenant_id = $1::uuid AND kid = $2", tenant, entry["kid"])
        if revoked is not None:
            if revoked["reason_code"] == "key_compromise" or at_epoch >= int(revoked["revoked_at"].timestamp()):
                return False
        elif row["status"] == "revoked":
            return False                                     # revoked without a ledger row: fail closed
        signature = b64.strict_decode(entry["sig"])
        message = signing_input(anchor.to_public(estate_id, entry["kid"]))
        return ed25519.verify(cert.public_key, message, signature)
    except (certs.CertError, JsonError, ValueError, TypeError, KeyError):
        return False


async def unsign(pool: Any, anchor: Anchor) -> None:
    """Called by ``audit.anchor_head`` when ``sink.publish`` failed and the sink does not hold this anchor: forget the
    signature that was never published. The stored public document goes, and ``anchor_v2_since`` returns to NULL only if
    this anchor was what set it and no other document remains (the estate has published no v2 anchor, so the legacy
    rule must not lock out its older legacy anchors). Never raises: if this fails the flag stays set, which fails closed."""
    try:
        if not anchor.sigs:
            return
        tenant = anchor.tenant_id
        at = _at(anchor.ts)
        with tenancy.tenant_context(tenant):
            async with pool.acquire() as con:
                async with con.transaction():
                    await con.fetchval("SELECT 1 FROM attest_estates WHERE tenant_id = $1::uuid FOR UPDATE", tenant)
                    await con.execute(
                        "DELETE FROM attest_anchors WHERE tenant_id = $1::uuid AND max_id = $2 AND at = $3",
                        tenant, anchor.max_id, at)
                    left = await con.fetchval("SELECT count(*) FROM attest_anchors WHERE tenant_id = $1::uuid", tenant)
                    if not left:
                        await con.execute(
                            "UPDATE attest_estates SET anchor_v2_since = NULL WHERE tenant_id = $1::uuid "
                            "AND anchor_v2_since = $2", tenant, anchor.max_id)
    except Exception as exc:  # noqa: BLE001 -- fail closed: the flag simply stays
        logger.warning("attest_anchor_unsign_failed", extra={"tenant_id": anchor.tenant_id, "error": type(exc).__name__})


sign_hook.unsign = unsign   # type: ignore[attr-defined]
