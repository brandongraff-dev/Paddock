"""KEK sealing of attestation key material (docs/ASSURANCE_P3.md 3.5, D17).

* The key encryption key is ``PADDOCK_ATTEST_KEK`` (or ``..._KEK_FILE``), 32 bytes, plus ``..._KEK_PREVIOUS`` (comma
  list) so a rotation can still open old blobs. It is deliberately not ``PADDOCK_SECRET_KEY`` and there is NO ephemeral
  development key: without a KEK nothing is sealed, so no key can be created (a key that vanishes on restart would
  publish a fingerprint nobody can sign for).
* Wrap key: ``HKDF-SHA256(KEK, salt="<tenant>|<kind>|<kid>", info=b"paddock-attest-key-wrap/v1")``. Cipher:
  AES-256-GCM with AAD ``paddock-attest-key/v1|<tenant>|<kind>|<kid>|<usage>|<alg>``. Blob:
  ``v1:<kek_id8>:<urlsafe-b64(nonce|ciphertext|tag)>``. Swapping a blob between tenants, kinds, kids, usages or
  algorithms therefore fails authentication.
* Nothing is cached: every call re-reads the settings, derives, uses and drops. ``unseal`` returns a ``bytearray`` that
  the caller wipes with :func:`zero` in a ``finally`` (best effort in CPython).
* This module and ``backend_local`` are the ONLY code that may name the sealed-secrets table (a lint test enforces it).
  The SQL helpers at the bottom are what the rest of the package (estate bootstrap, key lifecycle) calls.

Nothing in this file logs a plaintext, a KEK or a blob.
"""
from __future__ import annotations

import base64
import binascii
import hmac
import os
import re
import uuid
from hashlib import sha256
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .config import settings

VERSION = "v1"
_HKDF_INFO = b"paddock-attest-key-wrap/v1"
_AAD_PREFIX = "paddock-attest-key/v1"
_KEK_ID_CONTEXT = b"paddock-attest-kek-id/v1"
_NONCE_LEN = 12
_TAG_LEN = 16

#: kinds the wrap understands; the secrets TABLE only stores the first two (``disclosure`` blobs live in
#: ``attest_disclosures`` and are sealed with :func:`seal_raw`).
KINDS = frozenset({"signing", "commit", "disclosure"})
TABLE_KINDS = frozenset({"signing", "commit"})

_B64_BODY = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")
_KEK_ID = re.compile(r"^[0-9a-f]{8}$")
_COMPONENT_FORBIDDEN = re.compile(r"[|\x00-\x1f\x7f]")


class SealError(Exception):
    """Sealing or key configuration failed. The message never contains key material."""


class KekNotConfigured(SealError):
    """No KEK is configured: nothing can be sealed or opened (creation of keys is refused)."""


class UnsealError(SealError):
    """A blob is malformed, was sealed under a KEK we do not hold, or failed authentication (wrong tenant, kind, kid,
    usage, alg, or tampered)."""


# --------------------------------------------------------------------------- #
# KEK loading
# --------------------------------------------------------------------------- #

def _decode_kek(text: str, what: str) -> bytes:
    t = text.strip()
    if not t or not re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", t):
        raise SealError(f"{what} is not base64")
    t = t.replace("+", "-").replace("/", "_")
    t += "=" * (-len(t) % 4)
    try:
        raw = base64.urlsafe_b64decode(t)
    except (binascii.Error, ValueError):
        raise SealError(f"{what} is not base64") from None
    if len(raw) != 32:
        raise SealError(f"{what} must decode to exactly 32 bytes")
    if raw in (b"\x00" * 32, b"\xff" * 32):
        raise SealError(f"{what} is a placeholder, not a key")
    return raw


def _secret(value: Any) -> str:
    if value is None:
        return ""
    getter = getattr(value, "get_secret_value", None)
    return (getter() if getter else str(value)) or ""


def load_keks() -> list[bytes]:
    """Every configured KEK, primary first (empty list = none configured). A malformed value is an error, never skipped:
    silently ignoring a broken ``..._PREVIOUS`` entry would make old blobs unreadable without anyone noticing."""
    keks: list[bytes] = []
    primary = _secret(settings.kek).strip()
    path = (settings.kek_file or "").strip()
    if primary:
        keks.append(_decode_kek(primary, "PADDOCK_ATTEST_KEK"))
    elif path:
        try:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
        except OSError as exc:
            raise SealError(f"PADDOCK_ATTEST_KEK_FILE cannot be read ({type(exc).__name__})") from None
        keks.append(_decode_kek(text, "PADDOCK_ATTEST_KEK_FILE"))
    for part in _secret(settings.kek_previous).split(","):
        if part.strip():
            keks.append(_decode_kek(part, "PADDOCK_ATTEST_KEK_PREVIOUS"))
    if keks and not (primary or path):
        # only previous keys: sealing would have no primary. Treat as not configured.
        return []
    return keks


def kek_configured() -> bool:
    """True if a primary KEK is configured and well formed. Raises SealError if the configuration is broken."""
    return bool(load_keks())


def kek_id(kek: bytes) -> str:
    """8 hex characters naming a KEK inside a blob. A keyed MAC of a constant, not a plain hash of the key."""
    return hmac.new(kek, _KEK_ID_CONTEXT, sha256).hexdigest()[:8]


def _primary() -> bytes:
    keks = load_keks()
    if not keks:
        raise KekNotConfigured("PADDOCK_ATTEST_KEK is not configured")
    return keks[0]


# --------------------------------------------------------------------------- #
# Contexts
# --------------------------------------------------------------------------- #

def normalize_tenant(value: Any) -> str:
    """The canonical (lowercase, hyphenated) form of a tenant id; ``SealError`` if it is not a UUID."""
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, AttributeError, TypeError):
        raise SealError("tenant id is not a UUID") from None


def _component(value: Any, name: str) -> str:
    if (not isinstance(value, str) or not value or len(value) > 256 or not value.isascii()
            or _COMPONENT_FORBIDDEN.search(value)):
        raise SealError(f"{name} is empty, too long, not ASCII, or contains a separator or control character")
    return value


def _kind(value: Any) -> str:
    if value not in KINDS:
        raise SealError("unknown kind")
    return value


def wrap_salt(tenant_id: Any, kind: str, kid: str) -> str:
    return f"{normalize_tenant(tenant_id)}|{_kind(kind)}|{_component(kid, 'kid')}"


def wrap_aad(*, tenant_id: Any, kind: str, kid: str, usage: str, alg: str) -> bytes:
    return "|".join(
        (_AAD_PREFIX, normalize_tenant(tenant_id), _kind(kind), _component(kid, "kid"),
         _component(usage, "usage"), _component(alg, "alg"))
    ).encode("ascii")


# --------------------------------------------------------------------------- #
# Seal / unseal
# --------------------------------------------------------------------------- #

def _wrap_key(kek: bytes, salt: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt.encode("utf-8"), info=_HKDF_INFO).derive(kek)


def seal_raw(plaintext: bytes | bytearray, *, salt: str, aad: bytes) -> str:
    """Seal under the primary KEK with a caller-supplied HKDF salt and AAD (the building block; ``seal`` fixes both)."""
    kek = _primary()
    nonce = os.urandom(_NONCE_LEN)
    key = _wrap_key(kek, salt)
    ct = AESGCM(key).encrypt(nonce, bytes(plaintext), aad)
    return f"{VERSION}:{kek_id(kek)}:{base64.urlsafe_b64encode(nonce + ct).decode('ascii')}"


def _parse_blob(blob: Any) -> tuple[str, bytes, bytes]:
    if not isinstance(blob, str):
        raise UnsealError("sealed blob is not text")
    parts = blob.split(":")
    if len(parts) != 3 or parts[0] != VERSION or not _KEK_ID.match(parts[1]) or not _B64_BODY.match(parts[2]):
        raise UnsealError("sealed blob is malformed")
    try:
        raw = base64.urlsafe_b64decode(parts[2])
    except (binascii.Error, ValueError):
        raise UnsealError("sealed blob is malformed") from None
    if base64.urlsafe_b64encode(raw).decode("ascii") != parts[2] or len(raw) < _NONCE_LEN + _TAG_LEN:
        raise UnsealError("sealed blob is malformed")
    return parts[1], raw[:_NONCE_LEN], raw[_NONCE_LEN:]


def blob_kek_id(blob: str) -> str:
    """The KEK id a blob names (``UnsealError`` if it is not a blob)."""
    return _parse_blob(blob)[0]


def unseal_raw(blob: str, *, salt: str, aad: bytes) -> bytearray:
    kid8, nonce, ct = _parse_blob(blob)
    keks = load_keks()
    if not keks:
        raise KekNotConfigured("PADDOCK_ATTEST_KEK is not configured")
    for kek in keks:
        if kek_id(kek) != kid8:
            continue
        try:
            plain = AESGCM(_wrap_key(kek, salt)).decrypt(nonce, ct, aad)
        except InvalidTag:
            raise UnsealError("sealed blob failed authentication") from None
        out = bytearray(plain)
        return out
    raise UnsealError("no configured KEK can open this blob (rotated away?)")


def seal(plaintext: bytes | bytearray, *, tenant_id: Any, kind: str, kid: str, usage: str, alg: str) -> str:
    """Seal key material bound to (tenant, kind, kid, usage, alg)."""
    salt = wrap_salt(tenant_id, kind, kid)
    aad = wrap_aad(tenant_id=tenant_id, kind=kind, kid=kid, usage=usage, alg=alg)
    return seal_raw(plaintext, salt=salt, aad=aad)


def unseal(blob: str, *, tenant_id: Any, kind: str, kid: str, usage: str, alg: str) -> bytearray:
    """Open a blob for exactly this context. The caller wipes the result with :func:`zero`."""
    salt = wrap_salt(tenant_id, kind, kid)
    aad = wrap_aad(tenant_id=tenant_id, kind=kind, kid=kid, usage=usage, alg=alg)
    return unseal_raw(blob, salt=salt, aad=aad)


def needs_rewrap(blob: str) -> bool:
    """True when a blob is sealed under a KEK other than the current primary."""
    return blob_kek_id(blob) != kek_id(_primary())


def rewrap(blob: str, *, tenant_id: Any, kind: str, kid: str, usage: str, alg: str) -> str:
    """Open with any held KEK and seal again under the primary (KEK rotation)."""
    plain = unseal(blob, tenant_id=tenant_id, kind=kind, kid=kid, usage=usage, alg=alg)
    try:
        return seal(plain, tenant_id=tenant_id, kind=kind, kid=kid, usage=usage, alg=alg)
    finally:
        zero(plain)


def zero(buf: bytearray | None) -> None:
    """Best-effort wipe of a mutable buffer (CPython may have copied it; this narrows the window, no more)."""
    if buf is not None:
        for i in range(len(buf)):
            buf[i] = 0


# --------------------------------------------------------------------------- #
# The sealed-secrets table (attest_key_secrets): the only SQL on it outside backend_local
# --------------------------------------------------------------------------- #
#
# ``conn`` is an asyncpg connection. Every statement names the tenant explicitly in addition to row-level security:
# the tenant is part of the AAD, so a connection that is not stamped (a superuser test pool) must still never read or
# write another tenant's row.

def _table_kind(kind: str) -> str:
    if kind not in TABLE_KINDS:
        raise SealError("unknown kind for the secrets table")
    return kind


async def store_secret(conn: Any, *, plaintext: bytes | bytearray, tenant_id: Any, kind: str, kid: str,
                       usage: str, alg: str) -> bool:
    """Seal and insert. Returns False (and writes nothing) if a row for (tenant, kind, kid) already exists: a stored
    secret is never overwritten."""
    _table_kind(kind)
    sealed = seal(plaintext, tenant_id=tenant_id, kind=kind, kid=kid, usage=usage, alg=alg)
    row = await conn.fetchrow(
        "INSERT INTO attest_key_secrets (tenant_id, kind, kid, sealed, kek_id) VALUES ($1::uuid, $2, $3, $4, $5) "
        "ON CONFLICT (tenant_id, kind, kid) DO NOTHING RETURNING id",
        normalize_tenant(tenant_id), kind, kid, sealed, blob_kek_id(sealed),
    )
    return row is not None


async def load_secret(conn: Any, *, tenant_id: Any, kind: str, kid: str, usage: str, alg: str) -> bytearray | None:
    """Open the stored secret, or None if there is no row. Raises ``UnsealError`` if the row does not authenticate for
    this exact context."""
    _table_kind(kind)
    sealed = await conn.fetchval(
        "SELECT sealed FROM attest_key_secrets WHERE tenant_id = $1::uuid AND kind = $2 AND kid = $3",
        normalize_tenant(tenant_id), kind, kid,
    )
    if sealed is None:
        return None
    return unseal(sealed, tenant_id=tenant_id, kind=kind, kid=kid, usage=usage, alg=alg)


async def secret_exists(conn: Any, *, tenant_id: Any, kind: str, kid: str) -> bool:
    _table_kind(kind)
    return bool(await conn.fetchval(
        "SELECT EXISTS (SELECT 1 FROM attest_key_secrets WHERE tenant_id = $1::uuid AND kind = $2 AND kid = $3)",
        normalize_tenant(tenant_id), kind, kid,
    ))


async def delete_secret(conn: Any, *, tenant_id: Any, kind: str, kid: str) -> bool:
    """Crypto-erase: delete the only copy of the sealed material. Idempotent (False if there was nothing)."""
    _table_kind(kind)
    row = await conn.fetchrow(
        "DELETE FROM attest_key_secrets WHERE tenant_id = $1::uuid AND kind = $2 AND kid = $3 RETURNING id",
        normalize_tenant(tenant_id), kind, kid,
    )
    return row is not None
