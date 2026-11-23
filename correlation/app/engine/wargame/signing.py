"""Signing keys for closed-boundary certificates.

A certificate's fingerprint is an HMAC-SHA256 over its semantic fields
(:mod:`.certificate`). The fingerprint is only worth something if the key is
secret, so key handling lives here and mirrors the repo's audit-chain
convention (``orchestrator/app/audit.py``: ``AUDIT_HMAC_KEY`` /
``AUDIT_HMAC_KEY_FILE`` / ``AUDIT_HMAC_PREVIOUS_KEYS``):

* **Master key from the environment.** ``WARGAME_SIGNING_KEY`` (or
  ``WARGAME_SIGNING_KEY_FILE``, a docker secret / KMS-decrypted file) holds the
  master key; it never lives in the database. ``correlation/app/config.py``
  reads it; this module stays pure and takes the strings.
* **Rotation.** Retired masters go in ``WARGAME_SIGNING_PREVIOUS_KEYS``
  (comma/space separated). New certificates are signed with the current
  master; certificates signed with a retired one still verify.
* **Per-tenant keys.** A certificate is never signed with the master itself:
  the signing key is ``HMAC-SHA256(master, "paddock-wargame-cert/v1" || 0x00
  || tenant_id)`` (a single-block HKDF-Expand), so one tenant's certificate
  can't be verified under another tenant (or replayed as theirs) and the
  master is never exposed by a derived key.
* **Key id.** Each certificate records ``key_id`` = ``"wg1-"`` + the first 16
  hex chars of ``HMAC(master, "paddock-wargame-key-id/v1")`` (a public id, not
  the key), so verification picks the right master after rotation.

No key configured: certificates are still produced (so dev works), but they
are fingerprinted with the public :data:`DEMO_SIGNING_KEY`, carry
``key_id = "unsigned-dev"`` and an explicit ``unsigned_dev_signature``
assumption saying the fingerprint is not a signature. Never silently.

stdlib only.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

#: The public development key. Anyone can compute a fingerprint with it, so a
#: certificate carrying it is marked unsigned (see :data:`DEV_KEY_ID`).
DEMO_SIGNING_KEY = b"twin"

#: ``key_id`` of a certificate fingerprinted with :data:`DEMO_SIGNING_KEY`.
DEV_KEY_ID = "unsigned-dev"

#: ``key_id`` of a legacy certificate (signed before key ids existed). Those
#: were all fingerprinted with the demo key, so they are unsigned too.
LEGACY_KEY_ID = ""

KEY_ID_PREFIX = "wg1-"
_KID_LABEL = b"paddock-wargame-key-id/v1"
_DERIVE_LABEL = b"paddock-wargame-cert/v1"
_MIN_KEY_BYTES = 32


def key_id(master: bytes) -> str:
    """Public identifier of a master key (an HMAC of a constant, not the key)."""
    return KEY_ID_PREFIX + hmac.new(master, _KID_LABEL, hashlib.sha256).hexdigest()[:16]


def _norm_tenant(tenant_id: Optional[str]) -> str:
    tenant = (str(tenant_id) if tenant_id is not None else "").strip().lower()
    if not tenant:
        raise ValueError("a tenant id is required to derive a certificate signing key")
    return tenant


def derive_tenant_key(master: bytes, tenant_id: Optional[str]) -> bytes:
    """The per-tenant signing key derived from ``master`` (see module doc)."""
    tenant = _norm_tenant(tenant_id)
    return hmac.new(
        master, _DERIVE_LABEL + b"\x00" + tenant.encode("utf-8"), hashlib.sha256
    ).digest()


def is_unsigned_kid(kid: str) -> bool:
    """True for a key id whose fingerprint is not a real signature."""
    return kid in (DEV_KEY_ID, LEGACY_KEY_ID)


@dataclass(frozen=True)
class SigningKey:
    """The key a certificate is fingerprinted with, and how to label it."""

    kid: str
    key: bytes = field(repr=False)
    #: True: the public development key; the fingerprint proves nothing.
    unsigned: bool = False


@dataclass(frozen=True)
class Keyring:
    """The current master (``None`` = none configured) and retired masters."""

    current: Optional[bytes] = field(default=None, repr=False)
    previous: tuple[bytes, ...] = field(default=(), repr=False)

    @classmethod
    def from_strings(
        cls, current: Optional[str], previous: str = ""
    ) -> "Keyring":
        cur = (current or "").strip().encode("utf-8") or None
        if cur is not None and len(cur) < _MIN_KEY_BYTES:
            logger.warning(
                "WARGAME_SIGNING_KEY is shorter than %d bytes; use `openssl rand -hex 32`",
                _MIN_KEY_BYTES,
            )
        prev = tuple(
            p.encode("utf-8") for p in (previous or "").replace(",", " ").split()
        )
        return cls(current=cur, previous=prev)

    @property
    def configured(self) -> bool:
        return self.current is not None

    def signing_key(self, tenant_id: Optional[str]) -> SigningKey:
        """The key new certificates for ``tenant_id`` are signed with."""
        if self.current is None:
            return SigningKey(kid=DEV_KEY_ID, key=DEMO_SIGNING_KEY, unsigned=True)
        return SigningKey(
            kid=key_id(self.current),
            key=derive_tenant_key(self.current, tenant_id),
            unsigned=False,
        )

    def verification_key(self, kid: str, tenant_id: Optional[str]) -> Optional[bytes]:
        """The key to verify a certificate with ``kid`` for ``tenant_id``, or
        ``None`` when no configured master matches (a forged or foreign id)."""
        if not isinstance(kid, str) or not kid.isascii():
            return None  # compare_digest(str) raises on non-ASCII
        if is_unsigned_kid(kid):
            return DEMO_SIGNING_KEY
        for master in (self.current, *self.previous):
            if master is not None and hmac.compare_digest(key_id(master), kid):
                return derive_tenant_key(master, tenant_id)
        return None
