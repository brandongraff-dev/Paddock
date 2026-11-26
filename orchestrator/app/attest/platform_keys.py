"""The platform issuer and revoker keys (docs/ASSURANCE_P3.md 3.1, D16).

Two online Ed25519 keys, certified offline by the attestation root (``scripts/attest_root_ceremony.py``):

* the **issuer** (usage ``issue-cert``) certifies each estate's ``attest`` and ``anchor`` keys,
* the **revoker** (usage ``revoke``) signs revocation lists; it can only deny.

Both live in PKCS8 PEM files encrypted with ``PADDOCK_ATTEST_PLATFORM_KEY_PASSPHRASE`` (``..._ISSUER_KEY_FILE`` and
``..._REVOKER_KEY_FILE``) next to their certificate files; the pinned trust roots come from
``PADDOCK_ATTEST_TRUST_ROOTS_FILE`` or, if unset, the verifier release's own ``trust_roots.json`` (empty in a source
build). A KMS handle is a stub. **Missing or unverifiable material means "not configured" and no estate key can be
created: there are no ephemeral keys.**

:func:`load` returns keys that were checked every time it is called: the private key matches its certificate, the
certificate has the right usage, chains to a pinned root and is valid *now*. Decrypting a key is the slow part, so the
decrypted key object is cached by a hash of the file bytes and the passphrase (a replaced file, a rotated passphrase
or a re-certified key is picked up at once); validity is never cached. The private key is held by a ``PlatformKey``
that offers ``sign`` only: no attribute exposes it, and ``repr`` shows identity alone.
"""
from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from paddock_verify import limits

from . import certs
from .config import settings

logger = logging.getLogger(__name__)

#: Redis key the vendor admin script sets and the attest loop polls (convenience kill; the env flag is authoritative)
GLOBAL_KILL_REDIS_KEY = "paddock:attest:issuing_killed"


class PlatformKeysError(Exception):
    """The platform key material is unusable. ``code`` is a spec reason code where one exists, else ``platform.*``."""

    def __init__(self, message: str, code: str = "platform.unusable") -> None:
        super().__init__(message)
        self.code = code


class PlatformNotConfigured(PlatformKeysError):
    """A file or the passphrase is not set (``missing`` names the gaps: ``issuer_key``, ``issuer_cert``,
    ``revoker_key``, ``revoker_cert``, ``passphrase``)."""

    def __init__(self, missing: tuple) -> None:
        super().__init__("the attestation platform keys are not configured: missing " + ", ".join(missing),
                         "platform.not_configured")
        self.missing = tuple(missing)


class PlatformKey:
    """One online platform key: identity, certificate and ``sign``. Nothing else is exposed."""

    def __init__(self, usage: str, cert: certs.Cert, signer: Ed25519PrivateKey) -> None:
        self.usage = usage
        self.cert = cert
        self.kid = cert.kid
        self.public_key = cert.public_key
        self._signer = signer

    def sign(self, message: bytes) -> bytes:
        """Ed25519 over ``message`` (the full signing input), verified under the certified public key before it is
        returned (a swapped key file or a fault never yields a signature that would not verify)."""
        if not isinstance(message, (bytes, bytearray)):
            raise TypeError("message must be bytes")
        sig = self._signer.sign(bytes(message))
        try:
            self._signer.public_key().verify(sig, bytes(message))
        except InvalidSignature:  # pragma: no cover - a library fault
            raise PlatformKeysError("the platform signature failed its self-check") from None
        return sig

    def __repr__(self) -> str:
        return f"PlatformKey(usage={self.usage!r}, kid={self.kid!r})"

    __str__ = __repr__


@dataclass(frozen=True)
class PlatformKeys:
    issuer: PlatformKey
    revoker: PlatformKey
    roots: tuple

    def __repr__(self) -> str:
        return f"PlatformKeys(issuer={self.issuer.kid!r}, revoker={self.revoker.kid!r}, roots={len(self.roots)})"


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #

_KEY_CACHE: dict = {}
_KEY_CACHE_MAX = 8


def reset_cache() -> None:
    """Forget decrypted keys (tests, and a deliberate reload after rotating the files)."""
    _KEY_CACHE.clear()


def _present(path: Optional[str]) -> bool:
    if not path or not path.strip():
        return False
    try:
        return os.path.isfile(path) and os.path.getsize(path) > 0
    except OSError:
        return False


def _read(path: str, what: str) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(limits.MAX_AUX_FILE_BYTES + 1)[: limits.MAX_AUX_FILE_BYTES]
    except OSError:
        raise PlatformKeysError(f"the {what} file cannot be read") from None


def _passphrase() -> Optional[bytes]:
    secret = settings.platform_key_passphrase
    value = secret.get_secret_value() if secret is not None else ""
    return value.encode("utf-8") if value else None


def load_roots() -> list:
    """The pinned trust roots: ``PADDOCK_ATTEST_TRUST_ROOTS_FILE``, else the verifier release's ``trust_roots.json``.
    None at all is ``config.no_trust_roots`` (a source build has none)."""
    path = settings.trust_roots_file
    try:
        if path and path.strip():
            raw: Optional[bytes] = _read(path, "trust roots")
        else:
            try:
                raw = limits.read_data("trust_roots.json")
            except OSError:
                raw = None
        roots = certs.parse_roots(raw) if raw is not None else []
    except certs.CertError as exc:
        raise PlatformKeysError(f"the trust roots are unusable: {exc.detail}", exc.code) from None
    if not roots:
        raise PlatformKeysError("no trust roots are configured (PADDOCK_ATTEST_TRUST_ROOTS_FILE)", "config.no_trust_roots")
    return roots


def _decrypt(path: str, passphrase: bytes, what: str) -> Ed25519PrivateKey:
    data = _read(path, what)
    digest = hashlib.sha256(b"paddock-attest-platform-key/v1\x00" + hashlib.sha256(data).digest()
                            + hashlib.sha256(passphrase).digest()).hexdigest()
    cached = _KEY_CACHE.get(digest)
    if cached is not None:
        return cached
    try:
        key = serialization.load_pem_private_key(data, password=passphrase)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        # a wrong passphrase, an unencrypted file (refused) or a damaged file: never say which, never echo the passphrase
        raise PlatformKeysError(f"the {what} key file cannot be opened (wrong passphrase, unencrypted or damaged)") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise PlatformKeysError(f"the {what} key is not an Ed25519 key", "sig.alg_unsupported")
    if len(_KEY_CACHE) >= _KEY_CACHE_MAX:
        _KEY_CACHE.clear()
    _KEY_CACHE[digest] = key
    return key


def _raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _load_one(usage: str, key_file: str, cert_file: str, passphrase: bytes, roots: list, now: int) -> PlatformKey:
    label = "issuer" if usage == "issue-cert" else "revoker"
    try:
        cert = certs.parse_cert(_read(cert_file, f"{label} certificate"))
    except certs.CertError as exc:
        raise PlatformKeysError(f"the {label} certificate is invalid: {exc.detail}", exc.code) from None
    if cert.usage != usage:
        raise PlatformKeysError(f"the {label} certificate has usage {cert.usage!r}, not {usage!r}",
                                "key.cert_subject_mismatch")
    key = _decrypt(key_file, passphrase, f"{label} key")
    if _raw_public(key) != cert.public_key:
        raise PlatformKeysError(f"the {label} private key does not match its certificate", "key.cert_subject_mismatch")
    pinned = next((r for r in roots if r.kid == cert.kid and r.usage == "issue-cert"), None)
    try:
        if usage == "issue-cert" and pinned is not None:
            # a self-hoster's pinned issuer (chain length 1): trusted by being pinned, window judged here
            if not (pinned.window_contains(now) and cert.window_contains(now)):
                raise certs.CertError("issuer.outside_validity", "the pinned issuer is not valid now")
        else:
            certs.verify_chain(cert, issuers=[], roots=roots, at=now, expect_usage=usage)
    except certs.CertError as exc:
        raise PlatformKeysError(f"the {label} certificate does not verify: {exc.detail}", exc.code) from None
    return PlatformKey(usage, cert, key)


def load(*, now: Any = None) -> PlatformKeys:
    """Load and verify the issuer and revoker at ``now`` (default: the host clock). Raises
    :class:`PlatformNotConfigured` when a file or the passphrase is unset or missing, and :class:`PlatformKeysError`
    for anything unusable (wrong passphrase, mismatch, unverifiable or expired certificate, no trust roots)."""
    when = certs.epoch_of(now)
    missing = []
    for gap, value in (("issuer_key", settings.issuer_key_file), ("issuer_cert", settings.issuer_cert_file),
                       ("revoker_key", settings.revoker_key_file), ("revoker_cert", settings.revoker_cert_file)):
        if not _present(value):
            missing.append(gap)
    passphrase = _passphrase()
    if passphrase is None:
        missing.append("passphrase")
    if missing:
        raise PlatformNotConfigured(tuple(missing))
    roots = load_roots()
    issuer = _load_one("issue-cert", settings.issuer_key_file, settings.issuer_cert_file, passphrase, roots, when)
    revoker = _load_one("revoke", settings.revoker_key_file, settings.revoker_cert_file, passphrase, roots, when)
    return PlatformKeys(issuer=issuer, revoker=revoker, roots=tuple(roots))
