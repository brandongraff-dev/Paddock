"""The ``KeyBackend`` contract (docs/ASSURANCE_P3.md 3.6, D18).

A backend creates keys, signs and destroys them. It has **no export surface**: nothing named export, private, dump or
secret exists on a backend or a handle, so the private key can never leave through this interface.

* ``alg``, ``custody`` and ``max_message_bytes`` are part of the contract (``None`` = unlimited). A backend that can only
  sign a bounded message (raw-message KMS products cap it) raises :class:`MessageTooLarge` instead of truncating.
* ``sign`` signs the **full signing input** it is given (the DSSE PAE); it never accepts a digest or builds the payload.
* ``BackendUnavailable`` (timeout, throttling, a missing KEK) must propagate: the issuer must not issue.
* ``KeyHandle`` carries identity only (backend, tenant, kid, usage, alg, key_ref). It never carries sealed material (a
  handle that did made ``destroy()`` a no-op in the design probe) and its ``repr`` leaks nothing.

Every method takes an optional keyword ``conn`` (an open database connection) so a caller can run the call inside its
own transaction (the issuer allocates ``seq`` and signs in one). Backends that do not use a database ignore it.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Protocol, runtime_checkable

Custody = Literal["hosted", "byok-kms", "byok-hsm"]


class BackendError(Exception):
    """Base class. The message never contains key material."""


class BackendUnavailable(BackendError):
    """Timeout, throttling, a database or KMS outage, a missing KEK. The caller must not issue; retry later."""


class KekNotConfigured(BackendUnavailable):
    """No attestation KEK is configured: hosted keys cannot be created or opened (there is no ephemeral dev key)."""


class BackendKeyDisabled(BackendError):
    """The key exists but is disabled or revoked: it must not sign."""


class MessageTooLarge(BackendError):
    """The message is over ``max_message_bytes`` for this backend."""


class UnsupportedAlgorithm(BackendError):
    """``alg`` is not in the backend's allow-list (the algorithm is never negotiated down)."""


class KeyNotFound(BackendError):
    """No key material exists for this handle (never generated, destroyed, or another tenant's)."""


@dataclass(frozen=True)
class KeyHandle:
    """Identity of a key held by a backend. Not a secret, not the key."""

    backend: str
    tenant_id: str
    kid: str
    usage: str
    alg: str
    key_ref: str = ""

    def __repr__(self) -> str:  # identity only, and not even the tenant id
        return f"KeyHandle(backend={self.backend!r}, kid={self.kid!r}, usage={self.usage!r}, alg={self.alg!r})"

    __str__ = __repr__


@dataclass(frozen=True)
class BackendHealth:
    """``state`` is one of ``ok``, ``disabled``, ``missing``, ``unusable`` (cannot be opened, e.g. a rotated-away KEK)
    or ``unavailable`` (the backend or its dependency is down). Only ``ok`` has ``ok=True``."""

    ok: bool
    state: str
    detail: str = ""


@runtime_checkable
class KeyBackend(Protocol):
    name: str
    custody: Custody
    algs: frozenset[str]
    max_message_bytes: int | None

    async def generate(self, tenant_id: Any, usage: str, alg: str, *, conn: Any = None) -> tuple[KeyHandle, bytes]:
        """Create a key. Returns (handle, raw public key). Refuses an alg outside ``algs``."""

    async def sign(self, h: KeyHandle, message: bytes, *, conn: Any = None) -> bytes:
        """Sign ``message`` (the full signing input) with the key ``h`` names."""

    async def destroy(self, h: KeyHandle, *, conn: Any = None) -> None:
        """Destroy the key material (crypto-erase). Idempotent. ``sign`` afterwards fails."""

    async def health(self, h: KeyHandle, *, conn: Any = None) -> BackendHealth:
        """Report whether ``h`` could sign right now. Never raises for an outage: it reports ``unavailable``."""
