"""``LocalAesGcmBackend``: hosted custody (docs/ASSURANCE_P3.md 3.5, D17, D18).

Ed25519 seeds are generated here, sealed under the attestation KEK (``attest.crypto``) and stored in the sealed-secrets
table (this file and ``crypto.py`` are the only code that may name it). Properties the contract suite pins:

* ``sign`` unseals the seed, **re-derives the public key and checks the kid**, signs, **verifies its own signature**
  under the derived key and wipes the seed buffer in ``finally`` (best effort in CPython). Nothing is cached.
* The sealed blob is bound to tenant, kind, kid, usage and alg: a handle for another tenant, or a row swapped to
  another tenant or usage, fails authentication.
* If ``attest_keys`` already has a row for the kid, a ``revoked`` status refuses to sign (``BackendKeyDisabled``) and a
  public key that differs from the one derived from the seed refuses too (a swapped ``public_key`` column).
* No KEK means no key can be created (``KekNotConfigured``, a ``BackendUnavailable``): there is no ephemeral dev key.
* The backend has no export, dump or private-key surface and carries no state beyond the pool.
* The handle is not a capability: every call requires the handle's tenant to equal the current tenant context (and,
  with ``conn=``, the tenant the connection is stamped for). A request running for tenant A cannot sign with, probe,
  destroy or create keys for tenant B, even with a real handle of B. The context is never replaced from the handle.

SQL names the tenant explicitly in addition to row-level security (the tenant is part of the AAD, so even an
unstamped connection must never touch another tenant's row); the value always comes from the handle or the caller.
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import os
from typing import Any, AsyncIterator

import asyncpg
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .. import tenancy
from . import crypto
from .backend import (
    BackendError,
    BackendHealth,
    BackendKeyDisabled,
    BackendUnavailable,
    KekNotConfigured,
    KeyHandle,
    KeyNotFound,
    UnsupportedAlgorithm,
)

NAME = "local-aes-gcm"
USAGES = frozenset({"attest", "anchor"})

#: database failures that mean "try again later", not "this key is broken"
_TRANSIENT = (
    asyncpg.PostgresConnectionError, asyncpg.TooManyConnectionsError, asyncpg.CannotConnectNowError,
    asyncpg.InterfaceError, OSError, asyncio.TimeoutError,
)


def kid_of(public_key: bytes) -> str:
    """The key id: the first 32 hex characters of sha256(raw 32-byte public key) (D6)."""
    return hashlib.sha256(public_key).hexdigest()[:32]


def _raw_public(priv: Ed25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


class LocalAesGcmBackend:
    name = NAME
    custody = "hosted"
    algs = frozenset({"ed25519"})
    max_message_bytes = None

    def __init__(self, pool: Any) -> None:
        self._pool = pool

    # ------------------------------------------------------------------ plumbing

    @staticmethod
    def _require_context(tenant: str) -> None:
        """The key's tenant must be the tenant this code is running for. The handle is not a capability: a request
        for tenant A that holds tenant B's handle (a bug, a forged id) must not reach B's sealed seed, so the tenant
        context is checked here and never replaced by the handle's tenant."""
        ambient = tenancy.current_tenant_id()
        try:
            same = ambient is not None and crypto.normalize_tenant(ambient) == tenant
        except crypto.SealError:
            same = False
        if not same:
            raise BackendError("the key belongs to another tenant than the current tenant context")

    @contextlib.asynccontextmanager
    async def _connection(self, tenant_id: str, conn: Any) -> AsyncIterator[Any]:
        self._require_context(tenant_id)
        if conn is not None:
            # a connection stamped for a tenant (what row-level security uses) must be this key's tenant; an
            # unstamped one (superuser maintenance) is bounded by the tenant context above and the explicit tenant
            # filter in every statement
            stamped = await conn.fetchval("SELECT paddock_current_tenant()::text")
            if stamped is not None and crypto.normalize_tenant(stamped) != tenant_id:
                raise BackendError("the connection is stamped for another tenant than the key")
            yield conn
            return
        try:
            with tenancy.tenant_context(tenant_id):
                async with self._pool.acquire() as c:
                    yield c
        except _TRANSIENT as exc:
            raise BackendUnavailable(f"database unavailable ({type(exc).__name__})") from None

    def _check_handle(self, h: Any) -> str:
        if not isinstance(h, KeyHandle) or h.backend != NAME:
            raise BackendError("handle does not belong to this backend")
        if h.alg not in self.algs:
            raise UnsupportedAlgorithm(f"algorithm {h.alg!r} is not enabled")
        try:
            return crypto.normalize_tenant(h.tenant_id)
        except crypto.SealError:
            raise BackendError("handle has an invalid tenant id") from None

    # ------------------------------------------------------------------ interface

    async def generate(self, tenant_id: Any, usage: str, alg: str, *, conn: Any = None) -> tuple[KeyHandle, bytes]:
        if alg not in self.algs:
            raise UnsupportedAlgorithm(f"algorithm {alg!r} is not enabled")
        if usage not in USAGES:
            raise BackendError(f"usage {usage!r} is not a hosted key usage")
        try:
            tenant = crypto.normalize_tenant(tenant_id)
            configured = crypto.kek_configured()
        except crypto.SealError as exc:
            raise BackendError(str(exc)) from None
        if not configured:
            raise KekNotConfigured("PADDOCK_ATTEST_KEK is not configured: key creation is refused")
        seed = bytearray(os.urandom(32))
        try:
            priv = Ed25519PrivateKey.from_private_bytes(bytes(seed))
            public = _raw_public(priv)
            kid = kid_of(public)
            try:
                async with self._connection(tenant, conn) as c:
                    stored = await crypto.store_secret(
                        c, plaintext=seed, tenant_id=tenant, kind="signing", kid=kid, usage=usage, alg=alg)
            except crypto.KekNotConfigured:
                raise KekNotConfigured("PADDOCK_ATTEST_KEK is not configured: key creation is refused") from None
            except crypto.SealError as exc:
                raise BackendError(str(exc)) from None
            except _TRANSIENT as exc:
                raise BackendUnavailable(f"database unavailable ({type(exc).__name__})") from None
            if not stored:
                raise BackendError("a key with this id already exists")
        finally:
            crypto.zero(seed)
        return KeyHandle(NAME, tenant, kid, usage, alg), public

    async def _status_and_public(self, c: Any, tenant: str, kid: str) -> tuple[str | None, bytes | None]:
        row = await c.fetchrow(
            "SELECT status, public_key FROM attest_keys WHERE tenant_id = $1::uuid AND kid = $2", tenant, kid)
        if row is None:
            return None, None
        return row["status"], (bytes(row["public_key"]) or None)

    async def _open(self, c: Any, h: KeyHandle, tenant: str) -> bytearray:
        try:
            seed = await crypto.load_secret(
                c, tenant_id=tenant, kind="signing", kid=h.kid, usage=h.usage, alg=h.alg)
        except crypto.KekNotConfigured:
            raise KekNotConfigured("PADDOCK_ATTEST_KEK is not configured") from None
        except crypto.SealError:
            raise BackendError("sealed key failed authentication (wrong tenant, usage, KEK or tampered)") from None
        if seed is None:
            raise KeyNotFound("no key material for this handle")
        return seed

    async def sign(self, h: KeyHandle, message: bytes, *, conn: Any = None) -> bytes:
        tenant = self._check_handle(h)
        if not isinstance(message, (bytes, bytearray)):
            raise BackendError("message must be bytes")
        seed: bytearray | None = None
        try:
            async with self._connection(tenant, conn) as c:
                status, registered_public = await self._status_and_public(c, tenant, h.kid)
                if status == "revoked":
                    raise BackendKeyDisabled("the key is revoked")
                seed = await self._open(c, h, tenant)
            priv = Ed25519PrivateKey.from_private_bytes(bytes(seed))
            public = _raw_public(priv)
            if kid_of(public) != h.kid:
                raise BackendError("the sealed key does not match the kid of the handle")
            if registered_public is not None and registered_public != public:
                raise BackendError("the registered public key does not match the sealed key")
            sig = priv.sign(bytes(message))
            try:
                priv.public_key().verify(sig, bytes(message))
            except InvalidSignature:
                raise BackendError("signature self-check failed") from None
            return sig
        except _TRANSIENT as exc:
            raise BackendUnavailable(f"database unavailable ({type(exc).__name__})") from None
        finally:
            crypto.zero(seed)

    async def destroy(self, h: KeyHandle, *, conn: Any = None) -> None:
        tenant = self._check_handle(h)
        try:
            async with self._connection(tenant, conn) as c:
                await crypto.delete_secret(c, tenant_id=tenant, kind="signing", kid=h.kid)
        except _TRANSIENT as exc:
            raise BackendUnavailable(f"database unavailable ({type(exc).__name__})") from None

    async def health(self, h: KeyHandle, *, conn: Any = None) -> BackendHealth:
        try:
            tenant = self._check_handle(h)
        except BackendError as exc:
            return BackendHealth(False, "unusable", str(exc))
        seed: bytearray | None = None
        try:
            async with self._connection(tenant, conn) as c:
                status, registered_public = await self._status_and_public(c, tenant, h.kid)
                if status == "revoked":
                    return BackendHealth(False, "disabled", "the key is revoked")
                try:
                    seed = await crypto.load_secret(
                        c, tenant_id=tenant, kind="signing", kid=h.kid, usage=h.usage, alg=h.alg)
                except crypto.KekNotConfigured:
                    return BackendHealth(False, "unavailable", "kek_not_configured")
                except crypto.SealError:
                    return BackendHealth(False, "unusable", "sealed key cannot be opened")
            if seed is None:
                return BackendHealth(False, "missing", "no key material")
            public = _raw_public(Ed25519PrivateKey.from_private_bytes(bytes(seed)))
            if kid_of(public) != h.kid:
                return BackendHealth(False, "unusable", "kid mismatch")
            if registered_public is not None and registered_public != public:
                return BackendHealth(False, "unusable", "registered public key mismatch")
            return BackendHealth(True, "ok")
        except BackendUnavailable as exc:
            return BackendHealth(False, "unavailable", str(exc))
        except BackendError as exc:
            return BackendHealth(False, "unusable", str(exc))
        except _TRANSIENT as exc:
            return BackendHealth(False, "unavailable", f"database unavailable ({type(exc).__name__})")
        finally:
            crypto.zero(seed)
