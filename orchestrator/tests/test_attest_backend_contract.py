"""P3.2: the ``KeyBackend`` contract suite (docs/ASSURANCE_P3.md 3.6) and the local backend's own properties (3.5).

The first half is parametrised over every backend, including an in-memory fake KMS that has a message cap, so the
contract is not a description of one implementation. The second half is specific to ``LocalAesGcmBackend``.
"""
from __future__ import annotations

import dataclasses
import hashlib
import re
from typing import Any

import asyncpg
import pytest
import pytest_asyncio
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import SecretStr

from app import tenancy
from app.attest import backend as backend_mod
from app.attest import backend_local, crypto
from app.attest import config as attest_config
from app.attest.backend import (
    BackendError,
    BackendHealth,
    BackendKeyDisabled,
    BackendUnavailable,
    KekNotConfigured,
    KeyBackend,
    KeyHandle,
    KeyNotFound,
    MessageTooLarge,
    UnsupportedAlgorithm,
)
from app.attest.backend_local import LocalAesGcmBackend

TA = "00000000-0000-0000-0000-0000000000a1"
TB = "00000000-0000-0000-0000-0000000000b1"
FORBIDDEN_NAME = re.compile(r"export|private|dump|secret", re.I)
KEK_TEXT = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="      # 32 x 0x07


def _raw(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _verifies(public: bytes, message: bytes, sig: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(sig, message)
        return True
    except InvalidSignature:
        return False


# --------------------------------------------------------------------------- #
# A fake KMS: in-memory, capped, can be disabled or made unavailable
# --------------------------------------------------------------------------- #

class FakeKmsBackend:
    name = "fake-kms"
    custody = "byok-kms"
    algs = frozenset({"ed25519"})
    max_message_bytes = 4096

    def __init__(self, store: dict | None = None) -> None:
        self._keys: dict[tuple[str, str], Ed25519PrivateKey] = store if store is not None else {}
        self._off: set[tuple[str, str]] = set()
        self.down = False

    def _guard(self) -> None:
        if self.down:
            raise BackendUnavailable("kms throttled")

    async def generate(self, tenant_id, usage, alg, *, conn=None):
        self._guard()
        if alg not in self.algs:
            raise UnsupportedAlgorithm(alg)
        if usage not in ("attest", "anchor"):
            raise BackendError("usage")
        priv = Ed25519PrivateKey.generate()
        pub = _raw(priv.public_key())
        kid = hashlib.sha256(pub).hexdigest()[:32]
        self._keys[(str(tenant_id), kid)] = priv
        return KeyHandle(self.name, str(tenant_id), kid, usage, alg, key_ref=f"arn:fake:{kid}"), pub

    def _key(self, h):
        if not isinstance(h, KeyHandle) or h.backend != self.name:
            raise BackendError("foreign handle")
        if h.alg not in self.algs:
            raise UnsupportedAlgorithm(h.alg)
        k = (h.tenant_id, h.kid)
        if k in self._off:
            raise BackendKeyDisabled("disabled")
        if k not in self._keys:
            raise KeyNotFound("no such key")
        return self._keys[k]

    async def sign(self, h, message, *, conn=None):
        self._guard()
        if not isinstance(message, (bytes, bytearray)):
            raise BackendError("bytes only")
        if len(message) > self.max_message_bytes:
            raise MessageTooLarge(f"{len(message)} > {self.max_message_bytes}")
        return self._key(h).sign(bytes(message))

    async def destroy(self, h, *, conn=None):
        self._guard()
        self._keys.pop((h.tenant_id, h.kid), None)

    async def health(self, h, *, conn=None):
        if self.down:
            return BackendHealth(False, "unavailable", "down")
        if (h.tenant_id, h.kid) in self._off:
            return BackendHealth(False, "disabled")
        if (h.tenant_id, h.kid) not in self._keys:
            return BackendHealth(False, "missing")
        return BackendHealth(True, "ok")


class _Scoped:
    """Test helper: run every call in the handle's (or the requested) tenant context, as the issuer loop does. The
    backend itself refuses a handle whose tenant is not the current tenant context (see the dedicated tests, which
    use the raw backend)."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    async def generate(self, tenant_id, usage, alg, *, conn=None):
        with tenancy.tenant_context(tenant_id):
            return await self._inner.generate(tenant_id, usage, alg, conn=conn)

    async def sign(self, h, message, *, conn=None):
        with tenancy.tenant_context(h.tenant_id):
            return await self._inner.sign(h, message, conn=conn)

    async def destroy(self, h, *, conn=None):
        with tenancy.tenant_context(h.tenant_id):
            return await self._inner.destroy(h, conn=conn)

    async def health(self, h, *, conn=None):
        with tenancy.tenant_context(h.tenant_id):
            return await self._inner.health(h, conn=conn)


def _scoped(backend: Any) -> _Scoped:
    return _Scoped(backend)


class _FailingPool:
    def acquire(self):
        raise asyncpg.CannotConnectNowError("the database is starting up")


class Harness:
    def __init__(self, kind: str, backend: Any, db_pool: Any = None) -> None:
        self.kind, self.backend, self.db_pool = kind, backend, db_pool
        self.tenant_a, self.tenant_b = TA, TB
        self.pub: dict[str, bytes] = {}

    async def generate(self, tenant: str = TA, usage: str = "attest"):
        h, pub = await self.backend.generate(tenant, usage, "ed25519")
        self.pub[h.kid] = pub
        return h, pub

    async def disable(self, h: KeyHandle) -> None:
        if self.kind == "fake-kms":
            self.backend._off.add((h.tenant_id, h.kid))
            return
        async with self.db_pool.acquire() as con:
            await con.execute(
                "INSERT INTO attest_keys (tenant_id, kid, usage, public_key, status) VALUES ($1::uuid, $2, $3, $4, 'revoked')",
                h.tenant_id, h.kid, h.usage, self.pub[h.kid])

    def make_unavailable(self):
        if self.kind == "fake-kms":
            self.backend.down = True
            return self.backend
        return _scoped(LocalAesGcmBackend(_FailingPool()))


@pytest.fixture(autouse=True)
def _kek(monkeypatch):
    monkeypatch.setattr(attest_config.settings, "kek", SecretStr(KEK_TEXT))
    monkeypatch.setattr(attest_config.settings, "kek_file", None)
    monkeypatch.setattr(attest_config.settings, "kek_previous", None)


@pytest_asyncio.fixture
async def tenants(db_pool):
    for slug, tid in (("bk-a", TA), ("bk-b", TB)):
        await tenancy.create_tenant(db_pool, slug=slug, name=slug, tenant_id=tid)


@pytest_asyncio.fixture(params=["local-aes-gcm", "fake-kms"])
async def harness(request, db_pool, tenants):
    if request.param == "local-aes-gcm":
        return Harness("local-aes-gcm", _scoped(LocalAesGcmBackend(db_pool)), db_pool)
    return Harness("fake-kms", FakeKmsBackend(), db_pool)


# --------------------------------------------------------------------------- #
# The contract, for every backend
# --------------------------------------------------------------------------- #

async def test_backend_declares_its_contract(harness):
    b = harness.backend
    assert isinstance(b, KeyBackend)
    assert b.custody in ("hosted", "byok-kms", "byok-hsm")
    assert isinstance(b.algs, frozenset) and b.algs == frozenset({"ed25519"})
    assert b.max_message_bytes is None or (isinstance(b.max_message_bytes, int) and b.max_message_bytes > 0)
    assert isinstance(b.name, str) and b.name


async def test_sign_verifies_under_the_returned_key_and_kid_is_the_fingerprint(harness):
    h, pub = await harness.generate()
    assert len(pub) == 32 and h.kid == hashlib.sha256(pub).hexdigest()[:32]
    assert (h.tenant_id, h.usage, h.alg, h.backend) == (TA, "attest", "ed25519", harness.backend.name)
    msg = b"DSSEv1 28 application/vnd.in-toto+json 5 hello"
    sig = await harness.backend.sign(h, msg)
    assert len(sig) == 64 and _verifies(pub, msg, sig)
    assert not _verifies(pub, msg + b"x", sig)


async def test_ed25519_is_deterministic(harness):
    h, _ = await harness.generate()
    assert await harness.backend.sign(h, b"m") == await harness.backend.sign(h, b"m")
    assert await harness.backend.sign(h, b"m") != await harness.backend.sign(h, b"n")


async def test_no_export_private_dump_or_secret_surface(harness):
    h, _ = await harness.generate()
    for obj in (harness.backend, h, type(harness.backend), KeyHandle):
        bad = [n for n in dir(obj) if FORBIDDEN_NAME.search(n)]
        assert not bad, (obj, bad)
    assert not [n for n in vars(harness.backend) if FORBIDDEN_NAME.search(n)]
    assert not [f.name for f in dataclasses.fields(KeyHandle) if FORBIDDEN_NAME.search(f.name)]
    assert not [n for n in dir(backend_mod.KeyBackend) if FORBIDDEN_NAME.search(n)]


async def test_repr_of_handle_leaks_nothing(harness):
    h, pub = await harness.generate()
    if harness.kind == "fake-kms":
        seed = harness.backend._keys[(h.tenant_id, h.kid)].private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    else:
        async with harness.db_pool.acquire() as con:
            seed = bytes(await crypto.load_secret(con, tenant_id=TA, kind="signing", kid=h.kid, usage="attest", alg="ed25519"))
        sealed = await harness.db_pool.fetchval("SELECT sealed FROM attest_key_secrets WHERE kid = $1", h.kid)
        assert sealed not in repr(h) and sealed not in str(h)
    seed_hex = seed.hex()
    for text in (repr(h), str(h), f"{h!r}", repr(harness.backend), str(vars(harness.backend)) if hasattr(harness.backend, "__dict__") else ""):
        assert seed_hex not in text and seed.hex().upper() not in text
    assert TA not in repr(h) and TA not in str(h), "the tenant id does not need to be in a log line"
    assert h.kid in repr(h)


async def test_two_keys_are_independent(harness):
    h1, p1 = await harness.generate()
    h2, p2 = await harness.generate()
    assert h1.kid != h2.kid and p1 != p2
    s1 = await harness.backend.sign(h1, b"same")
    s2 = await harness.backend.sign(h2, b"same")
    assert s1 != s2 and _verifies(p1, b"same", s1) and _verifies(p2, b"same", s2)
    assert not _verifies(p2, b"same", s1) and not _verifies(p1, b"same", s2)
    await harness.backend.destroy(h1)
    assert _verifies(p2, b"x", await harness.backend.sign(h2, b"x"))      # destroying one leaves the other


@pytest.mark.parametrize("alg", ["ecdsa-p256-sha256", "rsa", "ed448", "", "ED25519"])
async def test_the_algorithm_allow_list_is_enforced(harness, alg):
    with pytest.raises(UnsupportedAlgorithm):
        await harness.backend.generate(TA, "attest", alg)


async def test_a_handle_with_another_algorithm_cannot_sign(harness):
    h, _ = await harness.generate()
    with pytest.raises(BackendError):
        await harness.backend.sign(dataclasses.replace(h, alg="ecdsa-p256-sha256"), b"m")


async def test_unknown_usage_is_refused(harness):
    for usage in ("issue-cert", "revoke", "", "root"):
        with pytest.raises(BackendError):
            await harness.backend.generate(TA, usage, "ed25519")


async def test_destroy_then_sign_fails_and_destroy_is_idempotent(harness):
    h, _ = await harness.generate()
    await harness.backend.sign(h, b"m")
    await harness.backend.destroy(h)
    with pytest.raises(BackendError):
        await harness.backend.sign(h, b"m")
    with pytest.raises(KeyNotFound):
        await harness.backend.sign(h, b"m")
    await harness.backend.destroy(h)                                       # second destroy is a no-op
    health = await harness.backend.health(h)
    assert health.ok is False and health.state == "missing"


async def test_backend_unavailable_propagates_so_the_issuer_does_not_issue(harness):
    h, _ = await harness.generate()
    down = harness.make_unavailable()
    with pytest.raises(BackendUnavailable):
        await down.sign(h, b"m")
    with pytest.raises(BackendUnavailable):
        await down.generate(TA, "attest", "ed25519")
    with pytest.raises(BackendUnavailable):
        await down.destroy(h)
    health = await down.health(h)
    assert health.ok is False and health.state == "unavailable"


async def test_a_message_over_the_cap_raises_message_too_large(harness):
    h, pub = await harness.generate()
    cap = harness.backend.max_message_bytes
    if cap is None:
        big = b"x" * (1 << 20)
        assert _verifies(pub, big, await harness.backend.sign(h, big))      # unlimited means unlimited
        return
    ok = b"x" * cap
    assert _verifies(pub, ok, await harness.backend.sign(h, ok))
    with pytest.raises(MessageTooLarge):
        await harness.backend.sign(h, ok + b"x")


async def test_messages_must_be_bytes(harness):
    h, _ = await harness.generate()
    for bad in ("text", 5, None, ["a"]):
        with pytest.raises(BackendError):
            await harness.backend.sign(h, bad)  # type: ignore[arg-type]


async def test_a_wrong_tenant_handle_cannot_sign(harness):
    h, _ = await harness.generate(TA)
    with pytest.raises(BackendError):
        await harness.backend.sign(dataclasses.replace(h, tenant_id=TB), b"m")
    # and cannot destroy either: tenant A's key survives
    await harness.backend.destroy(dataclasses.replace(h, tenant_id=TB))
    await harness.backend.sign(h, b"still here")


async def test_a_handle_of_another_backend_is_refused(harness):
    h, _ = await harness.generate()
    with pytest.raises(BackendError):
        await harness.backend.sign(dataclasses.replace(h, backend="somebody-else"), b"m")


async def test_health_is_ok_for_a_good_key_and_reflects_a_disabled_one(harness):
    h, _ = await harness.generate()
    assert await harness.backend.health(h) == BackendHealth(True, "ok")
    await harness.disable(h)
    health = await harness.backend.health(h)
    assert health.ok is False and health.state == "disabled"
    with pytest.raises(BackendKeyDisabled):
        await harness.backend.sign(h, b"m")


async def test_the_anchor_usage_is_supported_too(harness):
    h, pub = await harness.generate(usage="anchor")
    assert h.usage == "anchor" and _verifies(pub, b"a", await harness.backend.sign(h, b"a"))


# --------------------------------------------------------------------------- #
# LocalAesGcmBackend specifics
# --------------------------------------------------------------------------- #

async def test_local_backend_declares_hosted_custody_and_no_message_cap(db_pool):
    b = _scoped(LocalAesGcmBackend(db_pool))
    assert (b.name, b.custody, b.algs, b.max_message_bytes) == ("local-aes-gcm", "hosted", frozenset({"ed25519"}), None)
    assert b.name == backend_local.NAME == "local-aes-gcm"


async def test_the_sealed_row_holds_no_plaintext_seed(db_pool, tenants):
    b = _scoped(LocalAesGcmBackend(db_pool))
    h, _ = await b.generate(TA, "attest", "ed25519")
    async with db_pool.acquire() as con:
        row = await con.fetchrow("SELECT * FROM attest_key_secrets WHERE kid = $1", h.kid)
        seed = bytes(await crypto.load_secret(con, tenant_id=TA, kind="signing", kid=h.kid, usage="attest", alg="ed25519"))
    assert row["kind"] == "signing" and row["kek_id"] == crypto.blob_kek_id(row["sealed"])
    text = str(dict(row))
    for form in (seed.hex(), seed.hex().upper(), hashlib.sha256(seed).hexdigest()):
        assert form not in text
    import base64
    assert base64.b64encode(seed).decode() not in row["sealed"] and base64.urlsafe_b64encode(seed).decode() not in row["sealed"]


async def test_key_creation_is_refused_without_a_kek_and_writes_nothing(db_pool, tenants, monkeypatch):
    monkeypatch.setattr(attest_config.settings, "kek", None)
    b = _scoped(LocalAesGcmBackend(db_pool))
    with pytest.raises(KekNotConfigured) as ei:
        await b.generate(TA, "attest", "ed25519")
    assert isinstance(ei.value, BackendUnavailable)
    assert await db_pool.fetchval("SELECT count(*) FROM attest_key_secrets") == 0


async def test_signing_without_the_kek_is_unavailable_not_a_wrong_answer(db_pool, tenants, monkeypatch):
    b = _scoped(LocalAesGcmBackend(db_pool))
    h, _ = await b.generate(TA, "attest", "ed25519")
    monkeypatch.setattr(attest_config.settings, "kek", None)
    with pytest.raises(KekNotConfigured):
        await b.sign(h, b"m")
    health = await b.health(h)
    assert health.ok is False and health.state == "unavailable"


async def test_a_blob_moved_to_another_tenant_fails_authentication(db_pool, tenants):
    """mint_other_tenant_key / sealed_blob_swap_fails: B cannot sign with A's sealed seed even if the row is swapped."""
    b = _scoped(LocalAesGcmBackend(db_pool))
    ha, pub_a = await b.generate(TA, "attest", "ed25519")
    hb, _ = await b.generate(TB, "attest", "ed25519")
    async with db_pool.acquire() as con:
        await con.execute(
            "UPDATE attest_key_secrets SET sealed = (SELECT sealed FROM attest_key_secrets WHERE tenant_id = $1::uuid AND kid = $2) "
            "WHERE tenant_id = $3::uuid AND kid = $4", TA, ha.kid, TB, hb.kid)
    with pytest.raises(BackendError):
        await b.sign(hb, b"m")
    assert _verifies(pub_a, b"m", await b.sign(ha, b"m"))
    assert (await b.health(hb)).state == "unusable"


async def test_a_blob_moved_to_another_kid_or_usage_fails_authentication(db_pool, tenants):
    b = _scoped(LocalAesGcmBackend(db_pool))
    h1, _ = await b.generate(TA, "attest", "ed25519")
    h2, _ = await b.generate(TA, "attest", "ed25519")
    async with db_pool.acquire() as con:
        await con.execute(
            "UPDATE attest_key_secrets SET sealed = (SELECT sealed FROM attest_key_secrets WHERE kid = $1) WHERE kid = $2",
            h1.kid, h2.kid)
    with pytest.raises(BackendError):
        await b.sign(h2, b"m")
    # a handle that claims another usage than the one the seed was sealed for cannot open it
    with pytest.raises(BackendError):
        await b.sign(dataclasses.replace(h1, usage="anchor"), b"m")


async def test_a_sealed_seed_that_does_not_match_its_kid_is_refused(db_pool, tenants):
    """Guards a row planted under a kid that is not the fingerprint of the seed it holds."""
    fake_kid = "ab" * 16
    async with db_pool.acquire() as con:
        assert await crypto.store_secret(con, plaintext=b"\x11" * 32, tenant_id=TA, kind="signing", kid=fake_kid,
                                         usage="attest", alg="ed25519")
    b = _scoped(LocalAesGcmBackend(db_pool))
    h = KeyHandle("local-aes-gcm", TA, fake_kid, "attest", "ed25519")
    with pytest.raises(BackendError, match="kid"):
        await b.sign(h, b"m")
    assert (await b.health(h)).state == "unusable"


async def test_a_swapped_public_key_column_refuses_to_sign(db_pool, tenants):
    b = _scoped(LocalAesGcmBackend(db_pool))
    h, pub = await b.generate(TA, "attest", "ed25519")
    async with db_pool.acquire() as con:
        await con.execute("INSERT INTO attest_keys (tenant_id, kid, public_key, status) VALUES ($1::uuid, $2, $3, 'active')",
                          TA, h.kid, b"\x05" * 32)
    with pytest.raises(BackendError, match="public key"):
        await b.sign(h, b"m")


async def test_a_matching_registered_public_key_signs(db_pool, tenants):
    b = _scoped(LocalAesGcmBackend(db_pool))
    h, pub = await b.generate(TA, "attest", "ed25519")
    async with db_pool.acquire() as con:
        await con.execute("INSERT INTO attest_keys (tenant_id, kid, public_key, status) VALUES ($1::uuid, $2, $3, 'active')",
                          TA, h.kid, pub)
    assert _verifies(pub, b"m", await b.sign(h, b"m"))


async def test_the_unsealed_seed_buffer_is_wiped_after_signing(db_pool, tenants, monkeypatch):
    b = _scoped(LocalAesGcmBackend(db_pool))
    h, _ = await b.generate(TA, "attest", "ed25519")
    seen: list[bytearray] = []
    real = crypto.load_secret

    async def spy(*a, **k):
        out = await real(*a, **k)
        seen.append(out)
        return out

    monkeypatch.setattr(crypto, "load_secret", spy)
    await b.sign(h, b"m")
    assert len(seen) == 1 and len(seen[0]) == 32 and bytes(seen[0]) == b"\x00" * 32


async def test_the_seed_buffer_is_wiped_when_signing_fails_too(db_pool, tenants, monkeypatch):
    b = _scoped(LocalAesGcmBackend(db_pool))
    h, _ = await b.generate(TA, "attest", "ed25519")
    seen: list[bytearray] = []
    real = crypto.load_secret

    async def spy(*a, **k):
        out = await real(*a, **k)
        seen.append(out)
        return out

    monkeypatch.setattr(crypto, "load_secret", spy)
    monkeypatch.setattr(backend_local, "kid_of", lambda pub: "0" * 32)       # force the kid check to fail
    with pytest.raises(BackendError):
        await b.sign(h, b"m")
    assert seen and bytes(seen[0]) == b"\x00" * 32


async def test_a_signature_that_does_not_verify_is_never_returned(db_pool, tenants, monkeypatch):
    """sign-then-verify: a faulty signer (bit flip, fault injection) yields an error, not a bad signature."""
    b = _scoped(LocalAesGcmBackend(db_pool))
    h, _ = await b.generate(TA, "attest", "ed25519")
    real_cls = backend_local.Ed25519PrivateKey

    class Faulty:
        def __init__(self, inner):
            self._inner = inner

        def public_key(self):
            return self._inner.public_key()

        def sign(self, data):
            sig = bytearray(self._inner.sign(data))
            sig[0] ^= 1
            return bytes(sig)

    class FaultyFactory:
        @staticmethod
        def from_private_bytes(raw):
            return Faulty(real_cls.from_private_bytes(raw))

    monkeypatch.setattr(backend_local, "Ed25519PrivateKey", FaultyFactory)
    with pytest.raises(BackendError, match="self-check"):
        await b.sign(h, b"m")


async def test_there_is_no_unsealed_key_cache(db_pool, tenants):
    b = _scoped(LocalAesGcmBackend(db_pool))
    h, pub = await b.generate(TA, "attest", "ed25519")
    assert _verifies(pub, b"m", await b.sign(h, b"m"))
    async with db_pool.acquire() as con:
        await con.execute("DELETE FROM attest_key_secrets WHERE kid = $1", h.kid)
    with pytest.raises(KeyNotFound):
        await b.sign(h, b"m")                  # a cached key would still sign


async def test_a_revoked_key_row_blocks_signing_even_with_the_seed_present(db_pool, tenants):
    b = _scoped(LocalAesGcmBackend(db_pool))
    h, pub = await b.generate(TA, "attest", "ed25519")
    async with db_pool.acquire() as con:
        await con.execute("INSERT INTO attest_keys (tenant_id, kid, public_key, status) VALUES ($1::uuid, $2, $3, 'active')",
                          TA, h.kid, pub)
        await con.execute("UPDATE attest_keys SET status = 'revoked' WHERE kid = $1", h.kid)
    with pytest.raises(BackendKeyDisabled):
        await b.sign(h, b"m")
    assert (await b.health(h)).state == "disabled"


async def test_generate_and_sign_can_run_inside_the_callers_transaction(db_pool, tenants):
    b = _scoped(LocalAesGcmBackend(db_pool))
    async with db_pool.acquire() as con:
        try:
            async with con.transaction():
                h, pub = await b.generate(TA, "attest", "ed25519", conn=con)
                assert _verifies(pub, b"m", await b.sign(h, b"m", conn=con))      # visible inside the transaction
                raise RuntimeError("roll back")
        except RuntimeError:
            pass
    assert await db_pool.fetchval("SELECT count(*) FROM attest_key_secrets") == 0   # rolled back with the caller
    with pytest.raises(KeyNotFound):
        await b.sign(h, b"m")


async def test_through_the_non_superuser_app_pool_each_tenant_only_reaches_its_own_key(db_pool, app_pool, tenants):
    b = _scoped(LocalAesGcmBackend(app_pool))
    ha, pub_a = await b.generate(TA, "attest", "ed25519")
    hb, pub_b = await b.generate(TB, "attest", "ed25519")
    assert _verifies(pub_a, b"m", await b.sign(ha, b"m")) and _verifies(pub_b, b"m", await b.sign(hb, b"m"))
    with pytest.raises(KeyNotFound):
        await b.sign(dataclasses.replace(ha, tenant_id=TB), b"m")          # RLS and the explicit tenant both say no
    assert await db_pool.fetchval("SELECT count(*) FROM attest_key_secrets") == 2


async def _two_tenant_keys(b):
    with tenancy.tenant_context(TB):
        hb, pub_b = await b.generate(TB, "attest", "ed25519")
    with tenancy.tenant_context(TA):
        ha, pub_a = await b.generate(TA, "attest", "ed25519")
    return ha, pub_a, hb, pub_b


async def test_a_real_handle_of_another_tenant_is_refused_under_this_tenants_context(db_pool, tenants):
    """mint_other_tenant_key (11.3): tenant A's request context can neither sign with, destroy, probe nor create keys
    for tenant B's REAL key. The handle's tenant must equal the caller's tenant context."""
    b = LocalAesGcmBackend(db_pool)
    ha, pub_a, hb, pub_b = await _two_tenant_keys(b)
    with tenancy.tenant_context(TA):
        with pytest.raises(BackendError, match="tenant"):
            await b.sign(hb, b"m")
        with pytest.raises(BackendError, match="tenant"):
            await b.destroy(hb)
        with pytest.raises(BackendError, match="tenant"):
            await b.generate(TB, "attest", "ed25519")
        health = await b.health(hb)
        assert health.ok is False and health.state == "unusable"
        assert _verifies(pub_a, b"m", await b.sign(ha, b"m"))         # its own key still works
    with tenancy.tenant_context(TB):
        assert _verifies(pub_b, b"m", await b.sign(hb, b"m"))         # B's key survived the destroy attempt
        assert (await b.health(hb)).ok is True
    assert await db_pool.fetchval("SELECT count(*) FROM attest_key_secrets") == 2


async def test_a_real_handle_of_another_tenant_is_refused_through_the_app_pool_too(app_pool, tenants):
    b = LocalAesGcmBackend(app_pool)
    ha, pub_a, hb, pub_b = await _two_tenant_keys(b)
    with tenancy.tenant_context(TA):
        with pytest.raises(BackendError, match="tenant"):
            await b.sign(hb, b"m")
        async with app_pool.acquire() as con:
            with pytest.raises(BackendError, match="tenant"):
                await b.sign(hb, b"m", conn=con)
            with pytest.raises(BackendError, match="tenant"):
                await b.destroy(hb, conn=con)


async def test_a_connection_stamped_for_another_tenant_is_refused(db_pool, tenants):
    """With conn= the handle must also match the tenant the connection is stamped for (what RLS will use)."""
    b = LocalAesGcmBackend(db_pool)
    _, _, hb, pub_b = await _two_tenant_keys(b)
    with tenancy.tenant_context(TB):
        async with db_pool.acquire() as con:
            async with con.transaction():
                await con.execute("SELECT set_config('app.tenant_id', $1, true)", TA)
                with pytest.raises(BackendError, match="tenant"):
                    await b.sign(hb, b"m", conn=con)
                with pytest.raises(BackendError, match="tenant"):
                    await b.destroy(hb, conn=con)
                with pytest.raises(BackendError, match="tenant"):
                    await b.generate(TB, "attest", "ed25519", conn=con)
                await con.execute("SELECT set_config('app.tenant_id', $1, true)", TB)
                assert _verifies(pub_b, b"m", await b.sign(hb, b"m", conn=con))


async def test_no_tenant_context_at_all_is_refused(db_pool, tenants, monkeypatch):
    b = LocalAesGcmBackend(db_pool)
    _, _, hb, _ = await _two_tenant_keys(b)
    monkeypatch.setattr(tenancy.settings, "tenancy_strict", True)
    assert tenancy.current_tenant_id() is None
    with pytest.raises(BackendError, match="tenant"):
        await b.sign(hb, b"m")
    with pytest.raises(BackendError, match="tenant"):
        await b.generate(TB, "attest", "ed25519")


async def test_two_generate_calls_never_collide_and_each_has_one_row(db_pool, tenants):
    import asyncio
    b = _scoped(LocalAesGcmBackend(db_pool))
    out = await asyncio.gather(*[b.generate(TA, "attest", "ed25519") for _ in range(8)])
    assert len({h.kid for h, _ in out}) == 8
    assert await db_pool.fetchval("SELECT count(*) FROM attest_key_secrets") == 8


async def test_a_database_that_is_down_is_backend_unavailable_not_a_key_error(tenants):
    b = _scoped(LocalAesGcmBackend(_FailingPool()))
    h = KeyHandle("local-aes-gcm", TA, "c" * 32, "attest", "ed25519")
    with pytest.raises(BackendUnavailable):
        await b.sign(h, b"m")
    with pytest.raises(BackendUnavailable):
        await b.generate(TA, "attest", "ed25519")


async def test_no_key_material_anywhere(db_pool, tenants, caplog, monkeypatch, tmp_path):
    """11.3 no_key_material_anywhere: after generating, signing, failing, estate bootstrap and key registration, no log
    line, exception message, audit row or ``SELECT *`` on the key table contains a seed, the KEK or the commit key in
    any common encoding."""
    import base64
    import json
    import logging

    from app.attest import estate

    caplog.set_level(logging.DEBUG)
    for name in ("issuer.key", "issuer.cert", "revoker.key", "revoker.cert"):
        (tmp_path / name).write_text("x\n")
    for attr, name in (("issuer_key_file", "issuer.key"), ("issuer_cert_file", "issuer.cert"),
                       ("revoker_key_file", "revoker.key"), ("revoker_cert_file", "revoker.cert")):
        monkeypatch.setattr(attest_config.settings, attr, str(tmp_path / name))
    b = _scoped(LocalAesGcmBackend(db_pool))
    messages: list[str] = []
    h, pub = await b.generate(TA, "attest", "ed25519")
    await b.sign(h, b"payload")
    await b.health(h)
    async with db_pool.acquire() as con:
        await con.execute("INSERT INTO attest_keys (tenant_id, kid, public_key, status) VALUES ($1::uuid, $2, $3, 'active')",
                          TA, h.kid, pub)
        seed = bytes(await crypto.load_secret(con, tenant_id=TA, kind="signing", kid=h.kid, usage="attest", alg="ed25519"))
        await estate.ensure_estate(con)
        commit = await estate.get_commit_key(con)
        keys_row = str(dict(await con.fetchrow("SELECT * FROM attest_keys")))
        audit_rows = json.dumps([dict(r) for r in await con.fetch("SELECT * FROM audit_log")], default=str)
    for bad_call in (
        b.sign(dataclasses.replace(h, tenant_id=TB), b"m"), b.sign(dataclasses.replace(h, usage="anchor"), b"m"),
        b.generate(TA, "attest", "rsa"), b.sign(h, "not bytes"),
    ):
        with pytest.raises(BackendError) as ei:
            await bad_call
        messages.append(str(ei.value))
    monkeypatch.setattr(attest_config.settings, "kek", None)
    with pytest.raises(BackendError) as ei:
        await b.sign(h, b"m")
    messages.append(str(ei.value))
    monkeypatch.setattr(attest_config.settings, "kek", SecretStr(KEK_TEXT))

    kek_raw = base64.urlsafe_b64decode(KEK_TEXT)
    forms: list[str] = []
    for raw in (seed, kek_raw, commit):
        forms += [raw.hex(), raw.hex().upper(), base64.b64encode(raw).decode(), base64.urlsafe_b64encode(raw).decode(),
                  base64.b64encode(raw).decode().rstrip("=")]
    forms.append(KEK_TEXT)
    haystacks = {"logs": caplog.text, "errors": "\n".join(messages), "keys table": keys_row, "audit": audit_rows,
                 "repr": repr(h) + repr(b) + repr(attest_config.settings)}
    for where, text in haystacks.items():
        for form in forms:
            assert form not in text, f"key material leaked into {where}"
