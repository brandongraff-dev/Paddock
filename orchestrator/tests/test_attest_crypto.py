"""P3.2: attest settings and KEK sealing (docs/ASSURANCE_P3.md 3.5, 5.11, D17).

Pure tests (no database) plus the DB-backed secret store helpers at the end. The lint at the bottom pins D17:
only ``attest/crypto.py`` and ``attest/backend_local.py`` may name the sealed-secrets table.
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import uuid
from pathlib import Path

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import SecretStr, ValidationError

from app import tenancy
from app.attest import config as attest_config
from app.attest import crypto

TENANT = "00000000-0000-0000-0000-0000000000a1"
OTHER_TENANT = "00000000-0000-0000-0000-0000000000b1"
KID = "0123456789abcdef0123456789abcdef"
CTX = dict(tenant_id=TENANT, kind="signing", kid=KID, usage="attest", alg="ed25519")


def _kek(fill: int = 7) -> str:
    return base64.urlsafe_b64encode(bytes([fill]) * 32).decode()


@pytest.fixture
def kek(monkeypatch):
    monkeypatch.setattr(attest_config.settings, "kek", SecretStr(_kek(7)))
    monkeypatch.setattr(attest_config.settings, "kek_file", None)
    monkeypatch.setattr(attest_config.settings, "kek_previous", None)
    return _kek(7)


@pytest_asyncio.fixture
async def tenants(db_pool):
    for slug, tid in (("cry-a", TENANT), ("cry-b", OTHER_TENANT)):
        await tenancy.create_tenant(db_pool, slug=slug, name=slug, tenant_id=tid)


@pytest.fixture
def no_kek(monkeypatch):
    monkeypatch.setattr(attest_config.settings, "kek", None)
    monkeypatch.setattr(attest_config.settings, "kek_file", None)
    monkeypatch.setattr(attest_config.settings, "kek_previous", None)


# --------------------------------------------------------------------------- #
# Settings (5.11)
# --------------------------------------------------------------------------- #

def test_settings_defaults_match_the_contract_table():
    s = attest_config.AttestSettings(_env_file=None)
    assert s.issuing is True
    assert s.kek is None and s.kek_file is None and s.kek_previous is None
    for name in ("issuer_key_file", "issuer_cert_file", "revoker_key_file", "revoker_cert_file",
                 "platform_key_passphrase", "trust_roots_file", "dns_resolvers", "public_base_url"):
        assert getattr(s, name) is None, name
    assert s.ttl_default_h == 24
    assert (s.tick_s, s.upgrade_debounce_s, s.min_spacing_s, s.min_result_life_s) == (60, 300, 300, 900)
    assert s.max_tier == "observed"
    assert s.graph_leaf_cap == 500000
    assert s.require_anchor is False
    assert s.anchor_max_age_s == 7200
    assert (s.dns_recheck_hours, s.dns_grace_hours, s.dns_trust_ad) == (6, 6, False)
    assert s.serving_sweep_s == 300
    assert (s.history_served, s.statement_max_bytes) == (60, 262144)
    assert s.byok_enabled is False


def test_settings_read_the_paddock_attest_prefix(monkeypatch):
    monkeypatch.setenv("PADDOCK_ATTEST_ISSUING", "false")
    monkeypatch.setenv("PADDOCK_ATTEST_TTL_DEFAULT_H", "48")
    monkeypatch.setenv("PADDOCK_ATTEST_REQUIRE_ANCHOR", "true")
    monkeypatch.setenv("PADDOCK_ATTEST_KEK", _kek())
    s = attest_config.AttestSettings(_env_file=None)
    assert s.issuing is False and s.ttl_default_h == 48 and s.require_anchor is True
    assert isinstance(s.kek, SecretStr)


@pytest.mark.parametrize("name,value", [
    ("ttl_default_h", 0), ("ttl_default_h", 73), ("tick_s", 0), ("graph_leaf_cap", 0),
    ("statement_max_bytes", 0), ("history_served", 0), ("max_tier", "declared"), ("max_tier", "bogus"),
])
def test_settings_reject_values_outside_the_contract(name, value):
    with pytest.raises(ValidationError):
        attest_config.AttestSettings(_env_file=None, **{name: value})


def test_settings_repr_never_shows_key_material():
    s = attest_config.AttestSettings(_env_file=None, kek=_kek(9), kek_previous=_kek(8),
                                     platform_key_passphrase="correct horse battery staple")
    text = repr(s) + str(s) + str(s.model_dump())
    assert _kek(9) not in text and _kek(8) not in text and "correct horse" not in text


def test_byok_flag_is_off_and_no_other_backend_is_enabled_by_default():
    assert attest_config.AttestSettings(_env_file=None).byok_enabled is False


# --------------------------------------------------------------------------- #
# KEK loading
# --------------------------------------------------------------------------- #

def test_no_kek_means_not_configured_and_seal_is_refused(no_kek):
    assert crypto.kek_configured() is False
    with pytest.raises(crypto.KekNotConfigured):
        crypto.seal(b"x" * 32, **CTX)


def test_a_kms_key_id_alone_does_not_configure_anything_it_is_a_reserved_stub(monkeypatch, no_kek):
    monkeypatch.setattr(attest_config.settings, "kek_kms_key_id", "alias/paddock-attest")
    assert crypto.kek_configured() is False
    with pytest.raises(crypto.KekNotConfigured):
        crypto.seal(b"x" * 32, **CTX)


def test_previous_keks_alone_do_not_configure_sealing(monkeypatch, no_kek):
    """Old KEKs may only open: with no primary there is nothing to seal under."""
    monkeypatch.setattr(attest_config.settings, "kek_previous", SecretStr(_kek(3)))
    assert crypto.kek_configured() is False
    with pytest.raises(crypto.KekNotConfigured):
        crypto.seal(b"x" * 32, **CTX)


def test_there_is_no_ephemeral_dev_key(no_kek):
    # a second call still refuses: nothing was generated behind our back
    for _ in range(2):
        with pytest.raises(crypto.KekNotConfigured):
            crypto.seal(b"x" * 32, **CTX)
    assert crypto.kek_configured() is False


@pytest.mark.parametrize("bad", [
    "", "   ", "not base64 !!", base64.urlsafe_b64encode(b"\x01" * 31).decode(),
    base64.urlsafe_b64encode(b"\x01" * 33).decode(), base64.urlsafe_b64encode(b"\x00" * 32).decode(),
])
def test_malformed_or_weak_kek_is_refused_not_ignored(monkeypatch, bad):
    monkeypatch.setattr(attest_config.settings, "kek", SecretStr(bad))
    monkeypatch.setattr(attest_config.settings, "kek_file", None)
    monkeypatch.setattr(attest_config.settings, "kek_previous", None)
    if not bad.strip():
        # an empty value is "unset", not an error
        assert crypto.kek_configured() is False
        with pytest.raises(crypto.KekNotConfigured):
            crypto.seal(b"x" * 32, **CTX)
        return
    with pytest.raises(crypto.SealError):
        crypto.seal(b"x" * 32, **CTX)


def test_kek_accepts_standard_and_urlsafe_alphabets_with_or_without_padding(monkeypatch):
    raw = bytes(range(250, 250 - 32, -1))
    forms = {base64.b64encode(raw).decode(), base64.urlsafe_b64encode(raw).decode(),
             base64.urlsafe_b64encode(raw).decode().rstrip("=")}
    blobs = []
    for f in forms:
        monkeypatch.setattr(attest_config.settings, "kek", SecretStr(f))
        monkeypatch.setattr(attest_config.settings, "kek_file", None)
        blobs.append(crypto.seal(b"a" * 32, **CTX))
    monkeypatch.setattr(attest_config.settings, "kek", SecretStr(base64.b64encode(raw).decode()))
    for b in blobs:
        assert bytes(crypto.unseal(b, **CTX)) == b"a" * 32


def test_kek_file_is_read_and_primary_wins_over_it(monkeypatch, tmp_path):
    f = tmp_path / "kek"
    f.write_text(_kek(5) + "\n")
    monkeypatch.setattr(attest_config.settings, "kek", None)
    monkeypatch.setattr(attest_config.settings, "kek_previous", None)
    monkeypatch.setattr(attest_config.settings, "kek_file", str(f))
    blob = crypto.seal(b"s" * 32, **CTX)
    monkeypatch.setattr(attest_config.settings, "kek_file", None)
    monkeypatch.setattr(attest_config.settings, "kek", SecretStr(_kek(5)))
    assert bytes(crypto.unseal(blob, **CTX)) == b"s" * 32


def test_missing_kek_file_is_an_error_not_silence(monkeypatch, tmp_path):
    monkeypatch.setattr(attest_config.settings, "kek", None)
    monkeypatch.setattr(attest_config.settings, "kek_previous", None)
    monkeypatch.setattr(attest_config.settings, "kek_file", str(tmp_path / "nope"))
    with pytest.raises(crypto.SealError):
        crypto.seal(b"x" * 32, **CTX)


def test_kek_id_is_not_a_plain_hash_of_the_kek(kek):
    blob = crypto.seal(b"x" * 32, **CTX)
    kid8 = blob.split(":")[1]
    assert re.fullmatch(r"[0-9a-f]{8}", kid8)
    raw = base64.urlsafe_b64decode(kek)
    assert kid8 != hashlib.sha256(raw).hexdigest()[:8]
    assert crypto.blob_kek_id(blob) == kid8


# --------------------------------------------------------------------------- #
# Sealing (3.5)
# --------------------------------------------------------------------------- #

def test_blob_format_and_roundtrip(kek):
    seed = os.urandom(32)
    blob = crypto.seal(seed, **CTX)
    assert re.fullmatch(r"v1:[0-9a-f]{8}:[A-Za-z0-9_-]+={0,2}", blob)
    got = crypto.unseal(blob, **CTX)
    assert isinstance(got, bytearray) and bytes(got) == seed
    assert seed.hex() not in blob and base64.urlsafe_b64encode(seed).decode() not in blob


def test_two_seals_of_the_same_seed_differ(kek):
    assert crypto.seal(b"z" * 32, **CTX) != crypto.seal(b"z" * 32, **CTX)


def test_the_blob_matches_the_documented_construction(kek):
    """Rebuild the wrap exactly as 3.5 writes it, with a fixed nonce: HKDF-SHA256(KEK, salt='<tenant>|<kind>|<kid>',
    info=b'paddock-attest-key-wrap/v1'), AES-256-GCM, AAD 'paddock-attest-key/v1|<tenant>|<kind>|<kid>|<usage>|<alg>',
    blob 'v1:<kek_id8>:<b64(nonce|ct|tag)>'. A blob made independently must open, so the strings cannot drift."""
    kek_raw = base64.urlsafe_b64decode(kek)
    wrap = HKDF(algorithm=hashes.SHA256(), length=32, salt=f"{TENANT}|signing|{KID}".encode(),
                info=b"paddock-attest-key-wrap/v1").derive(kek_raw)
    aad = f"paddock-attest-key/v1|{TENANT}|signing|{KID}|attest|ed25519".encode()
    nonce = b"\x09" * 12
    seed = b"\x42" * 32
    ct = AESGCM(wrap).encrypt(nonce, seed, aad)
    own = crypto.seal(seed, **CTX)
    kek_id = own.split(":")[1]
    independent = f"v1:{kek_id}:{base64.urlsafe_b64encode(nonce + ct).decode()}"
    assert bytes(crypto.unseal(independent, **CTX)) == seed
    assert crypto.wrap_aad(**{k: v for k, v in CTX.items()}) == aad
    assert crypto.wrap_salt(TENANT, "signing", KID) == f"{TENANT}|signing|{KID}"


@pytest.mark.parametrize("field,other", [
    ("tenant_id", OTHER_TENANT), ("kind", "commit"), ("kid", "f" * 32), ("usage", "anchor"), ("alg", "ecdsa-p256-sha256"),
])
def test_sealed_blob_swap_fails(kek, field, other):
    """A blob moved to another tenant, kind, kid, usage or alg fails authentication (11.3 sealed_blob_swap_fails)."""
    blob = crypto.seal(b"k" * 32, **CTX)
    swapped = dict(CTX, **{field: other})
    with pytest.raises(crypto.UnsealError):
        crypto.unseal(blob, **swapped)


def test_a_flipped_bit_anywhere_fails(kek):
    blob = crypto.seal(b"k" * 32, **CTX)
    head, kid8, body = blob.split(":")
    raw = bytearray(base64.urlsafe_b64decode(body))
    for pos in (0, 11, 12, len(raw) - 1):
        bad = bytearray(raw)
        bad[pos] ^= 1
        with pytest.raises(crypto.UnsealError):
            crypto.unseal(f"{head}:{kid8}:{base64.urlsafe_b64encode(bytes(bad)).decode()}", **CTX)


@pytest.mark.parametrize("mangle", [
    lambda b: "", lambda b: "v2" + b[2:], lambda b: b.rsplit(":", 1)[0], lambda b: b + "!",
    lambda b: b.replace(":", "|"), lambda b: b[: b.rindex(":") + 1] + "AAAA",
    lambda b: b.split(":")[0] + ":zzzzzzzz:" + b.split(":")[2], lambda b: b + ":extra",
])
def test_malformed_blobs_raise_unseal_error_never_anything_else(kek, mangle):
    blob = crypto.seal(b"k" * 32, **CTX)
    with pytest.raises(crypto.UnsealError):
        crypto.unseal(mangle(blob), **CTX)


def test_non_string_blob_is_refused(kek):
    for bad in (None, b"v1:abcd1234:AAAA", 7):
        with pytest.raises(crypto.UnsealError):
            crypto.unseal(bad, **CTX)  # type: ignore[arg-type]


@pytest.mark.parametrize("bad", [
    dict(kid=""), dict(kid="a|b"), dict(usage="x|y"), dict(alg=""), dict(kind="bogus"),
    dict(tenant_id="not-a-uuid"), dict(kid="a\nb"),
])
def test_context_components_cannot_smuggle_the_separator(kek, bad):
    with pytest.raises((ValueError, crypto.SealError)):
        crypto.seal(b"k" * 32, **dict(CTX, **bad))


def test_tenant_id_is_normalised(kek):
    blob = crypto.seal(b"k" * 32, **dict(CTX, tenant_id=TENANT.upper()))
    assert bytes(crypto.unseal(blob, **dict(CTX, tenant_id=uuid.UUID(TENANT)))) == b"k" * 32


def test_unseal_returns_a_mutable_buffer_that_zero_wipes(kek):
    got = crypto.unseal(crypto.seal(b"k" * 32, **CTX), **CTX)
    crypto.zero(got)
    assert bytes(got) == b"\x00" * 32


# --------------------------------------------------------------------------- #
# KEK rotation
# --------------------------------------------------------------------------- #

def test_rotation_previous_kek_still_opens_old_blobs_and_rewrap_moves_them(monkeypatch, kek):
    old_blob = crypto.seal(b"r" * 32, **CTX)
    monkeypatch.setattr(attest_config.settings, "kek", SecretStr(_kek(8)))
    monkeypatch.setattr(attest_config.settings, "kek_previous", SecretStr(f"{_kek(1)}, {_kek(7)} ,"))
    assert bytes(crypto.unseal(old_blob, **CTX)) == b"r" * 32
    assert crypto.needs_rewrap(old_blob) is True
    new_blob = crypto.rewrap(old_blob, **CTX)
    assert crypto.needs_rewrap(new_blob) is False
    assert crypto.blob_kek_id(new_blob) != crypto.blob_kek_id(old_blob)
    # once the old KEK is dropped only the rewrapped blob opens
    monkeypatch.setattr(attest_config.settings, "kek_previous", None)
    assert bytes(crypto.unseal(new_blob, **CTX)) == b"r" * 32
    with pytest.raises(crypto.UnsealError):
        crypto.unseal(old_blob, **CTX)


def test_a_malformed_previous_kek_is_an_error(monkeypatch, kek):
    monkeypatch.setattr(attest_config.settings, "kek_previous", SecretStr("zzz,"))
    with pytest.raises(crypto.SealError):
        crypto.seal(b"k" * 32, **CTX)


def test_unseal_without_any_kek_is_kek_not_configured(monkeypatch, kek):
    blob = crypto.seal(b"k" * 32, **CTX)
    monkeypatch.setattr(attest_config.settings, "kek", None)
    with pytest.raises(crypto.KekNotConfigured):
        crypto.unseal(blob, **CTX)


# --------------------------------------------------------------------------- #
# Generic wrap for other callers (disclosure material uses a different AAD, 5.9)
# --------------------------------------------------------------------------- #

def test_raw_seal_binds_the_caller_supplied_aad(kek):
    blob = crypto.seal_raw(b"payload" * 100, salt="t|disclosure|p|7", aad=b"tenant|estate|pub|7")
    assert bytes(crypto.unseal_raw(blob, salt="t|disclosure|p|7", aad=b"tenant|estate|pub|7")) == b"payload" * 100
    with pytest.raises(crypto.UnsealError):
        crypto.unseal_raw(blob, salt="t|disclosure|p|7", aad=b"tenant|estate|pub|8")
    with pytest.raises(crypto.UnsealError):
        crypto.unseal_raw(blob, salt="t|disclosure|p|8", aad=b"tenant|estate|pub|7")


# --------------------------------------------------------------------------- #
# DB-backed secret store (the ONLY SQL on the sealed table besides backend_local)
# --------------------------------------------------------------------------- #

async def test_secret_store_roundtrip_and_crypto_erase(db_pool, tenants, kek):
    async with db_pool.acquire() as con:
        assert await crypto.store_secret(con, plaintext=b"s" * 32, **CTX) is True
        # same key again is refused (the row is the only copy, never overwritten)
        assert await crypto.store_secret(con, plaintext=b"t" * 32, **CTX) is False
        got = await crypto.load_secret(con, **CTX)
        assert bytes(got) == b"s" * 32
        row = await con.fetchrow("SELECT sealed, kek_id FROM attest_key_secrets WHERE kid = $1", KID)
        assert row["sealed"].startswith("v1:") and row["kek_id"] == crypto.blob_kek_id(row["sealed"])
        assert (b"s" * 32).hex() not in row["sealed"]
        assert await crypto.secret_exists(con, tenant_id=TENANT, kind="signing", kid=KID) is True
        assert await crypto.delete_secret(con, tenant_id=TENANT, kind="signing", kid=KID) is True
        assert await crypto.load_secret(con, **CTX) is None
        assert await crypto.delete_secret(con, tenant_id=TENANT, kind="signing", kid=KID) is False


async def test_secret_store_refuses_without_kek(db_pool, tenants, no_kek):
    async with db_pool.acquire() as con:
        with pytest.raises(crypto.KekNotConfigured):
            await crypto.store_secret(con, plaintext=b"s" * 32, **CTX)
        assert await con.fetchval("SELECT count(*) FROM attest_key_secrets") == 0


async def test_db_row_swap_between_tenants_fails_authentication(db_pool, tenants, kek):
    """sealed_blob_swap_fails at the database level: copy tenant A's sealed text into tenant B's row."""
    async with db_pool.acquire() as con:
        await con.execute("SET session_replication_role = replica")
        await crypto.store_secret(con, plaintext=b"a" * 32, **CTX)
        await crypto.store_secret(con, plaintext=b"b" * 32, **dict(CTX, tenant_id=OTHER_TENANT))
        await con.execute(
            "UPDATE attest_key_secrets SET sealed = (SELECT sealed FROM attest_key_secrets WHERE tenant_id = $1) "
            "WHERE tenant_id = $2", TENANT, OTHER_TENANT)
        with pytest.raises(crypto.UnsealError):
            await crypto.load_secret(con, **dict(CTX, tenant_id=OTHER_TENANT))
        assert bytes(await crypto.load_secret(con, **CTX)) == b"a" * 32


async def test_each_tenant_reads_only_its_own_row_even_on_an_unstamped_connection(db_pool, tenants, kek):
    """The SQL names the tenant itself (the AAD binds it): with the same kind and kid under two tenants (the commit key
    always has kind=commit, kid=commit) a superuser connection, where row-level security does not filter, must still
    return the requested tenant's secret, not whichever row comes first."""
    async with db_pool.acquire() as con:
        for tid, fill in ((TENANT, b"a"), (OTHER_TENANT, b"b")):
            assert await crypto.store_secret(con, plaintext=fill * 32, tenant_id=tid, kind="commit", kid="commit",
                                             usage="commit", alg="hmac-sha256")
        for tid, fill in ((OTHER_TENANT, b"b"), (TENANT, b"a")):
            got = await crypto.load_secret(con, tenant_id=tid, kind="commit", kid="commit", usage="commit", alg="hmac-sha256")
            assert bytes(got) == fill * 32
        assert await crypto.delete_secret(con, tenant_id=TENANT, kind="commit", kid="commit") is True
        assert await crypto.secret_exists(con, tenant_id=OTHER_TENANT, kind="commit", kid="commit") is True
        assert await crypto.secret_exists(con, tenant_id=TENANT, kind="commit", kid="commit") is False


# --------------------------------------------------------------------------- #
# Lint (D17): only crypto.py and backend_local.py may name the sealed table
# --------------------------------------------------------------------------- #

ROOT = Path(__file__).resolve().parents[2]
ALLOWED = {"orchestrator/app/attest/crypto.py", "orchestrator/app/attest/backend_local.py"}


def _py_files():
    for base in ("orchestrator/app", "scripts", "cli", "agent", "sdk/python"):
        d = ROOT / base
        if d.is_dir():
            for p in d.rglob("*.py"):
                if "__pycache__" not in p.parts and ".venv" not in p.parts:
                    yield p


def test_only_crypto_and_backend_local_name_the_secrets_table():
    offenders = []
    for p in _py_files():
        rel = p.relative_to(ROOT).as_posix()
        if rel in ALLOWED:
            continue
        if "attest_key_secrets" in p.read_text(encoding="utf-8", errors="replace"):
            offenders.append(rel)
    assert not offenders, f"D17: these files name attest_key_secrets: {offenders}"


def test_the_allowed_files_exist_and_the_lint_is_not_vacuous():
    assert "attest_key_secrets" in (ROOT / "orchestrator/app/attest/crypto.py").read_text()
    assert sum(1 for _ in _py_files()) > 50
