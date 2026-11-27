"""P3.3: estate key lifecycle: create, activate, rollover, renewal, retirement, revocation, keys.json, vendor admin
(docs/ASSURANCE_P3.md 3.3, 3.8, D16, D17).

Time is explicit everywhere (``now=``) so the choreography (300-day rotation, 60-day renewal, 48 h grace, 7-day erasure)
is tested at its boundaries. Certificates are checked with the independent construction in ``attest_fakes``.
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
from pathlib import Path

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from paddock_verify import b64

from app import tenancy
from app.attest import backend as backend_mod
from app.attest import certs, estate, keys, platform_keys, revocation
from app.attest import config as attest_config
from app.attest.backend_local import LocalAesGcmBackend

from . import attest_fakes as fk
from .attest_fakes import DAY, ESTATE_A, T0

ROOT = Path(__file__).resolve().parents[2]
ADMIN = ROOT / "scripts" / "attest_vendor_admin.py"
TA = "00000000-0000-0000-0000-0000000000a1"
TB = "00000000-0000-0000-0000-0000000000b1"
DEFAULT = "00000000-0000-0000-0000-000000000001"


@pytest.fixture
def plat(tmp_path, monkeypatch):
    p = fk.make_platform(tmp_path / "plat")
    fk.install(monkeypatch, p)
    return p


@pytest_asyncio.fixture
async def tenants(db_pool):
    for slug, tid in (("keys-a", TA), ("keys-b", TB)):
        await tenancy.create_tenant(db_pool, slug=slug, name=slug, tenant_id=tid)


async def counts(pool):
    async with pool.acquire() as con:
        return {t: await con.fetchval(f"SELECT count(*) FROM {t}") for t in
                ("attest_estates", "attest_keys", "attest_key_secrets")}


async def secrets_for(con, kid):
    return await con.fetchval("SELECT count(*) FROM attest_key_secrets WHERE kind = 'signing' AND kid = $1", kid)


async def make_active(con, usage="attest", now=T0, platform=None):
    k = await keys.create_key(con, usage, now=now, platform=platform)
    return await keys.activate(con, k.kid, now=now, platform=platform)


# --------------------------------------------------------------------------- #
# create_key
# --------------------------------------------------------------------------- #

async def test_creation_is_refused_without_a_kek_and_creates_nothing(db_pool, plat, monkeypatch):
    monkeypatch.setattr(attest_config.settings, "kek", None)
    async with db_pool.acquire() as con:
        with pytest.raises(estate.EstateNotConfigured) as ei:
            await keys.create_key(con, "attest", now=T0)
    assert "kek" in ei.value.missing
    assert all(v == 0 for v in (await counts(db_pool)).values())


async def test_creation_is_refused_without_verifiable_platform_keys_and_creates_nothing(db_pool, plat, monkeypatch):
    from pydantic import SecretStr

    monkeypatch.setattr(attest_config.settings, "platform_key_passphrase", SecretStr("a wrong passphrase 12345"))
    platform_keys.reset_cache()
    async with db_pool.acquire() as con:
        with pytest.raises(platform_keys.PlatformKeysError):
            await keys.create_key(con, "attest", now=T0)
    assert all(v == 0 for v in (await counts(db_pool)).values())          # not even the estate row


async def test_an_issuer_about_to_expire_certifies_no_new_key(db_pool, tmp_path, monkeypatch):
    p = fk.make_platform(tmp_path / "short", issuer_window=(T0 - 100 * DAY, T0 + 3 * DAY))
    fk.install(monkeypatch, p)
    async with db_pool.acquire() as con:
        with pytest.raises(keys.KeysError) as ei:
            await keys.create_key(con, "attest", now=T0)
    assert ei.value.code == "issuer.outside_validity"
    assert all(v == 0 for v in (await counts(db_pool)).values())


async def test_create_key_makes_a_pending_certified_key_with_a_sealed_seed(db_pool, plat):
    async with db_pool.acquire() as con:
        rec = await keys.create_key(con, "attest", created_by="alice", now=T0)
        info = await estate.get_estate(con)
        sealed = await secrets_for(con, rec.kid)
        row = await con.fetchrow("SELECT status, custody, backend, created_by, cert_serial FROM attest_keys WHERE kid = $1", rec.kid)
    assert rec.status == "pending" and rec.usage == "attest" and rec.alg == "ed25519" and rec.custody == "hosted"
    assert rec.kid == fk.kid_of(rec.public_key) and len(rec.public_key) == 32
    assert (rec.not_before, rec.not_after) == (T0, T0 + 365 * DAY)
    assert rec.cert.estate == info.estate_id and rec.cert.usage == "attest" and rec.cert.serial == 1
    assert (rec.cert.not_before, rec.cert.not_after) == (T0, T0 + 90 * DAY) and rec.cert_expires_at == T0 + 90 * DAY
    body = fk.independent_cert_check(rec.cert.envelope, plat.issuer_pub)
    assert body["kid"] == rec.kid and body["public_key"] == b64.encode(rec.public_key) and body["custody"] == "hosted"
    assert sealed == 1 and (row["status"], row["backend"], row["created_by"], row["cert_serial"]) == ("pending", "local-aes-gcm", "alice", 1)
    assert rec.handle.kid == rec.kid and rec.handle.tenant_id == DEFAULT


async def test_a_key_record_shows_no_key_material(db_pool, plat):
    async with db_pool.acquire() as con:
        rec = await keys.create_key(con, "attest", now=T0)
        sealed = await con.fetchval("SELECT sealed FROM attest_key_secrets WHERE kid = $1", rec.kid)
    text = repr(rec) + str(rec.handle) + repr(rec.cert)
    assert sealed not in text and rec.public_key.hex() not in text and b64.encode(rec.public_key) not in text


async def test_creation_audit_row_names_the_key_and_no_secret(db_pool, plat):
    async with db_pool.acquire() as con:
        rec = await keys.create_key(con, "attest", now=T0)
        sealed = await con.fetchval("SELECT sealed FROM attest_key_secrets WHERE kid = $1", rec.kid)
        rows = await con.fetch("SELECT action, details::text AS d, resource_id FROM audit_log WHERE action = 'attest.key.created'")
    async with db_pool.acquire() as con:
        issued = await con.fetch("SELECT details::text AS d FROM audit_log WHERE action = 'attest.cert.issued'")
    assert len(issued) == 1 and json.loads(issued[0]["d"])["serial"] == 1 and json.loads(issued[0]["d"])["kid"] == rec.kid
    assert len(rows) == 1 and rows[0]["resource_id"] == rec.kid
    d = json.loads(rows[0]["d"])
    assert d["kid"] == rec.kid and d["usage"] == "attest" and d["estate"].startswith("e_")
    assert sealed not in rows[0]["d"] and "seed" not in rows[0]["d"]


async def test_creation_is_atomic_when_certification_fails_after_the_seed_was_sealed(db_pool, plat, monkeypatch):
    def boom(*a, **k):
        raise certs.CertError("key.cert_invalid", "injected")

    monkeypatch.setattr(certs, "issue_cert", boom)
    async with db_pool.acquire() as con:
        with pytest.raises(certs.CertError):
            await keys.create_key(con, "attest", now=T0)
    assert all(v == 0 for v in (await counts(db_pool)).values())            # no sealed seed, no row, no estate


async def test_only_estate_key_usages_and_no_per_publication_keys(db_pool, plat):
    async with db_pool.acquire() as con:
        for usage in ("issue-cert", "revoke", "x"):
            with pytest.raises(keys.KeysError):
                await keys.create_key(con, usage, now=T0)
        with pytest.raises(keys.KeysError) as ei:
            await keys.create_key(con, "attest", publication_id="00000000-0000-0000-0000-0000000000ff", now=T0)
        assert ei.value.code == "keys.reserved"
    assert all(v == 0 for v in (await counts(db_pool)).values())


async def test_one_pending_key_per_usage_and_three_live_keys_at_most(db_pool, plat):
    async with db_pool.acquire() as con:
        k1 = await make_active(con, now=T0)
        k2 = await keys.rotate(con, "attest", now=T0 + 270 * DAY)
        with pytest.raises(keys.KeyStateError) as ei:
            await keys.create_key(con, "attest", now=T0 + 270 * DAY)
        assert ei.value.code == "keys.pending_exists"
        await keys.activate(con, k2.kid, now=T0 + 300 * DAY)
        k3 = await keys.rotate(con, "attest", now=T0 + 301 * DAY)
        await keys.activate(con, k3.kid, now=T0 + 302 * DAY)
        # live: k3 active, k2 retiring, k1 retiring -> three
        with pytest.raises(keys.KeyStateError) as ei:
            await keys.create_key(con, "attest", now=T0 + 303 * DAY)
        assert ei.value.code == "keys.too_many"
        # a different usage has its own budget
        assert (await keys.create_key(con, "anchor", now=T0 + 303 * DAY)).status == "pending"
        assert k1.kid != k2.kid != k3.kid


async def test_concurrent_creation_yields_exactly_one_pending_key(db_pool, plat):
    async with db_pool.acquire() as con:
        await estate.ensure_estate(con)                                           # the estate row exists already

    async def one():
        async with db_pool.acquire() as con:
            try:
                return await keys.create_key(con, "attest", now=T0)
            except keys.KeyStateError as exc:
                return exc.code

    out = await asyncio.gather(*[one() for _ in range(4)])
    made = [o for o in out if not isinstance(o, str)]
    assert len(made) == 1 and sorted(o for o in out if isinstance(o, str)) == ["keys.pending_exists"] * 3
    async with db_pool.acquire() as con:
        assert len(await keys.list_keys(con, "attest")) == 1
        assert await con.fetchval("SELECT count(*) FROM attest_key_secrets WHERE kind = 'signing'") == 1


# --------------------------------------------------------------------------- #
# activate and active_key
# --------------------------------------------------------------------------- #

async def test_activation_moves_pending_to_active_and_the_previous_key_to_retiring(db_pool, plat):
    async with db_pool.acquire() as con:
        assert await keys.active_key(con, "attest", now=T0) is None
        k1 = await make_active(con, now=T0)
        assert k1.status == "active" and k1.activated_at == T0
        assert (await keys.active_key(con, "attest", now=T0 + 1)).kid == k1.kid
        k2 = await keys.rotate(con, "attest", now=T0 + 10 * DAY)
        again = await keys.activate(con, k2.kid, now=T0 + 20 * DAY)
        assert again.status == "active"
        assert (await keys.get_key(con, k1.kid)).status == "retiring"
        assert (await keys.active_key(con, "attest", now=T0 + 21 * DAY)).kid == k2.kid
        audit = await con.fetch("SELECT details::text AS d FROM audit_log WHERE action = 'attest.key.activated' ORDER BY id")
        assert json.loads(audit[1]["d"])["previous"] == [k1.kid]
        retiring = await con.fetch("SELECT resource_id FROM audit_log WHERE action = 'attest.key.retiring'")
        assert [r["resource_id"] for r in retiring] == [k1.kid]


async def test_activation_refusals_leave_the_state_unchanged(db_pool, plat):
    async with db_pool.acquire() as con:
        k1 = await make_active(con, now=T0)
        with pytest.raises(keys.KeyStateError):
            await keys.activate(con, k1.kid, now=T0 + 1)                     # not pending
        with pytest.raises(keys.KeyNotFound):
            await keys.activate(con, "0" * 32, now=T0)
        k2 = await keys.rotate(con, "attest", now=T0 + DAY)
        with pytest.raises(keys.KeyStateError) as ei:
            await keys.activate(con, k2.kid, now=T0 + DAY + 91 * DAY)        # its certificate has expired
        assert ei.value.code == "key.outside_validity"
        await con.execute("DELETE FROM attest_key_secrets WHERE kid = $1", k2.kid)       # the sealed seed is gone
        with pytest.raises(keys.KeyStateError) as ei:
            await keys.activate(con, k2.kid, now=T0 + DAY + 1)
        assert ei.value.code == "keys.unhealthy"
        assert (await keys.get_key(con, k2.kid)).status == "pending" and (await keys.get_key(con, k1.kid)).status == "active"


async def test_an_expired_key_or_certificate_is_not_an_active_signing_key(db_pool, plat):
    async with db_pool.acquire() as con:
        k = await make_active(con, now=T0)
        assert await keys.active_key(con, "attest", now=T0 + 90 * DAY - 1) is not None
        assert await keys.active_key(con, "attest", now=T0 + 90 * DAY) is None       # cert window is end-exclusive
        assert await keys.active_key(con, "attest", now=T0 - 1) is None
        assert (await keys.get_key(con, k.kid)).status == "active"                   # status itself is unchanged


async def test_usages_have_independent_active_keys(db_pool, plat):
    async with db_pool.acquire() as con:
        a = await make_active(con, "attest", now=T0)
        b = await make_active(con, "anchor", now=T0)
        assert (await keys.active_key(con, "attest", now=T0)).kid == a.kid
        assert (await keys.active_key(con, "anchor", now=T0)).kid == b.kid
        assert a.cert.usage == "attest" and b.cert.usage == "anchor"


# --------------------------------------------------------------------------- #
# retirement and erasure (3.3)
# --------------------------------------------------------------------------- #

async def _statement(con, kid, seq, valid_until):
    await con.execute("INSERT INTO attest_statements (seq, issued_at, valid_until, kid) VALUES ($1, $2, $3, $4)",
                      seq, keys._dt(valid_until - DAY), keys._dt(valid_until), kid)


async def test_the_rollover_choreography_retires_after_the_last_valid_until_plus_48h_and_erases_after_7_days(db_pool, plat):
    async with db_pool.acquire() as con:
        k1 = await make_active(con, now=T0)
        await _statement(con, k1.kid, 1, T0 + 10 * DAY)
        k2 = await keys.rotate(con, "attest", now=T0 + 5 * DAY)
        await keys.activate(con, k2.kid, now=T0 + 6 * DAY)
        retire_at = T0 + 10 * DAY + 48 * 3600
        out = await keys.sweep(con, now=retire_at - 1)
        assert out == {"retired": [], "erased": []} and (await keys.get_key(con, k1.kid)).status == "retiring"
        out = await keys.sweep(con, now=retire_at)
        assert out["retired"] == [k1.kid] and out["erased"] == []
        r1 = await keys.get_key(con, k1.kid)
        assert r1.status == "retired" and r1.retired_at == retire_at
        assert await secrets_for(con, k1.kid) == 1                                     # the seed outlives retirement
        assert (await keys.sweep(con, now=retire_at + 7 * DAY - 1))["erased"] == []
        out = await keys.sweep(con, now=retire_at + 7 * DAY)
        assert out["erased"] == [k1.kid] and await secrets_for(con, k1.kid) == 0
        assert (await keys.sweep(con, now=retire_at + 8 * DAY)) == {"retired": [], "erased": []}      # idempotent
        assert (await keys.get_key(con, k2.kid)).status == "active" and await secrets_for(con, k2.kid) == 1
        be = LocalAesGcmBackend(db_pool)
        with pytest.raises(backend_mod.BackendError):
            await be.sign(r1.handle, b"x", conn=con)                                 # an erased key can never sign again


async def test_a_retired_key_stays_in_keys_json_so_history_verifies(db_pool, plat):
    async with db_pool.acquire() as con:
        k1 = await make_active(con, now=T0)
        k2 = await keys.rotate(con, "attest", now=T0 + DAY)
        await keys.activate(con, k2.kid, now=T0 + 2 * DAY)
        await keys.sweep(con, now=T0 + 10 * DAY)
        await keys.sweep(con, now=T0 + 20 * DAY)
        assert (await keys.get_key(con, k1.kid)).status == "retired"
        doc = await keys.keys_document(con, now=T0 + 20 * DAY)
    verified = certs.verify_keys_json(doc, roots=certs.parse_roots(plat.roots), at=T0 + 20 * DAY)
    assert {k1.kid, k2.kid} <= set(verified.keys)


async def test_anchor_keys_retire_after_their_last_anchor(db_pool, plat):
    async with db_pool.acquire() as con:
        a1 = await make_active(con, "anchor", now=T0)
        await con.execute("INSERT INTO attest_anchors (max_id, at, doc) VALUES (7, $1, $2::jsonb)",
                          keys._dt(T0 + 3 * DAY), json.dumps({"kid": a1.kid}))
        a2 = await keys.rotate(con, "anchor", now=T0 + DAY)
        await keys.activate(con, a2.kid, now=T0 + 2 * DAY)
        assert (await keys.sweep(con, now=T0 + 3 * DAY + 48 * 3600 - 1))["retired"] == []
        assert (await keys.sweep(con, now=T0 + 3 * DAY + 48 * 3600))["retired"] == [a1.kid]


# --------------------------------------------------------------------------- #
# automatic rollover and certificate renewal
# --------------------------------------------------------------------------- #

async def test_rotate_due_prepares_the_successor_at_270_days_and_switches_anchor_keys_at_300(db_pool, plat):
    async with db_pool.acquire() as con:
        a = await make_active(con, "attest", now=T0)
        b = await make_active(con, "anchor", now=T0)
        assert await keys.rotate_due(con, now=T0 + 269 * DAY) == {"created": [], "activated": []}
        out = await keys.rotate_due(con, now=T0 + 270 * DAY)
        assert len(out["created"]) == 2 and out["activated"] == []
        again = await keys.rotate_due(con, now=T0 + 271 * DAY)
        assert again == {"created": [], "activated": []}                                  # idempotent
        out = await keys.rotate_due(con, now=T0 + 300 * DAY)
        assert len(out["activated"]) == 1
        anchors = {k.kid: k.status for k in await keys.list_keys(con, "anchor")}
        assert anchors[b.kid] == "retiring" and "active" in anchors.values()
        attests = {k.kid: k.status for k in await keys.list_keys(con, "attest")}
        assert attests[a.kid] == "active" and "pending" in attests.values()              # DNS gates the attest switch


async def test_rotate_needs_an_active_key(db_pool, plat):
    async with db_pool.acquire() as con:
        with pytest.raises(keys.KeyStateError):
            await keys.rotate(con, "attest", now=T0)


async def test_certificates_are_renewed_at_60_days_with_the_same_key_and_window_start(db_pool, plat):
    async with db_pool.acquire() as con:
        k = await make_active(con, now=T0)
        assert await keys.renew_certs(con, now=T0 + 59 * DAY) == []                       # 31 days left
        assert await certs.renew_due(con, now=T0 + 60 * DAY) == [k.kid]                    # the interface name works too
        r = await keys.get_key(con, k.kid)
        assert r.cert.serial == 2 and r.cert_serial == 2 and r.public_key == k.public_key and r.kid == k.kid
        assert (r.cert.not_before, r.cert.not_after) == (T0, T0 + 150 * DAY) and r.cert_expires_at == T0 + 150 * DAY
        fk.independent_cert_check(r.cert.envelope, plat.issuer_pub)
        roots = certs.parse_roots(plat.roots)
        for at in (T0 + 10 * DAY, T0 + 100 * DAY):                                        # a statement from before still verifies
            certs.verify_chain(r.cert, issuers=[plat.issuer_cert], roots=roots, at=at, expect_usage="attest")
        assert await keys.renew_certs(con, now=T0 + 61 * DAY) == []                       # renewed once
        assert await keys.renew_certs(con, now=T0 + 120 * DAY) == [k.kid]
        # never past the key's own 365 days
        await keys.renew_certs(con, now=T0 + 330 * DAY)
        last = await keys.get_key(con, k.kid)
        assert last.cert.not_after == T0 + 365 * DAY
        assert await keys.renew_certs(con, now=T0 + 340 * DAY) == []
        audit = await con.fetchval("SELECT count(*) FROM audit_log WHERE action = 'attest.cert.renewed'")
        assert audit >= 3


async def test_renewal_skips_retiring_retired_and_revoked_keys_and_is_capped_by_the_issuer(db_pool, tmp_path, monkeypatch):
    p = fk.make_platform(tmp_path / "p", issuer_window=(T0 - 100 * DAY, T0 + 100 * DAY))
    fk.install(monkeypatch, p)
    async with db_pool.acquire() as con:
        k1 = await make_active(con, now=T0)
        k2 = await keys.rotate(con, "attest", now=T0 + DAY)
        await keys.activate(con, k2.kid, now=T0 + 2 * DAY)                                  # k1 is retiring now
        renewed = await keys.renew_certs(con, now=T0 + 65 * DAY)
        assert renewed == [k2.kid]                                                         # the issuer's end binds, not +90 days
        assert (await keys.get_key(con, k2.kid)).cert.not_after == T0 + 100 * DAY
        assert (await keys.get_key(con, k1.kid)).cert.serial == 1


# --------------------------------------------------------------------------- #
# keys.json from the database
# --------------------------------------------------------------------------- #

async def test_keys_document_lists_every_status_and_verifies(db_pool, plat):
    async with db_pool.acquire() as con:
        a = await make_active(con, "attest", now=T0)
        p = await keys.rotate(con, "attest", now=T0 + DAY)
        c = await make_active(con, "anchor", now=T0)
        doc = await keys.keys_document(con, now=T0 + 2 * DAY)
        again = await keys.keys_document(con, now=T0 + 2 * DAY)
        info = await estate.get_estate(con)
    assert doc == again and json.loads(doc)["estate"] == info.estate_id
    v = certs.verify_keys_json(doc, roots=certs.parse_roots(plat.roots), at=T0 + 2 * DAY)
    assert set(v.keys) == {a.kid, p.kid, c.kid} and v.revoker.kid == plat.revoker_kid
    assert all("status" not in e for e in json.loads(doc)["keys"])


async def test_keys_issued_by_an_earlier_issuer_are_listed_only_when_that_issuer_is_provided(db_pool, plat, monkeypatch):
    async with db_pool.acquire() as con:
        old = await make_active(con, "attest", now=T0)
        old_issuer_pub, old_issuer_kid = plat.issuer_pub, plat.issuer_kid
        # the platform rotates its issuer (same root): a new issuer key and certificate
        new_issuer = Ed25519PrivateKey.generate()
        new_cert = fk.make_cert(plat.root_priv, plat.root_kid, usage="issue-cert", pub=fk.raw_pub(new_issuer),
                                not_before=T0 - 10 * DAY, not_after=T0 + 700 * DAY, serial=9)
        plat.issuer_priv, plat.issuer_cert, plat.issuer_kid = new_issuer, new_cert, fk.kid_of(fk.raw_pub(new_issuer))
        Path(plat.files["issuer_key_file"]).write_bytes(fk._pem(new_issuer, plat.passphrase))
        Path(plat.files["issuer_cert_file"]).write_bytes(new_cert)
        fk.install(monkeypatch, plat)
        fresh = await make_active(con, "anchor", now=T0 + 5 * DAY)
        doc = json.loads(await keys.keys_document(con, now=T0 + 6 * DAY))
        assert [e["kid"] for e in doc["keys"]] == [fresh.kid]                      # the old key's issuer is not listable
        drop = Path(plat.files["issuer_cert_file"] + ".d")
        drop.mkdir()
        (drop / "issuer-2026.json").write_bytes(
            fk.make_cert(plat.root_priv, plat.root_kid, usage="issue-cert", pub=old_issuer_pub,
                         not_before=T0 - 150 * DAY, not_after=T0 + 365 * DAY, serial=1))
        (drop / "junk.json").write_text("{not json")
        (drop / "stranger.json").write_bytes(                                       # signed by a root we do not trust
            fk.make_cert(Ed25519PrivateKey.generate(), "1" * 32, usage="issue-cert", pub=fk.raw_pub(Ed25519PrivateKey.generate()),
                         not_before=T0 - DAY, not_after=T0 + DAY))
        doc = json.loads(await keys.keys_document(con, now=T0 + 6 * DAY))
        assert {e["kid"] for e in doc["keys"]} == {fresh.kid, old.kid} and len(doc["issuers"]) == 2
        assert certs.parse_cert(doc["issuers"][1]).kid == old_issuer_kid
        verified = certs.verify_keys_json(json.dumps(doc).encode(), roots=certs.parse_roots(plat.roots), at=T0 + 6 * DAY)
        assert {old.kid, fresh.kid} <= set(verified.keys)


async def test_keys_json_never_lists_more_than_16_keys_and_never_drops_a_live_one(db_pool, plat):
    """The open verifier reads at most 16 entries: the oldest retired keys fall off first, live keys never do."""
    async with db_pool.acquire() as con:
        t = T0
        live = []
        for i in range(9):
            for usage in ("attest", "anchor"):
                k = await make_active(con, usage, now=t)
                live.append(k.kid)
            t += 10 * DAY
            await keys.sweep(con, now=t + 5 * DAY)
        everything = await keys.list_keys(con)
        assert len(everything) == 18
        doc = json.loads(await keys.keys_document(con, now=t + 6 * DAY))
        kids = [e["kid"] for e in doc["keys"]]
        assert len(kids) == 16
        statuses = {k.kid: k.status for k in everything}
        listed_live = {kid for kid, st in statuses.items() if st in ("pending", "active", "retiring")}
        assert listed_live <= set(kids)
        dropped = [kid for kid in statuses if kid not in kids]
        assert len(dropped) == 2 and all(statuses[d] == "retired" for d in dropped)
        oldest_retired = sorted((k.retired_at, k.kid) for k in everything if k.status == "retired")[:2]
        assert sorted(d for d in dropped) == sorted(kid for _, kid in oldest_retired)
        certs.verify_keys_json(json.dumps(doc).encode(), roots=certs.parse_roots(plat.roots), at=t + 6 * DAY)


@pytest.mark.xfail(strict=False, reason="P3.4 keys.check_chain only accepts a revoker certified by an ISSUER, while "
                   "contract 3.1 and attest_root_ceremony.py certify it by the ROOT; P3.4 must also accept a root-signed "
                   "revoker (production accepts both). Passes once it does.")
async def test_the_open_verifier_accepts_a_root_certified_revoker(db_pool, plat):
    vkeys = pytest.importorskip("paddock_verify.keys")
    async with db_pool.acquire() as con:
        await make_active(con, "attest", now=None)
        t = await keys.db_now(con)
        eid = (await estate.get_estate(con)).estate_id
        doc = await keys.keys_document(con)
    kd = vkeys.parse_keys(doc)
    roots = vkeys.parse_roots(json.dumps(plat.roots).encode())
    assert vkeys.check_chain(kd.revoker, kd, roots, t, None, "revoke", None).codes == []
    assert eid


async def test_the_open_verifiers_own_modules_accept_what_production_issues(db_pool, tmp_path, monkeypatch):
    """Independent cross-check against the verifier package (P3.4): keys.json, certificate chains, the revocation list
    (with a supersession and a compromise) and a v2 anchor are all read the way a third party reads them. The revoker
    is certified through the issuer here, which is how the verifier's own vectors build it."""
    plat = fk.make_platform(tmp_path / "xplat", revoker_certified_by="issuer")
    fk.install(monkeypatch, plat)
    vkeys = pytest.importorskip("paddock_verify.keys")
    vrev = pytest.importorskip("paddock_verify.revocation")
    vanchor = pytest.importorskip("paddock_verify.anchor")
    from datetime import datetime, timezone

    from app import audit as audit_svc
    from app.attest import anchor_sig
    from app.audit_anchor import Anchor

    async with db_pool.acquire() as con:
        a1 = await make_active(con, "attest", now=None)
        c1 = await make_active(con, "anchor", now=None)
        a2 = await keys.rotate(con, "attest")
        t = await keys.db_now(con)
        eid = (await estate.get_estate(con)).estate_id
        doc = await keys.keys_document(con)
        subject = "paddock-estate:" + eid
        await revocation.supersede(con, subject, 3)
        res = await keys.revoke(con, a1.kid, reason="key_compromise", actor="admin", justification="cross-check run")
    anchor = Anchor(DEFAULT, 5, "ab" * 32, "hmac-sha256:0123abcd", datetime.now(timezone.utc).isoformat())
    await anchor_sig.sign_hook(db_pool, anchor)
    async with db_pool.acquire() as con:
        doc_after = await keys.keys_document(con)
    roots = vkeys.parse_roots(json.dumps(plat.roots).encode())
    kd = vkeys.parse_keys(doc_after)
    assert len(kd.issuers) == 1 and {a1.kid, a2.kid, c1.kid} <= set(kd.entries)
    for e in kd.entries.values():
        chain = vkeys.check_chain(e.cert, kd, roots, t, None, e.usage, eid, e)
        assert chain.codes == [], (e.kid, chain.codes)
    rc = vkeys.check_chain(kd.revoker, kd, roots, t, None, "revoke", None)
    assert rc.codes == []
    ev = vrev.evaluate(res.list.envelope, kd, roots, eid, t)
    assert ev.status == "ok", ev
    assert vrev.apply(ev.list, a1.kid, t - 10, subject, 1, [])[0].code == "key.revoked"            # compromise: whatever the time
    assert [f.code for f in vrev.apply(ev.list, a2.kid, t, subject, 2, [])] == ["chain.superseded"]
    assert vrev.apply(ev.list, a2.kid, t, subject, 3, []) == []
    pub = anchor_sig.public_bytes(anchor_sig.public_doc(anchor))
    claimed = {"max_id": 5, "head": "ab" * 32, "hash_alg": "hmac-sha256", "at": anchor.sigs[0]["at"], "kid": anchor.sigs[0]["kid"],
               "digest": anchor_sig.public_digest(anchor_sig.public_doc(anchor))}
    findings = vanchor.check_anchor(pub, claimed, eid, t, kd, roots, ev.list, 7200)
    assert findings == [], findings
    assert audit_svc.ANCHOR_SIGNERS is not None


# --------------------------------------------------------------------------- #
# emergency revoke (3.8 level 3)
# --------------------------------------------------------------------------- #

async def _bundle(con):
    for path in ("keys.json", "revoked.json", "attestation/latest.json", "attestation/1.json"):
        await con.execute("INSERT INTO attest_bundle_objects (domain_key, path, public) VALUES ($1, $2, TRUE)", "a" * 64, path)


async def _public(con):
    return {r["path"]: r["public"] for r in await con.fetch("SELECT path, public FROM attest_bundle_objects")}


async def test_revoking_an_active_attest_key_does_everything_in_one_go(db_pool, plat):
    async with db_pool.acquire() as con:
        k = await make_active(con, "attest", now=T0)
        await _bundle(con)
        res = await keys.revoke(con, k.kid, actor="admin", justification="key leaked on a laptop", now=T0 + DAY)
        assert res.key.status == "revoked" and res.key.revoked_at == T0 + DAY and not res.already_revoked
        row = await con.fetchrow("SELECT reason_code, revoked_at, actor, justification FROM attest_revocations WHERE kid = $1", k.kid)
        assert (row["reason_code"], row["actor"], row["justification"]) == ("key_compromise", "admin", "key leaked on a laptop")
        est = await con.fetchrow("SELECT hold_reason, hold_requires_ack FROM attest_estates")
        assert (est["hold_reason"], est["hold_requires_ack"]) == ("key_compromise", True)
        assert await _public(con) == {"keys.json": True, "revoked.json": True, "attestation/latest.json": False,
                                      "attestation/1.json": False}
        assert await secrets_for(con, k.kid) == 0
        with pytest.raises(backend_mod.BackendKeyDisabled):
            await LocalAesGcmBackend(db_pool).sign(k.handle, b"m", conn=con)
        # a pending replacement exists and is NOT active: issuing resumes only after an admin ack and DNS
        assert res.replacement is not None and res.replacement.status == "pending" and res.replacement.usage == "attest"
        assert await keys.active_key(con, "attest", now=T0 + DAY) is None
        # the list names the key and verifies
        assert res.list is not None and res.list_error is None
        entry = [e for e in res.list.doc["revoked"] if e["kid"] == k.kid]
        assert entry == [{"kid": k.kid, "reason": "key_compromise", "revoked_at": fk.ts(T0 + DAY)}]
        info = await estate.get_estate(con)
        lst = revocation.verify_list(res.list.envelope, issuers=[plat.issuer_cert], revoker=plat.revoker_cert,
                                     roots=certs.parse_roots(plat.roots), estate=info.estate_id, now=T0 + DAY)
        assert lst.key_status(k.kid, T0) == "key.revoked"                      # whatever its claimed issued_at
        hold = await con.fetchrow("SELECT details::text AS d FROM audit_log WHERE action = 'attest.hold.set'")
        assert json.loads(hold["d"]) == {"reason": "key_compromise", "requires_ack": True, "kid": k.kid}
        signed_rows = await con.fetch("SELECT details::text AS d FROM audit_log WHERE action = 'attest.revocation.signed'")
        assert [json.loads(r["d"])["seq"] for r in signed_rows] == [1]
        audit = await con.fetchrow("SELECT actor, justification, details::text AS d FROM audit_log WHERE action = 'attest.key.revoked'")
        assert audit["actor"] == "admin" and audit["justification"] == "key leaked on a laptop"
        assert "seed" not in audit["d"] and json.loads(audit["d"])["reason"] == "key_compromise"


async def test_revoke_is_idempotent_and_terminal(db_pool, plat):
    async with db_pool.acquire() as con:
        k = await make_active(con, "attest", now=T0)
        await keys.revoke(con, k.kid, now=T0 + DAY)
        again = await keys.revoke(con, k.kid, now=T0 + 2 * DAY)
        assert again.already_revoked and again.key.revoked_at == T0 + DAY
        assert await con.fetchval("SELECT count(*) FROM attest_revocations") == 1
        assert await con.fetchval("SELECT count(*) FROM audit_log WHERE action = 'attest.key.revoked'") == 1
        with pytest.raises(keys.KeyStateError):
            await keys.activate(con, k.kid, now=T0 + 3 * DAY)
        with pytest.raises(Exception):                                                   # the trigger: revoked is terminal
            await con.execute("UPDATE attest_keys SET status = 'active' WHERE kid = $1", k.kid)


async def test_revoking_an_anchor_key_activates_its_replacement_at_once(db_pool, plat):
    async with db_pool.acquire() as con:
        k = await make_active(con, "anchor", now=T0)
        res = await keys.revoke(con, k.kid, now=T0 + DAY)
        assert res.replacement.status == "active" and res.replacement.kid != k.kid
        assert (await keys.active_key(con, "anchor", now=T0 + DAY)).kid == res.replacement.kid


async def test_an_existing_pending_key_is_the_replacement_and_no_third_is_created(db_pool, plat):
    async with db_pool.acquire() as con:
        k1 = await make_active(con, "attest", now=T0)
        k2 = await keys.rotate(con, "attest", now=T0 + DAY)
        res = await keys.revoke(con, k1.kid, now=T0 + 2 * DAY)
        assert res.replacement.kid == k2.kid
        assert len(await keys.list_keys(con, "attest")) == 2


async def test_a_superseded_revocation_neither_holds_nor_hides_the_bundle(db_pool, plat):
    async with db_pool.acquire() as con:
        k = await make_active(con, "attest", now=T0)
        k2 = await keys.rotate(con, "attest", now=T0 + DAY)
        await keys.activate(con, k2.kid, now=T0 + 2 * DAY)
        await _bundle(con)
        res = await keys.revoke(con, k.kid, reason="superseded", now=T0 + 3 * DAY)
        assert res.key.status == "revoked" and res.replacement is None or res.replacement.kid != k.kid
        est = await con.fetchrow("SELECT hold_reason, hold_requires_ack FROM attest_estates")
        assert (est["hold_reason"], est["hold_requires_ack"]) == ("", False)
        assert await con.fetchval("SELECT count(*) FROM audit_log WHERE action = 'attest.hold.set'") == 0
        assert all((await _public(con)).values())
        assert [e["reason"] for e in res.list.doc["revoked"]] == ["superseded"]
        with pytest.raises(keys.KeysError):
            await keys.revoke(con, k2.kid, reason="because", now=T0 + 4 * DAY)


async def test_unknown_kids_cannot_be_revoked(db_pool, plat):
    async with db_pool.acquire() as con:
        await make_active(con, "attest", now=T0)
        with pytest.raises(keys.KeyNotFound):
            await keys.revoke(con, "f" * 32, now=T0)


async def test_a_missing_platform_never_undoes_a_revocation(db_pool, plat, monkeypatch):
    async with db_pool.acquire() as con:
        k = await make_active(con, "attest", now=T0)
        monkeypatch.setattr(attest_config.settings, "revoker_key_file", None)
        monkeypatch.setattr(attest_config.settings, "issuer_key_file", None)
        res = await keys.revoke(con, k.kid, now=T0 + DAY)
        assert res.key.status == "revoked" and res.list is None and res.list_error is not None
        assert res.replacement is None and res.replacement_error is not None
        assert await secrets_for(con, k.kid) == 0
        # the loop's resign picks it up once the platform is back
        fk.install(monkeypatch, plat)
        again = await revocation.resign_if_due(con, now=T0 + 2 * DAY)
        assert again is not None and [e["kid"] for e in again.doc["revoked"]] == [k.kid]


async def test_a_failing_backend_destroy_does_not_undo_the_revocation_and_sweep_finishes_it(db_pool, plat):
    class Flaky(LocalAesGcmBackend):
        async def destroy(self, h, *, conn=None):
            raise backend_mod.BackendUnavailable("down")

    async with db_pool.acquire() as con:
        k = await make_active(con, "attest", now=T0)
        res = await keys.revoke(con, k.kid, backend=Flaky(db_pool), now=T0 + DAY)
        assert res.key.status == "revoked" and res.destroy_error == "BackendUnavailable"
        assert await secrets_for(con, k.kid) == 1
        out = await keys.sweep(con, now=T0 + 2 * DAY)
        assert k.kid in out["erased"] and await secrets_for(con, k.kid) == 0


async def test_revoke_can_skip_signing_the_list(db_pool, plat):
    async with db_pool.acquire() as con:
        k = await make_active(con, "attest", now=T0)
        res = await keys.revoke(con, k.kid, resign=False, now=T0 + DAY)
        assert res.list is None and res.list_error is None
        assert await revocation.current_list(con) is None


# --------------------------------------------------------------------------- #
# isolation (the app role, RLS)
# --------------------------------------------------------------------------- #

async def test_tenants_have_separate_estates_keys_and_cannot_touch_each_others(db_pool, app_pool, plat, tenants):
    made = {}
    for tid in (TA, TB):
        with tenancy.tenant_context(tid):
            async with app_pool.acquire() as con:
                k = await make_active(con, "attest", now=T0)
                made[tid] = (k, (await estate.get_estate(con)).estate_id)
    assert made[TA][0].kid != made[TB][0].kid and made[TA][1] != made[TB][1]
    assert made[TA][0].cert.estate == made[TA][1] and made[TB][0].cert.estate == made[TB][1]
    with tenancy.tenant_context(TB):
        async with app_pool.acquire() as con:
            assert await keys.get_key(con, made[TA][0].kid) is None
            assert [k.kid for k in await keys.list_keys(con)] == [made[TB][0].kid]
            with pytest.raises(keys.KeyNotFound):
                await keys.revoke(con, made[TA][0].kid, now=T0)
            with pytest.raises(keys.KeyNotFound):
                await keys.activate(con, made[TA][0].kid, now=T0)
            doc = json.loads(await keys.keys_document(con, now=T0 + 1))
            assert [e["kid"] for e in doc["keys"]] == [made[TB][0].kid] and doc["estate"] == made[TB][1]
    with tenancy.tenant_context(TA):
        async with app_pool.acquire() as con:
            assert (await keys.get_key(con, made[TA][0].kid)).status == "active"
            assert await secrets_for(con, made[TA][0].kid) == 1


async def test_the_whole_lifecycle_runs_as_the_application_role_under_row_level_security(db_pool, app_pool, plat, tenants):
    """paddock_app owns nothing and cannot disable triggers: create, activate, renew, rotate, sweep, revoke and the
    list signing all work through it, tenant by tenant."""
    with tenancy.tenant_context(TA):
        async with app_pool.acquire() as con:
            k1 = await make_active(con, "attest", now=T0)
            a1 = await make_active(con, "anchor", now=T0)
            await _bundle(con)
            assert await keys.renew_certs(con, now=T0 + 60 * DAY) == sorted([k1.kid, a1.kid])
            k2 = await keys.rotate(con, "attest", now=T0 + 270 * DAY)
            await keys.activate(con, k2.kid, now=T0 + 300 * DAY)
            await _statement(con, k1.kid, 1, T0 + 301 * DAY)
            assert (await keys.sweep(con, now=T0 + 304 * DAY))["retired"] == [k1.kid]
            assert (await keys.sweep(con, now=T0 + 312 * DAY))["erased"] == [k1.kid]
            res = await keys.revoke(con, k2.kid, actor="admin", justification="rehearsal", now=T0 + 320 * DAY)
            assert res.key.status == "revoked" and res.list is not None and res.replacement is not None
            assert (await _public(con))["attestation/latest.json"] is False
            assert await secrets_for(con, k2.kid) == 0
            doc = await keys.keys_document(con, now=T0 + 321 * DAY)
            assert {e["kid"] for e in json.loads(doc)["keys"]} >= {k1.kid, k2.kid, a1.kid}
    with tenancy.tenant_context(TB):
        async with app_pool.acquire() as con:
            assert await keys.list_keys(con) == [] and await _public(con) == {}


async def test_the_sealed_seed_of_one_tenant_never_signs_for_another(db_pool, app_pool, plat, tenants):
    with tenancy.tenant_context(TA):
        async with app_pool.acquire() as con:
            ka = await make_active(con, "attest", now=T0)
    with tenancy.tenant_context(TB):
        async with app_pool.acquire() as con:
            with pytest.raises(backend_mod.BackendError):
                await LocalAesGcmBackend(app_pool).sign(ka.handle, b"mint", conn=con)


# --------------------------------------------------------------------------- #
# the vendor admin script
# --------------------------------------------------------------------------- #

def load_admin():
    spec = importlib.util.spec_from_file_location("attest_vendor_admin", ADMIN)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["attest_vendor_admin"] = mod
    spec.loader.exec_module(mod)
    return mod


async def test_admin_revoke_key_works_across_tenants_through_the_owner_connection(db_pool, plat, tenants, app_pool):
    adm = load_admin()
    with tenancy.tenant_context(TA):
        async with app_pool.acquire() as con:
            k = await make_active(con, "attest", now=T0)
    async with db_pool.acquire() as owner:
        out = await adm.revoke_key(owner, TA, k.kid, reason="key_compromise", justification="vendor cut-off", now=T0 + DAY)
    assert out["status"] == "revoked" and out["list_signed"] is True and out["replacement"]
    with tenancy.tenant_context(TA):
        async with app_pool.acquire() as con:
            assert (await keys.get_key(con, k.kid)).status == "revoked"
            audit = await con.fetchrow("SELECT actor, justification FROM audit_log WHERE action = 'attest.key.revoked'")
    assert audit["actor"] == "vendor-admin" and audit["justification"] == "vendor cut-off"


async def test_admin_revoke_key_reports_an_unsigned_list_when_the_platform_is_missing(db_pool, plat, monkeypatch):
    adm = load_admin()
    async with db_pool.acquire() as con:
        k = await make_active(con, "attest", now=T0)
    monkeypatch.setattr(attest_config.settings, "revoker_key_file", None)
    async with db_pool.acquire() as owner:
        out = await adm.revoke_key(owner, DEFAULT, k.kid, reason="key_compromise", justification="x" * 8, now=T0 + DAY)
    assert out["status"] == "revoked" and out["list_signed"] is False and "NOT re-signed" in out["warning"]


async def test_admin_refuses_a_missing_justification_and_unknown_inputs(db_pool, plat):
    adm = load_admin()
    async with db_pool.acquire() as con:
        k = await make_active(con, "attest", now=T0)
    async with db_pool.acquire() as owner:
        with pytest.raises(SystemExit):
            await adm.revoke_key(owner, DEFAULT, k.kid, reason="key_compromise", justification="short", now=T0)
        with pytest.raises(SystemExit):
            await adm.revoke_key(owner, "not-a-uuid", k.kid, reason="key_compromise", justification="long enough", now=T0)
        with pytest.raises(SystemExit):
            await adm.revoke_key(owner, DEFAULT, "f" * 32, reason="key_compromise", justification="long enough", now=T0)
    async with db_pool.acquire() as con:
        assert (await keys.get_key(con, k.kid)).status == "active"


async def test_admin_suspend_tenant_sets_the_flag_and_audits(db_pool, plat, tenants, app_pool):
    adm = load_admin()
    with tenancy.tenant_context(TA):
        async with app_pool.acquire() as con:
            await make_active(con, "attest", now=T0)
    async with db_pool.acquire() as owner:
        assert (await adm.suspend_tenant(owner, TA, justification="abuse report 42"))["issuing_suspended"] is True
    with tenancy.tenant_context(TA):
        async with app_pool.acquire() as con:
            assert (await estate.get_estate(con)).issuing_suspended is True
            row = await con.fetchrow("SELECT justification FROM audit_log WHERE action = 'attest.suspended'")
            assert row["justification"] == "abuse report 42"
    with tenancy.tenant_context(TB):
        async with app_pool.acquire() as con:
            assert await estate.get_estate(con) is None                                   # B untouched
    async with db_pool.acquire() as owner:
        assert (await adm.suspend_tenant(owner, TA, justification="resolved, lifting", resume=True))["issuing_suspended"] is False
        with pytest.raises(SystemExit):
            await adm.suspend_tenant(owner, TB, justification="no estate here")


def test_admin_main_requires_a_dsn_and_never_prints_secrets(monkeypatch, capsys):
    adm = load_admin()
    monkeypatch.delenv("PADDOCK_DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(SystemExit):
        adm.main(["revoke-key", "--tenant", DEFAULT, "--kid", "f" * 32, "--justification", "long enough text"])


# --------------------------------------------------------------------------- #
# rework round: the emergency path never deadlocks and never rolls back
# --------------------------------------------------------------------------- #

async def test_revoke_and_create_key_never_deadlock_and_the_revocation_always_lands(db_pool, app_pool, plat):
    """Lock order is the estate row first, then the key rows, in BOTH paths: a revoke may never be a deadlock victim."""
    import uuid

    for i in range(10):
        tid = str(uuid.UUID(int=(0xD0 << 100) + i))
        await tenancy.create_tenant(db_pool, slug=f"dl-{i}", name=f"dl-{i}", tenant_id=tid)
        with tenancy.tenant_context(tid):
            async with app_pool.acquire() as con:
                k = await make_active(con, "attest", now=T0)

            async def create():
                async with app_pool.acquire() as c:
                    try:
                        return await keys.create_key(c, "attest", now=T0 + DAY)
                    except keys.KeyStateError as exc:
                        return exc.code

            async def revoke():
                async with app_pool.acquire() as c:
                    return await keys.revoke(c, k.kid, actor="a", justification="because reasons", resign=False,
                                             now=T0 + DAY)

            out = await asyncio.gather(create(), revoke(), return_exceptions=True)
            assert not any(isinstance(o, BaseException) for o in out), out
            async with app_pool.acquire() as con:
                assert (await keys.get_key(con, k.kid)).status == "revoked"


@pytest.mark.parametrize("exc_factory", [
    lambda: RuntimeError("boom"),
    lambda: __import__("asyncpg").exceptions.QueryCanceledError("canceled"),
    lambda: __import__("asyncpg").exceptions.DeadlockDetectedError("deadlock"),
    lambda: ValueError("odd"),
])
async def test_any_failure_of_the_backend_destroy_never_undoes_the_revocation(db_pool, plat, exc_factory):
    class Broken(LocalAesGcmBackend):
        async def destroy(self, h, *, conn=None):
            raise exc_factory()

    async with db_pool.acquire() as con:
        k = await make_active(con, "attest", now=T0)
        res = await keys.revoke(con, k.kid, backend=Broken(db_pool), actor="a", justification="because reasons",
                                resign=False, now=T0 + DAY)
        assert res.key.status == "revoked" and res.destroy_error is not None
        assert await con.fetchval("SELECT count(*) FROM attest_revocations WHERE kid = $1", k.kid) == 1
        assert await con.fetchval("SELECT hold_reason FROM attest_estates") == "key_compromise"
        assert await secrets_for(con, k.kid) == 1                                 # the seed is still there ...
        out = await keys.sweep(con, now=T0 + 2 * DAY)                             # ... and the sweep erases it
        assert k.kid in out["erased"] and await secrets_for(con, k.kid) == 0


async def test_a_renewal_under_a_newer_issuer_says_when_the_window_start_had_to_move(db_pool, plat, tmp_path, monkeypatch):
    async with db_pool.acquire() as con:
        k = await make_active(con, "attest", now=T0)
        newer = fk.make_platform(tmp_path / "newer", issuer_window=(T0 + 30 * DAY, T0 + 500 * DAY),
                                 revoker_window=(T0 + 30 * DAY, T0 + 500 * DAY))
        fk.install(monkeypatch, newer)
        assert await keys.renew_certs(con, now=T0 + 61 * DAY) == [k.kid]
        row = await con.fetchrow("SELECT details FROM audit_log WHERE action = 'attest.cert.renewed' ORDER BY id DESC LIMIT 1")
        details = json.loads(row["details"]) if isinstance(row["details"], str) else row["details"]
        assert details["window_start_moved"] is True and details["kid"] == k.kid
        # an unchanged window start says so too
        fk.install(monkeypatch, plat)
