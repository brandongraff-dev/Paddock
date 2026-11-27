"""P3.3: the signed revocation list, supersession, issuer revocation, kill switch (docs/ASSURANCE_P3.md 3.4, 3.8, D20).

The list is verified here both by production ``revocation.verify_list`` and by an independent check made of the
verifier's primitives only.
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
from pathlib import Path

import fakeredis.aioredis
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from paddock_verify import b64, canon, dsse, ed25519

from app import tenancy
from app.attest import certs, estate, keys, platform_keys, revocation

from . import attest_fakes as fk
from .attest_fakes import DAY, T0

ROOT = Path(__file__).resolve().parents[2]
ADMIN = ROOT / "scripts" / "attest_vendor_admin.py"
TA = "00000000-0000-0000-0000-0000000000a1"
TB = "00000000-0000-0000-0000-0000000000b1"
SUBJECT = "dns:example.com"


@pytest.fixture
def plat(tmp_path, monkeypatch):
    p = fk.make_platform(tmp_path / "plat")
    fk.install(monkeypatch, p)
    return p


@pytest_asyncio.fixture
async def tenants(db_pool):
    for slug, tid in (("rev-a", TA), ("rev-b", TB)):
        await tenancy.create_tenant(db_pool, slug=slug, name=slug, tenant_id=tid)


async def with_estate(con):
    return (await estate.ensure_estate(con)).estate_id


def verify(plat, env, estate_id, now, **kw):
    return revocation.verify_list(env, issuers=[plat.issuer_cert], revoker=plat.revoker_cert,
                                  roots=certs.parse_roots(plat.roots), estate=estate_id, now=now, **kw)


def independent(env, signer_pub):
    """The verifier primitives alone: strict envelope, canonical payload, PAE signature."""
    e = dsse.parse_envelope(env, expected_type="application/vnd.paddock.revocation-list+json")
    doc = canon.roundtrip(e.payload)
    assert ed25519.verify(signer_pub, dsse.pae(e.payload_type, e.payload), e.sig)
    return doc


def re_sign(plat, env, mutate, signer="revoker"):
    """A list re-signed (validly) after ``mutate(doc)`` -- to build verification negatives."""
    e = dsse.parse_envelope(env)
    doc = json.loads(e.payload)
    mutate(doc)
    priv, kid = (plat.revoker_priv, plat.revoker_kid) if signer == "revoker" else (plat.issuer_priv, plat.issuer_kid)
    return fk.envelope(priv, kid, dsse.PAYLOAD_TYPE_REVOCATION, canon.dumps(doc))


# --------------------------------------------------------------------------- #
# signing
# --------------------------------------------------------------------------- #

async def test_the_first_list_has_the_documented_shape_and_verifies_independently(db_pool, plat):
    async with db_pool.acquire() as con:
        eid = await with_estate(con)
        signed = await revocation.sign_list(con, now=T0 + 7)
        stored = await revocation.current_list(con)
        row = await con.fetchrow("SELECT revocation_seq, revocation_signed_at FROM attest_estates")
    doc = independent(signed.envelope, plat.revoker_pub)
    assert doc == {"_type": "https://paddock.dev/revocation-list/v1", "estate": eid, "seq": 1, "issued_at": fk.ts(T0 + 7),
                   "next_update": fk.ts(T0 + 7 + DAY), "revoked": [], "superseded": []}
    assert signed.seq == 1 and signed.doc == doc and row["revocation_seq"] == 1
    async with db_pool.acquire() as con:
        audit = await con.fetch("SELECT details::text AS d, actor FROM audit_log WHERE action = 'attest.revocation.signed'")
    assert [json.loads(a["d"]) for a in audit] == [{"seq": 1, "estate": eid, "revoked": 0, "superseded": 0, "signer": plat.revoker_kid}]
    assert stored.envelope == signed.envelope and stored.seq == 1                    # served bytes == signed bytes
    e = dsse.parse_envelope(signed.envelope)
    assert e.keyid == plat.revoker_kid
    lst = verify(plat, signed.envelope, eid, T0 + 8)
    assert (lst.seq, lst.estate, lst.signer_usage, lst.signer_kid) == (1, eid, "revoke", plat.revoker_kid)


async def test_seq_grows_by_one_per_signing_even_under_concurrency(db_pool, plat):
    async with db_pool.acquire() as con:
        await with_estate(con)

    async def one(i):
        async with db_pool.acquire() as c:
            return (await revocation.sign_list(c, now=T0 + i)).seq

    seqs = await asyncio.gather(*[one(i) for i in range(5)])
    assert sorted(seqs) == [1, 2, 3, 4, 5]
    async with db_pool.acquire() as con:
        assert (await revocation.current_list(con)).seq == 5


async def test_the_issuer_key_may_sign_the_list_too(db_pool, plat):
    async with db_pool.acquire() as con:
        eid = await with_estate(con)
        signed = await revocation.sign_list(con, now=T0, signer="issuer")
        assert dsse.parse_envelope(signed.envelope).keyid == plat.issuer_kid
        assert verify(plat, signed.envelope, eid, T0).signer_usage == "issue-cert"
        with pytest.raises(revocation.RevocationError):
            await revocation.sign_list(con, now=T0, signer="root")


async def test_a_list_carries_every_revocation_in_order(db_pool, plat):
    async with db_pool.acquire() as con:
        eid = await with_estate(con)
        for kid, reason, at in (("b" * 32, "superseded", T0 + 50), ("a" * 32, "key_compromise", T0 + 50),
                                ("c" * 32, "cessation", T0 + 10)):
            await con.execute("INSERT INTO attest_revocations (kid, reason_code, revoked_at) VALUES ($1, $2, $3)",
                              kid, reason, keys._dt(at))
        signed = await revocation.sign_list(con, now=T0 + 100)
    assert signed.doc["revoked"] == [
        {"kid": "c" * 32, "reason": "cessation", "revoked_at": fk.ts(T0 + 10)},
        {"kid": "a" * 32, "reason": "key_compromise", "revoked_at": fk.ts(T0 + 50)},
        {"kid": "b" * 32, "reason": "superseded", "revoked_at": fk.ts(T0 + 50)}]
    lst = verify(plat, signed.envelope, eid, T0 + 100)
    assert lst.key_status("a" * 32, T0) == "key.revoked"                           # key_compromise: regardless of claimed time
    assert lst.key_status("b" * 32, T0 + 49) == "key.revoked_superseded"           # earlier statements only warn
    assert lst.key_status("b" * 32, T0 + 50) == "key.revoked"                      # issued_at >= revoked_at rejects
    assert lst.key_status("c" * 32, T0 + 11) == "key.revoked" and lst.key_status("d" * 32, T0) is None


async def test_signing_without_an_estate_or_a_platform_stores_nothing(db_pool, plat, monkeypatch):
    from app.attest import config as c

    async with db_pool.acquire() as con:
        with pytest.raises(revocation.RevocationError) as ei:
            await revocation.sign_list(con, now=T0)
        assert ei.value.code == "revocation.no_estate"
        await with_estate(con)
        monkeypatch.setattr(c.settings, "revoker_cert_file", None)
        with pytest.raises(platform_keys.PlatformNotConfigured):
            await revocation.sign_list(con, now=T0)
        assert await con.fetchval("SELECT revocation_seq FROM attest_estates") == 0
        assert await revocation.current_list(con) is None


async def test_a_clock_that_goes_backwards_never_makes_issued_at_go_backwards(db_pool, plat):
    async with db_pool.acquire() as con:
        await with_estate(con)
        first = await revocation.sign_list(con, now=T0 + 1000)
        second = await revocation.sign_list(con, now=T0 + 10)
    assert second.doc["issued_at"] == first.doc["issued_at"] and second.seq == 2


# --------------------------------------------------------------------------- #
# supersession
# --------------------------------------------------------------------------- #

async def test_supersede_signs_a_list_at_once_and_min_seq_only_grows(db_pool, plat):
    async with db_pool.acquire() as con:
        eid = await with_estate(con)
        s1 = await revocation.supersede(con, SUBJECT, 1843, now=T0)
        assert s1.seq == 1 and s1.doc["superseded"] == [{"subject": SUBJECT, "min_seq": 1843, "at": fk.ts(T0)}]
        assert await revocation.supersede(con, SUBJECT, 1843, now=T0 + 5) is None            # nothing new, nothing signed
        assert await revocation.supersede(con, SUBJECT, 100, now=T0 + 6) is None             # never lowered
        s2 = await revocation.supersede(con, SUBJECT, 1900, now=T0 + 10)
        assert s2.seq == 2 and s2.doc["superseded"] == [{"subject": SUBJECT, "min_seq": 1900, "at": fk.ts(T0 + 10)}]
        other = "paddock-estate:" + eid
        s3 = await revocation.supersede(con, other, 7, now=T0 + 20)
        assert [e["subject"] for e in s3.doc["superseded"]] == sorted([SUBJECT, other])
        lst = verify(plat, s3.envelope, eid, T0 + 21)
        assert lst.is_superseded(SUBJECT, 1899) and not lst.is_superseded(SUBJECT, 1900)
        assert lst.min_seq(other) == 7 and lst.min_seq("dns:other.example") is None
        # a re-signed list keeps the supersessions
        again = await revocation.sign_list(con, now=T0 + 30)
        assert again.doc["superseded"] == s3.doc["superseded"] and again.seq == 4


async def test_the_issuer_loses_the_ability_to_evaluate_min_seq_is_last_seq_plus_one(db_pool, plat):
    async with db_pool.acquire() as con:
        eid = await with_estate(con)
        s = await revocation.supersede(con, SUBJECT, 43 + 1, now=T0)          # last_seq 43: no statement >= 44 exists
        assert verify(plat, s.envelope, eid, T0).is_superseded(SUBJECT, 43)


@pytest.mark.parametrize("subject", ["", "example.com", "dns:", "dns:UPPER.example", "dns:a b.example", "dns:x", "ip:1.2.3.4",
                                     "paddock-estate:short", "dns:" + "a" * 300 + ".com", "dns:a\\b.example"])
async def test_supersede_refuses_a_bad_subject(db_pool, plat, subject):
    async with db_pool.acquire() as con:
        await with_estate(con)
        with pytest.raises(revocation.RevocationError):
            await revocation.supersede(con, subject, 1, now=T0)
        assert await con.fetchval("SELECT revocation_seq FROM attest_estates") == 0


@pytest.mark.parametrize("min_seq", [0, -1, 2 ** 53, "7", 1.5, True])
async def test_supersede_refuses_a_bad_min_seq(db_pool, plat, min_seq):
    async with db_pool.acquire() as con:
        await with_estate(con)
        with pytest.raises(revocation.RevocationError):
            await revocation.supersede(con, SUBJECT, min_seq, now=T0)


async def test_at_most_eleven_subjects_and_a_twelfth_displaces_only_a_subject_with_no_live_publication(db_pool, plat):
    async with db_pool.acquire() as con:
        eid = await with_estate(con)
        subjects = [f"dns:d{i}.example.com" for i in range(10)] + ["paddock-estate:" + eid]
        await con.execute("INSERT INTO attest_publications (subject_kind) VALUES ('estate')")
        for i in range(10):
            await con.execute("INSERT INTO attest_publications (subject_kind, domain, domain_key) VALUES ('domain', $1, $2)",
                              f"d{i}.example.com", str(i) * 64)
        for i, s in enumerate(subjects):
            await revocation.supersede(con, s, 5, now=T0 + i)
        with pytest.raises(revocation.RevocationError) as ei:
            await revocation.supersede(con, "dns:one-too-many.example.com", 5, now=T0 + 100)
        assert ei.value.code == "revocation.too_many_subjects"
        assert len((await revocation.current_list(con)).doc["superseded"]) == 11            # nothing half-written
        # d3.example.com is archived (it has a publication that was archived): it may be displaced
        await con.execute("UPDATE attest_publications SET archived_at = now() WHERE domain = 'd3.example.com'")
        s = await revocation.supersede(con, "dns:one-too-many.example.com", 5, now=T0 + 101)
        names = [e["subject"] for e in s.doc["superseded"]]
        assert len(names) == 11 and "dns:d3.example.com" not in names and "dns:one-too-many.example.com" in names


# --------------------------------------------------------------------------- #
# verification: what a consumer rejects
# --------------------------------------------------------------------------- #

@pytest_asyncio.fixture
async def base(db_pool, plat):
    async with db_pool.acquire() as con:
        eid = await with_estate(con)
        signed = await revocation.sign_list(con, now=T0)
    return plat, eid, signed.envelope


def bad(plat, env, eid, now=T0, code="revocation.unverifiable", **kw):
    with pytest.raises(revocation.RevocationError) as ei:
        verify(plat, env, eid, now, **kw)
    assert ei.value.code == code, (ei.value.code, ei.value.detail)


async def test_a_list_is_stale_only_after_next_update_plus_48_hours(base):
    plat, eid, env = base
    verify(plat, env, eid, T0 + DAY + 48 * 3600)                        # exactly at the boundary: not yet stale
    bad(plat, env, eid, T0 + DAY + 48 * 3600 + 1, code="revocation.stale")
    bad(plat, env, eid, T0 + 100 * DAY, code="revocation.stale")


async def test_a_list_from_the_future_is_refused(base):
    plat, eid, env = base
    verify(plat, env, eid, T0 - 300)
    bad(plat, env, eid, T0 - 301)


async def test_the_seq_may_not_go_backwards_against_a_cached_copy(base):
    plat, eid, env = base
    verify(plat, env, eid, T0, cached_seq=1)
    bad(plat, env, eid, T0, cached_seq=2)


async def test_another_estates_list_is_refused(base):
    plat, eid, env = base
    bad(plat, env, "e_" + "z" * 26)


async def test_tampering_breaks_the_signature_and_noncanonical_bytes_are_refused(base):
    plat, eid, env = base
    d = json.loads(env)
    raw = bytearray(b64.strict_decode(d["payload"]))
    raw[raw.index(b'"seq":1') + 6] = ord("2")
    d["payload"] = b64.encode(bytes(raw))
    bad(plat, json.dumps(d).encode(), eid)
    sig = bytearray(b64.strict_decode(json.loads(env)["signatures"][0]["sig"]))
    sig[5] ^= 1
    d2 = json.loads(env)
    d2["signatures"][0]["sig"] = b64.encode(bytes(sig))
    bad(plat, json.dumps(d2).encode(), eid)
    spaced = dsse.parse_envelope(env).payload.replace(b",", b", ")
    bad(plat, fk.envelope(plat.revoker_priv, plat.revoker_kid, dsse.PAYLOAD_TYPE_REVOCATION, spaced), eid)


async def test_only_a_chained_revoker_or_issuer_may_sign(base, tmp_path):
    plat, eid, env = base
    # an estate attest key certified by the issuer is not a revoker
    leaf = Ed25519PrivateKey.generate()
    attest = fk.make_cert(plat.issuer_priv, plat.issuer_kid, usage="attest", pub=fk.raw_pub(leaf), not_before=T0 - DAY,
                          not_after=T0 + 90 * DAY, estate=eid)
    forged = fk.envelope(leaf, fk.kid_of(fk.raw_pub(leaf)), dsse.PAYLOAD_TYPE_REVOCATION, dsse.parse_envelope(env).payload)
    with pytest.raises(revocation.RevocationError):
        revocation.verify_list(forged, issuers=[plat.issuer_cert, attest], revoker=plat.revoker_cert,
                               roots=certs.parse_roots(plat.roots), estate=eid, now=T0)
    # a revoker of another platform (different root)
    other = fk.make_platform(tmp_path / "other")
    foreign = fk.envelope(other.revoker_priv, other.revoker_kid, dsse.PAYLOAD_TYPE_REVOCATION, dsse.parse_envelope(env).payload)
    with pytest.raises(revocation.RevocationError):
        revocation.verify_list(foreign, issuers=[plat.issuer_cert], revoker=other.revoker_cert,
                               roots=certs.parse_roots(plat.roots), estate=eid, now=T0)
    # an unknown signer
    bad(plat, fk.envelope(leaf, fk.kid_of(fk.raw_pub(leaf)), dsse.PAYLOAD_TYPE_REVOCATION, dsse.parse_envelope(env).payload), eid)
    # the signer's certificate must be valid at the list's issued_at
    revoker_expired = fk.make_platform(tmp_path / "exp", revoker_window=(T0 - 10 * DAY, T0 - DAY))
    exp = fk.envelope(revoker_expired.revoker_priv, revoker_expired.revoker_kid, dsse.PAYLOAD_TYPE_REVOCATION,
                      dsse.parse_envelope(env).payload)
    with pytest.raises(revocation.RevocationError):
        revocation.verify_list(exp, issuers=[], revoker=revoker_expired.revoker_cert,
                               roots=certs.parse_roots(revoker_expired.roots), estate=eid, now=T0)


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(extra=1),
    lambda d: d.update(_type="https://paddock.dev/revocation-list/v2"),
    lambda d: d.update(seq=0),
    lambda d: d.update(next_update=d["issued_at"]),
    lambda d: d.update(issued_at="yesterday"),
    lambda d: d.update(revoked=[{"kid": "a" * 32, "reason": "oops", "revoked_at": "2026-12-01T00:00:00Z"}]),
    lambda d: d.update(revoked=[{"kid": "a" * 32, "reason": "cessation", "revoked_at": "2026-12-01T00:00:00Z"}] * 2),
    lambda d: d.update(revoked=[{"kid": "A" * 32, "reason": "cessation", "revoked_at": "2026-12-01T00:00:00Z"}]),
    lambda d: d.update(revoked=[{"kid": "a" * 32, "reason": "cessation"}]),
    lambda d: d.update(superseded=[{"subject": "dns:a.example", "min_seq": 0, "at": "2026-12-01T00:00:00Z"}]),
    lambda d: d.update(superseded=[{"subject": "dns:a.example", "min_seq": 1, "at": "2026-12-01T00:00:00Z"}] * 2),
    lambda d: d.update(superseded=[{"subject": "dns:a%d.example" % i, "min_seq": 1, "at": "2026-12-01T00:00:00Z"} for i in range(12)]),
    lambda d: d.update(superseded=[{"subject": "host.example", "min_seq": 1, "at": "2026-12-01T00:00:00Z"}]),
])
async def test_a_validly_signed_but_malformed_list_is_refused(base, mutate):
    plat, eid, env = base
    bad(plat, re_sign(plat, env, mutate), eid)


async def test_a_wrong_payload_type_is_refused(base):
    plat, eid, env = base
    payload = dsse.parse_envelope(env).payload
    bad(plat, fk.envelope(plat.revoker_priv, plat.revoker_kid, dsse.PAYLOAD_TYPE_STATEMENT, payload), eid)
    bad(plat, fk.envelope(plat.revoker_priv, plat.revoker_kid, dsse.PAYLOAD_TYPE_KEY_CERT, payload), eid)


async def test_garbage_input_is_an_error_not_a_crash(base):
    plat, eid, env = base
    for junk in (b"", b"{}", b"null", None, 5):
        bad(plat, junk, eid)


async def test_at_most_64_revocations_in_a_list_like_the_open_verifier_reads_it(db_pool, plat):
    async with db_pool.acquire() as con:
        eid = await with_estate(con)
        for i in range(64):
            await con.execute("INSERT INTO attest_revocations (kid, reason_code) VALUES ($1, 'cessation')", f"{i:032x}")
        signed = await revocation.sign_list(con, now=T0)
        assert len(signed.doc["revoked"]) == 64
        await con.execute("INSERT INTO attest_revocations (kid, reason_code) VALUES ($1, 'cessation')", "f" * 32)
        with pytest.raises(revocation.RevocationError) as ei:
            await revocation.sign_list(con, now=T0 + 1)
        assert ei.value.code == "revocation.too_many_revoked"
        assert (await revocation.current_list(con)).seq == signed.seq                  # nothing half-written
    plat_doc = signed.doc
    plat_doc["revoked"] = plat_doc["revoked"] + [{"kid": "f" * 32, "reason": "cessation", "revoked_at": fk.ts(T0)}]
    with pytest.raises(revocation.RevocationError):
        verify(plat, fk.envelope(plat.revoker_priv, plat.revoker_kid, dsse.PAYLOAD_TYPE_REVOCATION, canon.dumps(plat_doc)), eid, T0)


# --------------------------------------------------------------------------- #
# re-signing
# --------------------------------------------------------------------------- #

async def test_resign_if_due_covers_never_signed_old_and_unlisted_revocations(db_pool, plat):
    async with db_pool.acquire() as con:
        assert await revocation.resign_if_due(con, now=T0) is None                 # no estate yet: nothing to sign
        await with_estate(con)
        first = await revocation.resign_if_due(con, now=T0)
        assert first.seq == 1
        assert await revocation.resign_if_due(con, now=T0 + 5 * 3600) is None      # fresh enough
        second = await revocation.resign_if_due(con, now=T0 + 6 * 3600)            # 6 h: re-signed well before 24 h
        assert second.seq == 2
        await con.execute("INSERT INTO attest_revocations (kid, reason_code) VALUES ($1, 'key_compromise')", "e" * 32)
        third = await revocation.resign_if_due(con, now=T0 + 6 * 3600 + 5)          # a new revocation is not left waiting
        assert third.seq == 3 and [e["kid"] for e in third.doc["revoked"]] == ["e" * 32]
        assert await revocation.resign_if_due(con, now=T0 + 6 * 3600 + 6) is None


# --------------------------------------------------------------------------- #
# isolation
# --------------------------------------------------------------------------- #

async def test_each_tenant_has_its_own_list_seq_and_supersessions(db_pool, app_pool, plat, tenants):
    out = {}
    for tid in (TA, TB):
        with tenancy.tenant_context(tid):
            async with app_pool.acquire() as con:
                eid = await with_estate(con)
                await revocation.sign_list(con, now=T0)
                await revocation.supersede(con, SUBJECT, 9 if tid == TA else 3, now=T0 + 1)
                out[tid] = (eid, await revocation.current_list(con))
    assert out[TA][0] != out[TB][0] and out[TA][1].seq == out[TB][1].seq == 2
    assert out[TA][1].doc["superseded"][0]["min_seq"] == 9 and out[TB][1].doc["superseded"][0]["min_seq"] == 3
    assert out[TA][1].doc["estate"] == out[TA][0]
    # a list for estate A does not verify as B's
    with pytest.raises(revocation.RevocationError):
        verify(plat, out[TA][1].envelope, out[TB][0], T0 + 2)
    with tenancy.tenant_context(TB):
        async with app_pool.acquire() as con:
            assert (await revocation.current_list(con)).doc["estate"] == out[TB][0]


# --------------------------------------------------------------------------- #
# issuer revocation (root-signed, ships with a verifier release) and the vendor admin script
# --------------------------------------------------------------------------- #

def load_admin():
    spec = importlib.util.spec_from_file_location("attest_vendor_admin", ADMIN)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["attest_vendor_admin"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def root_pem(plat, tmp_path, monkeypatch):
    from cryptography.hazmat.primitives import serialization

    path = tmp_path / "root.pem"
    path.write_bytes(plat.root_priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                  serialization.BestAvailableEncryption(fk.PASSPHRASE.encode())))
    monkeypatch.setenv("PADDOCK_ATTEST_ROOT_PASSPHRASE", fk.PASSPHRASE)
    return path


def test_revoke_issuer_writes_a_root_signed_list_that_marks_the_issuer_revoked(plat, root_pem, tmp_path):
    adm = load_admin()
    out = tmp_path / "issuer_revocations.json"
    assert adm.main(["revoke-issuer", "--root-key-file", str(root_pem), "--issuer-kid", plat.issuer_kid,
                     "--reason", "key_compromise", "--out", str(out), "--at", "2026-12-02T00:00:00Z",
                     "--entries-out", str(tmp_path / "entries.json")]) == 0
    roots = certs.parse_roots(plat.roots)
    revoked = revocation.verify_issuer_revocations(out.read_bytes(), roots, now=T0 + 3 * DAY)
    assert set(revoked) == {plat.issuer_kid} and revoked[plat.issuer_kid].reason == "key_compromise"
    entries = json.loads((tmp_path / "entries.json").read_text())
    assert entries == [{"kid": plat.issuer_kid, "usage": "issuer-revoked"}]           # what the verifier's roots data takes
    assert certs.parse_roots(plat.roots + entries).revoked_issuers == frozenset({plat.issuer_kid})
    # and a certificate chain through that issuer is refused
    leaf = Ed25519PrivateKey.generate()
    env = fk.make_cert(plat.issuer_priv, plat.issuer_kid, usage="attest", pub=fk.raw_pub(leaf), not_before=T0,
                       not_after=T0 + DAY, estate=fk.ESTATE_A)
    with pytest.raises(certs.CertError) as ei:
        certs.verify_chain(env, issuers=[plat.issuer_cert], roots=roots, at=T0, revoked_issuers=set(revoked))
    assert ei.value.code == "issuer.revoked"


def test_revoke_issuer_extends_a_previous_list_and_never_overwrites(plat, root_pem, tmp_path):
    adm = load_admin()
    first, second = tmp_path / "one.json", tmp_path / "two.json"
    adm.main(["revoke-issuer", "--root-key-file", str(root_pem), "--issuer-kid", "a" * 32, "--reason", "cessation",
              "--out", str(first), "--at", "2026-12-02T00:00:00Z"])
    adm.main(["revoke-issuer", "--root-key-file", str(root_pem), "--issuer-kid", "b" * 32, "--reason", "key_compromise",
              "--previous", str(first), "--out", str(second), "--at", "2026-12-03T00:00:00Z"])
    roots = certs.parse_roots(plat.roots)
    assert set(revocation.verify_issuer_revocations(second.read_bytes(), roots)) == {"a" * 32, "b" * 32}
    assert json.loads(dsse.parse_envelope(second.read_bytes()).payload)["seq"] == 2
    with pytest.raises(SystemExit):
        adm.main(["revoke-issuer", "--root-key-file", str(root_pem), "--issuer-kid", "c" * 32, "--reason", "cessation",
                  "--out", str(second)])
    with pytest.raises(SystemExit):                                                  # not inside the repository
        adm.main(["revoke-issuer", "--root-key-file", str(root_pem), "--issuer-kid", "c" * 32, "--reason", "cessation",
                  "--out", str(ROOT / "tmp-should-not-exist.json")])
    with pytest.raises(SystemExit):
        adm.main(["revoke-issuer", "--root-key-file", str(root_pem), "--issuer-kid", "not-a-kid", "--reason", "cessation",
                  "--out", str(tmp_path / "x.json")])


def test_an_issuer_revocation_list_must_be_signed_by_a_pinned_root_and_be_well_formed(plat, root_pem, tmp_path):
    adm = load_admin()
    out = tmp_path / "ok.json"
    adm.main(["revoke-issuer", "--root-key-file", str(root_pem), "--issuer-kid", "a" * 32, "--reason", "cessation",
              "--out", str(out), "--at", "2026-12-02T00:00:00Z"])
    roots = certs.parse_roots(plat.roots)
    other = fk.make_platform(tmp_path / "other")
    with pytest.raises(revocation.RevocationError):
        revocation.verify_issuer_revocations(out.read_bytes(), certs.parse_roots(other.roots))
    with pytest.raises(revocation.RevocationError):                                  # the issuer key is not a root
        payload = dsse.parse_envelope(out.read_bytes()).payload
        revocation.verify_issuer_revocations(
            fk.envelope(plat.issuer_priv, plat.issuer_kid, dsse.PAYLOAD_TYPE_REVOCATION, payload), roots)
    with pytest.raises(revocation.RevocationError):                                  # an estate list is not an issuer list
        revocation.verify_issuer_revocations(
            fk.envelope(plat.root_priv, plat.root_kid, dsse.PAYLOAD_TYPE_REVOCATION,
                        canon.dumps({"_type": revocation.LIST_TYPE, "estate": fk.ESTATE_A, "seq": 1, "issued_at": fk.ts(T0),
                                     "next_update": fk.ts(T0 + DAY), "revoked": [], "superseded": []})), roots)
    with pytest.raises(revocation.RevocationError):
        revocation.verify_issuer_revocations(b"{}", roots)


async def test_global_kill_sets_and_clears_the_redis_key_the_loop_polls():
    adm = load_admin()
    r = fakeredis.aioredis.FakeRedis(decode_responses=True)
    assert await adm.global_kill(r, True) == {"issuing_killed": True}
    assert await r.get(platform_keys.GLOBAL_KILL_REDIS_KEY) is not None
    assert await adm.global_kill(r, True) == {"issuing_killed": True}              # idempotent
    assert await adm.global_kill(r, False) == {"issuing_killed": False}
    assert await r.get(platform_keys.GLOBAL_KILL_REDIS_KEY) is None
    assert "PADDOCK_ATTEST_ISSUING=false" in adm.GLOBAL_KILL_REMINDER                # the env flag is authoritative


def test_the_admin_script_has_the_four_documented_subcommands():
    adm = load_admin()
    text = ADMIN.read_text()
    for name in ("revoke-key", "suspend-tenant", "global-kill", "revoke-issuer"):
        assert f'"{name}"' in text
    assert callable(adm.main)
