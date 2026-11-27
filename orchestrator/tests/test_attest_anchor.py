"""P3.3: audit anchor v2: the signing hook, the public document, ``anchor_sig_status`` and the no-downgrade rule
(docs/ASSURANCE_P3.md 3.7, D15; adversarial rows ``anchor_downgrade_fails_closed``, ``anchor_sig_not_a_statement_sig``).

Signatures are re-checked here with the verifier's primitives only (``canon``, ``dsse``, ``ed25519``) so production
signing and production verification are both held against an independent reading of spec Appendix B.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from paddock_verify import b64, canon, dsse, ed25519

from app import audit as audit_svc
from app import tenancy
from app.attest import anchor_sig, backend, certs, estate, keys
from app.attest import config as attest_config
from app.attest.backend_local import LocalAesGcmBackend
from app.audit_anchor import Anchor, FileAnchorSink
from app.config import settings

from . import attest_fakes as fk
from .attest_fakes import DAY

TA = "00000000-0000-0000-0000-0000000000a1"
TB = "00000000-0000-0000-0000-0000000000b1"
DEFAULT = "00000000-0000-0000-0000-000000000001"
HMAC_KEY = "k" * 40
CTX = b"paddock-anchor/v2\n"


@pytest.fixture
def plat(tmp_path, monkeypatch):
    p = fk.make_platform(tmp_path / "plat")
    fk.install(monkeypatch, p)
    return p


@pytest.fixture(autouse=True)
def hmac_and_clean_hooks(monkeypatch):
    monkeypatch.setattr(settings, "audit_hmac_key", HMAC_KEY)
    monkeypatch.setattr(settings, "audit_hmac_previous_keys", "")
    monkeypatch.delenv("AUDIT_ANCHOR_ALLOW_LEGACY", raising=False)
    monkeypatch.setattr(audit_svc, "ANCHOR_SIGNERS", [])
    monkeypatch.setattr(audit_svc, "_SIGNERS_BOOTSTRAPPED", False)


@pytest_asyncio.fixture
async def tenants(db_pool):
    for slug, tid in (("anc-a", TA), ("anc-b", TB)):
        await tenancy.create_tenant(db_pool, slug=slug, name=slug, tenant_id=tid)


async def setup_key(con, now=None, usage="anchor"):
    k = await keys.create_key(con, usage, now=now)
    k = await keys.activate(con, k.kid, now=now)
    return k


@pytest_asyncio.fixture
async def world(db_pool, plat):
    async with db_pool.acquire() as con:
        key = await setup_key(con)
        info = await estate.get_estate(con)
    return SimpleNamespace(key=key, estate=info.estate_id, plat=plat, roots=certs.parse_roots(plat.roots))


async def audited(pool, n=2, tenant=None):
    for i in range(n):
        await audit_svc.record(pool, action="read", actor=f"u{i}", tenant_id=tenant)


def fresh_anchor(tenant=DEFAULT, max_id=5, head="ab" * 32, alg=None, ts=None):
    return Anchor(tenant_id=tenant, max_id=max_id, head_hash=head, hash_alg=alg or f"hmac-sha256:{audit_svc.key_id(HMAC_KEY.encode())}",
                  ts=ts or datetime.now(timezone.utc).isoformat())


def independent_check(entry: dict, anchor: Anchor, pub: bytes) -> bool:
    """Spec Appendix B with nothing but the verifier primitives."""
    doc = {"alg": entry["alg"], "at": entry["at"], "estate": entry["estate"], "hash_alg": anchor.hash_alg.split(":")[0],
           "head": anchor.head_hash, "kid": entry["kid"], "max_id": anchor.max_id, "v": 2}
    return ed25519.verify(pub, CTX + canon.dumps(doc), b64.strict_decode(entry["sig"]))


# --------------------------------------------------------------------------- #
# the signing hook
# --------------------------------------------------------------------------- #

async def test_the_hook_attaches_one_ed25519_signature_over_the_spec_document(db_pool, world):
    a = fresh_anchor()
    await anchor_sig.sign_hook(db_pool, a)
    assert a.sigs is not None and len(a.sigs) == 1
    (e,) = a.sigs
    assert set(e) == {"v", "alg", "kid", "estate", "at", "sig"}
    assert (e["v"], e["alg"], e["kid"], e["estate"]) == (2, "ed25519", world.key.kid, world.estate)
    assert e["at"] == a.ts[:19] + "Z" and len(b64.strict_decode(e["sig"])) == 64
    assert independent_check(e, a, world.key.public_key)
    assert audit_svc.check_anchor(audit_svc.sign_anchor(a)) == "ok"               # the HMAC side is untouched


async def test_the_signature_is_over_its_own_context_and_never_over_a_dsse_pae(db_pool, world):
    a = fresh_anchor()
    await anchor_sig.sign_hook(db_pool, a)
    (e,) = a.sigs
    sig = b64.strict_decode(e["sig"])
    doc = anchor_sig.public_doc(a, e)
    body = {k: v for k, v in doc.items() if k != "sig"}
    assert ed25519.verify(world.key.public_key, CTX + canon.dumps(body), sig)
    # the same signature is not valid as a statement, a cert or a revocation list signature (a different context)
    for ptype in (dsse.PAYLOAD_TYPE_STATEMENT, dsse.PAYLOAD_TYPE_KEY_CERT, dsse.PAYLOAD_TYPE_REVOCATION):
        assert not ed25519.verify(world.key.public_key, dsse.pae(ptype, canon.dumps(body)), sig)
    assert not ed25519.verify(world.key.public_key, canon.dumps(body), sig)       # nor over the bare document
    assert not CTX.startswith(b"DSSEv1 ") and not b"DSSEv1 ".startswith(CTX[:7])  # contexts are mutually non-prefix


async def test_anchor_sig_not_a_statement_sig_a_key_of_another_usage_is_refused(db_pool, world):
    """A signature made by the estate's ATTEST key over the anchor context is not an anchor signature."""
    async with db_pool.acquire() as con:
        attest = await setup_key(con, usage="attest")
    a = fresh_anchor()
    entry = {"v": 2, "alg": "ed25519", "kid": attest.kid, "estate": world.estate, "at": a.ts[:19] + "Z", "sig": ""}
    doc = a.to_public(world.estate, attest.kid)
    sig = await LocalAesGcmBackend(db_pool).sign(attest.handle, CTX + canon.dumps(doc))
    entry["sig"] = b64.encode(sig)
    assert independent_check(entry, a, attest.public_key)                          # a perfectly good Ed25519 signature
    a.sigs = [entry]
    assert await anchor_sig.anchor_sig_status(db_pool, a) == "bad_signature"       # ... by a key that is not an anchor key


async def test_the_public_document_has_the_documented_shape_and_hides_the_tenant_and_the_hmac_kid(db_pool, world):
    a = fresh_anchor()
    await anchor_sig.sign_hook(db_pool, a)
    doc = anchor_sig.public_doc(a)
    assert set(doc) == {"alg", "at", "estate", "hash_alg", "head", "kid", "max_id", "sig", "v"}
    assert doc["hash_alg"] == "hmac-sha256" and doc["head"] == a.head_hash and doc["max_id"] == 5 and doc["v"] == 2
    data = anchor_sig.public_bytes(doc)
    assert canon.roundtrip(data) == doc and data == canon.dumps(doc)               # canonical PCJ
    assert anchor_sig.public_digest(doc) == "sha256:" + hashlib.sha256(data).hexdigest()
    text = data.decode()
    assert DEFAULT not in text and audit_svc.key_id(HMAC_KEY.encode()) not in text
    a2 = fresh_anchor(alg="sha256", max_id=6)
    await anchor_sig.sign_hook(db_pool, a2)
    assert anchor_sig.public_doc(a2)["hash_alg"] == "sha256"


async def test_the_public_document_is_stored_for_statements_and_the_bundle(db_pool, world):
    a = fresh_anchor()
    await anchor_sig.sign_hook(db_pool, a)
    async with db_pool.acquire() as con:
        rows = await con.fetch("SELECT max_id, at, doc::text AS d FROM attest_anchors")
        latest = await anchor_sig.latest_public(con)
    assert len(rows) == 1 and rows[0]["max_id"] == 5
    assert json.loads(rows[0]["d"]) == anchor_sig.public_doc(a) == latest
    assert rows[0]["at"] == datetime.fromisoformat(a.ts).replace(microsecond=0)


async def test_the_anchor_v2_flag_is_set_by_the_first_v2_anchor_and_never_moves(db_pool, world):
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT anchor_v2_since FROM attest_estates") is None
    await anchor_sig.sign_hook(db_pool, fresh_anchor(max_id=5))
    await anchor_sig.sign_hook(db_pool, fresh_anchor(max_id=9))
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT anchor_v2_since FROM attest_estates") == 5


async def test_signing_the_same_anchor_twice_stores_one_public_document(db_pool, world):
    a = fresh_anchor(ts="2026-11-26T10:00:00.1+00:00")
    b = fresh_anchor(ts="2026-11-26T10:00:00.1+00:00")
    await anchor_sig.sign_hook(db_pool, a)
    await anchor_sig.sign_hook(db_pool, b)
    assert a.sigs == b.sigs                                                        # Ed25519 is deterministic
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT count(*) FROM attest_anchors") == 1


# --------------------------------------------------------------------------- #
# best effort: every failure is a legacy-only anchor, never a blocked one
# --------------------------------------------------------------------------- #

async def anchored_legacy_only(db_pool, tmp_path):
    await audited(db_pool)
    sink = FileAnchorSink(tmp_path / "a.jsonl")
    out = await audit_svc.anchor_head(db_pool, sink)
    assert out["anchored"] is True and "sigs" not in out["anchor"] and out["anchor"]["sig"]
    assert (await audit_svc.verify(db_pool, sink=sink))["ok"] is True              # legacy is accepted before the first v2
    return sink


async def test_no_estate_means_a_legacy_only_anchor(db_pool, plat, tmp_path):
    await anchored_legacy_only(db_pool, tmp_path)
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT count(*) FROM attest_anchors") == 0


async def test_no_active_anchor_key_means_a_legacy_only_anchor(db_pool, plat, tmp_path):
    async with db_pool.acquire() as con:
        await keys.create_key(con, "anchor")                                       # pending only
    await anchored_legacy_only(db_pool, tmp_path)


async def test_an_expired_anchor_cert_means_a_legacy_only_anchor(db_pool, plat, tmp_path):
    past = int(datetime.now(timezone.utc).timestamp()) - 100 * DAY
    async with db_pool.acquire() as con:
        await setup_key(con, now=past)                                             # its 90-day cert ended 10 days ago
    await anchored_legacy_only(db_pool, tmp_path)


async def test_an_unavailable_backend_means_a_legacy_only_anchor(db_pool, world, tmp_path, monkeypatch):
    async def down(self, h, message, *, conn=None):
        raise backend.BackendUnavailable("kms down")

    monkeypatch.setattr(LocalAesGcmBackend, "sign", down)
    await anchored_legacy_only(db_pool, tmp_path)


async def test_a_missing_kek_means_a_legacy_only_anchor(db_pool, world, tmp_path, monkeypatch):
    monkeypatch.setattr(attest_config.settings, "kek", None)
    await anchored_legacy_only(db_pool, tmp_path)


async def test_a_signature_that_cannot_be_stored_is_not_attached(db_pool, world, tmp_path, monkeypatch):
    """If the public document cannot be persisted the anchor must not claim a signature the statement could not cite."""
    async with db_pool.acquire() as con:
        await con.execute("ALTER TABLE attest_anchors RENAME TO attest_anchors_gone")
    try:
        await anchored_legacy_only(db_pool, tmp_path)
    finally:
        async with db_pool.acquire() as con:
            await con.execute("ALTER TABLE attest_anchors_gone RENAME TO attest_anchors")


async def test_the_hook_itself_never_raises_and_never_leaves_sigs_behind(db_pool, world, monkeypatch):
    """Not only anchor_head's guard: the hook is best effort on its own (its callers include tests and tools)."""
    async def down(self, h, message, *, conn=None):
        raise backend.BackendUnavailable("kms down")

    monkeypatch.setattr(LocalAesGcmBackend, "sign", down)
    a = fresh_anchor()
    a.sigs = [{"stale": "from an earlier attempt"}]
    await anchor_sig.sign_hook(db_pool, a)                       # must not raise
    assert a.sigs is None


async def test_the_hook_treats_an_unusable_tenant_id_as_any_other_failure(db_pool, world):
    boom = fresh_anchor(tenant="not-a-uuid")
    await anchor_sig.sign_hook(db_pool, boom)
    assert boom.sigs is None


async def test_the_hook_signs_for_the_anchors_tenant_whatever_the_ambient_context(db_pool, app_pool, plat, tenants):
    out = {}
    for tid in (TA, TB):
        with tenancy.tenant_context(tid):
            async with app_pool.acquire() as con:
                k = await setup_key(con)
                out[tid] = (k, (await estate.get_estate(con)).estate_id)
    a = fresh_anchor(tenant=TB)
    with tenancy.tenant_context(TA):                                               # the wrong ambient tenant on purpose
        await anchor_sig.sign_hook(app_pool, a)
    assert a.sigs[0]["kid"] == out[TB][0].kid and a.sigs[0]["estate"] == out[TB][1]
    assert independent_check(a.sigs[0], a, out[TB][0].public_key)


# --------------------------------------------------------------------------- #
# the lazy bootstrap and register()
# --------------------------------------------------------------------------- #

def test_register_is_idempotent():
    anchor_sig.register()
    anchor_sig.register()
    assert audit_svc.ANCHOR_SIGNERS == [anchor_sig.sign_hook]


async def test_anchor_head_registers_the_signer_by_itself_and_signs(db_pool, world, tmp_path):
    await audited(db_pool)
    sink = FileAnchorSink(tmp_path / "a.jsonl")
    out = await audit_svc.anchor_head(db_pool, sink)
    assert out["anchor"]["sigs"][0]["kid"] == world.key.kid and audit_svc.ANCHOR_SIGNERS == [anchor_sig.sign_hook]
    res = await audit_svc.verify(db_pool, sink=sink)
    assert res["ok"] is True and res["anchor"]["status"] == "ok"
    line = json.loads((tmp_path / "a.jsonl").read_text().splitlines()[0])
    assert line["sigs"] == out["anchor"]["sigs"] and line["sig"]                   # dual anchor under the same sink key


# --------------------------------------------------------------------------- #
# anchor_sig_status
# --------------------------------------------------------------------------- #

async def signed(db_pool, **kw):
    a = fresh_anchor(**kw)
    await anchor_sig.sign_hook(db_pool, a)
    assert a.sigs
    return a


async def test_a_valid_v2_anchor_is_ok(db_pool, world):
    assert await anchor_sig.anchor_sig_status(db_pool, await signed(db_pool)) == "ok"


@pytest.mark.parametrize("name,mutate", [
    ("flipped sig", lambda a, w: a.sigs[0].update(sig=b64.encode(bytes([b64.strict_decode(a.sigs[0]["sig"])[0] ^ 1]) + b64.strict_decode(a.sigs[0]["sig"])[1:]))),
    ("short sig", lambda a, w: a.sigs[0].update(sig=b64.encode(b"\x01" * 63))),
    ("sig not base64", lambda a, w: a.sigs[0].update(sig="!!!")),
    ("other head", lambda a, w: setattr(a, "head_hash", "cd" * 32)),
    ("other max_id", lambda a, w: setattr(a, "max_id", a.max_id + 1)),
    ("other time", lambda a, w: setattr(a, "ts", (datetime.fromisoformat(a.ts) + timedelta(seconds=5)).isoformat())),
    ("other hash family", lambda a, w: setattr(a, "hash_alg", "sha256")),
    ("estate swapped", lambda a, w: a.sigs[0].update(estate="e_" + "q" * 26)),
    ("at swapped", lambda a, w: a.sigs[0].update(at="2026-01-01T00:00:00Z")),
    ("v changed", lambda a, w: a.sigs[0].update(v=3)),
    ("alg changed", lambda a, w: a.sigs[0].update(alg="ecdsa-p256-sha256")),
    ("extra field", lambda a, w: a.sigs[0].update(extra=1)),
    ("missing field", lambda a, w: a.sigs[0].pop("at")),
    ("empty list", lambda a, w: setattr(a, "sigs", [])),
    ("malformed entry", lambda a, w: setattr(a, "sigs", [{"malformed": True}])),
    ("not a dict", lambda a, w: setattr(a, "sigs", ["x"])),
    ("two entries one bad", lambda a, w: a.sigs.append({**a.sigs[0], "sig": b64.encode(b"\x02" * 64)})),
])
async def test_any_tampering_with_a_v2_anchor_fails_closed(db_pool, world, name, mutate):
    a = await signed(db_pool)
    mutate(a, world)
    assert await anchor_sig.anchor_sig_status(db_pool, a) == "bad_signature", name


async def test_signatures_by_unknown_keys_are_ignored_but_an_anchor_with_only_those_is_refused(db_pool, world):
    a = await signed(db_pool)
    stranger = {**a.sigs[0], "kid": "0" * 32, "sig": b64.encode(b"\x07" * 64)}
    both = Anchor.from_dict({**json.loads(a.to_json()), "sigs": [stranger, a.sigs[0]]})
    assert await anchor_sig.anchor_sig_status(db_pool, both) == "ok"
    only = Anchor.from_dict({**json.loads(a.to_json()), "sigs": [stranger]})
    assert await anchor_sig.anchor_sig_status(db_pool, only) == "unknown_key"


async def test_a_signature_made_for_one_estate_is_refused_under_another(db_pool, app_pool, plat, tenants):
    made = {}
    for tid in (TA, TB):
        with tenancy.tenant_context(tid):
            async with app_pool.acquire() as con:
                await setup_key(con)
        a = fresh_anchor(tenant=tid)
        await anchor_sig.sign_hook(app_pool, a)
        made[tid] = a
    assert made[TA].sigs[0]["estate"] != made[TB].sigs[0]["estate"]
    assert await anchor_sig.anchor_sig_status(app_pool, made[TA]) == "ok"
    assert await anchor_sig.anchor_sig_status(app_pool, made[TB]) == "ok"
    swapped = Anchor.from_dict({**json.loads(made[TA].to_json()), "tenant_id": TB})
    assert await anchor_sig.anchor_sig_status(app_pool, swapped) != "ok"           # A's signature cannot vouch for B


async def test_a_db_writer_cannot_mint_an_anchor_key_without_a_certificate_chain(db_pool, world):
    """The DB row is not trusted: the certificate must chain to the pinned root (verifier cert code)."""
    now = int(datetime.now(timezone.utc).timestamp())
    attempts = []
    rogue = Ed25519PrivateKey.generate()
    attempts.append(("self-signed", rogue, rogue, fk.kid_of(fk.raw_pub(rogue))))
    rogue2 = Ed25519PrivateKey.generate()
    attempts.append(("signed by the revoker", rogue2, world.plat.revoker_priv, world.plat.revoker_kid))
    rogue3 = Ed25519PrivateKey.generate()
    attempts.append(("unknown issuer", rogue3, Ed25519PrivateKey.generate(), "1" * 32))
    for name, key, signer, signer_kid in attempts:
        pub, kid = fk.raw_pub(key), fk.kid_of(fk.raw_pub(key))
        cert = fk.make_cert(signer, signer_kid, usage="anchor", pub=pub, not_before=now - DAY, not_after=now + 90 * DAY,
                            estate=world.estate)
        async with db_pool.acquire() as con:
            await con.execute(
                "INSERT INTO attest_keys (kid, usage, public_key, status, not_before, not_after, cert, cert_serial, cert_expires_at) "
                "VALUES ($1, 'anchor', $2, 'pending', $3, $4, $5::jsonb, 1, $6)",
                kid, pub, datetime.fromtimestamp(now - DAY, timezone.utc), datetime.fromtimestamp(now + 90 * DAY, timezone.utc),
                cert.decode(), datetime.fromtimestamp(now + 90 * DAY, timezone.utc))
        a = fresh_anchor()
        entry = {"v": 2, "alg": "ed25519", "kid": kid, "estate": world.estate, "at": a.ts[:19] + "Z", "sig": ""}
        entry["sig"] = b64.encode(key.sign(CTX + canon.dumps(a.to_public(world.estate, kid))))
        a.sigs = [entry]
        assert independent_check(entry, a, pub), name                                  # a perfectly valid Ed25519 signature
        assert await anchor_sig.anchor_sig_status(db_pool, a) == "bad_signature", name


async def test_swapping_the_certificate_in_the_row_for_one_of_the_attackers_fails(db_pool, world):
    a = await signed(db_pool)
    attacker = Ed25519PrivateKey.generate()
    bogus = fk.make_cert(attacker, fk.kid_of(fk.raw_pub(attacker)), usage="anchor", pub=world.key.public_key,
                         not_before=int(datetime.now(timezone.utc).timestamp()) - DAY,
                         not_after=int(datetime.now(timezone.utc).timestamp()) + DAY, estate=world.estate)
    async with db_pool.acquire() as con:
        await con.execute("UPDATE attest_keys SET cert = $2::jsonb WHERE kid = $1", world.key.kid, bogus.decode())
    assert await anchor_sig.anchor_sig_status(db_pool, a) == "bad_signature"


async def test_without_pinned_roots_a_v2_anchor_cannot_be_verified_and_fails_closed(db_pool, world, monkeypatch):
    a = await signed(db_pool)
    monkeypatch.setattr(attest_config.settings, "trust_roots_file", None)
    assert await anchor_sig.anchor_sig_status(db_pool, a) == "bad_signature"


async def test_a_wrong_root_fails_closed(db_pool, world, tmp_path, monkeypatch):
    a = await signed(db_pool)
    other = fk.make_platform(tmp_path / "other")
    monkeypatch.setattr(attest_config.settings, "trust_roots_file", other.files["trust_roots_file"])
    assert await anchor_sig.anchor_sig_status(db_pool, a) == "bad_signature"


async def test_the_anchor_time_must_be_inside_the_certificate_window(db_pool, world):
    a = await signed(db_pool)
    early = Anchor.from_dict({**json.loads(a.to_json()), "ts": (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()})
    early.sigs = None
    # re-sign for the early time with the real key to isolate the window rule from the signature rule
    doc = early.to_public(world.estate, world.key.kid)
    sig = await LocalAesGcmBackend(db_pool).sign(world.key.handle, CTX + canon.dumps(doc))
    early.sigs = [{"v": 2, "alg": "ed25519", "kid": world.key.kid, "estate": world.estate, "at": doc["at"], "sig": b64.encode(sig)}]
    assert independent_check(early.sigs[0], early, world.key.public_key)
    assert await anchor_sig.anchor_sig_status(db_pool, early) == "bad_signature"   # the key did not exist yet


async def test_a_compromised_anchor_key_invalidates_its_anchors_but_a_superseded_one_only_later_ones(db_pool, world):
    before = await signed(db_pool, max_id=5)
    async with db_pool.acquire() as con:
        res = await keys.revoke(con, world.key.kid, reason="key_compromise", actor="admin", justification="leaked")
    assert res.replacement is not None and res.replacement.status == "active"
    assert await anchor_sig.anchor_sig_status(db_pool, before) == "bad_signature"   # regardless of its claimed time
    after = await signed(db_pool, max_id=6)                                        # the replacement key signs from now on
    assert after.sigs[0]["kid"] == res.replacement.kid
    assert await anchor_sig.anchor_sig_status(db_pool, after) == "ok"


async def test_a_superseded_anchor_key_still_verifies_what_it_signed_before_but_not_after(db_pool, world):
    before = await signed(db_pool, max_id=5)
    revoked_at = int(datetime.now(timezone.utc).timestamp()) + 3600
    # a validly signed anchor that claims a time at the revocation instant (made while the key could still sign)
    later = fresh_anchor(max_id=6, ts=datetime.fromtimestamp(revoked_at, timezone.utc).isoformat())
    doc = later.to_public(world.estate, world.key.kid)
    sig = await LocalAesGcmBackend(db_pool).sign(world.key.handle, CTX + canon.dumps(doc))
    later.sigs = [{"v": 2, "alg": "ed25519", "kid": world.key.kid, "estate": world.estate, "at": doc["at"], "sig": b64.encode(sig)}]
    assert independent_check(later.sigs[0], later, world.key.public_key)
    async with db_pool.acquire() as con:
        await keys.revoke(con, world.key.kid, reason="superseded", actor="admin", justification="rotated away", now=revoked_at)
    assert await anchor_sig.anchor_sig_status(db_pool, before) == "ok"             # older statements keep verifying
    assert await anchor_sig.anchor_sig_status(db_pool, later) == "bad_signature"   # at >= revoked_at is refused


async def test_a_rolled_over_anchor_key_keeps_verifying_old_anchors(db_pool, world):
    old = await signed(db_pool, max_id=5)
    async with db_pool.acquire() as con:
        nxt = await keys.rotate(con, "anchor")
        await keys.activate(con, nxt.kid)
    new = await signed(db_pool, max_id=6)
    assert new.sigs[0]["kid"] == nxt.kid != old.sigs[0]["kid"]
    assert await anchor_sig.anchor_sig_status(db_pool, old) == "ok"
    assert await anchor_sig.anchor_sig_status(db_pool, new) == "ok"


# --------------------------------------------------------------------------- #
# no silent downgrade
# --------------------------------------------------------------------------- #

async def test_legacy_anchors_are_accepted_until_the_first_v2_anchor_then_never_again(db_pool, world, tmp_path):
    await audited(db_pool)
    sink = FileAnchorSink(tmp_path / "a.jsonl")
    # the world fixture has an active anchor key, so remove the signer for the first anchor: legacy-only
    out = await audit_svc.anchor_head(db_pool, sink)
    assert "sigs" in out["anchor"] and (await audit_svc.verify(db_pool, sink=sink))["ok"] is True
    # an attacker (or an outage) now yields a legacy-only anchor for a later head
    await audited(db_pool, 1)
    audit_svc.ANCHOR_SIGNERS.clear()
    audit_svc._SIGNERS_BOOTSTRAPPED = True
    out2 = await audit_svc.anchor_head(db_pool, sink)
    assert out2["anchored"] is True and "sigs" not in out2["anchor"]
    res = await audit_svc.verify(db_pool, sink=sink)
    assert res["ok"] is False and res["anchor"]["status"] == "downgrade" and res["reason"] == "anchor_downgrade"
    # the next successful signing heals it
    audit_svc._SIGNERS_BOOTSTRAPPED = False
    await audited(db_pool, 1)
    await audit_svc.anchor_head(db_pool, sink)
    assert (await audit_svc.verify(db_pool, sink=sink))["ok"] is True


async def test_anchor_downgrade_fails_closed_even_if_the_sink_is_rolled_back_to_an_old_legacy_anchor(db_pool, world, tmp_path):
    await audited(db_pool)
    legacy_sink = FileAnchorSink(tmp_path / "legacy.jsonl")
    audit_svc.ANCHOR_SIGNERS.clear()
    audit_svc._SIGNERS_BOOTSTRAPPED = True
    await audit_svc.anchor_head(db_pool, legacy_sink)                              # an old, legacy anchor
    audit_svc._SIGNERS_BOOTSTRAPPED = False
    await audited(db_pool, 1)
    v2_sink = FileAnchorSink(tmp_path / "v2.jsonl")
    await audit_svc.anchor_head(db_pool, v2_sink)                                  # the first v2 anchor sets the flag
    # an attacker who controls the sink serves the old legacy anchor again
    res = await audit_svc.verify(db_pool, sink=legacy_sink)
    assert res["ok"] is False and res["anchor"]["status"] == "downgrade"


async def test_stripping_sigs_from_a_published_anchor_is_a_downgrade(db_pool, world, tmp_path):
    await audited(db_pool)
    sink = FileAnchorSink(tmp_path / "a.jsonl")
    await audit_svc.anchor_head(db_pool, sink)
    line = json.loads((tmp_path / "a.jsonl").read_text())
    line.pop("sigs")
    (tmp_path / "a.jsonl").write_text(json.dumps(line) + "\n")                     # the HMAC is still valid
    res = await audit_svc.verify(db_pool, sink=sink)
    assert res["ok"] is False and res["anchor"]["status"] == "downgrade"


async def test_tampering_with_sigs_in_the_sink_fails_the_full_verify(db_pool, world, tmp_path):
    await audited(db_pool)
    sink = FileAnchorSink(tmp_path / "a.jsonl")
    await audit_svc.anchor_head(db_pool, sink)
    line = json.loads((tmp_path / "a.jsonl").read_text())
    line["sigs"][0]["sig"] = b64.encode(b"\x09" * 64)
    (tmp_path / "a.jsonl").write_text(json.dumps(line) + "\n")
    res = await audit_svc.verify(db_pool, sink=sink)
    assert res["ok"] is False and res["anchor"]["status"] == "bad_signature" and res["reason"] == "anchor_bad_signature"


async def test_allow_legacy_false_refuses_every_legacy_anchor_and_accepts_v2(db_pool, world, tmp_path, monkeypatch):
    await audited(db_pool)
    audit_svc.ANCHOR_SIGNERS.clear()
    audit_svc._SIGNERS_BOOTSTRAPPED = True
    legacy_sink = FileAnchorSink(tmp_path / "legacy.jsonl")
    await audit_svc.anchor_head(db_pool, legacy_sink)
    monkeypatch.setenv("AUDIT_ANCHOR_ALLOW_LEGACY", "false")
    assert (await audit_svc.verify(db_pool, sink=legacy_sink))["anchor"]["status"] == "downgrade"
    audit_svc._SIGNERS_BOOTSTRAPPED = False
    await audited(db_pool, 1)
    v2_sink = FileAnchorSink(tmp_path / "v2.jsonl")
    await audit_svc.anchor_head(db_pool, v2_sink)
    assert (await audit_svc.verify(db_pool, sink=v2_sink))["ok"] is True


@pytest.mark.parametrize("value,allowed", [("true", True), ("1", True), ("yes", True), ("TRUE", True), ("false", False),
                                           ("0", False), ("no", False), ("off", False), ("maybe", False), ("", False)])
async def test_the_allow_legacy_flag_parses_fail_safe(db_pool, plat, monkeypatch, value, allowed):
    monkeypatch.setenv("AUDIT_ANCHOR_ALLOW_LEGACY", value)
    status = await anchor_sig.anchor_sig_status(db_pool, fresh_anchor())
    assert status == ("ok" if allowed else "downgrade")


async def test_an_unset_flag_allows_legacy_and_a_tenant_without_an_estate_is_unaffected(db_pool, plat):
    assert await anchor_sig.anchor_sig_status(db_pool, fresh_anchor()) == "ok"


async def test_a_database_without_the_attest_tables_still_verifies_legacy_anchors(db_pool, plat):
    async with db_pool.acquire() as con:
        await con.execute("ALTER TABLE attest_estates RENAME TO attest_estates_gone")
    try:
        assert await anchor_sig.anchor_sig_status(db_pool, fresh_anchor()) == "ok"
    finally:
        async with db_pool.acquire() as con:
            await con.execute("ALTER TABLE attest_estates_gone RENAME TO attest_estates")


async def test_the_sticky_flag_is_per_tenant(db_pool, app_pool, plat, tenants):
    with tenancy.tenant_context(TA):
        async with app_pool.acquire() as con:
            await setup_key(con)
    await anchor_sig.sign_hook(app_pool, fresh_anchor(tenant=TA, max_id=3))
    assert await anchor_sig.anchor_sig_status(app_pool, fresh_anchor(tenant=TA, max_id=9)) == "downgrade"
    assert await anchor_sig.anchor_sig_status(app_pool, fresh_anchor(tenant=TB, max_id=9)) == "ok"
