"""P3.3: certificates, chain verification, keys.json, platform key loading and the root ceremony script
(docs/ASSURANCE_P3.md 3.1, 3.2, D16).

Certificates are built here with an independent construction (``attest_fakes``: cryptography + the verifier's byte
primitives only), and the production ``attest.certs`` / ``attest.platform_keys`` are checked against it in both
directions: what production issues must verify under the independent check, and what the independent builder makes
must verify (or be rejected for the right code) under production ``verify_chain``.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import stat
import sys
import zipfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from paddock_verify import b64, dsse, ed25519

from app.attest import certs, platform_keys

from . import attest_fakes as fk
from .attest_fakes import DAY, ESTATE_A, ESTATE_B, T0

ROOT = Path(__file__).resolve().parents[2]
CEREMONY = ROOT / "scripts" / "attest_root_ceremony.py"


@pytest.fixture
def plat(tmp_path, monkeypatch):
    p = fk.make_platform(tmp_path / "plat")
    fk.install(monkeypatch, p)
    return p


@pytest.fixture
def roots(plat):
    return certs.parse_roots(plat.roots)


@pytest.fixture
def leaf_key():
    return Ed25519PrivateKey.generate()


def attest_cert(plat, leaf_key, *, usage="attest", estate=ESTATE_A, nb=T0, na=T0 + 90 * DAY, signer=None,
                signer_kid=None, **extra):
    return fk.make_cert(signer or plat.issuer_priv, signer_kid or plat.issuer_kid, usage=usage,
                        pub=fk.raw_pub(leaf_key), not_before=nb, not_after=na, serial=5, estate=estate, **extra)


def reject(code, *args, **kw):
    with pytest.raises(certs.CertError) as ei:
        certs.verify_chain(*args, **kw)
    assert ei.value.code == code, (ei.value.code, ei.value.detail)
    return ei.value


# --------------------------------------------------------------------------- #
# the happy path and the independent cross-check
# --------------------------------------------------------------------------- #

def test_a_certificate_chain_to_a_pinned_root_verifies(plat, roots, leaf_key):
    env = attest_cert(plat, leaf_key)
    res = certs.verify_chain(env, issuers=[plat.issuer_cert], roots=roots, at=T0 + DAY,
                             expect_usage="attest", expect_estate=ESTATE_A)
    assert res.cert.kid == fk.kid_of(fk.raw_pub(leaf_key)) and res.cert.usage == "attest"
    assert res.cert.public_key == fk.raw_pub(leaf_key) and res.cert.estate == ESTATE_A
    assert res.cert.custody == "hosted" and res.cert.serial == 5 and res.cert.alg == "ed25519"
    assert res.issuer.kid == plat.issuer_kid and res.root.kid == plat.root_kid and res.depth == 2
    assert res.window == (T0, T0 + 90 * DAY)          # the intersection of the three windows


def test_envelopes_as_text_or_object_are_accepted_and_a_parsed_cert_round_trips(plat, roots, leaf_key):
    env = attest_cert(plat, leaf_key)
    parsed = certs.parse_cert(env)
    for form in (env, env.decode(), json.loads(env), parsed):
        assert certs.verify_chain(form, issuers=[json.loads(plat.issuer_cert)], roots=roots, at=T0).cert.kid == parsed.kid
    assert parsed.envelope == env


def test_a_self_hoster_pins_its_own_issuer_and_the_chain_has_length_one(plat, leaf_key):
    pinned = [{"kid": plat.issuer_kid, "public_key": b64.encode(plat.issuer_pub), "usage": "issue-cert",
               "not_before": fk.ts(T0 - 100 * DAY), "not_after": fk.ts(T0 + 300 * DAY)}]
    res = certs.verify_chain(attest_cert(plat, leaf_key), issuers=[], roots=certs.parse_roots(pinned), at=T0 + 1)
    assert res.depth == 1 and res.issuer is None and res.root.kid == plat.issuer_kid


def test_a_pinned_issuer_does_not_certify_other_issuers_or_revokers(plat, leaf_key):
    pinned = [{"kid": plat.issuer_kid, "public_key": b64.encode(plat.issuer_pub), "usage": "issue-cert",
               "not_before": fk.ts(T0 - 100 * DAY), "not_after": fk.ts(T0 + 300 * DAY)}]
    other = Ed25519PrivateKey.generate()
    forged = fk.make_cert(plat.issuer_priv, plat.issuer_kid, usage="issue-cert", pub=fk.raw_pub(other),
                          not_before=T0 - DAY, not_after=T0 + DAY)
    reject("key.cert_subject_mismatch", forged, issuers=[], roots=certs.parse_roots(pinned), at=T0)


def test_certs_issued_by_production_verify_under_the_independent_check(plat, roots, leaf_key):
    pk = platform_keys.load(now=T0)
    cert = certs.issue_cert(pk.issuer, usage="anchor", public_key=fk.raw_pub(leaf_key), estate=ESTATE_A,
                            not_before=T0, not_after=T0 + 90 * DAY, serial=7)
    body = fk.independent_cert_check(cert.envelope, plat.issuer_pub)
    assert body == {
        "_type": "https://paddock.dev/key-cert/v1", "alg": "ed25519", "custody": "hosted", "estate": ESTATE_A,
        "issuer_kid": plat.issuer_kid, "kid": fk.kid_of(fk.raw_pub(leaf_key)), "not_after": fk.ts(T0 + 90 * DAY),
        "not_before": fk.ts(T0), "public_key": b64.encode(fk.raw_pub(leaf_key)), "serial": 7, "usage": "anchor"}
    again = certs.issue_cert(pk.issuer, usage="anchor", public_key=fk.raw_pub(leaf_key), estate=ESTATE_A,
                             not_before=T0, not_after=T0 + 90 * DAY, serial=7)
    assert again.envelope == cert.envelope                  # Ed25519 and PCJ are deterministic
    assert certs.verify_chain(cert, issuers=[pk.issuer.cert], roots=roots, at=T0).cert.usage == "anchor"


def test_the_issued_payload_is_pcj_and_the_signature_is_over_the_dsse_pae(plat, leaf_key):
    pk = platform_keys.load(now=T0)
    cert = certs.issue_cert(pk.issuer, usage="attest", public_key=fk.raw_pub(leaf_key), estate=ESTATE_A,
                            not_before=T0, not_after=T0 + DAY, serial=1)
    e = dsse.parse_envelope(cert.envelope, expected_type="application/vnd.paddock.key-cert+json")
    assert ed25519.verify(plat.issuer_pub, dsse.pae(e.payload_type, e.payload), e.sig)
    assert not ed25519.verify(plat.issuer_pub, e.payload, e.sig)                       # not the raw payload
    assert not ed25519.verify(plat.issuer_pub, b64.encode(e.payload).encode(), e.sig)  # not the base64 text
    assert e.keyid == plat.issuer_kid and e.payload == cert.payload and b" " not in e.payload


# --------------------------------------------------------------------------- #
# issue_cert refusals
# --------------------------------------------------------------------------- #

def test_issue_cert_clamps_the_window_to_the_issuers(plat, leaf_key):
    pk = platform_keys.load(now=T0)
    nb, na = int(pk.issuer.cert.not_before), int(pk.issuer.cert.not_after)
    c = certs.issue_cert(pk.issuer, usage="attest", public_key=fk.raw_pub(leaf_key), estate=ESTATE_A,
                         not_before=nb - 50 * DAY, not_after=na + 50 * DAY, serial=1)
    assert (c.not_before, c.not_after) == (nb, na)


def test_issue_cert_refuses_a_window_that_the_issuer_cannot_cover(plat, leaf_key):
    pk = platform_keys.load(now=T0)
    na = int(pk.issuer.cert.not_after)
    with pytest.raises(certs.CertError) as ei:
        certs.issue_cert(pk.issuer, usage="attest", public_key=fk.raw_pub(leaf_key), estate=ESTATE_A,
                         not_before=na + DAY, not_after=na + 90 * DAY, serial=1)
    assert ei.value.code == "key.outside_validity"


@pytest.mark.parametrize("kw,code", [
    (dict(usage="issue-cert"), "key.cert_subject_mismatch"),      # an online issuer never certifies issuers
    (dict(usage="revoke"), "key.cert_subject_mismatch"),
    (dict(usage="nope"), "key.cert_invalid"),
    (dict(estate=None), "key.cert_invalid"),
    (dict(estate="e_short"), "key.cert_invalid"),
    (dict(public_key=b"\x01" * 31), "key.cert_invalid"),
    (dict(public_key=b"\x00" * 31 + b"\x80"), "sig.weak_key"),    # a point of small order
    (dict(custody="vault"), "key.cert_invalid"),
    (dict(alg="rsa"), "sig.alg_unsupported"),
    (dict(serial=-1), "key.cert_invalid"),
    (dict(serial=2 ** 53), "key.cert_invalid"),
    (dict(not_after=T0), "key.cert_invalid"),
])
def test_issue_cert_refuses_bad_input(plat, leaf_key, kw, code):
    pk = platform_keys.load(now=T0)
    args = dict(usage="attest", public_key=fk.raw_pub(leaf_key), estate=ESTATE_A, not_before=T0,
                not_after=T0 + DAY, serial=1)
    args.update(kw)
    with pytest.raises(certs.CertError) as ei:
        certs.issue_cert(pk.issuer, **args)
    assert ei.value.code == code


def test_the_revoker_cannot_issue_estate_certs(plat, leaf_key):
    pk = platform_keys.load(now=T0)
    with pytest.raises(certs.CertError) as ei:
        certs.issue_cert(pk.revoker, usage="attest", public_key=fk.raw_pub(leaf_key), estate=ESTATE_A,
                         not_before=T0, not_after=T0 + DAY, serial=1)
    assert ei.value.code == "key.cert_subject_mismatch"


# --------------------------------------------------------------------------- #
# chain rejection matrix
# --------------------------------------------------------------------------- #

def test_without_trust_roots_nothing_verifies(plat, leaf_key):
    reject("config.no_trust_roots", attest_cert(plat, leaf_key), issuers=[plat.issuer_cert], roots=[], at=T0)


def test_an_issuer_that_is_not_supplied_or_not_known_does_not_chain(plat, roots, leaf_key):
    reject("key.root_unknown", attest_cert(plat, leaf_key), issuers=[], roots=roots, at=T0)
    stranger = Ed25519PrivateKey.generate()
    forged = attest_cert(plat, leaf_key, signer=stranger, signer_kid=fk.kid_of(fk.raw_pub(stranger)))
    reject("key.root_unknown", forged, issuers=[plat.issuer_cert], roots=roots, at=T0)


def test_an_issuer_cert_signed_by_a_foreign_root_does_not_chain(plat, leaf_key, tmp_path):
    other = fk.make_platform(tmp_path / "other")
    env = fk.make_cert(other.issuer_priv, other.issuer_kid, usage="attest", pub=fk.raw_pub(leaf_key), not_before=T0,
                       not_after=T0 + DAY, estate=ESTATE_A)
    reject("key.root_unknown", env, issuers=[other.issuer_cert], roots=certs.parse_roots(plat.roots), at=T0)


def test_a_root_never_signs_an_estate_key_directly(plat, roots, leaf_key):
    env = attest_cert(plat, leaf_key, signer=plat.root_priv, signer_kid=plat.root_kid)
    reject("key.cert_subject_mismatch", env, issuers=[], roots=roots, at=T0)


def test_an_issuer_cert_must_be_signed_by_a_root_not_by_another_issuer(plat, roots, leaf_key):
    rogue = Ed25519PrivateKey.generate()
    rogue_cert = fk.make_cert(plat.issuer_priv, plat.issuer_kid, usage="issue-cert", pub=fk.raw_pub(rogue),
                              not_before=T0 - DAY, not_after=T0 + 30 * DAY)        # signed by the issuer: depth 3
    env = attest_cert(plat, leaf_key, signer=rogue, signer_kid=fk.kid_of(fk.raw_pub(rogue)))
    reject("key.root_unknown", env, issuers=[rogue_cert, plat.issuer_cert], roots=roots, at=T0)


def test_certificate_usage_confusion_is_refused(plat, roots, leaf_key):
    # a revoker certificate cannot stand in for an issuer certificate
    env = attest_cert(plat, leaf_key, signer=plat.revoker_priv, signer_kid=plat.revoker_kid)
    reject("key.cert_subject_mismatch", env, issuers=[plat.revoker_cert], roots=roots, at=T0)
    # an anchor cert is not an attest cert and the reverse
    anchor = attest_cert(plat, leaf_key, usage="anchor")
    reject("key.cert_subject_mismatch", anchor, issuers=[plat.issuer_cert], roots=roots, at=T0, expect_usage="attest")
    # a cert for another estate
    reject("key.cert_subject_mismatch", attest_cert(plat, leaf_key, estate=ESTATE_B), issuers=[plat.issuer_cert],
           roots=roots, at=T0, expect_estate=ESTATE_A)


def test_the_validity_window_is_end_exclusive_and_checked_at_the_given_time(plat, roots, leaf_key):
    env = attest_cert(plat, leaf_key, nb=T0, na=T0 + 90 * DAY)
    kw = dict(issuers=[plat.issuer_cert], roots=roots)
    certs.verify_chain(env, at=T0, **kw)
    certs.verify_chain(env, at=T0 + 90 * DAY - 1, **kw)
    reject("key.outside_validity", env, at=T0 - 1, **kw)
    reject("key.outside_validity", env, at=T0 + 90 * DAY, **kw)
    reject("key.outside_validity", env, at=T0 + 91 * DAY, **kw)


def test_the_signing_key_window_must_contain_valid_until(plat, roots, leaf_key):
    env = attest_cert(plat, leaf_key, nb=T0, na=T0 + 90 * DAY)
    kw = dict(issuers=[plat.issuer_cert], roots=roots, at=T0 + 1)
    certs.verify_chain(env, valid_until=T0 + 90 * DAY, **kw)
    reject("key.outside_validity", env, valid_until=T0 + 90 * DAY + 1, **kw)


def test_an_issuer_outside_its_window_at_the_given_time_is_refused(tmp_path, leaf_key):
    p = fk.make_platform(tmp_path / "p", issuer_window=(T0 - 100 * DAY, T0 + 10 * DAY))
    r = certs.parse_roots(p.roots)
    env = fk.make_cert(p.issuer_priv, p.issuer_kid, usage="attest", pub=fk.raw_pub(leaf_key), not_before=T0 - 120 * DAY,
                       not_after=T0 + 90 * DAY, estate=ESTATE_A)
    certs.verify_chain(env, issuers=[p.issuer_cert], roots=r, at=T0 + 9 * DAY)
    reject("issuer.outside_validity", env, issuers=[p.issuer_cert], roots=r, at=T0 + 10 * DAY)
    reject("issuer.outside_validity", env, issuers=[p.issuer_cert], roots=r, at=T0 - 101 * DAY)


def test_an_expired_root_is_refused_as_an_issuer_problem(tmp_path, leaf_key):
    p = fk.make_platform(tmp_path / "p", root_window=(T0 - 400 * DAY, T0 + 5 * DAY))
    env = fk.make_cert(p.issuer_priv, p.issuer_kid, usage="attest", pub=fk.raw_pub(leaf_key), not_before=T0,
                       not_after=T0 + 90 * DAY, estate=ESTATE_A)
    reject("issuer.outside_validity", env, issuers=[p.issuer_cert], roots=certs.parse_roots(p.roots), at=T0 + 6 * DAY)


def test_a_revoked_issuer_is_refused(plat, roots, leaf_key):
    reject("issuer.revoked", attest_cert(plat, leaf_key), issuers=[plat.issuer_cert], roots=roots, at=T0,
           revoked_issuers={plat.issuer_kid})


def test_a_tampered_certificate_fails_its_signature(plat, roots, leaf_key):
    env = json.loads(attest_cert(plat, leaf_key))
    raw = bytearray(b64.strict_decode(env["payload"]))
    raw[raw.index(b"attest")] ^= 0x01                              # "attest" -> "`ttest": still canonical-looking ASCII
    env["payload"] = b64.encode(bytes(raw))
    reject("key.cert_invalid", env, issuers=[plat.issuer_cert], roots=roots, at=T0)
    sig = bytearray(b64.strict_decode(json.loads(attest_cert(plat, leaf_key))["signatures"][0]["sig"]))
    sig[0] ^= 1
    env2 = json.loads(attest_cert(plat, leaf_key))
    env2["signatures"][0]["sig"] = b64.encode(bytes(sig))
    reject("key.cert_invalid", env2, issuers=[plat.issuer_cert], roots=roots, at=T0)


def test_a_signature_with_a_non_reduced_scalar_is_refused(plat, roots, leaf_key):
    env = json.loads(attest_cert(plat, leaf_key))
    sig = b64.strict_decode(env["signatures"][0]["sig"])
    s = int.from_bytes(sig[32:], "little") + (2 ** 252 + 27742317777372353535851937790883648493)
    env["signatures"][0]["sig"] = b64.encode(sig[:32] + s.to_bytes(32, "little"))
    reject("key.cert_invalid", env, issuers=[plat.issuer_cert], roots=roots, at=T0)


def test_a_validly_signed_but_non_canonical_payload_is_refused(plat, roots, leaf_key):
    good = fk.cert_payload(usage="attest", pub=fk.raw_pub(leaf_key), issuer_kid=plat.issuer_kid, not_before=T0,
                           not_after=T0 + DAY, estate=ESTATE_A)
    spaced = good.replace(b",", b", ")
    env = fk.envelope(plat.issuer_priv, plat.issuer_kid, dsse.PAYLOAD_TYPE_KEY_CERT, spaced)
    reject("key.cert_invalid", env, issuers=[plat.issuer_cert], roots=roots, at=T0)


def test_the_envelope_key_id_must_be_the_issuer_kid_in_the_payload(plat, roots, leaf_key):
    payload = fk.cert_payload(usage="attest", pub=fk.raw_pub(leaf_key), issuer_kid=plat.issuer_kid, not_before=T0,
                              not_after=T0 + DAY, estate=ESTATE_A)
    env = fk.envelope(plat.issuer_priv, "0" * 32, dsse.PAYLOAD_TYPE_KEY_CERT, payload)
    reject("key.cert_invalid", env, issuers=[plat.issuer_cert], roots=roots, at=T0)


def test_a_statement_envelope_is_not_a_certificate(plat, roots, leaf_key):
    payload = fk.cert_payload(usage="attest", pub=fk.raw_pub(leaf_key), issuer_kid=plat.issuer_kid, not_before=T0,
                              not_after=T0 + DAY, estate=ESTATE_A)
    env = fk.envelope(plat.issuer_priv, plat.issuer_kid, dsse.PAYLOAD_TYPE_STATEMENT, payload)
    reject("key.cert_invalid", env, issuers=[plat.issuer_cert], roots=roots, at=T0)


@pytest.mark.parametrize("extra,code", [
    (dict(extra_field=1), "key.cert_invalid"),
    (dict(alg="ecdsa-p256-sha256"), "sig.alg_unsupported"),
    (dict(alg="rsa"), "sig.alg_unsupported"),
    (dict(custody="vault"), "key.cert_invalid"),
    (dict(usage="superuser"), "key.cert_invalid"),
])
def test_payload_schema_violations_are_refused(plat, roots, leaf_key, extra, code):
    kw = dict(usage="attest", pub=fk.raw_pub(leaf_key), issuer_kid=plat.issuer_kid, not_before=T0,
              not_after=T0 + DAY, estate=ESTATE_A)
    kw.update(extra)
    env = fk.envelope(plat.issuer_priv, plat.issuer_kid, dsse.PAYLOAD_TYPE_KEY_CERT, fk.cert_payload(**kw))
    reject(code, env, issuers=[plat.issuer_cert], roots=roots, at=T0)


def test_estate_presence_follows_usage(plat, roots, leaf_key):
    for usage, estate in (("attest", None), ("anchor", None), ("revoke", ESTATE_A), ("issue-cert", ESTATE_A)):
        env = fk.envelope(plat.root_priv if usage in ("revoke", "issue-cert") else plat.issuer_priv,
                          plat.root_kid if usage in ("revoke", "issue-cert") else plat.issuer_kid,
                          dsse.PAYLOAD_TYPE_KEY_CERT,
                          fk.cert_payload(usage=usage, pub=fk.raw_pub(leaf_key),
                                          issuer_kid=plat.root_kid if usage in ("revoke", "issue-cert") else plat.issuer_kid,
                                          not_before=T0, not_after=T0 + DAY, estate=estate))
        reject("key.cert_invalid", env, issuers=[plat.issuer_cert], roots=roots, at=T0)


def test_a_kid_that_is_not_the_key_fingerprint_is_refused(plat, roots, leaf_key):
    env = fk.envelope(plat.issuer_priv, plat.issuer_kid, dsse.PAYLOAD_TYPE_KEY_CERT,
                      fk.cert_payload(usage="attest", pub=fk.raw_pub(leaf_key), issuer_kid=plat.issuer_kid,
                                      not_before=T0, not_after=T0 + DAY, estate=ESTATE_A, kid="1" * 32))
    reject("key.fingerprint_mismatch", env, issuers=[plat.issuer_cert], roots=roots, at=T0)


@pytest.mark.parametrize("nb,na", [(T0, T0), (T0 + 5, T0)])
def test_an_empty_or_inverted_window_is_refused(plat, roots, leaf_key, nb, na):
    env = fk.envelope(plat.issuer_priv, plat.issuer_kid, dsse.PAYLOAD_TYPE_KEY_CERT,
                      fk.cert_payload(usage="attest", pub=fk.raw_pub(leaf_key), issuer_kid=plat.issuer_kid,
                                      not_before=nb, not_after=na, estate=ESTATE_A))
    reject("key.cert_invalid", env, issuers=[plat.issuer_cert], roots=roots, at=T0)


def test_garbage_is_a_cert_error_not_a_crash(plat, roots):
    for junk in (b"", b"{}", b"not json", b"[]", None, 5, {"payloadType": 1}):
        with pytest.raises(certs.CertError):
            certs.verify_chain(junk, issuers=[], roots=roots, at=T0)


@pytest.mark.parametrize("by,depth", [("root", 1), ("issuer", 2)])
def test_a_revoker_chains_through_the_root_or_through_the_issuer(tmp_path, by, depth):
    p = fk.make_platform(tmp_path / by, revoker_certified_by=by)
    res = certs.verify_chain(p.revoker_cert, issuers=[p.issuer_cert], roots=certs.parse_roots(p.roots), at=T0,
                             expect_usage="revoke")
    assert res.cert.usage == "revoke" and res.depth == depth and res.root.kid == p.root_kid


def test_a_pinned_issuer_may_certify_the_revoker_so_a_self_hoster_needs_no_root(tmp_path):
    p = fk.make_platform(tmp_path / "p", revoker_certified_by="issuer")
    pinned = [{"kid": p.issuer_kid, "public_key": b64.encode(p.issuer_pub), "usage": "issue-cert",
               "not_before": fk.ts(T0 - 100 * DAY), "not_after": fk.ts(T0 + 300 * DAY)}]
    res = certs.verify_chain(p.revoker_cert, issuers=[], roots=certs.parse_roots(pinned), at=T0)
    assert res.depth == 1 and res.issuer is None
    reject("issuer.revoked", p.revoker_cert, issuers=[], roots=certs.parse_roots(pinned + [{"kid": p.issuer_kid, "usage": "issuer-revoked"}]), at=T0)


def test_only_a_root_or_an_issuer_may_certify_a_revoker(plat, leaf_key, roots):
    rogue = Ed25519PrivateKey.generate()
    attest_cert_env = attest_cert(plat, rogue)
    for signer, signer_kid, issuers in ((plat.revoker_priv, plat.revoker_kid, [plat.revoker_cert]),      # a revoker
                                         (rogue, fk.kid_of(fk.raw_pub(rogue)), [attest_cert_env])):       # an estate key
        env = fk.make_cert(signer, signer_kid, usage="revoke", pub=fk.raw_pub(leaf_key), not_before=T0, not_after=T0 + DAY)
        with pytest.raises(certs.CertError) as ei:
            certs.verify_chain(env, issuers=issuers, roots=roots, at=T0)
        assert ei.value.code in ("key.cert_subject_mismatch", "key.root_unknown")
    stranger = Ed25519PrivateKey.generate()
    env = fk.make_cert(stranger, fk.kid_of(fk.raw_pub(stranger)), usage="revoke", pub=fk.raw_pub(leaf_key), not_before=T0,
                       not_after=T0 + DAY)
    reject("key.root_unknown", env, issuers=[plat.issuer_cert], roots=roots, at=T0)


# --------------------------------------------------------------------------- #
# trust roots
# --------------------------------------------------------------------------- #

def test_parse_roots_validates_every_entry(plat):
    good = plat.roots[0]
    assert certs.parse_roots(plat.roots)[0].kid == plat.root_kid
    assert certs.parse_roots(json.dumps(plat.roots))[0].usage == "root"
    for bad in (
        {**good, "kid": "0" * 32},                    # kid is not the key's fingerprint
        {**good, "usage": "attest"},
        {**good, "public_key": "AAAA"},
        {**good, "extra": 1},
        {k: v for k, v in good.items() if k != "usage"},
        {**good, "not_after": "tomorrow"},
        {**good, "not_before": good["not_after"]},
    ):
        with pytest.raises(certs.CertError):
            certs.parse_roots([bad])
    with pytest.raises(certs.CertError):
        certs.parse_roots([good, good])               # duplicate kid
    with pytest.raises(certs.CertError):
        certs.parse_roots({"not": "a list"})


def test_trust_roots_may_carry_issuer_revoked_entries_that_verify_chain_applies_by_itself(plat, leaf_key):
    """The verifier release lists revoked issuers inside its roots data (``{"kid","usage":"issuer-revoked"}``): the
    parsed roots carry them, so passing them to ``verify_chain`` is enough to refuse that issuer."""
    data = plat.roots + [{"kid": plat.issuer_kid, "usage": "issuer-revoked"}]
    roots = certs.parse_roots(data)
    assert [r.kid for r in roots] == [plat.root_kid] and roots.revoked_issuers == frozenset({plat.issuer_kid})
    reject("issuer.revoked", attest_cert(plat, leaf_key), issuers=[plat.issuer_cert], roots=roots, at=T0)
    certs.verify_chain(attest_cert(plat, leaf_key), issuers=[plat.issuer_cert], roots=certs.parse_roots(plat.roots), at=T0)
    for bad in ({"kid": plat.issuer_kid, "usage": "issuer-revoked", "extra": 1}, {"kid": "zz", "usage": "issuer-revoked"},
                {"usage": "issuer-revoked"}):
        with pytest.raises(certs.CertError):
            certs.parse_roots(plat.roots + [bad])


def test_a_pinned_issuer_that_the_release_also_revokes_is_refused(plat, leaf_key):
    pinned = [{"kid": plat.issuer_kid, "public_key": b64.encode(plat.issuer_pub), "usage": "issue-cert",
               "not_before": fk.ts(T0 - 100 * DAY), "not_after": fk.ts(T0 + 300 * DAY)},
              {"kid": plat.issuer_kid, "usage": "issuer-revoked"}]
    reject("issuer.revoked", attest_cert(plat, leaf_key), issuers=[], roots=certs.parse_roots(pinned), at=T0)


def test_platform_keys_whose_issuer_the_release_revokes_are_refused(plat, monkeypatch, tmp_path):
    from app.attest import config as c

    path = tmp_path / "revoking_roots.json"
    path.write_text(json.dumps(plat.roots + [{"kid": plat.issuer_kid, "usage": "issuer-revoked"}]))
    monkeypatch.setattr(c.settings, "trust_roots_file", str(path))
    platform_keys.reset_cache()
    with pytest.raises(platform_keys.PlatformKeysError) as ei:
        platform_keys.load(now=T0)
    assert ei.value.code == "issuer.revoked"


# --------------------------------------------------------------------------- #
# keys.json
# --------------------------------------------------------------------------- #

def keys_doc(plat, leaf_key, **over):
    cert = certs.parse_cert(attest_cert(plat, leaf_key))
    return certs.build_keys_json(ESTATE_A, issuers=[plat.issuer_cert], revoker=plat.revoker_cert, certs_=[cert]), cert


def test_keys_json_has_the_documented_shape_and_is_deterministic(plat, leaf_key):
    data, cert = keys_doc(plat, leaf_key)
    doc = json.loads(data)
    assert set(doc) == {"spec", "estate", "issuers", "revoker", "keys"} and doc["spec"] == "paddock-keys/v1"
    assert doc["estate"] == ESTATE_A and doc["issuers"] == [json.loads(plat.issuer_cert)]
    assert doc["revoker"] == json.loads(plat.revoker_cert)
    (entry,) = doc["keys"]
    assert entry == {"kid": cert.kid, "usage": "attest", "alg": "ed25519", "public_key": b64.encode(cert.public_key),
                     "custody": "hosted", "not_before": fk.ts(T0), "not_after": fk.ts(T0 + 90 * DAY),
                     "cert": json.loads(cert.envelope)}
    assert "status" not in entry and "status" not in doc                    # status is mutable and unsigned
    assert keys_doc(plat, leaf_key)[0] == data and data.isascii()
    assert len(data) < 64 * 1024


def test_keys_json_entries_are_sorted_and_verify_against_the_chain(plat, roots):
    ks = [Ed25519PrivateKey.generate() for _ in range(3)]
    cs = [certs.parse_cert(attest_cert(plat, k, nb=T0 + i * DAY, na=T0 + 90 * DAY)) for i, k in enumerate(ks)]
    anchor = certs.parse_cert(attest_cert(plat, Ed25519PrivateKey.generate(), usage="anchor"))
    data = certs.build_keys_json(ESTATE_A, issuers=[plat.issuer_cert], revoker=plat.revoker_cert,
                                 certs_=[cs[2], anchor, cs[0], cs[1]])
    order = [(e["usage"], e["not_before"], e["kid"]) for e in json.loads(data)["keys"]]
    assert order == sorted(order)
    verified = certs.verify_keys_json(data, roots=roots, at=T0 + 10 * DAY)
    assert set(verified.keys) == {c.kid for c in cs} | {anchor.kid}
    assert verified.estate == ESTATE_A and verified.revoker.kid == plat.revoker_kid
    assert verified.issuers[0].kid == plat.issuer_kid


def test_a_key_that_is_not_valid_at_the_given_time_is_listed_but_flagged_by_verify_chain_only(plat, roots, leaf_key):
    """keys.json keeps retired keys so history verifies: verify_keys_json checks structure and signatures, and each
    entry's window is judged by verify_chain at the statement's own issued_at."""
    data, cert = keys_doc(plat, leaf_key)
    verified = certs.verify_keys_json(data, roots=roots, at=T0 + 200 * DAY)
    assert cert.kid in verified.keys
    reject("key.outside_validity", cert, issuers=verified.issuers_envelopes, roots=roots, at=T0 + 200 * DAY)


@pytest.mark.parametrize("mutate,code", [
    (lambda d, c: d.update(spec="paddock-keys/v2"), "keys.invalid"),
    (lambda d, c: d.update(extra=1), "keys.invalid"),
    (lambda d, c: d.pop("revoker"), "keys.invalid"),
    (lambda d, c: d.update(estate="x"), "keys.invalid"),
    (lambda d, c: d.update(keys=d["keys"] * 2), "keys.invalid"),                      # duplicate kid
    (lambda d, c: d["keys"][0].update(usage="anchor"), "key.cert_subject_mismatch"),
    (lambda d, c: d["keys"][0].update(custody="byok-kms"), "key.cert_subject_mismatch"),
    (lambda d, c: d["keys"][0].update(alg="ecdsa-p256-sha256"), "key.cert_subject_mismatch"),
    (lambda d, c: d["keys"][0].update(not_after=fk.ts(T0 + 99 * DAY)), "key.cert_subject_mismatch"),
    (lambda d, c: d["keys"][0].update(not_before=fk.ts(T0 - DAY)), "key.cert_subject_mismatch"),
    (lambda d, c: d["keys"][0].update(public_key=b64.encode(b"\x07" * 32)), "key.cert_subject_mismatch"),
    (lambda d, c: d["keys"][0].update(kid="2" * 32), "key.cert_subject_mismatch"),
    (lambda d, c: d["keys"][0].update(status="active"), "keys.invalid"),              # an unsigned status is not allowed
    (lambda d, c: d["keys"][0].pop("cert"), "key.cert_missing"),
    (lambda d, c: d.update(estate="e_" + "c" * 26), "key.cert_subject_mismatch"),     # the certs name estate A
])
def test_keys_json_entries_must_equal_their_certificates(plat, roots, leaf_key, mutate, code):
    data, cert = keys_doc(plat, leaf_key)
    d = json.loads(data)
    mutate(d, cert)
    with pytest.raises(certs.CertError) as ei:
        certs.verify_keys_json(json.dumps(d).encode(), roots=roots, at=T0)
    assert ei.value.code == code, ei.value


def test_keys_json_rejects_a_bad_certificate_inside(plat, roots, leaf_key):
    data, cert = keys_doc(plat, leaf_key)
    d = json.loads(data)
    d["keys"][0]["cert"]["payload"] = d["keys"][0]["cert"]["payload"][:-4] + "AAAA"
    with pytest.raises(certs.CertError) as ei:
        certs.verify_keys_json(json.dumps(d).encode(), roots=roots, at=T0)
    assert ei.value.code in ("key.cert_invalid", "schema.base64_invalid", "input.not_json")


def test_keys_json_has_at_most_16_keys_and_1_to_4_issuers_like_the_open_verifier_reads_it(plat):
    ks = [certs.parse_cert(attest_cert(plat, Ed25519PrivateKey.generate())) for _ in range(17)]
    certs.build_keys_json(ESTATE_A, issuers=[plat.issuer_cert], revoker=plat.revoker_cert, certs_=ks[:16])
    with pytest.raises(certs.CertError) as ei:
        certs.build_keys_json(ESTATE_A, issuers=[plat.issuer_cert], revoker=plat.revoker_cert, certs_=ks)
    assert ei.value.code == "keys.invalid"
    for issuers in ([], [plat.issuer_cert] * 5):
        with pytest.raises(certs.CertError) as ei:
            certs.build_keys_json(ESTATE_A, issuers=issuers, revoker=plat.revoker_cert, certs_=ks[:1])
        assert ei.value.code == "keys.invalid"


# --------------------------------------------------------------------------- #
# platform key loading
# --------------------------------------------------------------------------- #

@pytest.fixture
def installed(plat):
    return plat


def test_load_returns_verified_platform_keys(installed):
    pk = platform_keys.load(now=T0)
    assert pk.issuer.kid == installed.issuer_kid and pk.issuer.usage == "issue-cert"
    assert pk.revoker.kid == installed.revoker_kid and pk.revoker.usage == "revoke"
    assert pk.issuer.public_key == installed.issuer_pub and pk.issuer.cert.envelope == installed.issuer_cert
    assert [r.kid for r in pk.roots] == [installed.root_kid]
    sig = pk.issuer.sign(b"message")
    assert len(sig) == 64 and ed25519.verify(installed.issuer_pub, b"message", sig)
    assert ed25519.verify(installed.revoker_pub, b"m", pk.revoker.sign(b"m"))


def test_platform_keys_never_show_key_material_or_the_passphrase(installed):
    pk = platform_keys.load(now=T0)
    text = repr(pk) + repr(pk.issuer) + str(pk.revoker) + repr(vars(pk.issuer).keys())
    assert fk.PASSPHRASE not in text and "PRIVATE" not in text and "BEGIN" not in text
    names = [n for n in dir(pk.issuer) if not n.startswith("__")]
    assert not [n for n in names if re.search(r"export|private|dump|secret|pem|seed", n, re.I)]
    assert installed.issuer_kid in repr(pk.issuer)                    # identity is fine


@pytest.mark.parametrize("attr,gap", [
    ("issuer_key_file", "issuer_key"), ("issuer_cert_file", "issuer_cert"),
    ("revoker_key_file", "revoker_key"), ("revoker_cert_file", "revoker_cert"),
])
def test_missing_material_is_not_configured_and_names_the_gap(installed, monkeypatch, attr, gap):
    from app.attest import config as c

    monkeypatch.setattr(c.settings, attr, None)
    with pytest.raises(platform_keys.PlatformNotConfigured) as ei:
        platform_keys.load(now=T0)
    assert gap in ei.value.missing


def test_a_missing_passphrase_is_not_configured(installed, monkeypatch):
    from app.attest import config as c

    monkeypatch.setattr(c.settings, "platform_key_passphrase", None)
    with pytest.raises(platform_keys.PlatformNotConfigured) as ei:
        platform_keys.load(now=T0)
    assert "passphrase" in ei.value.missing


def test_a_wrong_passphrase_is_an_error_that_does_not_echo_it(installed, monkeypatch):
    from pydantic import SecretStr

    from app.attest import config as c

    monkeypatch.setattr(c.settings, "platform_key_passphrase", SecretStr("a different passphrase 99"))
    with pytest.raises(platform_keys.PlatformKeysError) as ei:
        platform_keys.load(now=T0)
    assert "different passphrase" not in str(ei.value) and fk.PASSPHRASE not in str(ei.value)


def test_an_unencrypted_key_file_is_refused(installed, tmp_path, monkeypatch):
    from app.attest import config as c

    plain = tmp_path / "plain.pem"
    plain.write_bytes(installed.issuer_priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                          serialization.NoEncryption()))
    monkeypatch.setattr(c.settings, "issuer_key_file", str(plain))
    platform_keys.reset_cache()
    with pytest.raises(platform_keys.PlatformKeysError):
        platform_keys.load(now=T0)


@pytest.mark.parametrize("make", [
    lambda: rsa.generate_private_key(65537, 2048), lambda: ec.generate_private_key(ec.SECP256R1()),
])
def test_only_ed25519_platform_keys_are_accepted(installed, tmp_path, monkeypatch, make):
    from app.attest import config as c

    p = tmp_path / "other.pem"
    p.write_bytes(make().private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.BestAvailableEncryption(fk.PASSPHRASE.encode())))
    monkeypatch.setattr(c.settings, "issuer_key_file", str(p))
    platform_keys.reset_cache()
    with pytest.raises(platform_keys.PlatformKeysError):
        platform_keys.load(now=T0)


def test_a_key_that_does_not_match_its_certificate_is_refused(installed, monkeypatch):
    from app.attest import config as c

    monkeypatch.setattr(c.settings, "issuer_key_file", installed.files["revoker_key_file"])
    platform_keys.reset_cache()
    with pytest.raises(platform_keys.PlatformKeysError):
        platform_keys.load(now=T0)


def test_certificates_in_the_wrong_slot_are_refused(installed, monkeypatch):
    from app.attest import config as c

    monkeypatch.setattr(c.settings, "revoker_key_file", installed.files["issuer_key_file"])
    monkeypatch.setattr(c.settings, "revoker_cert_file", installed.files["issuer_cert_file"])
    platform_keys.reset_cache()
    with pytest.raises(platform_keys.PlatformKeysError) as ei:
        platform_keys.load(now=T0)
    assert ei.value.code == "key.cert_subject_mismatch"


def test_expired_and_not_yet_valid_issuer_certs_are_refused(tmp_path, monkeypatch):
    p = fk.make_platform(tmp_path / "p")
    fk.install(monkeypatch, p)
    platform_keys.load(now=T0)
    for when in (T0 + 400 * DAY, T0 - 200 * DAY):
        with pytest.raises(platform_keys.PlatformKeysError) as ei:
            platform_keys.load(now=when)                  # the cached key is re-judged against the clock every call
        assert ei.value.code == "issuer.outside_validity"


def test_without_trust_roots_the_platform_is_not_usable(plat, monkeypatch):
    fk.install(monkeypatch, plat, with_roots=False)
    with pytest.raises(platform_keys.PlatformKeysError) as ei:
        platform_keys.load(now=T0)
    assert ei.value.code == "config.no_trust_roots"


def test_a_root_that_did_not_sign_the_certs_is_refused(plat, tmp_path, monkeypatch):
    other = fk.make_platform(tmp_path / "other")
    fk.install(monkeypatch, plat)
    from app.attest import config as c

    monkeypatch.setattr(c.settings, "trust_roots_file", other.files["trust_roots_file"])
    platform_keys.reset_cache()
    with pytest.raises(platform_keys.PlatformKeysError) as ei:
        platform_keys.load(now=T0)
    assert ei.value.code == "key.root_unknown"


def test_an_issuer_certified_revoker_loads(tmp_path, monkeypatch):
    p = fk.make_platform(tmp_path / "p", revoker_certified_by="issuer")
    fk.install(monkeypatch, p)
    pk = platform_keys.load(now=T0)
    assert pk.revoker.cert.issuer_kid == p.issuer_kid and pk.revoker.kid == p.revoker_kid


def test_a_pinned_issuer_is_accepted_without_a_root_and_the_revoker_then_needs_its_own_root(plat, monkeypatch, tmp_path):
    """Self-hosters pin the issuer (chain length 1); the revoker cert must still chain to a pinned ``root``."""
    pinned = tmp_path / "pinned.json"
    pinned.write_text(json.dumps([{"kid": plat.issuer_kid, "public_key": b64.encode(plat.issuer_pub),
                                   "usage": "issue-cert", "not_before": fk.ts(T0 - 100 * DAY),
                                   "not_after": fk.ts(T0 + 300 * DAY)}]))
    fk.install(monkeypatch, plat)
    from app.attest import config as c

    monkeypatch.setattr(c.settings, "trust_roots_file", str(pinned))
    platform_keys.reset_cache()
    with pytest.raises(platform_keys.PlatformKeysError):
        platform_keys.load(now=T0)


def test_the_loader_caches_the_decrypted_key_but_notices_a_replaced_file(installed, tmp_path, monkeypatch):
    first = platform_keys.load(now=T0)
    assert platform_keys.load(now=T0).issuer.kid == first.issuer.kid
    newer = fk.make_platform(tmp_path / "newer")
    fk.install(monkeypatch, newer)
    platform_keys.reset_cache()
    assert platform_keys.load(now=T0).issuer.kid == newer.issuer_kid != first.issuer.kid
    # same path, new content: replaced in place
    for attr in ("issuer_key_file", "issuer_cert_file", "revoker_key_file", "revoker_cert_file", "trust_roots_file"):
        Path(installed.files[attr]).write_bytes(Path(newer.files[attr]).read_bytes())
    fk.install(monkeypatch, installed)
    assert platform_keys.load(now=T0).issuer.kid == newer.issuer_kid


def test_the_kill_switch_key_name_is_published_for_the_loop_and_the_admin_script():
    assert platform_keys.GLOBAL_KILL_REDIS_KEY == "paddock:attest:issuing_killed"


# --------------------------------------------------------------------------- #
# the root ceremony script
# --------------------------------------------------------------------------- #

def load_script():
    spec = importlib.util.spec_from_file_location("attest_root_ceremony", CEREMONY)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["attest_root_ceremony"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def cer(monkeypatch):
    monkeypatch.setenv("PADDOCK_ATTEST_ROOT_PASSPHRASE", fk.PASSPHRASE)
    monkeypatch.setenv("PADDOCK_ATTEST_PLATFORM_KEY_PASSPHRASE", fk.PASSPHRASE)
    return load_script()


@pytest.fixture
def ceremony(cer, tmp_path):
    out = tmp_path / "usb" / "root"
    assert cer.main(["generate-root", "--out-dir", str(out), "--not-before", "2026-01-01T00:00:00Z"]) == 0
    return out


def test_generate_root_writes_an_encrypted_key_the_public_key_a_record_and_a_roots_entry(cer, ceremony):
    pem = ceremony / "paddock-attest-root.pem"
    assert stat.S_IMODE(pem.stat().st_mode) == 0o600 and b"ENCRYPTED PRIVATE KEY" in pem.read_bytes()
    pub = (ceremony / "paddock-attest-root.pub").read_text().strip()
    raw = b64.strict_decode(pub)
    roots = json.loads((ceremony / "trust_roots.json").read_text())
    assert roots == [{"kid": fk.kid_of(raw), "public_key": pub, "usage": "root", "not_before": "2026-01-01T00:00:00Z",
                      "not_after": "2036-01-01T00:00:00Z"}]
    assert certs.parse_roots(roots)[0].kid == fk.kid_of(raw)
    record = (ceremony / "ceremony-record.txt").read_text()
    assert fk.kid_of(raw) in record and "PRIVATE" not in record and "BEGIN" not in record and fk.PASSPHRASE not in record
    assert "never the license key" in record.lower()


def test_generate_root_refuses_the_repository_overwriting_and_weak_passphrases(cer, ceremony, tmp_path, monkeypatch):
    with pytest.raises(SystemExit) as ei:
        cer.main(["generate-root", "--out-dir", str(ROOT / "tmp-ceremony-should-not-exist")])
    assert "repository" in str(ei.value) and not (ROOT / "tmp-ceremony-should-not-exist").exists()
    with pytest.raises(SystemExit) as ei:
        cer.main(["generate-root", "--out-dir", str(ceremony)])
    assert "exists" in str(ei.value)
    monkeypatch.setenv("PADDOCK_ATTEST_ROOT_PASSPHRASE", "short")
    with pytest.raises(SystemExit) as ei:
        cer.main(["generate-root", "--out-dir", str(tmp_path / "x")])
    assert "16" in str(ei.value) and not (tmp_path / "x").exists()
    monkeypatch.delenv("PADDOCK_ATTEST_ROOT_PASSPHRASE")
    with pytest.raises(SystemExit):
        cer.main(["generate-root", "--out-dir", str(tmp_path / "y")])          # no tty, no env: refused


def _certify(cer, ceremony, tmp_path, which, serial="3", *extra):
    out = tmp_path / which
    rc = cer.main([f"certify-{which}", "--root-key-file", str(ceremony / "paddock-attest-root.pem"), "--out-dir", str(out),
                   "--serial", serial, "--not-before", "2026-06-01T00:00:00Z", "--not-after", "2027-06-01T00:00:00Z", *extra])
    assert rc == 0
    return out


def test_certify_issuer_and_revoker_produce_certs_that_production_accepts(cer, ceremony, tmp_path, monkeypatch):
    iss = _certify(cer, ceremony, tmp_path, "issuer", "11")
    rev = _certify(cer, ceremony, tmp_path, "revoker", "12")
    root_pub = b64.strict_decode((ceremony / "paddock-attest-root.pub").read_text().strip())
    ic = fk.independent_cert_check((iss / "issuer.cert.json").read_bytes(), root_pub)
    rc = fk.independent_cert_check((rev / "revoker.cert.json").read_bytes(), root_pub)
    assert (ic["usage"], ic["serial"], ic["custody"], "estate" in ic) == ("issue-cert", 11, "hosted", False)
    assert (rc["usage"], rc["serial"], "estate" in rc) == ("revoke", 12, False)
    assert ic["not_before"] == "2026-06-01T00:00:00Z" and ic["not_after"] == "2027-06-01T00:00:00Z"
    for pem in (iss / "issuer.pem", rev / "revoker.pem"):
        assert stat.S_IMODE(pem.stat().st_mode) == 0o600 and b"ENCRYPTED PRIVATE KEY" in pem.read_bytes()
    # and the orchestrator can load the whole set the ceremony produced
    from app.attest import config as c

    for attr, path in (("issuer_key_file", iss / "issuer.pem"), ("issuer_cert_file", iss / "issuer.cert.json"),
                       ("revoker_key_file", rev / "revoker.pem"), ("revoker_cert_file", rev / "revoker.cert.json"),
                       ("trust_roots_file", ceremony / "trust_roots.json")):
        monkeypatch.setattr(c.settings, attr, str(path))
    from pydantic import SecretStr

    monkeypatch.setattr(c.settings, "platform_key_passphrase", SecretStr(fk.PASSPHRASE))
    platform_keys.reset_cache()
    pk = platform_keys.load(now=T0)
    assert pk.issuer.cert.serial == 11 and pk.revoker.cert.serial == 12 and pk.issuer.kid != pk.revoker.kid


def test_certify_revoker_through_the_issuer_when_asked(cer, ceremony, tmp_path, monkeypatch):
    iss = _certify(cer, ceremony, tmp_path, "issuer", "11")
    out = tmp_path / "revoker-via-issuer"
    assert cer.main(["certify-revoker", "--issuer-key-file", str(iss / "issuer.pem"), "--issuer-cert-file",
                     str(iss / "issuer.cert.json"), "--root-key-file", str(ceremony / "paddock-attest-root.pem"),
                     "--out-dir", str(out), "--serial", "12", "--not-before", "2026-06-01T00:00:00Z",
                     "--not-after", "2027-06-01T00:00:00Z"]) == 0
    issuer_pub = b64.strict_decode((iss / "issuer.pub").read_text().strip())
    body = fk.independent_cert_check((out / "revoker.cert.json").read_bytes(), issuer_pub)
    assert body["usage"] == "revoke" and body["issuer_kid"] == fk.kid_of(issuer_pub)
    from pydantic import SecretStr

    from app.attest import config as c

    for attr, path in (("issuer_key_file", iss / "issuer.pem"), ("issuer_cert_file", iss / "issuer.cert.json"),
                       ("revoker_key_file", out / "revoker.pem"), ("revoker_cert_file", out / "revoker.cert.json"),
                       ("trust_roots_file", ceremony / "trust_roots.json")):
        monkeypatch.setattr(c.settings, attr, str(path))
    monkeypatch.setattr(c.settings, "platform_key_passphrase", SecretStr(fk.PASSPHRASE))
    platform_keys.reset_cache()
    assert platform_keys.load(now=T0).revoker.cert.serial == 12
    with pytest.raises(SystemExit) as ei:                                    # the window may not exceed the issuer's
        cer.main(["certify-revoker", "--issuer-key-file", str(iss / "issuer.pem"), "--issuer-cert-file",
                  str(iss / "issuer.cert.json"), "--root-key-file", str(ceremony / "paddock-attest-root.pem"),
                  "--out-dir", str(tmp_path / "late"), "--serial", "13", "--not-before", "2026-06-01T00:00:00Z",
                  "--not-after", "2030-01-01T00:00:00Z"])
    assert "issuer" in str(ei.value).lower()
    with pytest.raises(SystemExit):                                          # only a revoker may go through the issuer
        cer.main(["certify-issuer", "--issuer-key-file", str(iss / "issuer.pem"), "--root-key-file",
                  str(ceremony / "paddock-attest-root.pem"), "--out-dir", str(tmp_path / "x"), "--serial", "1"])


def test_certify_defaults_to_a_one_year_window_and_certifies_a_given_public_key(cer, ceremony, tmp_path):
    other = Ed25519PrivateKey.generate()
    pubfile = tmp_path / "given.pub"
    pubfile.write_text(b64.encode(fk.raw_pub(other)) + "\n")
    out = tmp_path / "given"
    assert cer.main(["certify-issuer", "--root-key-file", str(ceremony / "paddock-attest-root.pem"), "--out-dir", str(out),
                     "--public-key-file", str(pubfile), "--serial", "1", "--not-before", "2026-06-01T00:00:00Z"]) == 0
    body = fk.cert_doc((out / "issuer.cert.json").read_bytes())
    assert body["kid"] == fk.kid_of(fk.raw_pub(other)) and body["not_after"] == "2027-06-01T00:00:00Z"
    assert not (out / "issuer.pem").exists()                      # no key was generated for a given public key


def test_certify_refuses_overwrites_the_repository_and_a_window_beyond_the_root(cer, ceremony, tmp_path):
    out = _certify(cer, ceremony, tmp_path, "issuer")
    with pytest.raises(SystemExit):
        _certify(cer, ceremony, tmp_path, "issuer")                # never overwrite
    assert out.exists()
    with pytest.raises(SystemExit) as ei:
        cer.main(["certify-issuer", "--root-key-file", str(ceremony / "paddock-attest-root.pem"),
                  "--out-dir", str(ROOT / "tmp-ceremony-should-not-exist"), "--serial", "1"])
    assert "repository" in str(ei.value)
    with pytest.raises(SystemExit) as ei:
        cer.main(["certify-issuer", "--root-key-file", str(ceremony / "paddock-attest-root.pem"),
                  "--out-dir", str(tmp_path / "late"), "--serial", "1", "--not-before", "2040-01-01T00:00:00Z"])
    assert "root" in str(ei.value).lower()


def test_certify_with_the_wrong_root_passphrase_fails_without_writing(cer, ceremony, tmp_path, monkeypatch):
    monkeypatch.setenv("PADDOCK_ATTEST_ROOT_PASSPHRASE", "an entirely different passphrase")
    with pytest.raises(SystemExit):
        cer.main(["certify-issuer", "--root-key-file", str(ceremony / "paddock-attest-root.pem"),
                  "--out-dir", str(tmp_path / "bad"), "--serial", "1"])
    assert not (tmp_path / "bad").exists()


def test_fingerprint_prints_the_kid_and_the_sha256_of_the_public_key(cer, ceremony, capsys):
    assert cer.main(["fingerprint", "--public-key-file", str(ceremony / "paddock-attest-root.pub")]) == 0
    out = capsys.readouterr().out
    raw = b64.strict_decode((ceremony / "paddock-attest-root.pub").read_text().strip())
    assert fk.kid_of(raw) in out and ed25519.fingerprint(raw) in out


def _wheel(path, roots):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("paddock_verify/data/trust_roots.json", json.dumps(roots))
        z.writestr("paddock_verify/__init__.py", "")
    return path


def test_check_reads_the_root_back_from_a_built_wheel(cer, ceremony, tmp_path, capsys):
    pubfile = ceremony / "paddock-attest-root.pub"
    roots = json.loads((ceremony / "trust_roots.json").read_text())
    good = _wheel(tmp_path / "good.whl", roots)
    assert cer.main(["check", "--wheel", str(good), "--public-key-file", str(pubfile)]) == 0
    assert "ok" in capsys.readouterr().out.lower()
    empty = _wheel(tmp_path / "empty.whl", [])
    assert cer.main(["check", "--wheel", str(empty), "--public-key-file", str(pubfile)]) == 1
    stranger = Ed25519PrivateKey.generate()
    other_roots = [{**roots[0], "public_key": b64.encode(fk.raw_pub(stranger)), "kid": fk.kid_of(fk.raw_pub(stranger))}]
    wrong = _wheel(tmp_path / "wrong.whl", other_roots)
    assert cer.main(["check", "--wheel", str(wrong), "--public-key-file", str(pubfile)]) == 1
    both = _wheel(tmp_path / "both.whl", roots + other_roots)
    assert cer.main(["check", "--wheel", str(both), "--public-key-file", str(pubfile)]) == 0
    assert cer.main(["check", "--wheel", str(both), "--public-key-file", str(pubfile), "--exact"]) == 1
    assert cer.main(["check", "--wheel", str(tmp_path / "missing.whl"), "--public-key-file", str(pubfile)]) != 0


def test_check_refuses_a_private_key_file(cer, ceremony):
    with pytest.raises(SystemExit):
        cer.main(["fingerprint", "--public-key-file", str(ceremony / "paddock-attest-root.pem")])


def test_the_script_never_imports_the_license_key_machinery():
    text = CEREMONY.read_text()
    assert not re.search(r"^\s*(import|from)\s+\S*(licensing|vendor_key_ceremony)", text, re.M)
    assert "VENDOR_PUBLIC_KEYS" not in text and "PADDOCK_VENDOR_KEY_PASSPHRASE" not in text
    assert os.access(CEREMONY, os.R_OK)
