"""Envelope v1: canonicalisation, signing input, limits, proofs, and the shared server vectors."""
from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os

import pytest

from paddock_agent import envelope, signing
from tests import vector_gen

VECTORS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors", "envelope_v1.json")


def _load():
    with open(VECTORS, encoding="utf-8") as fh:
        return json.load(fh)


def _b64u_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def server_verify(env, pub):
    """An INDEPENDENT re-implementation of the contract's checks 5 and 6 (does not use envelope.py)."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    payload = _b64u_decode(env["payload_b64"])
    if len(payload) != env["payload_len"]:
        return "payload_len"
    if hashlib.sha256(payload).hexdigest() != env["payload_sha256"]:
        return "payload_sha256"
    header = dict((k, v) for k, v in env.items() if k not in ("payload_b64", "sig"))
    msg = (b"paddock-agent-envelope/v1\n"
           + json.dumps(header, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                        allow_nan=False).encode("utf-8"))
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(_b64u_decode(env["sig"]), msg)
    except InvalidSignature:
        return "signature"
    return None


# --------------------------------------------------------------------------- #
# canonicalisation
# --------------------------------------------------------------------------- #

def test_canon_is_sorted_compact_utf8():
    assert envelope.canon({"b": 1, "a": [True, "é", {"z": 0, "y": "x"}]}) == \
        '{"a":[true,"é",{"y":"x","z":0}],"b":1}'.encode("utf-8")


@pytest.mark.parametrize("bad", [1.5, float("nan"), None, {"a": 1.0}, [1, None], {1: 2}, (1, 2), b"x",
                                 {"a": {"b": {"c": 1.25}}}])
def test_canon_refuses_floats_null_and_foreign_types(bad):
    with pytest.raises(envelope.EnvelopeError):
        envelope.canon(bad)


def test_canon_refuses_deep_nesting():
    x = 1
    for _ in range(envelope.MAX_JSON_DEPTH + 2):
        x = [x]
    with pytest.raises(envelope.EnvelopeError):
        envelope.canon(x)


# --------------------------------------------------------------------------- #
# build / sign / verify
# --------------------------------------------------------------------------- #

SEED = hashlib.sha256(b"seed").digest()
AG, TN = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"


def _env(**kw):
    args = dict(agent_id=AG, tenant_id=TN, kind="posture", seq=1, issued_at=1_790_000_000,
                payload=b'{"a":1}', payload_type=envelope.PAYLOAD_TYPE_POSTURE, collectors={"agent": "0.2.0"})
    args.update(kw)
    return envelope.build_envelope(SEED, **args)


def test_header_has_exactly_the_contract_fields_and_kid_rule():
    env = _env()
    assert set(env) == {"v", "alg", "kid", "agent_id", "tenant_id", "kind", "seq", "issued_at", "nonce",
                        "payload_type", "payload_sha256", "payload_len", "collectors", "payload_b64", "sig"}
    pub = signing.public_key(SEED)
    assert env["kid"] == hashlib.sha256(pub).hexdigest()[:32]
    assert env["v"] == 1 and env["alg"] == "ed25519"
    assert env["issued_at"] == "2026-09-21T14:13:20Z"
    assert len(_b64u_decode(env["nonce"])) == 16 and len(_b64u_decode(env["sig"])) == 64
    assert "=" not in env["nonce"] + env["sig"] + env["payload_b64"]
    assert env["payload_sha256"] == hashlib.sha256(b'{"a":1}').hexdigest() and env["payload_len"] == 7


def test_signing_input_is_prefix_plus_canon_of_header_without_payload_and_sig():
    env = _env()
    header = dict((k, v) for k, v in env.items() if k not in ("payload_b64", "sig"))
    expected = b"paddock-agent-envelope/v1\n" + json.dumps(
        header, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert envelope.signing_input(header) == expected
    assert signing.verify(signing.public_key(SEED), expected, _b64u_decode(env["sig"]))
    with pytest.raises(envelope.EnvelopeError):
        envelope.signing_input(env)          # must not be handed payload_b64 / sig


def test_nonce_is_fresh_each_time():
    assert _env()["nonce"] != _env()["nonce"]


def test_payload_bytes_are_signed_verbatim_never_reserialised():
    odd = b' { "b" : 2,\n  "a":1.5 , "u": "\\u00e9" } '          # whitespace, a float, an escape
    env = _env(payload=odd)
    assert _b64u_decode(env["payload_b64"]) == odd and env["payload_len"] == len(odd)
    assert server_verify(env, signing.public_key(SEED)) is None


@pytest.mark.parametrize("kw", [
    dict(seq=0), dict(seq=-1), dict(seq=True), dict(seq=1.0), dict(kind="inventory"),
    dict(agent_id="not-a-uuid"), dict(tenant_id=""), dict(issued_at="2026-11-24 19:00:00"),
    dict(collectors={"agent": 2}), dict(collectors={"agent": 1.5}), dict(payload="text"),
    dict(payload=b"x" * (envelope.MAX_PAYLOAD_BYTES + 1)),
])
def test_invalid_inputs_are_refused_before_signing(kw):
    with pytest.raises(envelope.EnvelopeError):
        _env(**kw)


def test_header_over_2kib_is_refused():
    with pytest.raises(envelope.EnvelopeError):
        _env(collectors=dict(("k%03d" % i, "v" * 20) for i in range(100)))


def test_verify_envelope_accepts_good_and_rejects_every_mutation():
    pub = signing.public_key(SEED)
    env = _env()
    assert envelope.verify_envelope(env, pub)
    for field, value in [("seq", 2), ("kind", "heartbeat"), ("agent_id", AG.replace("1", "3")),
                         ("tenant_id", TN.replace("2", "3")), ("issued_at", "2026-09-21T14:13:21Z"),
                         ("payload_type", "x"), ("nonce", envelope.b64u(b"\0" * 16)),
                         ("collectors", {"agent": "9"}), ("payload_len", 8), ("payload_sha256", "0" * 64),
                         ("payload_b64", envelope.b64u(b'{"a":2}')), ("kid", "0" * 32)]:
        bad = dict(env)
        bad[field] = value
        assert not envelope.verify_envelope(bad, pub), field
    extra = dict(env, surprise=1)
    assert not envelope.verify_envelope(extra, pub)
    assert not envelope.verify_envelope(_env(), signing.public_key(hashlib.sha256(b"other").digest()))


# --------------------------------------------------------------------------- #
# body encoding
# --------------------------------------------------------------------------- #

def test_small_body_is_plain_json_and_large_body_is_gzipped_deterministically():
    small = _env()
    body, enc = envelope.encode_body(small)
    assert enc is None and json.loads(body) == small
    big = _env(payload=json.dumps({"x": "A" * 20000}).encode())
    body1, enc1 = envelope.encode_body(big)
    body2, enc2 = envelope.encode_body(big)
    assert enc1 == "gzip" and body1 == body2
    assert json.loads(gzip.decompress(body1)) == big


def test_body_over_limits_is_refused_locally():
    import os as _os
    incompressible = _os.urandom(900 * 1024)
    env = _env(payload=incompressible)           # b64 of random bytes does not gzip below 1 MiB
    envelope.encode_body(env)                    # ~1.2 MB inflated, ~0.9 MB gzipped: fits
    env = _env(payload=_os.urandom(envelope.MAX_PAYLOAD_BYTES))
    with pytest.raises(envelope.EnvelopeError):
        envelope.encode_body(env)                # ~2.7 MB of base64 random data: > 1 MiB gzipped


# --------------------------------------------------------------------------- #
# enrollment + rotation proofs
# --------------------------------------------------------------------------- #

def test_token_prefix_parsing():
    assert envelope.token_prefix("fet_0123456789ab_" + "x" * 32) == "0123456789ab"
    for bad in ("", "fet_0123_" + "x" * 32, "fat_0123456789ab_" + "x" * 32, "fet_0123456789AB_" + "x" * 32,
                "fet_0123456789ab_short", "fet_0123456789ab", None):
        with pytest.raises(envelope.EnvelopeError):
            envelope.token_prefix(bad)


def test_enroll_proof_is_the_key_signature_over_the_contract_message():
    pub = signing.public_key(SEED)
    proof = envelope.enroll_proof(SEED, "0123456789ab", "web-01.example")
    msg = b"paddock-enroll/v1\n0123456789ab\nweb-01.example"
    assert envelope.enroll_proof_message("0123456789ab", "web-01.example") == msg
    assert signing.verify(pub, msg, _b64u_decode(proof))
    assert not signing.verify(pub, msg.replace(b"web-01", b"web-02"), _b64u_decode(proof))


def test_rotate_payload_binds_both_keys_and_the_agent():
    new_seed = hashlib.sha256(b"new").digest()
    old_kid = signing.key_id(signing.public_key(SEED))
    payload = json.loads(envelope.rotate_payload(new_seed, AG, old_kid))
    new_pub = signing.public_key(new_seed)
    assert set(payload) == {"new_key_id", "new_public_key_b64", "proof_b64"}
    assert _b64u_decode(payload["new_public_key_b64"]) == new_pub
    assert payload["new_key_id"] == signing.key_id(new_pub)
    msg = envelope.rotate_proof_message(AG, old_kid, payload["new_key_id"])
    assert signing.verify(new_pub, msg, _b64u_decode(payload["proof_b64"]))
    other = envelope.rotate_proof_message(AG.replace("1", "4"), old_kid, payload["new_key_id"])
    assert not signing.verify(new_pub, other, _b64u_decode(payload["proof_b64"]))


# --------------------------------------------------------------------------- #
# the shared vectors
# --------------------------------------------------------------------------- #

def test_vectors_file_is_current():
    assert vector_gen.dumps(vector_gen.build()) == open(VECTORS, encoding="utf-8").read(), \
        "regenerate with: cd agent && python -m tests.vector_gen --write"


def test_vectors_are_identical_under_the_pure_backend(monkeypatch):
    monkeypatch.setenv(signing.ENV_BACKEND, "pure")
    assert vector_gen.dumps(vector_gen.build()) == open(VECTORS, encoding="utf-8").read()


def test_every_vector_verifies_with_an_independent_verifier_and_every_negative_fails():
    doc = _load()
    pub = bytes.fromhex(doc["key"]["public_key_hex"])
    assert doc["key"]["key_id"] == hashlib.sha256(pub).hexdigest()[:32]
    for case in doc["cases"]:
        env = case["envelope"]
        assert json.loads(case["body_json"]) == env
        assert bytes.fromhex(case["payload_hex"]) == _b64u_decode(env["payload_b64"])
        header = dict((k, v) for k, v in env.items() if k not in ("payload_b64", "sig"))
        assert case["header"] == header
        sin = bytes.fromhex(case["signing_input_hex"])
        assert sin.startswith(b"paddock-agent-envelope/v1\n")
        assert sin[len(b"paddock-agent-envelope/v1\n"):] == json.dumps(
            header, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        assert server_verify(env, pub) is None, case["name"]
        assert envelope.verify_envelope(env, pub)
    for neg in doc["negative"]:
        assert server_verify(neg["envelope"], pub) == neg["fails_at"], neg["name"]
        assert not envelope.verify_envelope(neg["envelope"], pub), neg["name"]


def test_enroll_and_rotate_vectors_verify():
    doc = _load()
    e = doc["enroll"]
    pub = _b64u_decode(e["public_key_b64url"])
    assert signing.verify(pub, e["proof_message_utf8"].encode(), _b64u_decode(e["proof_b64url"]))
    assert e["proof_message_utf8"] == "paddock-enroll/v1\n%s\n%s" % (e["token_prefix"], e["hostname"])
    assert e["request_body"]["public_key_b64"] == e["public_key_b64url"]
    r = doc["rotate"]
    pay = json.loads(r["payload_json"])
    new_pub = _b64u_decode(pay["new_public_key_b64"])
    assert signing.verify(new_pub, r["proof_message_utf8"].encode(), _b64u_decode(pay["proof_b64"]))
    # the rotate envelope itself is signed by the OLD key
    rot = [c for c in doc["cases"] if c["name"] == "rotate"][0]["envelope"]
    assert rot["kid"] == r["old_key_id"] and rot["kind"] == "rotate"
    assert server_verify(rot, bytes.fromhex(doc["key"]["public_key_hex"])) is None
