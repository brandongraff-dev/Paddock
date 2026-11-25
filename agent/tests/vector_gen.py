"""Deterministic envelope-v1 / enrollment / rotation test vectors for the SERVER side to reuse.

    cd agent && python -m tests.vector_gen --write      # regenerates tests/vectors/envelope_v1.json

The seeds are fixed, the signatures are deterministic Ed25519, so the file is byte-stable; a test
(`test_envelope.py::test_vectors_file_is_current`) fails if the file and the code disagree. Every value a
verifier needs is listed: the exact signing input, the payload bytes, the signature and the full envelope.
"""
import copy
import hashlib
import json
import os
import sys

from paddock_agent import envelope, signing

HERE = os.path.dirname(os.path.abspath(__file__))
PATH = os.path.join(HERE, "vectors", "envelope_v1.json")

SEED = hashlib.sha256(b"paddock-agent-envelope-v1 test vector seed 1").digest()
SEED2 = hashlib.sha256(b"paddock-agent-envelope-v1 test vector seed 2").digest()
AGENT_ID = "11111111-1111-4111-8111-111111111111"
TENANT_ID = "22222222-2222-4222-8222-222222222222"
NONCE = envelope.b64u(bytes(range(16)))
COLLECTORS = {"agent": "0.2.0", "firewall": "1", "listeners": "1", "patch": "1", "self": "1", "sshd": "1"}
TOKEN = "fet_0123456789ab_" + envelope.b64u(hashlib.sha256(b"vector enroll secret").digest())
HOSTNAME = "web-01.example.internal"


def _posture_payload():
    return envelope.canon({
        "schema": 2,
        "collected_at": "2026-11-24T19:00:00Z",
        "sections": {"self": {"s": "ok", "conf": "exact", "partial": False,
                              "v": {"agent_version": "0.2.0", "hostname_note": "café ☃"}}},
    })


def _case(name, kind, seq, issued_at, payload, payload_type, collectors, nonce, seed=SEED):
    env = envelope.build_envelope(
        seed, agent_id=AGENT_ID, tenant_id=TENANT_ID, kind=kind, seq=seq, issued_at=issued_at,
        payload=payload, payload_type=payload_type, collectors=collectors, nonce=nonce)
    header, _payload, sig = envelope.split_envelope(env)
    sin = envelope.signing_input(header)
    body, _enc = envelope.encode_body(env, gzip_threshold=10 ** 9)
    return {
        "name": name,
        "header": header,
        "signing_input_hex": sin.hex(),
        "signing_input_utf8": sin.decode("utf-8"),
        "payload_hex": payload.hex(),
        "payload_utf8": payload.decode("utf-8"),
        "signature_hex": sig.hex(),
        "signature_b64url": env["sig"],
        "envelope": env,
        "body_json": body.decode("utf-8"),
    }


def _mutate(base, name, changes, fails_at, drop=()):
    env = copy.deepcopy(base["envelope"])
    env.update(changes)
    for k in drop:
        env.pop(k, None)
    return {"name": name, "envelope": env, "fails_at": fails_at}


def build():
    pub = signing.public_key(SEED)
    pub2 = signing.public_key(SEED2)
    kid, kid2 = signing.key_id(pub), signing.key_id(pub2)
    posture = _case("posture", envelope.KIND_POSTURE, 7, "2026-11-24T19:00:00Z", _posture_payload(),
                    envelope.PAYLOAD_TYPE_POSTURE, COLLECTORS, NONCE)
    heartbeat = _case("heartbeat", envelope.KIND_HEARTBEAT, 8, "2026-11-24T19:00:30Z",
                      envelope.canon({"agent_version": "0.2.0", "status": "ok"}),
                      envelope.PAYLOAD_TYPE_HEARTBEAT, {"agent": "0.2.0"},
                      envelope.b64u(bytes(range(16, 32))))
    rotate_payload = envelope.rotate_payload(SEED2, AGENT_ID, kid)
    rotate = _case("rotate", envelope.KIND_ROTATE, 9, "2026-11-24T19:01:00Z", rotate_payload,
                   envelope.PAYLOAD_TYPE_ROTATE, {"agent": "0.2.0"}, envelope.b64u(bytes(range(32, 48))))
    prefix = envelope.token_prefix(TOKEN)
    tampered = bytearray(_posture_payload())
    tampered[-5] ^= 0x01
    tampered_b64 = envelope.b64u(bytes(tampered))
    flipped_sig = bytearray(envelope.b64u_decode(posture["envelope"]["sig"]))
    flipped_sig[10] ^= 0x01
    return {
        "description": "Deterministic vectors for paddock agent envelope v1 (docs/ASSURANCE_P2.md "
                       "section 2). Regenerate: cd agent && python -m tests.vector_gen --write",
        "signing_prefix_utf8": envelope.SIGNING_PREFIX.decode("ascii"),
        "canon": "json.dumps(x, sort_keys=True, separators=(',', ':'), ensure_ascii=False, "
                 "allow_nan=False).encode('utf-8')",
        "b64": "URL-safe base64, no padding, for nonce / payload_b64 / sig / public keys / proofs",
        "agent_id": AGENT_ID,
        "tenant_id": TENANT_ID,
        "key": {"seed_hex": SEED.hex(), "public_key_hex": pub.hex(),
                "public_key_b64url": envelope.b64u(pub), "key_id": kid},
        "key2": {"seed_hex": SEED2.hex(), "public_key_hex": pub2.hex(),
                 "public_key_b64url": envelope.b64u(pub2), "key_id": kid2},
        "cases": [posture, heartbeat, rotate],
        "rotate": {
            "old_key_id": kid, "new_key_id": kid2,
            "proof_message_utf8": envelope.rotate_proof_message(AGENT_ID, kid, kid2).decode("utf-8"),
            "payload_json": rotate_payload.decode("utf-8"),
        },
        "enroll": {
            "token": TOKEN, "token_prefix": prefix, "hostname": HOSTNAME,
            "proof_message_utf8": envelope.enroll_proof_message(prefix, HOSTNAME).decode("utf-8"),
            "public_key_b64url": envelope.b64u(pub),
            "proof_b64url": envelope.enroll_proof(SEED, prefix, HOSTNAME),
            "key_id": kid,
            "request_body": {"token": TOKEN, "hostname": HOSTNAME, "public_key_b64": envelope.b64u(pub),
                             "proof_b64": envelope.enroll_proof(SEED, prefix, HOSTNAME),
                             "agent_version": "0.2.0",
                             "capabilities": ["block", "inventory", "posture", "quarantine"]},
        },
        "negative": [
            _mutate(posture, "payload_tampered_same_length",
                    {"payload_b64": tampered_b64}, "payload_sha256"),
            _mutate(posture, "payload_len_wrong", {"payload_len": posture["header"]["payload_len"] + 1},
                    "payload_len"),
            _mutate(posture, "seq_changed", {"seq": 8}, "signature"),
            _mutate(posture, "kind_changed", {"kind": "heartbeat"}, "signature"),
            _mutate(posture, "tenant_changed", {"tenant_id": "33333333-3333-4333-8333-333333333333"},
                    "signature"),
            _mutate(posture, "kid_changed", {"kid": kid2}, "signature"),
            _mutate(posture, "signature_bit_flipped", {"sig": envelope.b64u(bytes(flipped_sig))},
                    "signature"),
            _mutate(posture, "issued_at_changed", {"issued_at": "2026-11-24T19:00:01Z"}, "signature"),
        ],
    }


def dumps(doc):
    return json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv):
    text = dumps(build())
    if "--write" in argv:
        os.makedirs(os.path.dirname(PATH), exist_ok=True)
        with open(PATH, "w", encoding="utf-8") as fh:
            fh.write(text)
        print("wrote", PATH)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
