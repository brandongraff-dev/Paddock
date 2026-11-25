"""Cross-language wire vectors: what the agent signs is what the server verifies (docs/ASSURANCE_P2.md section 2).

``agent/tests/vectors/envelope_v1.json`` is produced by the AGENT package from fixed seeds (Python >= 3.8, stdlib
only, the vendored pure-Python RFC 8032 signer when ``cryptography`` is absent). Here the SERVER side
(``app.fleet_enroll`` / ``app.fleet_posture``, on ``cryptography``) consumes the very same bytes:

* the canonical signing input, bit for bit, from the header the vector carries;
* every signature, under three independent verifiers (the server's strict verifier, ``cryptography`` directly,
  and the OpenSSL command line when it can do Ed25519);
* the enrollment proof, and the whole ``POST /v1/fleet/enroll`` request body as a client would send it;
* the ingest pipeline (checks 1-10 of the contract) on the positive cases, with the clock pinned to the vector's
  ``issued_at``, and on every negative case, each of which must be refused at the right check.

The file is also checked against the agent's own generator: a vector that drifted from the code would hide a break.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import shutil
import subprocess
import uuid

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from httpx import ASGITransport, AsyncClient

from app import auth as auth_svc
from app import fleet_enroll as fe
from app import fleet_posture as fp
from app import tenancy
from app.config import settings

from . import p2_support as sup

VECTORS = sup.AGENT_DIR / "tests" / "vectors" / "envelope_v1.json"
V = json.loads(VECTORS.read_text(encoding="utf-8"))
UTC = dt.timezone.utc


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def at(iso: str) -> dt.datetime:
    return dt.datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


PUB = bytes.fromhex(V["key"]["public_key_hex"])
PUB2 = bytes.fromhex(V["key2"]["public_key_hex"])
CASES = {c["name"]: c for c in V["cases"]}


def test_the_vector_file_is_what_the_agent_generator_produces_today():
    """The vectors are only worth anything while they are the agent's real output."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("agent_vector_gen", sup.AGENT_DIR / "tests" / "vector_gen.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)             # the generator imports only paddock_agent
    assert json.loads(json.dumps(mod.build())) == V


# ---------------------------------------------------------------------------------------------- bytes
@pytest.mark.parametrize("name", sorted(CASES))
def test_signing_input_and_signature_agree_bit_for_bit(name):
    c = CASES[name]
    header = c["header"]
    signing_input = bytes.fromhex(c["signing_input_hex"])
    # 1. the server derives exactly the signing input the agent signed, from the header alone
    assert fp.signing_input(header) == signing_input
    assert signing_input == V["signing_prefix_utf8"].encode() + fp.canon(header)
    assert c["signing_input_utf8"].encode() == signing_input
    sig = b64u_dec(c["signature_b64url"])
    assert sig == bytes.fromhex(c["signature_hex"]) and len(sig) == 64
    # 2. three independent verifiers accept it, and none accepts a flipped bit
    assert fe.verify_ed25519(PUB, signing_input, sig) is True
    Ed25519PublicKey.from_public_bytes(PUB).verify(sig, signing_input)
    bad = bytes([sig[0] ^ 1]) + sig[1:]
    assert fe.verify_ed25519(PUB, signing_input, bad) is False
    with pytest.raises(InvalidSignature):
        Ed25519PublicKey.from_public_bytes(PUB).verify(bad, signing_input)
    assert fe.verify_ed25519(PUB, signing_input + b"x", sig) is False
    assert fe.verify_ed25519(PUB2, signing_input, sig) is False            # not under the other key
    # 3. the payload binding
    payload = bytes.fromhex(c["payload_hex"])
    assert hashlib.sha256(payload).hexdigest() == header["payload_sha256"] and len(payload) == header["payload_len"]
    env = c["envelope"]
    assert b64u_dec(env["payload_b64"]) == payload and b64u_dec(env["sig"]) == sig
    assert {k: v for k, v in env.items() if k not in ("payload_b64", "sig")} == header


@pytest.mark.skipif(shutil.which("openssl") is None, reason="needs the openssl CLI")
def test_openssl_command_line_verifies_the_agents_signatures(tmp_path):
    """A third, separately built verifier: the OpenSSL CLI (skipped where it cannot do raw Ed25519)."""
    der_prefix = bytes.fromhex("302a300506032b6570032100")                  # SubjectPublicKeyInfo for Ed25519
    pem = tmp_path / "pub.pem"
    pem.write_text("-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(der_prefix + PUB).decode() +
                   "\n-----END PUBLIC KEY-----\n")
    done = 0
    for name, c in sorted(CASES.items()):
        msg, sig = tmp_path / f"{name}.msg", tmp_path / f"{name}.sig"
        msg.write_bytes(bytes.fromhex(c["signing_input_hex"]))
        sig.write_bytes(b64u_dec(c["signature_b64url"]))
        res = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(pem), "-rawin",
                              "-in", str(msg), "-sigfile", str(sig)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        text = (res.stdout + res.stderr).decode()
        if "rawin" in text and "Unknown option" in text:
            pytest.skip("this openssl has no -rawin")
        assert res.returncode == 0 and "Signature Verified Successfully" in text, text
        done += 1
        msg.write_bytes(msg.read_bytes() + b"x")
        res = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(pem), "-rawin",
                              "-in", str(msg), "-sigfile", str(sig)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert res.returncode != 0
    assert done == len(CASES)


def test_key_ids_and_public_keys_are_the_ones_the_server_derives():
    for k in ("key", "key2"):
        pub = bytes.fromhex(V[k]["public_key_hex"])
        assert fe.key_id_for(pub) == V[k]["key_id"] == hashlib.sha256(pub).hexdigest()[:32]
        assert fe.parse_public_key(pub) == pub
        assert fe.parse_public_key_b64(V[k]["public_key_b64url"]) == pub


def test_enrollment_proof_verifies_on_the_server():
    e = V["enroll"]
    assert e["proof_message_utf8"].encode() == fe.enroll_proof_message("0123456789ab", e["hostname"])
    assert fe.verify_enroll_proof(PUB, "0123456789ab", e["hostname"], e["proof_b64url"]) is True
    assert fe.verify_enroll_proof(PUB, "0123456789ab", "other-host", e["proof_b64url"]) is False
    assert fe.verify_enroll_proof(PUB, "ba9876543210", e["hostname"], e["proof_b64url"]) is False
    assert fe.verify_enroll_proof(PUB2, "0123456789ab", e["hostname"], e["proof_b64url"]) is False


def test_rotation_proof_is_over_the_documented_message_and_verifies():
    r = V["rotate"]
    msg = ("paddock-rotate/v1\n%s\n%s\n%s" % (V["agent_id"], r["old_key_id"], r["new_key_id"])).encode()
    assert r["proof_message_utf8"].encode() == msg
    proof = b64u_dec(json.loads(r["payload_json"])["proof_b64"])
    assert fe.verify_ed25519(PUB2, msg, proof) is True            # the NEW key proves possession
    assert fe.verify_ed25519(PUB, msg, proof) is False


# ---------------------------------------------------------------------------------------------- the pipeline
@pytest.fixture
def enforce():
    prev = settings.auth_mode
    settings.auth_mode = "enforce"
    try:
        yield
    finally:
        settings.auth_mode = prev


@pytest.fixture(autouse=True)
def _limits():
    fe.reset_limiters()
    fp.reset_limiters()
    yield
    fe.reset_limiters()
    fp.reset_limiters()


async def seed_vector_agent(db_pool, app_pool):
    tid, aid = V["tenant_id"], uuid.UUID(V["agent_id"])
    await tenancy.create_tenant(db_pool, slug="vectors", name="Vectors", tenant_id=tid)
    with tenancy.tenant_context(tid):
        async with app_pool.acquire() as con:
            await con.execute("INSERT INTO fleet_agents (id, hostname, status, agent_version, last_seen) "
                              "VALUES ($1, 'web-01.example.internal', 'online', '0.2.0', NOW())", aid)
            await con.execute("INSERT INTO fleet_agent_keys (agent_id, key_id, public_key) VALUES ($1, $2, $3)",
                              aid, V["key"]["key_id"], PUB)
    return tid, aid


async def ingest(app_pool, env: dict, *, now: dt.datetime, kind: str | None = None):
    return await fp.ingest_envelope(app_pool, agent_id=uuid.UUID(V["agent_id"]), tenant_id=V["tenant_id"],
                                    kind=kind or env["kind"], body=json.dumps(env).encode(), content_encoding=None,
                                    client_ip="203.0.113.9", now=now)


async def test_every_negative_vector_is_refused_at_its_own_check_and_changes_nothing(db_pool, app_pool):
    tid, aid = await seed_vector_agent(db_pool, app_pool)
    expected = {                                    # vector name -> the contract check that must stop it
        "payload_tampered_same_length": ("payload_sha256_mismatch", 400),     # check 5
        "payload_len_wrong": ("payload_len_mismatch", 400),                   # check 5
        "seq_changed": ("bad_signature", 401),                                # check 6
        "kind_changed": ("bad_envelope", 400),                                # check 2: kind vs payload_type
        "signature_bit_flipped": ("bad_signature", 401),
        "issued_at_changed": ("bad_signature", 401),                          # the signature is before the clock
        "tenant_changed": ("tenant_mismatch", 403),                           # check 3
        "kid_changed": ("unknown_key", 401),                                  # check 4
    }
    assert {n["name"] for n in V["negative"]} == set(expected)
    for neg in V["negative"]:
        env = neg["envelope"]
        with pytest.raises(fp.Rejection) as exc:
            await ingest(app_pool, env, now=at(CASES["posture"]["header"]["issued_at"]))
        reason, status = expected[neg["name"]]
        assert (exc.value.reason, exc.value.status) == (reason, status), neg["name"]
    # none of the refusals advanced the sequence claim or stored anything
    with tenancy.tenant_context(tid):
        async with app_pool.acquire() as con:
            assert await con.fetchval("SELECT last_seq FROM fleet_agent_keys WHERE agent_id = $1", aid) == 0
            assert await con.fetchval("SELECT count(*) FROM agent_posture") == 0
            n = await con.fetchval("SELECT count(*) FROM audit_log WHERE action = 'fleet.evidence.rejected'")
    assert n == len(expected)


async def test_the_agents_heartbeat_and_rotation_vectors_are_accepted_by_the_real_ingest(db_pool, app_pool):
    tid, aid = await seed_vector_agent(db_pool, app_pool)
    hb = CASES["heartbeat"]
    res = await ingest(app_pool, hb["envelope"], now=at(hb["header"]["issued_at"]))
    assert res.kind == "heartbeat" and res.seq == 8 and res.key_id == V["key"]["key_id"] and not res.idempotent
    # the same bytes again: idempotent, nothing written; an older seq is a replay
    again = await ingest(app_pool, hb["envelope"], now=at(hb["header"]["issued_at"]))
    assert again.idempotent is True
    with pytest.raises(fp.Rejection) as exc:
        await ingest(app_pool, CASES["posture"]["envelope"], now=at(CASES["posture"]["header"]["issued_at"]))
    assert (exc.value.status, exc.value.reason) == (409, "replayed_seq") and exc.value.body["expected_min"] == 9
    # rotation: the OLD key signs the hand-over, the NEW key proves possession (the agent's own proof)
    ro = CASES["rotate"]
    res = await ingest(app_pool, ro["envelope"], now=at(ro["header"]["issued_at"]))
    assert res.kind == "rotate" and res.new_key_id == V["key2"]["key_id"]
    with tenancy.tenant_context(tid):
        async with app_pool.acquire() as con:
            rows = {r["key_id"]: r for r in await con.fetch("SELECT key_id, status, public_key FROM fleet_agent_keys")}
    assert rows[V["key"]["key_id"]]["status"] == "rotated"
    assert rows[V["key2"]["key_id"]]["status"] == "active" and bytes(rows[V["key2"]["key_id"]]["public_key"]) == PUB2
    # the retired key can no longer be used
    with pytest.raises(fp.Rejection) as exc:
        await ingest(app_pool, hb["envelope"], now=at(hb["header"]["issued_at"]))
    assert exc.value.status == 401


async def test_the_agents_posture_vector_passes_signature_and_is_judged_on_its_payload_alone(db_pool, app_pool):
    """The vector's payload is a toy (one ``self`` section with a non-ASCII note): the signature, digest, clock
    and seq checks (1-8) pass for it, and the server's own schema check (9) is the only thing that speaks."""
    await seed_vector_agent(db_pool, app_pool)
    c = CASES["posture"]
    try:
        res = await ingest(app_pool, c["envelope"], now=at(c["header"]["issued_at"]))
    except fp.Rejection as rej:
        assert rej.reason in ("payload_schema", "payload_not_json") and rej.status == 422, (rej.reason, rej.detail)
    else:
        assert res.kind == "posture" and res.seq == 7


# ---------------------------------------------------------------------------------------------- HTTP enroll
async def test_the_enroll_request_body_in_the_vector_is_accepted_byte_for_byte(db_pool, app_pool, fake_redis, enforce):
    """The exact JSON an agent sends to ``POST /v1/fleet/enroll`` redeems a token whose hash the server holds."""
    from .conftest import _build_app

    e = V["enroll"]
    token = e["token"]
    prefix = token.split("_")[1]
    with tenancy.tenant_context(tenancy.DEFAULT_TENANT_ID):
        async with app_pool.acquire() as con:
            await con.execute(
                "INSERT INTO fleet_enroll_tokens (token_prefix, token_hash, max_uses, uses, created_by, expires_at) "
                "VALUES ($1, $2, 1, 0, 'vectors', NOW() + interval '1 hour')", prefix, auth_svc.hash_api_key(token))
    app = _build_app(app_pool, fake_redis)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as http:
        r = await http.post("/v1/fleet/enroll", content=json.dumps(e["request_body"]).encode(),
                            headers={"Content-Type": "application/json"})
        assert r.status_code == 201, r.text
        out = r.json()
        assert out["key_id"] == e["key_id"] == V["key"]["key_id"] and out["hostname"] == e["hostname"]
        assert out["tenant_id"] == tenancy.DEFAULT_TENANT_ID and out["agent_token"].startswith("fat_")
        # the same body again: the token is spent
        r2 = await http.post("/v1/fleet/enroll", content=json.dumps(e["request_body"]).encode(),
                             headers={"Content-Type": "application/json"})
        assert r2.status_code == 401
        # and the freshly minted credential works with an envelope the AGENT signed (heartbeat vector, re-addressed
        # is impossible without the seed, so the agent's own signing code builds a new one under the vector key)
        seed = bytes.fromhex(V["key"]["seed_hex"])
        env = sup.agent_envelope.build_envelope(
            seed, agent_id=out["agent_id"], tenant_id=out["tenant_id"], kind="heartbeat", seq=1,
            issued_at=int(dt.datetime.now(UTC).timestamp()),
            payload=sup.agent_envelope.canon({"agent_version": "0.2.0", "status": "ok"}),
            payload_type=sup.agent_envelope.PAYLOAD_TYPE_HEARTBEAT, collectors={"agent": "0.2.0"})
        r3 = await http.post(f"/v1/fleet/{out['agent_id']}/heartbeat", json=env,
                             headers={"X-Agent-Token": out["agent_token"]})
        assert r3.status_code == 200, r3.text
