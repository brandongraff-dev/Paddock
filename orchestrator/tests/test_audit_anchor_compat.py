"""P3.3: audit anchor v2 compatibility (docs/ASSURANCE_P3.md 3.7, D15).

The trap: ``Anchor.signed_body()`` is ``asdict(self)`` minus ``sig``, so adding a dataclass field puts a new key into the
signed bytes of every stored legacy anchor and every HMAC anchor would verify as ``bad_signature``. The new detached
``sigs`` list must therefore be excluded from the signed body and omitted from the JSON when absent. These tests pin the
legacy bytes with literals that were produced by the unmodified code.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, dataclass
from typing import Any

import pytest

from app import audit as audit_svc
from app.audit_anchor import Anchor, FileAnchorSink
from app.config import settings

KEY = "k" * 40
TENANT = "00000000-0000-0000-0000-000000000001"

# produced by the code before the P3.3 change (git HEAD): Anchor(tenant, 42, "ab"*32, "hmac-sha256:0123abcd", ts, kid="0123abcd")
GOLDEN_SIGNED_BODY = (
    b'{"hash_alg":"hmac-sha256:0123abcd","head_hash":"abababababababababababababababababababababababababababababababab",'
    b'"kid":"0123abcd","max_id":42,"tenant_id":"00000000-0000-0000-0000-000000000001",'
    b'"ts":"2026-12-01T08:59:40.123456+00:00","v":1}'
)
GOLDEN_HMAC = "26d5600b0e65dff7bd2b25c7c8acc61639e5fa0cb5c8aa4ea2a16756ef801745"   # HMAC(b"k"*40, ctx + body)
GOLDEN_LINE = (
    '{"hash_alg":"hmac-sha256:0123abcd","head_hash":"abababababababababababababababababababababababababababababababab",'
    '"kid":"0123abcd","max_id":42,"sig":"' + GOLDEN_HMAC + '","tenant_id":"00000000-0000-0000-0000-000000000001",'
    '"ts":"2026-12-01T08:59:40.123456+00:00","v":1}'
)
SIG_ENTRY = {"v": 2, "alg": "ed25519", "kid": "f" * 32, "estate": "e_" + "a" * 26, "at": "2026-12-01T08:59:40Z",
             "sig": "A" * 86 + "=="}


def legacy(**kw: Any) -> Anchor:
    base = dict(tenant_id=TENANT, max_id=42, head_hash="ab" * 32, hash_alg="hmac-sha256:0123abcd",
                ts="2026-12-01T08:59:40.123456+00:00", kid="0123abcd")
    base.update(kw)
    return Anchor(**base)


@pytest.fixture
def key(monkeypatch):
    monkeypatch.setattr(settings, "audit_hmac_key", KEY)
    monkeypatch.setattr(settings, "audit_hmac_previous_keys", "")
    monkeypatch.delenv("AUDIT_ANCHOR_ALLOW_LEGACY", raising=False)


@pytest.fixture(autouse=True)
def isolated_signers(monkeypatch):
    """Each test controls the signer hook itself (the default signer is not auto-registered here)."""
    monkeypatch.setattr(audit_svc, "ANCHOR_SIGNERS", [], raising=False)
    monkeypatch.setattr(audit_svc, "_SIGNERS_BOOTSTRAPPED", True, raising=False)


# --------------------------------------------------------------------------- #
# the bytes of a legacy anchor do not change
# --------------------------------------------------------------------------- #

def test_a_legacy_anchor_has_no_sigs_field_and_serialises_exactly_as_before():
    a = legacy()
    assert a.sigs is None
    assert a.signed_body() == GOLDEN_SIGNED_BODY
    a.sig = GOLDEN_HMAC
    assert a.to_json() == GOLDEN_LINE
    assert "sigs" not in json.loads(a.to_json())
    assert "sigs" not in a.to_dict()


def test_sigs_are_excluded_from_the_signed_body():
    a = legacy(sigs=[dict(SIG_ENTRY)])
    assert a.signed_body() == GOLDEN_SIGNED_BODY            # the legacy bytes, byte for byte
    assert b"sigs" not in a.signed_body()


def test_the_hmac_check_passes_with_and_without_sigs(key):
    a = legacy()
    a.kid = audit_svc.key_id(KEY.encode())
    a = audit_svc.sign_anchor(a)
    assert audit_svc.check_anchor(a) == "ok"
    a.sigs = [dict(SIG_ENTRY)]
    assert audit_svc.check_anchor(a) == "ok"                  # attaching sigs afterwards cannot break the HMAC
    twin = Anchor.from_dict(json.loads(a.to_json()))
    assert twin.sigs == [SIG_ENTRY] and audit_svc.check_anchor(twin) == "ok"


def test_a_golden_legacy_line_still_parses_and_its_hmac_verifies(monkeypatch):
    """legacy_anchor_still_verifies: an anchor written by the old code is accepted by the new code."""
    monkeypatch.setattr(settings, "audit_hmac_key", KEY)
    kid = audit_svc.key_id(KEY.encode())
    body = json.loads(GOLDEN_LINE)
    body["kid"] = kid
    body.pop("sig")
    old = Anchor.from_dict(body)
    want = hmac.new(KEY.encode(), b"paddock-anchor/v1\n" + GOLDEN_SIGNED_BODY.replace(b"0123abcd", kid.encode()),
                    hashlib.sha256).hexdigest()
    old.sig = want
    again = Anchor.from_dict(json.loads(old.to_json()))
    assert again.sigs is None and audit_svc.check_anchor(again) == "ok"


def test_to_json_and_from_dict_round_trip_sigs():
    a = legacy(sigs=[dict(SIG_ENTRY)])
    a.sig = GOLDEN_HMAC
    d = json.loads(a.to_json())
    assert d["sigs"] == [SIG_ENTRY]
    b = Anchor.from_dict(d)
    assert b == a and b.to_json() == a.to_json()


@pytest.mark.parametrize("bad", ["x", 5, {"a": 1}, [1], ["x"], [None]])
def test_a_malformed_sigs_value_is_kept_as_a_malformed_entry_not_dropped(bad):
    """A tampered ``sigs`` must reach the status check as something that fails; it must not silently become ``None``
    (which would turn a forged-looking anchor into a plain legacy one)."""
    d = json.loads(GOLDEN_LINE)
    d["sigs"] = bad
    a = Anchor.from_dict(d)
    assert a.sigs is not None and a.sigs != [] and a.signed_body() == GOLDEN_SIGNED_BODY
    assert not any(isinstance(e, dict) and e.get("v") == 2 and e.get("sig") for e in a.sigs)


def test_an_old_binary_ignores_sigs_and_its_hmac_check_still_passes(monkeypatch):
    """Rolling deploy: the previous release's Anchor class (reproduced here from git HEAD) reads a dual anchor."""
    monkeypatch.setattr(settings, "audit_hmac_key", KEY)

    @dataclass
    class OldAnchor:
        tenant_id: str
        max_id: int
        head_hash: str
        hash_alg: str
        ts: str
        v: int = 1
        kid: str | None = None
        sig: str | None = None

        def signed_body(self) -> bytes:
            d = asdict(self)
            d.pop("sig", None)
            return json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")

        @classmethod
        def from_dict(cls, d):
            return cls(tenant_id=str(d["tenant_id"]), max_id=int(d["max_id"]), head_hash=str(d["head_hash"]),
                       hash_alg=str(d.get("hash_alg") or "sha256"), ts=str(d["ts"]), v=int(d.get("v", 1)),
                       kid=d.get("kid"), sig=d.get("sig"))

    new = legacy()
    new.kid = audit_svc.key_id(KEY.encode())
    new = audit_svc.sign_anchor(new)
    new.sigs = [dict(SIG_ENTRY)]
    old = OldAnchor.from_dict(json.loads(new.to_json()))
    mac = hmac.new(KEY.encode(), b"paddock-anchor/v1\n" + old.signed_body(), hashlib.sha256).hexdigest()
    assert old.signed_body() == new.signed_body() and hmac.compare_digest(mac, new.sig)


# --------------------------------------------------------------------------- #
# the public document
# --------------------------------------------------------------------------- #

def test_to_public_is_the_spec_document_without_tenant_or_hmac_key_id():
    a = legacy(hash_alg="hmac-sha256:0123abcd")
    doc = a.to_public("e_" + "a" * 26, "f" * 32)
    assert doc == {"alg": "ed25519", "at": "2026-12-01T08:59:40Z", "estate": "e_" + "a" * 26,
                   "hash_alg": "hmac-sha256", "head": "ab" * 32, "kid": "f" * 32, "max_id": 42, "v": 2}
    assert TENANT not in json.dumps(doc) and "0123abcd" not in json.dumps(doc)
    assert legacy(hash_alg="sha256").to_public("e_" + "a" * 26, "f" * 32)["hash_alg"] == "sha256"
    assert a.to_public("e_" + "a" * 26, "f" * 32, sig="QUJD")["sig"] == "QUJD"


def test_to_public_floors_the_time_and_handles_a_z_suffix_and_naive_input():
    for ts in ("2026-12-01T08:59:40.999999+00:00", "2026-12-01T08:59:40Z", "2026-12-01T10:59:40+02:00"):
        assert legacy(ts=ts).to_public("e_" + "a" * 26, "f" * 32)["at"] == "2026-12-01T08:59:40Z"


def test_to_public_refuses_an_unknown_hash_family():
    with pytest.raises(ValueError):
        legacy(hash_alg="md5").to_public("e_" + "a" * 26, "f" * 32)


# --------------------------------------------------------------------------- #
# the signer hook in anchor_head
# --------------------------------------------------------------------------- #

async def test_signers_run_after_hmac_signing_and_before_the_sink_publishes(db_pool, key, tmp_path):
    await audit_svc.record(db_pool, action="read", actor="u")
    order: list[str] = []

    class Sink(FileAnchorSink):
        async def publish(self, anchor):
            order.append("publish")
            seen["published"] = anchor.to_json()
            return await super().publish(anchor)

    seen: dict[str, Any] = {}

    async def signer(pool, anchor):
        order.append("signer")
        seen["hmac_present"] = bool(anchor.sig)
        anchor.sigs = [dict(SIG_ENTRY)]

    audit_svc.ANCHOR_SIGNERS.append(signer)
    out = await audit_svc.anchor_head(db_pool, Sink(tmp_path / "a.jsonl"))
    assert out["anchored"] is True and order == ["signer", "publish"] and seen["hmac_present"] is True
    assert json.loads(seen["published"])["sigs"] == [SIG_ENTRY]
    assert out["anchor"]["sigs"] == [SIG_ENTRY]


async def test_a_failing_signer_never_blocks_the_anchor_and_leaves_no_partial_sigs(db_pool, key, tmp_path):
    await audit_svc.record(db_pool, action="read", actor="u")
    calls: list[str] = []

    async def half(pool, anchor):
        anchor.sigs = [dict(SIG_ENTRY)]
        raise RuntimeError("backend down")

    async def good(pool, anchor):
        calls.append("good")

    audit_svc.ANCHOR_SIGNERS.extend([half, good])
    sink = FileAnchorSink(tmp_path / "a.jsonl")
    out = await audit_svc.anchor_head(db_pool, sink)
    assert out["anchored"] is True and calls == ["good"]
    assert out["anchor"].get("sigs") is None
    line = json.loads((tmp_path / "a.jsonl").read_text().splitlines()[0])
    assert "sigs" not in line and line["sig"]


async def test_a_legacy_only_anchor_is_unchanged_in_the_sink_and_in_the_result(db_pool, key, tmp_path):
    await audit_svc.record(db_pool, action="read", actor="u")
    sink = FileAnchorSink(tmp_path / "a.jsonl")
    out = await audit_svc.anchor_head(db_pool, sink)
    assert "sigs" not in out["anchor"]
    assert set(json.loads((tmp_path / "a.jsonl").read_text().splitlines()[0])) == {
        "tenant_id", "max_id", "head_hash", "hash_alg", "ts", "v", "kid", "sig"}
    again = await audit_svc.anchor_head(db_pool, sink)           # "head already anchored" returns the stored anchor
    assert again["anchored"] is False and "sigs" not in again["anchor"]


async def test_the_signer_hook_is_given_the_pool_and_a_hmac_signed_anchor(db_pool, key, tmp_path):
    await audit_svc.record(db_pool, action="read", actor="u")
    got: dict[str, Any] = {}

    async def signer(pool, anchor):
        got.update(pool=pool, tenant=anchor.tenant_id, max_id=anchor.max_id, kid=anchor.kid)

    audit_svc.ANCHOR_SIGNERS.append(signer)
    await audit_svc.anchor_head(db_pool, FileAnchorSink(tmp_path / "a.jsonl"))
    assert got["pool"] is db_pool and got["tenant"] == TENANT and got["max_id"] >= 1
    assert got["kid"] == audit_svc.key_id(KEY.encode())


# --------------------------------------------------------------------------- #
# verify() consults anchor_sig_status
# --------------------------------------------------------------------------- #

async def _anchored(db_pool, tmp_path, signer=None):
    await audit_svc.record(db_pool, action="read", actor="u")
    if signer is not None:
        audit_svc.ANCHOR_SIGNERS.append(signer)
    sink = FileAnchorSink(tmp_path / "a.jsonl")
    await audit_svc.anchor_head(db_pool, sink)
    return sink


async def test_verify_fails_closed_when_the_signature_check_says_bad(db_pool, key, tmp_path, monkeypatch):
    async def signer(pool, anchor):
        anchor.sigs = [dict(SIG_ENTRY)]

    sink = await _anchored(db_pool, tmp_path, signer)
    seen: list[Any] = []

    async def status(pool, tenant, anchor):
        seen.append((tenant, anchor.sigs))
        return "bad_signature"

    monkeypatch.setattr(audit_svc, "_anchor_sig_check", status)
    res = await audit_svc.verify(db_pool, sink=sink)
    assert res["ok"] is False and res["anchor"]["status"] == "bad_signature" and res["reason"] == "anchor_bad_signature"
    assert seen == [(TENANT, [SIG_ENTRY])]


async def test_verify_accepts_when_the_signature_check_says_ok(db_pool, key, tmp_path, monkeypatch):
    sink = await _anchored(db_pool, tmp_path)

    async def status(pool, tenant, anchor):
        return "ok"

    monkeypatch.setattr(audit_svc, "_anchor_sig_check", status)
    res = await audit_svc.verify(db_pool, sink=sink)
    assert res["ok"] is True and res["anchor"]["status"] == "ok"


async def test_a_downgrade_status_fails_verification_with_the_contract_reason(db_pool, key, tmp_path, monkeypatch):
    sink = await _anchored(db_pool, tmp_path)

    async def status(pool, tenant, anchor):
        return "downgrade"

    monkeypatch.setattr(audit_svc, "_anchor_sig_check", status)
    res = await audit_svc.verify(db_pool, sink=sink)
    assert res["ok"] is False and res["reason"] == "anchor_downgrade"


async def test_the_signature_check_does_not_run_when_the_chain_is_already_broken(db_pool, key, tmp_path, monkeypatch):
    sink = await _anchored(db_pool, tmp_path)
    async with db_pool.acquire() as con:
        await con.execute("UPDATE audit_log SET actor = 'mallory' WHERE id = (SELECT min(id) FROM audit_log)")

    async def status(pool, tenant, anchor):
        raise AssertionError("must not be called")

    monkeypatch.setattr(audit_svc, "_anchor_sig_check", status)
    res = await audit_svc.verify(db_pool, sink=sink)
    assert res["ok"] is False and res["anchor"]["status"] == "skipped"


async def test_a_legacy_anchor_verifies_with_no_attest_state_at_all(db_pool, key, tmp_path):
    """No estate, no keys, the flag unset: exactly the pre-P3 behaviour."""
    sink = await _anchored(db_pool, tmp_path)
    res = await audit_svc.verify(db_pool, sink=sink)
    assert res["ok"] is True and res["anchor"]["status"] == "ok"


async def test_allow_legacy_false_makes_a_legacy_anchor_fail_closed(db_pool, key, tmp_path, monkeypatch):
    sink = await _anchored(db_pool, tmp_path)
    monkeypatch.setenv("AUDIT_ANCHOR_ALLOW_LEGACY", "false")
    res = await audit_svc.verify(db_pool, sink=sink)
    assert res["ok"] is False and res["anchor"]["status"] == "downgrade" and res["reason"] == "anchor_downgrade"
    monkeypatch.setenv("AUDIT_ANCHOR_ALLOW_LEGACY", "true")
    assert (await audit_svc.verify(db_pool, sink=sink))["ok"] is True
