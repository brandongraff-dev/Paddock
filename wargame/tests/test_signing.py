"""Proof hash-chain + signature tests. Pure, no DB."""
from __future__ import annotations

from app.engine.signing import (
    GENESIS_HASH,
    ProofChain,
    ProofSigner,
    redact_and_cap,
    verify_chain,
)


def _chain(secret="s3cret"):
    signer = ProofSigner("k1", secret)
    c = ProofChain(signer)
    c.add("setup", {"replica": "redis-abc", "image": "redis:6.0"})
    c.add("before", {"verdict": "vulnerable", "evidence": {"version": "6.0"}})
    c.add("fix", {"fix_ref": "upgrade redis 6.0 -> 6.2"})
    c.add("after", {"verdict": "not_vulnerable"})
    c.add("summary", {"outcome": "proven_fixed"})
    return signer, c


def test_chain_links_and_verifies():
    signer, c = _chain()
    assert c.entries[0].prev_hash == GENESIS_HASH
    # each entry's prev_hash is the previous entry_hash
    for a, b in zip(c.entries, c.entries[1:]):
        assert b.prev_hash == a.entry_hash
    ok, reason = verify_chain([e.as_row() for e in c.entries], signer)
    assert ok, reason


def test_signatures_present_when_keyed():
    _, c = _chain("key")
    assert all(e.signature is not None and e.key_id == "k1" for e in c.entries)


def test_unsigned_mode_when_no_secret():
    signer, c = _chain("")
    assert all(e.signature is None and e.key_id is None for e in c.entries)
    ok, _ = verify_chain([e.as_row() for e in c.entries], signer)
    assert ok  # unsigned chain still verifies structurally


def test_tamper_payload_breaks_chain():
    signer, c = _chain()
    rows = [e.as_row() for e in c.entries]
    rows[1]["payload"]["verdict"] = "not_vulnerable"  # flip the 'before' verdict
    ok, reason = verify_chain(rows, signer)
    assert not ok and "tampered" in reason


def test_drop_entry_breaks_chain():
    signer, c = _chain()
    rows = [e.as_row() for e in c.entries]
    del rows[2]  # remove the 'fix' entry -> non-dense seq
    ok, reason = verify_chain(rows, signer)
    assert not ok


def test_renumber_breaks_chain():
    # Physically reordering the list is harmless (verify sorts by seq -- that's
    # correct). An attacker must RENUMBER to reorder, which breaks the links.
    signer, c = _chain()
    rows = [e.as_row() for e in c.entries]
    rows[1]["seq"], rows[2]["seq"] = rows[2]["seq"], rows[1]["seq"]
    ok, _ = verify_chain(rows, signer)
    assert not ok


def test_wrong_key_fails_signature():
    _, c = _chain("right-key")
    other = ProofSigner("k1", "wrong-key")
    ok, reason = verify_chain([e.as_row() for e in c.entries], other)
    assert not ok and "signature" in reason


def test_redaction_and_cap():
    out = redact_and_cap({"password": "hunter2", "note": "ok", "big": "x" * 20000})
    assert out["password"] == "<redacted>"
    assert out["note"] == "ok"
    import json
    assert len(json.dumps(out)) <= 8192 + 64
