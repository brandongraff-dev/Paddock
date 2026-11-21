"""Keyed + anchored + fail-closed audit chain (schema/098, app/audit.py,
app/audit_anchor.py, GovernanceMiddleware write-ahead)."""
from __future__ import annotations

import hashlib
import hmac
import io
import json

import httpx
import pytest

from app import audit as audit_svc
from app.audit_anchor import (
    Anchor,
    AnchorSinkError,
    FileAnchorSink,
    MultiAnchorSink,
    S3AnchorSink,
    WebhookAnchorSink,
)
from app.config import settings

KEY_A = "a" * 40
KEY_B = "b" * 40


@pytest.fixture
def key_a(monkeypatch):
    monkeypatch.setattr(settings, "audit_hmac_key", KEY_A)
    monkeypatch.setattr(settings, "audit_hmac_previous_keys", "")


@pytest.fixture
def sink(tmp_path):
    return FileAnchorSink(tmp_path / "anchors.jsonl")


async def _rows(pool, n, start=0):
    return [await audit_svc.record(pool, action="read", actor=f"u{i}") for i in range(start, start + n)]


# --------------------------------------------------------------------------- #
# Keyed chain
# --------------------------------------------------------------------------- #

async def test_keyed_rows_record_alg_and_verify(db_pool, key_a):
    rows = await _rows(db_pool, 3)
    kid = audit_svc.key_id(KEY_A.encode())
    assert all(r["hash_alg"] == f"hmac-sha256:{kid}" for r in rows)
    res = await audit_svc.verify(db_pool, sink=None)
    assert res["ok"] is True and res["checked"] == 3


async def test_legacy_rows_still_verify_after_key_is_introduced(db_pool, monkeypatch):
    await _rows(db_pool, 3)  # unkeyed sha256
    monkeypatch.setattr(settings, "audit_hmac_key", KEY_A)
    await _rows(db_pool, 3, start=3)
    async with db_pool.acquire() as con:
        algs = [r["hash_alg"] for r in await con.fetch("SELECT hash_alg FROM audit_log ORDER BY id")]
    assert algs[:3] == ["sha256"] * 3 and all(a.startswith("hmac-sha256:") for a in algs[3:])
    assert (await audit_svc.verify(db_pool, sink=None))["ok"] is True


async def test_superuser_cannot_forge_keyed_row(db_pool, key_a):
    rows = await _rows(db_pool, 4)
    # An attacker with DB access rewrites row 2 and recomputes an UNKEYED hash
    # for it -- impossible to recompute the HMAC without the key.
    async with db_pool.acquire() as con:
        r = await con.fetchrow("SELECT * FROM audit_log WHERE id = $1", rows[1]["id"])
        row = dict(r)
        row["actor"] = "mallory"
        forged = audit_svc.compute_entry_hash(r["prev_hash"], row)
        await con.execute(
            "UPDATE audit_log SET actor = 'mallory', entry_hash = $2 WHERE id = $1",
            rows[1]["id"],
            forged,
        )
    res = await audit_svc.verify(db_pool, sink=None)
    assert res["ok"] is False
    assert res["first_broken_id"] == rows[1]["id"]


async def test_downgrade_to_unkeyed_is_rejected(db_pool, monkeypatch):
    monkeypatch.setattr(settings, "audit_hmac_key", KEY_A)
    await _rows(db_pool, 2)
    monkeypatch.setattr(settings, "audit_hmac_key", None)
    monkeypatch.setattr(settings, "audit_hmac_previous_keys", KEY_A)
    bad = await audit_svc.record(db_pool, action="read", actor="sneaky")
    assert bad["hash_alg"] == "sha256"
    res = await audit_svc.verify(db_pool, sink=None)
    assert res["ok"] is False
    assert res["reason"] == "downgrade" and res["first_broken_id"] == bad["id"]


async def test_key_rotation(db_pool, monkeypatch):
    monkeypatch.setattr(settings, "audit_hmac_key", KEY_A)
    await _rows(db_pool, 2)
    # rotate: B is current, A kept for verification
    monkeypatch.setattr(settings, "audit_hmac_key", KEY_B)
    monkeypatch.setattr(settings, "audit_hmac_previous_keys", KEY_A)
    rows_b = await _rows(db_pool, 2, start=2)
    assert rows_b[0]["hash_alg"] == f"hmac-sha256:{audit_svc.key_id(KEY_B.encode())}"
    assert (await audit_svc.verify(db_pool, sink=None))["ok"] is True
    # retiring A too early makes its rows unverifiable -- loudly
    monkeypatch.setattr(settings, "audit_hmac_previous_keys", "")
    res = await audit_svc.verify(db_pool, sink=None)
    assert res["ok"] is False and res["reason"] == "unknown_key"


async def test_key_file(db_pool, monkeypatch, tmp_path):
    f = tmp_path / "audit.key"
    f.write_text(KEY_A + "\n")
    monkeypatch.setattr(settings, "audit_hmac_key_file", str(f))
    r = await audit_svc.record(db_pool, action="read", actor="x")
    assert r["hash_alg"] == f"hmac-sha256:{audit_svc.key_id(KEY_A.encode())}"


async def test_verify_streams_in_batches(db_pool):
    await _rows(db_pool, 7)
    res = await audit_svc.verify(db_pool, sink=None, batch_size=2)
    assert res["ok"] is True and res["checked"] == 7


# --------------------------------------------------------------------------- #
# Anchoring: truncation, mismatch, signatures
# --------------------------------------------------------------------------- #

async def test_anchor_then_verify_ok_and_growth_ok(db_pool, key_a, sink):
    await _rows(db_pool, 3)
    out = await audit_svc.anchor_head(db_pool, sink)
    assert out["anchored"] is True and out["anchor"]["sig"]
    await _rows(db_pool, 2, start=3)  # appending after an anchor is fine
    res = await audit_svc.verify(db_pool, sink=sink)
    assert res["ok"] is True and res["anchor"]["status"] == "ok"
    # anchoring again is incremental and idempotent
    assert (await audit_svc.anchor_head(db_pool, sink))["anchored"] is True
    assert (await audit_svc.anchor_head(db_pool, sink))["anchored"] is False


async def test_tail_truncation_detected(db_pool, key_a, sink):
    rows = await _rows(db_pool, 5)
    await audit_svc.anchor_head(db_pool, sink)
    # Delete the newest rows: the remaining prefix is a perfectly valid chain,
    # so only the anchor can notice.
    async with db_pool.acquire() as con:
        await con.execute("DELETE FROM audit_log WHERE id >= $1", rows[3]["id"])
    res = await audit_svc.verify(db_pool, sink=sink)
    assert res["checked"] == 3
    assert res["ok"] is False and res["anchor"]["status"] == "truncated"
    assert res["reason"] == "anchor_truncated"


async def test_full_rewrite_of_unkeyed_chain_detected_by_anchor(db_pool, sink):
    rows = await _rows(db_pool, 4)  # legacy unkeyed chain
    await audit_svc.anchor_head(db_pool, sink)
    # Superuser rewrites row 2 AND recomputes every following hash: the chain
    # verifies on its own ...
    async with db_pool.acquire() as con:
        await con.execute("UPDATE audit_log SET actor = 'mallory' WHERE id = $1", rows[1]["id"])
        prev = audit_svc.GENESIS_HASH
        for r in await con.fetch("SELECT * FROM audit_log ORDER BY id"):
            h = audit_svc.compute_entry_hash(prev, dict(r))
            await con.execute(
                "UPDATE audit_log SET prev_hash = $2, entry_hash = $3 WHERE id = $1", r["id"], prev, h
            )
            prev = h
    assert (await audit_svc.verify(db_pool, sink=None))["ok"] is True
    # ... but no longer matches the external anchor.
    res = await audit_svc.verify(db_pool, sink=sink)
    assert res["ok"] is False and res["anchor"]["status"] == "mismatch"


async def test_forged_anchor_rejected(db_pool, key_a, sink):
    await _rows(db_pool, 3)
    await audit_svc.anchor_head(db_pool, sink)
    lines = sink.path.read_text().splitlines()
    d = json.loads(lines[-1])
    d["max_id"] = 1  # attacker "re-anchors" an earlier head
    sink.path.write_text("\n".join(lines[:-1] + [json.dumps(d)]) + "\n")
    res = await audit_svc.verify(db_pool, sink=sink)
    assert res["ok"] is False and res["anchor"]["status"] == "bad_signature"


async def test_anchor_refuses_broken_chain(db_pool, sink):
    rows = await _rows(db_pool, 3)
    async with db_pool.acquire() as con:
        await con.execute("UPDATE audit_log SET actor = 'x' WHERE id = $1", rows[0]["id"])
    with pytest.raises(audit_svc.AuditIntegrityError):
        await audit_svc.anchor_head(db_pool, sink)
    assert not sink.path.exists()


async def test_anchor_refuses_when_truncated_since_last_anchor(db_pool, sink):
    rows = await _rows(db_pool, 4)
    await audit_svc.anchor_head(db_pool, sink)
    async with db_pool.acquire() as con:
        await con.execute("DELETE FROM audit_log WHERE id >= $1", rows[2]["id"])
    await _rows(db_pool, 3, start=10)  # attacker appends to hide the gap
    with pytest.raises(audit_svc.AuditIntegrityError):
        await audit_svc.anchor_head(db_pool, sink)


async def test_unreachable_sink_fails_verification_closed(db_pool):
    class Down:
        name = "down"

        async def latest(self, tenant_id):
            raise AnchorSinkError("connection refused")

        async def publish(self, anchor):
            raise AnchorSinkError("connection refused")

    await _rows(db_pool, 2)
    res = await audit_svc.verify(db_pool, sink=Down())
    assert res["ok"] is False and res["anchor"]["status"] == "unavailable"


async def test_verify_and_anchor_endpoints(app, client, db_pool, key_a, sink):
    app.state.audit_anchor_sink = sink
    r = await client.post("/v1/scope", json={"kind": "domain", "value": "anc.example", "added_by": "t"})
    assert r.status_code == 201
    r = await client.post("/v1/audit/anchor")
    assert r.status_code == 200 and r.json()["anchored"] is True
    v = (await client.get("/v1/audit/verify")).json()
    assert v["ok"] is True and v["anchor"]["status"] == "ok"
    async with db_pool.acquire() as con:
        await con.execute("DELETE FROM audit_log WHERE id = (SELECT max(id) FROM audit_log)")
        await con.execute("DELETE FROM audit_log WHERE id = (SELECT max(id) FROM audit_log)")
    v = (await client.get("/v1/audit/verify")).json()
    assert v["ok"] is False and v["anchor"]["status"] == "truncated"


# --------------------------------------------------------------------------- #
# Sink implementations
# --------------------------------------------------------------------------- #

def _anchor(max_id=5, tenant="t1"):
    return Anchor(tenant_id=tenant, max_id=max_id, head_hash="h" * 64, hash_alg="sha256",
                  ts="2026-01-01T00:00:00+00:00")


async def test_file_sink_latest_per_tenant(sink):
    for a in (_anchor(3), _anchor(9), _anchor(7), _anchor(50, tenant="t2")):
        await sink.publish(a)
    assert (await sink.latest("t1")).max_id == 9
    assert (await sink.latest("t2")).max_id == 50
    assert await sink.latest("nobody") is None


class _FakeS3:
    def __init__(self):
        self.objects: dict[str, bytes] = {}
        self.puts: list[dict] = []

    def put_object(self, **kw):
        assert kw["Key"] not in self.objects, "objects are never overwritten"
        self.puts.append(kw)
        self.objects[kw["Key"]] = kw["Body"]
        return {"VersionId": "v1"}

    def get_paginator(self, name):
        objs = self.objects

        class P:
            def paginate(self, Bucket, Prefix):
                yield {"Contents": [{"Key": k} for k in sorted(objs) if k.startswith(Prefix)]}

        return P()

    def get_object(self, Bucket, Key):
        return {"Body": io.BytesIO(self.objects[Key])}


async def test_s3_sink_uses_object_lock_and_reads_latest():
    fake = _FakeS3()
    s3 = S3AnchorSink("bucket", prefix="p/", retention_days=30, client=fake)
    await s3.publish(_anchor(9))
    await s3.publish(_anchor(10))
    await s3.publish(_anchor(2))
    put = fake.puts[0]
    assert put["ObjectLockMode"] == "COMPLIANCE" and put["ObjectLockRetainUntilDate"]
    assert put["ChecksumAlgorithm"] == "SHA256"
    assert (await s3.latest("t1")).max_id == 10  # zero-padded keys sort numerically


async def test_webhook_sink_signs_body_and_reads_back():
    seen: list[httpx.Request] = []
    stored: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.method == "POST":
            stored["last"] = request.content.decode()
            return httpx.Response(202)
        return httpx.Response(200, text=stored["last"])

    wh = WebhookAnchorSink(
        "https://anchors.invalid/in", secret="s3cret",
        latest_url="https://anchors.invalid/latest", transport=httpx.MockTransport(handler),
    )
    await wh.publish(_anchor(4))
    body = seen[0].content
    want = "sha256=" + hmac.new(b"s3cret", body, hashlib.sha256).hexdigest()
    assert seen[0].headers["X-Paddock-Signature"] == want
    assert (await wh.latest("t1")).max_id == 4
    assert seen[1].url.params["tenant_id"] == "t1"


async def test_multi_sink_reports_partial_failure(sink):
    class Bad:
        name = "bad"

        async def publish(self, a):
            raise AnchorSinkError("nope")

        async def latest(self, t):
            return None

    m = MultiAnchorSink([sink, Bad()])
    with pytest.raises(AnchorSinkError):
        await m.publish(_anchor(3))
    assert (await m.latest("t1")).max_id == 3  # the healthy sink still recorded it


# --------------------------------------------------------------------------- #
# Fail-closed auditing of mutations
# --------------------------------------------------------------------------- #

async def test_mutation_refused_when_audit_unavailable(client, db_pool, monkeypatch):
    async def boom(*a, **kw):
        raise RuntimeError("audit store down")

    monkeypatch.setattr(audit_svc, "record", boom)
    r = await client.post("/v1/scope", json={"kind": "domain", "value": "nope.example", "added_by": "t"})
    assert r.status_code == 503
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT count(*) FROM scope_entries WHERE value = 'nope.example'") == 0
    # reads are unaffected
    assert (await client.get("/v1/scope")).status_code == 200


async def test_mutation_writes_intent_then_outcome(client, db_pool):
    r = await client.post("/v1/scope", json={"kind": "domain", "value": "wa.example", "added_by": "t"})
    assert r.status_code == 201
    async with db_pool.acquire() as con:
        rows = await con.fetch(
            "SELECT id, status, details FROM audit_log WHERE path = '/v1/scope' ORDER BY id"
        )
    intent, outcome = (json.loads(r["details"]) for r in rows[-2:])
    assert intent == {"phase": "intent"} and rows[-2]["status"] is None
    assert outcome == {"phase": "outcome", "intent_id": rows[-2]["id"]}
    assert rows[-1]["status"] == 201


async def test_fail_closed_can_be_disabled(client, monkeypatch):
    async def boom(*a, **kw):
        raise RuntimeError("audit store down")

    monkeypatch.setattr(settings, "audit_fail_closed", False)
    monkeypatch.setattr(audit_svc, "record", boom)
    r = await client.post("/v1/scope", json={"kind": "domain", "value": "ok.example", "added_by": "t"})
    assert r.status_code == 201


async def test_same_transaction_audit_rolls_back_with_the_write(db_pool):
    async with db_pool.acquire() as con:
        with pytest.raises(RuntimeError):
            async with con.transaction():
                await con.execute(
                    "INSERT INTO scope_entries (kind, value, added_by) VALUES ('domain', 'tx.example', 't')"
                )
                await audit_svc.record(None, con=con, action="create", actor="t")
                raise RuntimeError("handler failed after auditing")
        assert await con.fetchval("SELECT count(*) FROM scope_entries WHERE value = 'tx.example'") == 0
        assert await con.fetchval("SELECT count(*) FROM audit_log") == 0
