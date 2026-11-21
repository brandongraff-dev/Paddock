"""Verified findings (schema 026): the safe-check orchestration.

No packet is ever sent: the active worker is simulated by posting results to
``/v1/verifications/{id}/result`` and by reading the job off the fake Redis
stream. The worker's own checks are tested in workers/active/tests.
"""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timedelta, timezone

import asyncpg
import pytest

from app import auth as auth_svc
from app import lifecycle
from app import scope as scope_svc
from app.integrations.base import EVENT_TYPES
from app.reports import metrics
from app.verification import service

PUBLIC_IP = "93.184.215.14"
HOST = "app.example.com"


@pytest.fixture(autouse=True)
def _fast_timings(monkeypatch):
    monkeypatch.setattr(service.cfg, "fix_delay_sec", 0)
    monkeypatch.setattr(service.cfg, "pr_delay_sec", 0)
    monkeypatch.setattr(service.cfg, "retry_sec", 0)
    monkeypatch.setattr(service.cfg, "max_attempts", 3)


def pin(*hosts: str) -> None:
    for h in hosts:
        scope_svc.dns_cache._by_host[h] = (time.monotonic() + 10_000, [PUBLIC_IP])


async def add_scope(pool, value: str = "example.com", kind: str = "subdomain_wildcard",
                    proof: str | None = "verified", **proof_cols) -> int:
    """A scope entry with a given proof status (None = no proof row at all)."""
    async with pool.acquire() as con:
        eid = await con.fetchval(
            "INSERT INTO scope_entries (kind, value, added_by) VALUES ($1, $2, 'test') RETURNING id",
            kind, value)
        if proof is not None:
            cols = {"status": proof, **proof_cols}
            names = ", ".join(cols)
            marks = ", ".join(f"${i + 2}" for i in range(len(cols)))
            await con.execute(
                f"INSERT INTO scope_proofs (scope_entry_id, {names}) VALUES ($1, {marks})",
                eid, *cols.values())
    scope_svc.scope_cache.invalidate()
    pin(HOST, "example.com")
    return eid


async def mk_finding(client, rule_id="exposed-env", source="exposed_file", asset=HOST,
                     evidence=None, severity="high", **extra) -> dict:
    item = {
        "asset_value": asset, "asset_kind": "subdomain", "rule_id": rule_id, "rule_source": source,
        "severity": severity, "title": f"{source} {rule_id}", "description": "d",
        "evidence": evidence if evidence is not None else {"url": f"https://{asset}/.env"},
        **extra,
    }
    r = await client.post("/v1/findings/bulk", json={"items": [item]})
    assert r.status_code == 200, r.text
    return r.json()["items"][0]


async def get_finding(client, fid) -> dict:
    r = await client.get(f"/v1/findings/{fid}")
    assert r.status_code == 200, r.text
    return r.json()["finding"]


async def jobs(fake_redis) -> list[dict]:
    out = []
    for _sid, fields in await fake_redis.xrange("queue:active"):
        job = json.loads(fields["job"])
        if job["kind"] == "verify_finding":
            out.append(job)
    return out


async def events(fake_redis) -> list[dict]:
    return [json.loads(f["event"]) for _s, f in await fake_redis.xrange("stream:events")]


SVC_KEY = "svc-key-verification-test"


@pytest.fixture(autouse=True)
def _service_key(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "service_api_key", SVC_KEY)


async def post_result(client, vid, verdict="confirmed", status="done", *, scan_id="auto",
                      service=True, **kw):
    """Post a result the way the active worker does: service key + the job's scan."""
    body = {"status": status, "check_id": "exposed_file", "reason": "test",
            "evidence": {"url": f"https://{HOST}/.env", "status": 200}, **kw}
    if status == "done":
        body["verdict"] = verdict
    headers = {}
    if service:
        headers["X-API-Key"] = SVC_KEY
        if scan_id == "auto":
            async with client._transport.app.state.pool.acquire() as con:
                scan_id = await con.fetchval(
                    "SELECT scan_id FROM finding_verifications WHERE id = $1", uuid.UUID(str(vid)))
        if scan_id:
            headers["X-Paddock-Scan"] = str(scan_id)
    return await client.post(f"/v1/verifications/{vid}/result", json=body, headers=headers)


async def verify(client, fid):
    return await client.post(f"/v1/findings/{fid}/verify")


async def ledger(pool, fid) -> list[asyncpg.Record]:
    async with pool.acquire() as con:
        return await con.fetch(
            "SELECT * FROM finding_verifications WHERE finding_id = $1 ORDER BY requested_at", uuid.UUID(str(fid)))


# =========================================================================== #
# the gate: scope AND proof-of-control
# =========================================================================== #

async def test_no_scope_entry_is_refused_with_reason_and_nothing_queued(client, db_pool, fake_redis):
    f = await mk_finding(client)
    r = await verify(client, f["id"])
    assert r.status_code == 403, r.text
    d = r.json()["detail"]
    assert d["error"] == "verification_refused" and "scope" in d["reason"]
    rows = await ledger(db_pool, f["id"])
    assert [x["status"] for x in rows] == ["refused"] and rows[0]["reason"] == d["reason"]
    assert await jobs(fake_redis) == []


@pytest.mark.parametrize("proof", ["pending", "expired", None])
async def test_unproven_scope_entry_is_refused_even_when_the_global_flag_is_off(
        client, db_pool, fake_redis, proof):
    from app.config import settings

    assert not settings.require_scope_proof  # scope.check alone WOULD allow this target
    await add_scope(db_pool, proof=proof)
    f = await mk_finding(client)
    r = await verify(client, f["id"])
    assert r.status_code == 403
    assert "proof-of-control" in r.json()["detail"]["reason"]
    assert await jobs(fake_redis) == []
    assert (await ledger(db_pool, f["id"]))[0]["status"] == "refused"


async def test_lapsed_attestation_is_refused(client, db_pool, fake_redis):
    await add_scope(db_pool, "93.184.215.0/24", "ipv4_cidr", proof="attested",
                    attestation_expires_at=datetime.now(timezone.utc) - timedelta(days=1))
    f = await mk_finding(client, asset=PUBLIC_IP, evidence={"url": f"https://{PUBLIC_IP}/.env"})
    r = await verify(client, f["id"])
    assert r.status_code == 403 and "proof" in r.json()["detail"]["reason"]


async def test_attested_range_is_accepted(client, db_pool, fake_redis):
    await add_scope(db_pool, "93.184.215.0/24", "ipv4_cidr", proof="attested")
    f = await mk_finding(client, asset=PUBLIC_IP, evidence={"url": f"https://{PUBLIC_IP}/.env"})
    r = await verify(client, f["id"])
    assert r.status_code == 202, r.text
    assert (await jobs(fake_redis))[0]["config"]["scope_proof"] == "attested"


async def test_a_proven_entry_wins_over_an_unproven_one_that_also_matches(client, db_pool, fake_redis):
    await add_scope(db_pool, HOST, "domain", proof="pending")          # matched first
    await add_scope(db_pool, "example.com", "subdomain_wildcard", proof="verified")
    f = await mk_finding(client)
    r = await verify(client, f["id"])
    assert r.status_code == 202, r.text
    assert r.json()["scope_proof"] == "verified"


async def test_verified_entry_queues_a_job_with_a_minimal_finding_payload(client, db_pool, fake_redis):
    eid = await add_scope(db_pool)
    f = await mk_finding(client, evidence={"url": f"https://{HOST}/.env", "secret_dump": "hunter2", "port": 443})
    r = await verify(client, f["id"])
    assert r.status_code == 202, r.text
    v = r.json()
    assert v["status"] == "queued" and v["purpose"] == "exploitability" and v["trigger"] == "manual"
    assert v["scope_entry_id"] == eid and v["scope_proof"] == "verified" and v["scan_id"]
    (job,) = await jobs(fake_redis)
    cfg = job["config"]
    assert job["target"] == HOST and cfg["verification_id"] == v["id"] and cfg["scope_proof"] == "verified"
    assert cfg["finding"]["rule_id"] == "exposed-env"
    assert cfg["finding"]["evidence"] == {"url": f"https://{HOST}/.env", "port": 443}   # nothing else leaves
    assert cfg["tenant_id"]
    async with db_pool.acquire() as con:
        scan = await con.fetchrow("SELECT kind, status FROM scans WHERE id = $1", uuid.UUID(v["scan_id"]))
        decisions = await con.fetch("SELECT decision, worker FROM scope_decisions WHERE worker = $1",
                                    "orchestrator.verification")
    assert (scan["kind"], scan["status"]) == ("verify_finding", "queued")
    assert decisions and decisions[0]["decision"] == "allow"      # every gate decision is audited


async def test_a_second_verify_returns_the_in_flight_row(client, db_pool, fake_redis):
    await add_scope(db_pool)
    f = await mk_finding(client)
    first = (await verify(client, f["id"])).json()
    second = (await verify(client, f["id"])).json()
    assert second["id"] == first["id"] and second["already_in_flight"] is True
    assert len(await jobs(fake_redis)) == 1


async def test_unknown_finding_is_404_and_abac_hides_restricted(client, db_pool):
    assert (await verify(client, uuid.uuid4())).status_code == 404
    assert (await client.get(f"/v1/findings/{uuid.uuid4()}/verifications")).status_code == 404


def test_capabilities_for_the_new_routes():
    f = "00000000-0000-0000-0000-000000000001"
    assert auth_svc.required_capability("POST", f"/v1/findings/{f}/verify") == "scan"
    assert auth_svc.required_capability("POST", "/v1/findings/verify/bulk") == "scan"
    assert auth_svc.required_capability("POST", f"/v1/verifications/{f}/result") == "write"
    assert auth_svc.required_capability("GET", f"/v1/findings/{f}/verifications") == "read"
    assert "scan" in auth_svc.capabilities_for("analyst") and "scan" not in auth_svc.capabilities_for("viewer")


# =========================================================================== #
# verdicts -> finding state + priority (never auto-close)
# =========================================================================== #

async def test_confirmed_raises_priority_and_explains_why(client, db_pool, fake_redis):
    await add_scope(db_pool)
    f = await mk_finding(client)
    before = await get_finding(client, f["id"])
    assert before["exploitability"] == "unverified"
    v = (await verify(client, f["id"])).json()
    r = await post_result(client, v["id"], "confirmed")
    assert r.status_code == 200, r.text
    after = await get_finding(client, f["id"])
    assert after["exploitability"] == "confirmed" and after["last_verified_at"]
    assert after["priority_score"] == before["priority_score"] + 15
    today = datetime.now(timezone.utc).date().isoformat()
    assert f"Verified exploitable on {today}" in [w["label"] for w in after["why"]]
    assert after["status"] == "open"
    evs = await events(fake_redis)
    verified = [e for e in evs if e["event"] == "finding_verified"]
    assert verified and verified[0]["verdict"] == "confirmed" and verified[0]["finding_id"] == f["id"]


async def test_not_reproducible_lowers_priority_but_never_closes(client, db_pool):
    await add_scope(db_pool)
    f = await mk_finding(client)
    before = await get_finding(client, f["id"])
    v = (await verify(client, f["id"])).json()
    await post_result(client, v["id"], "not_reproducible")
    after = await get_finding(client, f["id"])
    assert after["exploitability"] == "not_reproducible"
    assert after["priority_score"] == before["priority_score"] - 12
    assert any(w["label"].startswith("Not reproducible on ") and w["weight"] < 0 for w in after["why"])
    assert after["status"] == "open" and after["fix_verified_at"] is None     # no auto-close, no "fixed"


async def test_inconclusive_changes_state_but_not_priority(client, db_pool):
    await add_scope(db_pool)
    f = await mk_finding(client)
    before = await get_finding(client, f["id"])
    v = (await verify(client, f["id"])).json()
    await post_result(client, v["id"], "inconclusive")
    after = await get_finding(client, f["id"])
    assert after["exploitability"] == "inconclusive" and after["priority_score"] == before["priority_score"]
    assert after["status"] == "open"


async def test_priority_is_clamped_to_zero_and_pure_factor_math():
    s, why = lifecycle.explain_priority(severity="info", exploitability="not_reproducible")
    assert s == 0 and why[-1].weight == -12
    s, why = lifecycle.explain_priority(severity="critical", kev=True, exploitability="confirmed")
    assert s == 75 and why[0].key == "severity"
    s, _ = lifecycle.explain_priority(severity="high")
    assert s == 25                                   # no verdict: unchanged behaviour


async def test_unsupported_leaves_the_finding_unverified(client, db_pool):
    await add_scope(db_pool)
    f = await mk_finding(client)
    v = (await verify(client, f["id"])).json()
    r = await post_result(client, v["id"], status="unsupported", reason="no safe check for nuclei/x")
    assert r.status_code == 200 and r.json()["status"] == "unsupported"
    assert (await get_finding(client, f["id"]))["exploitability"] == "unverified"


async def test_worker_refusal_and_error_are_recorded(client, db_pool):
    await add_scope(db_pool)
    f = await mk_finding(client)
    v = (await verify(client, f["id"])).json()
    r = await post_result(client, v["id"], status="refused", reason="scope guard: out of scope")
    assert r.json()["status"] == "refused" and r.json()["reason"].startswith("scope guard")
    v2 = (await verify(client, f["id"])).json()
    assert v2["id"] != v["id"]
    r = await post_result(client, v2["id"], status="error", reason="boom")
    assert r.json()["status"] == "error"
    assert (await get_finding(client, f["id"]))["exploitability"] == "unverified"


async def test_result_validation_and_idempotence(client, db_pool):
    await add_scope(db_pool)
    f = await mk_finding(client)
    v = (await verify(client, f["id"])).json()
    bad = await client.post(f"/v1/verifications/{v['id']}/result", json={"status": "done"})
    assert bad.status_code == 422
    bad = await client.post(f"/v1/verifications/{v['id']}/result",
                            json={"status": "refused", "verdict": "confirmed"})
    assert bad.status_code == 422
    assert (await post_result(client, uuid.uuid4())).status_code == 404
    assert (await post_result(client, v["id"], "confirmed")).status_code == 200
    again = await post_result(client, v["id"], "not_reproducible")
    assert again.status_code == 409
    assert (await get_finding(client, f["id"]))["exploitability"] == "confirmed"   # first answer stands


async def test_oversized_evidence_is_capped(client, db_pool):
    await add_scope(db_pool)
    f = await mk_finding(client)
    v = (await verify(client, f["id"])).json()
    r = await post_result(client, v["id"], "confirmed", evidence={"blob": "x" * 50_000})
    assert r.status_code == 200
    assert r.json()["evidence"]["truncated"] is True
    assert len(json.dumps(r.json()["evidence"])) < 1000


async def test_ledger_is_append_only(client, db_pool):
    await add_scope(db_pool)
    f = await mk_finding(client)
    v = (await verify(client, f["id"])).json()
    await post_result(client, v["id"], "confirmed")
    async with db_pool.acquire() as con:
        with pytest.raises(asyncpg.IntegrityConstraintViolationError):
            await con.execute("UPDATE finding_verifications SET verdict = 'not_reproducible' WHERE id = $1",
                              uuid.UUID(v["id"]))


async def test_history_endpoint_lists_every_attempt_newest_first(client, db_pool):
    await add_scope(db_pool)
    f = await mk_finding(client)
    v1 = (await verify(client, f["id"])).json()
    await post_result(client, v1["id"], "confirmed")
    v2 = (await verify(client, f["id"])).json()
    await post_result(client, v2["id"], "not_reproducible")
    r = await client.get(f"/v1/findings/{f['id']}/verifications")
    assert r.status_code == 200, r.text
    h = r.json()
    assert h["exploitability"] == "not_reproducible"
    assert [i["id"] for i in h["items"]] == [v2["id"], v1["id"]]
    assert h["items"][1]["evidence"]["status"] == 200 and h["items"][1]["requested_by"]


async def test_exploitability_filter(client, db_pool):
    await add_scope(db_pool)
    a = await mk_finding(client, rule_id="exposed-env")
    b = await mk_finding(client, rule_id="exposed-git-head", evidence={"url": f"https://{HOST}/.git/HEAD"})
    va = (await verify(client, a["id"])).json()
    await post_result(client, va["id"], "confirmed")
    r = await client.get("/v1/findings", params={"exploitability": "confirmed"})
    assert [i["id"] for i in r.json()["items"]] == [a["id"]]
    r = await client.get("/v1/findings", params={"exploitability": "unverified"})
    assert [i["id"] for i in r.json()["items"]] == [b["id"]]
    assert (await client.get("/v1/findings", params={"exploitability": "bogus"})).status_code == 422


async def test_bulk_verify(client, db_pool, fake_redis):
    await add_scope(db_pool)
    a = await mk_finding(client, rule_id="exposed-env")
    b = await mk_finding(client, rule_id="exposed-git-head")
    oos = await mk_finding(client, rule_id="exposed-env", asset="other.invalid",
                           evidence={"url": "https://other.invalid/.env"})
    ghost = str(uuid.uuid4())
    r = await client.post("/v1/findings/verify/bulk",
                          json={"finding_ids": [a["id"], b["id"], oos["id"], ghost, a["id"]]})
    assert r.status_code == 200, r.text
    body = r.json()
    out = {i["finding_id"]: i for i in body["items"]}
    assert body["requested"] == 4 and body["queued"] == 2 and body["refused"] == 1
    assert out[a["id"]]["outcome"] == "queued" and out[oos["id"]]["outcome"] == "refused"
    assert out[ghost]["outcome"] == "not_found"
    assert len(await jobs(fake_redis)) == 2
    again = (await client.post("/v1/findings/verify/bulk", json={"finding_ids": [a["id"]]})).json()
    assert again["items"][0]["outcome"] == "already_in_flight"
    assert (await client.post("/v1/findings/verify/bulk", json={"finding_ids": []})).status_code == 422
    too_many = [str(uuid.uuid4()) for _ in range(101)]
    assert (await client.post("/v1/findings/verify/bulk", json={"finding_ids": too_many})).status_code == 422


async def test_stale_queued_job_times_out_to_error(client, db_pool, fake_redis, monkeypatch):
    await add_scope(db_pool)
    f = await mk_finding(client)
    v = (await verify(client, f["id"])).json()
    async with db_pool.acquire() as con:
        await con.execute("UPDATE finding_verifications SET dispatched_at = NOW() - interval '2 hours' "
                          "WHERE id = $1", uuid.UUID(v["id"]))
    out = await service.sweep(db_pool, fake_redis)
    assert out["expired"] == 1
    assert (await ledger(db_pool, f["id"]))[0]["status"] == "error"
    assert (await verify(client, f["id"])).status_code == 202         # and a new attempt is possible


# =========================================================================== #
# prove it's fixed
# =========================================================================== #

async def mark_fixed(client, fid, how="patch"):
    r = await client.patch(f"/v1/findings/{fid}", json={"status": "fixed", "notes": "patched"})
    assert r.status_code == 200, r.text


async def verified_fix_count(pool) -> int:
    end = datetime.now(timezone.utc) + timedelta(hours=1)
    rep = await metrics.build_report(pool, days=7, end=end, clearance="restricted")
    return rep.resolutions.verified


async def test_fixed_status_schedules_a_recheck_and_verified_fix_is_recorded(client, db_pool, fake_redis):
    await add_scope(db_pool)
    f = await mk_finding(client)
    await mark_fixed(client, f["id"])
    (row,) = await ledger(db_pool, f["id"])
    assert (row["purpose"], row["trigger"], row["status"]) == ("fix", "fix_status", "queued")
    (job,) = await jobs(fake_redis)
    assert job["config"]["purpose"] == "fix"
    assert await verified_fix_count(db_pool) == 0               # fixed, but not yet proven
    r = await post_result(client, str(row["id"]), "not_reproducible", check_id="exposed_file")
    assert r.status_code == 200, r.text
    after = await get_finding(client, f["id"])
    assert after["status"] == "fixed" and after["fix_verified_at"]
    assert after["exploitability"] == "not_reproducible"
    assert await verified_fix_count(db_pool) == 1               # counted by the existing metric
    evs = [e["event"] for e in await events(fake_redis)]
    assert "finding_fix_verified" in evs and "finding_reopened" not in evs
    hist = (await client.get(f"/v1/findings/{f['id']}")).json()["history"]
    assert any(h["actor"] == "system:verification" and "verified fixed" in (h["reason"] or "") for h in hist)


async def test_fix_that_did_not_hold_reopens_with_the_existing_event(client, db_pool, fake_redis):
    await add_scope(db_pool)
    f = await mk_finding(client)
    await mark_fixed(client, f["id"])
    (row,) = await ledger(db_pool, f["id"])
    r = await post_result(client, str(row["id"]), "confirmed")
    assert r.status_code == 200
    after = await get_finding(client, f["id"])
    assert after["status"] == "open" and after["status_reason"] == "fix did not hold"
    assert after["status_by"] == "system:verification" and after["fix_verified_at"] is None
    assert after["exploitability"] == "confirmed"
    evs = await events(fake_redis)
    reopened = [e for e in evs if e["event"] == "finding_reopened"]
    assert reopened and reopened[0]["reason"] == "fix did not hold" and reopened[0]["status"] == "open"
    assert "finding_fix_failed" in [e["event"] for e in evs]
    hist = (await client.get(f"/v1/findings/{f['id']}")).json()["history"]
    assert hist[0]["from_status"] == "fixed" and hist[0]["to_status"] == "open"
    assert await verified_fix_count(db_pool) == 0
    async with db_pool.acquire() as con:        # the reopen does not leave a "resolved" row behind
        assert await con.fetchval("SELECT COUNT(*) FROM finding_resolutions WHERE finding_id = $1",
                                  uuid.UUID(f["id"])) == 0
    # integration mapping: the stream entry becomes the existing finding.reopened event
    from app.integrations import service as isvc

    sid, fields = (await fake_redis.xrange("stream:events"))[-1]
    ev = await isvc.event_from_stream(db_pool, fields, sid)
    assert ev.type == "finding.reopened" and ev.data["reason"] == "fix did not hold"


async def test_duplicates_of_a_failed_fix_reopen_with_their_primary(client, db_pool, fake_redis):
    await add_scope(db_pool)
    f = await mk_finding(client)
    dup = await mk_finding(client, rule_id="exposed-env-2", evidence={"url": f"https://{HOST}/.env"})
    async with db_pool.acquire() as con:
        await con.execute("UPDATE findings SET duplicate_of = $1, status = 'fixed' WHERE id = $2",
                          uuid.UUID(f["id"]), uuid.UUID(dup["id"]))
    await mark_fixed(client, f["id"])
    (row,) = await ledger(db_pool, f["id"])
    await post_result(client, str(row["id"]), "confirmed")
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT status FROM findings WHERE id = $1", uuid.UUID(dup["id"])) == "open"


async def test_inconclusive_recheck_keeps_it_fixed_and_is_retried_then_gives_up(client, db_pool, fake_redis):
    await add_scope(db_pool)
    f = await mk_finding(client)
    await mark_fixed(client, f["id"])
    for attempt in range(1, 4):
        rows = await ledger(db_pool, f["id"])
        assert len(rows) == attempt and rows[-1]["status"] == "queued"
        await post_result(client, str(rows[-1]["id"]), "inconclusive")
        after = await get_finding(client, f["id"])
        assert after["status"] == "fixed" and after["fix_verified_at"] is None
        out = await service.sweep(db_pool, fake_redis)
        assert out["retried"] == (1 if attempt < 3 else 0)
    rows = await ledger(db_pool, f["id"])
    assert [r["trigger"] for r in rows] == ["fix_status", "retry", "retry"]
    assert await verified_fix_count(db_pool) == 0


async def test_a_retry_can_still_prove_the_fix(client, db_pool, fake_redis):
    await add_scope(db_pool)
    f = await mk_finding(client)
    await mark_fixed(client, f["id"])
    (r1,) = await ledger(db_pool, f["id"])
    await post_result(client, str(r1["id"]), "inconclusive")
    await service.sweep(db_pool, fake_redis)
    r2 = (await ledger(db_pool, f["id"]))[-1]
    await post_result(client, str(r2["id"]), "not_reproducible")
    assert (await get_finding(client, f["id"]))["fix_verified_at"]
    assert await verified_fix_count(db_pool) == 1


async def test_delayed_recheck_waits_for_the_sweep(client, db_pool, fake_redis, monkeypatch):
    monkeypatch.setattr(service.cfg, "fix_delay_sec", 3600)
    await add_scope(db_pool)
    f = await mk_finding(client)
    await mark_fixed(client, f["id"])
    (row,) = await ledger(db_pool, f["id"])
    assert row["status"] == "scheduled" and await jobs(fake_redis) == []
    assert (await service.sweep(db_pool, fake_redis))["dispatched"] == 0
    async with db_pool.acquire() as con:
        await con.execute("UPDATE finding_verifications SET run_after = NOW() - interval '1 second'")
    assert (await service.sweep(db_pool, fake_redis))["dispatched"] == 1
    assert len(await jobs(fake_redis)) == 1


async def test_recheck_of_a_finding_reopened_meanwhile_is_cancelled(client, db_pool, fake_redis, monkeypatch):
    monkeypatch.setattr(service.cfg, "fix_delay_sec", 3600)
    await add_scope(db_pool)
    f = await mk_finding(client)
    await mark_fixed(client, f["id"])
    assert (await client.post(f"/v1/findings/{f['id']}/reopen", json={"reason": "regressed"})).status_code == 200
    async with db_pool.acquire() as con:
        await con.execute("UPDATE finding_verifications SET run_after = NOW()")
    await service.sweep(db_pool, fake_redis)
    (row,) = await ledger(db_pool, f["id"])
    assert row["status"] == "cancelled" and "no longer fixed" in row["reason"]
    assert await jobs(fake_redis) == []


async def test_recheck_of_an_out_of_scope_fix_is_refused_and_recorded(client, db_pool, fake_redis):
    await add_scope(db_pool, proof="pending")
    f = await mk_finding(client)
    await mark_fixed(client, f["id"])
    (row,) = await ledger(db_pool, f["id"])
    assert row["status"] == "refused" and "proof-of-control" in row["reason"]
    assert (await get_finding(client, f["id"]))["status"] == "fixed"          # unproven, not undone
    assert await jobs(fake_redis) == []


async def test_manual_verify_of_a_fixed_finding_is_a_fix_check(client, db_pool, fake_redis, monkeypatch):
    monkeypatch.setattr(service.cfg, "fix_delay_sec", 3600)
    await add_scope(db_pool)
    f = await mk_finding(client)
    await mark_fixed(client, f["id"])                 # scheduled, not yet due
    r = await verify(client, f["id"])                 # "Verify now"
    assert r.status_code == 202 and r.json()["purpose"] == "fix" and r.json()["already_in_flight"] is True


async def test_reopening_clears_the_verified_fix(client, db_pool, fake_redis):
    await add_scope(db_pool)
    f = await mk_finding(client)
    await mark_fixed(client, f["id"])
    (row,) = await ledger(db_pool, f["id"])
    await post_result(client, str(row["id"]), "not_reproducible")
    assert (await get_finding(client, f["id"]))["fix_verified_at"]
    assert (await client.post(f"/v1/findings/{f['id']}/reopen", json={})).status_code == 200
    assert (await get_finding(client, f["id"]))["fix_verified_at"] is None


async def test_exploitability_filter_and_fix_verified_filter(client, db_pool, fake_redis):
    await add_scope(db_pool)
    f = await mk_finding(client)
    await mark_fixed(client, f["id"])
    (row,) = await ledger(db_pool, f["id"])
    await post_result(client, str(row["id"]), "not_reproducible")
    r = await client.get("/v1/findings", params={"fix_verified": "true", "status": "fixed"})
    assert [i["id"] for i in r.json()["items"]] == [f["id"]]
    r = await client.get("/v1/findings", params={"fix_verified": "false"})
    assert r.json()["items"] == []


# ---- fix signals other than a status PATCH ---------------------------------------

async def test_ticket_closed_via_inbound_sync_schedules_the_recheck(client, db_pool, fake_redis, monkeypatch):
    from .test_ticketing_inbound import _env, _finding as _t_finding, _integration, _signed, emitted  # noqa: F401
    from app.integrations import links
    from .ticketing_fakes import jira_webhook

    import base64
    import os
    import sys
    import types

    monkeypatch.setenv("PADDOCK_SECRET_KEY", base64.urlsafe_b64encode(os.urandom(32)).decode())
    from app.integrations import netsafety
    from .ticketing_fakes import allow_all

    monkeypatch.setattr(netsafety, "validate_outbound_url", allow_all)
    mod = types.ModuleType("app.integrations.service")

    async def emit(pool, event):
        return None

    mod.emit = emit
    monkeypatch.setitem(sys.modules, "app.integrations.service", mod)

    await add_scope(db_pool)
    f = await mk_finding(client)
    iid = await _integration(db_pool)
    await links.upsert(db_pool, iid, f["id"], "SEC-1", "https://acme.atlassian.net/browse/SEC-1")
    body = jira_webhook("SEC-1", "Done")
    r = await client.post(f"/v1/integrations/{iid}/inbound", content=body, headers=_signed(body))
    assert r.status_code == 200, r.text
    assert (await get_finding(client, f["id"]))["status"] == "fixed"
    (row,) = await ledger(db_pool, f["id"])
    assert (row["purpose"], row["trigger"], row["status"]) == ("fix", "fix_ticket", "queued")
    assert row["requested_by"].startswith("integration:")


async def test_remediation_pr_merged_schedules_the_recheck(client, db_pool, fake_redis):
    await add_scope(db_pool)
    f = await mk_finding(client)
    async with db_pool.acquire() as con:
        rid = await con.fetchval(
            "INSERT INTO remediations (finding_id, kind, summary, status) "
            "VALUES ($1, 'config_fix', 'x', 'pr_open') RETURNING id", uuid.UUID(f["id"]))
    # not fixed yet: the merge schedules an exploitability re-check (evidence, never a close)
    r = await client.post(f"/v1/remediation/{rid}/merged")
    assert r.status_code == 200, r.text
    assert r.json()["verification"]["purpose"] == "exploitability"
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT status FROM remediations WHERE id = $1", rid) == "merged"
        await con.execute("UPDATE finding_verifications SET status = 'cancelled', completed_at = NOW()")
    await mark_fixed(client, f["id"])
    async with db_pool.acquire() as con:
        await con.execute("UPDATE finding_verifications SET status = 'cancelled', completed_at = NOW() "
                          "WHERE status IN ('scheduled','queued')")
    r = await client.post(f"/v1/remediation/{rid}/merged")
    assert r.json()["verification"]["purpose"] == "fix"
    assert (await client.post(f"/v1/remediation/{uuid.uuid4()}/merged")).status_code == 404


# =========================================================================== #
# integration events
# =========================================================================== #

def test_event_catalogue_has_the_verification_events():
    for t in ("finding.verified", "finding.fix_verified", "finding.fix_failed"):
        assert t in EVENT_TYPES


async def test_stream_events_map_to_integration_events(client, db_pool, fake_redis):
    from app.integrations import service as isvc

    await add_scope(db_pool)
    f = await mk_finding(client)
    v = (await verify(client, f["id"])).json()
    await post_result(client, v["id"], "confirmed", evidence={"excerpt": "SECRET-LOOKING-VALUE"})
    sid, fields = [x for x in await fake_redis.xrange("stream:events") if "finding_verified" in x[1]["event"]][0]
    ev = await isvc.event_from_stream(db_pool, fields, sid)
    assert ev.type == "finding.verified" and ev.title.startswith("Verified exploitable:")
    assert ev.data["verdict"] == "confirmed" and ev.data["check_id"] == "exposed_file"
    assert ev.data["finding_id"] == f["id"]
    assert "SECRET-LOOKING-VALUE" not in json.dumps(ev.as_dict())      # evidence never leaves Paddock
    again = await isvc.event_from_stream(db_pool, fields, sid)
    assert again.id == ev.id                                           # idempotent delivery key

    await mark_fixed(client, f["id"])
    row = (await ledger(db_pool, f["id"]))[-1]
    await post_result(client, str(row["id"]), "not_reproducible")
    sid, fields = [x for x in await fake_redis.xrange("stream:events") if "finding_fix_verified" in x[1]["event"]][0]
    ev = await isvc.event_from_stream(db_pool, fields, sid)
    assert ev.type == "finding.fix_verified" and ev.title.startswith("Fix verified:")
    from app.integrations.ocsf import event_to_ocsf

    assert event_to_ocsf(ev)["activity_id"] == 3                        # Close (the OCSF mapping exists)


async def test_failed_fix_event_type(client, db_pool, fake_redis):
    from app.integrations import service as isvc

    await add_scope(db_pool)
    f = await mk_finding(client)
    await mark_fixed(client, f["id"])
    row = (await ledger(db_pool, f["id"]))[-1]
    await post_result(client, str(row["id"]), "confirmed")
    sid, fields = [x for x in await fake_redis.xrange("stream:events") if "finding_fix_failed" in x[1]["event"]][0]
    ev = await isvc.event_from_stream(db_pool, fields, sid)
    assert ev.type == "finding.fix_failed" and ev.title.startswith("Fix did not hold:")


# =========================================================================== #
# the migration itself
# =========================================================================== #

async def test_schema_defaults(db_pool):
    async with db_pool.acquire() as con:
        aid = await con.fetchval("INSERT INTO assets (kind, value, canonical, source) "
                                 "VALUES ('subdomain', 'x.example.com', 'x.example.com', 't') RETURNING id")
        fid = await con.fetchval(
            "INSERT INTO findings (asset_id, rule_id, rule_source, severity, title, description) "
            "VALUES ($1, 'r', 'manual', 'low', 't', 'd') RETURNING id", aid)
        row = await con.fetchrow("SELECT exploitability, last_verified_at, fix_verified_at FROM findings WHERE id = $1", fid)
        assert (row["exploitability"], row["last_verified_at"], row["fix_verified_at"]) == ("unverified", None, None)
        with pytest.raises(asyncpg.CheckViolationError):
            await con.execute("UPDATE findings SET exploitability = 'maybe' WHERE id = $1", fid)
        with pytest.raises(asyncpg.CheckViolationError):
            await con.execute("INSERT INTO finding_verifications (finding_id, requested_by, status, verdict) "
                              "VALUES ($1, 't', 'queued', 'confirmed')", fid)      # verdict only on done rows
        await con.execute("INSERT INTO finding_verifications (finding_id, requested_by) VALUES ($1, 't')", fid)
        with pytest.raises(asyncpg.UniqueViolationError):                          # one in flight per purpose
            await con.execute("INSERT INTO finding_verifications (finding_id, requested_by) VALUES ($1, 't')", fid)


# =========================================================================== #
# only the dispatched job may answer (no forged "verified fix")
# =========================================================================== #

async def _fixed_with_pending_check(client, db_pool, status="queued"):
    await add_scope(db_pool)
    f = await mk_finding(client)
    await mark_fixed(client, f["id"])
    (row,) = await ledger(db_pool, f["id"])
    if status != row["status"]:
        async with db_pool.acquire() as con:
            await con.execute("UPDATE finding_verifications SET status = $2 WHERE id = $1", row["id"], status)
    return f, row


async def test_a_user_cannot_forge_a_verified_fix(client, db_pool):
    """An admin (dev principal here) posting not_reproducible must not stamp fix_verified_at."""
    f, row = await _fixed_with_pending_check(client, db_pool)
    r = await post_result(client, row["id"], "not_reproducible", service=False)
    assert r.status_code == 403, r.text
    assert (await get_finding(client, f["id"]))["fix_verified_at"] is None


async def test_result_needs_the_matching_scan_header(client, db_pool):
    f, row = await _fixed_with_pending_check(client, db_pool)
    for sid in (None, str(uuid.uuid4())):
        r = await post_result(client, row["id"], "not_reproducible", scan_id=sid)
        assert r.status_code in (403, 409), r.text
    assert (await get_finding(client, f["id"]))["fix_verified_at"] is None
    assert (await post_result(client, row["id"], "not_reproducible")).status_code == 200
    assert (await get_finding(client, f["id"]))["fix_verified_at"] is not None


async def test_result_for_a_scheduled_row_is_refused(client, db_pool):
    """A scheduled row has not been through the proof gate: no result may land on it."""
    f, row = await _fixed_with_pending_check(client, db_pool, status="scheduled")
    r = await post_result(client, row["id"], "not_reproducible", scan_id=str(row["scan_id"] or uuid.uuid4()))
    assert r.status_code in (403, 409), r.text
    assert (await get_finding(client, f["id"]))["fix_verified_at"] is None
