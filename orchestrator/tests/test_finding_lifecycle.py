"""Finding lifecycle (schema 019): transitions, expiry, suppression, dedupe,
SLA and explained priority. DB-backed through the real API.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone

import pytest

from app import auth as auth_svc
from app import lifecycle
from app.config import settings


@pytest.fixture(autouse=True)
def _reset_throttle():
    lifecycle.reset_sweep_throttle()
    yield
    lifecycle.reset_sweep_throttle()


def _future(days: int = 30) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


async def _post(client, *items):
    r = await client.post("/v1/findings/bulk", json={"items": list(items)})
    assert r.status_code == 200, r.text
    return r.json()


def _item(rule_id="r-1", source="manual", severity="high", asset="app.example.com",
          kind="subdomain", **extra):
    d = {
        "asset_value": asset, "asset_kind": kind, "rule_id": rule_id, "rule_source": source,
        "severity": severity, "title": f"{source} {rule_id}", "description": "d",
    }
    d.update(extra)
    return d


async def _one(client, **kw):
    body = await _post(client, _item(**kw))
    return body["items"][0]


async def _audit_rows(pool, resource_id):
    async with pool.acquire() as con:
        rows = await con.fetch(
            "SELECT actor, action, details FROM audit_log WHERE resource_id = $1 ORDER BY id",
            str(resource_id),
        )
    return [dict(r, details=json.loads(r["details"]) if isinstance(r["details"], str)
                 else r["details"]) for r in rows]


# =========================================================================== #
# Pure units
# =========================================================================== #

def test_vuln_keys_cve_ghsa_cwe_and_fallback():
    assert lifecycle.vuln_keys("nuclei", "CVE-2021-44228", {}, {}) == ["cve:CVE-2021-44228"]
    assert lifecycle.vuln_keys("sca", "sca:npm:lodash",
                               {"cve_ids": ["cve-2021-23337", "CVE-2020-8203"]}, {}) == [
        "cve:CVE-2020-8203", "cve:CVE-2021-23337"]
    assert lifecycle.vuln_keys("nuclei", "log4j-rce", {},
                               {"classification": {"cve-id": ["CVE-2021-44228"]}}) == [
        "cve:CVE-2021-44228"]
    assert lifecycle.vuln_keys("sca", "x", {"osv_ids": ["GHSA-jfh8-c2jp-5v3q"]}, {}) == [
        "ghsa:GHSA-jfh8-c2jp-5v3q"]
    assert lifecycle.vuln_keys("sast", "sast:sql-injection",
                               {"cwe": "CWE-89", "file": "app.py", "start_line": 12}, {}) == [
        "cwe:CWE-89@app.py:12"]
    # no stable identity -> per-engine fallback that never collapses across engines
    assert lifecycle.vuln_keys("header_check", "missing-hsts", {}, {}) == [
        "rule:header_check:missing-hsts"]


def test_asset_key_normalizes_hosts_but_not_lookalikes():
    a = lifecycle.asset_key("endpoint", "https://App.Example.com:8443/login?x=1")
    b = lifecycle.asset_key("subdomain", "app.example.com")
    c = lifecycle.asset_key("subdomain", "app.example.com.evil.io")
    assert a == b == "host:app.example.com"
    assert c != a
    assert lifecycle.asset_key("repository", "Org/Repo") == "repository:org/repo"
    assert lifecycle.asset_key("technology", "nginx", metadata={"host": "app.example.com"}) == a


def test_suppression_matching_is_and_and_glob():
    sup = {"rule_id": "sast:weak-*", "asset_pattern": "*.staging.example.com", "enabled": True}
    f = {"rule_id": "sast:weak-hash", "rule_source": "sast", "metadata": {}}
    assert lifecycle.suppression_matches(sup, f, {"value": "api.staging.example.com"})
    assert not lifecycle.suppression_matches(sup, f, {"value": "staging.example.com.evil.io"})
    assert not lifecycle.suppression_matches(
        sup, {**f, "rule_id": "sast:sql-injection"}, {"value": "api.staging.example.com"})
    assert lifecycle.suppression_matches({"tag": "lab"}, f, {"metadata": {"tags": ["Lab"]}})
    assert not lifecycle.suppression_matches({"tag": "lab"}, f, {"metadata": {"tags": []}})
    # an empty rule can never suppress everything
    assert not lifecycle.suppression_matches({"rule_source": "sast"}, f, {})
    past = datetime.now(timezone.utc) - timedelta(seconds=1)
    assert not lifecycle.suppression_active({"enabled": True, "expires_at": past})
    assert not lifecycle.suppression_active({"enabled": False, "expires_at": None})


def test_compute_due_and_breach():
    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert lifecycle.compute_due(t0, 24) == t0 + timedelta(hours=24)
    assert lifecycle.compute_due(t0, 0) is None  # info: no clock
    tk = t0 + timedelta(hours=5)
    assert lifecycle.compute_due(t0, 24, tk) == tk  # ticket's owner SLA wins
    now = t0 + timedelta(hours=25)
    assert lifecycle.is_breached("open", t0 + timedelta(hours=24), now)
    assert not lifecycle.is_breached("accepted", t0 + timedelta(hours=24), now)
    assert not lifecycle.is_breached("open", None, now)


def test_explain_priority_is_attributable_and_capped():
    score, why = lifecycle.explain_priority(
        severity="critical", cvss=9.8, epss=0.92, kev=True, internet_facing=True,
        path_distance=2, path_target="db.internal", engines=["nuclei", "cve_match", "sca"],
        owner="payments",
    )
    labels = [w.label for w in why]
    assert "KEV-listed" in labels and "EPSS 0.92" in labels and "internet-facing" in labels
    assert "2 hops from crown jewel db.internal" in labels
    assert "seen by 3 engines" in labels and "owner: payments" in labels
    assert score == 100  # capped
    assert [w.weight for w in why] == sorted([w.weight for w in why], reverse=True)
    low, low_why = lifecycle.explain_priority(severity="info")
    assert low == sum(w.weight for w in low_why) == 1


# =========================================================================== #
# Transitions
# =========================================================================== #

async def test_accept_requires_reason_and_records_history_and_audit(client, db_pool):
    f = await _one(client)
    for body in ({}, {"reason": ""}, {"reason": "   "}):
        r = await client.post(f"/v1/findings/{f['id']}/accept", json=body)
        assert r.status_code == 422, body
    r = await client.post(f"/v1/findings/{f['id']}/accept",
                          json={"reason": "compensating WAF rule", "accepted_until": _future()})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["from_status"] == "open" and out["to_status"] == "accepted"
    assert out["finding"]["status"] == "accepted"
    assert out["finding"]["status_reason"] == "compensating WAF rule"
    assert out["finding"]["accepted_until"] is not None
    detail = (await client.get(f"/v1/findings/{f['id']}")).json()
    assert detail["history"][0]["to_status"] == "accepted"
    assert detail["history"][0]["reason"] == "compensating WAF rule"
    rows = await _audit_rows(db_pool, f["id"])
    tr = [x for x in rows if x["details"].get("transition") == "accept"]
    assert tr and tr[0]["details"]["reason"] == "compensating WAF rule"


async def test_accept_expiry_must_be_future(client):
    f = await _one(client)
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    r = await client.post(f"/v1/findings/{f['id']}/accept",
                          json={"reason": "ok for now", "accepted_until": past})
    assert r.status_code == 422


async def test_false_positive_requires_reason_and_can_feed_suppression(client):
    f = await _one(client, rule_id="sast:weak-hash", source="sast", severity="medium")
    r = await client.post(f"/v1/findings/{f['id']}/false-positive", json={})
    assert r.status_code == 422
    r = await client.post(f"/v1/findings/{f['id']}/false-positive",
                          json={"reason": "md5 used for cache keys only", "suppress": True})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["to_status"] == "false_positive" and out["suppression_id"]
    sup = (await client.get(f"/v1/suppressions/{out['suppression_id']}")).json()
    assert sup["rule_id"] == "sast:weak-hash" and sup["asset_pattern"] == "app.example.com"
    assert sup["reason"] == "md5 used for cache keys only"
    # next ingest of the same noise is suppressed at ingest
    again = await _post(client, _item(rule_id="sast:weak-hash", source="sast", severity="medium"))
    assert again["suppressed"] == 1 and again["items"][0]["suppressed"] is True


async def test_reopen_and_illegal_transitions(client):
    f = await _one(client)
    r = await client.post(f"/v1/findings/{f['id']}/reopen", json={})
    assert r.status_code == 409  # already open
    await client.post(f"/v1/findings/{f['id']}/false-positive", json={"reason": "scanner bug"})
    r = await client.post(f"/v1/findings/{f['id']}/reopen", json={"reason": "reproduced by hand"})
    assert r.status_code == 200
    assert r.json()["finding"]["status"] == "open"
    assert r.json()["finding"]["accepted_until"] is None
    # fixed cannot be risk-accepted
    await client.patch(f"/v1/findings/{f['id']}", json={"status": "fixed"})
    r = await client.post(f"/v1/findings/{f['id']}/accept", json={"reason": "whatever"})
    assert r.status_code == 409
    r = await client.post("/v1/findings/00000000-0000-0000-0000-000000000000/accept",
                          json={"reason": "nope"})
    assert r.status_code == 404


async def test_patch_dismissal_needs_reason(client):
    f = await _one(client)
    r = await client.patch(f"/v1/findings/{f['id']}", json={"status": "false_positive"})
    assert r.status_code == 422
    r = await client.patch(f"/v1/findings/{f['id']}",
                           json={"status": "accepted", "notes": "accepted by CISO"})
    assert r.status_code == 200
    assert r.json()["status"] == "accepted" and r.json()["status_reason"] == "accepted by CISO"
    # legacy statuses keep working without a reason
    r = await client.patch(f"/v1/findings/{f['id']}", json={"status": "triaged"})
    assert r.status_code == 200 and r.json()["status"] == "triaged"


async def test_db_constraint_refuses_reasonless_dismissal(db_pool, client):
    f = await _one(client)
    import asyncpg

    async with db_pool.acquire() as con:
        with pytest.raises(asyncpg.CheckViolationError):
            await con.execute("UPDATE findings SET status='accepted' WHERE id=$1::uuid", f["id"])


# =========================================================================== #
# Expiry
# =========================================================================== #

async def _expire(db_pool, fid):
    async with db_pool.acquire() as con:
        await con.execute(
            "UPDATE findings SET accepted_until = NOW() - INTERVAL '1 minute' WHERE id = $1::uuid",
            fid,
        )


async def test_expired_acceptance_reopens_via_sweep(client, db_pool):
    f = await _one(client)
    await client.post(f"/v1/findings/{f['id']}/accept",
                      json={"reason": "until patch window", "accepted_until": _future(1)})
    res = await lifecycle.sweep_expired(db_pool)
    assert res["reopened"] == 0  # not yet expired
    await _expire(db_pool, f["id"])
    res = await lifecycle.sweep_expired(db_pool)
    assert res["reopened"] == 1
    d = (await client.get(f"/v1/findings/{f['id']}")).json()
    assert d["finding"]["status"] == "open"
    assert d["finding"]["status_reason"].startswith("auto-reopened")
    assert d["history"][0]["actor"] == lifecycle.SYSTEM_ACTOR
    rows = await _audit_rows(db_pool, f["id"])
    assert any(x["details"].get("transition") == "auto_reopen" for x in rows)
    assert (await lifecycle.sweep_expired(db_pool))["reopened"] == 0  # idempotent


async def test_expired_false_positive_reopens_on_read(client, db_pool):
    f = await _one(client)
    await client.post(f"/v1/findings/{f['id']}/false-positive",
                      json={"reason": "re-check next quarter", "accepted_until": _future(1)})
    await _expire(db_pool, f["id"])
    lifecycle.reset_sweep_throttle()
    page = (await client.get("/v1/findings")).json()
    assert [x["status"] for x in page["items"] if x["id"] == f["id"]] == ["open"]


async def test_scheduler_loop_runs_the_sweep(client, db_pool, fake_redis, monkeypatch):
    from app import scheduler

    f = await _one(client)
    await client.post(f"/v1/findings/{f['id']}/accept",
                      json={"reason": "short", "accepted_until": _future(1)})
    await _expire(db_pool, f["id"])
    monkeypatch.setattr(settings, "scheduler_interval_sec", 0)

    class _App:
        class state:  # noqa: N801
            pool = db_pool
            redis = fake_redis

    task = asyncio.create_task(scheduler.scheduler_loop(_App))
    try:
        for _ in range(100):
            async with db_pool.acquire() as con:
                st = await con.fetchval("SELECT status FROM findings WHERE id=$1::uuid", f["id"])
            if st == "open":
                break
            await asyncio.sleep(0.05)
        assert st == "open"
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task


# =========================================================================== #
# Suppression at ingest
# =========================================================================== #

async def test_suppression_at_ingest_hidden_but_countable(client, fake_redis):
    r = await client.post("/v1/suppressions", json={
        "rule_id": "sast:weak-*", "asset_pattern": "*.staging.example.com",
        "reason": "staging uses test crypto", "expires_at": _future(),
    })
    assert r.status_code == 201, r.text
    sid = r.json()["id"]
    assert r.json()["author"] and r.json()["active"] is True
    body = await _post(
        client,
        _item(rule_id="sast:weak-hash", source="sast", asset="api.staging.example.com"),
        # look-alike host: must NOT be suppressed
        _item(rule_id="sast:weak-hash", source="sast", asset="staging.example.com.evil.io"),
        _item(rule_id="sast:sql-injection", source="sast", asset="api.staging.example.com"),
    )
    assert body["inserted"] == 3 and body["suppressed"] == 1
    page = (await client.get("/v1/findings")).json()
    assert page["total"] == 2 and page["suppressed_total"] == 1
    only = (await client.get("/v1/findings", params={"suppressed": "only"})).json()
    assert [x["asset_value"] for x in only["items"]] == ["api.staging.example.com"]
    assert only["items"][0]["suppressed"] is True and only["items"][0]["suppressed_by"] == sid
    assert (await client.get("/v1/findings", params={"suppressed": "include"})).json()["total"] == 3
    sup = (await client.get(f"/v1/suppressions/{sid}")).json()
    assert sup["match_count"] == 1 and sup["suppressed_now"] == 1
    events = await fake_redis.xrange(settings.events_stream)
    kinds = [json.loads(e[1]["event"])["event"] for e in events]
    assert kinds.count("finding_suppressed") == 1 and kinds.count("finding_opened") == 2


async def test_suppression_by_tag_retroactive_and_release(client, db_pool):
    async with db_pool.acquire() as con:
        await con.execute(
            "INSERT INTO assets (kind, value, canonical, source, metadata) "
            "VALUES ('subdomain','lab1.example.com','lab1.example.com','t','{\"tags\":[\"lab\"]}')"
        )
    f = await _one(client, asset="lab1.example.com")
    r = await client.post("/v1/suppressions", json={"tag": "lab", "reason": "lab gear, no data"})
    sid = r.json()["id"]
    assert r.json()["suppressed_now"] == 1  # applied to the already-stored finding
    assert (await client.get("/v1/findings")).json()["total"] == 0
    # disable -> released
    r = await client.patch(f"/v1/suppressions/{sid}", json={"enabled": False})
    assert r.status_code == 200 and r.json()["active"] is False
    page = (await client.get("/v1/findings")).json()
    assert [x["id"] for x in page["items"]] == [f["id"]]
    # re-enable re-applies; delete releases
    await client.patch(f"/v1/suppressions/{sid}", json={"enabled": True})
    assert (await client.get("/v1/findings")).json()["total"] == 0
    assert (await client.delete(f"/v1/suppressions/{sid}")).status_code == 204
    assert (await client.get("/v1/findings")).json()["total"] == 1
    assert (await client.get(f"/v1/suppressions/{sid}")).status_code == 404


async def test_suppression_validation_and_expiry(client, db_pool):
    r = await client.post("/v1/suppressions", json={"reason": "nothing to match"})
    assert r.status_code == 422
    r = await client.post("/v1/suppressions", json={"rule_id": "x", "reason": ""})
    assert r.status_code == 422
    r = await client.post("/v1/suppressions", json={"rule_id": "r-1", "reason": "temporary",
                                                    "expires_at": _future(1)})
    sid = r.json()["id"]
    await _one(client)
    assert (await client.get("/v1/findings")).json()["suppressed_total"] == 1
    async with db_pool.acquire() as con:
        await con.execute(
            "UPDATE finding_suppressions SET expires_at = NOW() - INTERVAL '1 s' WHERE id=$1::uuid",
            sid,
        )
    res = await lifecycle.sweep_expired(db_pool)
    assert res["released"] == 1
    page = (await client.get("/v1/findings")).json()
    assert page["total"] == 1 and page["suppressed_total"] == 0
    assert (await client.get("/v1/suppressions", params={"active": False})).json()[0]["id"] == sid


# =========================================================================== #
# Cross-engine dedupe
# =========================================================================== #

LOG4J = "CVE-2021-44228"


async def _three_engines(client):
    return await _post(
        client,
        _item(rule_id=LOG4J, source="nuclei", severity="critical",
              asset="https://app.example.com/login", kind="endpoint",
              evidence={"cve_ids": [LOG4J]}),
        _item(rule_id=LOG4J, source="cve_match", severity="critical", asset="app.example.com",
              kind="subdomain", epss=0.97),
        _item(rule_id="sca:Maven:log4j-core", source="sca", severity="critical",
              asset="org/app", kind="repository",
              evidence={"cve_ids": [LOG4J, "CVE-2021-45046"]},
              metadata={"host": "app.example.com"}),
    )


async def test_dedupe_collapses_three_engines_into_one_primary(client):
    body = await _three_engines(client)
    assert body["inserted"] == 3 and body["duplicates"] == 2
    primary = body["items"][0]
    assert primary["duplicate_of"] is None
    assert all(x["duplicate_of"] == primary["id"] for x in body["items"][1:])
    page = (await client.get("/v1/findings")).json()
    assert page["total"] == 1 and page["duplicates_total"] == 2
    item = page["items"][0]
    assert item["id"] == primary["id"] and item["source_count"] == 3
    assert sorted(s["rule_source"] for s in item["sources"]) == ["cve_match", "nuclei", "sca"]
    assert "seen by 3 engines" in [w["label"] for w in item["why"]]
    assert "EPSS 0.97" in [w["label"] for w in item["why"]]  # taken from the duplicate's CVE
    allp = (await client.get("/v1/findings", params={"include_duplicates": True})).json()
    assert allp["total"] == 3
    # the fingerprint is stable and queryable
    same = (await client.get("/v1/findings", params={
        "fingerprint": item["fingerprint"], "include_duplicates": True})).json()
    assert same["total"] >= 2
    # re-ingest keeps the collapse (idempotent)
    again = await _three_engines(client)
    assert again["inserted"] == 0 and again["duplicates"] == 2


async def test_dedupe_transition_propagates_to_duplicates(client):
    body = await _three_engines(client)
    pid = body["items"][0]["id"]
    r = await client.post(f"/v1/findings/{pid}/accept", json={"reason": "isolated segment"})
    assert r.json()["propagated_to"] == 2
    allp = (await client.get("/v1/findings", params={"include_duplicates": True})).json()
    assert {x["status"] for x in allp["items"]} == {"accepted"}


async def test_dedupe_does_not_collapse_lookalikes(client):
    body = await _post(
        client,
        _item(rule_id=LOG4J, source="cve_match", asset="app.example.com"),
        _item(rule_id=LOG4J, source="nuclei", asset="app.example.com.evil.io"),  # other host
        _item(rule_id="CVE-2021-45046", source="nuclei", asset="app.example.com"),  # other CVE
        _item(rule_id="sast:sql-injection", source="sast", asset="org/app", kind="repository",
              evidence={"cwe": "CWE-89", "file": "app.py", "start_line": 10}),
        _item(rule_id="sast:sql-injection-2", source="sast", asset="org/app", kind="repository",
              evidence={"cwe": "CWE-89", "file": "app.py", "start_line": 99}),  # other line
        _item(rule_id="missing-hsts", source="header_check", asset="app.example.com"),
        _item(rule_id="missing-hsts", source="nuclei", asset="app.example.com"),  # no stable id
    )
    assert body["duplicates"] == 0
    assert (await client.get("/v1/findings")).json()["total"] == 7


async def test_dedupe_cwe_location_collapses_semgrep_and_fallback(client):
    ev = {"cwe": "CWE-89", "file": "app.py", "start_line": 10}
    body = await _post(
        client,
        _item(rule_id="sast:sql-injection", source="sast", asset="org/app", kind="repository",
              evidence={**ev, "engine": "taint_fallback"}),
        _item(rule_id="sast:python.django.sqli", source="sast", asset="org/app",
              kind="repository", evidence={**ev, "engine": "semgrep"}),
    )
    assert body["duplicates"] == 1


async def test_backfill_identity_for_directly_inserted_rows(client, db_pool):
    async with db_pool.acquire() as con:
        aid = await con.fetchval(
            "INSERT INTO assets (kind, value, canonical, source) "
            "VALUES ('subdomain','old.example.com','old.example.com','t') RETURNING id")
        for src in ("nuclei", "cve_match"):
            await con.execute(
                "INSERT INTO findings (asset_id, rule_id, rule_source, severity, title, description)"
                " VALUES ($1, $2, $3, 'high', 't', 'd')", aid, LOG4J, src)
    assert (await client.get("/v1/findings")).json()["total"] == 2
    r = await client.post("/v1/findings/recompute-identity")
    assert r.json() == {"stamped": 2, "collapsed": 1}
    assert (await client.get("/v1/findings")).json()["total"] == 1


# =========================================================================== #
# SLA
# =========================================================================== #

async def _age(db_pool, fid, hours):
    async with db_pool.acquire() as con:
        await con.execute(
            "UPDATE findings SET first_seen = NOW() - make_interval(hours => $2) WHERE id=$1::uuid",
            fid, hours,
        )


async def test_sla_due_and_breach_from_policies(client, db_pool):
    crit = await _one(client, rule_id="c", severity="critical")
    info = await _one(client, rule_id="i", severity="info")
    await _age(db_pool, crit["id"], 30)
    d = (await client.get(f"/v1/findings/{crit['id']}")).json()["finding"]
    first = datetime.fromisoformat(d["first_seen"])
    assert datetime.fromisoformat(d["due_at"]) == first + timedelta(hours=24)
    assert d["sla_hours"] == 24 and d["sla_breached"] is True
    assert "SLA breached" in [w["label"] for w in d["why"]]
    di = (await client.get(f"/v1/findings/{info['id']}")).json()["finding"]
    assert di["due_at"] is None and di["sla_breached"] is False  # info: 0h = no clock
    breached = (await client.get("/v1/findings", params={"sla_breached": True})).json()
    assert [x["id"] for x in breached["items"]] == [crit["id"]]
    # editing the policy re-dates the finding
    r = await client.patch("/v1/sla-policies/critical", json={"hours": 48})
    assert r.status_code == 200, r.text
    d = (await client.get(f"/v1/findings/{crit['id']}")).json()["finding"]
    assert d["sla_breached"] is False
    # dismissed findings never breach
    await _age(db_pool, crit["id"], 100)
    await client.post(f"/v1/findings/{crit['id']}/accept", json={"reason": "accepted"})
    d = (await client.get(f"/v1/findings/{crit['id']}")).json()["finding"]
    assert d["due_at"] is not None and d["sla_breached"] is False


async def test_sla_ticket_due_overrides_policy(client, db_pool):
    f = await _one(client, severity="low")
    due = datetime.now(timezone.utc) - timedelta(hours=1)
    async with db_pool.acquire() as con:
        await con.execute(
            "INSERT INTO tickets (finding_id, title, severity, owner_team, sla_due) "
            "VALUES ($1::uuid, 't', 'low', 'payments', $2)", f["id"], due)
    d = (await client.get(f"/v1/findings/{f['id']}")).json()["finding"]
    assert abs(datetime.fromisoformat(d["due_at"]) - due) < timedelta(seconds=1)
    assert d["sla_breached"] is True and d["owner"] == "payments"


# =========================================================================== #
# Explained priority
# =========================================================================== #

async def test_why_and_priority_from_real_context(client, db_pool):
    async with db_pool.acquire() as con:
        edge = await con.fetchval(
            "INSERT INTO assets (kind, value, canonical, source, metadata) VALUES "
            "('subdomain','pay.example.com','pay.example.com','t','{\"public\": true}') RETURNING id")
        mid = await con.fetchval(
            "INSERT INTO assets (kind, value, canonical, source) VALUES "
            "('ipv4','10.0.0.5','10.0.0.5','t') RETURNING id")
        db = await con.fetchval(
            "INSERT INTO assets (kind, value, canonical, source, metadata) VALUES "
            "('service','payments-db','payments-db','t','{\"crown_jewel\": true}') RETURNING id")
        hops = [{"asset_id": str(a)} for a in (edge, mid, db)]
        await con.execute(
            "INSERT INTO attack_paths (source_asset_id, target_asset_id, hops, length, total_cost,"
            " exploitability, severity, title, fingerprint) VALUES ($1,$2,$3::jsonb,2,3,80,"
            "'critical','pay -> db','fp1')", edge, db, json.dumps(hops))
        await con.execute(
            "INSERT INTO asset_owners (name, match, team, priority) VALUES "
            "('pay', '{\"value_regex\": \"^pay\\\\.\"}', 'payments', 10)")
        await con.execute(
            "INSERT INTO cves (id, known_exploited, epss) VALUES ($1, TRUE, 0.92)", LOG4J)
    body = await _post(client, _item(rule_id=LOG4J, source="cve_match", severity="critical",
                                     asset="pay.example.com", cvss=10.0))
    fid = body["items"][0]["id"]
    d = (await client.get(f"/v1/findings/{fid}")).json()["finding"]
    labels = [w["label"] for w in d["why"]]
    assert "KEV-listed" in labels and "EPSS 0.92" in labels and "internet-facing" in labels
    assert "2 hops from crown jewel payments-db" in labels
    assert "owner: payments" in labels and d["owner"] == "payments"
    assert d["kev"] is True
    assert d["priority_score"] == min(100, sum(w["weight"] for w in d["why"]))
    assert d["priority_score"] == 100
    # the crown jewel's own finding says so
    async with db_pool.acquire() as con:
        await con.execute(
            "INSERT INTO findings (asset_id, rule_id, rule_source, severity, title, description)"
            " VALUES ($1, 'weak-auth', 'manual', 'low', 't', 'd')", db)
    page = (await client.get("/v1/findings", params={"rule_source": "manual"})).json()
    jw = [w["label"] for w in page["items"][0]["why"]]
    assert "is crown jewel payments-db" in jw
    # a plain low finding scores low
    low = await _one(client, rule_id="low-1", severity="low", asset="quiet.example.com")
    dl = (await client.get(f"/v1/findings/{low['id']}")).json()["finding"]
    assert dl["priority_score"] < 20


# =========================================================================== #
# Back-compat + RBAC
# =========================================================================== #

async def test_legacy_shapes_still_served(client):
    f = await _one(client)
    legacy = (await client.get("/v1/findings/list")).json()
    assert isinstance(legacy, list) and legacy[0]["id"] == f["id"]
    d = (await client.get(f"/v1/findings/{f['id']}")).json()
    assert set(d) >= {"finding", "asset", "chains"}
    for key in ("id", "asset_id", "rule_id", "rule_source", "severity", "status", "metadata"):
        assert key in d["finding"]


@pytest.fixture
def enforce():
    prev = settings.auth_mode
    settings.auth_mode = "enforce"
    try:
        yield
    finally:
        settings.auth_mode = prev


async def _key_for(pool, username, role):
    full, prefix, key_hash = auth_svc.generate_api_key()
    async with pool.acquire() as con:
        uid = await con.fetchval(
            "INSERT INTO app_users (username, role, clearance) VALUES ($1,$2,'internal') "
            "RETURNING id", username, role)
        await con.execute(
            "INSERT INTO api_keys (user_id, name, prefix, key_hash, scopes) "
            "VALUES ($1,$2,$3,$4,$5::text[])", uid, f"k-{prefix}", prefix, key_hash,
            sorted(auth_svc.ROLE_CAPABILITIES[role]))
    return {"Authorization": f"Bearer {full}"}


async def test_rbac_triage_capability_required(client, db_pool, enforce):
    assert auth_svc.required_capability("POST", "/v1/findings/abc/accept") == "triage"
    assert auth_svc.required_capability("POST", "/v1/findings/abc/false-positive") == "triage"
    assert auth_svc.required_capability("POST", "/v1/findings/abc/reopen") == "triage"
    assert auth_svc.required_capability("POST", "/v1/suppressions") == "triage"
    assert auth_svc.required_capability("DELETE", "/v1/suppressions/x") == "triage"
    assert auth_svc.required_capability("GET", "/v1/suppressions") == "read"
    assert auth_svc.required_capability("POST", "/v1/findings/recompute-identity") == "admin"
    svc = await _key_for(db_pool, "admin1", "admin")
    viewer = await _key_for(db_pool, "viewer1", "viewer")
    analyst = await _key_for(db_pool, "analyst1", "analyst")
    r = await client.post("/v1/findings/bulk", json={"items": [_item()]}, headers=svc)
    fid = r.json()["items"][0]["id"]
    r = await client.post(f"/v1/findings/{fid}/accept", json={"reason": "x-y-z"}, headers=viewer)
    assert r.status_code == 403
    r = await client.post("/v1/suppressions", json={"rule_id": "x", "reason": "noise"},
                          headers=viewer)
    assert r.status_code == 403
    r = await client.post(f"/v1/findings/{fid}/accept", json={"reason": "x-y-z"}, headers=analyst)
    assert r.status_code == 200
    rows = await _audit_rows(db_pool, fid)
    assert any(x["actor"] == "analyst1" and x["details"].get("transition") == "accept"
               for x in rows)
    assert any(x["action"] == "deny" for x in await _audit_rows(db_pool, fid))
