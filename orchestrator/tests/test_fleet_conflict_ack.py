"""P2.1 section 4.6 (WP4): acknowledging the scan conflict ``agent_closed_scan_open``, against the real database.

An acknowledgement clears ONE conflict record for coverage purposes and nothing else (D30): it binds
``(agent, proto, port)`` and the observation the operator looked at (a blind pre-acknowledgement is impossible), it
expires (default 168 h, at most 720 h), a LATER observation re-raises the conflict, only ``agent_closed_scan_open``
can be acknowledged, and every acknowledgement is disclosed in the facts, the coverage detail and the audit chain.
"""
from __future__ import annotations

import datetime as dt
import json
import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app import fleet_enroll as fe
from app import fleet_posture as fp
from app import tenancy
from app.assurance.builders import host_fw as hf
from app.config import settings

from .p2_support import hdr, seed_key
from .test_assurance_host_fw_db import _persist_scan_edge, conn_for, healthy, load_build, now_, persist, post, seed_host
from .test_fleet_pairing import audits, seed_asset

A = tenancy.DEFAULT_TENANT_ID
B = "00000000-0000-0000-0000-0000000000ba"
MIN = dt.timedelta(minutes=1)
H = dt.timedelta(hours=1)
WHY = "the scan hit the old load balancer, host firewall verified by hand"


@pytest.fixture(autouse=True)
def _fresh_limiters():
    fe.reset_limiters()
    fp.reset_limiters()
    yield
    fe.reset_limiters()
    fp.reset_limiters()


@pytest_asyncio.fixture
async def http(app_pool, fake_redis):
    from .conftest import _build_app
    app = _build_app(app_pool, fake_redis)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


class W:
    """One host whose firewall denies 8080 while the external scan saw it open."""


async def rebuild(app_pool, *, now=None):
    now = now or now_() + 10 * dt.timedelta(seconds=1)
    rows, out = await load_build(app_pool, now=now)
    await persist(app_pool, out, now)
    return rows, out


async def world(app_pool, port=8080, *, seen=None):
    w = W()
    w.h = await seed_host(app_pool)
    w.t = now_() - 5 * MIN
    await post(app_pool, w.h, healthy(collected=w.t - 2 * MIN, seq=1, ips=["10.0.0.5"]), now=w.t - 2 * MIN)
    w.seen = seen or w.t
    await _persist_scan_edge(app_pool, "ip:10.0.0.5", port, w.seen)
    w.now = now_() + 10 * dt.timedelta(seconds=1)
    await rebuild(app_pool, now=w.now)
    return w


def iso(t):
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ack_body(w, port=8080, proto="tcp", **kw):
    return {"proto": proto, "port": port, "scan_seen_at": iso(w.seen), "justification": WHY, **kw}


async def post_ack(http, w, **kw):
    return await http.post(f"/v1/fleet/agents/{w.h.id}/conflicts/acks", json=ack_body(w, **kw))


async def acks(db, agent_id=None):
    rows = await db.fetch("SELECT * FROM fleet_conflict_acks ORDER BY acked_at, id")
    return [dict(r) for r in rows if agent_id is None or r["agent_id"] == agent_id]


async def fact_row(db):
    r = await db.fetchrow("SELECT facts FROM reach_node_facts WHERE source = 'host_fw'")
    return None if r is None else (json.loads(r["facts"]) if isinstance(r["facts"], str) else r["facts"])


async def coverage(db):
    return [dict(r) for r in await db.fetch("SELECT node_ref, detail FROM reach_coverage WHERE source = 'host_fw'")]


# --------------------------------------------------------------------------- #
# GET conflicts
# --------------------------------------------------------------------------- #

async def test_get_conflicts_lists_the_current_conflict_with_when_it_was_true(http, app_pool, db_pool):
    w = await world(app_pool)
    r = await http.get(f"/v1/fleet/agents/{w.h.id}/conflicts")
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["agent_id"] == str(w.h.id) and out["node_ref"] == f"agent:{w.h.id}"
    assert out["as_of"] is not None and "graph_built_at" in out
    assert out["conflicts"] == [{"kind": "agent_closed_scan_open", "proto": "tcp", "port": 8080,
                                 "scan_seen_at": iso(w.seen), "ackable": True, "ack": None}]
    assert (await http.get(f"/v1/fleet/agents/{uuid.uuid4()}/conflicts")).json() == {"detail": "agent not found"}


async def test_get_conflicts_is_empty_without_facts_or_conflicts(http, app_pool, db_pool):
    h = await seed_host(app_pool)
    r = await http.get(f"/v1/fleet/agents/{h.id}/conflicts")
    assert r.status_code == 200 and r.json()["conflicts"] == [] and r.json()["as_of"] is None


async def test_get_conflicts_reads_the_fact_of_the_agent_not_of_another_node(http, app_pool, db_pool):
    w = await world(app_pool)
    other = await seed_host(app_pool, 2)
    r = await http.get(f"/v1/fleet/agents/{other.id}/conflicts")
    assert r.status_code == 200 and r.json()["conflicts"] == []


# --------------------------------------------------------------------------- #
# POST
# --------------------------------------------------------------------------- #

async def test_an_ack_restores_coverage_is_disclosed_everywhere_and_is_audited(http, app_pool, db_pool):
    w = await world(app_pool)
    assert await coverage(db_pool) == []
    r = await post_ack(http, w)
    assert r.status_code == 201, r.text
    out = r.json()
    assert out["status"] == "active" and out["kind"] == "agent_closed_scan_open" and out["proto"] == "tcp"
    assert out["port"] == 8080 and out["through_seen_at"] == iso(w.seen) and out["acked_by"] == "dev-admin"
    assert out["justification"] == WHY and out["cleared_by"] is None and out["cleared_reason"] == ""
    exp = dt.datetime.fromisoformat(out["expires_at"].replace("Z", "+00:00"))
    assert dt.timedelta(hours=167, minutes=59) < exp - dt.datetime.now(dt.timezone.utc) <= dt.timedelta(hours=168)
    (row,) = await acks(db_pool)
    ev = json.loads(row["evidence"]) if isinstance(row["evidence"], str) else row["evidence"]
    assert row["status"] == "active" and ev["kind"] == "agent_closed_scan_open" and ev["port"] == 8080
    (aud,) = await audits(db_pool, "fleet.conflict.ack", w.h.id)
    assert aud["justification"] == WHY and aud["details"]["port"] == 8080 and aud["details"]["proto"] == "tcp"
    assert aud["details"]["ack_id"] == out["id"] and aud["details"]["scan_seen_at"] == iso(w.seen)
    assert aud["details"]["conflict"]["kind"] == "agent_closed_scan_open" and aud["details"]["ttl_hours"] == 168
    assert await db_pool.fetchval("SELECT count(*) FROM assurance_state WHERE last_build_at IS NULL") == 1
    # the next build: coverage is back and the ack is disclosed in the facts and in the coverage detail
    await rebuild(app_pool, now=w.now + MIN)
    (cov,) = await coverage(db_pool)
    detail = json.loads(cov["detail"]) if isinstance(cov["detail"], str) else cov["detail"]
    assert cov["node_ref"] == f"agent:{w.h.id}" and detail["acknowledged_conflicts"] == 1
    data = (await fact_row(db_pool))["host_agent"]["data"]
    assert data["conflicts"] == [] and data["conflicts_acknowledged"][0]["ack_id"] == out["id"]
    assert data["conflicts_acknowledged"][0]["acked_by"] == "dev-admin"
    g = (await http.get(f"/v1/fleet/agents/{w.h.id}/conflicts")).json()
    assert g["conflicts"][0]["ack"]["id"] == out["id"] and g["conflicts"][0]["ack"]["status"] == "active"
    assert g["conflicts"][0]["ackable"] is True


async def test_a_later_observation_is_not_covered_and_re_raises_the_conflict(http, app_pool, db_pool):
    w = await world(app_pool)
    assert (await post_ack(http, w)).status_code == 201
    await rebuild(app_pool, now=w.now + MIN)
    assert len(await coverage(db_pool)) == 1
    later = w.seen + 2 * MIN
    await _persist_scan_edge(app_pool, "ip:10.0.0.5", 8080, later)
    await rebuild(app_pool, now=w.now + 3 * MIN)
    assert await coverage(db_pool) == []                                      # re-raised: the old ack does not cover it
    g = (await http.get(f"/v1/fleet/agents/{w.h.id}/conflicts")).json()
    assert g["conflicts"] == [{"kind": "agent_closed_scan_open", "proto": "tcp", "port": 8080,
                               "scan_seen_at": iso(later), "ackable": True, "ack": None}]
    # the operator can acknowledge the NEW observation; the old row is superseded, never two active
    r = await http.post(f"/v1/fleet/agents/{w.h.id}/conflicts/acks",
                        json={**ack_body(w), "scan_seen_at": iso(later)})
    assert r.status_code == 201
    assert sorted(a["status"] for a in await acks(db_pool)) == ["active", "superseded"]
    await rebuild(app_pool, now=w.now + 4 * MIN)
    assert len(await coverage(db_pool)) == 1


async def test_a_re_ack_of_the_same_observation_supersedes_the_previous_row(http, app_pool, db_pool):
    w = await world(app_pool)
    first = (await post_ack(http, w)).json()
    second = (await post_ack(http, w, ttl_hours=24, justification="extended after the second review")).json()
    rows = {a["id"]: a for a in await acks(db_pool)}
    assert rows[uuid.UUID(first["id"])]["status"] == "superseded" and rows[uuid.UUID(first["id"])]["cleared_reason"] == "superseded"
    assert rows[uuid.UUID(second["id"])]["status"] == "active"
    assert sum(1 for a in rows.values() if a["status"] == "active") == 1
    assert len(await audits(db_pool, "fleet.conflict.ack", w.h.id)) == 2


async def test_an_ack_cannot_be_blind_it_must_echo_the_observation_shown(http, app_pool, db_pool):
    w = await world(app_pool)
    for seen in (w.seen - 10 * MIN, w.seen + 10 * MIN, w.seen + dt.timedelta(days=30)):
        r = await http.post(f"/v1/fleet/agents/{w.h.id}/conflicts/acks", json={**ack_body(w), "scan_seen_at": iso(seen)})
        assert r.status_code == 409 and r.json()["reason"] == "conflict_changed", (seen, r.text)
        assert r.json()["scan_seen_at"] == iso(w.seen)                    # the observation that IS current
    r = await post_ack(http, w, port=9999)                                # nothing observed there: no pre-ack
    assert r.status_code == 409 and r.json()["reason"] == "no_such_conflict"
    r = await post_ack(http, w, proto="udp")
    assert r.status_code == 409 and r.json()["reason"] == "no_such_conflict"
    assert await acks(db_pool) == []


async def test_no_conflict_at_all_means_no_ack(http, app_pool, db_pool):
    h = await seed_host(app_pool)
    r = await http.post(f"/v1/fleet/agents/{h.id}/conflicts/acks",
                        json={"proto": "tcp", "port": 22, "scan_seen_at": iso(now_()), "justification": WHY})
    assert r.status_code == 409 and r.json()["reason"] == "no_such_conflict"


@pytest.mark.parametrize("kind", ["agent_scan_check_budget_exceeded", "paired_peer_mismatch", "anything_else"])
async def test_only_agent_closed_scan_open_is_acknowledgeable(http, app_pool, db_pool, kind):
    w = await world(app_pool)
    r = await post_ack(http, w, kind=kind)
    assert r.status_code == 422 and r.json()["reason"] == "not_ackable", r.text
    assert await acks(db_pool) == []


@pytest.mark.parametrize("payload", [
    {"justification": "too short"}, {"justification": " " * 20}, {"justification": "x" * 1001},
    {"ttl_hours": 0}, {"ttl_hours": 721}, {"ttl_hours": -1}, {"ttl_hours": 1.5},
    {"port": 0}, {"port": 65536}, {"proto": "any"}, {"proto": "sctp"}, {"scan_seen_at": "yesterday"},
    {"extra": True},
])
async def test_the_body_is_strict(http, app_pool, db_pool, payload):
    w = await world(app_pool)
    r = await post_ack(http, w, **payload)
    assert r.status_code == 422, (payload, r.text)
    assert await acks(db_pool) == []


async def test_the_ttl_is_bounded_by_the_setting_and_720_hours_is_the_most(http, app_pool, db_pool, monkeypatch):
    w = await world(app_pool)
    r = await post_ack(http, w, ttl_hours=720)
    assert r.status_code == 201
    exp = dt.datetime.fromisoformat(r.json()["expires_at"].replace("Z", "+00:00"))
    assert exp - dt.datetime.now(dt.timezone.utc) <= dt.timedelta(hours=720)
    monkeypatch.setattr(settings, "assurance_conflict_ack_max_h", 48)
    r = await post_ack(http, w, ttl_hours=49)
    assert r.status_code == 422 and r.json()["reason"] == "ttl_exceeds_limit"
    assert (await post_ack(http, w, ttl_hours=48)).status_code == 201


async def test_a_revoked_or_legacy_agent_cannot_be_acked(http, app_pool, db_pool):
    w = await world(app_pool)
    await db_pool.execute("UPDATE fleet_agents SET legacy = TRUE WHERE id = $1", w.h.id)
    r = await post_ack(http, w)
    assert r.status_code == 409 and r.json()["reason"] == "agent_not_live"
    assert (await http.post(f"/v1/fleet/agents/{uuid.uuid4()}/conflicts/acks", json=ack_body(w))).status_code == 404


# --------------------------------------------------------------------------- #
# DELETE
# --------------------------------------------------------------------------- #

async def test_delete_clears_the_ack_at_once_and_the_conflict_is_back_at_the_next_build(http, app_pool, db_pool):
    w = await world(app_pool)
    ack = (await post_ack(http, w)).json()
    path = f"/v1/fleet/agents/{w.h.id}/conflicts/acks/{ack['id']}"
    assert (await http.delete(path)).status_code == 422                       # the justification is required
    assert (await http.delete(path, params={"justification": "no"})).status_code == 422
    r = await http.delete(path, params={"justification": "the firewall was not verified after all"})
    assert r.status_code == 200 and r.json()["status"] == "cleared" and r.json()["cleared_by"] == "dev-admin"
    assert r.json()["cleared_reason"] == "the firewall was not verified after all" and r.json()["cleared_at"]
    (aud,) = await audits(db_pool, "fleet.conflict.ack_clear", w.h.id)
    assert aud["details"]["ack_id"] == ack["id"] and aud["justification"] == "the firewall was not verified after all"
    assert aud["details"]["port"] == 8080
    r = await http.delete(path, params={"justification": "second time"})
    assert r.status_code == 404 and r.json() == {"detail": "ack not found"}
    await rebuild(app_pool, now=w.now + MIN)
    assert await coverage(db_pool) == []


async def test_a_foreign_or_unknown_ack_id_is_a_plain_404(http, app_pool, db_pool):
    w = await world(app_pool)
    other = await seed_host(app_pool, 2)
    ack = (await post_ack(http, w)).json()
    for agent, aid in ((other.id, ack["id"]), (w.h.id, str(uuid.uuid4()))):
        r = await http.delete(f"/v1/fleet/agents/{agent}/conflicts/acks/{aid}", params={"justification": "some reason"})
        assert r.status_code == 404 and r.json() == {"detail": "ack not found"}
    assert (await acks(db_pool))[0]["status"] == "active"


# --------------------------------------------------------------------------- #
# expiry, revoke, re-key
# --------------------------------------------------------------------------- #

async def test_an_expired_ack_never_covers_even_before_reconcile_marks_it(http, app_pool, db_pool):
    from app import fleet_pairing as fpair
    w = await world(app_pool)
    ack = (await post_ack(http, w)).json()
    await rebuild(app_pool, now=w.now + MIN)
    assert len(await coverage(db_pool)) == 1
    await db_pool.execute("UPDATE fleet_conflict_acks SET expires_at = NOW() - interval '1 minute' WHERE id = $1::uuid",
                          ack["id"])
    await rebuild(app_pool, now=w.now + 2 * MIN)
    assert await coverage(db_pool) == []                                      # the builder reads only unexpired rows
    assert (await acks(db_pool))[0]["status"] == "active"                     # not yet marked
    with tenancy.tenant_context(A):
        async with app_pool.acquire() as con:
            out = await fpair.reconcile(con, now_())
    assert out["acks_expired"] == 1
    row = (await acks(db_pool))[0]
    assert row["status"] == "expired" and row["cleared_reason"] == "expired" and row["cleared_at"] is not None
    (aud,) = await audits(db_pool, "fleet.conflict.ack_expire", w.h.id)
    assert aud["details"]["ack_id"] == ack["id"]
    with tenancy.tenant_context(A):
        async with app_pool.acquire() as con:
            assert (await fpair.reconcile(con, now_()))["acks_expired"] == 0


async def test_revoking_the_agent_clears_its_acks(http, app_pool, db_pool):
    w = await world(app_pool)
    await post_ack(http, w)
    assert (await http.post(f"/v1/fleet/agents/{w.h.id}/revoke", json={})).status_code == 200
    row = (await acks(db_pool))[0]
    assert row["status"] == "cleared" and row["cleared_reason"] == "agent_revoked"
    (aud,) = await audits(db_pool, "fleet.conflict.ack_clear", w.h.id)
    assert aud["details"]["reason"] == "agent_revoked"


# --------------------------------------------------------------------------- #
# the acknowledgement changes nothing but coverage
# --------------------------------------------------------------------------- #

async def test_an_ack_never_touches_another_conflict_a_tier_or_a_signature(http, app_pool, db_pool):
    w = await world(app_pool)
    await _persist_scan_edge(app_pool, "ip:10.0.0.5", 9090, w.seen)           # a second conflict
    await rebuild(app_pool, now=w.now + MIN)
    assert (await post_ack(http, w)).status_code == 201
    rows, out = await rebuild(app_pool, now=w.now + 2 * MIN)
    assert out.coverage == []                                                  # 9090 is still open: no coverage
    f = out.facts[0]
    assert [c["port"] for c in f.facts["firewall"]["conflict"]] == [9090]
    assert f.tier == "configured" and all(e["signed"] is True for n, e in f.facts.items() if n != "host_agent")
    assert f.facts["host_agent"]["data"]["conflicts_acknowledged"][0]["port"] == 8080


async def test_the_acks_sql_is_read_only_and_names_no_tenant():
    assert "tenant_id" not in hf.ACKS_SQL.lower()
    for word in ("INSERT", "UPDATE", "DELETE"):
        assert word not in hf.ACKS_SQL.upper()


# --------------------------------------------------------------------------- #
# tenancy
# --------------------------------------------------------------------------- #

async def test_a_tenant_never_reads_or_clears_another_tenants_acks(app_pool, db_pool, fake_redis):
    from app import fleet_pairing as fpair
    w = await world(app_pool)
    await db_pool.execute(
        "INSERT INTO fleet_conflict_acks (agent_id, proto, port, justification, through_seen_at) VALUES ($1,'tcp',8080,$2,NOW())",
        w.h.id, WHY)
    await tenancy.create_tenant(db_pool, slug="ackb", name="Ack B", tenant_id=B)
    ack_id = (await acks(db_pool))[0]["id"]
    with tenancy.tenant_context(B):
        with pytest.raises(fpair.PairingError) as e1:
            await fpair.clear_ack(app_pool, w.h.id, ack_id, justification="some reason", actor="x", actor_role="admin")
        with pytest.raises(fpair.PairingError) as e2:
            await fpair.clear_ack(app_pool, uuid.uuid4(), uuid.uuid4(), justification="some reason", actor="x",
                                  actor_role="admin")
    assert (e1.value.status, e1.value.body) == (e2.value.status, e2.value.body) == (404, {"detail": "agent not found"})
    assert (await acks(db_pool))[0]["status"] == "active"


async def test_acks_are_only_visible_through_the_tenant_context(app_pool, db_pool):
    w = await world(app_pool)
    await post_ack_direct(app_pool, w)
    await tenancy.create_tenant(db_pool, slug="ackc", name="Ack C", tenant_id=B)
    async with conn_for(app_pool, B) as con:
        assert await con.fetchval("SELECT count(*) FROM fleet_conflict_acks") == 0
    async with conn_for(app_pool, A) as con:
        assert await con.fetchval("SELECT count(*) FROM fleet_conflict_acks") == 1


async def post_ack_direct(app_pool, w):
    from app import fleet_pairing as fpair
    with tenancy.tenant_context(A):
        return await fpair.create_ack(
            app_pool, w.h.id, kind="agent_closed_scan_open", proto="tcp", port=8080, scan_seen_at=w.seen,
            justification=WHY, ttl_hours=168, actor="x", actor_role="admin")
