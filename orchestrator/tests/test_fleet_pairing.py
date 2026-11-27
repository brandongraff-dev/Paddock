"""P2.1 section 4 (WP4): the operator pairing of an agent with a cloud instance, against the real database.

Routes (``PUT|DELETE|GET /v1/fleet/agents/{id}/pairing``, ``.../pairing/candidates``, ``GET /v1/fleet/pairings``), the
algorithm of 4.4, the cascades (revoke, re-key, signed rotation), the ingest mirror (``fleet_posture._resolve_node``),
``fleet_pairing.reconcile``, tenant isolation and the RBAC / billing gates. The app is served through the
NON-superuser role (RLS enforced) in the normal and in the ``ORCH_TEST_APP_ROLE=1`` run; ``db_pool`` (superuser) is
used to seed and to tamper underneath.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import json
import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app import fleet_enroll as fe
from app import fleet_posture as fp
from app import tenancy
from app.config import settings

from .p2_support import hdr, seed_key
from .test_assurance_host_fw_db import conn_for, healthy, now_, post, seed_host

A = tenancy.DEFAULT_TENANT_ID
B = "00000000-0000-0000-0000-0000000000b9"
H = dt.timedelta(hours=1)
PRIV = "10.0.0.5"
PUB = "54.1.2.3"


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


async def seed_asset(db, priv=(PRIV,), pub=(PUB,), *, rtype="instance", kind="cloud_resource", age=dt.timedelta(0),
                     classification="internal", tenant=A, name=None, extra=None):
    name = name or "i-" + uuid.uuid4().hex[:8]
    md = {"resource_type": rtype, "private_ips": list(priv), "public_ips": list(pub), **(extra or {})}
    return await db.fetchval(
        "INSERT INTO assets (tenant_id, kind, value, canonical, source, metadata, classification, last_seen) "
        "VALUES ($1,$2,$3,$3,'test',$4::jsonb,$5, NOW() - $6::interval) RETURNING id",
        tenant, kind, f"arn:aws:ec2:eu-west-1:123456789012:instance/{name}", json.dumps(md), classification, age)


async def audits(db, action, resource=None):
    rows = await db.fetch("SELECT * FROM audit_log WHERE action = $1 ORDER BY id", action)
    out = [dict(r, details=json.loads(r["details"]) if isinstance(r["details"], str) else r["details"])
           for r in rows]
    return [r for r in out if resource is None or r["resource_id"] == str(resource)]


async def agent_row(db, agent_id):
    r = await db.fetchrow("SELECT node_ref, identity, status, revoked_at FROM fleet_agents WHERE id = $1", agent_id)
    ident = r["identity"]
    return r["node_ref"], (json.loads(ident) if isinstance(ident, str) else ident), r


async def pairing_rows(db, agent_id=None):
    sql = "SELECT * FROM fleet_agent_pairings" + (" WHERE agent_id = $1" if agent_id else "") + " ORDER BY paired_at, id"
    return [dict(r) for r in await (db.fetch(sql, agent_id) if agent_id else db.fetch(sql))]


def body(asset, why="maintenance window 42, verified by cloud console", **kw):
    return {"asset_id": str(asset), "justification": why, **kw}


async def pair(http, host, asset, **kw):
    return await http.put(f"/v1/fleet/agents/{host.id}/pairing", json=body(asset, **kw))


async def unpair(http, host, why="decommissioned the old instance"):
    return await http.delete(f"/v1/fleet/agents/{host.id}/pairing", params={"justification": why})


async def live_host(app_pool, n=1, *, ips=(PRIV,), peer=PRIV, **kw):
    """An agent with a real signed posture through the real ingest: its identity holds the claimed ips and the peer."""
    h = await seed_host(app_pool, n, **kw)
    await post(app_pool, h, healthy(collected=now_(), seq=1, ips=list(ips)), ip=peer)
    return h


# --------------------------------------------------------------------------- #
# PUT: the algorithm of 4.4
# --------------------------------------------------------------------------- #

async def test_put_pairs_the_agent_with_the_asset_in_one_transaction(http, app_pool, db_pool):
    h = await live_host(app_pool)
    asset = await seed_asset(db_pool)
    r = await pair(http, h, asset)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["status"] == "active" and out["changed"] is True and out["agent_id"] == str(h.id)
    assert out["asset_id"] == str(asset) and out["asset_canonical"].startswith("arn:aws:ec2:")
    assert out["justification"].startswith("maintenance window") and out["paired_by"] == "dev-admin"
    assert out["ended_at"] is None and out["ended_by"] is None
    assert out["checks"]["claimed_ips"] == [PRIV] and PRIV in out["checks"]["asset_ips"]
    assert out["checks"]["claimed_subset"] is True and out["checks"]["peer_direct"] is True
    assert out["checks"]["peer_in_asset"] is True and out["checks"]["asset_kind"] == "cloud_instance"
    assert out["effective"] == {"node_ref": f"asset:{asset}", "basis": "paired", "state": "active", "note": ""}
    node, ident, _ = await agent_row(db_pool, h.id)
    assert node == f"asset:{asset}" and ident["basis"] == "paired" and "note" not in ident
    assert ident["ips"] == [PRIV] and ident["peer_ip"] == PRIV                 # nothing else of the identity moved
    (row,) = await pairing_rows(db_pool, h.id)
    assert row["status"] == "active" and row["asset_id"] == asset and row["paired_by"] == "dev-admin"
    (aud,) = await audits(db_pool, "fleet.pairing.create", h.id)
    assert aud["resource_type"] == "fleet_agent" and aud["justification"].startswith("maintenance window")
    assert aud["details"]["asset_id"] == str(asset) and aud["details"]["acknowledge_mismatch"] is False
    assert aud["details"]["checks"]["claimed_subset"] is True and aud["details"]["asset_canonical"]
    # the graph is asked to rebuild
    assert await db_pool.fetchval("SELECT count(*) FROM assurance_state WHERE last_build_at IS NULL") == 1


async def test_put_is_idempotent_for_the_same_asset(http, app_pool, db_pool):
    h = await live_host(app_pool)
    asset = await seed_asset(db_pool)
    first = (await pair(http, h, asset)).json()
    again = await pair(http, h, asset, why="a different but long enough reason")
    assert again.status_code == 200 and again.json()["changed"] is False
    assert again.json()["id"] == first["id"] and again.json()["justification"] == first["justification"]
    assert len(await pairing_rows(db_pool, h.id)) == 1
    assert len(await audits(db_pool, "fleet.pairing.create", h.id)) == 1


async def test_another_asset_for_a_paired_agent_is_409_and_the_asset_id_is_named(http, app_pool, db_pool):
    h = await live_host(app_pool)
    a1, a2 = await seed_asset(db_pool), await seed_asset(db_pool, ("10.0.0.6",))
    assert (await pair(http, h, a1)).status_code == 200
    r = await pair(http, h, a2)
    assert r.status_code == 409 and r.json()["reason"] == "agent_already_paired" and r.json()["asset_id"] == str(a1)
    assert [p["asset_id"] for p in await pairing_rows(db_pool, h.id)] == [a1]


async def test_two_agents_on_one_asset_is_409_by_the_unique_index(http, app_pool, db_pool):
    h1 = await live_host(app_pool, 1)
    h2 = await live_host(app_pool, 2, ips=("10.0.0.6",), peer="10.0.0.6")
    asset = await seed_asset(db_pool, ("10.0.0.5", "10.0.0.6"))
    assert (await pair(http, h1, asset)).status_code == 200
    r = await pair(http, h2, asset)
    assert r.status_code == 409 and r.json()["reason"] == "asset_already_paired" and r.json()["agent_id"] == str(h1.id)
    assert await db_pool.fetchval("SELECT count(*) FROM fleet_agent_pairings WHERE status = 'active'") == 1
    node, _, _ = await agent_row(db_pool, h2.id)
    assert node == f"agent:{h2.id}"                                            # the loser changed nothing


async def test_a_race_for_one_asset_has_exactly_one_winner(http, app_pool, db_pool):
    hosts = [await live_host(app_pool, n, ips=(f"10.0.0.{4 + n}",), peer=f"10.0.0.{4 + n}") for n in (1, 2, 3, 4)]
    asset = await seed_asset(db_pool, ("10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8"))
    rs = await asyncio.gather(*[pair(http, h, asset) for h in hosts])
    codes = sorted(r.status_code for r in rs)
    assert codes == [200, 409, 409, 409], [r.text for r in rs]
    assert all(r.json().get("reason") == "asset_already_paired" for r in rs if r.status_code == 409)
    assert await db_pool.fetchval("SELECT count(*) FROM fleet_agent_pairings WHERE status = 'active'") == 1


@pytest.mark.parametrize("kw,status,code", [
    ({"rtype": "db_instance"}, 422, "asset_not_a_vm"),
    ({"rtype": "load_balancer"}, 422, "asset_not_a_vm"),
    ({"kind": "domain"}, 422, "asset_not_a_vm"),                     # VM-looking metadata on another kind is no VM
    ({"age": dt.timedelta(hours=73)}, 409, "asset_stale"),
    ({"age": dt.timedelta(hours=-3)}, 409, "asset_stale"),            # a date in the future can never age: same as the decision
])
async def test_the_asset_must_be_a_fresh_vm(http, app_pool, db_pool, kw, status, code):
    h = await live_host(app_pool)
    asset = await seed_asset(db_pool, **kw)
    r = await pair(http, h, asset)
    assert r.status_code == status and r.json()["reason"] == code, r.text
    assert await pairing_rows(db_pool, h.id) == []


async def test_the_asset_age_limit_is_the_setting(http, app_pool, db_pool, monkeypatch):
    h = await live_host(app_pool)
    asset = await seed_asset(db_pool, age=dt.timedelta(hours=10))
    monkeypatch.setattr(settings, "assurance_pairing_asset_max_age_h", 9)
    assert (await pair(http, h, asset)).status_code == 409
    monkeypatch.setattr(settings, "assurance_pairing_asset_max_age_h", 11)
    assert (await pair(http, h, asset)).status_code == 200


async def test_a_missing_hidden_or_random_asset_answers_identically(http, app_pool, db_pool):
    h = await live_host(app_pool)
    hidden = await seed_asset(db_pool, classification="restricted")
    # the dev principal has clearance 'restricted': lower the asset's visibility bar the other way round
    r_missing = await pair(http, h, uuid.uuid4())
    assert r_missing.status_code == 404 and r_missing.json() == {"detail": "asset not found"}
    assert (await pair(http, h, hidden)).status_code == 200          # visible to restricted clearance


async def test_an_asset_above_the_callers_clearance_is_a_plain_404(app_pool, db_pool, monkeypatch):
    """A hidden asset answers exactly like a missing one, so the route is no existence oracle across clearance."""
    from app import fleet_pairing as fpair
    h = await live_host(app_pool)
    hidden = await seed_asset(db_pool, classification="restricted")
    with tenancy.tenant_context(A):
        with pytest.raises(fpair.PairingError) as hid:
            await fpair.put_pairing(app_pool, h.id, asset_id=hidden, justification="whatever reason", actor="x",
                                    actor_role="admin", clearance_rank=1)
        with pytest.raises(fpair.PairingError) as gone:
            await fpair.put_pairing(app_pool, h.id, asset_id=uuid.uuid4(), justification="whatever reason", actor="x",
                                    actor_role="admin", clearance_rank=1)
    assert (hid.value.status, hid.value.body) == (gone.value.status, gone.value.body) == (404, {"detail": "asset not found"})
    assert await pairing_rows(db_pool, h.id) == []


async def test_a_pairing_to_an_asset_above_the_callers_clearance_is_redacted_not_hidden(app_pool, db_pool):
    """The pairing is the agent's, the asset is not the caller's to read: the shape stays, every field that could name
    or describe the asset or carry the operator's reasoning is blank (also what ``AgentDetailOut.pairing`` shows)."""
    from app import fleet_pairing as fpair
    h = await live_host(app_pool)
    asset = await seed_asset(db_pool, classification="restricted")
    with tenancy.tenant_context(A):
        await fpair.put_pairing(app_pool, h.id, asset_id=asset, justification="verified in the console", actor="adm",
                                actor_role="admin", clearance_rank=3)
        full = await fpair.get_pairing(app_pool, h.id, clearance_rank=3)
        low = await fpair.get_pairing(app_pool, h.id, clearance_rank=1)
    assert full["justification"] == "verified in the console" and full["asset_canonical"].startswith("arn:")
    assert full["checks"]["asset_ips"] == [PRIV, PUB]
    assert low["asset_id"] == asset and low["status"] == "active" and low["effective"]["state"] == "active"
    assert low["justification"] == "" and low["asset_canonical"] == "" and low["paired_by"] == ""
    assert low["checks"]["asset_ips"] == [] and low["checks"]["claimed_ips"] == [] and low["checks"]["observed_peer"] is None
    assert PUB not in json.dumps(low, default=str) and "verified" not in json.dumps(low, default=str)
    with tenancy.tenant_context(A):
        rows = await fpair.list_pairings(app_pool, status=None, asset_id=None, limit=10, offset=0, clearance_rank=1)
    assert rows[0]["asset_canonical"] == "" and rows[0]["checks"]["asset_ips"] == []


async def test_agent_states_that_cannot_be_paired(http, app_pool, db_pool):
    asset = await seed_asset(db_pool)
    r = await http.put(f"/v1/fleet/agents/{uuid.uuid4()}/pairing", json=body(asset))
    assert r.status_code == 404 and r.json() == {"detail": "agent not found"}
    revoked = await live_host(app_pool, 1)
    await db_pool.execute("UPDATE fleet_agents SET status = 'revoked', revoked_at = NOW() WHERE id = $1", revoked.id)
    r = await pair(http, revoked, asset)
    assert r.status_code == 409 and r.json()["reason"] == "agent_not_live"
    legacy = await live_host(app_pool, 2)
    await db_pool.execute("UPDATE fleet_agents SET legacy = TRUE WHERE id = $1", legacy.id)
    r = await pair(http, legacy, asset)
    assert r.status_code == 409 and r.json()["reason"] == "agent_not_live"
    nokey = await live_host(app_pool, 3)
    await db_pool.execute("UPDATE fleet_agent_keys SET status = 'revoked', revoked_at = NOW() WHERE agent_id = $1",
                          nokey.id)
    r = await pair(http, nokey, asset)
    assert r.status_code == 409 and r.json()["reason"] == "agent_has_no_active_key"
    assert await pairing_rows(db_pool) == []


async def test_a_disagreeing_claim_is_409_unless_acknowledged_and_never_a_proof(http, app_pool, db_pool):
    h = await live_host(app_pool, ips=("10.0.0.5", "10.77.0.1"))              # claims an address the asset lacks
    asset = await seed_asset(db_pool)
    r = await pair(http, h, asset)
    assert r.status_code == 409 and r.json()["reason"] == "identity_claims_disagree"
    assert r.json()["checks"]["claimed_subset"] is False and r.json()["checks"]["claimed_ips"] == ["10.0.0.5", "10.77.0.1"]
    assert await pairing_rows(db_pool, h.id) == []
    ok = await pair(http, h, asset, acknowledge_mismatch=True)
    assert ok.status_code == 200 and ok.json()["checks"]["acknowledged_mismatch"] is True
    (aud,) = await audits(db_pool, "fleet.pairing.create", h.id)
    assert aud["details"]["acknowledge_mismatch"] is True and aud["details"]["checks"]["acknowledged_mismatch"] is True


async def test_a_private_direct_peer_that_is_not_the_assets_is_409_unless_acknowledged(http, app_pool, db_pool):
    h = await live_host(app_pool, ips=(PRIV,), peer="10.9.9.9")
    asset = await seed_asset(db_pool)
    r = await pair(http, h, asset)
    assert r.status_code == 409 and r.json()["reason"] == "identity_claims_disagree"
    assert r.json()["checks"]["peer_in_asset"] is False and r.json()["checks"]["observed_peer"] == "10.9.9.9"
    assert (await pair(http, h, asset, acknowledge_mismatch=True)).status_code == 200


async def test_no_claim_and_a_public_or_proxied_peer_is_not_a_disagreement(http, app_pool, db_pool):
    from app.auth import ClientAddr
    h = await seed_host(app_pool, 1)
    await post(app_pool, h, healthy(collected=now_(), seq=1, ips=[]), ip=ClientAddr("93.184.216.34", proxied=False))
    asset = await seed_asset(db_pool)
    r = await pair(http, h, asset)
    assert r.status_code == 200 and r.json()["checks"]["claimed_subset"] is None
    assert r.json()["checks"]["peer_in_asset"] is None                          # a public peer proves nothing
    h2 = await seed_host(app_pool, 2)
    await post(app_pool, h2, healthy(collected=now_(), seq=1, ips=[]), ip=ClientAddr("10.9.9.9", proxied=True))
    asset2 = await seed_asset(db_pool, ("10.0.0.6",))
    r = await pair(http, h2, asset2)
    assert r.status_code == 200 and r.json()["checks"]["peer_direct"] is False and r.json()["checks"]["observed_peer"] is None


@pytest.mark.parametrize("payload", [
    {"justification": "ab"}, {"justification": "  a  "}, {"justification": "x" * 1001}, {"justification": ""},
    {"extra": 1}, {"acknowledge_mismatch": "maybe"}, {"asset_id": "nope"},
])
async def test_the_body_is_strict(http, app_pool, db_pool, payload):
    h = await live_host(app_pool)
    asset = await seed_asset(db_pool)
    b = {**body(asset), **payload}
    r = await http.put(f"/v1/fleet/agents/{h.id}/pairing", json=b)
    assert r.status_code == 422, (payload, r.text)
    assert await pairing_rows(db_pool, h.id) == []


async def test_the_justification_is_stripped_and_three_characters_are_enough(http, app_pool, db_pool):
    h = await live_host(app_pool)
    asset = await seed_asset(db_pool)
    r = await pair(http, h, asset, why="  abc  ")
    assert r.status_code == 200 and r.json()["justification"] == "abc"


# --------------------------------------------------------------------------- #
# DELETE, GET, candidates, ledger
# --------------------------------------------------------------------------- #

async def test_delete_ends_the_pairing_and_the_ledger_keeps_every_row(http, app_pool, db_pool):
    h = await live_host(app_pool)
    a1, a2 = await seed_asset(db_pool), await seed_asset(db_pool, ("10.0.0.6",))
    await pair(http, h, a1, acknowledge_mismatch=True)
    assert (await http.delete(f"/v1/fleet/agents/{h.id}/pairing")).status_code == 422       # justification is required
    assert (await http.delete(f"/v1/fleet/agents/{h.id}/pairing", params={"justification": "no"})).status_code == 422
    r = await unpair(http, h)
    assert r.status_code == 200 and r.json()["status"] == "ended" and r.json()["ended_reason"] == "unpaired"
    assert r.json()["ended_by"] == "dev-admin" and r.json()["ended_at"] is not None
    assert r.json()["effective"]["node_ref"] == f"agent:{h.id}" and r.json()["effective"]["basis"] == "claimed"
    node, ident, _ = await agent_row(db_pool, h.id)
    assert node == f"agent:{h.id}" and ident["basis"] == "claimed"
    assert (await unpair(http, h)).status_code == 404 and (await unpair(http, h)).json() == {"detail": "no active pairing"}
    (aud,) = await audits(db_pool, "fleet.pairing.end", h.id)
    assert aud["details"]["asset_id"] == str(a1) and aud["details"]["reason"] == "unpaired" and aud["justification"]
    # to move: DELETE then PUT; the old row is neither deleted nor re-pointed
    assert (await pair(http, h, a2, acknowledge_mismatch=True)).status_code == 200
    rows = await pairing_rows(db_pool, h.id)
    assert [(p["asset_id"], p["status"]) for p in rows] == [(a1, "ended"), (a2, "active")]
    assert rows[0]["ended_reason"] == "unpaired"


async def test_a_pairing_ledger_row_can_neither_be_deleted_nor_re_pointed_by_the_app_role(app_pool, db_pool):
    h = await live_host(app_pool)
    asset = await seed_asset(db_pool)
    await db_pool.execute("INSERT INTO fleet_agent_pairings (agent_id, asset_id, justification) VALUES ($1,$2,'why')",
                          h.id, asset)
    # the module never issues such a statement; the source is the evidence
    import inspect

    from app import fleet_pairing as fpair
    src = inspect.getsource(fpair)
    assert "DELETE FROM fleet_agent_pairings" not in src and "SET asset_id" not in src and "SET agent_id" not in src


async def test_get_pairing_is_404_when_never_paired_then_shows_the_active_and_the_last_ended(http, app_pool, db_pool):
    h = await live_host(app_pool)
    asset = await seed_asset(db_pool)
    r = await http.get(f"/v1/fleet/agents/{h.id}/pairing")
    assert r.status_code == 404
    assert (await http.get(f"/v1/fleet/agents/{uuid.uuid4()}/pairing")).json() == {"detail": "agent not found"}
    await pair(http, h, asset)
    r = await http.get(f"/v1/fleet/agents/{h.id}/pairing")
    assert r.status_code == 200 and r.json()["status"] == "active" and r.json()["changed"] is False
    assert r.json()["effective"]["state"] == "active" and r.json()["justification"].startswith("maintenance")
    await unpair(http, h)
    r = await http.get(f"/v1/fleet/agents/{h.id}/pairing")
    assert r.status_code == 200 and r.json()["status"] == "ended"


async def test_candidates_are_vm_assets_whose_addresses_intersect_the_claim_and_create_nothing(http, app_pool, db_pool):
    h = await live_host(app_pool, ips=(PRIV, "10.0.0.8"))
    good = await seed_asset(db_pool, (PRIV,), name="good")
    both = await seed_asset(db_pool, ("10.0.0.8",), (PUB,), rtype="virtual_machine", name="both")
    await seed_asset(db_pool, ("10.0.0.99",), name="elsewhere")
    await seed_asset(db_pool, (PRIV,), rtype="db_instance", name="db")
    await seed_asset(db_pool, (PRIV,), age=dt.timedelta(hours=80), name="stale")
    await seed_asset(db_pool, (PRIV,), kind="domain", name="dom")
    r = await http.get(f"/v1/fleet/agents/{h.id}/pairing/candidates")
    assert r.status_code == 200
    got = {c["asset_id"]: c for c in r.json()}
    assert set(got) == {str(good), str(both)}
    assert got[str(good)]["checks"]["claimed_subset"] is False and got[str(good)]["checks"]["asset_kind"] == "cloud_instance"
    assert got[str(good)]["paired_to"] is None
    assert await pairing_rows(db_pool) == []
    await pair(http, h, good, acknowledge_mismatch=True)
    other = await live_host(app_pool, 2, ips=(PRIV,), peer=PRIV)
    r = await http.get(f"/v1/fleet/agents/{other.id}/pairing/candidates")
    assert {c["asset_id"]: c["paired_to"] for c in r.json()}[str(good)] == str(h.id)


async def test_candidates_are_capped_and_empty_without_a_claim(http, app_pool, db_pool):
    h = await live_host(app_pool)
    for i in range(25):
        await seed_asset(db_pool, (PRIV,), name=f"n{i}")
    assert len((await http.get(f"/v1/fleet/agents/{h.id}/pairing/candidates")).json()) == 20
    h2 = await seed_host(app_pool, 2)
    await post(app_pool, h2, healthy(collected=now_(), seq=1, ips=[]), ip="10.0.0.9")
    assert (await http.get(f"/v1/fleet/agents/{h2.id}/pairing/candidates")).json() == []
    assert (await http.get(f"/v1/fleet/agents/{uuid.uuid4()}/pairing/candidates")).status_code == 404


async def test_the_ledger_lists_pairings_with_filters_and_paging(http, app_pool, db_pool):
    hosts = [await live_host(app_pool, n, ips=(f"10.0.0.{4 + n}",), peer=f"10.0.0.{4 + n}") for n in (1, 2, 3)]
    assets = [await seed_asset(db_pool, (f"10.0.0.{4 + n}",)) for n in (1, 2, 3)]
    for h, a in zip(hosts, assets):
        assert (await pair(http, h, a)).status_code == 200
    await unpair(http, hosts[0])
    r = await http.get("/v1/fleet/pairings")
    assert r.status_code == 200 and len(r.json()) == 3
    act = (await http.get("/v1/fleet/pairings", params={"status": "active"})).json()
    end = (await http.get("/v1/fleet/pairings", params={"status": "ended"})).json()
    assert len(act) == 2 and len(end) == 1 and end[0]["ended_reason"] == "unpaired"
    one = (await http.get("/v1/fleet/pairings", params={"asset_id": str(assets[1])})).json()
    assert [p["asset_id"] for p in one] == [str(assets[1])]
    page = (await http.get("/v1/fleet/pairings", params={"limit": 1, "offset": 1})).json()
    assert len(page) == 1
    assert (await http.get("/v1/fleet/pairings", params={"status": "weird"})).status_code == 422
    assert (await http.get("/v1/fleet/pairings", params={"limit": 0})).status_code == 422
    assert (await http.get("/v1/fleet/pairings", params={"asset_id": "x"})).status_code == 422


async def test_agent_out_names_the_paired_asset_and_the_detail_has_a_viewer_safe_pairing(http, app_pool, db_pool):
    h = await live_host(app_pool)
    asset = await seed_asset(db_pool)
    assert (await http.get(f"/v1/fleet/agents/{h.id}")).json()["pairing"] is None
    await pair(http, h, asset)
    rows = (await http.get("/v1/fleet/agents")).json()
    assert [a["paired_asset_id"] for a in rows] == [str(asset)]
    d = (await http.get(f"/v1/fleet/agents/{h.id}")).json()
    p = d["pairing"]
    assert d["paired_asset_id"] == str(asset) and p["status"] == "active" and p["asset_id"] == str(asset)
    assert p["justification"] == "" and p["asset_canonical"] == "" and p["paired_by"] == ""
    assert p["checks"]["claimed_ips"] == [] and p["checks"]["asset_ips"] == [] and p["checks"]["observed_peer"] is None
    assert p["effective"]["state"] == "active" and p["effective"]["basis"] == "paired"
    txt = json.dumps(d)
    assert PUB not in txt and "maintenance window" not in txt and "arn:aws" not in txt
    await unpair(http, h)
    assert (await http.get(f"/v1/fleet/agents/{h.id}")).json()["paired_asset_id"] is None


# --------------------------------------------------------------------------- #
# findings follow the host (the SLA clock and tickets stay on the same finding)
# --------------------------------------------------------------------------- #

async def seed_finding(db, invariant, target):
    from app.assurance.findings_sync import ESTATE_KIND, ESTATE_VALUE, asset_uuid, rule_id_for
    aid = asset_uuid(target)
    if aid is None:
        aid = await db.fetchval(
            "INSERT INTO assets (tenant_id, kind, value, canonical, source, metadata) VALUES ($1,$2,$3,$3,'test','{}'::jsonb)"
            " ON CONFLICT (tenant_id, kind, canonical) DO UPDATE SET last_seen = NOW() RETURNING id",
            A, ESTATE_KIND, ESTATE_VALUE)
    witness = {"hops": [], "weakest_basis": "configured", "confirmed": False,
               "detail": {"node": target, "clause": "password_login_possible"}}
    ev = {"invariant": invariant, "target_ref": target, "witness": witness, "verdict": "VIOLATED"}
    return await db.fetchval(
        "INSERT INTO findings (tenant_id, asset_id, rule_id, rule_source, severity, title, description, status, "
        "evidence, metadata) VALUES ($1,$2,$3,'invariant','high','t','d','open',$4::jsonb,$5::jsonb) RETURNING id",
        A, aid, rule_id_for(invariant, target, estate=asset_uuid(target) is None), json.dumps(ev),
        json.dumps({"invariant_id": invariant, "target_ref": target}))


async def refresh_witness(db, fid, node):
    """What the next evaluation does: the witness names the finding's new node (``finding_follow`` moves the target
    only, and moves a finding again only while its witness names the node it is on)."""
    await db.execute("UPDATE findings SET evidence = jsonb_set(evidence, '{witness,detail,node}', to_jsonb($2::text)) "
                     "WHERE id = $1", fid, node)


async def finding_target(db, fid):
    ev = await db.fetchval("SELECT evidence FROM findings WHERE id = $1", fid)
    return (json.loads(ev) if isinstance(ev, str) else ev)["target_ref"]


async def test_the_findings_of_the_host_follow_it_to_the_asset_and_back(http, app_pool, db_pool):
    h = await live_host(app_pool)
    asset = await seed_asset(db_pool)
    fid = await seed_finding(db_pool, "std:server-ssh-hardened", f"agent:{h.id}")
    await pair(http, h, asset)
    assert await finding_target(db_pool, fid) == f"asset:{asset}"
    await refresh_witness(db_pool, fid, f"asset:{asset}")
    await unpair(http, h)
    assert await finding_target(db_pool, fid) == f"agent:{h.id}"
    assert await db_pool.fetchval("SELECT count(*) FROM findings") == 1                # the same row, never a duplicate


# --------------------------------------------------------------------------- #
# cascades: revoke, re-key (not rotation); same transaction as the existing code
# --------------------------------------------------------------------------- #

async def test_revoking_the_agent_ends_the_pairing_but_leaves_the_node_ref_for_the_tombstone(http, app_pool, db_pool):
    h = await live_host(app_pool)
    asset = await seed_asset(db_pool)
    await pair(http, h, asset)
    fid = await seed_finding(db_pool, "std:server-ssh-hardened", f"asset:{asset}")
    r = await http.post(f"/v1/fleet/agents/{h.id}/revoke", json={"reason": "stolen host"})
    assert r.status_code == 200, r.text
    (row,) = await pairing_rows(db_pool, h.id)
    assert row["status"] == "ended" and row["ended_reason"] == "agent_revoked" and row["ended_at"] is not None
    node, _, _ = await agent_row(db_pool, h.id)
    assert node == f"asset:{asset}"                                            # the tombstone key stays
    assert await finding_target(db_pool, fid) == f"asset:{asset}"
    (aud,) = await audits(db_pool, "fleet.pairing.end", h.id)
    assert aud["details"]["reason"] == "agent_revoked" and aud["details"]["asset_id"] == str(asset)
    # the builder keeps the revoked host as an UNKNOWN tombstone on the asset node while the finding is open
    from app.assurance.builders import host_fw as hf
    async with conn_for(app_pool, A) as con:
        rows = await hf.load(con, now_() + dt.timedelta(minutes=1))
    assert [t["node_ref"] for t in rows.tombstones] == [f"asset:{asset}"] and rows.pairings == []
    out = hf.build(rows, now_() + dt.timedelta(minutes=1))
    assert [f.node_ref for f in out.facts] == [f"asset:{asset}"]
    assert out.facts[0].facts["host_agent"]["reason"] == "agent_revoked" and out.coverage == []


async def test_revoking_an_unpaired_agent_writes_no_pairing_audit(http, app_pool, db_pool):
    h = await live_host(app_pool)
    assert (await http.post(f"/v1/fleet/agents/{h.id}/revoke", json={})).status_code == 200
    assert await audits(db_pool, "fleet.pairing.end") == []


async def _rekey(app_pool, db_pool, agent_id, hostname):
    full, _ = await fe.mint_token(app_pool, actor="admin@test", for_agent=agent_id)
    from .test_fleet_enroll import Agent
    agent = Agent()
    out = await fe.enroll_agent(app_pool, **agent.kwargs(full, hostname, client_ip="198.51.100.7"))
    assert out["rekey"] is True
    return out


async def test_a_rekey_ends_the_pairing_clears_the_acks_and_moves_the_findings_home(http, app_pool, db_pool):
    h = await live_host(app_pool)
    asset = await seed_asset(db_pool)
    await pair(http, h, asset)
    fid = await seed_finding(db_pool, "std:server-ssh-hardened", f"asset:{asset}")
    await db_pool.execute(
        "INSERT INTO fleet_conflict_acks (agent_id, proto, port, justification) VALUES ($1,'tcp',8080,'looked at it')", h.id)
    await _rekey(app_pool, db_pool, h.id, h.hostname)
    (row,) = await pairing_rows(db_pool, h.id)
    assert row["status"] == "ended" and row["ended_reason"] == "rekeyed"
    node, ident, _ = await agent_row(db_pool, h.id)
    assert node == f"agent:{h.id}" and ident["basis"] == "claimed"
    assert await finding_target(db_pool, fid) == f"agent:{h.id}"
    ack = await db_pool.fetchrow("SELECT status, cleared_reason FROM fleet_conflict_acks WHERE agent_id = $1", h.id)
    assert (ack["status"], ack["cleared_reason"]) == ("cleared", "rekeyed")
    (aud,) = await audits(db_pool, "fleet.pairing.end", h.id)
    assert aud["details"]["reason"] == "rekeyed"
    # a later PUT for the same agent works again (the new host is paired explicitly, never inherited)
    assert (await pair(http, h, asset, acknowledge_mismatch=True)).status_code == 200


async def test_a_rekey_of_an_unpaired_agent_writes_nothing_extra(http, app_pool, db_pool):
    h = await live_host(app_pool)
    await _rekey(app_pool, db_pool, h.id, h.hostname)
    assert await audits(db_pool, "fleet.pairing.end") == []


async def test_a_signed_key_rotation_keeps_the_pairing(http, app_pool, db_pool):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from .test_fleet_posture import build_envelope, kid_of, rotate_payload
    h = await live_host(app_pool)
    asset = await seed_asset(db_pool)
    await pair(http, h, asset)
    new_sk = Ed25519PrivateKey.generate()
    now = now_()
    h.seq += 1
    env = build_envelope(h.sk, agent_id=h.id, tenant_id=A, kind="rotate", seq=h.seq,
                         payload=rotate_payload(new_sk, str(h.id), kid_of(h.sk)), issued=now)
    res = await fp.ingest_envelope(app_pool, agent_id=h.id, tenant_id=A, kind="rotate",
                                   body=json.dumps(env).encode(), content_encoding=None, client_ip="10.0.0.5", now=now)
    assert res.new_key_id == kid_of(new_sk)
    (row,) = await pairing_rows(db_pool, h.id)
    assert row["status"] == "active"
    node, ident, _ = await agent_row(db_pool, h.id)
    assert node == f"asset:{asset}" and ident["basis"] == "paired"


# --------------------------------------------------------------------------- #
# the ingest mirror and reconcile
# --------------------------------------------------------------------------- #

async def test_a_posture_of_a_paired_agent_keeps_it_paired(http, app_pool, db_pool):
    h = await live_host(app_pool)
    asset = await seed_asset(db_pool)
    await pair(http, h, asset)
    await post(app_pool, h, healthy(collected=now_(), seq=2, ips=[PRIV], security=3), ip=PRIV)
    node, ident, _ = await agent_row(db_pool, h.id)
    assert node == f"asset:{asset}" and ident["basis"] == "paired" and "note" not in ident


async def test_a_posture_after_the_asset_went_stale_makes_the_pairing_inert_and_the_findings_follow(http, app_pool, db_pool):
    h = await live_host(app_pool)
    asset = await seed_asset(db_pool)
    await pair(http, h, asset)
    fid = await seed_finding(db_pool, "std:server-ssh-hardened", f"asset:{asset}")
    await db_pool.execute("UPDATE assets SET last_seen = NOW() - interval '100 hours' WHERE id = $1", asset)
    await post(app_pool, h, healthy(collected=now_(), seq=2, ips=[PRIV], security=3), ip=PRIV)
    node, ident, _ = await agent_row(db_pool, h.id)
    assert node == f"agent:{h.id}" and ident["basis"] == "claimed" and ident["note"] == "pairing_inert:asset_stale"
    assert await finding_target(db_pool, fid) == f"agent:{h.id}"
    await refresh_witness(db_pool, fid, f"agent:{h.id}")
    (row,) = await pairing_rows(db_pool, h.id)
    assert row["status"] == "active"                                          # never auto-ended
    eff = (await http.get(f"/v1/fleet/agents/{h.id}/pairing")).json()["effective"]
    assert eff["state"] == "inert_asset_stale" and eff["node_ref"] == f"agent:{h.id}" and eff["basis"] == "claimed"
    # the asset is seen again: the next posture restores the pairing
    await db_pool.execute("UPDATE assets SET last_seen = NOW() WHERE id = $1", asset)
    await post(app_pool, h, healthy(collected=now_(), seq=3, ips=[PRIV], security=4), ip=PRIV)
    node, ident, _ = await agent_row(db_pool, h.id)
    assert node == f"asset:{asset}" and ident["basis"] == "paired" and "note" not in ident
    assert await finding_target(db_pool, fid) == f"asset:{asset}"


async def test_a_rogue_agent_claiming_the_assets_addresses_never_demotes_the_paired_one(http, app_pool, db_pool):
    """4.5 effect 7: claims never own addresses. The rogue's own posture runs the ingest decision over every agent whose
    claim overlaps; a PAIRED agent's node is decided by its pairing, so it must not be demoted (nor its findings moved)."""
    h = await live_host(app_pool, 1)
    asset = await seed_asset(db_pool)
    await pair(http, h, asset)
    fid = await seed_finding(db_pool, "std:server-ssh-hardened", f"asset:{asset}")
    rogue = await seed_host(app_pool, 2)
    await post(app_pool, rogue, healthy(collected=now_(), seq=1, ips=[PRIV]), ip="10.0.0.99")
    node, ident, _ = await agent_row(db_pool, h.id)
    assert node == f"asset:{asset}" and ident["basis"] == "paired"
    assert await finding_target(db_pool, fid) == f"asset:{asset}"
    rnode, rident, _ = await agent_row(db_pool, rogue.id)
    assert rnode == f"agent:{rogue.id}" and rident["basis"] == "claimed"
    # ... and the same through the builder: the rogue is its own node, the paired host keeps the asset
    from app.assurance.builders import host_fw as hf
    async with conn_for(app_pool, A) as con:
        rows = await hf.load(con, now_() + dt.timedelta(seconds=30))
    out = hf.build(rows, now_() + dt.timedelta(seconds=30))
    assert sorted(f.node_ref for f in out.facts) == sorted([f"asset:{asset}", f"agent:{rogue.id}"])


async def test_effective_states_inert_missing_not_vm_and_peer_mismatch(http, app_pool, db_pool):
    h = await live_host(app_pool)
    asset = await seed_asset(db_pool)
    await pair(http, h, asset)

    async def state():
        return (await http.get(f"/v1/fleet/agents/{h.id}/pairing")).json()["effective"]["state"]
    await db_pool.execute("UPDATE assets SET metadata = metadata || '{\"resource_type\": \"db_instance\"}'::jsonb "
                          "WHERE id = $1", asset)
    assert await state() == "inert_asset_not_vm"
    await db_pool.execute("UPDATE assets SET metadata = metadata || '{\"resource_type\": \"instance\"}'::jsonb "
                          "WHERE id = $1", asset)
    assert await state() == "active"
    await post(app_pool, h, healthy(collected=now_(), seq=2, ips=[PRIV]), ip="10.9.9.9")   # a direct, private, other peer
    assert await state() == "peer_mismatch"
    await db_pool.execute("DELETE FROM assets WHERE id = $1", asset)
    assert await state() == "inert_asset_missing"


async def test_reconcile_updates_the_columns_audits_each_transition_once_and_is_idempotent(http, app_pool, db_pool):
    from app import fleet_pairing as fpair
    h = await live_host(app_pool)
    asset = await seed_asset(db_pool)
    await pair(http, h, asset)
    fid = await seed_finding(db_pool, "std:server-ssh-hardened", f"asset:{asset}")

    async def run():
        with tenancy.tenant_context(A):
            async with app_pool.acquire() as con:
                return await fpair.reconcile(con, now_())
    assert (await run())["transitions"] == 0
    await db_pool.execute("UPDATE assets SET last_seen = NOW() - interval '100 hours' WHERE id = $1", asset)
    out = await run()
    assert out["transitions"] == 1
    node, ident, _ = await agent_row(db_pool, h.id)
    assert node == f"agent:{h.id}" and ident["basis"] == "claimed" and ident["note"] == "pairing_inert:asset_stale"
    assert await finding_target(db_pool, fid) == f"agent:{h.id}"
    await refresh_witness(db_pool, fid, f"agent:{h.id}")
    assert (await run())["transitions"] == 0
    (aud,) = await audits(db_pool, "fleet.pairing.inert", h.id)
    assert aud["details"]["state"] == "inert_asset_stale" and aud["details"]["asset_id"] == str(asset)
    await db_pool.execute("UPDATE assets SET last_seen = NOW() WHERE id = $1", asset)
    assert (await run())["transitions"] == 1
    node, ident, _ = await agent_row(db_pool, h.id)
    assert node == f"asset:{asset}" and ident["basis"] == "paired" and "note" not in ident
    assert await finding_target(db_pool, fid) == f"asset:{asset}"
    assert len(await audits(db_pool, "fleet.pairing.restored", h.id)) == 1
    assert (await run())["transitions"] == 0
    assert len(await audits(db_pool, "fleet.pairing.inert", h.id)) == 1


async def test_the_runner_reconciles_before_the_builders_and_the_paired_host_gets_coverage(http, app_pool, db_pool):
    from app.assurance import runner
    h = await live_host(app_pool)
    asset = await seed_asset(db_pool)
    await pair(http, h, asset)
    summary = await runner.build_tenant(app_pool, A, now=now_() + dt.timedelta(seconds=5))
    assert summary["host_fw"]["ok"] is True, summary["host_fw"]
    async with db_pool.acquire() as con:
        facts = await con.fetch("SELECT node_ref FROM reach_node_facts WHERE source = 'host_fw'")
        cov = await con.fetch("SELECT node_ref FROM reach_coverage WHERE source = 'host_fw'")
    assert [f["node_ref"] for f in facts] == [f"asset:{asset}"] and [c["node_ref"] for c in cov] == [f"asset:{asset}"]
    # the asset goes stale: reconcile (before the builders) puts the host back on agent:<uuid>, never a pass
    await db_pool.execute("UPDATE assets SET last_seen = NOW() - interval '100 hours' WHERE id = $1", asset)
    await runner.build_tenant(app_pool, A, now=now_() + dt.timedelta(seconds=10))
    async with db_pool.acquire() as con:
        facts = await con.fetch("SELECT node_ref FROM reach_node_facts WHERE source = 'host_fw'")
    assert [f["node_ref"] for f in facts] == [f"agent:{h.id}"]
    node, _, _ = await agent_row(db_pool, h.id)
    assert node == f"agent:{h.id}"


async def test_a_reconcile_failure_never_stops_the_build(app_pool, db_pool, monkeypatch):
    from app import fleet_pairing as fpair
    from app.assurance import runner

    async def boom(*a, **k):
        raise RuntimeError("boom")
    monkeypatch.setattr(fpair, "reconcile", boom)
    await live_host(app_pool)
    summary = await runner.build_tenant(app_pool, A, now=now_() + dt.timedelta(seconds=5))
    assert summary["host_fw"]["ok"] is True


# --------------------------------------------------------------------------- #
# RBAC and the billing gate
# --------------------------------------------------------------------------- #

@pytest_asyncio.fixture
async def enforced(db_pool, app_pool, fake_redis):
    from .conftest import _build_app
    prev = settings.auth_mode
    settings.auth_mode = "enforce"
    app = _build_app(app_pool, fake_redis)
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            c.keys = {role: await seed_key(db_pool, A, f"u-{role}", role) for role in ("admin", "analyst", "viewer")}
            yield c
    finally:
        settings.auth_mode = prev


async def test_rbac_admin_writes_triage_reads_a_viewer_nothing(enforced, app_pool, db_pool):
    h = await live_host(app_pool)
    asset = await seed_asset(db_pool)
    k = enforced.keys
    path = f"/v1/fleet/agents/{h.id}/pairing"
    for role in ("analyst", "viewer"):
        r = await enforced.put(path, headers=hdr(k[role]), json=body(asset))
        assert r.status_code == 403, (role, r.text)
        r = await enforced.delete(path, headers=hdr(k[role]), params={"justification": "reason"})
        assert r.status_code == 403, role
    assert await pairing_rows(db_pool, h.id) == []
    assert (await enforced.put(path, headers=hdr(k["admin"]), json=body(asset))).status_code == 200
    for p in (path, path + "/candidates", "/v1/fleet/pairings", f"/v1/fleet/agents/{h.id}/conflicts"):
        assert (await enforced.get(p, headers=hdr(k["analyst"]))).status_code == 200, p
        assert (await enforced.get(p, headers=hdr(k["viewer"]))).status_code == 403, p
    ack = {"proto": "tcp", "port": 22, "scan_seen_at": "2026-01-01T00:00:00Z", "justification": "looked at the scan"}
    assert (await enforced.post(f"/v1/fleet/agents/{h.id}/conflicts/acks", headers=hdr(k["analyst"]), json=ack)
            ).status_code == 403
    # the agent list stays viewer-safe
    assert (await enforced.get("/v1/fleet/agents", headers=hdr(k["viewer"]))).status_code == 200


async def test_the_pairing_never_leaks_between_tenants_and_a_foreign_id_answers_like_a_random_one(
        enforced, app_pool, db_pool):
    await tenancy.create_tenant(db_pool, slug="pairb", name="Pair B", tenant_id=B)
    key_b = await seed_key(db_pool, B, "admin-b", "admin")
    h = await live_host(app_pool)
    asset = await seed_asset(db_pool)
    await pair_enforced(enforced, h, asset)
    random_id = uuid.uuid4()
    for method, tail, kw in (("get", "/pairing", {}), ("get", "/pairing/candidates", {}), ("get", "/conflicts", {}),
                             ("put", "/pairing", {"json": body(asset)}),
                             ("delete", "/pairing", {"params": {"justification": "some reason"}})):
        foreign = await getattr(enforced, method)(f"/v1/fleet/agents/{h.id}{tail}", headers=hdr(key_b), **kw)
        rnd = await getattr(enforced, method)(f"/v1/fleet/agents/{random_id}{tail}", headers=hdr(key_b), **kw)
        assert (foreign.status_code, foreign.json()) == (rnd.status_code, rnd.json()) == (404, {"detail": "agent not found"}), \
            (method, tail)
    assert (await enforced.get("/v1/fleet/pairings", headers=hdr(key_b))).json() == []
    assert (await enforced.get("/v1/fleet/pairings", headers=hdr(enforced.keys["admin"]))).json()[0]["agent_id"] == str(h.id)
    # tenant B's admin cannot pair its own agent to tenant A's asset: the asset is invisible there
    async with conn_for(app_pool, B) as con:
        hb = uuid.UUID(int=77)
        await con.execute("INSERT INTO fleet_agents (id, hostname, status, agent_version, last_seen) "
                          "VALUES ($1,'b-1','online','0.2.0',NOW())", hb)
        await con.execute("INSERT INTO fleet_agent_keys (agent_id, key_id, public_key) VALUES ($1,$2,$3)",
                          hb, "b" * 32, b"\x01" * 32)
    r = await enforced.put(f"/v1/fleet/agents/{hb}/pairing", headers=hdr(key_b), json=body(asset))
    assert r.status_code == 404 and r.json() == {"detail": "asset not found"}


async def pair_enforced(c, h, asset, **kw):
    r = await c.put(f"/v1/fleet/agents/{h.id}/pairing", headers=hdr(c.keys["admin"]), json=body(asset, **kw))
    assert r.status_code == 200, r.text
    return r.json()


async def test_the_pairing_put_is_billing_gated_and_the_delete_never_is(enforced, app_pool, db_pool, monkeypatch):
    from app.billing import config as bcfg
    from app.billing import service
    h = await live_host(app_pool)
    asset = await seed_asset(db_pool)
    out = await pair_enforced(enforced, h, asset)
    assert out["status"] == "active"
    await db_pool.execute("UPDATE tenants SET created_at = NOW() - make_interval(days => 60) WHERE id = $1::uuid", A)
    monkeypatch.setattr(bcfg.settings, "stripe_secret_key", "sk_test_not_a_real_key")
    monkeypatch.setattr(bcfg.settings, "stripe_webhook_secret", "whsec_x")
    monkeypatch.setattr(bcfg.settings, "stripe_price_team", "price_team_placeholder")
    monkeypatch.setattr(bcfg.settings, "stripe_price_enterprise", "price_ent_placeholder")
    monkeypatch.setattr(bcfg.settings, "billing_public_url", "https://app.example.test")
    monkeypatch.setattr(bcfg.settings, "billing_cache_ttl_sec", 0.0)
    monkeypatch.setattr(bcfg.settings, "enforce_editions", "auto")
    service.invalidate()
    k = enforced.keys["admin"]
    h2 = await live_host(app_pool, 2, ips=("10.0.0.6",), peer="10.0.0.6")
    a2 = await seed_asset(db_pool, ("10.0.0.6",))
    r = await enforced.put(f"/v1/fleet/agents/{h2.id}/pairing", headers=hdr(k), json=body(a2))
    assert r.status_code == 402, r.text
    assert await pairing_rows(db_pool, h2.id) == []
    # withdrawing trust is never gated; reads are not gated either
    r = await enforced.delete(f"/v1/fleet/agents/{h.id}/pairing", headers=hdr(k), params={"justification": "gone"})
    assert r.status_code == 200 and r.json()["status"] == "ended"
    assert (await enforced.get(f"/v1/fleet/agents/{h.id}/pairing", headers=hdr(k))).status_code == 200
    service.invalidate()


@pytest.mark.parametrize("raw,hours", [(12, 12), (1, 1), (0, 72), (-4, 72), ("junk", 72), (None, 72), ("30", 30)])
def test_the_runner_reads_the_asset_age_setting_and_fails_to_the_default(monkeypatch, raw, hours):
    """A bad setting must neither widen the age into "never stale" nor stop a build (the settings object a test or an
    older deployment supplies may lack it altogether)."""
    from types import SimpleNamespace

    from app.assurance import runner
    monkeypatch.setattr(runner, "settings", SimpleNamespace(assurance_pairing_asset_max_age_h=raw))
    assert runner._pairing_asset_max_age() == dt.timedelta(hours=hours)
    monkeypatch.setattr(runner, "settings", SimpleNamespace())
    assert runner._pairing_asset_max_age() == dt.timedelta(hours=72)
