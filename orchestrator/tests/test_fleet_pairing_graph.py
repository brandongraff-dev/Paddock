"""P2.1 section 4.5 through the whole stack: pairing -> ``host_fw.load`` -> ``build`` -> ``store.persist_build`` ->
``graph_loader`` -> the REAL ``paddock_assurance`` library.

The facts, edges and coverage of a paired host land on ``asset:<uuid>`` (no ``agent:<uuid>`` node); its zone comes from
the asset's addresses and beats a lying claim; the host-firewall coverage sits NEXT TO the cloud coverage of the same
node (a different source); the std host invariants judge it at tier ``configured``; every P2 gate still applies (a
conflict, an inert pairing, a revocation, silence are UNKNOWN, never a pass).
"""
from __future__ import annotations

import datetime as dt
import json

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app import fleet_enroll as fe
from app import fleet_posture as fp
from app import tenancy
from app.assurance import runner
from app.assurance.types import BuildOutput, CoverageOut

from .test_assurance_host_fw_db import (FWD, SSH, conn_for, doc_of, evaluate, healthy, load_build, now_, persist, post,
                                        seed_host)
from .test_fleet_pairing import PRIV, PUB, pair, seed_asset

pytest.importorskip("paddock_assurance")
A = tenancy.DEFAULT_TENANT_ID
MIN = dt.timedelta(minutes=1)


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


async def paired_world(app_pool, db_pool, http, *, ips=(PRIV,), peer=PRIV, ack=False, **asset_kw):
    h = await seed_host(app_pool)
    t = now_()
    await post(app_pool, h, healthy(collected=t - MIN, seq=1, ips=list(ips)), now=t - MIN, ip=peer)
    asset = await seed_asset(db_pool, **asset_kw)
    r = await pair(http, h, asset, acknowledge_mismatch=ack)
    assert r.status_code == 200, r.text
    now = t + 10 * dt.timedelta(seconds=1)
    return h, asset, now


async def build_and_load(app_pool, now, **opts):
    rows, out = await load_build(app_pool, now=now, **opts)
    await persist(app_pool, out, now)
    return rows, out, await doc_of(app_pool, now)


def node_of(doc, ref):
    return next((n for n in doc["nodes"] if n["id"] == ref), None)


async def test_a_paired_host_is_the_asset_node_and_the_std_invariants_judge_it(app_pool, db_pool, http):
    h, asset, now = await paired_world(app_pool, db_pool, http)
    ref = f"asset:{asset}"
    rows, out, doc = await build_and_load(app_pool, now)
    assert [p["agent_id"] for p in rows.pairings] == [str(h.id)]
    assert node_of(doc, h.ref) is None                                  # the agent node is gone
    n = node_of(doc, ref)
    assert n is not None and "agent" in n["tags"] and {c["source"] for c in n["coverage"]} == {"host_fw"}
    assert set(n["facts"]) >= {"sshd", "firewall", "listeners", "patch", "host_agent"}
    assert n["facts"]["host_agent"]["data"]["identity_basis"] == "paired"
    for std_id in (SSH, FWD):
        r = evaluate(doc, std_id, now + MIN)
        assert r["verdict"] == "HOLDS" and r["evidence_tier"] == "configured", (std_id, r["reasons"])
    assert all(e["dst"] == ref for e in doc["edges"] if e["dst"] in (ref, h.ref))


async def test_the_zone_comes_from_the_assets_addresses_and_beats_a_lying_claim(app_pool, db_pool, http):
    async with conn_for(app_pool) as con:
        await con.execute("INSERT INTO zones (name, cidrs) VALUES ('pos', ARRAY['10.0.0.0/24'])")
        await con.execute("INSERT INTO zones (name, cidrs) VALUES ('guest', ARRAY['10.99.0.0/24'])")
    # the host CLAIMS a guest-zone address; the instance is in the pos zone (the operator acknowledges the mismatch)
    h, asset, now = await paired_world(app_pool, db_pool, http, ips=("10.99.0.7",), peer=PRIV, ack=True)
    _, _, doc = await build_and_load(app_pool, now)
    n = node_of(doc, f"asset:{asset}")
    assert n["zone"] == "pos" and not n.get("zone_unknown")
    # control: the same lie WITHOUT a pairing is not placed by the host's word (P2 behaviour: zone_unknown)
    h2 = await seed_host(app_pool, 2)
    await post(app_pool, h2, healthy(collected=now_(), seq=1, ips=["10.99.0.7"]), ip="10.0.0.9")
    _, _, doc = await build_and_load(app_pool, now)
    assert node_of(doc, h2.ref).get("zone_unknown") is True


async def test_host_coverage_sits_next_to_the_cloud_coverage_of_the_same_node(app_pool, db_pool, http):
    h, asset, now = await paired_world(app_pool, db_pool, http)
    ref = f"asset:{asset}"
    cloud = BuildOutput(source="aws_sg", mode="replace", coverage=[
        CoverageOut(node_ref=ref, direction="in", tier="configured", observed_at=now, source="aws_sg", detail={})])
    await persist(app_pool, cloud, now)
    _, _, doc = await build_and_load(app_pool, now)
    assert {c["source"] for c in node_of(doc, ref)["coverage"]} == {"aws_sg", "host_fw"}


async def test_a_scan_conflict_on_the_asset_node_is_unknown_and_an_ack_restores_it(app_pool, db_pool, http):
    from .test_assurance_host_fw_db import _persist_scan_edge
    h, asset, now = await paired_world(app_pool, db_pool, http)
    ref = f"asset:{asset}"
    await _persist_scan_edge(app_pool, ref, 8080, now - MIN)
    _, out, doc = await build_and_load(app_pool, now)
    assert out.coverage == [] and evaluate(doc, FWD, now + MIN)["verdict"] == "UNKNOWN"
    conflict = out.facts[0].facts["firewall"]["conflict"][0]
    r = await http.post(f"/v1/fleet/agents/{h.id}/conflicts/acks", json={
        "proto": "tcp", "port": 8080, "scan_seen_at": conflict["scan_seen_at"],
        "justification": "the scan hit the cloud load balancer in front of this instance"})
    assert r.status_code == 201, r.text
    _, out, doc = await build_and_load(app_pool, now)
    assert [c.node_ref for c in out.coverage] == [ref] and out.coverage[0].detail["acknowledged_conflicts"] == 1
    r = evaluate(doc, FWD, now + MIN)
    assert r["verdict"] == "HOLDS" and r["evidence_tier"] == "configured"


async def test_a_peer_mismatch_after_pairing_is_unknown_never_a_pass(app_pool, db_pool, http):
    h, asset, now = await paired_world(app_pool, db_pool, http)
    ref = f"asset:{asset}"
    _, _, doc = await build_and_load(app_pool, now)
    assert evaluate(doc, FWD, now + MIN)["verdict"] == "HOLDS"
    # the agent now connects directly from a private address that is not the asset's
    await post(app_pool, h, healthy(collected=now_(), seq=2, ips=[PRIV]), ip="10.9.9.9")
    _, out, doc = await build_and_load(app_pool, now + 20 * dt.timedelta(seconds=1))
    assert out.coverage == []
    f = out.facts[0].facts
    assert f["firewall"]["conflict"][0]["kind"] == "paired_peer_mismatch"
    r = evaluate(doc, FWD, now + MIN)
    assert r["verdict"] == "UNKNOWN" and ref in r["unproven_targets"]


async def test_an_inert_pairing_is_the_unpaired_behaviour_with_a_visible_note(app_pool, db_pool, http):
    h, asset, now = await paired_world(app_pool, db_pool, http)
    await db_pool.execute("UPDATE assets SET last_seen = NOW() - interval '100 hours' WHERE id = $1", asset)
    _, out, doc = await build_and_load(app_pool, now)
    assert node_of(doc, f"asset:{asset}") is None or "facts" not in node_of(doc, f"asset:{asset}")
    n = node_of(doc, h.ref)
    assert n is not None and n["facts"]["host_agent"]["data"]["identity_note"] == "pairing_inert:asset_stale"
    assert n["facts"]["host_agent"]["data"]["identity_basis"] == "claimed"


async def test_a_revoked_paired_host_stays_an_unknown_tombstone_on_the_asset(app_pool, db_pool, http):
    from .test_fleet_pairing import seed_finding
    h, asset, now = await paired_world(app_pool, db_pool, http)
    ref = f"asset:{asset}"
    await seed_finding(db_pool, SSH, ref)
    assert (await http.post(f"/v1/fleet/agents/{h.id}/revoke", json={})).status_code == 200
    _, out, doc = await build_and_load(app_pool, now)
    assert out.coverage == []
    n = node_of(doc, ref)
    assert n["facts"]["host_agent"]["data"]["agent_status"] == "revoked"
    r = evaluate(doc, SSH, now + MIN)
    assert r["verdict"] == "UNKNOWN" and r["violating_targets"] == []


async def test_the_runner_builds_a_paired_host_and_a_second_pass_changes_nothing(app_pool, db_pool, http):
    h, asset, now = await paired_world(app_pool, db_pool, http)
    first = await runner.build_tenant(app_pool, A, now=now)
    assert first["host_fw"]["ok"] is True and first["host_fw"]["facts_stored"] == 1
    again = await runner.build_tenant(app_pool, A, now=now + MIN)
    assert again["host_fw"]["ok"] is True and again["host_fw"]["changed"] is False
    assert again["host_fw"]["facts_changed"] == 0
    async with conn_for(app_pool) as con:
        refs_ = [r["node_ref"] for r in await con.fetch("SELECT node_ref FROM reach_node_facts WHERE source = 'host_fw'")]
    assert refs_ == [f"asset:{asset}"]
    assert json.dumps(PUB) and PUB                                       # (the asset's public address is not in the fact)
    async with conn_for(app_pool) as con:
        facts = await con.fetchval("SELECT facts::text FROM reach_node_facts WHERE source = 'host_fw'")
    assert PUB not in facts
