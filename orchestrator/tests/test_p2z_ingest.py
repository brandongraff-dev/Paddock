"""P2 round 2, Z-4 (DB-backed): the ingest's shared-peer lookup and the builder must agree on which agents share an
address, whatever spelling the stored peer has (``::ffff:10.0.1.5`` and ``10.0.1.5`` are one address)."""
from __future__ import annotations

import json

import pytest

from app.assurance.builders import _ipmap

from .test_assurance_host_fw_db import conn_for, healthy, post, seed_host
from .test_node_identity_a1 import NAT_PUBLIC, _agree, _node_ref, _seed_asset


@pytest.fixture(autouse=True)
def _private_peer_proof_on(monkeypatch):
    """The shared-peer lookup is about rule 3 of ``_ipmap.corroborate``, which only matters while a private peer
    counts as proof (OFF in production since review finding Z-2): switch it on for this module."""
    monkeypatch.setattr(_ipmap, "PRIVATE_PEER_IS_PROOF", True)


async def test_z4_the_stored_peer_is_the_normalised_address(app_pool):
    h = await seed_host(app_pool)
    await post(app_pool, h, healthy(ips=["10.0.9.9"]), ip="::ffff:10.0.1.5")
    assert (await _node_ref(app_pool, h))[1]["peer_ip"] == "10.0.1.5"
    h2 = await seed_host(app_pool, 2, hostname="two")
    await post(app_pool, h2, healthy(ips=["10.0.9.8"]), ip="2001:DB8:0:0::1")
    assert (await _node_ref(app_pool, h2))[1]["peer_ip"] == "2001:db8::1"


async def test_z4_a_mapped_and_a_plain_spelling_of_one_peer_are_one_shared_address(app_pool):
    """Agent A is stored with the v4-mapped spelling, B posts from the plain one. The builder merges the two forms and
    demotes both; the ingest must see A when B posts, so the column and the graph say the same thing."""
    await _seed_asset(app_pool, ["10.0.1.5"], [NAT_PUBLIC])
    a = await seed_host(app_pool, 1, hostname="a")
    b = await seed_host(app_pool, 2, hostname="b")
    await post(app_pool, a, healthy(ips=["10.0.9.9"]), ip="::ffff:10.0.1.5")
    await post(app_pool, b, healthy(ips=["10.0.1.5"]), ip="10.0.1.5")
    ref, ident = await _node_ref(app_pool, b)
    assert ref == f"agent:{b.id}" and ident["basis"] == "claimed" and ident["note"] == "shared_peer_address", \
        "the ingest missed the other agent behind the same address and merged B into the instance"
    await _agree(app_pool, a, b)


async def test_z4_a_row_stored_before_normalisation_is_still_found(app_pool):
    """Rows written by the previous build keep the raw spelling until their agent posts again."""
    await _seed_asset(app_pool, ["10.0.1.5"], [NAT_PUBLIC])
    a = await seed_host(app_pool, 1, hostname="a")
    b = await seed_host(app_pool, 2, hostname="b")
    await post(app_pool, a, healthy(ips=["10.0.9.9"]), ip="10.0.1.5")
    async with conn_for(app_pool) as con:
        await con.execute("UPDATE fleet_agents SET identity = jsonb_set(identity, '{peer_ip}', '\"::FFFF:10.0.1.5\"') "
                          "WHERE id = $1", a.id)
    await post(app_pool, b, healthy(ips=["10.0.1.5"]), ip="10.0.1.5")
    ref, ident = await _node_ref(app_pool, b)
    assert ref == f"agent:{b.id}" and ident["note"] == "shared_peer_address"
    await _agree(app_pool, a, b)


# --------------------------------------------------------------------------- #
# Z-7: a host an operator labels out of the selector is an OPT-OUT, and its open finding stays open
# --------------------------------------------------------------------------- #

from .test_assurance_host_fw_db import now_  # noqa: E402
from .test_p2x_lifecycle import FWD, _findings, _run, _two_violating_hosts  # noqa: E402


async def test_z7_a_host_labelled_out_of_the_selector_keeps_its_open_finding_open(app_pool, db_pool, fake_redis):
    """Declared ``agent=false`` (or ``server=false``) removes the host from ``tag: [agent, server]``. The verdict no
    longer judges it, but nothing PROVED it fixed, so its finding is not closed: it stays open until an operator closes
    it, or the host is selected again and evaluates PASS (docs/ASSURANCE_P2.md 13.4 item 6, owner decision (a))."""
    h1, h2 = await _two_violating_hosts(app_pool, db_pool, fake_redis)
    async with conn_for(app_pool) as con:
        for t_ in ("agent", "server"):          # a host selected by either tag must lose both to leave the selector
            await con.execute("INSERT INTO asset_labels (node_ref, tag, value, source) VALUES ($1,$2,'false','declared')",
                              h1.ref, t_)
    res = await _run(db_pool, fake_redis)
    assert res[FWD]["verdict"] == "VIOLATED"                       # h2 is still judged (and still violates)
    f = await _findings(db_pool)
    assert f[h1.ref]["status"] == "open", f[h1.ref]["status_reason"]
    assert f[h2.ref]["status"] == "open"
    # h2 is fixed: the invariant now HOLDS for the one host it judges; h1, which it no longer sees, stays open
    t = now_()
    from .test_assurance_host_fw_db import healthy, post
    await post(app_pool, h2, healthy(collected=t, seq=2, fw_default="drop"), now=t, ip="10.0.0.6")
    res = await _run(db_pool, fake_redis)
    assert res[FWD]["verdict"] == "HOLDS"
    f = await _findings(db_pool)
    assert f[h2.ref]["status"] == "fixed" and f[h1.ref]["status"] == "open"
