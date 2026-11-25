"""P2 adversarial review, package A1: node identity and corroboration that cannot be forged.

One regression test group per confirmed finding (the key is in the test name). Every test asserts the SAFE outcome:
an unsafe input must not produce a corroboration, a false HOLDS or a silent closure. The pure checks use no
database; the DB-backed ones share the fixtures of ``test_fleet_posture`` (two tenants, the real HTTP surface,
the RLS-enforcing role).
"""
from __future__ import annotations

import json
import pathlib
import uuid

import pytest
import yaml
from httpx import ASGITransport, AsyncClient
from starlette.requests import Request

from app import auth
from app.config import settings

REPO = pathlib.Path(__file__).resolve().parents[2]


def _req(peer: str, xff: str | None) -> Request:
    return Request({"type": "http", "client": (peer, 1234), "method": "GET", "path": "/",
                    "headers": [(b"x-forwarded-for", xff.encode())] if xff is not None else []})


def _helm_default_cidrs() -> str:
    values = yaml.safe_load((REPO / "deploy/helm/paddock/values.yaml").read_text())
    return str(values["config"]["trustedProxyCidrs"] or "")


def _set(monkeypatch, name, value):
    monkeypatch.setattr(settings, name, value, raising=False)


# =========================================================================== #
# wire-1: client_ip_strict must not skip XFF entries because they sit inside a trusted CIDR
# =========================================================================== #

FORGED = "198.51.100.77"          # the victim instance's public address, which the attacker writes into XFF


def test_wire_1_the_shipped_helm_default_does_not_let_a_private_host_forge_its_address(monkeypatch):
    """Under the CIDRs the Helm chart ships, a compromised host on a private address must not get the address it
    wrote into X-Forwarded-For back as 'the peer' (through the ingress, or connecting directly)."""
    cidrs = _helm_default_cidrs()
    _set(monkeypatch, "trusted_proxy_cidrs", cidrs)
    # through the ingress (10.0.0.2): the ingress appended the host's real address 10.0.1.9 after the forged entry
    assert auth.client_ip_strict(_req("10.0.0.2", f"{FORGED}, 10.0.1.9")) != FORGED
    # the same host connecting to the API directly from RFC1918 space with a forged header
    assert auth.client_ip_strict(_req("10.0.1.9", FORGED)) != FORGED
    # a forged entry in front of several private hops
    assert auth.client_ip_strict(_req("10.0.0.2", f"{FORGED}, 10.0.1.9, 10.0.0.7")) != FORGED


def test_wire_1_with_broad_private_cidrs_only_the_rightmost_entry_counts_through_a_proxy(monkeypatch):
    """Even if an operator trusts all of RFC1918, the entry a trusted proxy APPENDED is the one used, never the
    attacker-written one to its left."""
    _set(monkeypatch, "trusted_proxy_cidrs", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16")
    assert auth.client_ip_strict(_req("10.0.0.2", f"{FORGED}, 10.0.1.9")) == "10.0.1.9"
    assert auth.client_ip_strict(_req("10.0.0.2", f"{FORGED}, 10.0.1.9, 10.0.0.7")) == "10.0.0.7"


def test_wire_1_the_forged_entry_is_never_returned_for_any_hop_count(monkeypatch):
    """(A hop count larger than the real chain with a trusted range that also covers the hosts is an operator
    misconfiguration nothing can detect, so the range here is the proxies' own /24.)"""
    _set(monkeypatch, "trusted_proxy_cidrs", "10.0.0.0/24")
    for hops in (1, 2, 3):
        _set(monkeypatch, "trusted_proxy_hops", hops)
        for xff in (f"{FORGED}, 10.0.1.9", f"{FORGED}, 10.0.1.9, 10.0.0.7", f"{FORGED}, {FORGED}, 10.0.1.9",
                    f"{FORGED}, <junk>", ""):
            assert auth.client_ip_strict(_req("10.0.0.2", xff)) != FORGED, (hops, xff)


def test_wire_1_an_honest_host_behind_the_ingress_gets_its_own_address(monkeypatch):
    _set(monkeypatch, "trusted_proxy_cidrs", "10.0.0.2/32")             # the ingress only
    assert auth.client_ip_strict(_req("10.0.0.2", "10.0.1.5")) == "10.0.1.5"          # the ingress overwrote XFF
    assert auth.client_ip_strict(_req("10.0.0.2", "10.0.1.5, ")) == "10.0.0.2"        # an empty entry is junk: fail closed
    assert auth.client_ip_strict(_req("10.0.0.2", f"{FORGED}, 10.0.1.5")) == "10.0.1.5"   # the ingress appended
    # a peer that is not the trusted proxy is never believed
    assert auth.client_ip_strict(_req("10.0.1.9", FORGED)) == "10.0.1.9"


def test_wire_1_a_configured_hop_count_reads_the_nth_entry_from_the_right(monkeypatch):
    _set(monkeypatch, "trusted_proxy_cidrs", "10.0.0.0/24")
    _set(monkeypatch, "trusted_proxy_hops", 2)               # LB in front of the ingress, both append
    assert auth.client_ip_strict(_req("10.0.0.2", f"{FORGED}, 203.0.113.9, 10.0.0.9")) == "203.0.113.9"
    # the entries between the client and us must be the proxies we trust: otherwise the chain is not what the
    # operator configured (e.g. one proxy fewer) and the left entry would be the attacker's
    assert auth.client_ip_strict(_req("10.0.0.2", f"{FORGED}, 10.0.1.9")) == "10.0.0.2"
    assert auth.client_ip_strict(_req("10.0.0.2", "10.0.1.9")) == "10.0.0.2"           # shorter than the chain


def test_wire_1_garbage_and_missing_headers_fail_closed(monkeypatch):
    _set(monkeypatch, "trusted_proxy_cidrs", "10.0.0.2/32")
    assert auth.client_ip_strict(_req("10.0.0.2", f"{FORGED}, <script>")) == "10.0.0.2"
    assert auth.client_ip_strict(_req("10.0.0.2", "")) == "10.0.0.2"
    assert auth.client_ip_strict(_req("10.0.0.2", None)) == "10.0.0.2"
    _set(monkeypatch, "trusted_proxy_hops", 0)               # a nonsensical hop count is the default, not "skip all"
    assert auth.client_ip_strict(_req("10.0.0.2", f"{FORGED}, 10.0.1.9")) == "10.0.1.9"


# =========================================================================== #
# hostfw-2: a shared egress address is not proof of being an instance
# =========================================================================== #

from . import test_assurance_host_fw as T            # noqa: E402  (the builder fixtures, shared on purpose)
from . import test_assurance_external as X           # noqa: E402
from app.assurance import refs                      # noqa: E402
from app.assurance.builders import _ipmap           # noqa: E402
from app.assurance.builders import host_fw as hf    # noqa: E402

PRIV = "10.0.0.5"
NAT_PUBLIC = "93.184.216.34"          # globally routable (inert string): the NAT instance's public address


def _instance(n=100, priv=(PRIV,), pub=(NAT_PUBLIC,)):
    return T.cloud(n, priv=list(priv), pub=list(pub))


def _nodes_of(out):
    return sorted(f.node_ref for f in out.facts)


def _build(agents, assets, **kw):
    r = T.rows_of(*[(a, T.posture_row()) for a in agents], assets=assets)
    return hf.build(r, T.NOW, **kw)


def test_hostfw_2_a_public_peer_address_alone_never_corroborates():
    """B is another machine behind a NAT instance N: the server sees N's PUBLIC address. B claims N's private address.
    Before the fix B was merged into asset:N and N (no agent of its own) showed B's facts and inbound coverage."""
    inst = _instance()
    b = T.agent_row(1, ips=(PRIV,), peer=NAT_PUBLIC)
    out = _build([b], [inst])
    assert _nodes_of(out) == [T.ref1(1)], "merged into the instance on a public peer address alone"
    assert refs.asset_ref(inst["id"]) not in T.covered(out)
    assert out.facts[0].facts["host_agent"]["data"]["identity_basis"] == "claimed"


def test_hostfw_2_a_private_peer_address_of_the_instance_still_corroborates():
    inst = _instance()
    out = _build([T.agent_row(1, ips=(PRIV,), peer=PRIV)], [inst])
    assert _nodes_of(out) == [refs.asset_ref(inst["id"])]


def test_hostfw_2_two_agents_presenting_the_same_peer_address_are_not_corroborated():
    """A NAT/proxy instance with two enrolled agents behind it: the peer proves nothing about WHICH machine it is."""
    inst = _instance()
    a = T.agent_row(1, ips=(PRIV,), peer=PRIV, hostname="n")
    b = T.agent_row(2, ips=("10.0.9.9",), peer=PRIV, hostname="b")          # claims its OWN address, same peer
    out = _build([a, b], [inst])
    assert _nodes_of(out) == sorted([T.ref1(1), T.ref1(2)])
    assert refs.asset_ref(inst["id"]) not in T.covered(out)
    assert {f.facts["host_agent"]["data"]["identity_note"] for f in out.facts if f.node_ref == T.ref1(1)} \
        == {"shared_peer_address"}


def test_hostfw_2_the_ingest_decision_is_the_builders_decision():
    """One shared function decides (docs/ASSURANCE_P2.md E3): the same claims and assets give the same answer
    through ``_ipmap.corroborate`` as through the builder."""
    inst = _instance()
    amap = _ipmap.build_ip_map([inst])
    claims = [_ipmap.Claim("a1", (PRIV,), NAT_PUBLIC)]
    d = _ipmap.corroborate(claims, amap)["a1"]
    assert d.ref is None and d.note == "peer_address_not_instance"
    d = _ipmap.corroborate([_ipmap.Claim("a1", (PRIV,), PRIV)], amap)["a1"]
    assert d.ref == refs.asset_ref(inst["id"]) and d.note == ""


# =========================================================================== #
# hostfw-5 / wire-5: an uncorroborated claimer never demotes or clashes with a corroborated agent
# =========================================================================== #

def test_hostfw_5_an_uncorroborated_claimer_does_not_demote_the_corroborated_agent():
    inst = _instance()
    honest = T.agent_row(1, ips=(PRIV,), peer=PRIV, hostname="honest")
    liar = T.agent_row(2, ips=(PRIV,), peer="198.51.100.7", hostname="liar")       # fails its OWN peer check
    out = _build([honest, liar], [inst])
    assert refs.asset_ref(inst["id"]) in _nodes_of(out), "the honest agent was demoted by a claim that never passed"
    assert T.ref1(2) in _nodes_of(out)
    assert refs.asset_ref(inst["id"]) in T.covered(out)


def test_wire_5_overlapping_claims_only_clash_when_the_other_agent_passed_the_same_check():
    """(Replaces test_overlapping_claims_also_clash_even_if_the_second_is_not_itself_a_candidate, which encoded the
    rule this finding proves wrong.) A second agent whose peer is the instance's address DOES clash."""
    inst = _instance(priv=(PRIV, "10.0.0.6"))
    a = T.agent_row(1, ips=(PRIV,), peer=PRIV, hostname="a")
    unrelated = T.agent_row(2, ips=("10.0.0.6",), peer="198.51.100.1", hostname="b")
    assert refs.asset_ref(inst["id"]) in _nodes_of(_build([a, unrelated], [inst]))
    rival = T.agent_row(2, ips=("10.0.0.6",), peer="10.0.0.6", hostname="b")        # passes its own check too
    out = _build([a, rival], [inst])
    assert _nodes_of(out) == sorted([T.ref1(1), T.ref1(2)])


def test_hostfw_5_agent_claims_never_make_an_assets_address_ambiguous_in_the_shared_map():
    pub = X.A
    inst = X.cloud(ips_pub=[pub], ips_priv=["10.0.0.5"])
    claimer = {"id": T.aid(7), "kind": "agent", "node_ref": None, "identity": {"ips": [pub, "10.0.0.5"]}}
    m = _ipmap.build_ip_map([inst, claimer])
    assert not m.is_ambiguous(pub) and not m.is_ambiguous("10.0.0.5")
    assert m.resolve(pub) == refs.asset_ref(inst["id"])
    assert m.report() == []
    # the claim is still an over-approximation for EDGES: the claimant is one more candidate, never the owner
    assert refs.agent_ref(T.aid(7)) in m.resolve_all(pub) and refs.asset_ref(inst["id"]) in m.resolve_all(pub)


def test_hostfw_5_observed_scan_coverage_survives_a_claim_of_the_victims_public_address():
    pub = X.A
    inst = X.cloud(ips_pub=[pub])
    claimer = {"id": T.aid(7), "kind": "agent", "node_ref": None, "identity": {"ips": [pub]}}
    base = X.build(X.rows(scans=[X.scan(pub)], assets=[inst]))
    attacked = X.build(X.rows(scans=[X.scan(pub)], assets=[inst, claimer]))
    node = refs.asset_ref(inst["id"])
    assert [(c.node_ref, c.tier) for c in base.coverage] == [(node, "observed")]
    assert [(c.node_ref, c.tier) for c in attacked.coverage] == [(node, "observed")], attacked.notes


def test_hostfw_5_an_uncorroborated_claim_never_owns_an_address_so_it_never_gets_coverage_from_it():
    """A host that claims an address nobody owns used to become the unique owner (agent:B) and sentry coverage on the
    address was credited to agent:B. The claim is a hint for edges only."""
    claimer = {"id": T.aid(7), "kind": "agent", "node_ref": None, "identity": {"ips": ["10.5.5.5"]}}
    m = _ipmap.build_ip_map([claimer])
    assert m.resolve("10.5.5.5") == "ip:10.5.5.5"
    assert set(m.resolve_all("10.5.5.5")) == {"ip:10.5.5.5", refs.agent_ref(T.aid(7))}
    assert m.ips_of(refs.agent_ref(T.aid(7))) == ()


# =========================================================================== #
# the same decisions through the REAL ingest and the REAL loader (database)
# =========================================================================== #

from app import tenancy                              # noqa: E402
from .test_assurance_host_fw_db import (             # noqa: E402,F401
    A as TENANT, conn_for, doc_of, healthy, load_build, persist, post, seed_host)


async def _seed_asset(pool, private, public=(), rtype="instance"):
    async with conn_for(pool) as con:
        return str(await con.fetchval(
            "INSERT INTO assets (tenant_id, kind, value, canonical, source, metadata) "
            "VALUES ($1,'cloud_resource',$2,$2,'test',$3::jsonb) RETURNING id",
            TENANT, "i-" + uuid.uuid4().hex[:8],
            json.dumps({"resource_type": rtype, "private_ips": list(private), "public_ips": list(public)})))


async def _node_ref(pool, h):
    async with conn_for(pool) as con:
        r = await con.fetchrow("SELECT node_ref, identity FROM fleet_agents WHERE id=$1", h.id)
    ident = r["identity"] if isinstance(r["identity"], dict) else json.loads(r["identity"])
    return r["node_ref"], ident


async def _graph_refs(pool):
    """agent id -> the node ref the BUILDER gave it (from the facts it emits)."""
    _rows, out = await load_build(pool)
    return {f.facts["host_agent"]["data"]["agent_id"]: f.node_ref for f in out.facts}


async def _agree(pool, *hosts):
    """The column the ingest wrote and the graph the builder derives must say the same thing."""
    graph = await _graph_refs(pool)
    for h in hosts:
        col, _ = await _node_ref(pool, h)
        assert graph.get(str(h.id)) == col, f"{h.hostname}: fleet_agents.node_ref {col} vs graph {graph.get(str(h.id))}"


async def test_hostfw_2_ingest_a_public_peer_address_alone_does_not_corroborate(app_pool):
    inst = await _seed_asset(app_pool, ["10.0.1.5"], [NAT_PUBLIC])
    h = await seed_host(app_pool)
    await post(app_pool, h, healthy(ips=["10.0.1.5"]), ip=NAT_PUBLIC)
    ref, ident = await _node_ref(app_pool, h)
    assert ref == f"agent:{h.id}" and ident["basis"] == "claimed" and ident["note"] == "peer_address_not_instance"
    await _agree(app_pool, h)
    # control: the instance's own PRIVATE address as the peer corroborates
    h2 = await seed_host(app_pool, 2, hostname="web-2")
    await post(app_pool, h2, healthy(ips=["10.0.1.5"]), ip="10.0.1.5")
    assert (await _node_ref(app_pool, h2))[0] == f"asset:{inst}"
    await _agree(app_pool, h2)


async def test_hostfw_2_ingest_two_agents_sharing_a_peer_address_are_not_corroborated(app_pool):
    await _seed_asset(app_pool, ["10.0.1.5"], [NAT_PUBLIC])
    nat = await seed_host(app_pool, 1, hostname="nat")
    behind = await seed_host(app_pool, 2, hostname="behind")
    await post(app_pool, nat, healthy(ips=["10.0.1.5"]), ip="10.0.1.5")
    assert (await _node_ref(app_pool, nat))[0].startswith("asset:")               # alone at that address: corroborated
    await post(app_pool, behind, healthy(ips=["10.0.9.9"]), ip="10.0.1.5")       # another machine, same source address
    ref, ident = await _node_ref(app_pool, nat)
    assert ref == f"agent:{nat.id}" and ident["basis"] == "claimed", "the shared peer address still corroborated"
    assert ident["note"] == "shared_peer_address"
    await _agree(app_pool, nat, behind)


async def test_wire_5_ingest_an_uncorroborated_claimer_does_not_demote_the_corroborated_agent(app_pool):
    inst = await _seed_asset(app_pool, ["10.0.1.5"], ["54.1.2.3"])
    honest = await seed_host(app_pool, 1, hostname="honest")
    liar = await seed_host(app_pool, 2, hostname="liar")
    await post(app_pool, honest, healthy(ips=["10.0.1.5"]), ip="10.0.1.5")
    assert (await _node_ref(app_pool, honest))[0] == f"asset:{inst}"
    await post(app_pool, liar, healthy(ips=["10.0.1.5"]), ip="198.51.100.7")        # claims it, from elsewhere
    assert (await _node_ref(app_pool, honest))[0] == f"asset:{inst}", "demoted by a claim that never passed"
    assert (await _node_ref(app_pool, liar))[0] == f"agent:{liar.id}"
    await _agree(app_pool, honest, liar)
    # and the graph keeps the honest host on the instance
    assert (await _graph_refs(app_pool))[str(honest.id)] == f"asset:{inst}"


async def test_wire_5_ingest_two_agents_that_both_pass_merge_neither_and_the_column_follows(app_pool):
    await _seed_asset(app_pool, ["10.0.1.5", "10.0.1.6"])
    a = await seed_host(app_pool, 1, hostname="a")
    b = await seed_host(app_pool, 2, hostname="b")
    await post(app_pool, a, healthy(ips=["10.0.1.5"]), ip="10.0.1.5")
    assert (await _node_ref(app_pool, a))[0].startswith("asset:")
    await post(app_pool, b, healthy(ips=["10.0.1.6"]), ip="10.0.1.6")               # a different private address of the instance
    assert (await _node_ref(app_pool, a))[0] == f"agent:{a.id}" and (await _node_ref(app_pool, b))[0] == f"agent:{b.id}"
    await _agree(app_pool, a, b)


async def test_hostfw_5_ingest_and_builder_agree_over_a_scenario_matrix(app_pool):
    inst = await _seed_asset(app_pool, ["10.0.1.5", "10.0.1.6"], [NAT_PUBLIC])
    hosts = [await seed_host(app_pool, i, hostname=f"h{i}") for i in range(1, 6)]
    plan = [(["10.0.1.5"], "10.0.1.5"), (["10.0.1.6"], NAT_PUBLIC), (["10.0.1.5"], "198.51.100.7"),
            (["10.0.1.99"], "10.0.1.5"), ([], "10.0.1.5")]
    for h, (ips, peer) in zip(hosts, plan):
        await post(app_pool, h, healthy(ips=ips), ip=peer)
        await _agree(app_pool, *hosts[: hosts.index(h) + 1])
    await _agree(app_pool, *hosts)
    assert inst


# =========================================================================== #
# a finding follows its host when the host's node_ref changes (agent:<uuid> <-> asset:<uuid>)
# =========================================================================== #

from .test_assurance_findings import AG1, by_target, hres, hsync, hw, rows as finding_rows   # noqa: E402


async def _instance_asset(pool) -> str:
    return str(await pool.fetchval(
        "INSERT INTO assets (tenant_id, kind, value, canonical, source, metadata) "
        "VALUES ($1,'cloud_resource','i-follow','i-follow','test','{}'::jsonb) RETURNING id", TENANT))


async def _follow(pool, moves):
    from app.assurance import finding_follow
    async with pool.acquire() as con:
        return await finding_follow.migrate_targets(con, moves)


async def test_a_finding_follows_its_host_from_the_agent_node_to_the_asset_node(db_pool, fake_redis):
    await hsync(db_pool, fake_redis, hres("VIOLATED", [hw(AG1)], violating=[AG1]))
    (before,) = await finding_rows(db_pool)
    x = await _instance_asset(db_pool)
    moved = await _follow(db_pool, {AG1: f"asset:{x}"})
    assert moved == 1
    (after,) = await finding_rows(db_pool)
    assert after["id"] == before["id"] and after["status"] == "open"        # the SAME finding (tickets, SLA age, history)
    assert by_target([after]) == {f"asset:{x}": "open"} and str(after["asset_id"]) == x
    assert after["rule_id"] == "invariant:std:server-ssh-hardened" and after["first_seen"] == before["first_seen"]
    # the next evaluation, now naming the asset node, refreshes THAT finding: nothing closes, nothing reopens
    rep = await hsync(db_pool, fake_redis, hres("VIOLATED", [hw(f"asset:{x}")], violating=[f"asset:{x}"]), version=8)
    assert (rep.opened, rep.closed, rep.reopened) == (0, 0, 0)
    assert len(await finding_rows(db_pool)) == 1


async def test_a_finding_follows_its_host_back_from_the_asset_node_to_the_agent_node(db_pool, fake_redis):
    x = await _instance_asset(db_pool)
    ax = f"asset:{x}"
    await hsync(db_pool, fake_redis, hres("VIOLATED", [hw(ax)], violating=[ax]))
    (before,) = await finding_rows(db_pool)
    assert await _follow(db_pool, {ax: AG1}) == 1
    (after,) = await finding_rows(db_pool)
    assert after["id"] == before["id"] and by_target([after]) == {AG1: "open"} and after["a_kind"] == "org"
    rep = await hsync(db_pool, fake_redis, hres("VIOLATED", [hw(AG1)], violating=[AG1]), version=8)
    assert (rep.opened, rep.closed, rep.reopened) == (0, 0, 0) and len(await finding_rows(db_pool)) == 1


async def test_following_never_overwrites_a_finding_that_already_exists_at_the_destination(db_pool, fake_redis):
    x = await _instance_asset(db_pool)
    ax = f"asset:{x}"
    await hsync(db_pool, fake_redis, hres("VIOLATED", [hw(AG1), hw(ax)], violating=[AG1, ax]))
    assert len(await finding_rows(db_pool)) == 2
    assert await _follow(db_pool, {AG1: ax}) == 0                         # the key is taken: nothing is merged or lost
    assert by_target(await finding_rows(db_pool)) == {AG1: "open", ax: "open"}


async def test_following_leaves_closed_findings_and_other_hosts_alone(db_pool, fake_redis):
    other = f"agent:{uuid.UUID(int=2)}"
    await hsync(db_pool, fake_redis, hres("VIOLATED", [hw(AG1), hw(other)], violating=[AG1, other]))
    # AG1 closes: it is named in passing_targets (hostfw-4: a host that is merely absent from the lists never closes)
    await hsync(db_pool, fake_redis, hres("VIOLATED", [hw(other)], violating=[other], passing=[AG1]), version=8)
    assert by_target(await finding_rows(db_pool)) == {AG1: "fixed", other: "open"}
    x = await _instance_asset(db_pool)
    assert await _follow(db_pool, {AG1: f"asset:{x}", "agent:not-a-uuid": f"asset:{x}", AG1 + "x": "ip:1.2.3.4"}) == 0
    assert by_target(await finding_rows(db_pool)) == {AG1: "fixed", other: "open"}


# =========================================================================== #
# wire-1 through the real HTTP surface: the finding's exact repro, and the honest case
# =========================================================================== #

from .test_fleet_posture import (                    # noqa: E402,F401
    _reset_limiters, agent_row as fleet_agent_row, enforce, enroll_host, good_posture, jd, ps, rls_app, world,
    _seed_instance as seed_instance)

LEGACY_HELM_CIDRS = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"      # what the chart used to ship


def _client(app, peer: str) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app, client=(peer, 5555)), base_url="http://test")


async def _post_via(app, world_, host, xff, *, peer, ips):
    async with _client(app, peer) as c:
        r = await c.post(f"/v1/fleet/{host.agent_id}/posture",
                         headers={"X-Agent-Token": host.token, "Content-Type": "application/json",
                                  "X-Forwarded-For": xff},
                         content=json.dumps(host.env("posture", good_posture(ips=ips))))
    assert r.status_code == 200, r.text


async def _enrolled(world_, name="h"):
    return await enroll_host(world_.client, world_.admin_a, name)


@pytest.mark.parametrize("cidrs", [_helm_default_cidrs(), LEGACY_HELM_CIDRS], ids=["shipped_default", "legacy_default"])
async def test_wire_1_a_private_host_cannot_forge_the_peer_it_is_corroborated_from(world, rls_app, monkeypatch, cidrs):
    """The finding's repro: victim instance 10.0.1.5 / 198.51.100.77 with no agent of its own; a compromised host
    claims 10.0.1.5 and sends X-Forwarded-For: 198.51.100.77 through the ingress (10.0.0.2)."""
    monkeypatch.setattr(settings, "trusted_proxy_cidrs", cidrs)
    victim = await seed_instance(world.db, ["10.0.1.5"], [FORGED])
    host = await _enrolled(world)
    await _post_via(rls_app, world, host, f"{FORGED}, 10.0.1.9", peer="10.0.0.2", ips=["10.0.1.5"])
    a = await fleet_agent_row(world.db, host.agent_id)
    ident = jd(a["identity"])
    assert a["node_ref"] == f"agent:{host.agent_id}" and a["node_ref"] != f"asset:{victim}"
    assert ident["basis"] == "claimed" and ident["peer_ip"] != FORGED


async def test_wire_1_a_host_connecting_directly_from_a_private_address_cannot_forge_it_either(world, rls_app,
                                                                                               monkeypatch):
    monkeypatch.setattr(settings, "trusted_proxy_cidrs", _helm_default_cidrs())
    victim = await seed_instance(world.db, ["10.0.1.5"], [FORGED])
    host = await _enrolled(world)
    await _post_via(rls_app, world, host, FORGED, peer="10.0.1.9", ips=["10.0.1.5"])
    a = await fleet_agent_row(world.db, host.agent_id)
    assert a["node_ref"] == f"agent:{host.agent_id}" and jd(a["identity"])["peer_ip"] == "10.0.1.9"
    assert victim


@pytest.mark.parametrize("xff", ["10.0.1.5", f"{FORGED}, 10.0.1.5"], ids=["ingress_overwrites", "ingress_appends"])
async def test_wire_1_an_honest_host_behind_the_ingress_is_still_corroborated(world, rls_app, monkeypatch, xff):
    monkeypatch.setattr(settings, "trusted_proxy_cidrs", "10.0.0.2/32")        # the ingress only
    inst = await seed_instance(world.db, ["10.0.1.5"], ["54.1.2.3"])
    host = await _enrolled(world)
    await _post_via(rls_app, world, host, xff, peer="10.0.0.2", ips=["10.0.1.5"])
    a = await fleet_agent_row(world.db, host.agent_id)
    assert a["node_ref"] == f"asset:{inst}" and jd(a["identity"])["basis"] == "corroborated"
    assert jd(a["identity"])["peer_ip"] == "10.0.1.5"


# =========================================================================== #
# hostfw-1: what a host says about its own addresses must not decide its zone or CIDR membership
# =========================================================================== #

import datetime as _dt                                # noqa: E402
import importlib                                      # noqa: E402
from app.assurance import graph_loader as gl          # noqa: E402

_ZONES = [{"id": "1", "name": "pos", "kind": "custom", "cidrs": ["10.10.0.0/24"], "description": "",
           "source": "declared", "created_by": None, "created_at": None, "updated_at": None},
          {"id": "2", "name": "guest", "kind": "custom", "cidrs": ["10.99.0.0/24"], "description": "",
           "source": "declared", "created_by": None, "created_at": None, "updated_at": None}]
_GUEST_CANNOT_REACH_POS = """
apiVersion: paddock.dev/invariant/v1
id: acme:guest-cannot-reach-pos
title: guest cannot reach pos
subjects: { from: { zone: guest }, to: { zone: pos } }
assert: unreachable
evidence: { min_tier: observed, max_age: 24h }
coverage: { require: 0 }
"""


def _segmentation_doc(claimed, *, peer=None, label=None, extra_edges=()):
    """B accepts SSH from the guest zone (a violation if B is in pos). Only what B CLAIMS (and the server saw) varies."""
    a = T.agent_row(1, ips=(claimed,), peer=peer)
    fw = T.fw_section([T.chain([T.acc(proto="tcp", dport=[[22, 22]], src=["10.99.0.0/24"])])])
    out = hf.build(T.rows_of((a, T.posture_row(T.sections(firewall=fw)))), T.NOW)
    nodes = [{"node_ref": n.ref, "kind": n.kind, "asset_id": None, "attrs": json.dumps(n.attrs)} for n in out.nodes]
    nodes += [{"node_ref": "ip:10.10.0.50", "kind": "ip", "asset_id": None, "attrs": "{}"},
              {"node_ref": "ip:10.99.0.9", "kind": "ip", "asset_id": None, "attrs": "{}"}]
    edges = [{"src_ref": e.src_ref, "dst_ref": e.dst_ref, "proto": e.proto, "port_lo": e.port_lo,
              "port_hi": e.port_hi, "basis": e.basis, "source": e.source} for e in out.edges] + list(extra_edges)
    cov = [{"node_ref": c.node_ref, "direction": c.direction, "tier": c.tier, "observed_at": c.observed_at,
            "source": c.source, "detail": json.dumps(c.detail)} for c in out.coverage]
    for r in ("ip:10.10.0.50", "ip:10.99.0.9", "cidr:10.99.0.0/24"):
        cov.append({"node_ref": r, "direction": "both", "tier": "observed", "observed_at": T.NOW - T.MIN,
                    "source": "sentry", "detail": "{}"})
    facts = [{"node_ref": f.node_ref, "source": f.source, "tier": f.tier, "observed_at": f.observed_at,
              "facts": json.dumps(f.facts)} for f in out.facts]
    labels = [{"node_ref": T.ref1(1), "tag": "zone", "value": label, "source": "declared"}] if label else []
    snap = {"state": {"graph_version": 1}, "nodes": nodes, "edges": edges, "cov": cov, "facts": facts,
            "labels": labels, "zones": _ZONES}
    return gl._assemble(snap, {}, T.NOW)


def _verdict(doc) -> str:
    C = importlib.import_module("paddock_assurance.compile")
    E = importlib.import_module("paddock_assurance.evaluate")
    G = importlib.import_module("paddock_assurance.graph")
    v = E.evaluate(C.compile_text(_GUEST_CANNOT_REACH_POS), G.ReachGraph.from_dict(doc), T.NOW).verdict
    return getattr(v, "value", str(v))


def _node(doc, ref):
    return next(n for n in doc["nodes"] if n["id"] == ref)


@pytest.mark.parametrize("claimed", ["10.1.2.3", "192.168.5.5", "172.17.0.1"])
def test_hostfw_1_a_claimed_address_never_removes_a_host_from_a_cidr_rule(claimed):
    """B really sits in 10.0.0.0/8; whatever it claims, ``cidr:10.0.0.0/8 -> DB`` must include it as a source."""
    rule = {"src_ref": "cidr:10.0.0.0/8", "dst_ref": "ip:10.10.0.50", "proto": "tcp", "port_lo": 5432,
            "port_hi": 5432, "basis": "configured", "source": "aws_sg"}
    doc, _diag = _segmentation_doc(claimed, extra_edges=[rule])
    into_db = {e["src"] for e in doc["edges"] if e["dst"] == "ip:10.10.0.50"}
    assert T.ref1(1) in into_db, f"the claim {claimed} took B out of the CIDR rule"


def test_hostfw_1_a_hosts_claimed_address_does_not_decide_its_zone_when_the_server_saw_it_elsewhere():
    """B is really in pos (the server saw it connect from 10.10.0.7) and claims a guest/unzoned address."""
    verdicts = {}
    for claimed in ("10.10.0.7", "10.99.0.7", "192.168.77.7", "172.17.0.1"):
        doc, _ = _segmentation_doc(claimed, peer="10.10.0.7")
        assert _node(doc, T.ref1(1)).get("zone") == "pos", (claimed, _node(doc, T.ref1(1)))
        verdicts[claimed] = _verdict(doc)
    assert set(verdicts.values()) == {"VIOLATED"}, verdicts          # never HOLDS: B is a pos host guest can reach


def test_hostfw_1_a_declared_zone_label_overrides_any_claim():
    for claimed in ("10.99.0.7", "192.168.77.7"):
        doc, _ = _segmentation_doc(claimed, label="pos")
        assert _node(doc, T.ref1(1))["zone"] == "pos"
        assert _verdict(doc) == "VIOLATED"


def test_hostfw_1_the_node_carries_no_address_so_the_loader_reads_it_as_unknown():
    doc, diag = _segmentation_doc("10.10.0.7", peer="10.10.0.7")
    out = hf.build(T.rows_of((T.agent_row(1, ips=("10.10.0.7",), peer="10.10.0.7"), T.posture_row())), T.NOW)
    node = next(n for n in out.nodes if n.ref == T.ref1(1))
    assert node.attrs["ips"] == [] and node.attrs["claimed_ips"] == ["10.10.0.7"]
    assert node.attrs["observed_ips"] == ["10.10.0.7"]


def test_hostfw_1_a_zone_that_rests_on_the_hosts_own_claim_alone_is_reported_not_silent():
    """No label, no independent address: the claim is the only hint left. It still places an honest host (so it is
    not dropped from every zone-selected invariant) but the loader says that the placement is unverified."""
    doc, diag = _segmentation_doc("10.10.0.7", peer=None)
    assert _node(doc, T.ref1(1)).get("zone") == "pos"
    assert diag.zone_from_claim == [T.ref1(1)]
    doc, diag = _segmentation_doc("10.10.0.7", peer="10.99.0.7")      # the server saw it in guest: that wins, conflict kept
    assert _node(doc, T.ref1(1)).get("zone") == "guest"
    assert diag.zone_conflicts.get(T.ref1(1)) == ["guest", "pos"] and diag.zone_from_claim == []


def test_hostfw_1_a_stale_node_row_that_still_lists_claimed_addresses_cannot_narrow_cidr_membership():
    """Rows written by an older build (or another builder) may still carry ``attrs.ips`` for an agent node."""
    nodes = [{"node_ref": T.ref1(1), "kind": "host", "asset_id": None, "attrs": json.dumps({"ips": ["192.168.5.5"]})},
             {"node_ref": "ip:10.10.0.50", "kind": "ip", "asset_id": None, "attrs": "{}"}]
    edges = [{"src_ref": "cidr:10.0.0.0/8", "dst_ref": "ip:10.10.0.50", "proto": "tcp", "port_lo": 5432,
              "port_hi": 5432, "basis": "configured", "source": "aws_sg"}]
    snap = {"state": {"graph_version": 1}, "nodes": nodes, "edges": edges, "cov": [], "facts": [], "labels": [],
            "zones": _ZONES}
    doc, _ = gl._assemble(snap, {}, T.NOW)
    assert T.ref1(1) in {e["src"] for e in doc["edges"] if e["dst"] == "ip:10.10.0.50"}
    assert "zone" not in _node(doc, T.ref1(1))


# =========================================================================== #
# hostfw-9: identity resolution is O(n), walk results are reused across builds, verification stays off the loop,
# and one agent cannot ask for a rebuild at will
# =========================================================================== #

import asyncio                                        # noqa: E402
import time                                           # noqa: E402


def test_hostfw_9_identity_resolution_is_linear_in_the_number_of_agents():
    n = 4000
    assets = [T.cloud(1000 + i, priv=[f"10.{i // 250}.{i % 250}.5"]) for i in range(n)]
    agents = [T.agent_row(i + 1, ips=(f"10.{i // 250}.{i % 250}.5",), peer=f"10.{i // 250}.{i % 250}.5")
              for i in range(n)]
    amap = _ipmap.build_ip_map(assets)
    t0 = time.perf_counter()
    idents = hf._resolve_identities(agents, amap)
    took = time.perf_counter() - t0
    assert sum(1 for i in idents.values() if i.basis == "corroborated") == n
    assert took < 1.5, f"{took:.2f}s for {n} agents: identity resolution is not linear"


def test_hostfw_9_a_walk_result_is_reused_by_the_next_build_with_the_same_firewall(monkeypatch):
    calls = []
    real = hf._compute_reach

    def counting(fw, lst, addressable):
        calls.append(1)
        return real(fw, lst, addressable)

    monkeypatch.setattr(hf, "_compute_reach", counting)
    hf._REACH_CACHE.clear()
    first = hf.build(T.rows_of((T.agent_row(1), T.posture_row())), T.NOW)
    second = hf.build(T.rows_of((T.agent_row(1), T.posture_row()), (T.agent_row(2, ips=("10.0.0.6",)), T.posture_row())),
                      T.NOW)
    assert len(calls) == 1, "the same firewall and listeners were walked again in the next build"
    assert [e.src_ref for e in first.edges] == [e.src_ref for e in second.edges if e.dst_ref == T.ref1(1)]
    # a different listener table is a different walk
    other = T.sections(listeners=T.lis_section()) if hasattr(T, "lis_section") else T.sections()
    hf.build(T.rows_of((T.agent_row(3), T.posture_row(other))), T.NOW)
    assert len(calls) >= 1


async def test_hostfw_9_verifying_stored_postures_never_blocks_the_event_loop(monkeypatch):
    class Conn:
        def __init__(self):
            self.n = 0

        async def fetch(self, sql, *args):
            if sql is hf.AGENTS_SQL:
                return [{"id": uuid.UUID(int=i + 1), "hostname": f"h{i}", "status": "online", "legacy": False,
                         "revoked_at": None, "last_seen": T.NOW, "silent_after_s": 300, "node_ref": None,
                         "identity": {"ips": []}, "last_posture_at": T.NOW, "agent_version": "0.2.0"}
                        for i in range(20)]
            if sql is hf.POSTURE_SQL:
                return [{"agent_id": a, "key_id": "k", "seq": 1, "collected_at": T.NOW, "received_at": T.NOW,
                         "signed": True, "key_status": "active", "payload_sha256": "a" * 64} for a in args[0]]
            return []

    def slow_verify(row):
        time.sleep(0.05)                      # what a hostile, very large posture costs to parse and verify
        return False, "unverified", None

    monkeypatch.setattr(hf, "_verify_stored", slow_verify)
    gaps: list[float] = []
    stop = asyncio.Event()

    async def ticker():
        last = time.perf_counter()
        while not stop.is_set():
            await asyncio.sleep(0.005)
            now = time.perf_counter()
            gaps.append(now - last)
            last = now

    task = asyncio.create_task(ticker())
    await asyncio.sleep(0.02)
    await hf.load(Conn(), T.NOW)
    stop.set()
    await task
    assert max(gaps) < 0.04, f"the event loop stalled for {max(gaps) * 1000:.0f} ms while verifying postures"


async def test_hostfw_9_one_agent_cannot_re_queue_a_rebuild_on_every_post(app_pool):
    from app import fleet_posture as fp
    fp.reset_limiters()
    h = await seed_host(app_pool)
    async with conn_for(app_pool) as con:
        await con.execute("INSERT INTO assurance_state (last_build_at) VALUES (NOW()) "
                          "ON CONFLICT (tenant_id) DO UPDATE SET last_build_at = NOW()")

    async def stamp():
        async with conn_for(app_pool) as con:
            return await con.fetchval("SELECT last_build_at FROM assurance_state")

    async def rebuild_requested():
        return (await stamp()) is None

    async def settle():
        async with conn_for(app_pool) as con:
            await con.execute("UPDATE assurance_state SET last_build_at = NOW()")

    requested = 0
    for i in range(6):
        await post(app_pool, h, healthy(ips=[], security=i + 1))       # a content change on every post
        requested += 1 if await rebuild_requested() else 0
        await settle()
    assert requested == 1, f"{requested} rebuilds requested by one agent in a burst of 6 changed postures"


# =========================================================================== #
# REWORK ROUND (verifier report): multi-line XFF, proxied peers never corroborate or place a host, the claim-only
# zone gap is reported, and a finding follows its host only for host-config invariants
# =========================================================================== #

def _req_lines(peer: str, lines: list[str], extra: dict[str, str] | None = None) -> Request:
    headers = [(b"x-forwarded-for", ln.encode()) for ln in lines]
    headers += [(k.encode(), v.encode()) for k, v in (extra or {}).items()]
    return Request({"type": "http", "client": (peer, 1234), "method": "GET", "path": "/", "headers": headers})


def test_wire_1_two_x_forwarded_for_header_lines_are_read_as_one_list(monkeypatch):
    """A proxy that adds its own X-Forwarded-For LINE instead of appending to the client's (HAProxy style): the
    client-written first line must not be the one believed. Before the fix only the first line was read."""
    _set(monkeypatch, "trusted_proxy_cidrs", "10.0.0.2/32")
    _set(monkeypatch, "trusted_proxy_hops", 1)
    assert auth.client_ip_strict(_req_lines("10.0.0.2", [FORGED, "10.0.1.9"])) == "10.0.1.9"
    assert auth.client_ip_strict(_req_lines("10.0.0.2", [f"{FORGED}, 203.0.113.9", "10.0.1.9"])) == "10.0.1.9"
    _set(monkeypatch, "trusted_proxy_hops", 2)
    assert auth.client_ip_strict(_req_lines("10.0.0.2", [FORGED, "203.0.113.9", "10.0.0.2"])) == "203.0.113.9"
    # an empty extra line is junk: fail closed to the peer, never to the client-written line
    _set(monkeypatch, "trusted_proxy_hops", 1)
    assert auth.client_ip_strict(_req_lines("10.0.0.2", [FORGED, ""])) == "10.0.0.2"


def test_hostfw_2_a_peer_that_may_be_a_proxy_is_marked_so(monkeypatch):
    """The returned address carries whether it is a TCP peer of an endpoint host (``proxied`` False) or the address
    of something that may be forwarding for others (a forwarding header the server does not trust, a peer that is
    itself a trusted proxy, a client entry inside the trusted range)."""
    _set(monkeypatch, "trusted_proxy_cidrs", "")
    _set(monkeypatch, "trusted_proxy_hops", 1)
    assert auth.client_ip_strict(_req("10.42.0.5", None)).proxied is False                  # a plain connection
    got = auth.client_ip_strict(_req("10.42.0.5", "198.51.100.9"))
    assert got == "10.42.0.5" and got.proxied is True, "an untrusted peer that sent X-Forwarded-For is a proxy"
    for header in ("forwarded", "x-real-ip", "via", "x-forwarded-proto"):
        got = auth.client_ip_strict(_req_lines("10.42.0.5", [], {header: "1.2.3.4"}))
        assert got.proxied is True, header
    _set(monkeypatch, "trusted_proxy_cidrs", "10.0.0.2/32")
    got = auth.client_ip_strict(_req("10.0.0.2", "10.0.1.5"))                               # the honest case
    assert got == "10.0.1.5" and got.proxied is False
    got = auth.client_ip_strict(_req("10.0.0.2", None))                                     # the proxy itself
    assert got == "10.0.0.2" and got.proxied is True
    got = auth.client_ip_strict(_req("10.0.0.2", "10.0.0.2"))                               # the client IS a proxy
    assert got.proxied is True
    got = auth.client_ip_strict(_req("10.0.0.2", "not-an-ip"))                              # junk: the proxy again
    assert got == "10.0.0.2" and got.proxied is True
    got = auth.client_ip_strict(_req("10.0.1.9", FORGED))                                   # untrusted peer + header
    assert got == "10.0.1.9" and got.proxied is True
    assert auth.client_ip_strict(_req("10.0.0.2", "10.0.1.5")) == "10.0.1.5"                # still a plain str


def _proxied(agent, flag=True):
    agent["identity"]["peer_proxied"] = flag
    return agent


def test_hostfw_2_a_proxied_peer_address_never_corroborates():
    """The verifier's single-agent bypass: the instance IS the ingress/NAT box, every request carries its private
    address, and the only enrolled agent claims it. The shared-address rule needs a SECOND agent; this one does not."""
    inst = _instance()
    a = _proxied(T.agent_row(1, ips=(PRIV,), peer=PRIV))
    out = _build([a], [inst])
    assert _nodes_of(out) == [T.ref1(1)], "corroborated from an address that may belong to a proxy"
    idents = hf._resolve_identities([a], _ipmap.build_ip_map([inst]))
    assert idents[T.aid(1)].basis == "claimed" and idents[T.aid(1)].note == "peer_not_direct"
    # control: the same agent seen directly still corroborates (the honest case is not lost)
    b = T.agent_row(1, ips=(PRIV,), peer=PRIV)
    assert _nodes_of(_build([b], [inst])) == [refs.asset_ref(inst["id"])]


def test_hostfw_2_a_proxied_agent_still_counts_as_sharing_its_peer_address():
    """A proxied agent presents the proxy's address: it still makes the address 'shared' for the direct agent."""
    inst = _instance()
    direct = T.agent_row(1, ips=(PRIV,), peer=PRIV)
    behind = _proxied(T.agent_row(2, ips=("10.9.9.9",), peer=PRIV))
    idents = hf._resolve_identities([direct, behind], _ipmap.build_ip_map([inst]))
    assert idents[T.aid(1)].basis == "claimed" and idents[T.aid(1)].note == "shared_peer_address"


def test_hostfw_1_a_proxied_peer_is_not_a_zone_hint():
    """The ingress address is not evidence about WHERE the host is (verifier's low finding): only a direct,
    unique private peer becomes ``observed_ips``."""
    inst = []
    a = _proxied(T.agent_row(1, ips=("10.10.0.7",), peer="10.99.0.1"))
    idents = hf._resolve_identities([a], _ipmap.build_ip_map(inst))
    assert idents[T.aid(1)].observed == []
    b = T.agent_row(1, ips=("10.10.0.7",), peer="10.99.0.1")
    assert hf._resolve_identities([b], _ipmap.build_ip_map(inst))[T.aid(1)].observed == ["10.99.0.1"]


def test_hostfw_1_a_host_whose_zone_nothing_independent_supports_is_listed_as_unplaced():
    """No label, no direct unique private peer, a claim that matches no zone: the node has no zone at all. It must be
    on the diagnostics list the runner reads, never silently absent from every zone selector."""
    doc, diag = _segmentation_doc("192.168.77.7", peer=None)
    assert "zone" not in _node(doc, T.ref1(1))
    assert T.ref1(1) in diag.zone_unplaced
    doc, diag = _segmentation_doc("10.10.0.7", peer=None)            # placed by its own claim only: reported too
    assert T.ref1(1) in diag.zone_from_claim and T.ref1(1) not in diag.zone_unplaced
    doc, diag = _segmentation_doc("192.168.77.7", peer="10.10.0.7")  # the server saw it in pos: placed, not unplaced
    assert T.ref1(1) not in diag.zone_unplaced and _node(doc, T.ref1(1))["zone"] == "pos"


@pytest.mark.xfail(strict=True, reason="deferred (needs a library 'zone unknown' state): a lying host with no "
                                       "label and no usable peer is simply in no zone, so the zone selector misses it")
@pytest.mark.parametrize("peer", [None, "203.0.113.5", "127.0.0.1", "10.0.0.9"])
def test_hostfw_1_residual_a_lie_with_no_usable_peer_is_not_a_false_holds(peer):
    doc, _ = _segmentation_doc("192.168.77.7", peer=peer)           # B really is in pos and accepts guest SSH
    assert _verdict(doc) != "HOLDS"


async def _plain_post(app, host, ips, *, peer, headers=None):
    async with _client(app, peer) as c:
        r = await c.post(f"/v1/fleet/{host.agent_id}/posture",
                         headers={"X-Agent-Token": host.token, "Content-Type": "application/json", **(headers or {})},
                         content=json.dumps(host.env("posture", good_posture(ips=ips))))
    assert r.status_code == 200, r.text


async def test_hostfw_2_the_only_agent_behind_the_shared_ingress_address_is_not_corroborated(world, rls_app,
                                                                                            monkeypatch):
    """The verifier's probe (a): default Helm (no trusted proxies), the ingress node is an inventoried instance with
    private address 10.42.0.5, the ONLY enrolled agent claims 10.42.0.5, every request arrives from 10.42.0.5."""
    monkeypatch.setattr(settings, "trusted_proxy_cidrs", _helm_default_cidrs())
    ingress = await seed_instance(world.db, ["10.42.0.5"], [])
    host = await _enrolled(world)
    await _plain_post(rls_app, host, ["10.42.0.5"], peer="10.42.0.5", headers={"X-Forwarded-For": "203.0.113.50"})
    a = await fleet_agent_row(world.db, host.agent_id)
    ident = jd(a["identity"])
    assert a["node_ref"] == f"agent:{host.agent_id}" and a["node_ref"] != f"asset:{ingress}"
    assert ident["basis"] == "claimed" and ident["note"] == "peer_not_direct" and ident["peer_proxied"] is True


async def test_hostfw_2_a_host_that_connects_directly_from_the_instances_private_address_is_still_corroborated(
        world, rls_app, monkeypatch):
    monkeypatch.setattr(settings, "trusted_proxy_cidrs", _helm_default_cidrs())
    inst = await seed_instance(world.db, ["10.42.0.5"], [])
    host = await _enrolled(world)
    await _plain_post(rls_app, host, ["10.42.0.5"], peer="10.42.0.5")
    a = await fleet_agent_row(world.db, host.agent_id)
    assert a["node_ref"] == f"asset:{inst}" and jd(a["identity"])["peer_proxied"] is False


async def test_hostfw_2_the_graph_and_the_column_agree_for_a_proxied_peer(app_pool):
    from app.auth import ClientAddr
    await _seed_asset(app_pool, ["10.0.1.5"], [NAT_PUBLIC])
    h = await seed_host(app_pool)
    await post(app_pool, h, healthy(ips=["10.0.1.5"]), ip=ClientAddr("10.0.1.5", proxied=True))
    ref, ident = await _node_ref(app_pool, h)
    assert ref == f"agent:{h.id}" and ident["note"] == "peer_not_direct"
    await _agree(app_pool, h)
    await post(app_pool, h, healthy(ips=["10.0.1.5"], security=3), ip="10.0.1.5")   # now seen directly: corroborated
    assert (await _node_ref(app_pool, h))[0].startswith("asset:")
    await _agree(app_pool, h)


async def _seed_finding(pool, invariant, target, witness):
    """A live invariant finding on ``target`` with the evidence shape ``findings_sync`` writes."""
    from app.assurance.findings_sync import asset_uuid, rule_id_for, ESTATE_KIND, ESTATE_VALUE
    aid = asset_uuid(target)
    if aid is None:
        asset = await pool.fetchval(
            "INSERT INTO assets (tenant_id, kind, value, canonical, source, metadata) "
            "VALUES ($1,$2,$3,$3,'test','{}'::jsonb) ON CONFLICT (tenant_id, kind, canonical) "
            "DO UPDATE SET last_seen = NOW() RETURNING id", TENANT, ESTATE_KIND, ESTATE_VALUE)
    else:
        asset = aid
    ev = {"invariant": invariant, "target_ref": target, "witness": witness, "verdict": "VIOLATED"}
    return await pool.fetchval(
        "INSERT INTO findings (tenant_id, asset_id, rule_id, rule_source, severity, title, description, status, evidence, "
        "metadata) VALUES ($1,$2,$3,'invariant','high','t','d','open',$4::jsonb,$5::jsonb) RETURNING id",
        TENANT, asset, rule_id_for(invariant, target, estate=aid is None), json.dumps(ev),
        json.dumps({"invariant_id": invariant, "target_ref": target}))


async def test_wire_5_following_moves_only_host_config_findings_not_the_assets_other_findings(db_pool, fake_redis):
    """A cloud-sourced reachability finding on asset:X must stay on asset:X when the HOST's node ref changes."""
    x = await _instance_asset(db_pool)
    ax = f"asset:{x}"
    from .test_assurance_findings import reach_witness
    cloud = await _seed_finding(db_pool, "acme:no-internet-to-db", ax, reach_witness(ax))
    cover = await _seed_finding(db_pool, "std:coverage-complete", ax,
                                {"hops": [], "weakest_basis": "unknown", "confirmed": False,
                                 "detail": {"node": ax, "direction": "in", "reason": "no_sensor"}})
    host = await _seed_finding(db_pool, "std:server-ssh-hardened", ax, hw(ax))
    assert await _follow(db_pool, {ax: AG1}) == 1, "only the host-config finding follows the host"
    by_id = {r["id"]: json.loads(r["evidence"])["target_ref"] for r in await finding_rows(db_pool)}
    assert by_id[cloud] == ax and by_id[cover] == ax and by_id[host] == AG1
