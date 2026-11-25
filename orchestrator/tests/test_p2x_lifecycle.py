"""P2 adversarial-review regressions: finding lifecycle and the host_fw builder (hostfw-3, -4, -6, -7, -8).

Each test failed against the unmodified source for the reason in its docstring (see the work package report).
Product rules under test: HOLDS means "no counterexample under this evidence", UNKNOWN never becomes HOLDS,
and a finding never closes by ABSENCE (a host that leaves the graph, is oversized, revoked, re-keyed ... is
not a host that was proven fixed).
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import ipaddress
import json
import uuid

import pytest

from app.assurance import findings_sync as fs
from app.assurance import store
from app.assurance.builders import host_fw as hf

from .test_assurance_findings import AG1, AG2, AG3, NOW, by_target, hres, hsync, hw, rows

UTC = dt.timezone.utc


def with_passing(res, passing=(), truncated=False):
    res["passing_targets"] = sorted(passing)
    res["passing_truncated"] = truncated
    return res


# --------------------------------------------------------------------------- #
# hostfw-4: a finding never closes by absence (findings_sync)
# --------------------------------------------------------------------------- #

async def test_holds_closes_only_targets_evaluated_as_passing(db_pool, fake_redis):
    """hostfw-4 (HOLDS path): AG1 left the graph (revoked) and is in no list at all; before the fix a HOLDS
    closed it ('invariant holds at graph version 3'). Only AG2, in passing_targets, may close."""
    await hsync(db_pool, fake_redis, hres("VIOLATED", [hw(AG1), hw(AG2)], violating=[AG1, AG2]))
    rep = await hsync(db_pool, fake_redis, with_passing(hres("HOLDS"), [AG2]), version=8)
    assert rep.closed == 1
    assert by_target(await rows(db_pool)) == {AG1: "open", AG2: "fixed"}
    (fixed,) = [r for r in await rows(db_pool) if r["status"] == "fixed"]
    assert "passing" in fixed["status_reason"] or "passes" in fixed["status_reason"]
    # honest return of AG1 (it now evaluates PASS): it closes with a clear reason
    rep = await hsync(db_pool, fake_redis, with_passing(hres("HOLDS"), [AG1, AG2]), version=9)
    assert rep.closed == 1 and set(by_target(await rows(db_pool)).values()) == {"fixed"}


@pytest.mark.parametrize("why,patch", [
    ("no list", lambda r: (r.pop("passing_targets"), r.pop("passing_truncated"))),
    ("bad list", lambda r: r.update(passing_targets=[1, 2])),
    ("not a list", lambda r: r.update(passing_targets="agent:x")),
    ("truncated", lambda r: r.update(passing_truncated=True)),
])
async def test_holds_without_a_trustworthy_passing_list_closes_nothing(db_pool, fake_redis, why, patch):
    """hostfw-4: an older library (no passing_targets) or a capped list closes nothing on HOLDS."""
    await hsync(db_pool, fake_redis, hres("VIOLATED", [hw(AG1)], violating=[AG1]))
    res = with_passing(hres("HOLDS"), [AG1])
    patch(res)
    rep = await hsync(db_pool, fake_redis, res, version=8)
    assert rep.closed == 0 and rep.close_skipped in ("no_target_list", "truncated"), why
    assert by_target(await rows(db_pool)) == {AG1: "open"}


async def test_holds_never_closes_a_passing_target_that_is_also_blind_or_unproven(db_pool, fake_redis):
    await hsync(db_pool, fake_redis, hres("VIOLATED", [hw(AG1), hw(AG2)], violating=[AG1, AG2]))
    res = with_passing(hres("HOLDS", unproven=[AG1], blind=[(AG2, "approximate", "firewall")]), [AG1, AG2])
    rep = await hsync(db_pool, fake_redis, res, version=8)
    assert rep.closed == 0 and by_target(await rows(db_pool)) == {AG1: "open", AG2: "open"}


async def test_violated_closes_only_targets_proven_passing(db_pool, fake_redis):
    """hostfw-4 (VIOLATED path): AG1 vanished from the graph (in neither violating, unproven nor passing), AG3 is
    now evaluated PASS, AG2 still violates. Before the fix both AG1 and AG3 closed ('no longer violating')."""
    await hsync(db_pool, fake_redis, hres("VIOLATED", [hw(AG1), hw(AG2), hw(AG3)], violating=[AG1, AG2, AG3]))
    res = with_passing(hres("VIOLATED", [hw(AG2)], violating=[AG2]), [AG3])
    rep = await hsync(db_pool, fake_redis, res, version=8)
    assert rep.closed == 1
    assert by_target(await rows(db_pool)) == {AG1: "open", AG2: "open", AG3: "fixed"}


async def test_violated_without_a_passing_list_closes_nothing_for_host_config(db_pool, fake_redis):
    await hsync(db_pool, fake_redis, hres("VIOLATED", [hw(AG1), hw(AG2)], violating=[AG1, AG2]))
    res = hres("VIOLATED", [hw(AG2)], violating=[AG2])
    del res["passing_targets"], res["passing_truncated"]            # a library that predates the list
    rep = await hsync(db_pool, fake_redis, res, version=8)
    assert rep.closed == 0 and rep.close_skipped
    assert by_target(await rows(db_pool)) == {AG1: "open", AG2: "open"}
    res = with_passing(hres("VIOLATED", [hw(AG2)], violating=[AG2]), [AG1], truncated=True)
    rep = await hsync(db_pool, fake_redis, res, version=9)
    assert rep.closed == 0 and by_target(await rows(db_pool)) == {AG1: "open", AG2: "open"}


# --------------------------------------------------------------------------- #
# hostfw-4, end to end: real ingest, real builder, real library, real runner
# --------------------------------------------------------------------------- #

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from app import fleet_posture as fp  # noqa: E402
from app.assurance import runner  # noqa: E402

from .test_assurance_host_fw_db import (  # noqa: E402
    A, MIN, conn_for, healthy, load_build, now_, post, seed_host,
)
from .test_fleet_posture import kid_of, pubkey  # noqa: E402

FWD = "std:server-default-deny-inbound"


async def _findings(pool):
    return {r["tgt"]: dict(r) for r in await pool.fetch(
        "SELECT status, status_reason, fix_verified_at, evidence->>'target_ref' AS tgt FROM findings "
        "WHERE rule_source = 'invariant' ORDER BY evidence->>'target_ref'")}


async def _run(db_pool, fake_redis):
    s = await runner.evaluate_tenant(db_pool, A, force=True, rebuild=True, redis=fake_redis)
    assert not s["errors"], s["errors"]
    return {r["invariant_id"]: r for r in s["results"]}


async def _two_violating_hosts(app_pool, db_pool, fake_redis):
    """Two enrolled hosts whose firewall accepts inbound by default; ``std:server-default-deny-inbound`` is on.
    (The SSH invariant needs the agent's ``daemon`` block, which this tree's ingest schema does not accept yet;
    the lifecycle under test is the same for every host-config invariant.)"""
    h1, h2 = await seed_host(app_pool, 1), await seed_host(app_pool, 2)
    async with conn_for(app_pool) as con:
        await runner.install_std(con, FWD)
    t = now_()
    await post(app_pool, h1, healthy(collected=t, seq=1, fw_default="accept"), now=t)
    await post(app_pool, h2, healthy(collected=t, seq=1, fw_default="accept"), now=t, ip="10.0.0.6")
    res = await _run(db_pool, fake_redis)
    assert res[FWD]["verdict"] == "VIOLATED", res[FWD]
    f = await _findings(db_pool)
    assert {k: v["status"] for k, v in f.items()} == {h1.ref: "open", h2.ref: "open"}
    return h1, h2


async def test_revoking_a_host_does_not_close_its_finding_when_the_rest_of_the_fleet_holds(
        app_pool, db_pool, fake_redis):
    """hostfw-4 (HOLDS path): the revoked host dropped out of the selector, the other host is clean, the verdict
    was HOLDS and the revoked host's finding closed as 'fixed'. Now it stays open and the verdict is UNKNOWN."""
    h1, h2 = await _two_violating_hosts(app_pool, db_pool, fake_redis)
    t = now_()
    await post(app_pool, h2, healthy(collected=t, seq=2, fw_default="drop"), now=t, ip="10.0.0.6")
    await fp.revoke_agent(app_pool, h1.id, actor="admin", actor_role="admin", reason="decommission")
    res = await _run(db_pool, fake_redis)
    assert res[FWD]["verdict"] == "UNKNOWN", res[FWD]
    f = await _findings(db_pool)
    assert f[h1.ref]["status"] == "open", f[h1.ref]


async def test_revoking_a_host_does_not_close_its_finding_while_others_still_violate(
        app_pool, db_pool, fake_redis):
    """hostfw-4 (VIOLATED path): 'no longer violating ... still has 1 other violating target(s)' for a host that
    merely left the graph."""
    h1, h2 = await _two_violating_hosts(app_pool, db_pool, fake_redis)
    await fp.revoke_agent(app_pool, h1.id, actor="admin", actor_role="admin", reason="decommission")
    res = await _run(db_pool, fake_redis)
    assert res[FWD]["verdict"] == "VIOLATED"
    f = await _findings(db_pool)
    assert f[h1.ref]["status"] == "open", f[h1.ref]["status_reason"]
    assert f[h2.ref]["status"] == "open"


async def test_a_tombstone_reads_unknown_and_an_honest_reenrollment_that_passes_closes_with_a_reason(
        app_pool, db_pool, fake_redis):
    h1, h2 = await _two_violating_hosts(app_pool, db_pool, fake_redis)
    t = now_()
    await post(app_pool, h2, healthy(collected=t, seq=2, fw_default="drop"), now=t, ip="10.0.0.6")
    await fp.revoke_agent(app_pool, h1.id, actor="admin", actor_role="admin", reason="decommission")
    rows, out = await load_build(app_pool)
    tomb = {f.node_ref: f for f in out.facts}[h1.ref]
    assert tomb.facts["host_agent"]["status"] == "unavailable"
    assert tomb.facts["host_agent"]["data"]["agent_status"] == "revoked"
    assert h1.ref in {n.ref for n in out.nodes} and not [c for c in out.coverage if c.node_ref == h1.ref]
    res = await _run(db_pool, fake_redis)
    assert res[FWD]["verdict"] == "UNKNOWN"
    assert (await _findings(db_pool))[h1.ref]["status"] == "open"
    # an operator re-enrolls the host honestly (re-key token: same agent id, a NEW key, revoked_at cleared)
    h1.sk = Ed25519PrivateKey.generate()
    await db_pool.execute(
        "UPDATE fleet_agents SET status = 'online', revoked_at = NULL, revoked_by = NULL, last_seen = NOW() "
        "WHERE id = $1", h1.id)
    await db_pool.execute("INSERT INTO fleet_agent_keys (agent_id, key_id, public_key) VALUES ($1, $2, $3)",
                          h1.id, kid_of(h1.sk), pubkey(h1.sk))
    t = now_()
    await post(app_pool, h1, healthy(collected=t, seq=50, fw_default="drop"), now=t, seq=50)
    await post(app_pool, h2, healthy(collected=t, seq=3, fw_default="drop"), now=t, ip="10.0.0.6")
    res = await _run(db_pool, fake_redis)
    assert res[FWD]["verdict"] == "HOLDS", res[FWD]
    f = await _findings(db_pool)
    assert {v["status"] for v in f.values()} == {"fixed"}
    assert "passing" in f[h1.ref]["status_reason"]


async def test_a_revoked_host_without_an_open_finding_is_not_kept_in_the_graph(app_pool, db_pool, fake_redis):
    """The tombstone exists to protect an open finding; a revoked host that has none (a decommissioned
    autoscaling instance) must not stay in the graph for ever."""
    h1 = await seed_host(app_pool, 1)
    t = now_()
    await post(app_pool, h1, healthy(collected=t, seq=1, fw_default="drop"), now=t)
    await fp.revoke_agent(app_pool, h1.id, actor="admin", actor_role="admin", reason="decommission")
    rows, out = await load_build(app_pool)
    assert out.facts == [] and rows.tombstones == []


# --------------------------------------------------------------------------- #
# hostfw-6: a pure re-sign of an unchanged posture is not a change
# --------------------------------------------------------------------------- #

from app.assurance import graph_loader  # noqa: E402

from .test_assurance_host_fw import agent_row, posture_row  # noqa: E402


def _host_agent_entry(**data):
    base = {"agent_id": "a", "hostname": "h", "identity_basis": "claimed", "key_id": "k", "seq": 7,
            "payload_sha256": "a" * 64, "collected_at": "2026-12-01T11:58:00Z", "silent_after_s": 300,
            "firewall": {"engine": "nft", "exact": True, "reasons": []},
            "listeners": {"count": 1, "complete": True}, "coverage": {"granted": True, "blocked_by": []},
            "conflicts": []}
    base.update(data)
    return store.normalise_fact_entry("host_agent", {
        "status": "ok", "signed": True, "key_id": "k", "seq": base["seq"], "evidence_ref": f"p:{base['seq']}",
        "conf": "exact", "partial": False, "data": base})


def test_the_host_agent_provenance_keys_are_not_part_of_the_fact_digest():
    """hostfw-6: data.seq / payload_sha256 / collected_at moved with every re-signed posture and so bumped the
    graph version hourly ('row digest equal: False')."""
    a = _host_agent_entry()
    b = _host_agent_entry(seq=8, payload_sha256="b" * 64, collected_at="2026-12-01T12:58:00Z")
    assert store.fact_row_digest("configured", {"host_agent": a}) == store.fact_row_digest("configured", {"host_agent": b})
    # ... and the graph document hash agrees (the runner re-evaluates on a changed hash)
    def doc(e):
        return {"nodes": [{"id": "agent:x", "facts": {"host_agent": {k: v for k, v in e.items()}}}]}
    assert graph_loader.doc_sha(doc(a)) == graph_loader.doc_sha(doc(b))
    # a real change still changes both
    for over in ({"coverage": {"granted": False, "blocked_by": ["conflict"]}},
                 {"conflicts": [{"kind": "agent_closed_scan_open", "proto": "tcp", "port": 1}]},
                 {"firewall": {"engine": "nft", "exact": False, "reasons": ["x"]}}, {"key_id": "other"}):
        c = _host_agent_entry(**over)
        assert store.fact_row_digest("configured", {"host_agent": c}) != store.fact_row_digest("configured", {"host_agent": a}), over
        assert graph_loader.doc_sha(doc(c)) != graph_loader.doc_sha(doc(a)), over


def test_a_new_scan_time_inside_the_conflict_list_of_the_summary_is_not_a_change():
    c1 = {"kind": "agent_closed_scan_open", "proto": "tcp", "port": 1, "scan_seen_at": "2026-12-01T11:00:00Z"}
    c2 = dict(c1, scan_seen_at="2026-12-01T11:30:00Z")
    a, b = _host_agent_entry(conflicts=[c1]), _host_agent_entry(conflicts=[c2])
    assert store.fact_row_digest("configured", {"host_agent": a}) == store.fact_row_digest("configured", {"host_agent": b})


async def test_a_re_signed_identical_posture_does_not_bump_the_graph_version(app_pool, db_pool):
    """hostfw-6, through the real ingest, builder and store: 'refresh persist: changed True version 2 facts_changed 1'."""
    h = await seed_host(app_pool, 1)
    t0 = now_() - 90 * MIN
    await post(app_pool, h, healthy(collected=t0, seq=1), now=t0)
    first = await runner.build_tenant(app_pool, A)
    assert first["host_fw"]["ok"] is True and first["host_fw"]["facts_changed"] == 1
    t1 = now_() - 5 * MIN
    r = await post(app_pool, h, healthy(collected=t1, seq=2), now=t1)
    assert r.stored, r                                           # stored again (an hour later), content unchanged
    again = await runner.build_tenant(app_pool, A)
    assert again["host_fw"]["ok"] is True
    assert again["host_fw"]["facts_changed"] == 0 and again["host_fw"]["changed"] is False, again["host_fw"]


# --------------------------------------------------------------------------- #
# hostfw-7: an oversized fact row is never dropped, the host stays in scope as UNKNOWN
# --------------------------------------------------------------------------- #

from app.assurance.types import BuildOutput, FactOut, NodeOut  # noqa: E402

from .test_assurance_host_fw import lis_section, listener, one, sections  # noqa: E402


def _fat_out(ref, fat_bytes=300_000, *, collector="sshd"):
    ent = {"status": "ok", "signed": True, "key_id": "k", "seq": 3, "evidence_ref": "p:3", "conf": "exact",
           "partial": False, "data": {"blob": ["x" * 900 for _ in range(fat_bytes // 900)]}}
    small = dict(ent, data={"agent_id": "a"})
    return BuildOutput(source="host_fw", mode="replace", nodes=[NodeOut(ref=ref, kind="host", label="h")],
                       facts=[FactOut(node_ref=ref, source="host_fw", tier="configured",
                                      observed_at=dt.datetime(2026, 12, 1, tzinfo=UTC),
                                      facts={collector: ent, "host_agent": small})])


def test_an_oversized_fact_row_keeps_the_host_with_an_error_entry_for_the_big_collector():
    """hostfw-7: 'skipped facts agent:...: facts larger than 262144 bytes' dropped the WHOLE row, so the host left
    the std host invariants (no agent tag) and a violating host read HOLDS."""
    ref = "agent:00000000-0000-0000-0000-000000000001"
    rep = store.BuildReport()
    rows = store._clean_facts(_fat_out(ref), rep)
    assert list(rows) == [ref], rep.notes
    entries = rows[ref]["entries"]
    assert set(entries) == {"sshd", "host_agent"}
    assert entries["sshd"]["status"] == "error" and entries["sshd"]["reason"] == "facts_too_large"
    assert entries["sshd"]["conf"] == "approximate" and entries["sshd"]["partial"] is True
    assert entries["sshd"]["signed"] is False and entries["sshd"]["data"] == {}
    assert entries["host_agent"]["data"] == {"agent_id": "a"}          # the small entry is untouched
    assert len(rows[ref]["facts"]) <= store.MAX_FACT_ROW_BYTES
    assert any("facts_too_large" in n for n in rep.notes) and rep.skipped >= 1


def test_every_collector_oversized_still_leaves_a_tagged_row():
    ref = "agent:00000000-0000-0000-0000-000000000001"
    out = _fat_out(ref, collector="listeners")
    out.facts[0].facts["host_agent"]["data"] = {"blob": ["y" * 900 for _ in range(400)]}
    out = dataclasses.replace(out, facts=[out.facts[0]])
    rep = store.BuildReport()
    rows = store._clean_facts(out, rep)
    assert list(rows) == [ref]
    assert set(rows[ref]["entries"]) == {"listeners", "host_agent"}
    assert all(e["status"] == "error" and e["reason"] == "facts_too_large" for e in rows[ref]["entries"].values())


def test_a_row_whose_every_entry_is_invalid_still_leaves_the_host_with_an_error_entry():
    ref = "agent:00000000-0000-0000-0000-000000000001"
    out = _fat_out(ref)
    out = dataclasses.replace(out, facts=[dataclasses.replace(out.facts[0], facts={"sshd": {"status": "bogus"}})])
    rep = store.BuildReport()
    rows = store._clean_facts(out, rep)
    assert list(rows) == [ref] and set(rows[ref]["entries"]) == {"host_agent"}
    assert rows[ref]["entries"]["host_agent"]["status"] == "error"


def test_a_big_listener_table_is_capped_counted_and_reads_as_incomplete():
    """hostfw-7: every listener (up to 2000) was copied into the fact, so a few thousand binds overflowed the row."""
    rows = [listener(1000 + i, ip=f"::ffff:10.{i // 250}.{i % 250}.1", bind="specific", comm="�" * 15)
            for i in range(1500)]
    out = one(sections(listeners=lis_section(rows)))
    d = out.facts[0].facts["listeners"]["data"]
    assert len(d["listeners"]) == hf.MAX_FACT_LISTENERS == 200
    assert d["count"] == 1500 and d["omitted"] == 1300             # count != len(rows): the library reads it as partial
    assert all(len(r["ip"]) <= 20 for r in d["listeners"])                # the 45-character spelling is normalised
    assert ipaddress.ip_address(d["listeners"][0]["ip"]) == ipaddress.ip_address("::ffff:10.0.0.1")
    rep = store.BuildReport()
    stored = store._clean_facts(out, rep)
    assert len(stored) == 1 and len(next(iter(stored.values()))["facts"]) < 100_000, rep.notes


# --------------------------------------------------------------------------- #
# hostfw-8: a rule token the builder does not recognise widens, it never silently "does not match"
# --------------------------------------------------------------------------- #

from .test_assurance_host_fw import acc, chain, edges_of, fw_section  # noqa: E402


def _edges_for(rule_match):
    secs = sections(firewall=fw_section([chain([acc(**rule_match)])]))
    return one(secs)


_TCP22 = {"proto": "tcp", "dport": [[22, 22]]}


@pytest.mark.parametrize("m", [
    {**_TCP22, "proto": "TCP"}, {**_TCP22, "proto": "6"}, {**_TCP22, "proto": "Tcp"}, {**_TCP22, "proto": "tcp "},
    {**_TCP22, "proto": "p6"}, {**_TCP22, "proto": "p256"}, {**_TCP22, "proto": "all"},
    {**_TCP22, "proto": "ipv6-icmp"},
    # ('ospf' used to be listed here: an honest ``-p ospf`` rule widened every listener. It is a real protocol name
    # of /etc/protocols and now stays exact: test_p2z_builder.py (Z-5) and the exact list below.)
    {**_TCP22, "ct": ["NEW"]}, {**_TCP22, "ct": ["weird"]}, {**_TCP22, "ct": ["new", "weird"]},
    {**_TCP22, "dtype": ["LOCAL"]}, {**_TCP22, "dtype": ["loopback"]},
])
def test_an_unrecognised_token_widens_instead_of_dropping_the_rule(m):
    """hostfw-8: accept tcp/22 with proto 'TCP' (or '6', ct ['NEW'], ...) on a default-drop chain: 'edges=[]
    and coverage=1' while the canonical spelling gives internet and cidr:0.0.0.0/0 edges at 100."""
    out = _edges_for(m)
    e = edges_of(out, "tcp")
    assert ("internet", "tcp", 22, 22, hf.CONF_MAYBE) in e or ("cidr:0.0.0.0/0", "tcp", 22, 22, hf.CONF_MAYBE) in e, \
        (m, e)
    assert all(c == hf.CONF_MAYBE for *_x, c in e), (m, e)          # never an exact (100) claim from an unread token


@pytest.mark.parametrize("m,matches", [
    ({**_TCP22}, True), ({**_TCP22, "ct": ["new", "established"]}, True), ({**_TCP22, "dtype": ["local"]}, True),
    ({**_TCP22, "ct": ["invalid", "related", "untracked"]}, False),      # canonical and exact: never a NEW packet
    ({**_TCP22, "dtype": ["anycast", "broadcast", "multicast", "unicast"]}, False),
    ({**_TCP22, "proto": "sctp"}, False),                                   # canonical, another protocol
])
def test_canonical_tokens_stay_exact(m, matches):
    e = edges_of(_edges_for(m), "tcp")
    if matches:
        assert ("internet", "tcp", 22, 22, hf.CONF_ALLOW) in e, e
    else:
        assert e == [], e


@pytest.mark.parametrize("bad", ["eth*", "", "a" * 16, "e th0", "eth0/1", "eth\n0", 5])
def test_an_unreadable_interface_name_marks_the_rule_unknown(bad):
    for key in ("iif", "oif"):
        assert hf._Rule({"v": "accept", "m": {key: bad}}, 4).unknown is True, (key, bad)
    for good in ("lo", "eth0", "ens3.100", "br-1a2b3c4d5e6f", "wg0", "docker0", "a" * 15):
        assert hf._Rule({"v": "accept", "m": {"iif": good}}, 4).unknown is False, good


def test_canonical_protocol_names_and_numbers_are_read_exactly():
    for good in ("tcp", "udp", "icmp", "icmpv6", "sctp", "dccp", "udplite", "gre", "esp", "ah", "igmp", "ipip",
                 "ipv6", "p89", "p253", "p0", "p255", "ospf", "vrrp", "pim", "ipsec-esp"):
        assert hf._Rule({"v": "accept", "m": {"proto": good}}, 4).unknown is False, good
    assert hf._Rule({"v": "accept", "m": {"icmp": [300]}}, 4).unknown is True
    assert hf._Rule({"v": "accept", "m": {"icmp": [8]}}, 4).unknown is False


# --------------------------------------------------------------------------- #
# hostfw-3: the agent_closed_scan_open conflict is sticky
# --------------------------------------------------------------------------- #

from .test_assurance_host_fw import NOW, H as HOUR, agent_row, posture_row, rows_of, scan_edge  # noqa: E402,F811


def _built(*, collected, scan_seen, cover=(), port=8080, proto="tcp"):
    rows = rows_of((agent_row(), posture_row(collected=collected, received=collected)),
                   scans=[scan_edge(port, seen=scan_seen, proto=proto)])
    rows.scan_cover = list(cover)
    return hf.build(rows, NOW)


def _cover(*, started, finished, node=None):
    return {"node_ref": node or "ip:10.0.0.5", "started_at": started, "finished_at": finished}


def test_a_later_posture_that_repeats_the_lie_does_not_clear_the_conflict():
    """hostfw-3: scan saw tcp/8080 at T-30m; a posture collected at T-20m (10 minutes after the scan, same lie)
    gave 'coverage: 1 conflicts: []'. The observation is still in the graph, so the conflict stays."""
    out = _built(collected=NOW - 20 * MIN, scan_seen=NOW - 30 * MIN)
    assert out.coverage == [], "a signed 'closed' posture must not erase an observed open port"
    c = out.facts[0].facts["firewall"]["conflict"]
    assert [(x["kind"], x["proto"], x["port"]) for x in c] == [("agent_closed_scan_open", "tcp", 8080)]


def test_the_conflict_lasts_for_the_whole_external_window_not_for_one_posture_interval():
    out = _built(collected=NOW - MIN, scan_seen=NOW - 100 * HOUR)
    assert out.coverage == []
    assert out.facts[0].facts["host_agent"]["data"]["coverage"]["blocked_by"] == ["conflict"]


def test_a_later_full_scan_that_no_longer_sees_the_port_is_the_positive_evidence_that_clears_it():
    seen, collected = NOW - 30 * MIN, NOW - 20 * MIN
    later = _cover(started=NOW - 10 * MIN, finished=NOW - 5 * MIN)
    assert len(_built(collected=collected, scan_seen=seen, cover=[later]).coverage) == 1
    # a scan that STARTED before the observation may have seen it: not evidence
    early = _cover(started=NOW - 40 * MIN, finished=NOW - 5 * MIN)
    assert _built(collected=collected, scan_seen=seen, cover=[early]).coverage == []
    # a scan that finished before the posture says nothing about the posture's claim
    before = _cover(started=NOW - 90 * MIN, finished=NOW - 60 * MIN)
    assert _built(collected=collected, scan_seen=NOW - 120 * MIN, cover=[before]).coverage == []
    # another node's scan is not this node's evidence
    other = _cover(started=NOW - 10 * MIN, finished=NOW - 5 * MIN, node="ip:10.9.9.9")
    assert _built(collected=collected, scan_seen=seen, cover=[other]).coverage == []
    # the scanner is TCP only: it cannot clear a UDP observation
    assert _built(collected=collected, scan_seen=seen, cover=[later], proto="udp", port=5353).coverage == []
    assert _built(collected=collected, scan_seen=seen, cover=[later], proto="any", port=5353).coverage == []


async def _persist_scan(app_pool, *, edge_seen, scan_started, scan_finished, port=8080):
    """external_exposure's output as the store holds it: an observed edge and full-port coverage naming the scan."""
    from app.assurance import refs
    from app.assurance.types import CoverageOut, EdgeOut
    sid = uuid.uuid4()
    async with conn_for(app_pool) as con:
        await con.execute("DELETE FROM reach_edges WHERE source = 'external_scan'")
        await con.execute(
            "INSERT INTO scans (id, kind, target, status, started_at, finished_at) "
            "VALUES ($1, 'port_scan', '10.0.0.5', 'completed', $2, $3)", sid, scan_started, scan_finished)
    out = BuildOutput(
        source="external_scan", mode="window", window=dt.timedelta(hours=168),
        nodes=[NodeOut(refs.INTERNET, "internet"), NodeOut("ip:10.0.0.5", "host", attrs={"ips": ["10.0.0.5"]})],
        edges=[EdgeOut(src_ref=refs.INTERNET, dst_ref="ip:10.0.0.5", proto="tcp", port_lo=port, port_hi=port,
                       basis="observed", source="external_scan", last_seen=edge_seen, confidence=100,
                       evidence={"origin": "external_scan"})],
        coverage=[CoverageOut(node_ref="ip:10.0.0.5", direction="in", tier="observed", observed_at=scan_finished,
                              source="external_scan", detail={"ports": "1-65535", "proto": "tcp", "origin": "internet",
                                                              "ips": ["10.0.0.5"], "scans": [str(sid)]})])
    async with conn_for(app_pool) as con:
        await store.persist_build(con, out, scan_finished)


async def test_a_later_full_scan_row_clears_the_conflict_through_the_real_store(app_pool):
    h = await seed_host(app_pool)
    t = now_()
    await post(app_pool, h, healthy(collected=t - 20 * MIN, seq=1, ips=["10.0.0.5"]), now=t - 20 * MIN)
    now = t + 10 * dt.timedelta(seconds=1)
    # a scan finished after the posture but STARTED before the port was last seen open: that is no evidence
    await _persist_scan(app_pool, edge_seen=t - 5 * MIN, scan_started=t - 8 * MIN, scan_finished=t - 4 * MIN)
    rows, out = await load_build(app_pool, now=now)
    assert [c["node_ref"] for c in rows.scan_cover] == ["ip:10.0.0.5"]
    assert out.coverage == []
    # a full scan that started after the last observation and finished after the posture, without seeing it again
    await _persist_scan(app_pool, edge_seen=t - 30 * MIN, scan_started=t - 8 * MIN, scan_finished=t - 4 * MIN)
    _, out = await load_build(app_pool, now=now)
    assert len(out.coverage) == 1
    # ... a scan that finished BEFORE the posture was collected says nothing about it
    await _persist_scan(app_pool, edge_seen=t - 50 * MIN, scan_started=t - 40 * MIN, scan_finished=t - 30 * MIN)
    _, out = await load_build(app_pool, now=now)
    assert out.coverage == []


async def test_an_oversized_collector_never_takes_a_violating_host_out_of_scope(app_pool):
    """hostfw-7 end to end (store -> loader -> library): the host stays tagged and its verdict is not HOLDS."""
    pytest.importorskip("paddock_assurance")
    from .test_assurance_host_fw_db import doc_of, evaluate
    from .test_assurance_host_fw import sshd_section
    fw = fw_section([chain([acc(**_TCP22)], policy="accept")], default4="accept", default6="accept")
    fw["v"]["flat_view"]["default_input_policy"] = "accept"
    ssh = sshd_section()
    ssh["v"]["probes"]["deltas"] = [{"user": f"u{i}", "addr": "10.0.0.1",
                                     "delta": {f"k{j}": "v" * 60 for j in range(60)}} for i in range(1500)]
    now = NOW
    rows = rows_of((agent_row(), posture_row(sections(firewall=fw, sshd=ssh))))
    out = hf.build(rows, now)
    assert len(json.dumps([f.facts for f in out.facts])) > store.MAX_FACT_ROW_BYTES      # the premise
    async with conn_for(app_pool) as con:
        rep = await store.persist_build(con, out, now)
    assert rep.facts_stored == 1, rep.notes
    doc = await doc_of(app_pool, now)
    node = next(n for n in doc["nodes"] if n["id"] == hf.refs.agent_ref(agent_row()["id"]))
    assert "agent" in node["tags"] and node["facts"]["sshd"]["status"] == "error"
    assert node["facts"]["sshd"]["reason"] == "facts_too_large"
    r = evaluate(doc, FWD, now + MIN)
    assert r["verdict"] != "HOLDS" and node["id"] in (r["violating_targets"] + r["unproven_targets"]), r


def _tomb(n=1, **kw):
    return {"id": str(uuid.UUID(int=n)), "hostname": f"old{n}", "status": "revoked", "legacy": False,
            "revoked_at": NOW - HOUR, "node_ref": None, **kw}


def test_a_tombstone_is_one_unsigned_unavailable_fact_with_no_edges_and_no_coverage():
    rows = hf.HostFwRows(tombstones=[_tomb(), _tomb(2, status="online", legacy=True, revoked_at=None)])
    out = hf.build(rows, NOW)
    assert out.edges == [] and out.coverage == []
    by = {f.node_ref: f.facts for f in out.facts}
    assert set(by) == {hf.refs.agent_ref(str(uuid.UUID(int=1))), hf.refs.agent_ref(str(uuid.UUID(int=2)))}
    a, b = (by[hf.refs.agent_ref(str(uuid.UUID(int=i)))]["host_agent"] for i in (1, 2))
    assert (a["data"]["agent_status"], a["reason"], a["signed"], a["status"]) == ("revoked", "agent_revoked", False, "unavailable")
    assert (b["data"]["agent_status"], b["reason"]) == ("legacy", "agent_legacy")
    assert {n.ref for n in out.nodes} == set(by)
    assert out == hf.build(rows, NOW)                                      # deterministic


def test_a_tombstone_never_overrides_a_live_agent_and_follows_a_corroborated_node():
    inst = aid_ref = hf.refs.asset_ref(str(uuid.UUID(int=100)))
    rows = hf.HostFwRows(tombstones=[_tomb(2, node_ref=inst), _tomb(3, node_ref=inst), _tomb(4, node_ref="internet"),
                                     _tomb(5, node_ref="not a ref"), {"id": "bad"}])
    out = hf.build(rows, NOW)
    by = {f.node_ref for f in out.facts}
    assert inst in by and hf.refs.agent_ref(str(uuid.UUID(int=2))) not in by      # the instance's own tombstone ...
    assert len([f for f in out.facts if f.node_ref == inst]) == 1                 # ... once, not once per agent
    assert hf.refs.agent_ref(str(uuid.UUID(int=4))) in by and hf.refs.agent_ref(str(uuid.UUID(int=5))) in by
    # a live agent that decides the same node wins
    live = agent_row(1)
    rows = rows_of((live, posture_row()))
    rows.tombstones = [_tomb(1, status="online", legacy=True, revoked_at=None)]
    out = hf.build(rows, NOW)
    (f,) = out.facts
    assert f.facts["host_agent"]["status"] == "ok"
