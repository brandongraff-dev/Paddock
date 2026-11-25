"""Host facts through the store and the graph loader (docs/ASSURANCE_P2.md sections 5 and 7.2).

DB-backed and RLS-realistic like ``test_assurance_store.py``: store calls go through ``app_pool``
(the non-superuser ``paddock_app`` role, tenant stamped on acquire); ``db_pool`` (superuser) only
tampers with the tables underneath. The last section drives the real runner and the real
``paddock_assurance`` library over facts, end to end (clean -> HOLDS, violation -> VIOLATED and a
finding, silence -> UNKNOWN with the finding still open, fix -> HOLDS and the finding closes).
"""
from __future__ import annotations

import contextlib
import copy
import datetime as dt
import json
import pathlib
import uuid

import pytest

from app import tenancy
from app.assurance import builders as builders_pkg
from app.assurance import graph_loader, refs, runner, store
from app.assurance.types import BuildOutput, CoverageOut, EdgeOut, FactOut, NodeOut
from app.config import settings

A = tenancy.DEFAULT_TENANT_ID
B = "00000000-0000-0000-0000-0000000000b2"
T0 = dt.datetime(2026, 12, 1, 9, 0, tzinfo=dt.timezone.utc)
H = dt.timedelta(hours=1)
SRC = "host_fw"
KEY = "0f3a9c1d77b24e5a8c10d2e4b6a8f012"
AG1 = refs.agent_ref(uuid.UUID(int=1))
AG2 = refs.agent_ref(uuid.UUID(int=2))
AG3 = refs.agent_ref(uuid.UUID(int=3))


@contextlib.asynccontextmanager
async def conn_for(pool, tid=A):
    with tenancy.tenant_context(tid):
        async with pool.acquire() as con:
            yield con


@pytest.fixture
async def tenant_b(db_pool):
    await tenancy.create_tenant(db_pool, slug="bravo", name="Bravo Corp", tenant_id=B)
    return B


# --------------------------------------------------------------------------- #
# builders of facts (shapes copied from assurance/examples/estate-hosts-*.json)
# --------------------------------------------------------------------------- #

def sshd_data(password="no", max_tries=3):
    return {"installed": True, "source": "sshd_T",
            "config": {"passwordauthentication": password, "kbdinteractiveauthentication": "no",
                       "permitrootlogin": "no", "pubkeyauthentication": "yes", "permitemptypasswords": "no",
                       "usepam": "yes", "maxauthtries": max_tries, "authenticationmethods": "any",
                       "port": [22]},
            "probes": {"deltas": []}, "match": {"blocks": 0, "unprobed": False},
            # the running daemon, as a current agent reports it: a config claim needs this positive evidence
            "daemon": {"found": True, "masters": 1, "pid": 812, "start_epoch": 1780000000, "reexec_epoch": None,
                       "config_path": None, "config_default": True, "options_override": False,
                       "binary_matches": True, "config_mtime": 1770000000, "reload_pending": False}}


def fw_data(default="drop"):
    fam = {"read": True, "effective_default": default}
    return {"backend": "nft", "ipv6_enabled": True, "families": {"ip4": dict(fam), "ip6": dict(fam)},
            "flat_view": {"default_input_policy": default, "confidence": "exact"},
            "opaque_features": [], "dataplane": []}


def ent(data, **kw):
    e = {"status": "ok", "signed": True, "key_id": KEY, "seq": 1, "evidence_ref": "posture:1",
         "conf": "exact", "partial": False, "data": data}
    e.update(kw)
    return e


def host(ref=AG1, *, at=T0, tier="configured", source=SRC, seq=1, password="no", default="drop", **over):
    """A FactOut with sshd + firewall; ``over`` replaces/adds collector entries."""
    facts = {"sshd": ent(sshd_data(password), seq=seq, evidence_ref=f"posture:{seq}"),
             "firewall": ent(fw_data(default), seq=seq, evidence_ref=f"posture:{seq}")}
    facts.update(over)
    return FactOut(ref, source, tier, at, facts)


def build(*facts, source=SRC, nodes=None, edges=(), coverage=()):
    nodes = [NodeOut(f.node_ref, "host") for f in facts] if nodes is None else nodes
    return BuildOutput(source=source, mode="replace", nodes=list(nodes), edges=list(edges),
                       coverage=list(coverage), facts=list(facts))


async def persist(pool, out, now=T0, tid=A):
    async with conn_for(pool, tid) as con:
        return await store.persist_build(con, out, now)


async def version(pool, tid=A) -> int:
    async with conn_for(pool, tid) as con:
        return (await store.get_state(con)).graph_version


async def fact_rows(pool, tid=A, source=None):
    async with conn_for(pool, tid) as con:
        return await con.fetch(
            "SELECT id, node_ref, source, tier, observed_at, digest, facts::text AS facts FROM reach_node_facts "
            "WHERE ($1::text IS NULL OR source = $1) ORDER BY node_ref, source", source)


async def load(pool, now=T0, tid=A):
    async with conn_for(pool, tid) as con:
        return await graph_loader.load_graph_doc_with_diagnostics(con, now)


def node_of(doc, ref):
    return next(n for n in doc["nodes"] if n["id"] == ref)


# --------------------------------------------------------------------------- #
# refs
# --------------------------------------------------------------------------- #

def test_agent_refs_are_canonical_and_validated():
    u = uuid.uuid4()
    assert refs.agent_ref(str(u).upper()) == f"agent:{u}"
    assert refs.parse_ref(f"agent:{u}") == ("agent", str(u))
    assert refs.is_valid_ref(AG1)
    for bad in ("agent:", "agent:123", f"agent:{str(u).upper()}", f"agent:{u.hex}", f"agent:{{{u}}}",
                f"agent:urn:uuid:{u}", f"AGENT:{u}", f"agent:{u} ", "agent:" + "x" * 200):
        assert not refs.is_valid_ref(bad), bad
    with pytest.raises(refs.RefError):
        refs.agent_ref("nope")


# --------------------------------------------------------------------------- #
# entry validation and digest (pure)
# --------------------------------------------------------------------------- #

def test_a_valid_entry_is_normalised_with_the_safe_defaults():
    got = store.normalise_fact_entry("sshd", {"status": "ok", "signed": True, "data": {"a": [1, "x", None, True]}})
    assert got == {"status": "ok", "signed": True, "conf": "approximate", "partial": True, "seq": 0,
                   "key_id": "", "evidence_ref": "", "data": {"a": [1, "x", None, True]}}
    # unknown keys never reach the evaluator
    assert "bogus" not in store.normalise_fact_entry("sshd", {"status": "ok", "signed": True, "bogus": 1})
    # an entry may carry its own weaker tier / older stamp; both are normalised
    got = store.normalise_fact_entry("sshd", ent({}, tier="declared", observed_at="2026-12-01T08:00:00Z"))
    assert got["tier"] == "declared" and got["observed_at"] == "2026-12-01T08:00:00+00:00"


@pytest.mark.parametrize("bad", [
    {"status": "ok"},                                            # signed is mandatory (no default)
    {"status": "ok", "signed": "true"},
    {"status": "ok", "signed": 1},
    {"status": "fine", "signed": True},
    {"status": "ok", "signed": True, "seq": -1},
    {"status": "ok", "signed": True, "seq": True},
    {"status": "ok", "signed": True, "seq": 1.0},
    {"status": "ok", "signed": True, "conf": "mostly"},
    {"status": "ok", "signed": True, "partial": "no"},
    {"status": "ok", "signed": True, "tier": "observed-ish"},
    {"status": "ok", "signed": True, "observed_at": "2026-12-01T09:00:00"},     # naive
    {"status": "ok", "signed": True, "observed_at": 5},
    {"status": "ok", "signed": True, "key_id": 5},
    {"status": "ok", "signed": True, "key_id": "k" * 300},
    {"status": "ok", "signed": True, "data": []},
    {"status": "ok", "signed": True, "data": {"x": 1.5}},                       # no floats
    {"status": "ok", "signed": True, "data": {"x": float("nan")}},
    {"status": "ok", "signed": True, "data": {"x": "a\x00b"}},                  # jsonb cannot hold NUL
    {"status": "ok", "signed": True, "data": {"x": "\ud800"}},                  # not encodable
    {"status": "ok", "signed": True, "data": {"x": "y" * 3000}},
    {"status": "ok", "signed": True, "data": {"x": list(range(5001))}},
    {"status": "ok", "signed": True, "data": {1: "int key"}},
    {"status": "ok", "signed": True, "data": {"x": (1, 2)}},                    # tuples are not JSON
    {"status": "ok", "signed": True, "data": {"x": 2 ** 70}},
    {"status": "ok", "signed": True, "conflicts": [{"kind": "k"}]},             # misspelt marker
    {"status": "ok", "signed": True, "conflict": "yes"},
    {"status": "ok", "signed": True, "conflict": 0},                            # never read as "no conflict"
    {"status": "ok", "signed": True, "conflict": {}},
    {"status": "ok", "signed": True, "conflict": [1]},
    "not an object",
    None,
])
def test_invalid_entries_are_refused(bad):
    with pytest.raises(store.FactInvalid):
        store.normalise_fact_entry("sshd", bad)


def test_depth_is_capped():
    deep: dict = {}
    cur = deep
    for _ in range(store.MAX_FACT_DEPTH + 2):
        cur["n"] = {}
        cur = cur["n"]
    with pytest.raises(store.FactInvalid):
        store.normalise_fact_entry("sshd", {"status": "ok", "signed": True, "data": deep})


@pytest.mark.parametrize("conflict,kept", [(None, False), (False, False), ([], False), (True, True),
                                           ({"kind": "k"}, True), ([{"kind": "k"}], True)])
def test_conflict_markers_follow_the_librarys_reading(conflict, kept):
    got = store.normalise_fact_entry("firewall", ent({}, conflict=conflict))
    assert ("conflict" in got) is kept


def _row_digest(**entry_over):
    e = store.normalise_fact_entry("sshd", ent({"a": 1}, **entry_over))
    return store.fact_row_digest("configured", {"sshd": e})


def test_the_digest_ignores_timestamps_and_provenance_but_nothing_that_means_something():
    base = _row_digest()
    # a re-signed identical posture: new stamp, new seq, new evidence pointer
    assert _row_digest(observed_at="2026-12-02T00:00:00Z", seq=99, evidence_ref="posture:99") == base
    # everything that changes what the evaluator can conclude changes the digest
    for over in ({"signed": False}, {"key_id": "other"}, {"conf": "approximate"}, {"partial": True},
                 {"status": "error"}, {"status": "unavailable", "reason": "tool_missing"},
                 {"conflict": True}, {"tier": "declared"}):
        assert _row_digest(**over) != base, over
    assert store.fact_row_digest("observed", {"sshd": store.normalise_fact_entry("sshd", ent({"a": 1}))}) != base
    changed_data = store.normalise_fact_entry("sshd", ent({"a": 2}))
    assert store.fact_row_digest("configured", {"sshd": changed_data}) != base
    # a conflict record's own timestamps are not state, its content is
    c1 = _row_digest(conflict=[{"kind": "agent_closed_scan_open", "port": 22, "scan_seen_at": "2026-12-01T09:00:00Z"}])
    c2 = _row_digest(conflict=[{"kind": "agent_closed_scan_open", "port": 22, "scan_seen_at": "2026-12-01T10:00:00Z"}])
    c3 = _row_digest(conflict=[{"kind": "agent_closed_scan_open", "port": 23, "scan_seen_at": "2026-12-01T09:00:00Z"}])
    assert c1 == c2 and c1 != c3 and c1 != base


# --------------------------------------------------------------------------- #
# persist_build: replace / digest / version semantics
# --------------------------------------------------------------------------- #

async def test_first_persist_stores_rows_and_bumps_the_version(app_pool):
    rep = await persist(app_pool, build(host(AG1), host(AG2)))
    assert rep.changed and rep.facts_changed == 2 and rep.facts_stored == 2 and rep.skipped == 0
    assert rep.nodes_added == 2 and rep.graph_version == 1 == await version(app_pool)
    assert len(rep.facts_digest) == 64
    rows = await fact_rows(app_pool)
    assert [r["node_ref"] for r in rows] == [AG1, AG2]
    r = rows[0]
    assert (r["source"], r["tier"], r["observed_at"]) == (SRC, "configured", T0) and len(r["digest"]) == 64
    assert set(json.loads(r["facts"])) == {"sshd", "firewall"}


async def test_a_pure_refresh_does_not_bump_the_graph_version(app_pool):
    first = await persist(app_pool, build(host(AG1, seq=1)))
    (before,) = await fact_rows(app_pool)
    later = T0 + H
    rep = await persist(app_pool, build(host(AG1, at=later, seq=2)), later)
    assert not rep.changed and rep.facts_changed == 0 and rep.facts_stored == 1
    assert rep.facts_digest == first.facts_digest
    assert await version(app_pool) == 1                         # nothing for the runner to re-evaluate
    (after,) = await fact_rows(app_pool)
    assert after["id"] == before["id"] and after["digest"] == before["digest"]
    assert after["observed_at"] == later                         # the stamp moved forward ...
    stored = json.loads(after["facts"])
    assert stored["sshd"]["seq"] == 2 and stored["sshd"]["evidence_ref"] == "posture:2"   # ... and so did provenance


async def test_an_identical_build_writes_nothing(app_pool, db_pool):
    await persist(app_pool, build(host(AG1)))
    (before,) = await fact_rows(app_pool)
    await db_pool.execute("UPDATE reach_node_facts SET digest = digest")      # no-op, keeps xmin readable
    xmin = await db_pool.fetchval("SELECT xmin::text FROM reach_node_facts")
    rep = await persist(app_pool, build(host(AG1)))
    assert not rep.changed and rep.facts_changed == 0
    assert await db_pool.fetchval("SELECT xmin::text FROM reach_node_facts") == xmin     # row not rewritten
    assert (await fact_rows(app_pool))[0]["id"] == before["id"]


@pytest.mark.parametrize("what,mutate", [
    ("value", lambda f: host(f.node_ref, password="yes")),
    ("value2", lambda f: host(f.node_ref, default="accept")),
    ("signed", lambda f: host(f.node_ref, sshd=ent(sshd_data(), signed=False))),
    ("key_id", lambda f: host(f.node_ref, sshd=ent(sshd_data(), key_id="f" * 32))),
    ("conf", lambda f: host(f.node_ref, sshd=ent(sshd_data(), conf="approximate"))),
    ("partial", lambda f: host(f.node_ref, sshd=ent(sshd_data(), partial=True))),
    ("status", lambda f: host(f.node_ref, sshd=ent({}, status="error", reason="timeout"))),
    ("conflict", lambda f: host(f.node_ref, firewall=ent(fw_data(), conflict=[{"kind": "agent_closed_scan_open"}]))),
    ("entry-tier", lambda f: host(f.node_ref, sshd=ent(sshd_data(), tier="declared"))),
    ("row-tier", lambda f: host(f.node_ref, tier="observed")),
    ("collector-added", lambda f: host(f.node_ref, patch=ent({"security_updates_pending": 0}))),
    ("collector-removed", lambda f: FactOut(f.node_ref, SRC, "configured", T0, {"sshd": f.facts["sshd"]})),
], ids=lambda x: x if isinstance(x, str) else "")
async def test_a_real_fact_change_bumps_the_version(app_pool, what, mutate):
    base = host(AG1)
    await persist(app_pool, build(base))
    rep = await persist(app_pool, build(mutate(base)), T0 + H)
    assert rep.changed and rep.facts_changed == 1, what
    assert await version(app_pool) == 2


async def test_a_conflict_records_own_timestamp_is_not_a_change(app_pool):
    def with_conflict(seen):
        return host(AG1, firewall=ent(fw_data(), conflict=[
            {"kind": "agent_closed_scan_open", "proto": "tcp", "port": 22, "scan_seen_at": seen}]))
    await persist(app_pool, build(with_conflict("2026-12-01T08:55:00Z")))
    rep = await persist(app_pool, build(with_conflict("2026-12-01T09:55:00Z")), T0 + H)
    assert not rep.changed and rep.facts_changed == 0


async def test_a_backwards_moving_stamp_bumps_because_freshness_only_shrank(app_pool):
    await persist(app_pool, build(host(AG1, at=T0)))
    rep = await persist(app_pool, build(host(AG1, at=T0 - H)), T0 + H)
    assert rep.changed and rep.facts_changed == 1
    assert (await fact_rows(app_pool))[0]["observed_at"] == T0 - H


async def test_a_host_that_loses_its_facts_is_removed_and_bumps(app_pool):
    await persist(app_pool, build(host(AG1), host(AG2)))
    rep = await persist(app_pool, build(host(AG1)), T0 + H)
    assert rep.changed and rep.facts_changed == 1 and rep.facts_stored == 1
    assert [r["node_ref"] for r in await fact_rows(app_pool)] == [AG1]
    rep = await persist(app_pool, build(), T0 + 2 * H)             # a source that emits no facts at all
    assert rep.changed and rep.facts_changed == 1 and rep.facts_stored == 0 and rep.facts_digest == ""
    assert await fact_rows(app_pool) == []


async def test_replace_only_touches_this_sources_rows(app_pool):
    await persist(app_pool, build(host(AG1)))
    await persist(app_pool, build(host(AG1, source="other_src"), source="other_src"))
    assert {r["source"] for r in await fact_rows(app_pool)} == {SRC, "other_src"}
    await persist(app_pool, build(host(AG2)), T0 + H)               # host_fw now only knows AG2
    got = {(r["node_ref"], r["source"]) for r in await fact_rows(app_pool)}
    assert got == {(AG1, "other_src"), (AG2, SRC)}


async def test_builders_that_emit_no_facts_leave_other_sources_alone_and_change_nothing(app_pool):
    await persist(app_pool, build(host(AG1)))
    v = await version(app_pool)
    out = BuildOutput(source="aws_sg", mode="replace")              # an untouched P1 builder
    assert out.facts == []
    rep = await persist(app_pool, out, T0 + H)
    assert not rep.changed and rep.facts_changed == 0 and rep.facts_stored == 0
    assert await version(app_pool) == v and len(await fact_rows(app_pool)) == 1


async def test_invalid_rows_are_skipped_and_counted_not_fatal(app_pool):
    good = host(AG1)
    bad = [
        FactOut(AG2, "wrong_source", "configured", T0, {"sshd": ent({})}),               # source mismatch
        FactOut("internet", SRC, "configured", T0, {"sshd": ent({})}),                  # the internet has no host
        FactOut("agent:nope", SRC, "configured", T0, {"sshd": ent({})}),
        FactOut(AG3, SRC, "certain", T0, {"sshd": ent({})}),                            # bad tier
        FactOut(AG3, SRC, "configured", T0.replace(tzinfo=None), {"sshd": ent({})}),    # naive stamp
        FactOut(AG3, SRC, "configured", T0, [("sshd", {})]),                            # not an object
        FactOut(AG3, SRC, "configured", T0, {f"c{i}": ent({}) for i in range(17)}),     # > 16 collectors
        FactOut(AG3, SRC, "configured", T0, {"x" * 40: ent({})}),                       # bad collector name
    ]
    rep = await persist(app_pool, build(good, *bad, nodes=[NodeOut(AG1, "host")]))
    assert rep.facts_stored >= 1 and rep.skipped >= len(bad) - 1
    rows = await fact_rows(app_pool)
    stored = {r["node_ref"]: json.loads(r["facts"]) for r in rows}
    assert set(stored[AG1]) == {"sshd", "firewall"}
    assert "internet" not in stored and "agent:nope" not in stored
    assert all(r["source"] == SRC for r in rows)
    assert any("skipped facts" in n or "dropped fact" in n for n in rep.notes)


async def test_a_bad_collector_entry_is_dropped_alone_the_others_stay(app_pool):
    f = host(AG1, firewall={"status": "ok", "data": {}})            # no 'signed'
    rep = await persist(app_pool, build(f))
    assert rep.skipped == 1 and any("firewall" in n for n in rep.notes)
    (row,) = await fact_rows(app_pool)
    assert set(json.loads(row["facts"])) == {"sshd"}


async def test_two_rows_for_one_node_are_both_distrusted(app_pool):
    rep = await persist(app_pool, build(host(AG1), host(AG1, password="yes"), host(AG2)))
    assert rep.skipped >= 1 and any("two fact rows" in n for n in rep.notes)
    assert [r["node_ref"] for r in await fact_rows(app_pool)] == [AG2]


async def test_facts_with_nothing_in_them_still_store_a_row_for_the_agent_tag(app_pool):
    rep = await persist(app_pool, build(FactOut(AG1, SRC, "configured", T0, {})))
    assert rep.facts_stored == 1
    doc, diag = await load(app_pool)
    n = node_of(doc, AG1)
    assert n["tags"] == ["agent"] and "facts" not in n and diag.facts_dropped == 0


async def test_a_node_carrying_facts_is_never_pruned_until_the_facts_go(app_pool):
    await persist(app_pool, build(host(AG1)))
    far = T0 + 5 * store.NODE_GRACE
    # the builder no longer emits the node, but its facts row (another source's) still names it
    await persist(app_pool, build(host(AG1, source="x_src"), source="x_src", nodes=[]), far)
    other = BuildOutput(source=SRC, mode="replace", nodes=[NodeOut(AG2, "host")])
    rep = await persist(app_pool, other, far)
    assert rep.nodes_removed == 0
    async with conn_for(app_pool) as con:
        assert await con.fetchval("SELECT count(*) FROM reach_nodes WHERE node_ref = $1", AG1) == 1
        await con.execute("DELETE FROM reach_node_facts")
    rep = await persist(app_pool, other, far + H)
    assert rep.nodes_removed == 1
    async with conn_for(app_pool) as con:
        assert await con.fetchval("SELECT count(*) FROM reach_nodes WHERE node_ref = $1", AG1) == 0


async def test_facts_are_tenant_scoped_under_rls(app_pool, tenant_b):
    await persist(app_pool, build(host(AG1)))
    await persist(app_pool, build(host(AG1, password="yes")), tid=B)       # same node_ref + source in B
    assert len(await fact_rows(app_pool, A)) == 1 and len(await fact_rows(app_pool, B)) == 1
    a = json.loads((await fact_rows(app_pool, A))[0]["facts"])
    b = json.loads((await fact_rows(app_pool, B))[0]["facts"])
    assert a["sshd"]["data"]["config"]["passwordauthentication"] == "no"
    assert b["sshd"]["data"]["config"]["passwordauthentication"] == "yes"
    doc_a, _ = await load(app_pool, tid=A)
    doc_b, _ = await load(app_pool, tid=B)
    assert node_of(doc_a, AG1)["facts"]["sshd"]["data"]["config"]["passwordauthentication"] == "no"
    assert node_of(doc_b, AG1)["facts"]["sshd"]["data"]["config"]["passwordauthentication"] == "yes"
    # B replacing its source does not touch A
    await persist(app_pool, build(), T0 + H, tid=B)
    assert len(await fact_rows(app_pool, A)) == 1 and await fact_rows(app_pool, B) == []
    assert await version(app_pool, A) == 1


async def test_concurrent_persists_of_one_source_do_not_double_count_or_deadlock(app_pool):
    import asyncio
    reps = await asyncio.gather(*[persist(app_pool, build(host(AG1), host(AG2))) for _ in range(3)])
    assert sum(1 for r in reps if r.changed) == 1                    # the advisory lock serialises them
    assert len(await fact_rows(app_pool)) == 2 and await version(app_pool) == 1


# --------------------------------------------------------------------------- #
# graph loader: the pinned document shape
# --------------------------------------------------------------------------- #

def _golden_fact(data, *, seq=1, **over):
    d = {"status": "ok", "tier": "configured", "observed_at": "2026-12-01T09:00:00+00:00", "signed": True,
         "source": SRC, "key_id": KEY, "seq": seq, "evidence_ref": f"posture:{seq}", "conf": "exact",
         "partial": False, "data": data}
    d.update(over)
    return d


async def test_the_loader_emits_the_pinned_document_shape(app_pool):
    await persist(app_pool, build(host(AG1)))
    doc, diag = await load(app_pool)
    # ``zone_unknown``: an agent node nothing independent placed (no label, no direct private peer) is a possible member
    # of every zone selector (package Z, finding Z-1); the pinned shape carries the attribute, only ever when true.
    assert node_of(doc, AG1) == {
        "id": AG1, "kind": "host", "tags": ["agent"], "zone_unknown": True,
        "facts": {"firewall": _golden_fact(fw_data()), "sshd": _golden_fact(sshd_data())}}
    assert diag.facts_dropped == 0 and diag.fact_issues == []
    assert [n["id"] for n in doc["nodes"]] == sorted(n["id"] for n in doc["nodes"])
    assert list(node_of(doc, AG1)["facts"]) == ["firewall", "sshd"]            # sorted collectors
    # the document is JSON (no tuples, datetimes, Records) ...
    assert json.loads(json.dumps(doc)) == doc
    # ... and the library accepts exactly it
    import paddock_assurance as lib
    g = lib.ReachGraph.from_dict(doc)
    node = next(n for n in g.nodes.values() if n.id == AG1) if isinstance(g.nodes, dict) else None
    assert node is not None and node.host is not None and set(node.host.facts) == {"firewall", "sshd"}
    f = node.host.facts["sshd"]
    assert f.signed and f.tier.value == "configured" and f.key_id == KEY and f.seq == 1
    assert f.conf == "exact" and f.partial is False and f.source == SRC and f.evidence_ref == "posture:1"


async def test_optional_keys_appear_only_when_present(app_pool):
    f = host(AG1, patch=ent({}, status="unavailable", reason="tool_missing"),
             firewall=ent(fw_data(), conflict=[{"kind": "agent_closed_scan_open", "port": 22}]))
    await persist(app_pool, build(f))
    doc, _ = await load(app_pool)
    facts = node_of(doc, AG1)["facts"]
    assert "conflict" not in facts["sshd"] and "reason" not in facts["sshd"]
    assert facts["firewall"]["conflict"] == [{"kind": "agent_closed_scan_open", "port": 22}]
    assert facts["patch"]["reason"] == "tool_missing" and facts["patch"]["status"] == "unavailable"


async def test_an_entry_can_only_be_weaker_or_older_than_its_row(app_pool):
    f = host(AG1, tier="observed",
             sshd=ent(sshd_data(), tier="declared", observed_at="2026-12-01T07:00:00Z"),
             firewall=ent(fw_data(), tier="tested", observed_at="2026-12-01T12:00:00Z"))
    await persist(app_pool, build(f))
    facts = node_of((await load(app_pool))[0], AG1)["facts"]
    assert (facts["sshd"]["tier"], facts["sshd"]["observed_at"]) == ("declared", "2026-12-01T07:00:00+00:00")
    assert (facts["firewall"]["tier"], facts["firewall"]["observed_at"]) == ("observed", "2026-12-01T09:00:00+00:00")


async def test_nodes_with_facts_are_auto_tagged_and_declared_labels_win(app_pool):
    web = refs.agent_ref(uuid.UUID(int=10))
    await persist(app_pool, build(host(AG1), host(AG2), host(AG3),
                                  nodes=[NodeOut(AG1, "host"), NodeOut(AG2, "host"), NodeOut(AG3, "host"),
                                         NodeOut(web, "host")]))
    async with conn_for(app_pool) as con:
        await store.set_label(con, AG1, "server", "true", set_by="t", justification="j")
        await store.set_label(con, AG2, "agent", "false", set_by="t", justification="not an agent host")
        await store.set_label(con, AG3, "app-tier", "web", set_by="t", justification="j")
    doc, _ = await load(app_pool)
    assert node_of(doc, AG1)["tags"] == ["agent", "server"]
    assert node_of(doc, AG2)["tags"] == []                    # a declared label overrides the default
    assert "facts" in node_of(doc, AG2)                        # (the facts are still carried)
    assert node_of(doc, AG3)["tags"] == ["agent", "app-tier"]
    assert node_of(doc, web)["tags"] == [] and "facts" not in node_of(doc, web)   # no facts, no tag


async def test_a_node_known_only_from_facts_appears_in_the_document(app_pool):
    await persist(app_pool, build(host(AG1), nodes=[]))
    doc, _ = await load(app_pool)
    n = node_of(doc, AG1)
    assert n["kind"] == "host" and n["tags"] == ["agent"]


async def test_zone_resolution_works_for_agent_nodes(app_pool):
    """(Rewritten for review finding hostfw-1: what the host SAYS about its addresses does not place it.)
    ``attrs.ips`` of an agent node is ignored; the address the server observed places it; the host's own claim
    only places it as a last, reported resort."""
    async with conn_for(app_pool) as con:
        await store.upsert_zone(con, "dmz", ["10.20.0.0/24"], set_by="t", justification="j")
    f = host(AG1)
    await persist(app_pool, BuildOutput(source=SRC, mode="replace", facts=[f],
                                        nodes=[NodeOut(AG1, "host", attrs={"ips": ["10.20.0.7"]})]))
    doc, diag = await load(app_pool)
    assert "zone" not in node_of(doc, AG1) and diag.zone_from_claim == []
    await persist(app_pool, BuildOutput(source=SRC, mode="replace", facts=[f],
                                        nodes=[NodeOut(AG1, "host", attrs={"ips": [], "observed_ips": ["10.20.0.7"]})]))
    doc, diag = await load(app_pool)
    assert node_of(doc, AG1)["zone"] == "dmz" and diag.zone_from_claim == []
    await persist(app_pool, BuildOutput(source=SRC, mode="replace", facts=[f],
                                        nodes=[NodeOut(AG1, "host", attrs={"ips": [], "claimed_ips": ["10.20.0.7"]})]))
    doc, diag = await load(app_pool)
    assert node_of(doc, AG1)["zone"] == "dmz" and diag.zone_from_claim == [AG1]


async def test_cidr_rules_include_agent_hosts_by_their_addresses(app_pool):
    """An agent host inside a SG source range gets the expanded edge like any other host."""
    f = host(AG1)
    await persist(app_pool, BuildOutput(source=SRC, mode="replace", facts=[f],
                                        nodes=[NodeOut(AG1, "host", attrs={"ips": ["10.20.0.7"]})]))
    db = refs.asset_ref(uuid.uuid4())
    await persist(app_pool, BuildOutput(
        source="aws_sg", mode="replace", nodes=[NodeOut(db, "cloud_db")],
        edges=[EdgeOut("cidr:10.20.0.0/24", db, "tcp", 5432, 5432, "configured", "aws_sg", T0)]))
    doc, _ = await load(app_pool)
    assert any(e["src"] == AG1 and e["dst"] == db for e in doc["edges"])


async def test_the_document_is_deterministic(app_pool):
    await persist(app_pool, build(host(AG2), host(AG1), host(AG3)))
    d1, _ = await load(app_pool)
    d2, _ = await load(app_pool)
    assert json.dumps(d1, sort_keys=False) == json.dumps(d2, sort_keys=False)
    assert graph_loader.doc_sha(d1) == graph_loader.doc_sha(d2)


async def test_doc_sha_ignores_pure_refreshes_and_sees_real_changes(app_pool):
    await persist(app_pool, build(host(AG1, seq=1)))
    sha0 = graph_loader.doc_sha((await load(app_pool))[0])
    # refresh: later stamp, new seq / evidence_ref, same content
    later = T0 + H
    await persist(app_pool, build(host(AG1, at=later, seq=2)), later)
    sha1 = graph_loader.doc_sha((await load(app_pool, now=later))[0])
    assert sha1 == sha0
    # a real change
    await persist(app_pool, build(host(AG1, at=later, seq=3, password="yes")), later)
    sha2 = graph_loader.doc_sha((await load(app_pool, now=later))[0])
    assert sha2 != sha0
    # signed flipped / conflict set: also visible
    await persist(app_pool, build(host(AG1, at=later, seq=3, password="yes",
                                       sshd=ent(sshd_data("yes"), signed=False, seq=3))), later)
    assert graph_loader.doc_sha((await load(app_pool, now=later))[0]) not in (sha0, sha2)


def test_doc_sha_strips_only_the_fact_keys_it_documents():
    def doc(**over):
        f = _golden_fact({"a": 1})
        f.update(over)
        return {"version": 1, "now": "x", "edges": [], "nodes": [{"id": AG1, "kind": "host", "facts": {"sshd": f}}]}
    base = graph_loader.doc_sha(doc())
    assert graph_loader.doc_sha(doc(observed_at="2030-01-01T00:00:00+00:00", seq=7, evidence_ref="z")) == base
    for over in ({"signed": False}, {"key_id": "k"}, {"conf": "approximate"}, {"partial": True},
                 {"status": "error"}, {"tier": "declared"}, {"source": "s2"}, {"data": {"a": 2}},
                 {"conflict": [{"k": 1}]}):
        assert graph_loader.doc_sha(doc(**over)) != base, over


# --------------------------------------------------------------------------- #
# graph loader: stored rows that cannot be carried are dropped, never fatal
# --------------------------------------------------------------------------- #

async def _tamper(db_pool, ref, facts, *, source=SRC, tier="configured", tid=A):
    await db_pool.execute(
        "INSERT INTO reach_node_facts (tenant_id, node_ref, source, tier, observed_at, digest, facts) "
        "VALUES ($1, $2, $3, $4, $5, 'x', $6::jsonb)", tid, ref, source, tier, T0, json.dumps(facts))


async def test_garbage_in_the_table_never_breaks_the_graph(app_pool, db_pool):
    await persist(app_pool, build(host(AG1)))
    bad_entries = {
        "sshd": {"status": "ok"},                                  # unsigned-by-omission
        "firewall": {"status": "ok", "signed": True, "data": {"x": 1.5}},   # a float
        "BadName": ent({}),
        "patch": "nope",
        "listeners": ent({}, conflict="yes"),
        "self": ent({"ok": True}),                                 # the one good entry
    }
    await _tamper(db_pool, AG2, bad_entries)
    await _tamper(db_pool, AG3, {f"c{i}": ent({}) for i in range(17)})       # > 16 collectors
    await _tamper(db_pool, "internet", {"sshd": ent({})})
    await _tamper(db_pool, AG1, ["not", "an", "object"], source="weird")
    doc, diag = await load(app_pool)
    n2 = node_of(doc, AG2)
    assert set(n2["facts"]) == {"self"} and n2["tags"] == ["agent"]
    assert "facts" not in node_of(doc, AG3) and node_of(doc, AG3)["tags"] == ["agent"]
    assert "facts" not in node_of(doc, "internet")
    assert set(node_of(doc, AG1)["facts"]) == {"firewall", "sshd"}           # the good source survives
    assert diag.facts_dropped >= 8 and diag.fact_issues
    import paddock_assurance as lib
    lib.ReachGraph.from_dict(doc)                                  # the library takes the whole document


async def test_two_sources_claiming_one_collector_are_both_dropped(app_pool, db_pool):
    await persist(app_pool, build(host(AG1)))
    await _tamper(db_pool, AG1, {"sshd": ent(sshd_data("yes")), "patch": ent({"p": 1})}, source="rival")
    doc, diag = await load(app_pool)
    facts = node_of(doc, AG1)["facts"]
    assert set(facts) == {"firewall", "patch"}                     # sshd is claimed twice: neither is trusted
    assert facts["patch"]["source"] == "rival" and facts["firewall"]["source"] == SRC
    assert any("sshd" in i for i in diag.fact_issues)


async def test_more_than_16_collectors_across_sources_drops_the_node(app_pool, db_pool):
    await _tamper(db_pool, AG1, {f"a{i}": ent({}) for i in range(10)}, source="s1")
    await _tamper(db_pool, AG1, {f"b{i}": ent({}) for i in range(10)}, source="s2")
    doc, diag = await load(app_pool)
    assert "facts" not in node_of(doc, AG1) and node_of(doc, AG1)["tags"] == ["agent"]
    assert any("collectors across sources" in i for i in diag.fact_issues)


async def test_the_document_wide_fact_budget_is_enforced_deterministically(app_pool, db_pool, monkeypatch):
    monkeypatch.setattr(store, "MAX_FACT_TOTAL_ELEMENTS", 30)     # 13 elements per node: two fit, three do not
    for ref in (AG1, AG2, AG3):
        await _tamper(db_pool, ref, {"sshd": ent({"x": list(range(10))})})
    doc, diag = await load(app_pool)
    assert "facts" in node_of(doc, AG1) and "facts" in node_of(doc, AG2) and "facts" not in node_of(doc, AG3)
    assert any("budget" in i for i in diag.fact_issues)


async def test_a_fact_the_library_would_refuse_is_dropped_not_passed_on(app_pool, db_pool, monkeypatch):
    pytest.importorskip("paddock_assurance.hostfacts")
    from paddock_assurance import hostfacts
    real = hostfacts.parse_fact

    def strict(name, raw, nid, budget):
        if raw.get("seq") == 13:
            raise hostfacts.FactError("unlucky")
        return real(name, raw, nid, budget)

    monkeypatch.setattr(hostfacts, "parse_fact", strict)
    await persist(app_pool, build(host(AG1, seq=13, sshd=ent(sshd_data(), seq=13), firewall=ent(fw_data(), seq=2))))
    doc, diag = await load(app_pool)
    assert set(node_of(doc, AG1)["facts"]) == {"firewall"}
    assert any("rejected by the assurance library" in i for i in diag.fact_issues)


async def test_a_broken_library_parser_does_not_break_the_loader(app_pool, monkeypatch):
    pytest.importorskip("paddock_assurance.hostfacts")
    from paddock_assurance import hostfacts

    def boom(*a, **k):
        raise TypeError("signature changed")

    monkeypatch.setattr(hostfacts, "parse_fact", boom)
    await persist(app_pool, build(host(AG1)))
    doc, diag = await load(app_pool)
    assert set(node_of(doc, AG1)["facts"]) == {"firewall", "sshd"} and diag.facts_dropped == 0


# --------------------------------------------------------------------------- #
# the library over the loader's document (the real evaluator, the real std invariants)
# --------------------------------------------------------------------------- #

def _evaluate(doc, std_id, now):
    import paddock_assurance as lib
    from paddock_assurance import stdlib
    return lib.evaluate(stdlib.load_std(std_id), lib.ReachGraph.from_dict(doc), now).to_dict()


SSH = "std:server-ssh-hardened"
FWD = "std:server-default-deny-inbound"


async def test_std_host_invariants_over_loaded_facts(app_pool):
    await persist(app_pool, build(host(AG1), host(AG2)))
    doc, _ = await load(app_pool)
    for std_id in (SSH, FWD):
        r = _evaluate(doc, std_id, T0 + dt.timedelta(minutes=5))
        assert r["verdict"] == "HOLDS", (std_id, r["reasons"])
        assert r["evidence_tier"] == "configured"
        assert r["assertion"] == "host-config"


@pytest.mark.parametrize("what,fact,verdict,std_id", [
    ("password login", lambda: host(AG2, password="yes"), "VIOLATED", SSH),
    ("firewall accepts", lambda: host(AG2, default="accept"), "VIOLATED", FWD),
    ("unsigned", lambda: host(AG2, sshd=ent(sshd_data("yes"), signed=False)), "UNKNOWN", SSH),
    ("approximate", lambda: host(AG2, firewall=ent(fw_data("accept"), conf="approximate")), "UNKNOWN", FWD),
    ("partial", lambda: host(AG2, sshd=ent(sshd_data("yes"), partial=True)), "UNKNOWN", SSH),
    ("collector error", lambda: host(AG2, sshd=ent({}, status="error", reason="timeout")), "UNKNOWN", SSH),
    ("unavailable", lambda: host(AG2, firewall=ent({}, status="unavailable", reason="permission_denied")),
     "UNKNOWN", FWD),
    ("conflict", lambda: host(AG2, firewall=ent(fw_data("accept"),
                                                conflict=[{"kind": "agent_closed_scan_open", "port": 22}])),
     "UNKNOWN", FWD),
    ("declared tier below min_tier", lambda: host(AG2, tier="declared"), "UNKNOWN", SSH),
])
async def test_loaded_facts_that_cannot_be_trusted_never_hold(app_pool, what, fact, verdict, std_id):
    await persist(app_pool, build(host(AG1), fact()))
    doc, _ = await load(app_pool)
    r = _evaluate(doc, std_id, T0 + dt.timedelta(minutes=5))
    assert r["verdict"] == verdict, (what, r["reasons"])
    if verdict == "VIOLATED":
        assert r["violating_targets"] == [AG2] and r["unproven_targets"] == []
    else:
        assert AG2 in r["unproven_targets"] and r["violating_targets"] == []


async def test_stale_facts_are_unknown_and_so_is_a_declared_server_without_an_agent(app_pool):
    await persist(app_pool, build(host(AG1, password="yes")))
    doc, _ = await load(app_pool)
    r = _evaluate(doc, SSH, T0 + dt.timedelta(hours=7))             # max_age is 6h: a stale violation is UNKNOWN
    assert r["verdict"] == "UNKNOWN" and r["violating_targets"] == [] and r["unproven_targets"] == [AG1]
    # a host tagged server with no agent facts is selected and unknown (no_agent), never out of scope
    ghost = refs.agent_ref(uuid.UUID(int=99))
    await persist(app_pool, BuildOutput(source="seed", mode="replace", nodes=[NodeOut(ghost, "host")]))
    async with conn_for(app_pool) as con:
        await store.set_label(con, ghost, "server", "true", set_by="t", justification="j")
    await persist(app_pool, build(host(AG1)), T0 + H)
    doc, _ = await load(app_pool, now=T0 + H)
    r = _evaluate(doc, SSH, T0 + H + dt.timedelta(minutes=1))
    assert r["verdict"] == "UNKNOWN" and r["unproven_targets"] == [ghost]
    assert {b["reason"] for b in r["blind_spots"] if b["node"] == ghost} == {"no_agent"}


async def test_the_library_example_estate_round_trips_through_store_and_loader(app_pool):
    ex = pathlib.Path(__file__).resolve().parents[2] / "assurance" / "examples" / "estate-hosts-violated.json"
    if not ex.exists():
        pytest.skip("library examples not present")
    raw = json.loads(ex.read_text())
    now = dt.datetime.fromisoformat(raw["now"].replace("Z", "+00:00"))
    # the example uses its own ids; rebuild them as agent refs and feed the facts through the store
    ids = {n["id"]: refs.agent_ref(uuid.UUID(int=1000 + i)) for i, n in enumerate(raw["nodes"]) if n.get("facts")}
    out_facts = []
    for n in raw["nodes"]:
        if not n.get("facts"):
            continue
        entries = {}
        for c, f in n["facts"].items():
            entries[c] = {k: v for k, v in f.items() if k not in ("tier", "observed_at", "source")}
        seen = min(dt.datetime.fromisoformat(f["observed_at"].replace("Z", "+00:00")) for f in n["facts"].values())
        out_facts.append(FactOut(ids[n["id"]], SRC, "configured", seen, entries))
    await persist(app_pool, build(*out_facts), now)
    async with conn_for(app_pool) as con:
        for ref in ids.values():
            await store.set_label(con, ref, "server", "true", set_by="t", justification="j")
    doc, diag = await load(app_pool, now=now)
    assert diag.facts_dropped == 0
    for n in raw["nodes"]:
        if n.get("facts"):
            got = node_of(doc, ids[n["id"]])["facts"]
            assert set(got) == set(n["facts"])
            for c, f in n["facts"].items():
                want = dict(f, source=SRC)
                stamp = lambda t: dt.datetime.fromisoformat(t.replace("Z", "+00:00"))   # noqa: E731
                have = dict(got[c])
                assert stamp(have.pop("observed_at")) == stamp(want.pop("observed_at"))
                assert have == want, (n["id"], c)
    r = _evaluate(doc, SSH, now + dt.timedelta(minutes=1))
    assert r["verdict"] == "VIOLATED" and len(r["violating_targets"]) == 1


# --------------------------------------------------------------------------- #
# end to end: facts -> real runner -> real library -> findings
# --------------------------------------------------------------------------- #

class _FactsBuilder:
    """A stand-in for the host_fw builder: emits whatever ``self.facts`` holds."""

    SOURCE = SRC

    def __init__(self):
        self.facts: list = []
        self.seen_opts: list = []

    async def load(self, conn, now, **opts):
        return None

    def build(self, rows, now, **opts):
        self.seen_opts.append(opts)
        return BuildOutput(source=SRC, mode="replace", nodes=[NodeOut(f.node_ref, "host") for f in self.facts],
                           facts=list(self.facts))


@pytest.fixture
def fb(monkeypatch):
    b = _FactsBuilder()
    monkeypatch.setattr(builders_pkg, "load_builders", lambda: [b])
    monkeypatch.setattr(settings, "assurance_backstop_min", 100_000)
    monkeypatch.setattr(settings, "assurance_rebuild_min", 100_000)
    runner._LAST_BUILD.clear()
    runner._LAST_EVAL.clear()
    runner._PLAN_CACHE.clear()
    yield b
    runner._LAST_BUILD.clear()
    runner._LAST_EVAL.clear()
    runner._PLAN_CACHE.clear()


async def _go(pool, now, redis, **kw):
    return await runner.run_tenant(pool, A, now=now, redis=redis, rebuild=True, **kw)


async def _host_findings(db_pool):
    return await db_pool.fetch(
        "SELECT f.*, a.kind AS a_kind, a.value AS a_value FROM findings f JOIN assets a ON a.id = f.asset_id "
        "WHERE f.rule_source = 'invariant' ORDER BY f.rule_id")


def _verdict(summary, std_id):
    return next(r for r in summary["results"] if r["invariant_id"] == std_id)


async def test_end_to_end_host_facts_drive_verdicts_and_findings(db_pool, app_pool, fake_redis, fb):
    async with conn_for(app_pool) as con:
        await runner.install_std(con, SSH, actor="test")
    web1, web2 = host(AG1), host(AG2)
    fb.facts = [web1, web2]
    s = await _go(app_pool, T0 + dt.timedelta(minutes=5), fake_redis)
    assert _verdict(s, SSH)["verdict"] == "HOLDS" and s["builders"][SRC]["facts_stored"] == 2
    assert fb.seen_opts[0]["agent_posture_max_age"] == dt.timedelta(hours=6)
    assert await _host_findings(db_pool) == []
    v_hold = await version(app_pool)

    # a PURE refresh (new stamp, new seq): no version bump, nothing re-evaluated
    t1 = T0 + dt.timedelta(minutes=40)
    fb.facts = [host(AG1, at=t1, seq=2), host(AG2, at=t1, seq=2)]
    s = await _go(app_pool, t1, fake_redis)
    assert s["builders"][SRC]["changed"] is False and await version(app_pool) == v_hold
    assert s["evaluated"] == 0 and s["skipped"] == "up_to_date"

    # PasswordAuthentication yes on web2: VIOLATED, one finding for that host only
    t2 = t1 + dt.timedelta(minutes=10)
    fb.facts = [host(AG1, at=t2, seq=3), host(AG2, at=t2, seq=3, password="yes")]
    s = await _go(app_pool, t2, fake_redis)
    r = _verdict(s, SSH)
    assert r["verdict"] == "VIOLATED" and r["findings"]["opened"] == 1
    (f,) = await _host_findings(db_pool)
    assert f["status"] == "open" and f["rule_id"] == f"invariant:{SSH}@{AG2}"
    assert f["a_kind"] == "org" and f["a_value"] == "paddock-assurance"            # estate asset: no cloud asset
    assert "password" in f["description"].lower() and AG2 in f["title"]
    ev = json.loads(f["evidence"]) if isinstance(f["evidence"], str) else f["evidence"]
    assert ev["target_ref"] == AG2 and ev["witness"]["detail"]["node"] == AG2
    assert ev["witness"]["detail"]["tier"] == "configured" and ev["witness"]["detail"]["signed"] == "true"
    assert ev["witness"]["detail"]["key_id"] == KEY

    # the agent goes silent: the facts age past max_age. UNKNOWN, and the open finding stays open
    t3 = t2 + dt.timedelta(hours=7)
    s = await _go(app_pool, t3, fake_redis, force=True)
    assert _verdict(s, SSH)["verdict"] == "UNKNOWN"
    (f,) = await _host_findings(db_pool)
    assert f["status"] == "open"

    # fixed and reported again: HOLDS, the finding closes (configuration evidence: not verified)
    t4 = t3 + dt.timedelta(minutes=10)
    fb.facts = [host(AG1, at=t4, seq=4), host(AG2, at=t4, seq=4)]
    s = await _go(app_pool, t4, fake_redis)
    assert _verdict(s, SSH)["verdict"] == "HOLDS"
    (f,) = await _host_findings(db_pool)
    assert f["status"] == "fixed" and f["fix_verified_at"] is None


async def test_the_agent_tag_puts_hosts_in_scope_without_a_declared_server_label(db_pool, app_pool, fake_redis, fb):
    async with conn_for(app_pool) as con:
        await runner.install_std(con, FWD, actor="test")
    fb.facts = [host(AG1, default="accept")]
    s = await _go(app_pool, T0 + dt.timedelta(minutes=1), fake_redis)
    assert _verdict(s, FWD)["verdict"] == "VIOLATED"
    # a declared 'agent: false' takes it out of scope: no selector match is UNKNOWN, never HOLDS
    async with conn_for(app_pool) as con:
        await store.set_label(con, AG1, "agent", "false", set_by="t", justification="decommissioned")
    s = await _go(app_pool, T0 + dt.timedelta(minutes=2), fake_redis, force=True)
    assert _verdict(s, FWD)["verdict"] == "UNKNOWN"
    assert "empty_selector:to" in _verdict(s, FWD)["reasons"]


async def test_facts_that_cannot_be_stored_leave_the_host_unknown_not_holding(db_pool, app_pool, fake_redis, fb):
    async with conn_for(app_pool) as con:
        await runner.install_std(con, SSH, actor="test")
    bad = host(AG1, sshd={"status": "ok", "data": sshd_data()})      # no 'signed': dropped at persist
    fb.facts = [bad]
    s = await _go(app_pool, T0 + dt.timedelta(minutes=1), fake_redis)
    assert s["builders"][SRC]["skipped"] == 1
    assert _verdict(s, SSH)["verdict"] == "UNKNOWN"


async def test_loaded_documents_carry_no_coverage_for_agent_facts(app_pool):
    """Host facts are NOT reach coverage: a host with facts is still blind in the reach sense."""
    await persist(app_pool, build(host(AG1)))
    doc, _ = await load(app_pool)
    assert "coverage" not in node_of(doc, AG1)


async def test_facts_coexist_with_coverage_and_edges_of_the_same_node(app_pool):
    f = host(AG1)
    out = build(f, edges=[EdgeOut("internet", AG1, "tcp", 22, 22, "configured", SRC, T0)],
                coverage=[CoverageOut(AG1, "in", "configured", T0, SRC)])
    await persist(app_pool, out)
    doc, _ = await load(app_pool)
    n = node_of(doc, AG1)
    assert n["coverage"][0]["source"] == SRC and set(n["facts"]) == {"firewall", "sshd"}
    assert any(e["src"] == "internet" and e["dst"] == AG1 for e in doc["edges"])
    import paddock_assurance as lib
    lib.ReachGraph.from_dict(copy.deepcopy(doc))
