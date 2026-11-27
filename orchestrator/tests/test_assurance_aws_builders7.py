"""builders-7 (docs/ASSURANCE_P2_1.md section 5, D31/D32/D38): the ESTATE residual and the ENI inventory.

The hole this closes: a database admits a security group by reference, the group has one modelled member,
and an unmodelled interface (Lambda, Fargate, endpoint, ...) sits in the same group. No node, edge or unknown
edge represented it, so ``no-internet-to-datastore`` read HOLDS. The fix is a residual node
``estate:<acct>:<region>:<vpc|none>`` with a configured edge ``estate -> dst`` for every security-group-reference
rule whose membership is not PROVEN complete, and the proof is a complete, fresh, untruncated
``DescribeNetworkInterfaces`` read in which every interface is a modelled instance or load balancer of that very
group. Each rule of the proof has a test that fails when the rule is dropped (mutation-checked, see the report).

Sections: pure builder behaviour, the loader/store/library chain (real Postgres, RLS role), the pin, and the
connector's ENI read (moto and a hand-made client for the failure modes moto cannot produce).
"""
from __future__ import annotations

import copy
import datetime as dt
import json
import random
import re
from pathlib import Path

import pytest

from app.assurance import graph_loader, refs, store
from app.assurance.builders import aws_sg

from .test_assurance_aws import (ACCT, NOW, REG, T_NEW, WORLD, TENANT_A, _seed, cov, conn_for, db_row, edge_keys,
                                 edges, inst_row, lb_row, ref, rule, run, sg_row, uid)

VPC = "vpc-0a1b2c"
ESTATE = f"estate:{ACCT}:{REG}:{VPC}"
SG_REF = {"type": "sg", "value": "sg-app"}


# --------------------------------------------------------------------------- #
# builders of rows
# --------------------------------------------------------------------------- #

def inv(*, complete=True, read_at=None, instances=("i-app1",), lbs=(), unmodeled=0, kinds=None, truncated=False,
        total=None, region=REG):
    """The metadata the connector writes on a security group asset (section 5.3)."""
    n = len(instances) + len(lbs) + unmodeled if total is None else total
    return {
        "eni_inventory": {"complete": complete, "read_at": (read_at or T_NEW).isoformat(), "region": region,
                          "eni_total": n},
        "eni_members": {"instances": sorted(instances), "lbs": sorted(lbs),
                        "unmodeled": {"count": unmodeled, "kinds": kinds or ({"lambda": unmodeled} if unmodeled else {}),
                                      "sample": [{"id": f"eni-{i:04d}", "kind": "lambda", "public": False}
                                                 for i in range(min(unmodeled, 10))]},
                        "truncated": truncated},
        "inventory_complete": True,
    }


def sg7(gid, rules, *, vpc=VPC, meta=None, **kw):
    row = sg_row(gid, rules, **kw)
    if vpc is not None:
        row["metadata"]["vpc_id"] = vpc
    row["metadata"].update(meta or {})
    return row


def app(name, sgs, iid, **kw):
    row = inst_row(name, sgs, **kw)
    row["metadata"]["instance_id"] = iid
    return row


def world(app_meta=None, *, dst_sgs=("sg-db",), extra=(), app_rows=None, db_public=False):
    """db (sg-db) admits sg-app by reference; sg-app has one modelled member, app-1 (i-app1)."""
    rows = [db_row("db", list(dst_sgs), public=db_public),
            *(app_rows if app_rows is not None else [app("app-1", ["sg-app"], "i-app1")]),
            sg7("sg-db", [rule("tcp", 5432, 5432, SG_REF)]),
            sg7("sg-app", [], meta=app_meta),
            *extra]
    return rows


def estate_edges(out, dst="db"):
    return edges(out, src=ESTATE, dst=ref(dst))


def member_edge(out):
    return edges(out, src=ref("app-1"), dst=ref("db"))


def kinds_of(out):
    return {n.ref: n.kind for n in out.nodes}


# --------------------------------------------------------------------------- #
# the proof: complete inventory, every ENI a modelled member
# --------------------------------------------------------------------------- #

def test_without_eni_data_a_synced_group_with_members_gets_an_estate_edge():
    out = run(world())
    assert len(member_edge(out)) == 1                                   # the modelled member is still an edge
    (e,) = estate_edges(out)
    assert (e.proto, e.port_lo, e.port_hi, e.basis, e.source) == ("tcp", 5432, 5432, "configured", "aws_sg")
    assert e.evidence["unmodeled_members"] is True and e.evidence["via_sg"] == ["sg-app"]
    assert e.evidence["sg"] == ["sg-db"] and e.evidence["rules"] == [{"sg": "sg-db", "index": 0}]
    assert kinds_of(out)[ESTATE] == "estate"
    assert not any(x.src_ref in ("internet", "cidr:0.0.0.0/0") for x in out.edges)   # never both widenings
    assert cov(out, "db")                                               # an estate edge does not blind the destination


def test_a_complete_fresh_inventory_of_modelled_members_proves_the_estate_away():
    out = run(world(inv()))
    assert estate_edges(out) == [] and ESTATE not in kinds_of(out)
    assert not [n for n in out.nodes if n.kind == "estate"]
    assert edge_keys(out) == {(ref("app-1"), ref("db"), "tcp", 5432, 5432)}
    assert cov(out, "db") and not any("ENI inventory" in n for n in out.notes)


def test_an_inventory_listing_a_modelled_load_balancer_is_proven_by_its_typed_name():
    rows = [db_row("db", ["sg-db"]), app("app-1", ["sg-app"], "i-app1"),
            lb_row("front", ["sg-app"]), sg7("sg-db", [rule("tcp", 5432, 5432, SG_REF)]),
            sg7("sg-app", [], meta=inv(lbs=("app/front",)))]
    out = run(rows)
    assert estate_edges(out) == []
    assert {e.src_ref for e in out.edges} == {ref("app-1"), ref("front")}


@pytest.mark.parametrize("meta", [
    pytest.param(None, id="no inventory at all"),
    pytest.param(inv(complete=False), id="complete false"),
    pytest.param({**inv(), "eni_inventory": {**inv()["eni_inventory"], "complete": "true"}}, id="complete is a string"),
    pytest.param({**inv(), "eni_inventory": {**inv()["eni_inventory"], "complete": 1}}, id="complete is an int"),
    pytest.param({**inv(), "eni_inventory": None}, id="inventory not a dict"),
    pytest.param({**inv(), "eni_members": None}, id="members not a dict"),
    pytest.param({**inv(), "eni_members": {}}, id="members empty dict"),
    pytest.param(inv(truncated=True), id="truncated inventory"),
    pytest.param({**inv(), "eni_members": {**inv()["eni_members"], "truncated": "false"}}, id="truncated not a bool"),
    pytest.param({**inv(), "eni_members": {k: v for k, v in inv()["eni_members"].items() if k != "truncated"}},
                 id="truncated missing"),
    pytest.param(inv(unmodeled=1), id="one Lambda ENI"),
    pytest.param(inv(unmodeled=3, kinds={"ecs": 3}), id="three Fargate ENIs"),
    pytest.param(inv(instances=("i-app1", "i-ghost")), id="an instance that is not a modelled member"),
    pytest.param(inv(instances=("i-other",)), id="a modelled instance of ANOTHER group"),
    pytest.param(inv(lbs=("app/ghost",)), id="a load balancer that is not modelled"),
    pytest.param(inv(lbs=("net/front",)), id="a modelled lb of another TYPE with the same name"),
    pytest.param(inv(lbs=("front",)), id="an untyped lb name"),
    pytest.param(inv(read_at=T_NEW - dt.timedelta(hours=1, seconds=1)), id="read an hour before the sync"),
    pytest.param(inv(read_at=T_NEW + dt.timedelta(hours=1, seconds=1)), id="read an hour after the sync"),
    pytest.param(inv(read_at=NOW + dt.timedelta(days=3)), id="read in the future"),
    pytest.param(inv(read_at=NOW + dt.timedelta(minutes=6)), id="read after the build clock"),
    pytest.param({**inv(), "eni_inventory": {**inv()["eni_inventory"], "read_at": "yesterday"}}, id="unparseable read_at"),
    pytest.param({**inv(), "eni_inventory": {**inv()["eni_inventory"], "read_at": "2026-12-01T11:50:00"}},
                 id="read_at without a zone"),
    pytest.param({**inv(), "eni_inventory": {**inv()["eni_inventory"], "read_at": None}}, id="no read_at"),
    pytest.param({**inv(), "eni_inventory": {**inv()["eni_inventory"], "region": "eu-west-1"}}, id="read of another region"),
    pytest.param({**inv(), "inventory_complete": False}, id="the region's instance or group listing was partial"),
    pytest.param({**inv(), "eni_members": {**inv()["eni_members"], "instances": "i-app1"}}, id="instances not a list"),
    pytest.param({**inv(), "eni_members": {**inv()["eni_members"], "instances": ["i-app1", 7]}}, id="instance not a string"),
    pytest.param({**inv(), "eni_members": {**inv()["eni_members"], "lbs": None}}, id="lbs not a list"),
    pytest.param({**inv(), "eni_members": {**inv()["eni_members"], "unmodeled": None}}, id="unmodeled not a dict"),
    pytest.param({**inv(), "eni_members": {**inv()["eni_members"], "unmodeled": {"kinds": {}, "sample": []}}},
                 id="unmodeled count missing"),
    pytest.param({**inv(), "eni_members": {**inv()["eni_members"],
                                           "unmodeled": {"count": False, "kinds": {}, "sample": []}}},
                 id="unmodeled count is a bool"),
    pytest.param({**inv(), "eni_members": {**inv()["eni_members"],
                                           "unmodeled": {"count": "0", "kinds": {}, "sample": []}}},
                 id="unmodeled count is a string"),
    pytest.param({**inv(), "eni_members": {**inv()["eni_members"],
                                           "unmodeled": {"count": -1, "kinds": {}, "sample": []}}},
                 id="unmodeled count is negative"),
    pytest.param({**inv(), "eni_members": {**inv()["eni_members"],
                                           "unmodeled": {"count": 0.0, "kinds": {}, "sample": []}}},
                 id="unmodeled count is a float"),
])
def test_every_unproven_condition_keeps_the_estate_edge(meta):
    rows = world(meta)
    rows.append(app("other", ["sg-other"], "i-other"))
    rows.append(lb_row("front", ["sg-app"]))
    rows.append(sg7("sg-other", []))
    out = run(rows)
    assert len(estate_edges(out)) == 1, "membership must stay unproven"
    assert kinds_of(out)[ESTATE] == "estate"


def test_the_inventory_is_stale_when_the_groups_row_was_refreshed_without_a_new_read():
    # an older connector keeps refreshing last_seen while the shallow merge keeps the old complete:true
    fresh = world(inv(read_at=T_NEW))
    assert estate_edges(run(fresh)) == []
    old = world(inv(read_at=T_NEW - dt.timedelta(hours=30)))
    assert len(estate_edges(run(old))) == 1


def test_a_sync_clock_ahead_of_now_cannot_make_a_stale_read_fresh():
    # last_seen is clamped to now (future timestamps never make anything fresher): a read_at an hour+ behind
    # the clamped last_seen is stale even when the raw last_seen sits in the future
    future = NOW + dt.timedelta(hours=5)
    rows = world(inv(read_at=NOW - dt.timedelta(hours=2)))
    for r in rows:
        r["last_seen"] = future
    assert len(estate_edges(run(rows))) == 1


def test_a_read_much_newer_than_the_groups_own_last_seen_is_unproven_too():
    # the skew is two sided: an inventory read 90 minutes AFTER the group row was last seen does not describe
    # the membership the rules were read against (the rest of the sync may be that old)
    old = NOW - dt.timedelta(hours=2)

    def rows(read_at):
        rs = world(inv(read_at=read_at))
        for r in rs:
            r["last_seen"] = old
        return rs

    assert estate_edges(run(rows(old))) == []                                    # control: same instant, proven
    assert len(estate_edges(run(rows(NOW - dt.timedelta(minutes=30))))) == 1     # 90 min newer: unproven


def test_the_inventory_boundary_is_one_hour_inclusive():
    assert estate_edges(run(world(inv(read_at=T_NEW - dt.timedelta(hours=1))))) == []
    assert estate_edges(run(world(inv(read_at=T_NEW + dt.timedelta(minutes=15))))) == []   # NOW + 5 min of skew


def test_a_modelled_db_in_the_referenced_group_is_an_unmodelled_eni_by_decision_D32():
    # RDS ENIs are listed as unmodelled on purpose: a db that shares sg-app keeps the estate edge
    rows = world(inv(unmodeled=1, kinds={"rds": 1}), app_rows=[app("app-1", ["sg-app"], "i-app1")])
    rows.append(db_row("db2", ["sg-app"]))
    out = run(rows)
    assert len(estate_edges(out)) == 1


# --------------------------------------------------------------------------- #
# zero modelled members, unsynced groups: the pre-existing widening stays, never both
# --------------------------------------------------------------------------- #

def test_zero_modelled_members_without_a_complete_inventory_stays_world_open_and_has_no_estate():
    rows = [db_row("db", ["sg-db"], public=True), sg7("sg-db", [rule("tcp", 5432, 5432, SG_REF)]), sg7("sg-app", [])]
    out = run(rows)
    (e,) = edges(out, "internet", ref("db"))
    assert e.evidence["unmodeled_sg_members"] == ["sg-app"]
    assert not [n for n in out.nodes if n.kind == "estate"] and not any(x.src_ref.startswith("estate:") for x in out.edges)


def test_zero_modelled_members_with_a_complete_inventory_and_unmodelled_enis_is_estate_not_world_open():
    rows = [db_row("db", ["sg-db"], public=True), sg7("sg-db", [rule("tcp", 5432, 5432, SG_REF)]),
            sg7("sg-app", [], meta=inv(instances=(), unmodeled=2, kinds={"ecs": 2}))]
    out = run(rows)
    assert len(estate_edges(out)) == 1
    assert not edges(out, "internet", ref("db")) and not edges(out, "cidr:0.0.0.0/0", ref("db"))


def test_zero_members_proven_empty_by_a_complete_inventory_is_no_edge_at_all():
    rows = [db_row("db", ["sg-db"], public=True), sg7("sg-db", [rule("tcp", 5432, 5432, SG_REF)]),
            sg7("sg-app", [], meta=inv(instances=()))]
    out = run(rows)
    assert out.edges == [] and cov(out, "db")


def test_an_unsynced_or_cross_account_group_is_still_world_open_with_no_estate():
    rows = [db_row("db", ["sg-db"], public=True),
            sg7("sg-db", [rule("tcp", 5432, 5432, {"type": "sg", "value": "sg-nowhere"},
                               {"type": "sg", "value": "sg-x", "account": "222222222222"})])]
    out = run(rows)
    assert edges(out, "internet", ref("db")) and not any(e.src_ref.startswith("estate:") for e in out.edges)


def test_a_cross_account_group_with_its_own_complete_inventory_needs_no_estate():
    other = "222222222222"
    rows = [db_row("db", ["sg-db"]), app("theirs", ["sg-x"], "i-theirs", acct=other),
            sg7("sg-x", [], acct=other, meta=inv(instances=("i-theirs",))),
            sg7("sg-db", [rule("tcp", 5432, 5432, {"type": "sg", "value": "sg-x", "account": other})])]
    out = run(rows)
    assert {e.src_ref for e in out.edges} == {ref("theirs")}


def test_the_instance_match_is_scoped_to_account_and_region():
    # same instance id string in another account must not prove this group's membership
    rows = [db_row("db", ["sg-db"]), app("theirs", ["sg-app"], "i-app1", acct="222222222222"),
            sg7("sg-app", [], meta=inv(instances=("i-app1",))),
            sg7("sg-db", [rule("tcp", 5432, 5432, SG_REF)])]
    out = run(rows)
    assert len(estate_edges(out)) == 1


# --------------------------------------------------------------------------- #
# the node and its edges
# --------------------------------------------------------------------------- #

def test_the_estate_node_is_canonical_never_covered_and_lists_its_groups():
    rows = world() + [db_row("db2", ["sg-db2"]), sg7("sg-db2", [rule("tcp", 3306, 3306, {"type": "sg", "value": "sg-app2"})]),
                      sg7("sg-app2", [])]
    rows.append(app("app-2", ["sg-app2"], "i-app2"))
    out = run(rows)
    (n,) = [x for x in out.nodes if x.kind == "estate"]
    assert n.ref == ESTATE and refs.is_valid_ref(n.ref) and n.asset_id is None
    assert n.attrs == {"account_id": ACCT, "region": REG, "vpc_id": VPC, "sgs": ["sg-app", "sg-app2"]}
    assert not any(c.node_ref.startswith("estate:") for c in out.coverage)
    assert {(e.src_ref, e.dst_ref) for e in out.edges if e.src_ref == ESTATE} == {(ESTATE, ref("db")), (ESTATE, ref("db2"))}
    assert json.dumps(n.attrs)


def test_a_group_without_a_vpc_id_gets_the_none_residual():
    rows = [db_row("db", ["sg-db"]), app("app-1", ["sg-app"], "i-app1"),
            sg7("sg-db", [rule("tcp", 5432, 5432, SG_REF)], vpc=None), sg7("sg-app", [], vpc=None)]
    out = run(rows)
    assert edges(out, src=f"estate:{ACCT}:{REG}:none", dst=ref("db"))
    rows2 = [db_row("db", ["sg-db"]), app("app-1", ["sg-app"], "i-app1"),
             sg7("sg-db", [rule("tcp", 5432, 5432, SG_REF)]), sg7("sg-app", [], vpc="VPC-NOT VALID")]
    assert edges(run(rows2), src=f"estate:{ACCT}:{REG}:none", dst=ref("db"))


def test_a_destination_account_that_cannot_form_an_estate_ref_widens_instead_of_dropping_the_residual():
    # fail safe: if the residual cannot be represented, the pre-existing world-open widening applies
    bad = "acct-1"
    rows = [db_row("db", ["sg-db"], public=True, acct=bad), app("app-1", ["sg-app"], "i-app1", acct=bad),
            sg7("sg-db", [rule("tcp", 5432, 5432, SG_REF)], acct=bad),
            sg7("sg-app", [], acct=bad)]
    out = run(rows)
    assert not any(e.src_ref.startswith("estate:") for e in out.edges)
    assert edges(out, "internet", ref("db"))
    assert any("estate" in n for n in out.notes)


def test_estate_edges_only_come_from_group_references_never_from_cidr_or_world_sources():
    rows = [db_row("db", ["sg-db"], public=True), app("app-1", ["sg-app"], "i-app1"),
            sg7("sg-db", [rule("tcp", 5432, 5432, SG_REF), rule("tcp", 22, 22, WORLD),
                          rule("tcp", 3306, 3306, {"type": "cidr", "value": "10.0.0.0/16"})]),
            sg7("sg-app", [])]
    out = run(rows)
    assert {e.port_lo for e in out.edges if e.src_ref == ESTATE} == {5432}


def test_each_reference_rule_draws_its_own_estate_edge_and_rules_merge_per_port_range():
    rows = [db_row("db", ["sg-db"]), app("app-1", ["sg-app"], "i-app1"),
            sg7("sg-db", [rule("tcp", 5432, 5432, SG_REF), rule("tcp", 5433, 5433, SG_REF),
                          rule("udp", 53, 53, SG_REF)]),
            sg7("sg-app", [])]
    out = run(rows)
    assert {(e.proto, e.port_lo, e.port_hi) for e in estate_edges(out)} == {
        ("tcp", 5432, 5432), ("tcp", 5433, 5433), ("udp", 53, 53)}


def test_a_self_reference_estate_edge_targets_the_destination_not_itself():
    rows = [app("a", ["sg-c"], "i-a"), app("b", ["sg-c"], "i-b"),
            sg7("sg-c", [rule("tcp", 9000, 9000, {"type": "sg", "value": "sg-c"})])]
    out = run(rows)
    assert {(e.src_ref, e.dst_ref) for e in out.edges if e.src_ref == ESTATE} == {(ESTATE, ref("a")), (ESTATE, ref("b"))}
    proven = [app("a", ["sg-c"], "i-a"), app("b", ["sg-c"], "i-b"),
              sg7("sg-c", [rule("tcp", 9000, 9000, {"type": "sg", "value": "sg-c"})],
                  meta=inv(instances=("i-a", "i-b")))]
    assert not [e for e in run(proven).edges if e.src_ref == ESTATE]


def test_estate_edges_are_the_oldest_input_dated_and_never_in_the_future():
    out = run(world())
    (e,) = estate_edges(out)
    assert e.last_seen <= NOW and e.last_seen.tzinfo is not None


# --------------------------------------------------------------------------- #
# partial region reads withdraw coverage; the note says why
# --------------------------------------------------------------------------- #

def test_a_group_flagged_partial_leaves_every_destination_that_uses_it_blind():
    rows = world(inv())
    rows[-1]["metadata"]["inventory_complete"] = False        # sg-app
    out = run(rows)
    assert cov(out, "db")                                      # the db only references it as a source ...
    assert len(estate_edges(out)) == 1                         # ... whose membership is then unproven
    rows = world(inv(), dst_sgs=("sg-db",))
    rows[2]["metadata"]["inventory_complete"] = False         # sg-db: the destination's own group
    out = run(rows)
    assert not cov(out, "db")
    assert any("partial" in n and "sg-db" in n for n in out.notes)


def test_a_destination_flagged_partial_is_blind_but_keeps_its_known_edges():
    rows = world(inv())
    rows[0]["metadata"]["inventory_complete"] = False
    out = run(rows)
    assert not cov(out, "db") and member_edge(out)


def test_a_partial_flag_of_true_or_absent_changes_nothing():
    rows = world(inv())
    rows[0]["metadata"]["inventory_complete"] = True
    assert cov(run(rows), "db")
    assert cov(run(world(inv())), "db")


def test_the_missing_inventory_note_names_the_cause():
    out = run(world())
    (n,) = [x for x in out.notes if "ENI inventory missing" in x]
    assert n.startswith("aws_sg: 1 SG(s) referenced by rules have unenumerated members (ENI inventory missing)")
    assert "sg-app" in n
    assert not any("ENI inventory missing" in x for x in run(world(inv())).notes)
    assert any("estate" in x and "sg-app" in x for x in out.notes)


def test_an_inventory_that_is_complete_but_lists_a_lambda_is_noted_as_unmodelled_not_as_missing():
    out = run(world(inv(unmodeled=1)))
    assert not any("ENI inventory missing" in x for x in out.notes)
    assert any("estate" in x for x in out.notes)


# --------------------------------------------------------------------------- #
# determinism, purity, store contract
# --------------------------------------------------------------------------- #

def test_output_is_byte_identical_whatever_the_row_order():
    rows = world(inv(unmodeled=1)) + [lb_row("front", ["sg-app"])]
    ref_out = run(rows)
    for seed in range(8):
        shuffled = rows[:]
        random.Random(seed).shuffle(shuffled)
        assert run(shuffled) == ref_out
    assert [n.ref for n in ref_out.nodes] == sorted(n.ref for n in ref_out.nodes)


def test_build_does_not_mutate_its_input_rows():
    rows = world(inv(unmodeled=1))
    before = copy.deepcopy(rows)
    run(rows)
    assert rows == before


def test_every_estate_node_and_edge_is_something_the_store_accepts():
    out = run(world())
    for n in out.nodes:
        assert refs.is_valid_ref(n.ref) and n.kind in refs.KINDS
        json.dumps(n.attrs)
    for e in out.edges:
        assert refs.is_valid_ref(e.src_ref) and refs.is_valid_ref(e.dst_ref)
        json.dumps(e.evidence)


def test_garbage_in_the_eni_fields_never_raises_and_never_proves():
    for junk in ({"eni_inventory": "x", "eni_members": 3}, {"eni_inventory": [], "eni_members": []},
                 {"eni_inventory": {"complete": True}, "eni_members": {"instances": [None], "lbs": [[]],
                                                                       "unmodeled": {"count": None}}}):
        out = run(world({**junk, "vpc_id": 5}))
        assert len([e for e in out.edges if e.src_ref.startswith("estate:")]) == 1


# --------------------------------------------------------------------------- #
# loader, store and library: the chain a verdict is computed from (real Postgres, RLS role)
# --------------------------------------------------------------------------- #

PLAN = """\
apiVersion: paddock.dev/invariant/v1
id: acme:db-not-from-internet
title: Databases are not reachable from the internet
severity: critical
subjects:
  from: { id: internet }
  to: { class: data_store }
assert: unreachable
via: { protocols: [tcp], max_hops: 6 }
evidence: { min_tier: configured, max_age: 24h }
coverage: { require: 0.0 }
"""


async def _chain(db_pool, app_pool, rows, now=NOW):
    """seed -> aws_sg.load/build -> persist -> graph document -> library verdict."""
    import paddock_assurance as lib

    for r in rows:
        await _seed(db_pool, r, TENANT_A)
    async with conn_for(app_pool) as con:
        out = aws_sg.build(await aws_sg.load(con, now), now)
        await store.persist_build(con, out, now)
        doc = await graph_loader.load_graph_doc(con, now)
    graph = lib.ReachGraph.from_dict(doc)
    return out, doc, lib.evaluate(lib.compile_text(PLAN), graph, now)


async def test_unmodelled_eni_in_a_referenced_group_is_unknown_with_the_estate_witness_never_holds(db_pool, app_pool):
    out, doc, res = await _chain(db_pool, app_pool, world())
    assert res.verdict.value == "UNKNOWN", (res.verdict, res.reasons)
    assert "possible_via_unknown_edges" in res.reasons
    hops = [(h.src, h.dst, h.basis) for h in res.witnesses[0].hops]
    assert hops == [("internet", ESTATE, "unknown"), (ESTATE, ref("db"), "configured")]
    est = next(n for n in doc["nodes"] if n["id"] == ESTATE)
    assert est["kind"] == "estate" and est.get("zone_unknown") is True and not est.get("coverage")


async def test_a_complete_inventory_with_only_modelled_members_holds(db_pool, app_pool):
    _, doc, res = await _chain(db_pool, app_pool, world(inv()))
    assert ESTATE not in {n["id"] for n in doc["nodes"]}
    assert res.verdict.value == "HOLDS", (res.verdict, res.reasons)


async def test_one_lambda_eni_turns_the_complete_inventory_unknown_again(db_pool, app_pool):
    _, _, res = await _chain(db_pool, app_pool, world(inv(unmodeled=1)))
    assert res.verdict.value == "UNKNOWN" and "possible_via_unknown_edges" in res.reasons


async def test_the_estate_node_is_not_cidr_expanded_and_never_covered_in_the_document(db_pool, app_pool):
    rows = world() + [sg7("sg-cidr", [rule("tcp", 22, 22, {"type": "cidr", "value": "10.0.0.0/16"})]),
                      db_row("db3", ["sg-cidr"])]
    _, doc, _ = await _chain(db_pool, app_pool, rows)
    assert not any(e["src"] == ESTATE and e["dst"] == ref("db3") for e in doc["edges"])
    assert {e["dst"] for e in doc["edges"] if e["src"] == ESTATE} == {ref("db")}


async def test_estate_ignores_operator_labels_in_the_document(db_pool, app_pool):
    for r in world():
        await _seed(db_pool, r, TENANT_A)
    now = NOW
    async with conn_for(app_pool) as con:
        await store.persist_build(con, aws_sg.build(await aws_sg.load(con, now), now), now)
        # the label writer refuses an estate node outright ...
        for tag, value in (("zone", "dmz"), ("class", "data_store"), ("kind", "host"), ("crown-jewel", "true")):
            with pytest.raises(ValueError):
                store.validate_label(ESTATE, tag, value)
        # ... and a row that got there anyway (a direct write) is still ignored by the loader
        await con.execute(
            "INSERT INTO asset_labels (node_ref, tag, value, source, set_by, justification, set_at) VALUES "
            "($1, 'zone', 'dmz', 'declared', 'x', 'y', $2), ($1, 'class', 'data_store', 'declared', 'x', 'y', $2), "
            "($1, 'kind', 'host', 'declared', 'x', 'y', $2)", ESTATE, now)
        for direction in ("in", "out"):       # ... and so is coverage written around the store
            await con.execute(
                "INSERT INTO reach_coverage (node_ref, direction, source, tier, observed_at) "
                "VALUES ($1, $2, 'aws_sg', 'configured', $3)", ESTATE, direction, now)
        doc = await graph_loader.load_graph_doc(con, now)
    est = next(n for n in doc["nodes"] if n["id"] == ESTATE)
    assert est["kind"] == "estate" and est.get("zone_unknown") is True
    assert "zone" not in est and "class" not in est and not est.get("tags") and not est.get("coverage")


async def test_the_loader_lets_the_ref_prefix_decide_the_kind_of_a_node_written_around_the_store(db_pool, app_pool):
    none_ref = f"estate:{ACCT}:{REG}:none"
    async with conn_for(app_pool) as con:
        await con.execute(
            "INSERT INTO reach_nodes (node_ref, kind, source) VALUES ($1, 'host', 'x'), ('ip:10.9.9.9', 'estate', 'x')",
            none_ref)
        doc = await graph_loader.load_graph_doc(con, NOW)
    kinds = {n["id"]: n["kind"] for n in doc["nodes"]}
    assert kinds[none_ref] == "estate" and kinds["ip:10.9.9.9"] == "ip"
    assert next(n for n in doc["nodes"] if n["id"] == none_ref)["zone_unknown"] is True
    assert "zone_unknown" not in next(n for n in doc["nodes"] if n["id"] == "ip:10.9.9.9")


async def test_estate_kind_and_ref_are_tied_together_by_the_store(db_pool, app_pool):
    from app.assurance.types import BuildOutput, CoverageOut, NodeOut

    async with conn_for(app_pool) as con:
        rep = await store.persist_build(con, BuildOutput("aws_sg", "replace", [
            NodeOut(ESTATE, "estate", "ok"),
            NodeOut(f"estate:{ACCT}:{REG}:none", "host", "kind must be estate"),
            NodeOut(f"asset:{uid('x')}", "estate", "an asset is not an estate"),
        ], [], [CoverageOut(ESTATE, "in", "configured", NOW, "aws_sg")]), NOW)
        rows = {r["node_ref"]: r["kind"] for r in await con.fetch("SELECT node_ref, kind FROM reach_nodes")}
        cov_rows = await con.fetchval("SELECT count(*) FROM reach_coverage")
    assert rows == {ESTATE: "estate"}
    assert rep.skipped >= 3 and cov_rows == 0


async def test_persisting_the_estate_is_stable_and_it_leaves_when_the_proof_arrives(db_pool, app_pool):
    rows = world()
    for r in rows:
        await _seed(db_pool, r, TENANT_A)
    async with conn_for(app_pool) as con:
        out = aws_sg.build(await aws_sg.load(con, NOW), NOW)
        assert (await store.persist_build(con, out, NOW)).changed
        assert (await store.persist_build(con, aws_sg.build(await aws_sg.load(con, NOW), NOW), NOW)).changed is False
        assert await con.fetchval("SELECT count(*) FROM reach_edges WHERE src_ref LIKE 'estate:%'") == 1
    async with db_pool.acquire() as con:
        md = rows[-1]["metadata"] | inv()
        await con.execute("UPDATE assets SET metadata = $2::jsonb WHERE id = $1::uuid", rows[-1]["id"], json.dumps(md))
    async with conn_for(app_pool) as con:
        rep = await store.persist_build(con, aws_sg.build(await aws_sg.load(con, NOW), NOW), NOW)
        assert rep.changed and rep.edges_removed == 1
        assert await con.fetchval("SELECT count(*) FROM reach_edges WHERE src_ref LIKE 'estate:%'") == 0


# --------------------------------------------------------------------------- #
# the dependency pin (D38)
# --------------------------------------------------------------------------- #

def test_the_orchestrator_pins_the_library_that_knows_the_estate_kind():
    import importlib

    import paddock_assurance as lib
    lib_eval = importlib.import_module("paddock_assurance.evaluate")   # the package re-exports the function

    root = Path(__file__).resolve().parents[1]
    text = (root / "pyproject.toml").read_text()
    m = re.search(r'"paddock-assurance\s*>=\s*([0-9]+)\.([0-9]+)(?:\.([0-9]+))?"', text)
    assert m, "orchestrator/pyproject.toml must declare paddock-assurance>=0.4.0"
    assert tuple(int(x or 0) for x in m.groups()) >= (0, 4, 0)
    have = tuple(int(x) for x in lib.__version__.split(".")[:3])
    assert have >= tuple(int(x or 0) for x in m.groups())
    assert "estate" in lib_eval.PSEUDO_KINDS
