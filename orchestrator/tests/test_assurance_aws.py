"""aws_sg builder (docs/ASSURANCE_P1.md 4.1): pure behaviour with hand-built rows, plus an end
to end run of the real AWS connector (moto) through ``apply_source_batch`` -> ``load`` -> ``build``
-> ``persist_build``, and the RLS-aware loader.

The soundness claims each have a test that fails when the code is weakened (mutation-checked, see
the final report): coverage only when every SG synced; unknown things widen to world-open; CIDR
and SG sources expand to the modeled nodes inside them; ``0.0.0.0/0`` on an unaddressable node
is NOT the internet.
"""
from __future__ import annotations

import contextlib
import datetime as dt
import json
import random
import uuid

import pytest

from app import tenancy
from app.assurance import refs
from app.assurance.builders import aws_sg
from app.assurance.types import BuildOutput

NOW = dt.datetime(2026, 12, 1, 12, 0, tzinfo=dt.timezone.utc)
T_OLD = NOW - dt.timedelta(hours=5)
T_MID = NOW - dt.timedelta(hours=2)
T_NEW = NOW - dt.timedelta(minutes=10)
ACCT, REG = "111111111111", "us-east-1"
WORLD = {"type": "cidr", "value": "0.0.0.0/0"}
WORLD6 = {"type": "cidr6", "value": "::/0"}


def uid(name: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, name))


def ref(name: str) -> str:
    return refs.asset_ref(uid(name))


def rule(proto="tcp", lo=443, hi=None, *sources, **extra):
    return {"proto": proto, "from": lo, "to": lo if hi is None else hi,
            "sources": list(sources or [WORLD]), **extra}


def sg_row(gid, rules, *, acct=ACCT, region=REG, seen=T_NEW, truncated=False, name=None):
    md = {"provider": "aws", "resource_type": "security_group", "account_id": acct,
          "region": region, "group_id": gid, "ingress_truncated": truncated}
    if rules is not None:
        md["ingress_rules"] = rules
    return {"id": uid(name or f"{acct}/{region}/{gid}"), "canonical":
            f"arn:aws:ec2:{region}:{acct}:security-group/{gid}", "last_seen": seen, "metadata": md}


def inventory(row, *, instances=(), lbs=(), read_at=T_NEW):
    """Give a security-group row the COMPLETE ENI inventory the connector writes (docs/ASSURANCE_P2_1.md 5.3):
    the listed instances and load balancers are all that sits in the group. Without it a group referenced by a
    rule has unproven membership and draws an estate edge (tests/test_assurance_aws_builders7.py)."""
    row["metadata"].update(
        inventory_complete=True,
        eni_inventory={"complete": True, "read_at": read_at.isoformat(), "region": row["metadata"]["region"],
                       "eni_total": len(instances) + len(lbs)},
        eni_members={"instances": sorted(instances), "lbs": sorted(lbs), "truncated": False,
                     "unmodeled": {"count": 0, "kinds": {}, "sample": []}})
    return row


def inst_row(name, sgs, *, public=("54.0.0.1",), private=("10.0.0.5",), acct=ACCT, region=REG,
             seen=T_NEW, iid=None):
    md = {"provider": "aws", "resource_type": "instance", "account_id": acct, "region": region,
          "name": name, "private_ips": list(private)}
    if iid:
        md["instance_id"] = iid
    if sgs is not None:
        md["security_groups"] = list(sgs)
    if public is not None:
        md["public_ips"] = list(public)
    return {"id": uid(name), "canonical": f"arn:aws:ec2:{region}:{acct}:instance/{name}",
            "last_seen": seen, "metadata": md}


def db_row(name, sgs, *, public=False, acct=ACCT, region=REG, seen=T_NEW, port=5432):
    md = {"provider": "aws", "resource_type": "db_instance", "account_id": acct, "region": region,
          "name": name, "security_groups": list(sgs), "port": port}
    if public is not None:
        md["publicly_accessible"] = public
    return {"id": uid(name), "canonical": f"arn:aws:rds:{region}:{acct}:db:{name}",
            "last_seen": seen, "metadata": md}


def lb_row(name, sgs, *, scheme="internet-facing", acct=ACCT, region=REG, seen=T_NEW):
    md = {"provider": "aws", "resource_type": "application_load_balancer", "account_id": acct,
          "region": region, "name": name, "security_groups": list(sgs)}
    if scheme is not None:
        md["scheme"] = scheme
    return {"id": uid(name), "canonical": f"arn:aws:elasticloadbalancing:{region}:{acct}:lb/{name}",
            "last_seen": seen, "metadata": md}


def run(rows, **opts) -> BuildOutput:
    return aws_sg.build(rows, NOW, **opts)


def edges(out, src=None, dst=None):
    return [e for e in out.edges
            if (src is None or e.src_ref == src) and (dst is None or e.dst_ref == dst)]


def edge_keys(out):
    return {(e.src_ref, e.dst_ref, e.proto, e.port_lo, e.port_hi) for e in out.edges}


def cov(out, name):
    return [c for c in out.coverage if c.node_ref == ref(name)]


# --------------------------------------------------------------------------- #
# Internet addressability
# --------------------------------------------------------------------------- #

def test_world_open_on_public_instance_is_internet_to_node():
    out = run([inst_row("web", ["sg-w"]), sg_row("sg-w", [rule("tcp", 443)])])
    assert edge_keys(out) == {("internet", ref("web"), "tcp", 443, 443)}
    (e,) = out.edges
    assert (e.basis, e.source, e.confidence) == ("configured", "aws_sg", 100)
    assert "assumed_public" not in e.evidence
    assert e.evidence["dst_asset"] == uid("web") and e.evidence["sg"] == ["sg-w"]
    assert e.evidence["rules"] == [{"sg": "sg-w", "index": 0}]
    assert {n.ref: n.kind for n in out.nodes} == {
        ref("web"): "cloud_instance", "internet": "internet"}


def test_world_open_on_private_instance_is_not_the_internet():
    out = run([inst_row("db1", ["sg-d"], public=[]), sg_row("sg-d", [rule("tcp", 22)])])
    keys = edge_keys(out)
    assert ("cidr:0.0.0.0/0", ref("db1"), "tcp", 22, 22) in keys
    assert not any(k[0] == "internet" for k in keys)
    assert {n.ref for n in out.nodes} == {ref("db1"), "cidr:0.0.0.0/0"}
    assert cov(out, "db1")           # the rules are fully known, the node is simply not addressable


def test_unknown_addressability_assumes_public_and_says_so():
    rows = [inst_row("a", ["sg-1"], public=None), db_row("b", ["sg-1"], public=None),
            lb_row("c", ["sg-1"], scheme=None), sg_row("sg-1", [rule("tcp", 80)])]
    out = run(rows)
    for name in "abc":
        (e,) = edges(out, "internet", ref(name))
        assert e.evidence["assumed_public"] is True


def test_rds_and_lb_addressability():
    rows = [db_row("pub", ["sg-1"], public=True), db_row("priv", ["sg-1"], public=False),
            lb_row("ext", ["sg-1"]), lb_row("int", ["sg-1"], scheme="internal"),
            sg_row("sg-1", [rule("tcp", 5432)])]
    out = run(rows)
    assert edges(out, "internet", ref("pub")) and edges(out, "internet", ref("ext"))
    assert not edges(out, "internet", ref("priv")) and not edges(out, "internet", ref("int"))
    assert edges(out, "cidr:0.0.0.0/0", ref("priv")) and edges(out, "cidr:0.0.0.0/0", ref("int"))
    assert {n.kind for n in out.nodes} >= {"cloud_db", "cloud_lb"}


# --------------------------------------------------------------------------- #
# Ports and protocols are the rule's, not the node's
# --------------------------------------------------------------------------- #

def test_ports_are_the_rules_range_not_the_databases_default():
    out = run([db_row("pg", ["sg-1"], public=True, port=5432),
               sg_row("sg-1", [rule("tcp", 6000, 6100), rule("udp", 53), rule("icmp", 0, 0),
                               rule("any", 0, 65535)])])
    assert edge_keys(out) == {
        ("internet", ref("pg"), "tcp", 6000, 6100), ("internet", ref("pg"), "udp", 53, 53),
        ("internet", ref("pg"), "icmp", 0, 0), ("internet", ref("pg"), "any", 1, 65535)}
    assert not [e for e in out.edges if e.port_lo <= 5432 <= e.port_hi and e.proto == "tcp"]


def test_a_node_in_several_groups_gets_the_union_of_their_rules():
    out = run([inst_row("x", ["sg-a", "sg-b"]), sg_row("sg-a", [rule("tcp", 22)]),
               sg_row("sg-b", [rule("tcp", 22), rule("tcp", 80)])])
    got = {(e.port_lo, tuple(e.evidence["sg"])) for e in edges(out, "internet", ref("x"))}
    assert got == {(22, ("sg-a", "sg-b")), (80, ("sg-b",))}      # same rule in two groups merges


def test_port_zero_and_wide_ranges_stay_inside_the_stores_bounds():
    out = run([inst_row("x", ["sg-1"]),
               sg_row("sg-1", [rule("tcp", 0, 1024), rule("tcp", 0, 0), rule("tcp", 9, 4), rule("bogus", 1)])])
    for e in out.edges:
        assert 1 <= e.port_lo <= e.port_hi <= 65535 or e.proto == "icmp"
    assert ("internet", ref("x"), "tcp", 1, 1024) in edge_keys(out)
    assert ("internet", ref("x"), "tcp", 1, 65535) in edge_keys(out)      # 0-0 widened, not dropped
    assert not cov(out, "x")                                              # the bogus rule: blind


# --------------------------------------------------------------------------- #
# CIDR / SG / IPv6 / prefix-list sources
# --------------------------------------------------------------------------- #

def test_ipv6_world_open():
    pub = run([inst_row("a", ["sg-1"]), sg_row("sg-1", [rule("tcp", 443, 443, WORLD6)])])
    assert edge_keys(pub) == {("internet", ref("a"), "tcp", 443, 443)}
    priv = run([inst_row("a", ["sg-1"], public=[]), sg_row("sg-1", [rule("tcp", 443, 443, WORLD6)])])
    assert ("cidr:::/0", ref("a"), "tcp", 443, 443) in edge_keys(priv)
    assert refs.is_valid_ref("cidr:::/0")
    v6 = run([inst_row("a", ["sg-1"]),
              sg_row("sg-1", [rule("tcp", 22, 22, {"type": "cidr6", "value": "2001:db8::/32"})])])
    assert edge_keys(v6) == {("cidr:2001:db8::/32", ref("a"), "tcp", 22, 22)}


def test_other_cidr_is_a_cidr_node_and_expands_to_nodes_inside_it():
    rows = [inst_row("tgt", ["sg-t"], public=[], private=["10.0.1.9"]),
            inst_row("inside", ["sg-o"], private=["10.0.0.7"]),
            inst_row("outside", ["sg-o"], private=["192.168.5.5"]),
            lb_row("noips", ["sg-o"]),
            sg_row("sg-t", [rule("tcp", 8080, 8080, {"type": "cidr", "value": "10.0.0.0/24"})]),
            sg_row("sg-o", [])]
    out = run(rows)
    assert ("cidr:10.0.0.0/24", ref("tgt"), "tcp", 8080, 8080) in edge_keys(out)
    assert not any(e.src_ref == "internet" for e in out.edges)
    # the soundness point: a public instance in that CIDR is a stepping stone, so it must be a source
    assert (ref("inside"), ref("tgt"), "tcp", 8080, 8080) in edge_keys(out)
    assert (ref("outside"), ref("tgt"), "tcp", 8080, 8080) not in edge_keys(out)
    unknown = edges(out, ref("noips"), ref("tgt"))
    assert unknown and unknown[0].evidence["ip_unknown"] is True       # IPs unknown -> may be inside


def test_world_open_private_node_is_reachable_from_every_other_node():
    """The stepping-stone case: internet -> public A -> private B (world-open rule, no public IP).
    Without these edges the graph would have no internet path to B and HOLDS would be false."""
    out = run([inst_row("a", ["sg-a"]), inst_row("b", ["sg-b"], public=[], private=["10.0.0.8"]),
               sg_row("sg-a", [rule("tcp", 443)]), sg_row("sg-b", [rule("tcp", 5432)])])
    keys = edge_keys(out)
    assert ("internet", ref("a"), "tcp", 443, 443) in keys
    assert (ref("a"), ref("b"), "tcp", 5432, 5432) in keys
    assert ("internet", ref("b"), "tcp", 5432, 5432) not in keys


def test_broad_public_cidr_is_the_world_but_broad_private_is_not():
    assert aws_sg.is_world_like(aws_sg._parse_net("0.0.0.0/0"))
    assert aws_sg.is_world_like(aws_sg._parse_net("0.0.0.0/1"))
    assert aws_sg.is_world_like(aws_sg._parse_net("2000::/3"))
    assert not aws_sg.is_world_like(aws_sg._parse_net("10.0.0.0/8"))
    assert not aws_sg.is_world_like(aws_sg._parse_net("203.0.113.0/24"))
    out = run([inst_row("a", ["sg-1"]),
               sg_row("sg-1", [rule("tcp", 22, 22, {"type": "cidr", "value": "0.0.0.0/1"}),
                               rule("tcp", 23, 23, {"type": "cidr", "value": "10.0.0.0/8"})])])
    (e22,) = edges(out, "internet", ref("a"))
    assert e22.port_lo == 22 and e22.evidence["broad_public_cidr"] is True
    assert ("cidr:10.0.0.0/8", ref("a"), "tcp", 23, 23) in edge_keys(out)


def test_sg_source_is_every_member_of_that_group():
    # sg-web is referenced by a rule, so its membership must be proven (else an estate edge is added): a
    # complete inventory naming exactly its three modeled members does that
    rows = [inst_row("web1", ["sg-web"], iid="i-web1"),
            inst_row("web2", ["sg-web"], public=[], private=["10.0.0.6"], iid="i-web2"),
            lb_row("alb", ["sg-web", "sg-lb"]), inst_row("other", ["sg-other"]),
            db_row("db", ["sg-db"]),
            inventory(sg_row("sg-web", []), instances=["i-web1", "i-web2"], lbs=["app/alb"]),
            sg_row("sg-lb", []), sg_row("sg-other", []),
            sg_row("sg-db", [rule("tcp", 5432, 5432, {"type": "sg", "value": "sg-web"})])]
    out = run(rows)
    assert edge_keys(out) == {(ref(m), ref("db"), "tcp", 5432, 5432) for m in ("web1", "web2", "alb")}
    e = edges(out, ref("web1"), ref("db"))[0]
    assert e.evidence["via_sg"] == ["sg-web"] and e.evidence["src_asset"] == uid("web1")
    assert not any(e.src_ref == "internet" for e in out.edges)   # a private db is not the internet
    assert cov(out, "db")


def test_sg_self_reference_connects_members_but_not_a_node_to_itself():
    out = run([inst_row("a", ["sg-c"], iid="i-a"), inst_row("b", ["sg-c"], iid="i-b"),
               inventory(sg_row("sg-c", [rule("tcp", 9000, 9000, {"type": "sg", "value": "sg-c"})]),
                         instances=["i-a", "i-b"])])
    assert edge_keys(out) == {(ref("a"), ref("b"), "tcp", 9000, 9000),
                              (ref("b"), ref("a"), "tcp", 9000, 9000)}


def test_cross_account_sg_reference_resolves_by_account_and_region():
    other = "222222222222"
    rows = [db_row("db", ["sg-db"]), inst_row("theirs", ["sg-x"], acct=other),
            inst_row("mine", ["sg-x"]),     # same id in OUR account: must not be confused
            sg_row("sg-x", [], acct=other), sg_row("sg-x", []),
            sg_row("sg-db", [rule("tcp", 5432, 5432,
                                  {"type": "sg", "value": "sg-x", "account": other})])]
    keys = edge_keys(run(rows))
    assert (ref("theirs"), ref("db"), "tcp", 5432, 5432) in keys
    assert (ref("mine"), ref("db"), "tcp", 5432, 5432) not in keys


def test_prefix_list_is_over_approximated_and_noted():
    rows = [inst_row("pub", ["sg-1"]), inst_row("priv", ["sg-2"], public=[]),
            sg_row("sg-1", [rule("tcp", 22, 22, {"type": "prefix_list", "value": "pl-1"})]),
            sg_row("sg-2", [rule("tcp", 22, 22, {"type": "prefix_list", "value": "pl-1"})])]
    out = run(rows)
    (e,) = edges(out, "internet", ref("pub"))
    assert e.evidence["prefix_list"] == ["pl-1"]
    assert edges(out, "cidr:0.0.0.0/0", ref("priv"))[0].evidence["prefix_list"] == ["pl-1"]
    assert any("prefix list" in n and "pl-1" in n for n in out.notes)
    assert cov(out, "pub") and cov(out, "priv")          # widened, so coverage is still honest


def test_unresolved_and_unmodeled_sg_references_widen():
    rows = [db_row("db", ["sg-db"], public=True),
            sg_row("sg-empty", []),
            sg_row("sg-db", [rule("tcp", 1, 1, {"type": "sg", "value": "sg-nowhere"}),
                             rule("tcp", 2, 2, {"type": "sg", "value": "sg-empty"})])]
    out = run(rows)
    by_port = {e.port_lo: e for e in edges(out, "internet", ref("db"))}
    assert by_port[1].evidence["unresolved_sg"] == ["sg-nowhere"]
    assert by_port[2].evidence["unmodeled_sg_members"] == ["sg-empty"]
    assert any("not synced" in n for n in out.notes) and any("no modeled member" in n for n in out.notes)


def test_unparsed_cidr_is_the_whole_world():
    out = run([inst_row("a", ["sg-1"]),
               sg_row("sg-1", [rule("tcp", 22, 22, {"type": "cidr", "value": "oops"}),
                               rule("tcp", 23, 23, {"type": "cidr", "value": "0.0.0.0/0",
                                                    "unparsed": True})])])
    assert {e.port_lo for e in edges(out, "internet", ref("a"))} == {22, 23}
    assert all(e.evidence["unparsed_source"] is True for e in edges(out, "internet", ref("a")))


# --------------------------------------------------------------------------- #
# Coverage: inbound, configured, only when everything is known
# --------------------------------------------------------------------------- #

def test_coverage_is_inbound_configured_and_dated_by_the_oldest_input():
    out = run([inst_row("a", ["sg-1", "sg-2"], seen=T_MID),
               sg_row("sg-1", [rule("tcp", 22)], seen=T_OLD), sg_row("sg-2", [], seen=T_NEW)])
    (c,) = out.coverage
    assert (c.node_ref, c.direction, c.tier, c.source) == (ref("a"), "in", "configured", "aws_sg")
    assert c.observed_at == T_OLD
    assert c.detail == {"security_groups": ["sg-1", "sg-2"], "synced_rules": True}


def test_empty_synced_rules_mean_covered_with_no_inbound_edges():
    out = run([inst_row("a", ["sg-1"]), sg_row("sg-1", [])])
    assert out.edges == [] and [c.node_ref for c in out.coverage] == [ref("a")]


def test_missing_ingress_rules_means_no_coverage_and_a_note():
    out = run([inst_row("a", ["sg-1"]), sg_row("sg-1", None)])
    assert out.coverage == [] and any("without synced ingress rules" in n for n in out.notes)


def test_one_unsynced_group_blinds_the_whole_node_but_keeps_known_edges():
    out = run([inst_row("a", ["sg-1", "sg-2"]), inst_row("b", ["sg-1"]),
               sg_row("sg-1", [rule("tcp", 22)]), sg_row("sg-2", None)])
    assert [c.node_ref for c in out.coverage] == [ref("b")]
    assert ("internet", ref("a"), "tcp", 22, 22) in edge_keys(out)   # still over-approximating


def test_group_never_synced_at_all_blinds_the_node():
    out = run([inst_row("a", ["sg-ghost"])])
    assert out.coverage == [] and any("not synced" in n for n in out.notes)


def test_truncated_rules_never_claim_coverage():
    out = run([inst_row("a", ["sg-1"]), sg_row("sg-1", [rule("tcp", 22)], truncated=True)])
    assert out.coverage == [] and any("capped" in n for n in out.notes)


def test_unreadable_rule_widens_and_blinds():
    out = run([inst_row("a", ["sg-1"]), sg_row("sg-1", ["not-a-rule"])])
    assert out.coverage == []
    assert ("internet", ref("a"), "any", 1, 65535) in edge_keys(out)


def test_nodes_without_security_group_data_are_blind_and_noted():
    rows = [inst_row("nokey", None), inst_row("empty", []), lb_row("nlb", [])]
    out = run(rows)
    assert out.coverage == [] and out.edges == []
    assert any("no security-group data" in n for n in out.notes)
    assert {n.ref for n in out.nodes} == {ref("nokey"), ref("empty"), ref("nlb")}   # still nodes


def test_coverage_is_never_outbound_and_never_for_the_internet_or_cidrs():
    out = run([inst_row("a", ["sg-1"]), inst_row("b", ["sg-1"], public=[]),
               sg_row("sg-1", [rule("tcp", 22), rule("tcp", 23, 23, {"type": "cidr", "value": "10.0.0.0/8"})])])
    assert out.coverage and {c.direction for c in out.coverage} == {"in"}
    assert {c.node_ref for c in out.coverage} <= {ref("a"), ref("b")}


def test_future_timestamps_do_not_make_coverage_fresher_than_now():
    future = NOW + dt.timedelta(hours=3)
    out = run([inst_row("a", ["sg-1"], seen=future), sg_row("sg-1", [], seen=future)])
    assert out.coverage[0].observed_at == NOW


def test_expansion_cap_degrades_to_blind_not_to_a_wrong_hold():
    rows = [inst_row(f"n{i}", ["sg-o"], private=[f"10.0.0.{i + 10}"]) for i in range(5)]
    rows += [inst_row("t", ["sg-t"]), sg_row("sg-o", []),
             sg_row("sg-t", [rule("tcp", 22, 22, {"type": "cidr", "value": "10.0.0.0/24"})])]
    full = run(rows)
    assert cov(full, "t")
    capped = run(rows, max_expanded_edges=2)
    assert not cov(capped, "t") and any("edge cap" in n for n in capped.notes)
    assert cov(capped, "n0")                    # other nodes are unaffected
    assert ("cidr:10.0.0.0/24", ref("t"), "tcp", 22, 22) in edge_keys(capped)


# --------------------------------------------------------------------------- #
# Identity: SG ids are only unique per (account, region)
# --------------------------------------------------------------------------- #

def test_same_sg_id_in_two_regions_and_accounts_does_not_collide():
    rows = [
        inst_row("east", ["sg-1"]), sg_row("sg-1", [rule("tcp", 22)]),
        inst_row("west", ["sg-1"], region="us-west-2"), sg_row("sg-1", [], region="us-west-2"),
        inst_row("other", ["sg-1"], acct="222222222222"),
        sg_row("sg-1", [rule("tcp", 443)], acct="222222222222"),
        inst_row("unsynced", ["sg-1"], region="eu-west-1"),     # no sg-1 row in that region
    ]
    out = run(rows)
    ports_into = {n: {(e.proto, e.port_lo) for e in out.edges if e.dst_ref == ref(n)}
                  for n in ("east", "west", "other", "unsynced")}
    assert ports_into == {"east": {("tcp", 22)}, "west": set(), "other": {("tcp", 443)},
                          "unsynced": set()}
    assert {k for k in edge_keys(out) if k[0] == "internet"} == {
        ("internet", ref("east"), "tcp", 22, 22), ("internet", ref("other"), "tcp", 443, 443)}
    assert {c.node_ref for c in out.coverage} == {ref("east"), ref("west"), ref("other")}
    assert not cov(out, "unsynced")


def test_sg_members_are_scoped_to_account_and_region():
    rows = [db_row("db", ["sg-db"]), inst_row("here", ["sg-w"]),
            inst_row("elsewhere", ["sg-w"], region="us-west-2"),
            sg_row("sg-w", []), sg_row("sg-w", [], region="us-west-2"),
            sg_row("sg-db", [rule("tcp", 5432, 5432, {"type": "sg", "value": "sg-w"})])]
    assert (ref("here"), ref("db"), "tcp", 5432, 5432) in edge_keys(run(rows))
    assert (ref("elsewhere"), ref("db"), "tcp", 5432, 5432) not in edge_keys(run(rows))


# --------------------------------------------------------------------------- #
# Determinism / hygiene
# --------------------------------------------------------------------------- #

def _world():
    return [inst_row("web", ["sg-web"]), inst_row("app", ["sg-app"], public=[]),
            db_row("db", ["sg-db"], public=True), lb_row("alb", ["sg-web"]),
            sg_row("sg-web", [rule("tcp", 443), rule("tcp", 80, 80, WORLD6)]),
            sg_row("sg-app", [rule("tcp", 8080, 8080, {"type": "sg", "value": "sg-web"})]),
            sg_row("sg-db", [rule("tcp", 5432, 5432, {"type": "sg", "value": "sg-app"},
                                  {"type": "cidr", "value": "10.0.0.0/16"})])]


def test_output_is_deterministic_and_sorted_whatever_the_row_order():
    rows = _world()
    ref_out = run(rows)
    for seed in range(8):
        shuffled = rows[:]
        random.Random(seed).shuffle(shuffled)
        assert run(shuffled) == ref_out
    keys = [(e.src_ref, e.dst_ref, e.proto, e.port_lo, e.port_hi) for e in ref_out.edges]
    assert keys == sorted(keys)
    assert [n.ref for n in ref_out.nodes] == sorted(n.ref for n in ref_out.nodes)
    assert [c.node_ref for c in ref_out.coverage] == sorted(c.node_ref for c in ref_out.coverage)
    assert ref_out.notes == sorted(ref_out.notes)


def test_every_edge_and_node_is_something_the_store_accepts():
    out = run(_world())
    assert out.source == "aws_sg" == aws_sg.SOURCE and out.mode == "replace" and out.window is None
    for n in out.nodes:
        assert refs.is_valid_ref(n.ref) and n.kind in refs.KINDS
        json.dumps(n.attrs)
        assert (n.ref == "internet") == (n.kind == "internet")
    for e in out.edges:
        assert refs.is_valid_ref(e.src_ref) and refs.is_valid_ref(e.dst_ref) and e.src_ref != e.dst_ref
        assert e.proto in ("tcp", "udp", "icmp", "any") and e.basis == "configured"
        assert e.source == "aws_sg" and e.last_seen.tzinfo is not None and e.last_seen <= NOW
        json.dumps(e.evidence)
    assert {c.direction for c in out.coverage} == {"in"}


def test_build_is_pure_and_survives_garbage_rows():
    rows = _world() + [{}, {"metadata": None}, {"id": "nope", "metadata": {"resource_type": "instance"}},
                       {"id": uid("x"), "last_seen": "yesterday", "metadata": {"resource_type": "instance"}},
                       "str", None]
    before = json.dumps(rows[:7], default=str)
    out = run(rows)
    assert json.dumps(rows[:7], default=str) == before          # inputs untouched
    assert out == run(_world())                                 # junk contributes nothing


def test_non_aws_and_unmodeled_resource_types_are_ignored():
    s3 = {"id": uid("b"), "canonical": "arn:aws:s3:::b", "last_seen": T_NEW,
          "metadata": {"provider": "aws", "resource_type": "bucket"}}
    assert run([s3]).nodes == []


# --------------------------------------------------------------------------- #
# DB-backed: loader (RLS) and the real connector end to end (moto)
# --------------------------------------------------------------------------- #

TENANT_A = tenancy.DEFAULT_TENANT_ID
TENANT_B = "00000000-0000-0000-0000-0000000000b2"


@contextlib.asynccontextmanager
async def conn_for(pool, tid=TENANT_A):
    with tenancy.tenant_context(tid):          # tenancy is set BEFORE acquire, as in production
        async with pool.acquire() as con:
            yield con


async def _seed(db_pool, row, tenant):
    async with db_pool.acquire() as con:
        await con.execute(
            "INSERT INTO assets (id, tenant_id, kind, value, canonical, source, metadata, last_seen) "
            "VALUES ($1::uuid, $2::uuid, 'cloud_resource', $3, $3, 'integration:aws', $4::jsonb, $5)",
            row["id"], tenant, row["canonical"], json.dumps(row["metadata"]), row["last_seen"])


async def test_loader_is_tenant_scoped_and_filters_by_metadata_not_source(db_pool, app_pool):
    await tenancy.create_tenant(db_pool, slug="bravo", name="Bravo", tenant_id=TENANT_B)
    mine = [inst_row("a-inst", ["sg-1"]), sg_row("sg-1", [rule("tcp", 22)]), db_row("a-db", ["sg-1"]),
            lb_row("a-lb", ["sg-1"])]
    theirs = [inst_row("b-inst", ["sg-b"]), sg_row("sg-b", [rule("tcp", 22)], name="b-sg")]
    for r in mine:
        await _seed(db_pool, r, TENANT_A)
    for r in theirs:
        await _seed(db_pool, r, TENANT_B)
    # rows the loader must not return: another provider, and an aws bucket
    for name, md in (("gcp-vm", {"provider": "gcp", "resource_type": "instance"}),
                     ("bucket", {"provider": "aws", "resource_type": "bucket"})):
        await _seed(db_pool, {"id": uid(name), "canonical": f"x:{name}", "last_seen": NOW,
                              "metadata": md}, TENANT_A)
    # ... and a row whose assets.source is not the connector's still counts (merge never updates it)
    async with db_pool.acquire() as con:
        await con.execute("UPDATE assets SET source = 'otdiscovery' WHERE id = $1::uuid", uid("a-db"))

    async with conn_for(app_pool, TENANT_A) as con:
        rows_a = await aws_sg.load(con, NOW)
    async with conn_for(app_pool, TENANT_B) as con:
        rows_b = await aws_sg.load(con, NOW)
    assert {r["id"] for r in rows_a} == {uid(n) for n in ("a-inst", "a-db", "a-lb")} | {
        uid("111111111111/us-east-1/sg-1")}
    assert {r["id"] for r in rows_b} == {uid("b-inst"), uid("b-sg")}
    assert all(isinstance(r["metadata"], dict) and r["last_seen"].tzinfo for r in rows_a)
    out_a, out_b = aws_sg.build(rows_a, NOW), aws_sg.build(rows_b, NOW)
    assert {n.asset_id for n in out_a.nodes if n.asset_id} == {uid(n) for n in ("a-inst", "a-db", "a-lb")}
    assert {n.asset_id for n in out_b.nodes if n.asset_id} == {uid("b-inst")}


async def test_connector_world_end_to_end(db_pool, app_pool, fake_redis, monkeypatch):
    pytest.importorskip("boto3")
    moto = pytest.importorskip("moto")
    from app.assurance import store
    from app.integrations.ingest import apply_source_batch
    from tests.test_aws_connector import REGION, SECRETS, _build_world, aws_mod

    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        monkeypatch.setenv(k, "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    with moto.mock_aws():
        world = _build_world()
        conn = aws_mod.AwsConnector(
            {"regions": [REGION], "role_arn": "arn:aws:iam::123456789012:role/paddock-readonly"},
            SECRETS, http=None)
        batch = await conn.pull()
    await apply_source_batch(db_pool, fake_redis, batch, source="integration:aws")
    # a second sync is the common case: the shallow metadata merge must keep the rules intact
    await apply_source_batch(db_pool, fake_redis, batch, source="integration:aws")

    now = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=5)
    async with conn_for(app_pool) as con:
        out = aws_sg.build(await aws_sg.load(con, now), now)
        by_arn = {n.attrs["arn"]: n for n in out.nodes if n.attrs.get("arn")}
        inst = by_arn[f"arn:aws:ec2:{REGION}:123456789012:instance/{world['iid']}"]
        lb = by_arn[world["lb_arn"]]
        rds = next(n for n in out.nodes if n.kind == "cloud_db")
        keys = edge_keys(out)

        assert inst.kind == "cloud_instance" and lb.kind == "cloud_lb"
        if world["public_ip"]:
            assert ("internet", inst.ref, "tcp", 22, 22) in keys
            assert ("internet", inst.ref, "tcp", 443, 443) in keys
        assert ("internet", lb.ref, "tcp", 443, 443) in keys                   # internet-facing ALB
        # the database SG admits the web SG: its members (instance, ALB) reach the db on 5432
        assert (inst.ref, rds.ref, "tcp", 5432, 5432) in keys
        assert (lb.ref, rds.ref, "tcp", 5432, 5432) in keys
        # RDS is PubliclyAccessible, but its SG names no world rule and none was invented
        assert not any(e.dst_ref == rds.ref and e.src_ref in ("internet", "cidr:0.0.0.0/0")
                       for e in out.edges)
        assert {c.node_ref for c in out.coverage} == {inst.ref, lb.ref, rds.ref}
        assert all(c.observed_at <= now and c.direction == "in" for c in out.coverage)

        rep = await store.persist_build(con, out, now)
        assert rep.changed and rep.edges_added == len(out.edges)
        assert (await store.persist_build(con, aws_sg.build(await aws_sg.load(con, now), now), now)
                ).changed is False                                              # stable round trip
        stored = await con.fetchval(
            "SELECT count(*) FROM reach_edges WHERE source = 'aws_sg'")
        assert stored == len(out.edges)
        assert await con.fetchval(
            "SELECT count(*) FROM reach_coverage WHERE source = 'aws_sg' AND direction = 'in'") == 3
    blob = json.dumps([e.evidence for e in out.edges] + out.notes)
    assert "ext-123" not in blob and "testing" not in blob


async def test_removed_rule_disappears_from_the_graph_on_the_next_build(db_pool, app_pool):
    """replace mode: tightening a security group removes the edge (and nothing else does)."""
    from app.assurance import store

    rows = [inst_row("a", ["sg-1"]), sg_row("sg-1", [rule("tcp", 22), rule("tcp", 443)])]
    for r in rows:
        await _seed(db_pool, r, TENANT_A)
    async with conn_for(app_pool) as con:
        await store.persist_build(con, aws_sg.build(await aws_sg.load(con, NOW), NOW), NOW)
        assert await con.fetchval("SELECT count(*) FROM reach_edges") == 2
    async with db_pool.acquire() as con:
        md = rows[1]["metadata"] | {"ingress_rules": [rule("tcp", 443)]}
        await con.execute("UPDATE assets SET metadata = $2::jsonb WHERE id = $1::uuid",
                          rows[1]["id"], json.dumps(md))
    async with conn_for(app_pool) as con:
        rep = await store.persist_build(con, aws_sg.build(await aws_sg.load(con, NOW), NOW), NOW)
        assert rep.edges_removed == 1
        assert await con.fetchval("SELECT port_lo FROM reach_edges") == 443
