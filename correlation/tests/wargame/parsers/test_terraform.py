"""Tests for the Terraform plan parser (``terraform show -json`` → ProposedChange)."""
from __future__ import annotations

import copy
import json
import os

import pytest

from app.engine.wargame.environment import (
    ChangeKind,
    Environment,
    apply_change,
)
from app.engine.wargame.model import (
    Action,
    Edge,
    Node,
    PortRange,
    Proto,
    RuleSet,
)
from app.engine.wargame.parsers.base import ANY_CIDRS
from app.engine.wargame.parsers.terraform import parse_plan, parse_plan_detailed

_FIX = os.path.join(os.path.dirname(__file__), "fixtures")


@pytest.fixture
def plan() -> dict:
    with open(os.path.join(_FIX, "terraform_plan.json")) as f:
        return json.load(f)


def _addr(o) -> str:
    """The plan address an op came from (rule ids may be in the AWS scheme)."""
    return o.rule.raw_ref if o.rule else o.description.removeprefix("remove ")


def _op(change, address: str):
    ops = [o for o in change.ops if _addr(o) == address]
    assert len(ops) == 1, f"expected one op for {address}"
    return ops[0]


def test_create_sg_rule_is_add_rule(plan):
    change = parse_plan(plan)
    op = _op(change, "aws_security_group_rule.db_from_app")
    assert op.kind is ChangeKind.ADD_RULE
    assert op.ruleset_id == "sg-db"
    r = op.rule
    assert r.action is Action.ALLOW
    assert r.src_cidrs == ("10.9.0.0/24",)
    assert r.dst_cidrs == ANY_CIDRS
    assert r.ports == (PortRange.single(Proto.TCP, 5432),)
    assert r.id == "aws_security_group_rule.db_from_app"
    assert r.conditional is False


def test_delete_is_remove_rule(plan):
    op = _op(parse_plan(plan), "aws_security_group_rule.legacy_ssh")
    assert op.kind is ChangeKind.REMOVE_RULE
    assert op.ruleset_id == "sg-bastion"
    assert op.rule_id == "aws_security_group_rule.legacy_ssh"


def test_nacl_rule_order_action_and_ruleset(plan):
    change = parse_plan(plan)
    op = _op(change, "aws_network_acl_rule.deny_telnet")
    assert op.kind is ChangeKind.ADD_RULE
    assert op.ruleset_id == "acl-0abc:ingress"
    assert op.rule.order == 90
    assert op.rule.action is Action.DENY
    assert op.rule.src_cidrs == ("192.168.50.0/24",)
    assert op.rule.dst_cidrs == ANY_CIDRS
    assert op.rule.ports == (PortRange.single(Proto.TCP, 23),)

    egress = copy.deepcopy(plan)
    after = egress["resource_changes"][2]["change"]["after"]
    after["egress"] = True
    op2 = _op(parse_plan(egress), "aws_network_acl_rule.deny_telnet")
    assert op2.ruleset_id == "acl-0abc:egress"
    assert op2.rule.src_cidrs == ANY_CIDRS
    assert op2.rule.dst_cidrs == ("192.168.50.0/24",)


def test_known_after_apply_cidr_is_conditional(plan):
    op = _op(parse_plan(plan), "aws_vpc_security_group_ingress_rule.web_unknown_src")
    assert op.kind is ChangeKind.ADD_RULE
    assert op.ruleset_id == "sg-web"
    assert op.rule.conditional is True
    assert "0.0.0.0/0" in op.rule.src_cidrs
    assert op.rule.ports == (PortRange.single(Proto.TCP, 443),)
    assert "unresolved" in op.description


def test_unknown_security_group_id_falls_back_to_address(plan):
    p = copy.deepcopy(plan)
    after = p["resource_changes"][0]["change"]
    after["after"]["security_group_id"] = None
    after["after_unknown"]["security_group_id"] = True
    op = _op(parse_plan(p), "aws_security_group_rule.db_from_app")
    assert op.ruleset_id == "aws_security_group_rule.db_from_app"
    assert op.rule.conditional is True


def test_unknown_port_is_any_and_conditional(plan):
    p = copy.deepcopy(plan)
    ch = p["resource_changes"][0]["change"]
    ch["after"]["from_port"] = None
    ch["after"]["to_port"] = None
    ch["after_unknown"].update({"from_port": True, "to_port": True})
    op = _op(parse_plan(p), "aws_security_group_rule.db_from_app")
    assert op.rule.conditional is True
    assert op.rule.ports == (PortRange(Proto.TCP, 0, 65535),)


def test_protocol_minus_one_is_any():
    plan = {"resource_changes": [{
        "address": "aws_security_group_rule.all", "type": "aws_security_group_rule",
        "change": {"actions": ["create"], "before": None, "after_unknown": {},
                   "after": {"type": "egress", "protocol": "-1", "from_port": 0,
                             "to_port": 0, "cidr_blocks": ["10.0.0.0/8"],
                             "security_group_id": "sg-x"}}}]}
    op = parse_plan(plan).ops[0]
    assert op.ruleset_id == "sg-x:egress"
    assert op.rule.ports == (PortRange.any(),)
    assert op.rule.src_cidrs == ANY_CIDRS
    assert op.rule.dst_cidrs == ("10.0.0.0/8",)


def test_replace_is_modify_using_after(plan):
    for actions in (["create", "delete"], ["delete", "create"]):
        p = copy.deepcopy(plan)
        ch = p["resource_changes"][0]["change"]
        ch["actions"] = actions
        ch["before"] = dict(ch["after"], cidr_blocks=["10.8.0.0/24"])
        op = _op(parse_plan(p), "aws_security_group_rule.db_from_app")
        assert op.kind is ChangeKind.MODIFY_RULE
        assert op.rule.src_cidrs == ("10.9.0.0/24",)
        assert op.rule_id == "aws_security_group_rule.db_from_app"


def test_update_is_modify(plan):
    p = copy.deepcopy(plan)
    p["resource_changes"][0]["change"]["actions"] = ["update"]
    op = _op(parse_plan(p), "aws_security_group_rule.db_from_app")
    assert op.kind is ChangeKind.MODIFY_RULE


def test_unrelated_and_noop_resources_ignored_without_raising(plan):
    result = parse_plan_detailed(plan)
    addrs = {_addr(o) for o in result.change.ops}
    assert "aws_s3_bucket.logs" not in addrs
    assert "aws_security_group_rule.untouched" not in addrs
    assert len(result.change.ops) == 4
    assert [a for a, _ in result.skipped] == ["aws_s3_bucket.logs"]


def test_malformed_resources_are_skipped_not_raised():
    plan = {"resource_changes": [
        "junk",
        {"address": "aws_security_group_rule.a", "type": "aws_security_group_rule",
         "change": {"actions": ["create"], "after": None}},
        {"address": "aws_security_group_rule.b", "type": "aws_security_group_rule",
         "change": {"actions": ["create"], "after": {"type": "sideways"}}},
    ]}
    result = parse_plan_detailed(plan)
    assert result.change.ops == []
    assert len(result.skipped) == 3
    assert parse_plan({}).ops == []


def test_metadata_and_affected_rulesets(plan):
    change = parse_plan(plan)
    assert change.source == "terraform-plan"
    assert "4 network rule change(s)" in change.title
    assert "1 skipped" in change.title
    assert change.affected_ruleset_ids() == {
        "sg-db", "sg-bastion", "acl-0abc:ingress", "sg-web"}


def test_deterministic_and_ordered_by_address(plan):
    rev = copy.deepcopy(plan)
    rev["resource_changes"].reverse()
    a, b = parse_plan(plan), parse_plan(rev)
    assert a == b
    assert parse_plan(json.dumps(plan)) == a
    keys = [_addr(o) for o in a.ops]
    assert keys == sorted(keys)


def test_change_composes_with_environment(plan):
    env = Environment()
    env.add_node(Node("app", cidrs=("10.9.0.0/24",)))
    env.add_node(Node("db", cidrs=("10.1.0.0/24",)))
    env.add_ruleset(RuleSet(id="sg-db", rules=[]))
    env.add_edge(Edge("app", "db", rule_set_id="sg-db",
                      port=PortRange.single(Proto.TCP, 5432)))
    assert env.boundary_decision("app", "db").allowed is False

    only_db = copy.deepcopy(plan)
    only_db["resource_changes"] = only_db["resource_changes"][:1]
    new = apply_change(env, parse_plan(only_db))

    assert new.boundary_decision("app", "db").allowed is True
    assert [r.id for r in new.rulesets["sg-db"].rules] == [
        "aws_security_group_rule.db_from_app"]
    # original untouched
    assert env.rulesets["sg-db"].rules == []


# -- AWS export <-> Terraform plan id matching (audit) -------------------------

from app.engine.wargame.parsers import parse as _parse_vendor  # noqa: E402
from app.engine.wargame.parsers.terraform import bind_to_environment  # noqa: E402


def _live_env(sgs=(), nacls=()) -> Environment:
    res = _parse_vendor("aws", {"SecurityGroups": list(sgs), "NetworkAcls": list(nacls)})
    env = Environment()
    for rs in res.rulesets.values():
        env.add_ruleset(rs)
    return env


def _perm(proto, lo, hi, *cidrs):
    return {"IpProtocol": proto, "FromPort": lo, "ToPort": hi,
            "IpRanges": [{"CidrIp": c} for c in cidrs]}


def _plan(*rcs) -> dict:
    return {"resource_changes": list(rcs)}


def _rc(addr, rtype, actions, before=None, after=None, unknown=None):
    return {"address": addr, "type": rtype,
            "change": {"actions": actions, "before": before, "after": after,
                       "after_unknown": unknown or {}}}


def _sg_before(**kw):
    base = {"type": "ingress", "protocol": "tcp", "from_port": 5432, "to_port": 5432,
            "security_group_id": "sg-db", "cidr_blocks": ["10.9.0.0/24"]}
    base.update(kw)
    return base


def test_remove_one_cidr_of_a_bundled_aws_permission_splits_not_deletes():
    # The AWS parser makes ONE rule for the permission; removing one of its
    # CIDRs must leave the other (removing the rule whole = false closed).
    env = _live_env([{"GroupId": "sg-db", "IpPermissions": [
        _perm("tcp", 5432, 5432, "10.9.0.0/24", "10.8.0.0/24")]}])
    live_id = env.rulesets["sg-db"].rules[0].id
    plan = _plan(_rc("aws_security_group_rule.a", "aws_security_group_rule",
                     ["delete"], before=_sg_before()))
    new = apply_change(env, parse_plan(plan, env))
    (r,) = new.rulesets["sg-db"].rules
    assert r.id == live_id and r.src_cidrs == ("10.8.0.0/24",)
    assert env.rulesets["sg-db"].rules[0].src_cidrs == ("10.9.0.0/24", "10.8.0.0/24")


def test_remove_whole_rule_from_live_export_lands():
    env = _live_env([{"GroupId": "sg-db", "IpPermissions": [
        _perm("tcp", 5432, 5432, "10.9.0.0/24"), _perm("tcp", 22, 22, "10.1.0.0/16")]}])
    plan = _plan(_rc("aws_security_group_rule.a", "aws_security_group_rule",
                     ["delete"], before=_sg_before()))
    new = apply_change(env, parse_plan(plan, env))
    assert [r.ports[0].low for r in new.rulesets["sg-db"].rules] == [22]


def test_modify_cidr_in_live_rule_lands_as_remove_plus_add():
    env = _live_env([{"GroupId": "sg-db", "IpPermissions": [
        _perm("tcp", 5432, 5432, "10.9.0.0/24")]}])
    plan = _plan(_rc("aws_security_group_rule.a", "aws_security_group_rule", ["update"],
                     before=_sg_before(),
                     after=_sg_before(cidr_blocks=["10.7.0.0/24"])))
    new = apply_change(env, parse_plan(plan, env))
    assert [r.src_cidrs for r in new.rulesets["sg-db"].rules] == [("10.7.0.0/24",)]


def test_vpc_egress_rule_removal_matches_egress_ruleset():
    env = _live_env([{"GroupId": "sg-w", "IpPermissions": [],
                      "IpPermissionsEgress": [
                          {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]}])
    plan = _plan(_rc("aws_vpc_security_group_egress_rule.e",
                     "aws_vpc_security_group_egress_rule", ["delete"],
                     before={"security_group_id": "sg-w", "ip_protocol": "-1",
                             "cidr_ipv4": "10.0.0.0/8"}))
    new = apply_change(env, parse_plan(plan, env))
    assert new.rulesets["sg-w:egress"].rules == []


def test_unmatchable_removal_is_retained_with_a_warning_never_applied_wrongly():
    env = _live_env([{"GroupId": "sg-db", "IpPermissions": [
        {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
         "UserIdGroupPairs": [{"GroupId": "sg-app"}]}]}])
    plan = _plan(_rc("aws_security_group_rule.a", "aws_security_group_rule", ["delete"],
                     before=_sg_before(cidr_blocks=[], source_security_group_id="sg-app")))
    pp = parse_plan_detailed(plan, env)
    assert pp.change.ops == []                       # nothing narrows the model
    assert any("retained" in n for _, n in pp.warnings)
    new = apply_change(env, pp.change)
    assert len(new.rulesets["sg-db"].rules) == 1     # the allow is still there


def test_removal_of_cidr_not_in_live_export_is_retained_with_warning():
    env = _live_env([{"GroupId": "sg-db", "IpPermissions": [
        _perm("tcp", 5432, 5432, "10.1.0.0/24")]}])
    plan = _plan(_rc("aws_security_group_rule.a", "aws_security_group_rule",
                     ["delete"], before=_sg_before()))
    pp = parse_plan_detailed(plan, env)
    assert pp.change.ops == [] and pp.warnings


def test_nacl_ids_match_aws_scheme_so_remove_and_modify_land():
    env = _live_env(nacls=[{"NetworkAclId": "acl-1", "Entries": [
        {"RuleNumber": 100, "RuleAction": "allow", "Protocol": "6", "Egress": False,
         "CidrBlock": "0.0.0.0/0", "PortRange": {"From": 22, "To": 22}},
        {"RuleNumber": 32767, "RuleAction": "deny", "Protocol": "-1", "Egress": False,
         "CidrBlock": "0.0.0.0/0"}]}])
    before = {"network_acl_id": "acl-1", "rule_number": 100, "egress": False,
              "protocol": "6", "rule_action": "allow", "cidr_block": "0.0.0.0/0",
              "from_port": 22, "to_port": 22}
    # remove
    rm = _plan(_rc("aws_network_acl_rule.ssh", "aws_network_acl_rule", ["delete"],
                   before=before))
    assert parse_plan(rm).ops[0].rule_id == "acl-1:ingress#100"
    new = apply_change(env, parse_plan(rm))
    assert [r.order for r in new.rulesets["acl-1:ingress"].rules] == [32767]
    # modify (renumbering moves the live rule)
    mod = _plan(_rc("aws_network_acl_rule.ssh", "aws_network_acl_rule", ["update"],
                    before=before, after=dict(before, rule_number=90, rule_action="deny")))
    new = apply_change(env, parse_plan(mod))
    got = [(r.order, r.action) for r in new.rulesets["acl-1:ingress"].rules]
    assert got == [(90, Action.DENY), (32767, Action.DENY)]


def test_nacl_remove_of_missing_rule_is_retained_with_warning():
    env = _live_env(nacls=[{"NetworkAclId": "acl-1", "Entries": []}])
    plan = _plan(_rc("aws_network_acl_rule.x", "aws_network_acl_rule", ["delete"],
                     before={"network_acl_id": "acl-1", "rule_number": 5, "egress": False,
                             "protocol": "-1", "rule_action": "deny", "cidr_block": "0.0.0.0/0"}))
    pp = parse_plan_detailed(plan, env)
    assert pp.change.ops == [] and pp.warnings


def test_unknown_or_unmodelled_nacl_deny_is_dropped_never_widened():
    after = {"network_acl_id": "acl-1", "rule_number": 50, "egress": False,
             "protocol": "-1", "rule_action": "deny", "cidr_block": None}
    plan = _plan(_rc("aws_network_acl_rule.d", "aws_network_acl_rule", ["create"],
                     after=after, unknown={"cidr_block": True}))
    pp = parse_plan_detailed(plan)
    assert pp.change.ops == [] and pp.warnings
    gre = dict(after, cidr_block="10.0.0.0/8", protocol="47")
    pp = parse_plan_detailed(_plan(_rc("aws_network_acl_rule.g", "aws_network_acl_rule",
                                       ["create"], after=gre)))
    assert pp.change.ops == []
    # an unknown ALLOW is widened + conditional instead
    allow = dict(after, rule_action="allow")
    op = parse_plan(_plan(_rc("aws_network_acl_rule.a", "aws_network_acl_rule",
                              ["create"], after=allow, unknown={"cidr_block": True}))).ops[0]
    assert op.rule.conditional and op.rule.src_cidrs == ANY_CIDRS


def test_unmodelled_protocol_sg_rule_is_conditional_any():
    plan = _plan(_rc("aws_security_group_rule.g", "aws_security_group_rule", ["create"],
                     after=_sg_before(protocol="47", cidr_blocks=["10.0.0.0/8"])))
    op = parse_plan(plan).ops[0]
    assert op.rule.conditional and op.rule.ports == (PortRange.any(),)


def test_inline_sg_blocks_diff_into_add_and_remove_against_live_export():
    env = _live_env([{"GroupId": "sg-9", "IpPermissions": [
        _perm("tcp", 22, 22, "10.0.0.0/8"), _perm("tcp", 80, 80, "0.0.0.0/0")]}])
    blk = lambda port, cidr: {"protocol": "tcp", "from_port": port, "to_port": port,  # noqa: E731
                              "cidr_blocks": [cidr], "ipv6_cidr_blocks": [],
                              "security_groups": [], "prefix_list_ids": [], "self": False}
    before = {"id": "sg-9", "ingress": [blk(22, "10.0.0.0/8"), blk(80, "0.0.0.0/0")],
              "egress": []}
    after = {"id": "sg-9", "ingress": [blk(80, "0.0.0.0/0"), blk(443, "10.5.0.0/16")],
             "egress": []}
    plan = _plan(_rc("aws_security_group.web", "aws_security_group", ["update"],
                     before=before, after=after))
    new = apply_change(env, parse_plan(plan, env))
    got = sorted((r.ports[0].low, tuple(r.src_cidrs)) for r in new.rulesets["sg-9"].rules)
    assert got == [(80, ("0.0.0.0/0",)), (443, ("10.5.0.0/16",))]


def test_inline_sg_unknown_blocks_never_remove_and_add_conditional_any():
    before = {"id": "sg-9", "ingress": [{"protocol": "tcp", "from_port": 22, "to_port": 22,
                                         "cidr_blocks": ["10.0.0.0/8"]}], "egress": []}
    after = {"id": "sg-9", "ingress": None, "egress": []}
    plan = _plan(_rc("aws_security_group.web", "aws_security_group", ["update"],
                     before=before, after=after, unknown={"ingress": True}))
    ops = parse_plan(plan).ops
    assert [o.kind for o in ops] == [ChangeKind.ADD_RULE]
    assert ops[0].rule.conditional and ops[0].rule.src_cidrs == ANY_CIDRS


def test_new_inline_sg_is_an_add_ruleset_and_delete_is_retained():
    after = {"id": None, "ingress": [{"protocol": "tcp", "from_port": 22, "to_port": 22,
                                      "cidr_blocks": ["0.0.0.0/0"]}], "egress": []}
    plan = _plan(_rc("aws_security_group.n", "aws_security_group", ["create"],
                     after=after, unknown={"id": True}))
    ops = parse_plan(plan).ops
    assert ops[0].kind is ChangeKind.ADD_RULESET and ops[0].ruleset.rules
    gone = _plan(_rc("aws_security_group.n", "aws_security_group", ["delete"],
                     before={"id": "sg-9", "ingress": [], "egress": []}))
    pp = parse_plan_detailed(gone)
    assert pp.change.ops == [] and pp.warnings


def test_bind_does_not_mutate_inputs():
    env = _live_env([{"GroupId": "sg-db", "IpPermissions": [
        _perm("tcp", 5432, 5432, "10.9.0.0/24", "10.8.0.0/24")]}])
    plan = parse_plan_detailed(_plan(_rc("aws_security_group_rule.a",
                                         "aws_security_group_rule", ["delete"],
                                         before=_sg_before())))
    snapshot = list(plan.change.ops)
    bound = bind_to_environment(plan, env)
    assert plan.change.ops == snapshot and bound is not plan
    assert env.rulesets["sg-db"].rules[0].src_cidrs == ("10.9.0.0/24", "10.8.0.0/24")
