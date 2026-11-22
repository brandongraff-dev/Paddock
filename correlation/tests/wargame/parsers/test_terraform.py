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


def _op(change, address: str):
    ops = [o for o in change.ops
           if (o.rule.id if o.rule else o.rule_id) == address]
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
    addrs = {(o.rule.id if o.rule else o.rule_id) for o in result.change.ops}
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
    keys = [o.rule.id if o.rule else o.rule_id for o in a.ops]
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
