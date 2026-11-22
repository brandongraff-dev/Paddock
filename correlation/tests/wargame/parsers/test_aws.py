"""Tests for the AWS parser: Security Groups and Network ACLs → RuleSets.

These exercise the two things that decide correctness for a defensive tool:
the direction / reference modelling, and the honesty rule (anything the static
config can't prove is conditional and over-approximated toward reachable).
"""
from __future__ import annotations

import json
import os

import pytest

from app.engine.wargame import rules
from app.engine.wargame.model import Action, PortRange, Proto
from app.engine.wargame.parsers import base, parse
from app.engine.wargame.parsers.aws import AwsParser
from app.engine.wargame.parsers.base import ConditionalFeature, WarningLevel

_FIX = os.path.join(os.path.dirname(__file__), "fixtures")


def _load(name: str) -> dict:
    with open(os.path.join(_FIX, name)) as f:
        return json.load(f)


@pytest.fixture
def sgs() -> dict:
    return _load("aws_security_groups.json")


@pytest.fixture
def nacls() -> dict:
    return _load("aws_network_acls.json")


def _rule_on_port(ruleset, proto: Proto, port: int):
    """The rule in ``ruleset`` whose port range admits ``proto``/``port``."""
    for r in ruleset.rules:
        if any(pr.contains(proto, port) for pr in r.ports):
            return r
    raise AssertionError(f"no rule admitting {proto}/{port} in {ruleset.id}")


# -- registration ------------------------------------------------------------

def test_registered_under_aws():
    assert "aws" in base.available_vendors()
    assert isinstance(base.get_parser("aws"), AwsParser)


def test_accepts_json_string(sgs):
    res = parse("aws", json.dumps(sgs))
    assert "sg-0web" in res.rulesets


# -- security groups: world-open 443 -----------------------------------------

def test_world_open_443(sgs):
    res = parse("aws", sgs)
    web = res.rulesets["sg-0web"]
    assert web.vendor == "aws"
    assert web.default_action is Action.DENY
    assert len(web.rules) == 1
    r = web.rules[0]
    assert r.action is Action.ALLOW
    assert set(r.src_cidrs) == {"0.0.0.0/0", "::/0"}      # v4 + v6 world
    assert r.dst_cidrs == ("0.0.0.0/0", "::/0")           # dst ANY: bound host
    assert r.ports == (PortRange(Proto.TCP, 443, 443),)
    assert r.conditional is False
    assert r.cost_class == "cloud_policy"


def test_egress_is_a_separate_ruleset_and_dst_scoped(sgs):
    res = parse("aws", sgs)
    assert "sg-0web:egress" in res.rulesets
    eg = res.rulesets["sg-0web:egress"]
    r = eg.rules[0]
    # egress: src ANY, dst = the permission's ranges
    assert r.src_cidrs == ("0.0.0.0/0", "::/0")
    assert "0.0.0.0/0" in r.dst_cidrs


def test_ipprotocol_minus_one_is_any_any_port(sgs):
    res = parse("aws", sgs)
    r = res.rulesets["sg-0web:egress"].rules[0]   # IpProtocol "-1"
    assert len(r.ports) == 1
    pr = r.ports[0]
    assert pr.proto is Proto.ANY
    assert (pr.low, pr.high) == (0, 65535)


# -- SG-to-SG references ------------------------------------------------------

def test_sg_to_sg_without_members_is_conditional_unresolved(sgs):
    res = parse("aws", sgs)
    app = res.rulesets["sg-0app"]
    r = _rule_on_port(app, Proto.TCP, 8080)       # the UserIdGroupPairs rule
    assert r.conditional is True
    assert set(r.src_cidrs) == {"0.0.0.0/0", "::/0"}   # over-approx to ANY
    # a warning naming the referenced SG, and a conditional/unresolved reason
    assert any(
        w.level is WarningLevel.UNRESOLVED and "sg-0web" in w.message
        for w in res.warnings
    )
    assert any(w.level is WarningLevel.CONDITIONAL for w in res.warnings)


def test_sg_to_sg_with_members_resolves_and_is_not_conditional(sgs):
    members = {"sg-0web": ["10.1.0.0/24"], "sg-0app": ["10.2.0.0/24"]}
    res = parse("aws", sgs, sg_members=members)
    app = res.rulesets["sg-0app"]
    r = _rule_on_port(app, Proto.TCP, 8080)
    assert r.conditional is False
    assert r.src_cidrs == ("10.1.0.0/24",)
    # db SG src = the app SG's members
    db = res.rulesets["sg-0db"]
    rdb = _rule_on_port(db, Proto.TCP, 5432)
    assert rdb.conditional is False
    assert rdb.src_cidrs == ("10.2.0.0/24",)


def test_prefix_list_is_conditional(sgs):
    res = parse("aws", sgs, sg_members={"sg-0web": ["10.1.0.0/24"]})
    app = res.rulesets["sg-0app"]
    r = _rule_on_port(app, Proto.TCP, 9090)       # the PrefixListIds rule
    assert r.conditional is True
    assert set(r.src_cidrs) == {"0.0.0.0/0", "::/0"}
    assert any(
        w.level is WarningLevel.UNRESOLVED and "pl-" in w.message
        for w in res.warnings
    )


# -- bindings -----------------------------------------------------------------

def test_sg_binding_captures_attached_enis(sgs):
    res = parse("aws", sgs)
    web_bindings = [b for b in res.bindings if b.ruleset_id == "sg-0web"]
    assert web_bindings
    assert web_bindings[0].attached_to == ("eni-0web001", "eni-0web002")


# -- network ACLs -------------------------------------------------------------

def test_nacl_splits_ingress_egress_and_orders_by_rule_number(nacls):
    res = parse("aws", nacls)
    assert "acl-0web:ingress" in res.rulesets
    assert "acl-0web:egress" in res.rulesets
    ing = res.rulesets["acl-0web:ingress"]
    # Rule.order == RuleNumber, and the lower deny precedes the higher allow.
    by_order = sorted(ing.rules, key=lambda r: r.order)
    assert by_order[0].order == 90 and by_order[0].action is Action.DENY
    assert by_order[1].order == 100 and by_order[1].action is Action.ALLOW
    assert all(r.cost_class == "cloud_policy" for r in ing.rules)


def test_nacl_ingress_src_is_cidr_dst_any(nacls):
    res = parse("aws", nacls)
    ing = res.rulesets["acl-0web:ingress"]
    deny90 = next(r for r in ing.rules if r.order == 90)
    assert deny90.src_cidrs == ("10.9.0.0/24",)
    assert deny90.dst_cidrs == ("0.0.0.0/0", "::/0")


def test_nacl_lower_deny_beats_higher_allow(nacls):
    res = parse("aws", nacls)
    ing = res.rulesets["acl-0web:ingress"]
    # 443 is allowed to all at rule 100, but rule 90 denies 10.9.0.0/24 first.
    denied = rules.evaluate(ing, "10.9.0.5", "10.0.0.5", Proto.TCP, 443)
    assert denied.allowed is False
    assert denied.matched_rule == "acl-0web:ingress#90"
    # a source outside that /24 is allowed by rule 100.
    allowed = rules.evaluate(ing, "203.0.113.5", "10.0.0.5", Proto.TCP, 443)
    assert allowed.allowed is True
    assert allowed.matched_rule == "acl-0web:ingress#100"


def test_nacl_minus_one_entry_is_any_any_port(nacls):
    res = parse("aws", nacls)
    ing = res.rulesets["acl-0web:ingress"]
    r110 = next(r for r in ing.rules if r.order == 110)
    assert r110.ports == (PortRange.any(),)
    pr = r110.ports[0]
    assert pr.proto is Proto.ANY and (pr.low, pr.high) == (0, 65535)


def test_nacl_ipv6_entry(nacls):
    res = parse("aws", nacls)
    ing = res.rulesets["acl-0web:ingress"]
    r120 = next(r for r in ing.rules if r.order == 120)
    assert r120.src_cidrs == ("2001:db8::/32",)


def test_nacl_binding_captures_subnet(nacls):
    res = parse("aws", nacls)
    bindings = [b for b in res.bindings if b.ruleset_id == "acl-0web:ingress"]
    assert bindings and bindings[0].attached_to == ("subnet-0public",)


# -- solver integration: boundary_permits ------------------------------------

def test_boundary_permits_allow_and_deny(sgs):
    res = parse("aws", sgs)
    web = res.rulesets["sg-0web"]
    # world → host on 443 is permitted (and proved, not conditional)
    dec = rules.boundary_permits(
        web, ["203.0.113.5/32"], ["10.0.0.5/32"], PortRange(Proto.TCP, 443, 443)
    )
    assert dec.allowed is True and dec.conditional is False
    # the same boundary on 22 is not admitted (falls through to default DENY)
    dec22 = rules.boundary_permits(
        web, ["203.0.113.5/32"], ["10.0.0.5/32"], PortRange(Proto.TCP, 22, 22)
    )
    assert dec22.allowed is False


def test_conditional_boundary_reads_as_possibly_open(sgs):
    # Without sg_members the app-tier 8080 allow is conditional; the solver
    # must treat the boundary as possibly-open (never closed).
    res = parse("aws", sgs)
    app = res.rulesets["sg-0app"]
    dec = rules.boundary_permits(
        app, ["10.1.0.9/32"], ["10.2.0.9/32"], PortRange(Proto.TCP, 8080, 8080)
    )
    assert dec.allowed is True and dec.conditional is True


# -- combined input + determinism --------------------------------------------

def test_combined_input_one_dict(sgs, nacls):
    combined = {
        "SecurityGroups": sgs["SecurityGroups"],
        "NetworkAcls": nacls["NetworkAcls"],
    }
    res = parse("aws", combined)
    assert "sg-0web" in res.rulesets
    assert "acl-0web:ingress" in res.rulesets


def test_missing_keys_do_not_raise():
    res = parse("aws", {"Something": "else"})
    assert res.rulesets == {}
    assert any(w.level is WarningLevel.INFO for w in res.warnings)


def test_deterministic(sgs, nacls):
    combined = {
        "SecurityGroups": sgs["SecurityGroups"],
        "NetworkAcls": nacls["NetworkAcls"],
    }
    a = parse("aws", combined)
    b = parse("aws", combined)
    assert a.rulesets == b.rulesets
    assert a.bindings == b.bindings
    assert a.warnings == b.warnings


def test_conditional_count_reflects_unresolved(sgs):
    res = parse("aws", sgs)          # no sg_members: app-tier refs unresolved
    # sg-0app 8080 (SG ref) + sg-0app 9090 (prefix list) + sg-0db 5432 (SG ref)
    assert res.conditional_count() == 3
    # supplying members for the SG refs leaves only the prefix list conditional
    res2 = parse("aws", sgs, sg_members={"sg-0web": ["10.1.0.0/24"],
                                         "sg-0app": ["10.2.0.0/24"]})
    assert res2.conditional_count() == 1
    r = _rule_on_port(res2.rulesets["sg-0app"], Proto.TCP, 9090)
    assert r.conditional is True
    assert ConditionalFeature.UNRESOLVED  # feature enum is the one we flag
