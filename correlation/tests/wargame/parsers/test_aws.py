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


# -- audit regressions -------------------------------------------------------

from app.engine.wargame.parsers.aws import combine_security_groups  # noqa: E402


def _sg(perms=None, egress=None, gid="sg-t", **extra) -> dict:
    sg = {"GroupId": gid, "OwnerId": "111111111111"}
    if perms is not None:
        sg["IpPermissions"] = perms
    if egress is not None:
        sg["IpPermissionsEgress"] = egress
    sg.update(extra)
    return {"SecurityGroups": [sg]}


def _cidr(c="10.0.0.0/8"):
    return [{"CidrIp": c}]


@pytest.mark.parametrize("tok,proto", [
    ("-1", Proto.ANY), ("6", Proto.TCP), ("tcp", Proto.TCP),
    ("17", Proto.UDP), ("udp", Proto.UDP), ("1", Proto.ICMP),
    ("icmp", Proto.ICMP), ("58", Proto.ICMP), ("icmpv6", Proto.ICMP),
])
def test_sg_protocol_tokens(tok, proto):
    raw = _sg([{"IpProtocol": tok, "FromPort": 80, "ToPort": 80, "IpRanges": _cidr()}])
    r = parse("aws", raw).rulesets["sg-t"].rules[0]
    assert not r.conditional
    assert all(p.proto is proto for p in r.ports)
    if proto is Proto.ANY:
        assert r.ports == (PortRange.any(),)      # ports ignored for "all"
    elif proto is Proto.ICMP:
        assert r.ports == (PortRange(Proto.ICMP, 0, 65535),)
    else:
        assert r.ports == (PortRange(proto, 80, 80),)


def test_sg_unmodelled_protocol_is_conditional_any():
    # GRE (47): over-approximated, never dropped or narrowed
    res = parse("aws", _sg([{"IpProtocol": "47", "IpRanges": _cidr()}]))
    r = res.rulesets["sg-t"].rules[0]
    assert r.conditional and r.ports == (PortRange.any(),)
    assert any(w.level is WarningLevel.UNSUPPORTED for w in res.warnings)


def test_sg_garbage_port_does_not_crash_and_widens():
    res = parse("aws", _sg([{"IpProtocol": "tcp", "FromPort": "x", "ToPort": None,
                             "IpRanges": _cidr()}]))
    r = res.rulesets["sg-t"].rules[0]
    assert r.conditional and r.ports == (PortRange(Proto.TCP, 0, 65535),)


def test_icmp_minus_one_ports_and_ipv6_ranges():
    res = parse("aws", _sg([{"IpProtocol": "icmpv6", "FromPort": -1, "ToPort": -1,
                             "Ipv6Ranges": [{"CidrIpv6": "2001:db8::/32"}]}]))
    r = res.rulesets["sg-t"].rules[0]
    assert r.src_cidrs == ("2001:db8::/32",) and not r.conditional
    assert r.ports == (PortRange(Proto.ICMP, 0, 65535),)


def test_prefix_list_is_conditional_not_dropped():
    res = parse("aws", _sg([{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                             "IpRanges": _cidr("192.0.2.0/24"),
                             "PrefixListIds": [{"PrefixListId": "pl-0abc"}]}]))
    r = res.rulesets["sg-t"].rules[0]
    assert r.conditional and r.src_cidrs == base.ANY_CIDRS
    assert any("pl-0abc" in w.message for w in res.warnings)


def test_group_pair_without_group_id_is_not_silently_dropped():
    # A GroupName-only pair next to a literal CIDR used to leave just the CIDR:
    # the real source set was narrowed (false closed).
    res = parse("aws", _sg([{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                             "IpRanges": _cidr("192.0.2.0/24"),
                             "UserIdGroupPairs": [{"GroupName": "bastion"}]}]))
    r = res.rulesets["sg-t"].rules[0]
    assert r.conditional and r.src_cidrs == base.ANY_CIDRS


def test_group_ref_without_members_is_conditional_any_even_with_cidrs():
    res = parse("aws", _sg([{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                             "IpRanges": _cidr("192.0.2.0/24"),
                             "UserIdGroupPairs": [{"GroupId": "sg-other"}]}]))
    r = res.rulesets["sg-t"].rules[0]
    assert r.conditional and r.src_cidrs == base.ANY_CIDRS


def test_cross_account_group_ref_stays_conditional_even_with_members():
    perm = {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
            "UserIdGroupPairs": [{"GroupId": "sg-peer", "UserId": "999999999999"}]}
    res = AwsParser().parse(_sg([perm]), sg_members={"sg-peer": ["10.7.0.0/24"]})
    r = res.rulesets["sg-t"].rules[0]
    assert r.conditional and r.src_cidrs == ("10.7.0.0/24",)
    # same-account ref with members is a hard allow
    perm["UserIdGroupPairs"][0]["UserId"] = "111111111111"
    res = AwsParser().parse(_sg([perm]), sg_members={"sg-peer": ["10.7.0.0/24"]})
    assert not res.rulesets["sg-t"].rules[0].conditional


def test_unparseable_cidr_widens_instead_of_matching_nothing():
    res = parse("aws", _sg([{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                             "IpRanges": [{"CidrIp": "not-a-cidr"}]}]))
    r = res.rulesets["sg-t"].rules[0]
    assert r.conditional and r.src_cidrs == base.ANY_CIDRS


def test_permission_with_no_source_is_conditional_any():
    res = parse("aws", _sg([{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22}]))
    assert res.rulesets["sg-t"].rules[0].conditional


def test_missing_ingress_key_is_not_deny_all():
    res = parse("aws", {"SecurityGroups": [{"GroupId": "sg-t"}]})
    rules_ = res.rulesets["sg-t"].rules
    assert len(rules_) == 1 and rules_[0].conditional
    assert rules_[0].src_cidrs == base.ANY_CIDRS


def test_empty_egress_is_deny_all_but_missing_egress_is_unmodelled():
    res = parse("aws", _sg([], egress=[]))
    assert res.rulesets["sg-t:egress"].rules == []
    assert res.rulesets["sg-t:egress"].default_action is Action.DENY
    res = parse("aws", _sg([]))
    assert "sg-t:egress" not in res.rulesets
    assert any("IpPermissionsEgress" in w.message for w in res.warnings)


def test_default_sg_egress_allow_all():
    res = parse("aws", _sg([], egress=[{"IpProtocol": "-1", "IpRanges": _cidr("0.0.0.0/0")}]))
    r = res.rulesets["sg-t:egress"].rules[0]
    assert "0.0.0.0/0" in r.dst_cidrs and r.ports == (PortRange.any(),)
    assert r.src_cidrs == base.ANY_CIDRS and r.action is Action.ALLOW


def test_non_object_permission_is_widened_not_dropped():
    res = parse("aws", _sg(["junk"]))
    r = res.rulesets["sg-t"].rules[0]
    assert r.conditional and r.src_cidrs == base.ANY_CIDRS


def test_combine_security_groups_is_a_union():
    raw = {"SecurityGroups": [
        {"GroupId": "sg-a", "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": _cidr("10.0.0.0/8")}]},
        {"GroupId": "sg-b", "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": _cidr("0.0.0.0/0")}]},
    ]}
    res = parse("aws", raw)
    merged = combine_security_groups(res, ["sg-b", "sg-a"], "eni-1")
    assert merged is res.rulesets["eni-1"] and merged.default_action is Action.DENY
    ports = {(p.low, p.high) for r in merged.rules for p in r.ports}
    assert ports == {(22, 22), (443, 443)}
    assert [r.order for r in merged.rules] == [0, 1]
    # originals untouched, unknown ids warn rather than raise
    assert len(res.rulesets["sg-a"].rules) == 1
    assert combine_security_groups(res, ["sg-zzz"], "eni-2") is None


# -- NACL audit regressions --------------------------------------------------

def _nacl(entries, nid="acl-t") -> dict:
    return {"NetworkAcls": [{"NetworkAclId": nid, "Entries": entries,
                             "Associations": [{"SubnetId": "subnet-1"}]}]}


def _e(num, action="allow", proto="6", cidr="0.0.0.0/0", egress=False, ports=(22, 22), **x):
    e = {"RuleNumber": num, "RuleAction": action, "Protocol": proto,
         "CidrBlock": cidr, "Egress": egress}
    if ports:
        e["PortRange"] = {"From": ports[0], "To": ports[1]}
    e.update(x)
    return e


def test_nacl_orders_by_rule_number_regardless_of_export_order():
    entries = [_e(32767, "deny", "-1", ports=None), _e(200), _e(100, "deny")]
    rs = parse("aws", _nacl(entries)).rulesets["acl-t:ingress"]
    assert [r.order for r in rs.rules] == [100, 200, 32767]
    assert rs.default_action is Action.DENY
    assert rs.rules[0].action is Action.DENY and rs.rules[0].id == "acl-t:ingress#100"


def test_nacl_egress_flag_and_string_flag():
    res = parse("aws", _nacl([_e(100, egress=True), _e(110, egress="false")]))
    assert [r.order for r in res.rulesets["acl-t:egress"].rules] == [100]
    assert [r.order for r in res.rulesets["acl-t:ingress"].rules] == [110]


def test_nacl_deny_for_unmodelled_protocol_is_dropped_not_widened():
    # A deny for GRE (47) read as "deny any" would shadow every later allow.
    entries = [_e(100, "deny", "47", ports=None), _e(200, "allow", "6", ports=(443, 443))]
    res = parse("aws", _nacl(entries))
    assert [r.order for r in res.rulesets["acl-t:ingress"].rules] == [200]
    assert any("deny entry skipped" in w.message for w in res.warnings)


def test_nacl_specific_icmp_deny_is_dropped_not_widened_to_all_icmp():
    entries = [_e(100, "deny", "1", ports=None, IcmpTypeCode={"Type": 8, "Code": -1}),
               _e(200, "allow", "1", ports=None)]
    res = parse("aws", _nacl(entries))
    assert [r.order for r in res.rulesets["acl-t:ingress"].rules] == [200]


def test_nacl_deny_with_bad_cidr_is_dropped_allow_is_conditional():
    res = parse("aws", _nacl([_e(100, "deny", cidr="bogus"), _e(110, "allow", cidr="bogus")]))
    rs = res.rulesets["acl-t:ingress"]
    assert [(r.order, r.conditional) for r in rs.rules] == [(110, True)]


def test_nacl_unmodelled_protocol_allow_is_conditional_any():
    res = parse("aws", _nacl([_e(100, "allow", "47", ports=None)]))
    r = res.rulesets["acl-t:ingress"].rules[0]
    assert r.conditional and r.ports == (PortRange.any(),)


def test_nacl_unknown_action_reads_as_conditional_allow():
    res = parse("aws", _nacl([_e(100, "maybe")]))
    r = res.rulesets["acl-t:ingress"].rules[0]
    assert r.action is Action.ALLOW and r.conditional


def test_nacl_ipv4_ipv6_same_number_keep_unique_ids():
    v6 = {"RuleNumber": 100, "RuleAction": "allow", "Protocol": "-1", "Egress": False,
          "Ipv6CidrBlock": "::/0"}
    res = parse("aws", _nacl([_e(100, "deny"), v6]))
    ids = [r.id for r in res.rulesets["acl-t:ingress"].rules]
    assert len(ids) == len(set(ids)) == 2


def test_nacl_missing_entries_is_not_deny_all():
    res = parse("aws", {"NetworkAcls": [{"NetworkAclId": "acl-t"}]})
    for d in ("ingress", "egress"):
        (r,) = res.rulesets[f"acl-t:{d}"].rules
        assert r.conditional and r.action is Action.ALLOW


def test_nacl_stateless_return_path_warning():
    res = parse("aws", _nacl([_e(100, "allow", ports=(443, 443))]))
    assert any("stateless" in w.message for w in res.warnings)
    ok = parse("aws", _nacl([_e(100, "allow", ports=(443, 443)),
                             _e(100, "allow", egress=True, ports=(1024, 65535))]))
    assert not any("stateless" in w.message for w in ok.warnings)
