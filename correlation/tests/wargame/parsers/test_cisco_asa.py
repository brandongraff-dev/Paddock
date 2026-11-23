"""Tests for the Cisco ASA parser."""
from __future__ import annotations

from pathlib import Path

import pytest

from app.engine.wargame.model import Action, PortRange, Proto
from app.engine.wargame.parsers import get_parser
from app.engine.wargame.parsers.base import WarningLevel
from app.engine.wargame.parsers.cisco_asa import CiscoAsaParser
from app.engine.wargame.rules import evaluate

FIXTURE = Path(__file__).parent / "fixtures" / "cisco_asa.conf"


@pytest.fixture(scope="module")
def result():
    return CiscoAsaParser().parse(FIXTURE.read_text())


def _parse(text: str):
    return CiscoAsaParser().parse(text)


def test_registered():
    assert isinstance(get_parser("cisco_asa"), CiscoAsaParser)


def test_ruleset_shape(result):
    rs = result.rulesets["OUTSIDE_IN"]
    assert rs.vendor == "cisco_asa"
    assert rs.default_action is Action.DENY
    assert len(rs.rules) == 5


def test_ace_order_preserved(result):
    rules = result.rulesets["OUTSIDE_IN"].rules
    assert [r.order for r in rules] == [1, 2, 3, 4, 5]
    assert [r.action for r in rules] == [
        Action.ALLOW, Action.ALLOW, Action.DENY, Action.ALLOW, Action.ALLOW]


def test_group_to_host_object_on_https(result):
    r = result.rulesets["OUTSIDE_IN"].rules[0]
    assert set(r.src_cidrs) == {
        "198.51.100.10/31", "198.51.100.12/30", "198.51.100.16/30",
        "198.51.100.20/32", "198.51.100.50/32"}
    assert r.dst_cidrs == ("10.10.1.10/32",)
    assert r.ports == (PortRange(Proto.TCP, 443, 443),)
    assert not r.conditional


def test_udp_domain_any_any(result):
    r = result.rulesets["OUTSIDE_IN"].rules[1]
    assert "0.0.0.0/0" in r.src_cidrs and "0.0.0.0/0" in r.dst_cidrs
    assert r.ports == (PortRange(Proto.UDP, 53, 53),)


def test_nested_group_object_resolution(result):
    deny = result.rulesets["OUTSIDE_IN"].rules[2]
    assert deny.src_cidrs == ("192.0.2.0/24",)
    assert set(deny.dst_cidrs) == {
        "10.10.1.10/32", "10.10.1.11/32", "10.10.3.5/32", "10.10.4.0/24"}
    assert deny.ports == (PortRange.any(),)


def test_object_group_service_eq_and_range(result):
    r = result.rulesets["OUTSIDE_IN"].rules[3]
    assert set(r.ports) == {
        PortRange(Proto.TCP, 443, 443), PortRange(Proto.TCP, 8000, 8100)}


def test_tcp_udp_group_expands_both_protos():
    res = _parse(
        "object-group service DNS-SVC tcp-udp\n port-object eq 53\n"
        "access-list A extended permit object-group DNS-SVC any any\n")
    assert set(res.rulesets["A"].rules[0].ports) == {
        PortRange(Proto.TCP, 53, 53), PortRange(Proto.UDP, 53, 53)}


def test_object_service_destination():
    res = _parse(
        "object service HTTPS\n service tcp destination eq 443\n"
        "access-list A extended permit tcp any any object HTTPS\n")
    assert res.rulesets["A"].rules[0].ports == (PortRange(Proto.TCP, 443, 443),)


def test_deny_before_permit_wins(result):
    rs = result.rulesets["OUTSIDE_IN"]
    d = evaluate(rs, "192.0.2.77", "10.10.1.10", Proto.TCP, 443)
    assert d.allowed is False
    assert d.matched_rule == "OUTSIDE_IN#3"
    # An unrelated source still reaches the same target via the broad permit.
    d2 = evaluate(rs, "8.8.8.8", "10.10.1.10", Proto.TCP, 443)
    assert d2.allowed is True and d2.matched_rule == "OUTSIDE_IN#4"
    # Partner hits the first, more specific permit.
    d3 = evaluate(rs, "198.51.100.50", "10.10.1.10", Proto.TCP, 443)
    assert d3.allowed and d3.matched_rule == "OUTSIDE_IN#1"


def test_address_forms_and_ip_is_any_proto():
    res = _parse(
        "access-list A extended permit ip host 10.0.0.1 10.1.0.0 255.255.0.0\n"
        "access-list A extended deny tcp any4 any range 1000 2000\n")
    a, b = res.rulesets["A"].rules
    assert a.src_cidrs == ("10.0.0.1/32",)
    assert a.dst_cidrs == ("10.1.0.0/16",)
    assert a.ports == (PortRange.any(),)
    assert "0.0.0.0/0" in b.src_cidrs
    assert b.ports == (PortRange(Proto.TCP, 1000, 2000),)


def test_named_port_https_is_tcp_443():
    res = _parse("access-list A extended permit tcp any any eq https\n")
    assert res.rulesets["A"].rules[0].ports == (PortRange(Proto.TCP, 443, 443),)


def test_extra_spaces_and_indentation_tolerated():
    res = _parse(
        "object network   H1\n    host   10.9.9.9\n"
        "  access-list   A  extended   permit   tcp   object H1   any   eq   www  log\n")
    r = res.rulesets["A"].rules[0]
    assert r.src_cidrs == ("10.9.9.9/32",)
    assert r.ports == (PortRange(Proto.TCP, 80, 80),)


def test_access_group_binding(result):
    acl = [b for b in result.bindings if b.ruleset_id == "OUTSIDE_IN"]
    assert len(acl) == 1
    b = acl[0]
    assert (b.ruleset_id, b.interface, b.direction) == ("OUTSIDE_IN", "outside", "in")


def test_access_group_out():
    res = _parse(
        "access-list X extended permit ip any any\n"
        "access-group X out interface dmz\n")
    b = res.bindings[0]
    assert (b.interface, b.direction) == ("dmz", "out")


def test_unknown_lines_warn_not_crash():
    res = _parse(
        "frobnicate the widgets\n"
        "access-list A extended permit tcp any any eq 22\n"
        "access-list A standard permit 10.0.0.0 255.0.0.0\n"
        "access-list A extended permit tcp\n")
    # The standard ACE is skipped; the truncated *permit* can't be dropped
    # (that could fake a closed door), so it is kept as a conditional any.
    rules = res.rulesets["A"].rules
    assert len(rules) == 2
    assert not rules[0].conditional and rules[1].conditional
    assert rules[1].action is Action.ALLOW
    levels = {w.level for w in res.warnings}
    assert WarningLevel.UNSUPPORTED in levels


def test_unresolved_object_is_conditional():
    res = _parse("access-list A extended permit tcp object MISSING any eq 22\n")
    r = res.rulesets["A"].rules[0]
    assert r.conditional
    assert any(w.level is WarningLevel.UNRESOLVED for w in res.warnings)


def test_empty_and_garbage_input():
    assert _parse("").rulesets == {}
    assert _parse("\n!\n: x\n").rulesets == {}


def test_deterministic(result):
    again = CiscoAsaParser().parse(FIXTURE.read_text())
    assert again.rulesets == result.rulesets
    assert again.bindings == result.bindings
    assert [str(w) for w in again.warnings] == [str(w) for w in result.warnings]


# ---------------------------------------------------------------------------
# Audit regressions: honesty rule (no false "closed")
# ---------------------------------------------------------------------------

def _rules(text: str, acl: str = "A"):
    return _parse(text).rulesets[acl].rules


def test_any4_any6_are_family_scoped():
    # A deny on any4 must not also deny IPv6 traffic (broadened DENY).
    r = _rules("access-list A extended deny ip any4 any6\n")[0]
    assert r.src_cidrs == ("0.0.0.0/0",)
    assert r.dst_cidrs == ("::/0",)
    r = _rules("access-list A extended deny ip 0.0.0.0 0.0.0.0 any\n")[0]
    assert r.src_cidrs == ("0.0.0.0/0",)


def test_zero_netmask_is_any_not_host():
    # ASA uses netmasks: "10.1.1.0 0.0.0.0" is /0, never a /32 host (that
    # would narrow a permit to one address).
    r = _rules("access-list A extended permit ip 10.1.1.0 0.0.0.0 any\n")[0]
    assert r.src_cidrs == ("0.0.0.0/0",)
    res = _parse(
        "object-group network G\n network-object 10.0.0.0 0.0.0.255\n"
        "access-list A extended permit ip object-group G any\n")
    # a Cisco *wildcard* is not a valid ASA netmask: unresolved, never narrowed
    assert res.rulesets["A"].rules[0].conditional


def test_unmodelled_protocol_deny_is_conditional():
    # "deny 47" (GRE) widens to all protocols; it must be conditional so it
    # can't prove TCP closed.
    for proto in ("47", "gre", "esp", "sctp"):
        r = _rules(f"access-list A extended deny {proto} any any\n")[0]
        assert r.conditional, proto
    assert not _rules("access-list A extended deny 6 any any\n")[0].conditional


def test_icmp6_is_icmp_and_family_scoped():
    r = _rules("access-list A extended deny icmp6 any any\n")[0]
    assert r.ports == (PortRange(Proto.ICMP, 0, 65535),)
    assert r.src_cidrs == ("::/0",) and r.dst_cidrs == ("::/0",)
    r = _rules("access-list A extended deny icmp any any\n")[0]
    assert r.src_cidrs == ("0.0.0.0/0",)


def test_icmp_type_deny_is_conditional():
    # "deny icmp any any echo" would otherwise deny ALL ICMP.
    r = _rules("access-list A extended deny icmp any any echo\n")[0]
    assert r.conditional
    assert not _rules("access-list A extended deny icmp any any\n")[0].conditional
    res = _parse(
        "object-group icmp-type PINGS\n icmp-object echo\n"
        "access-list A extended deny object-group PINGS any any\n")
    assert res.rulesets["A"].rules[0].conditional


def test_source_port_deny_is_conditional():
    # "deny tcp any eq 80 any" only denies source port 80; widened to all
    # TCP it would prove closed what is open.
    r = _rules("access-list A extended deny tcp any eq 80 any\n")[0]
    assert r.conditional
    assert r.ports == (PortRange(Proto.TCP, 0, 65535),)


def test_lt_gt_exclusive_and_neq_two_ranges():
    lt, gt, neq = _rules(
        "access-list A extended permit tcp any any lt 1024\n"
        "access-list A extended permit tcp any any gt 1023\n"
        "access-list A extended permit tcp any any neq 22\n")
    assert lt.ports == (PortRange(Proto.TCP, 0, 1023),)
    assert gt.ports == (PortRange(Proto.TCP, 1024, 65535),)
    assert neq.ports == (PortRange(Proto.TCP, 0, 21), PortRange(Proto.TCP, 23, 65535))


def test_port_operator_matching_nothing_is_not_widened_to_any():
    # "lt 0" matches no port; it must not become "any port" (which would
    # turn a deny into deny-all).
    res = _parse("access-list A extended deny tcp any any lt 0\n")
    assert res.rulesets["A"].rules == []


def test_asa_named_ports_are_protocol_specific():
    t, u = _rules(
        "access-list A extended permit tcp any any eq kerberos\n"
        "access-list A extended permit udp any any eq kerberos\n")
    assert t.ports == (PortRange(Proto.TCP, 88, 88),)
    assert u.ports == (PortRange(Proto.UDP, 750, 750),)
    r = _rules("access-list A extended permit udp any any eq snmptrap\n")[0]
    assert r.ports == (PortRange(Proto.UDP, 162, 162),) and not r.conditional
    r = _rules("access-list A extended permit tcp any any eq no-such-port\n")[0]
    assert r.conditional and r.ports == (PortRange(Proto.TCP, 0, 65535),)


def test_ace_without_extended_keyword_is_parsed():
    r = _rules("access-list A permit tcp any host 10.9.9.9 eq 22\n")[0]
    assert r.action is Action.ALLOW and r.dst_cidrs == ("10.9.9.9/32",)


def test_unparseable_permit_is_conditional_any_not_dropped():
    # A user-identity ACE we can't fully read must not vanish.
    rs = _parse(
        "access-list A extended permit ip frobnicate any any\n"
        "access-list A extended deny ip frobnicate any any\n").rulesets["A"]
    assert len(rs.rules) == 1
    assert rs.rules[0].action is Action.ALLOW and rs.rules[0].conditional
    assert evaluate(rs, "1.1.1.1", "2.2.2.2", Proto.TCP, 80).allowed


def test_user_and_security_group_prefixes_are_conditional():
    r = _rules("access-list A extended permit tcp user CORP\\bob host 10.0.0.1 "
               "host 10.0.0.2 eq 22\n")[0]
    assert r.conditional
    assert r.src_cidrs == ("10.0.0.1/32",) and r.dst_cidrs == ("10.0.0.2/32",)
    r = _rules("access-list A extended deny ip security-group tag 5 any any\n")[0]
    assert r.conditional


def test_inactive_ace_skipped_but_acl_exists():
    res = _parse(
        "access-list A extended permit tcp any any eq 22 inactive\n"
        "access-group A in interface outside\n")
    assert res.rulesets["A"].rules == []      # inactive = not evaluated


def test_time_range_is_conditional_for_deny():
    r = _rules("access-list A extended deny ip any any time-range NIGHTS\n")[0]
    assert r.conditional


def test_object_group_cycle_is_conditional_any():
    res = _parse(
        "object-group network L1\n group-object L2\n"
        "object-group network L2\n group-object L1\n"
        "access-list A extended deny ip object-group L1 any\n")
    r = res.rulesets["A"].rules[0]
    assert r.conditional and "0.0.0.0/0" in r.src_cidrs


def test_protocol_and_service_groups_nested():
    res = _parse(
        "object-group protocol P\n protocol-object tcp\n protocol-object udp\n"
        "object-group service S tcp\n port-object eq 22\n"
        "object-group service S2\n service-object tcp-udp destination eq 53\n"
        " group-object S\n"
        "access-list A extended permit object-group P any any\n"
        "access-list A extended permit object-group S2 any any\n")
    p, s2 = res.rulesets["A"].rules
    assert set(p.ports) == {PortRange(Proto.TCP, 0, 65535), PortRange(Proto.UDP, 0, 65535)}
    assert set(s2.ports) == {PortRange(Proto.TCP, 53, 53), PortRange(Proto.UDP, 53, 53),
                             PortRange(Proto.TCP, 22, 22)}
    assert not p.conditional and not s2.conditional


def test_control_plane_access_group_not_bound():
    res = _parse(
        "access-list M extended deny ip any any\n"
        "access-group M in interface outside control-plane\n")
    assert not [b for b in res.bindings if b.ruleset_id == "M"]


def test_unknown_access_list_binding_is_conditional_open():
    res = _parse("access-group GHOST in interface outside\n")
    rs = res.rulesets["GHOST"]
    d = evaluate(rs, "1.1.1.1", "2.2.2.2", Proto.TCP, 443)
    assert d.allowed and d.conditional


_IFACES = (
    "interface G0\n nameif outside\n security-level 0\n"
    " ip address 203.0.113.2 255.255.255.0\n"
    "interface G1\n nameif inside\n security-level 100\n"
    "interface G2\n nameif dmz\n security-level 50\n"
    "interface G3\n nameif dmz2\n security-level 50\n"
)


def _pair(res, src, dst):
    return [b for b in res.bindings if b.src_zone == src and b.dst_zone == dst]


def test_no_acl_is_security_level_default_not_deny():
    # No inbound ACL on inside: higher -> lower is PERMITTED by default.
    res = _parse(_IFACES + "access-list O extended deny ip any any\n"
                 "access-group O in interface outside\n")
    (b,) = _pair(res, "inside", "outside")
    rs = res.rulesets[b.ruleset_id]
    assert evaluate(rs, "10.0.0.1", "8.8.8.8", Proto.TCP, 443).allowed
    # lower -> higher with no ACL: denied
    (b,) = _pair(res, "dmz", "inside")
    assert not evaluate(res.rulesets[b.ruleset_id], "1.1.1.1", "2.2.2.2",
                        Proto.TCP, 22).allowed
    # equal levels: denied without same-security-traffic ...
    (b,) = _pair(res, "dmz", "dmz2")
    assert b.ruleset_id == "asa:security-level:deny"
    # ... outside has an ACL, so it gets no security-level binding
    assert not _pair(res, "outside", "inside")


def test_same_security_traffic_permits_equal_levels():
    res = _parse(_IFACES + "same-security-traffic permit inter-interface\n")
    (b,) = _pair(res, "dmz", "dmz2")
    assert b.ruleset_id == "asa:security-level:permit"


def test_global_acl_follows_interface_acl():
    res = _parse(
        _IFACES
        + "access-list O extended deny tcp any any eq 22\n"
        "access-list G extended permit tcp any any eq 443\n"
        "access-group O in interface outside\n"
        "access-group G global\n")
    rs = res.rulesets["O"]
    # interface rules first, then global, then implicit deny
    assert [r.id for r in rs.rules] == ["O#1", "G#1"]
    assert evaluate(rs, "1.1.1.1", "10.0.0.1", Proto.TCP, 443).allowed
    assert not evaluate(rs, "1.1.1.1", "10.0.0.1", Proto.TCP, 22).allowed
    # interfaces with no ACL of their own are governed by the global ACL,
    # not by the security-level default
    ins = [b for b in res.bindings if b.interface == "inside"]
    assert ins and all(b.ruleset_id == "G" for b in ins)
    assert "asa:security-level:permit" not in res.rulesets


def test_global_acl_merge_keeps_outbound_copy_clean():
    res = _parse(
        "access-list O extended deny tcp any any eq 22\n"
        "access-list G extended permit ip any any\n"
        "access-group O in interface outside\n"
        "access-group O out interface dmz\n"
        "access-group G global\n")
    ins = next(b for b in res.bindings if b.interface == "outside")
    outs = next(b for b in res.bindings if b.interface == "dmz")
    assert ins.ruleset_id == "O+G" and outs.ruleset_id == "O"
    assert len(res.rulesets["O"].rules) == 1
    assert len(res.rulesets["O+G"].rules) == 2


def test_object_nat_widens_and_flags():
    # 8.3+: the ACL names the real address; a topology using the public
    # (mapped) address must not read the boundary closed.
    res = _parse(
        "ASA Version 9.16(4)\n" + _IFACES
        + "object network WEB\n host 10.1.1.10\n nat (dmz,outside) static 203.0.113.10\n"
        "access-list O extended permit tcp any object WEB eq 443\n"
        "access-group O in interface outside\n")
    r = res.rulesets["O"].rules[0]
    assert set(r.dst_cidrs) == {"10.1.1.10/32", "203.0.113.10/32"}
    assert r.conditional
    assert evaluate(res.rulesets["O"], "8.8.8.8", "203.0.113.10", Proto.TCP, 443).allowed


def test_twice_nat_and_interface_pat():
    res = _parse(
        _IFACES
        + "object network REAL\n host 10.1.1.20\n"
        "object network PUB\n host 203.0.113.20\n"
        "nat (dmz,outside) source static REAL PUB\n"
        "access-list O extended permit tcp any host 10.1.1.20 eq 22\n")
    r = res.rulesets["O"].rules[0]
    assert "203.0.113.20/32" in r.dst_cidrs and r.conditional


def test_pre_83_nat_marks_everything_conditional():
    res = _parse(
        "ASA Version 8.2(5)\n"
        "static (inside,outside) 203.0.113.30 10.1.1.30 netmask 255.255.255.255\n"
        "access-list O extended permit tcp any host 203.0.113.30 eq 80\n"
        "access-list O extended deny ip any any\n")
    rules = res.rulesets["O"].rules
    assert all(r.conditional for r in rules)
    assert "10.1.1.30/32" in rules[0].dst_cidrs


def test_unknown_object_member_line_makes_object_conditional():
    res = _parse(
        "object-group network G\n network-object 10.0.0.0 255.0.0.0\n"
        " frobnicate 1.2.3.4\n"
        "access-list A extended deny ip object-group G any\n")
    assert res.rulesets["A"].rules[0].conditional
