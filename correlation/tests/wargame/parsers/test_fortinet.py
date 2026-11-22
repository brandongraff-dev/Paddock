"""Tests for the FortiGate (FortiOS CLI) parser."""
from __future__ import annotations

from pathlib import Path

import pytest

from app.engine.wargame.model import Action, PortRange, Proto
from app.engine.wargame.parsers import base
from app.engine.wargame.parsers.base import ConditionalFeature, WarningLevel
from app.engine.wargame.parsers.fortinet import (
    FortinetParser,
    _build_table_for_tests,
    _tokenize,
)
from app.engine.wargame.rules import evaluate

FIXTURE = Path(__file__).parent / "fixtures" / "fortigate.conf"


@pytest.fixture(scope="module")
def raw() -> str:
    return FIXTURE.read_text()


@pytest.fixture(scope="module")
def result(raw):
    return FortinetParser().parse(raw)


def _rule(result, rsid, pid):
    rs = result.rulesets[rsid]
    return next(r for r in rs.rules if r.id.endswith(f":{pid}"))


# -- registry / tokenizer ----------------------------------------------------

def test_registered():
    assert isinstance(base.get_parser("fortinet"), FortinetParser)


def test_tokenizer_quotes_and_nesting():
    tree = _tokenize(
        'config firewall address\n edit "a b"\n  set comment "x \\"y\\" z"\n'
        '  set member "A" "B"\n next\nend\n'
    )
    cfg = tree.children[0]
    assert cfg.name == "firewall address"
    e = cfg.children[0]
    assert e.name == "a b"
    assert e.settings["comment"] == ['x "y" z']
    assert e.settings["member"] == ["A", "B"]


def test_garbage_never_raises():
    for junk in ("", "end\nnext\nend", "config firewall policy\n edit 1\n set action", "\x00\x01"):
        FortinetParser().parse(junk)


# -- address objects ---------------------------------------------------------

def test_subnet_iprange_and_all_resolve(raw):
    t = _build_table_for_tests(raw)
    assert t.resolve_addresses("LAN_NET").cidrs == ("10.10.0.0/16",)
    assert t.resolve_addresses("DMZ_WEB").cidrs == ("172.16.10.10/32",)
    assert t.resolve_addresses("VENDOR_RANGE").cidrs == ("203.0.113.16/28",)
    assert "0.0.0.0/0" in t.resolve_addresses("all").cidrs


def test_fqdn_and_geo_conditional(raw):
    t = _build_table_for_tests(raw)
    f = t.resolve_addresses("updates.example.com")
    assert f.conditional and ConditionalFeature.FQDN in f.features
    g = t.resolve_addresses("BLOCKED_COUNTRIES")
    assert g.conditional and ConditionalFeature.GEO in g.features


def test_addrgrp_resolution(raw):
    t = _build_table_for_tests(raw)
    assert set(t.resolve_addresses("DMZ_SERVERS").cidrs) == {
        "172.16.10.10/32", "172.16.20.0/24"}


# -- services ----------------------------------------------------------------

def test_service_custom_range_src_suffix_icmp_group(raw):
    t = _build_table_for_tests(raw)
    assert t.resolve_service("WEB_ALT").ports == (PortRange(Proto.TCP, 8000, 8100),)
    api = t.resolve_service("APP_API").ports
    assert PortRange(Proto.TCP, 8443, 8443) in api
    assert PortRange(Proto.TCP, 9000, 9000) in api   # ":src" suffix dropped
    assert PortRange(Proto.UDP, 5353, 5353) in api
    assert t.resolve_service("ALL_PING").ports == (PortRange(Proto.ICMP, 0, 65535),)
    grp = t.resolve_service("WEB_SERVICES")
    assert PortRange(Proto.TCP, 443, 443) in grp.ports
    assert PortRange(Proto.TCP, 8000, 8100) in grp.ports
    assert not grp.conditional


# -- policies ----------------------------------------------------------------

def test_disabled_policy_skipped(result):
    ids = [r.id for rs in result.rulesets.values() for r in rs.rules]
    assert not any(i.endswith(":5") for i in ids)
    assert any(w.level == WarningLevel.INFO and "disabled" in w.message
               for w in result.warnings)


def test_zone_pair_rulesets_and_bindings(result):
    assert set(result.rulesets) == {"lan>dmz", "lan>wan1", "wan1>dmz"}
    for rs in result.rulesets.values():
        assert rs.vendor == "fortinet" and rs.default_action == Action.DENY
    b = {x.ruleset_id: (x.src_zone, x.dst_zone) for x in result.bindings}
    assert b == {"lan>dmz": ("lan", "dmz"), "lan>wan1": ("lan", "wan1"),
                 "wan1>dmz": ("wan1", "dmz")}
    assert len(result.bindings) == 3


def test_deny_precedes_accept_in_same_pair(result):
    rs = result.rulesets["lan>dmz"]
    # policy 2 is split: its clean services, then (same order) APP_API,
    # whose "9000:1024-65535" source-port range is not modelled
    assert [r.action for r in rs.rules] == [Action.DENY, Action.ALLOW, Action.ALLOW]
    assert [r.id for r in rs.rules] == [
        "fortinet:1", "fortinet:2", "fortinet:2#conditional"]
    assert rs.rules[0].order < rs.rules[1].order == rs.rules[2].order
    assert not rs.rules[1].conditional and rs.rules[2].conditional
    # telnet hits the deny first; https falls to the accept
    d = evaluate(rs, "10.10.1.5", "172.16.10.10", Proto.TCP, 23)
    assert not d.allowed and d.matched_rule.endswith(":1")
    d = evaluate(rs, "10.10.1.5", "172.16.10.10", Proto.TCP, 443)
    assert d.allowed and d.matched_rule.endswith(":2") and not d.conditional
    d = evaluate(rs, "10.10.1.5", "172.16.10.10", Proto.ICMP, 0)
    assert d.allowed
    # outside the allowed ports: implicit deny
    assert not evaluate(rs, "10.10.1.5", "172.16.10.10", Proto.TCP, 3389).allowed


def test_missing_action_is_deny(result):
    r = _rule(result, "lan>wan1", 6)
    assert r.action == Action.DENY


def test_dns_builtin_covers_tcp_and_udp(result):
    r = _rule(result, "lan>wan1", 6)
    assert PortRange(Proto.TCP, 53, 53) in r.ports
    assert PortRange(Proto.UDP, 53, 53) in r.ports


def test_fqdn_policy_is_conditional(result):
    r = _rule(result, "lan>wan1", 3)
    assert r.conditional is True
    assert any(w.level == WarningLevel.CONDITIONAL and "DNS" in w.message
               for w in result.warnings)
    d = evaluate(result.rulesets["lan>wan1"], "10.10.1.5", "8.8.8.8", Proto.TCP, 443)
    assert d.allowed and d.conditional


def test_plain_policy_not_conditional(result):
    assert _rule(result, "wan1>dmz", 4).conditional is False


def test_unsupported_block_warned(result):
    assert any(w.level == WarningLevel.UNSUPPORTED and "router static" in w.message
               for w in result.warnings)


def test_multi_interface_key_and_unset_any():
    raw = (
        'config firewall policy\n edit 1\n  set srcintf "a" "b"\n'
        '  set dstintf "c"\n  set srcaddr "all"\n  set dstaddr "all"\n'
        '  set action accept\n  set service "ALL"\n next\n'
        ' edit 2\n  set action accept\n next\nend\n'
    )
    res = FortinetParser().parse(raw)
    # one set per concrete interface pair; the any/any policy also governs
    # a>c and b>c, after policy 1 (sequence order)
    assert set(res.rulesets) == {"a>c", "b>c", "any>any"}
    assert [r.id for r in res.rulesets["a>c"].rules] == ["fortinet:1", "fortinet:2"]
    assert [r.id for r in res.rulesets["any>any"].rules] == ["fortinet:2"]


def test_unknown_objects_are_conditional():
    raw = (
        'config firewall policy\n edit 1\n  set srcintf "a"\n  set dstintf "b"\n'
        '  set srcaddr "GHOST"\n  set dstaddr "all"\n  set action accept\n'
        '  set service "ALL"\n next\nend\n'
    )
    res = FortinetParser().parse(raw)
    assert res.rulesets["a>b"].rules[0].conditional is True
    assert any(w.level == WarningLevel.UNRESOLVED for w in res.warnings)


def test_determinism(raw):
    def snap():
        r = FortinetParser().parse(raw)
        return (
            {k: v.rules for k, v in r.rulesets.items()},
            r.bindings,
            [(w.level, w.message, w.ref) for w in r.warnings],
        )
    assert snap() == snap()


# ---------------------------------------------------------------------------
# Audit regressions: honesty rule (no false "closed")
# ---------------------------------------------------------------------------

def _pol(body: str, extra: str = "", pid: str = "1") -> str:
    return (extra + "config firewall policy\n"
            f" edit {pid}\n" + body + " next\nend\n")


_STD = ('  set srcintf "lan"\n  set dstintf "wan1"\n  set srcaddr "all"\n'
        '  set dstaddr "all"\n  set service "ALL"\n')


def _only_rule(res, rsid="lan>wan1"):
    (r,) = res.rulesets[rsid].rules
    return r


def test_policy_order_is_sequence_not_id():
    raw = ("config firewall policy\n"
           " edit 20\n" + _STD + "  set action deny\n next\n"
           " edit 5\n" + _STD + "  set action accept\n next\nend\n")
    rs = FortinetParser().parse(raw).rulesets["lan>wan1"]
    assert [r.id for r in sorted(rs.rules, key=lambda r: r.order)] == [
        "fortinet:20", "fortinet:5"]
    assert not evaluate(rs, "10.0.0.1", "8.8.8.8", Proto.TCP, 80).allowed


def test_srcaddr_negate_accept_is_exact_complement_not_narrowed():
    # "accept from everything EXCEPT 10/8": widening/inverting this wrongly
    # would hide that 8.8.8.8 is allowed.
    raw = _pol('  set srcintf "lan"\n  set dstintf "wan1"\n'
               '  set srcaddr "CORP"\n  set srcaddr-negate enable\n'
               '  set dstaddr "all"\n  set action accept\n  set service "ALL"\n',
               'config firewall address\n edit "CORP"\n'
               '  set subnet 10.0.0.0 255.0.0.0\n next\nend\n')
    rs = FortinetParser().parse(raw).rulesets["lan>wan1"]
    d = evaluate(rs, "8.8.8.8", "1.1.1.1", Proto.TCP, 443)
    assert d.allowed and not d.conditional
    assert not evaluate(rs, "10.1.2.3", "1.1.1.1", Proto.TCP, 443).allowed


def test_dstaddr_negate_over_conditional_object_widens():
    raw = _pol('  set srcintf "lan"\n  set dstintf "wan1"\n  set srcaddr "all"\n'
               '  set dstaddr "F"\n  set dstaddr-negate enable\n'
               '  set action deny\n  set service "ALL"\n',
               'config firewall address\n edit "F"\n  set type fqdn\n'
               '  set fqdn "x.example.test"\n next\nend\n')
    r = _only_rule(FortinetParser().parse(raw))
    assert r.conditional and r.dst_cidrs == ("0.0.0.0/0",)


def test_service_negate_is_conditional():
    raw = _pol(_STD.replace('"ALL"', '"HTTPS"')
               + '  set service-negate enable\n  set action deny\n')
    r = _only_rule(FortinetParser().parse(raw))
    assert r.conditional


def test_ipv4_all_does_not_cover_ipv6():
    # srcaddr/dstaddr are IPv4 fields: a deny on "all" must not deny IPv6.
    r = _only_rule(FortinetParser().parse(_pol(_STD + "  set action deny\n")))
    assert r.src_cidrs == ("0.0.0.0/0",) and r.dst_cidrs == ("0.0.0.0/0",)


def test_ipv6_fields_and_policy6_are_parsed():
    v6obj = ('config firewall address6\n edit "V6"\n  set ip6 2001:db8::/48\n'
             ' next\nend\n')
    raw = _pol(_STD + '  set srcaddr6 "V6"\n  set dstaddr6 "all"\n'
               '  set action accept\n', v6obj)
    r = _only_rule(FortinetParser().parse(raw))
    assert "2001:db8::/48" in r.src_cidrs and "::/0" in r.dst_cidrs
    raw6 = (v6obj + "config firewall policy6\n edit 1\n"
            '  set srcintf "lan"\n  set dstintf "wan1"\n  set srcaddr "V6"\n'
            '  set dstaddr "all"\n  set action accept\n  set service "ALL"\n'
            " next\nend\n")
    rs = FortinetParser().parse(raw6).rulesets["lan>wan1"]
    assert evaluate(rs, "2001:db8::5", "2001:4860::8888", Proto.TCP, 443).allowed


def test_any_interface_policy_governs_concrete_pairs():
    # An accept on srcintf any, listed first, must appear in lan>wan1 ahead
    # of the specific deny; otherwise lan>wan1 reads closed.
    raw = ("config firewall policy\n"
           " edit 1\n" + _STD.replace('"lan"', '"any"') + "  set action accept\n next\n"
           " edit 2\n" + _STD + "  set action deny\n next\nend\n")
    rs = FortinetParser().parse(raw).rulesets["lan>wan1"]
    assert [r.id for r in rs.rules] == ["fortinet:1", "fortinet:2"]
    assert evaluate(rs, "10.0.0.1", "8.8.8.8", Proto.TCP, 80).allowed


def test_custom_service_ranges_and_src_suffix():
    raw = ('config firewall service custom\n edit "S"\n'
           '  set tcp-portrange 80 443 8000-8080:1-65535\n'
           '  set udp-portrange 53:53\n next\n'
           ' edit "BAD"\n  set tcp-portrange 70000 x-y\n next\nend\n')
    t = _build_table_for_tests(raw)
    s = t.resolve_service("S")
    assert set(s.ports) == {PortRange(Proto.TCP, 80, 80), PortRange(Proto.TCP, 443, 443),
                            PortRange(Proto.TCP, 8000, 8080), PortRange(Proto.UDP, 53, 53)}
    assert s.conditional    # udp src port 53 only: not modelled
    bad = t.resolve_service("BAD")
    assert bad.conditional and PortRange(Proto.TCP, 0, 65535) in bad.ports


def test_out_of_range_port_does_not_crash_parse():
    raw = ('config firewall service custom\n edit "BIG"\n  set tcp-portrange 70000\n'
           ' next\nend\n' + _pol(_STD.replace('"ALL"', '"BIG"') + "  set action accept\n"))
    res = FortinetParser().parse(raw)
    assert res.rulesets["lan>wan1"].rules[0].conditional
    assert not any("aborted" in w.message for w in res.warnings)


def test_ip_protocol_number_deny_is_conditional():
    raw = ('config firewall service custom\n edit "GRE"\n  set protocol IP\n'
           '  set protocol-number 47\n next\nend\n'
           + _pol(_STD.replace('"ALL"', '"GRE"') + "  set action deny\n"))
    assert _only_rule(FortinetParser().parse(raw)).conditional


def test_icmp_type_service_deny_is_conditional():
    raw = ('config firewall service custom\n edit "ECHO"\n  set protocol ICMP\n'
           '  set icmptype 8\n next\nend\n'
           + _pol(_STD.replace('"ALL"', '"ECHO"') + "  set action deny\n"))
    assert _only_rule(FortinetParser().parse(raw)).conditional


def test_builtin_ntp_and_sip_cover_tcp_and_udp():
    raw = _pol(_STD.replace('"ALL"', '"NTP" "SIP"') + "  set action accept\n")
    ports = set(_only_rule(FortinetParser().parse(raw)).ports)
    assert {PortRange(Proto.TCP, 123, 123), PortRange(Proto.UDP, 123, 123),
            PortRange(Proto.TCP, 5060, 5060), PortRange(Proto.UDP, 5060, 5060)} <= ports


def test_schedule_deny_is_conditional():
    raw = _pol(_STD + '  set action deny\n  set schedule "nights"\n')
    assert _only_rule(FortinetParser().parse(raw)).conditional


def test_users_internet_service_app_are_conditional():
    for extra in ('  set groups "staff"\n', '  set internet-service enable\n',
                  '  set application 15832\n'):
        raw = _pol(_STD + "  set action accept\n" + extra)
        assert _only_rule(FortinetParser().parse(raw)).conditional, extra


def test_vip_is_conditional_nat_with_both_addresses():
    vip = ('config firewall vip\n edit "WEB_VIP"\n  set extip 203.0.113.10\n'
           '  set mappedip "10.0.5.10"\n  set extintf "wan1"\n next\nend\n')
    raw = _pol(_STD.replace('"lan"', '"wan1"', 1).replace('"wan1"\n  set srcaddr',
               '"lan"\n  set srcaddr').replace('set dstaddr "all"', 'set dstaddr "WEB_VIP"')
               + "  set action accept\n", vip)
    rs = FortinetParser().parse(raw).rulesets["wan1>lan"]
    (r,) = rs.rules
    assert set(r.dst_cidrs) == {"203.0.113.10/32", "10.0.5.10/32"} and r.conditional
    for dst in ("203.0.113.10", "10.0.5.10"):
        assert evaluate(rs, "8.8.8.8", dst, Proto.TCP, 443).allowed


def test_deny_without_match_vip_is_conditional_when_vips_exist():
    vip = ('config firewall vip\n edit "V"\n  set extip 203.0.113.10\n'
           '  set mappedip "10.0.5.10"\n next\nend\n')
    r = _only_rule(FortinetParser().parse(_pol(_STD + "  set action deny\n", vip)))
    assert r.conditional
    r = _only_rule(FortinetParser().parse(
        _pol(_STD + "  set action deny\n  set match-vip enable\n", vip)))
    assert not r.conditional


def test_addrgrp_exclude_is_exact():
    objs = ('config firewall address\n edit "NET"\n  set subnet 10.0.0.0 255.255.0.0\n'
            ' next\n edit "HOLE"\n  set subnet 10.0.1.0 255.255.255.0\n next\nend\n'
            'config firewall addrgrp\n edit "G"\n  set member "NET"\n'
            '  set exclude enable\n  set exclude-member "HOLE"\n next\nend\n')
    raw = _pol(_STD.replace('set srcaddr "all"', 'set srcaddr "G"') + "  set action deny\n",
               objs)
    rs = FortinetParser().parse(raw).rulesets["lan>wan1"]
    assert not rs.rules[0].conditional
    assert not evaluate(rs, "10.0.2.1", "8.8.8.8", Proto.TCP, 80).allowed
    # the excluded hole is NOT denied by this policy
    assert evaluate(rs, "10.0.1.5", "8.8.8.8", Proto.TCP, 80).matched_rule is None


def test_wildcard_and_unknown_address_types_conditional():
    raw = _pol(_STD.replace('set srcaddr "all"', 'set srcaddr "W"') + "  set action deny\n",
               'config firewall address\n edit "W"\n  set type wildcard\n'
               '  set wildcard 10.0.1.0 255.0.255.0\n next\nend\n')
    assert _only_rule(FortinetParser().parse(raw)).conditional


def test_unknown_action_is_conditional_accept():
    r = _only_rule(FortinetParser().parse(_pol(_STD + "  set action frobnicate\n")))
    assert r.action is Action.ALLOW and r.conditional


def test_missing_service_is_conditional():
    raw = _pol('  set srcintf "lan"\n  set dstintf "wan1"\n  set srcaddr "all"\n'
               '  set dstaddr "all"\n  set action deny\n')
    assert _only_rule(FortinetParser().parse(raw)).conditional


def test_multi_vdom_rulesets_are_prefixed_and_objects_scoped():
    raw = ("config vdom\n edit root\n"
           "config firewall address\n edit \"N\"\n  set subnet 10.1.0.0 255.255.0.0\n next\nend\n"
           + _pol(_STD.replace('set srcaddr "all"', 'set srcaddr "N"') + "  set action accept\n")
           + "next\n edit dmzvdom\n"
           "config firewall address\n edit \"N\"\n  set subnet 10.2.0.0 255.255.0.0\n next\nend\n"
           + _pol(_STD.replace('set srcaddr "all"', 'set srcaddr "N"') + "  set action accept\n")
           + "next\nend\n")
    res = FortinetParser().parse(raw)
    assert res.rulesets["root:lan>wan1"].rules[0].src_cidrs == ("10.1.0.0/16",)
    assert res.rulesets["dmzvdom:lan>wan1"].rules[0].src_cidrs == ("10.2.0.0/16",)


def test_proxy_policy_block_is_flagged():
    res = FortinetParser().parse("config firewall proxy-policy\n edit 1\n next\nend\n")
    assert any("can permit traffic" in w.message for w in res.warnings)
