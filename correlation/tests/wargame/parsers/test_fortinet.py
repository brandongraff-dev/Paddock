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
    assert [r.action for r in rs.rules] == [Action.DENY, Action.ALLOW]
    assert rs.rules[0].order < rs.rules[1].order
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
    assert set(res.rulesets) == {"a+b>c", "any>any"}


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
