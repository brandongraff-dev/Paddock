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
    assert len(result.bindings) == 1
    b = result.bindings[0]
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
    assert len(res.rulesets["A"].rules) == 1
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
