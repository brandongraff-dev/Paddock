"""Tests for the parser foundation: normalisation, object resolution, and
the honesty rule (conditional / unresolved → never a clean proof)."""
from __future__ import annotations

import pytest

from app.engine.wargame.model import Action, PortRange, Proto
from app.engine.wargame.parsers import base
from app.engine.wargame.parsers.base import (
    AddressObject,
    ConditionalFeature,
    ObjectTable,
    ResolvedAddresses,
    ResolvedService,
    ServiceObject,
    WarningLevel,
    build_rule,
    normalize_cidrs,
    port_from_name,
    proto_from,
    service_from_name,
)


# -- address normalisation ---------------------------------------------------

@pytest.mark.parametrize(
    "token,expected",
    [
        ("any", ["0.0.0.0/0", "::/0"]),
        ("ALL", ["0.0.0.0/0", "::/0"]),
        ("10.0.0.1", ["10.0.0.1/32"]),
        ("10.0.0.0/24", ["10.0.0.0/24"]),
        ("10.0.0.0 255.255.255.0", ["10.0.0.0/24"]),       # netmask
        ("10.0.0.0 0.0.0.255", ["10.0.0.0/24"]),           # cisco wildcard
        ("10.0.0.0/255.255.0.0", ["10.0.0.0/16"]),         # dotted mask after /
        ("2001:db8::/32", ["2001:db8::/32"]),
        ("2001:db8::1", ["2001:db8::1/128"]),
    ],
)
def test_normalize_cidrs(token, expected):
    assert normalize_cidrs(token) == expected


def test_normalize_range_summarizes():
    got = normalize_cidrs("10.0.0.0-10.0.0.255")
    assert got == ["10.0.0.0/24"]


def test_normalize_non_literal_returns_none():
    # An object name is not an address literal.
    assert normalize_cidrs("GUEST_NET") is None
    assert normalize_cidrs("") is None


def test_noncontiguous_wildcard_is_not_forced_into_a_cidr():
    # 0.0.0.255 with a hole (e.g. 0.0.255.0 split) — a non-contiguous mask
    # can't be one CIDR; normalize returns None so the caller flags it.
    assert normalize_cidrs("10.0.0.0 0.255.0.255") is None


# -- protocol / port ---------------------------------------------------------

@pytest.mark.parametrize(
    "token,proto",
    [("tcp", Proto.TCP), ("6", Proto.TCP), ("udp", Proto.UDP),
     ("icmp", Proto.ICMP), ("ip", Proto.ANY), ("-1", Proto.ANY),
     ("nonsense", Proto.ANY)],
)
def test_proto_from(token, proto):
    assert proto_from(token) is proto


def test_port_from_name():
    assert port_from_name("443") == 443
    assert port_from_name("https") == 443
    assert port_from_name("postgresql") == 5432
    assert port_from_name("not-a-service") is None


def test_service_from_name():
    ssh = service_from_name("ssh")
    assert ssh == (PortRange(Proto.TCP, 22, 22),)
    assert service_from_name("any") == (PortRange.any(),)
    assert service_from_name("mystery-svc") is None


# -- object table: nested groups ---------------------------------------------

def _table():
    t = ObjectTable()
    t.add_address(AddressObject("WEB1", cidrs=("10.1.0.10/32",)))
    t.add_address(AddressObject("WEB2", cidrs=("10.1.0.11/32",)))
    t.add_address(AddressObject("WEB_TIER", members=("WEB1", "WEB2")))
    t.add_address(AddressObject("APP_TIER", cidrs=("10.2.0.0/24",)))
    t.add_address(AddressObject("ALL_TIERS", members=("WEB_TIER", "APP_TIER")))
    t.add_service(ServiceObject("WEB_PORTS", ports=(
        PortRange(Proto.TCP, 80, 80), PortRange(Proto.TCP, 443, 443))))
    return t


def test_resolve_nested_address_group():
    r = _table().resolve_addresses("ALL_TIERS")
    assert set(r.cidrs) == {"10.1.0.10/32", "10.1.0.11/32", "10.2.0.0/24"}
    assert r.conditional is False


def test_resolve_literal_through_table():
    r = _table().resolve_addresses("192.168.1.0/24")
    assert r.cidrs == ("192.168.1.0/24",)


def test_cycle_is_safe():
    t = ObjectTable()
    t.add_address(AddressObject("A", members=("B",)))
    t.add_address(AddressObject("B", members=("A", "10.5.0.0/24")))
    r = t.resolve_addresses("A")
    assert "10.5.0.0/24" in r.cidrs  # terminates, picks up the literal


# -- the honesty rule --------------------------------------------------------

def test_unresolved_object_is_conditional_and_opens_wide():
    # An object we can't read must NOT silently vanish; it resolves to
    # "any" and is flagged UNRESOLVED so no boundary can be proved closed.
    r = _table().resolve_addresses("MYSTERY_OBJECT")
    assert set(r.cidrs) == {"0.0.0.0/0", "::/0"}
    assert r.conditional is True
    assert ConditionalFeature.UNRESOLVED in r.features
    assert r.unresolved == ("MYSTERY_OBJECT",)


def test_fqdn_object_is_conditional():
    t = ObjectTable()
    t.add_address(AddressObject(
        "updates.example.com", conditional=True,
        feature=ConditionalFeature.FQDN))
    r = t.resolve_addresses("updates.example.com")
    assert r.conditional is True
    assert ConditionalFeature.FQDN in r.features


def test_build_rule_propagates_conditional_and_warns():
    t = _table()
    src = t.resolve_addresses("MYSTERY_OBJECT")   # unresolved → conditional
    dst = t.resolve_addresses("APP_TIER")
    svc = t.resolve_service("WEB_PORTS")
    rule, warnings = build_rule(
        rule_id="r1", action=Action.ALLOW, order=10,
        src=src, dst=dst, service=svc, vendor="test", raw_ref="line 1")
    assert rule.conditional is True
    assert any(w.level == WarningLevel.UNRESOLVED for w in warnings)


def test_build_rule_app_id_is_conditional():
    t = _table()
    rule, warnings = build_rule(
        rule_id="r2", action=Action.ALLOW, order=20,
        src=t.resolve_addresses("WEB_TIER"),
        dst=t.resolve_addresses("APP_TIER"),
        service=t.resolve_service("WEB_PORTS"),
        vendor="paloalto", raw_ref="rule allow-web",
        extra_conditional=True, extra_feature=ConditionalFeature.APP_ID)
    assert rule.conditional is True
    assert any(w.level == WarningLevel.CONDITIONAL
               and "application" in w.message for w in warnings)


def test_clean_rule_is_not_conditional():
    t = _table()
    rule, warnings = build_rule(
        rule_id="r3", action=Action.ALLOW, order=30,
        src=t.resolve_addresses("WEB_TIER"),
        dst=t.resolve_addresses("APP_TIER"),
        service=t.resolve_service("WEB_PORTS"),
        vendor="test", raw_ref="line 3")
    assert rule.conditional is False
    assert not any(w.level in (WarningLevel.UNRESOLVED, WarningLevel.CONDITIONAL)
                   for w in warnings)


# -- registry ----------------------------------------------------------------

def test_unknown_vendor_raises_helpfully():
    with pytest.raises(KeyError):
        base.get_parser("no-such-vendor")
