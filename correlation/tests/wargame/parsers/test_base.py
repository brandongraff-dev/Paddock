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
    # a cycle means the config is not what we think: conditional any
    assert r.conditional and "0.0.0.0/0" in r.cidrs


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


# -- user-defined objects win over same-named built-ins ----------------------

def test_user_service_object_shadows_wellknown_name():
    # A config that defines a service group named "DNS" (tcp+udp/53) must
    # win over the generic WELL_KNOWN_SERVICES "dns" (udp-only).
    t = ObjectTable()
    t.add_service(ServiceObject("DNS", ports=(
        PortRange(Proto.TCP, 53, 53), PortRange(Proto.UDP, 53, 53))))
    r = t.resolve_service("DNS")
    assert set(r.ports) == {PortRange(Proto.TCP, 53, 53), PortRange(Proto.UDP, 53, 53)}
    assert r.conditional is False
    # An undefined well-known name still falls back to the built-in.
    assert ObjectTable().resolve_service("ssh").ports == (PortRange(Proto.TCP, 22, 22),)


def test_user_address_object_shadows_literal_lookalike_is_not_an_issue_but_name_wins():
    # A user object is resolved from the table first; a literal only when no
    # object has that name.
    t = ObjectTable()
    t.add_address(AddressObject("corp", cidrs=("10.7.0.0/16",)))
    assert t.resolve_addresses("corp").cidrs == ("10.7.0.0/16",)
    assert t.resolve_addresses("10.7.0.0/16").cidrs == ("10.7.0.0/16",)


# ---------------------------------------------------------------------------
# Audit regressions
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "token,expected",
    [
        ("0.0.0.0/0", ["0.0.0.0/0"]),                 # IPv4 only, not ::/0
        ("0.0.0.0 0.0.0.0", ["0.0.0.0/0"]),
        ("any4", ["0.0.0.0/0"]),
        ("any6", ["::/0"]),
        ("::/0", ["::/0"]),
        ("10.0.0.5/24", ["10.0.0.0/24"]),             # host bits masked
        ("10.0.0.5 255.255.255.0", ["10.0.0.0/24"]),
        ("10.0.0.1 - 10.0.0.2", ["10.0.0.1/32", "10.0.0.2/32"]),
        ("10.0.0.0-10.0.1.255", ["10.0.0.0/23"]),
        ("10.0.0.1-10.0.0.6", ["10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/31", "10.0.0.6/32"]),
        ("2001:db8::1-2001:db8::3", ["2001:db8::1/128", "2001:db8::2/127"]),
        ("2001:db8:: 32", ["2001:db8::/32"]),
    ],
)
def test_normalize_cidrs_edge_cases(token, expected):
    assert normalize_cidrs(token) == expected


@pytest.mark.parametrize("junk", [
    "10.0.0.0/33", "300.1.1.1", "10.0.0.9-10.0.0.1", "10.0.0.1-2001:db8::1",
    "10.0.0.0 255.0.255.0", "2001:db8:: 255.255.0.0", "a b c", "10.0.0.1-",
    "10.0.0.0 255.255.255.0 extra", None, "",
])
def test_normalize_cidrs_garbage_is_none(junk):
    assert normalize_cidrs(junk) is None


def test_normalize_netmask_style():
    # netmask vendors (ASA, FortiOS): a zero mask is /0, never a host
    assert normalize_cidrs("10.1.1.0 0.0.0.0", mask_style="netmask") == ["0.0.0.0/0"]
    assert normalize_cidrs("10.0.0.0 0.0.0.255", mask_style="netmask") is None
    assert normalize_cidrs("10.0.0.0 0.0.0.255", mask_style="wildcard") == ["10.0.0.0/24"]
    assert normalize_cidrs("10.0.0.0 255.255.255.0", mask_style="wildcard") is None


def test_port_range_never_raises_on_out_of_range():
    assert base.port_range(Proto.TCP, 70000) == PortRange(Proto.TCP, 65535, 65535)
    assert base.port_range(Proto.TCP, -5, 10) == PortRange(Proto.TCP, 0, 10)
    assert base.port_range(Proto.TCP, 2000, 1000) == PortRange(Proto.TCP, 1000, 2000)
    assert base.port_range(Proto.UDP, 0, 65535) == PortRange(Proto.UDP, 0, 65535)


def test_port_from_name_edges():
    assert port_from_name("0") == 0
    assert port_from_name("65535") == 65535
    assert port_from_name("65536") is None
    assert port_from_name("-1") is None
    assert port_from_name("icmp") is None          # not a port


def test_proto_is_exact():
    for tok in ("tcp", "udp", "icmp", "icmp6", "6", "17", "1", "58", "ip", "any", "-1"):
        assert base.proto_is_exact(tok), tok
    for tok in ("gre", "47", "esp", "sctp", "nonsense"):
        assert not base.proto_is_exact(tok), tok
    assert proto_from("icmp6") is Proto.ICMP


def test_depth_guard_is_conditional_any():
    t = ObjectTable()
    for i in range(40):
        t.add_address(AddressObject(f"G{i}", members=(f"G{i + 1}",)))
    t.add_address(AddressObject("G40", cidrs=("10.0.0.0/8",)))
    r = t.resolve_addresses("G0")
    assert r.conditional and "0.0.0.0/0" in r.cidrs


def test_empty_group_is_conditional_any_not_clean_any():
    t = ObjectTable()
    t.add_address(AddressObject("EMPTY"))
    t.add_service(ServiceObject("NOSVC"))
    r = t.resolve_addresses("EMPTY")
    assert r.conditional and set(r.cidrs) == {"0.0.0.0/0", "::/0"}
    s = t.resolve_service("NOSVC")
    assert s.conditional and s.ports == (PortRange.any(),)


def test_partially_read_conditional_object_still_opens_wide():
    # An object with an unreadable member must not resolve to only the part
    # we could read (that narrows an allow).
    t = ObjectTable()
    t.add_address(AddressObject("PART", cidrs=("10.0.0.0/24",), conditional=True,
                                feature=ConditionalFeature.UNRESOLVED))
    r = t.resolve_addresses("PART")
    assert r.conditional and "0.0.0.0/0" in r.cidrs and "10.0.0.0/24" in r.cidrs
    # a NAT (VIP) object is exactly its addresses, just flagged
    t.add_address(AddressObject("VIP", cidrs=("203.0.113.1/32", "10.0.0.1/32"),
                                conditional=True, feature=ConditionalFeature.NAT))
    v = t.resolve_addresses("VIP")
    assert v.conditional and set(v.cidrs) == {"203.0.113.1/32", "10.0.0.1/32"}


def test_complement_and_exclude():
    assert base.complement_cidrs(["0.0.0.0/0", "::/0"]) == []
    comp = base.complement_cidrs(["10.0.0.0/8"], (4,))
    assert "10.0.0.0/8" not in comp and "11.0.0.0/8" in comp
    assert base.cidrs_overlap(comp, ["9.255.255.255/32"])
    assert not base.cidrs_overlap(comp, ["10.1.2.3/32"])
    assert "::/0" in base.complement_cidrs(["10.0.0.0/8"])
    assert base.exclude_cidrs(["10.0.0.0/23"], ["10.0.1.0/24"]) == ["10.0.0.0/24"]
    assert base.exclude_cidrs(["10.0.0.0/24"], ["10.0.0.0/16"]) == []
    with pytest.raises(ValueError):
        base.exclude_cidrs(["garbage"], [])


def test_build_rule_empty_sides_are_conditional_any():
    rule, warnings = build_rule(
        rule_id="r", action=Action.DENY, order=1,
        src=ResolvedAddresses(()), dst=ResolvedAddresses(("10.0.0.0/8",)),
        service=ResolvedService(()), vendor="t")
    assert rule.conditional
    assert rule.src_cidrs == ("0.0.0.0/0", "::/0") and rule.ports == (PortRange.any(),)
    assert any(w.level == WarningLevel.UNRESOLVED for w in warnings)


def test_build_rule_extra_features_each_warn():
    t = _table()
    rule, warnings = build_rule(
        rule_id="r", action=Action.ALLOW, order=1,
        src=t.resolve_addresses("WEB_TIER"), dst=t.resolve_addresses("APP_TIER"),
        service=t.resolve_service("WEB_PORTS"), vendor="t",
        extra_features=(ConditionalFeature.SCHEDULE, ConditionalFeature.PARTIAL_MATCH))
    assert rule.conditional
    msgs = [w.message for w in warnings if w.level == WarningLevel.CONDITIONAL]
    assert len(msgs) == 2


def test_apply_nat_overapprox():
    from app.engine.wargame.model import Rule
    r = Rule("r", Action.ALLOW, 1, ("0.0.0.0/0",), ("10.0.0.5/32",))
    nr, changed = base.apply_nat_overapprox(r, [(("10.0.0.5/32",), ("203.0.113.5/32",))])
    assert changed and nr.conditional and "203.0.113.5/32" in nr.dst_cidrs
    # an "any" side already covers the mapped address: unchanged, not flagged
    r2 = Rule("r2", Action.ALLOW, 1, ("0.0.0.0/0",), ("0.0.0.0/0",))
    nr2, changed2 = base.apply_nat_overapprox(r2, [(("10.0.0.5/32",), ("203.0.113.5/32",))])
    assert not changed2 and not nr2.conditional
