"""Tests for the Wargame shared data model (pure)."""
from __future__ import annotations

import pytest

from app.engine.wargame.model import (
    Action,
    EvidenceLabel,
    Hop,
    LABEL_STRENGTH,
    PortRange,
    Proto,
    Route,
    Rule,
    RuleSet,
    _ip_in_cidr,
    strongest_label,
    weakest_label,
)


# -- ip / cidr ---------------------------------------------------------------

@pytest.mark.parametrize(
    "ip,cidr,expected",
    [
        ("10.0.0.5", "10.0.0.0/24", True),
        ("10.0.1.5", "10.0.0.0/24", False),
        ("10.0.0.5", "10.0.0.5", True),        # bare ip == /32
        ("10.0.0.6", "10.0.0.5", False),
        ("2001:db8::1", "2001:db8::/32", True),
        ("2001:db9::1", "2001:db8::/32", False),
        ("not-an-ip", "10.0.0.0/24", False),   # garbage never raises
        ("10.0.0.5", "garbage", False),
    ],
)
def test_ip_in_cidr(ip, cidr, expected):
    assert _ip_in_cidr(ip, cidr) is expected


# -- port ranges -------------------------------------------------------------

def test_port_range_contains_and_proto():
    pr = PortRange(Proto.TCP, 5432, 5432)
    assert pr.contains(Proto.TCP, 5432)
    assert not pr.contains(Proto.TCP, 5433)
    assert not pr.contains(Proto.UDP, 5432)
    # ANY proto on either side matches.
    assert PortRange(Proto.ANY, 0, 65535).contains(Proto.TCP, 1)
    assert PortRange.single(Proto.TCP, 22).contains(Proto.ANY, 22)


def test_port_range_rejects_bad_bounds():
    with pytest.raises(ValueError):
        PortRange(Proto.TCP, 100, 10)
    with pytest.raises(ValueError):
        PortRange(Proto.TCP, -1, 5)
    with pytest.raises(ValueError):
        PortRange(Proto.TCP, 0, 70000)


# -- rule matching -----------------------------------------------------------

def test_rule_matches_src_dst_port():
    r = Rule(
        id="r1",
        action=Action.ALLOW,
        order=10,
        src_cidrs=("10.1.0.0/16",),
        dst_cidrs=("10.2.0.0/16",),
        ports=(PortRange.single(Proto.TCP, 443),),
    )
    assert r.matches("10.1.2.3", "10.2.3.4", Proto.TCP, 443)
    assert not r.matches("10.9.2.3", "10.2.3.4", Proto.TCP, 443)   # wrong src
    assert not r.matches("10.1.2.3", "10.9.3.4", Proto.TCP, 443)   # wrong dst
    assert not r.matches("10.1.2.3", "10.2.3.4", Proto.TCP, 80)    # wrong port


# -- evidence ladder ---------------------------------------------------------

def test_label_strength_is_total_and_ordered():
    # Every label has a strength, and the "weak" ones are genuinely weakest.
    assert set(LABEL_STRENGTH) == set(EvidenceLabel)
    assert LABEL_STRENGTH[EvidenceLabel.UNKNOWN] < LABEL_STRENGTH[EvidenceLabel.INFERRED]
    assert LABEL_STRENGTH[EvidenceLabel.INFERRED] < LABEL_STRENGTH[EvidenceLabel.CONDITIONAL]
    assert LABEL_STRENGTH[EvidenceLabel.CONDITIONAL] < LABEL_STRENGTH[EvidenceLabel.PROVED_CONFIG]


def test_weakest_and_strongest():
    s = {EvidenceLabel.PROVED_CONFIG, EvidenceLabel.OBSERVED, EvidenceLabel.INFERRED}
    assert weakest_label(s) == EvidenceLabel.INFERRED
    assert strongest_label(s) == EvidenceLabel.OBSERVED
    assert weakest_label(set()) == EvidenceLabel.UNKNOWN
    assert strongest_label(frozenset()) == EvidenceLabel.UNKNOWN


# -- route weakest-hop semantics --------------------------------------------

def test_route_is_as_strong_as_weakest_hop():
    route = Route(
        entry="guest_wifi",
        jewel="payments_db",
        hops=[
            Hop("guest_wifi", "fridge", frozenset({EvidenceLabel.OBSERVED})),
            Hop("fridge", "pos", frozenset({EvidenceLabel.PROVED_CONFIG})),
            Hop("pos", "payments_db", frozenset({EvidenceLabel.INFERRED})),
        ],
    )
    assert route.weakest_label == EvidenceLabel.INFERRED
    assert route.length == 3
    assert route.pair == ("guest_wifi", "payments_db")


def test_route_fix_elements_is_union():
    route = Route(
        entry="e",
        jewel="j",
        hops=[
            Hop("e", "m", frozenset({EvidenceLabel.PROVED_CONFIG}),
                fix_candidate_ids=frozenset({"rule_a"})),
            Hop("m", "j", frozenset({EvidenceLabel.PROVED_CONFIG}),
                fix_candidate_ids=frozenset({"rule_b", "rule_c"})),
        ],
    )
    assert route.fix_elements == frozenset({"rule_a", "rule_b", "rule_c"})


def test_empty_route_is_unknown():
    assert Route("e", "j", []).weakest_label == EvidenceLabel.UNKNOWN


# -- rule/ruleset smoke ------------------------------------------------------

def test_ruleset_defaults_to_deny():
    rs = RuleSet(id="fw1", rules=[])
    assert rs.default_action == Action.DENY
