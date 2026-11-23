"""Tests for the topology assembly contract (fabric)."""
from __future__ import annotations

from app.engine.wargame.fabric import (
    EdgeSpec,
    SegmentSpec,
    TopologySpec,
    always_reachable,
    segment_for_ip,
)
from app.engine.wargame.model import EvidenceLabel, NodeRole, PortRange, Proto


def test_segment_to_node():
    node = SegmentSpec("db", ("10.1.0.0/24",), NodeRole.CROWN_JEWEL,
                       reason="cardholder data", jewel_kind="chd").to_node()
    assert node.id == "db"
    assert node.role is NodeRole.CROWN_JEWEL
    assert node.cidrs == ("10.1.0.0/24",)
    assert node.jewel_kind == "chd"


def test_edge_to_edge():
    e = EdgeSpec("a", "b", rule_set_id="fw", port=PortRange.single(Proto.TCP, 443),
                 base_labels=frozenset({EvidenceLabel.OBSERVED})).to_edge()
    assert e.src == "a" and e.dst == "b" and e.rule_set_id == "fw"
    assert EvidenceLabel.OBSERVED in e.base_labels


def test_segment_for_ip_longest_prefix_wins():
    spec = TopologySpec(segments=[
        SegmentSpec("broad", ("10.0.0.0/8",)),
        SegmentSpec("narrow", ("10.1.2.0/24",)),
    ])
    assert segment_for_ip(spec, "10.1.2.5") == "narrow"
    assert segment_for_ip(spec, "10.9.9.9") == "broad"
    assert segment_for_ip(spec, "192.168.0.1") is None
    assert segment_for_ip(spec, "not-an-ip") is None


def test_always_reachable_default():
    assert always_reachable("10.0.0.0/24", "10.1.0.0/24") is True
