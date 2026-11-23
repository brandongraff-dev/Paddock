"""Tests for the topology assembler (:mod:`app.engine.wargame.topology`).

Covers segment→node assembly, declared-edge preservation, binding auto-wire,
observed-flow drift, route-reachability pruning, endpoint validation, the
identity/ingest merge of extra nodes and edges, that the assembled
environment is searchable, and one end-to-end pass that parses the committed
Cisco ASA fixture and assembles an edge gated by the real ACL.
"""
from __future__ import annotations

from pathlib import Path

from app.engine.wargame.fabric import (
    EdgeSpec,
    SegmentSpec,
    TopologyResult,
    TopologySpec,
)
from app.engine.wargame.model import (
    Action,
    Edge,
    EvidenceLabel,
    Flow,
    Node,
    NodeRole,
    PortRange,
    Proto,
    Rule,
    RuleSet,
)
from app.engine.wargame.parsers import parse
from app.engine.wargame.parsers.base import RuleSetBinding
from app.engine.wargame.topology import build_topology

ASA_FIXTURE = (
    Path(__file__).parent / "parsers" / "fixtures" / "cisco_asa.conf"
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _allow_all(rid: str) -> RuleSet:
    """A rule set that permits any flow (so a governed edge is traversable)."""
    return RuleSet(
        rid,
        [Rule(f"{rid}:allow", Action.ALLOW, 1,
              ("0.0.0.0/0",), ("0.0.0.0/0",), (PortRange.any(),))],
        default_action=Action.DENY,
    )


def _messages(result: TopologyResult) -> list[str]:
    return [w.message for w in result.warnings]


def _real_flow(src: str, dst: str) -> Flow:
    return Flow(src_ip=src, dst_ip=dst, proto=Proto.TCP, dst_port=443,
                handshake_completed=True)


# ---------------------------------------------------------------------------
# 1. segments become nodes
# ---------------------------------------------------------------------------

def test_segments_become_nodes():
    spec = TopologySpec(segments=[
        SegmentSpec("entry", ("10.0.0.0/24",), NodeRole.ENTRY),
        SegmentSpec("jewel", ("10.1.0.0/24",), NodeRole.CROWN_JEWEL,
                    jewel_kind="chd"),
    ])
    env = build_topology(spec, {}).environment
    assert set(env.nodes) == {"entry", "jewel"}
    assert env.nodes["entry"].role is NodeRole.ENTRY
    assert env.nodes["jewel"].role is NodeRole.CROWN_JEWEL
    assert env.nodes["jewel"].cidrs == ("10.1.0.0/24",)


# ---------------------------------------------------------------------------
# 2. a declared governed edge is preserved and its ruleset attached
# ---------------------------------------------------------------------------

def test_declared_governed_edge_preserved_with_ruleset():
    spec = TopologySpec(
        segments=[
            SegmentSpec("entry", ("10.0.0.0/24",), NodeRole.ENTRY),
            SegmentSpec("jewel", ("10.1.0.0/24",), NodeRole.CROWN_JEWEL),
        ],
        edges=[EdgeSpec("entry", "jewel", rule_set_id="fw")],
    )
    result = build_topology(spec, {"fw": _allow_all("fw")})
    env = result.environment
    edge = env.find_edge("entry", "jewel")
    assert edge is not None and edge.rule_set_id == "fw"
    assert "fw" in env.rulesets
    assert ("entry", "jewel") in env.reachability().open_pairs
    assert result.discovered_edges == []


def test_edge_referencing_unknown_ruleset_warns_but_is_kept():
    spec = TopologySpec(
        segments=[
            SegmentSpec("a", ("10.0.0.0/24",), NodeRole.ENTRY),
            SegmentSpec("b", ("10.1.0.0/24",), NodeRole.CROWN_JEWEL),
        ],
        edges=[EdgeSpec("a", "b", rule_set_id="ghost")],
    )
    result = build_topology(spec, {})
    assert result.environment.find_edge("a", "b") is not None
    assert any("unknown rule set" in m for m in _messages(result))
    # A governed edge whose set is missing is non-traversable in the solver.
    assert ("a", "b") not in result.environment.reachability().open_pairs


# ---------------------------------------------------------------------------
# 3. binding auto-wire
# ---------------------------------------------------------------------------

def test_binding_autowire_creates_discovered_governed_edge():
    spec = TopologySpec(
        segments=[
            SegmentSpec("a", ("10.0.0.0/24",), NodeRole.ENTRY),
            SegmentSpec("b", ("10.1.0.0/24",), NodeRole.CROWN_JEWEL),
        ],
        zone_to_segment={"zoneA": "a", "zoneB": "b"},
    )
    binding = RuleSetBinding(ruleset_id="z", src_zone="zoneA", dst_zone="zoneB")
    result = build_topology(spec, {"z": _allow_all("z")}, bindings=[binding])

    assert len(result.discovered_edges) == 1
    wired = result.discovered_edges[0]
    assert (wired.src, wired.dst, wired.rule_set_id) == ("a", "b", "z")
    assert result.environment.find_edge("a", "b", "z") is not None
    assert any("auto-wired governed edge" in m for m in _messages(result))
    assert ("a", "b") in result.environment.reachability().open_pairs


def test_binding_autowire_skipped_when_declared_edge_exists():
    spec = TopologySpec(
        segments=[
            SegmentSpec("a", ("10.0.0.0/24",), NodeRole.ENTRY),
            SegmentSpec("b", ("10.1.0.0/24",), NodeRole.CROWN_JEWEL),
        ],
        edges=[EdgeSpec("a", "b", rule_set_id="z")],
        zone_to_segment={"zoneA": "a", "zoneB": "b"},
    )
    binding = RuleSetBinding(ruleset_id="z", src_zone="zoneA", dst_zone="zoneB")
    result = build_topology(spec, {"z": _allow_all("z")}, bindings=[binding])
    assert result.discovered_edges == []
    assert not any("auto-wired" in m for m in _messages(result))


def test_binding_skipped_silently_when_endpoint_unmapped():
    spec = TopologySpec(
        segments=[SegmentSpec("a", ("10.0.0.0/24",))],
        zone_to_segment={"zoneA": "a"},  # zoneB maps to nothing
    )
    binding = RuleSetBinding(ruleset_id="z", src_zone="zoneA", dst_zone="zoneB")
    result = build_topology(spec, {"z": _allow_all("z")}, bindings=[binding])
    assert result.discovered_edges == []
    assert result.warnings == []


# ---------------------------------------------------------------------------
# 4. observed flows surface drift
# ---------------------------------------------------------------------------

def _two_seg_spec(edge: bool = False) -> TopologySpec:
    edges = [EdgeSpec("e", "j")] if edge else []
    return TopologySpec(
        segments=[
            SegmentSpec("e", ("10.0.0.0/24",), NodeRole.ENTRY),
            SegmentSpec("j", ("10.1.0.0/24",), NodeRole.CROWN_JEWEL),
        ],
        edges=edges,
    )


def test_observed_cross_segment_flow_discovers_observed_edge():
    result = build_topology(
        _two_seg_spec(edge=False), {},
        observed_flows=[_real_flow("10.0.0.5", "10.1.0.9")],
    )
    assert len(result.discovered_edges) == 1
    edge = result.discovered_edges[0]
    assert (edge.src, edge.dst) == ("e", "j")
    assert edge.rule_set_id is None
    assert EvidenceLabel.OBSERVED in edge.base_labels
    assert any("observed flow not explained" in m for m in _messages(result))


def test_dropped_syn_flow_is_not_evidence():
    dropped = Flow(src_ip="10.0.0.5", dst_ip="10.1.0.9", proto=Proto.TCP,
                   dst_port=443)  # no handshake / dst-side / allow-log
    result = build_topology(_two_seg_spec(edge=False), {},
                            observed_flows=[dropped])
    assert result.discovered_edges == []
    assert result.warnings == []


def test_observed_flow_merges_into_existing_edge():
    result = build_topology(
        _two_seg_spec(edge=True), {},
        observed_flows=[_real_flow("10.0.0.5", "10.1.0.9")],
    )
    # Enriches the declared edge; does not surface a discovered edge/warning.
    assert result.discovered_edges == []
    assert result.warnings == []
    edge = result.environment.find_edge("e", "j")
    assert EvidenceLabel.OBSERVED in edge.base_labels


# ---------------------------------------------------------------------------
# 5. route reachability prunes edges with no underlying route
# ---------------------------------------------------------------------------

def test_route_reachable_false_drops_edge():
    spec = TopologySpec(
        segments=[
            SegmentSpec("a", ("10.0.0.0/24",), NodeRole.ENTRY),
            SegmentSpec("b", ("10.1.0.0/24",), NodeRole.CROWN_JEWEL),
        ],
        edges=[EdgeSpec("a", "b")],
    )
    dropped = build_topology(spec, {}, route_reachable=lambda s, d: False)
    assert dropped.environment.find_edge("a", "b") is None
    assert any("no route between a and b" in m for m in _messages(dropped))

    kept = build_topology(spec, {}, route_reachable=lambda s, d: True)
    assert kept.environment.find_edge("a", "b") is not None
    assert _messages(kept) == []


# ---------------------------------------------------------------------------
# 6. endpoint validation
# ---------------------------------------------------------------------------

def test_unknown_edge_endpoint_warns_and_skips():
    spec = TopologySpec(
        segments=[SegmentSpec("a", ("10.0.0.0/24",))],
        edges=[EdgeSpec("a", "ghost")],
    )
    result = build_topology(spec, {})
    assert result.environment.edges == []
    assert any("edge endpoint unknown" in m for m in _messages(result))


# ---------------------------------------------------------------------------
# 7. extra nodes / edges merged (identity + ingest)
# ---------------------------------------------------------------------------

def test_extra_nodes_and_edges_merged():
    spec = TopologySpec(segments=[
        SegmentSpec("entry", ("10.0.0.0/24",), NodeRole.ENTRY),
    ])
    extra_node = Node("jewel", NodeRole.CROWN_JEWEL, ("10.1.0.0/24",))
    result = build_topology(
        spec, {},
        extra_nodes=[extra_node],
        extra_edges=[Edge("entry", "jewel")],
    )
    env = result.environment
    assert "jewel" in env.nodes
    assert env.find_edge("entry", "jewel") is not None
    # extra edge to an unknown node warns and is skipped.
    result2 = build_topology(spec, {}, extra_edges=[Edge("entry", "nowhere")])
    assert result2.environment.edges == []
    assert any("extra edge endpoint unknown" in m for m in _messages(result2))


def test_extra_node_collision_warns_and_wins():
    spec = TopologySpec(segments=[
        SegmentSpec("x", ("10.0.0.0/24",), NodeRole.INTERMEDIATE),
    ])
    winner = Node("x", NodeRole.CROWN_JEWEL, ("10.9.0.0/24",))
    result = build_topology(spec, {}, extra_nodes=[winner])
    assert result.environment.nodes["x"].role is NodeRole.CROWN_JEWEL
    assert any("overrides declared segment" in m for m in _messages(result))


# ---------------------------------------------------------------------------
# 8. the assembled environment is searchable end to end
# ---------------------------------------------------------------------------

def test_reachability_finds_expected_open_pair():
    spec = TopologySpec(
        segments=[
            SegmentSpec("entry", ("10.0.0.0/24",), NodeRole.ENTRY),
            SegmentSpec("mid", ("10.1.0.0/24",), NodeRole.INTERMEDIATE),
            SegmentSpec("jewel", ("10.2.0.0/24",), NodeRole.CROWN_JEWEL),
        ],
        edges=[
            EdgeSpec("entry", "mid", rule_set_id="fw1"),
            EdgeSpec("mid", "jewel", rule_set_id="fw2"),
        ],
    )
    result = build_topology(
        spec, {"fw1": _allow_all("fw1"), "fw2": _allow_all("fw2")})
    assert ("entry", "jewel") in result.environment.reachability().open_pairs


# ---------------------------------------------------------------------------
# integration: parse the committed ASA fixture and assemble it
# ---------------------------------------------------------------------------

def test_integration_parse_asa_and_assemble():
    parsed = parse("cisco_asa", ASA_FIXTURE.read_text())
    assert "OUTSIDE_IN" in parsed.rulesets

    # Declare two segments whose addresses the ACL references: the partner
    # range on the outside and the DMZ web server (crown jewel).
    spec = TopologySpec(
        segments=[
            SegmentSpec("outside", ("198.51.100.0/24",), NodeRole.ENTRY,
                        reason="partner / internet edge"),
            SegmentSpec("web", ("10.10.1.10/32",), NodeRole.CROWN_JEWEL,
                        jewel_kind="dmz web server"),
        ],
        edges=[EdgeSpec("outside", "web", rule_set_id="OUTSIDE_IN",
                        port=PortRange.single(Proto.TCP, 443))],
    )
    result = build_topology(spec, parsed.rulesets)
    env = result.environment

    edge = env.find_edge("outside", "web")
    assert edge is not None and edge.rule_set_id == "OUTSIDE_IN"
    assert env.rulesets["OUTSIDE_IN"].rules  # the parsed ACL is attached

    # The parsed ACL gates the edge, and reachability is computable over it.
    decision = env.boundary_decision(
        "outside", "web", PortRange.single(Proto.TCP, 443))
    assert decision.allowed is True
    assert ("outside", "web") in env.reachability().open_pairs
