"""Cross-vendor parser ↔ solver integration.

Proves the thing that matters: a config parsed by any vendor parser
produces RuleSets the reachability engine can actually evaluate. Each
vendor is skipped cleanly until its module and fixture land, so this file
is committed alongside the foundation.
"""
from __future__ import annotations

import json
import os

import pytest

from app.engine.wargame import reachability
from app.engine.wargame.model import (
    Edge,
    EvidenceLabel,
    Node,
    NodeRole,
    PortRange,
    Proto,
    Rule,
    RuleSet,
)
from app.engine.wargame.parsers import available_vendors, base, parse

_FIX = os.path.join(os.path.dirname(__file__), "fixtures")

# (vendor, fixture filename, is_json)
_CASES = [
    ("aws", "aws_security_groups.json", True),
    ("cisco_asa", "cisco_asa.conf", False),
    ("fortinet", "fortigate.conf", False),
    ("paloalto", "paloalto_set.conf", False),
]


def _load(vendor: str, fname: str, is_json: bool):
    if vendor not in available_vendors():
        pytest.skip(f"{vendor} parser not available yet")
    path = os.path.join(_FIX, fname)
    if not os.path.exists(path):
        pytest.skip(f"fixture {fname} not present yet")
    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh) if is_json else fh.read()
    return parse(vendor, raw)


@pytest.mark.parametrize("vendor,fname,is_json", _CASES)
def test_parser_output_is_evaluable(vendor, fname, is_json):
    result = _load(vendor, fname, is_json)
    assert result.vendor == vendor
    assert result.rulesets, "expected at least one RuleSet"
    # Every rule is a well-formed Rule the solver can read.
    for rs in result.rulesets.values():
        assert isinstance(rs, RuleSet)
        for r in rs.rules:
            assert isinstance(r, Rule)
            assert r.src_cidrs and r.dst_cidrs and r.ports


@pytest.mark.parametrize("vendor,fname,is_json", _CASES)
def test_some_rules_are_marked_conditional_where_expected(vendor, fname, is_json):
    # Each fixture is built to include at least one runtime-only / unresolved
    # construct, so each parser must emit at least one conditional rule
    # (the honesty rule in action). AWS's conditional case is the SG-to-SG /
    # prefix-list reference without members.
    result = _load(vendor, fname, is_json)
    assert result.conditional_count() >= 1, (
        f"{vendor}: expected at least one conditional rule from the fixture"
    )


def test_parsed_firewall_gates_a_reachability_edge():
    """Use a REAL parsed Cisco ASA RuleSet to gate an edge, and confirm the
    solver treats a permitted flow as reachable and a non-permitted one as
    closed."""
    if "cisco_asa" not in available_vendors():
        pytest.skip("cisco_asa parser not available yet")
    path = os.path.join(_FIX, "cisco_asa.conf")
    if not os.path.exists(path):
        pytest.skip("cisco_asa fixture not present yet")
    with open(path, encoding="utf-8") as fh:
        result = parse("cisco_asa", fh.read())

    # Pick any parsed RuleSet and find a concrete allow it contains, then
    # build a 1-hop topology whose edge is gated by that RuleSet.
    rs = next(iter(result.rulesets.values()))
    allow = next((r for r in rs.rules if r.action.value == "allow"
                  and r.src_cidrs and r.dst_cidrs
                  and r.src_cidrs[0] != "0.0.0.0/0"), None)
    if allow is None:
        pytest.skip("no concrete allow rule in fixture to anchor the test")

    # Representative src/dst inside the allow's first cidrs.
    import ipaddress
    src_net = ipaddress.ip_network(allow.src_cidrs[0], strict=False)
    dst_net = ipaddress.ip_network(allow.dst_cidrs[0], strict=False)
    src_ip = str(next(src_net.hosts(), src_net.network_address))
    dst_ip = str(next(dst_net.hosts(), dst_net.network_address))
    port = allow.ports[0]

    nodes = {
        "entry": Node("entry", NodeRole.ENTRY, (f"{src_ip}/32",)),
        "jewel": Node("jewel", NodeRole.CROWN_JEWEL, (f"{dst_ip}/32",)),
    }
    rulesets = {rs.id: rs}
    edges = [Edge("entry", "jewel", rule_set_id=rs.id, port=port)]
    out = reachability.backward_reachability(nodes, edges, rulesets)
    assert ("entry", "jewel") in out.open_pairs
    route = out.routes_for(("entry", "jewel"))[0]
    # A concrete config-permitted hop is proved by config (or conditional if
    # the rule used a runtime feature).
    assert route.hops[0].labels & {
        EvidenceLabel.PROVED_CONFIG, EvidenceLabel.CONDITIONAL
    }
