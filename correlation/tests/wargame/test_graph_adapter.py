"""Tests for the legacy-asset-graph → Wargame Environment adapter.

Pure: no database. Builds a small graph dict by hand (the shape
:meth:`AttackPathEngine._load_graph` returns) and checks node roles, the
undirected→two-directed edge expansion, the honest all-``INFERRED`` labelling,
that reachability finds an open (entry, jewel) route whose weakest label is
inferred, and determinism.
"""
from __future__ import annotations

import ipaddress

from app.engine.wargame.environment import Environment
from app.engine.wargame.graph_adapter import environment_from_graph
from app.engine.wargame.model import EvidenceLabel, NodeRole


def _graph() -> dict:
    """A 4-asset graph: an internet-facing endpoint (source) → an ipv4 host →
    a crown-jewel DB (via metadata.crown_jewel) plus a technology data store.

        endpoint(entry) -- ipv4 -- db(jewel)
                              |
                           tech(mongodb data_store, also a jewel)
    """
    assets = {
        "a-endpoint": {
            "id": "a-endpoint",
            "kind": "endpoint",
            "value": "https://app.example.com/login",
            "metadata": {},
        },
        "a-ip": {
            "id": "a-ip",
            "kind": "ipv4",
            "value": "10.0.0.5",
            "metadata": {},
        },
        "a-db": {
            "id": "a-db",
            "kind": "technology",
            "value": "internal-service",
            "metadata": {"crown_jewel": True},
        },
        "a-mongo": {
            "id": "a-mongo",
            "kind": "technology",
            "value": "MongoDB 5.0",
            "metadata": {},
        },
    }
    # Undirected adjacency: sorted neighbour id lists, mirrored both ways.
    adj = {
        "a-endpoint": ["a-ip"],
        "a-ip": ["a-db", "a-endpoint", "a-mongo"],
        "a-db": ["a-ip"],
        "a-mongo": ["a-ip"],
    }
    return {
        "assets": assets,
        "adj": adj,
        "edge_kind": {},
        "findings_by_asset": {},
        "public_nets": (ipaddress.ip_network("0.0.0.0/0"),),
    }


def test_node_roles():
    env = environment_from_graph(_graph())
    assert env.nodes["a-endpoint"].role is NodeRole.ENTRY
    assert env.nodes["a-endpoint"].reason == "endpoint"
    # crown_jewel via metadata, and a data-store technology, are both jewels.
    assert env.nodes["a-db"].role is NodeRole.CROWN_JEWEL
    assert env.nodes["a-db"].jewel_kind == "sensitive"
    assert env.nodes["a-mongo"].role is NodeRole.CROWN_JEWEL
    assert env.nodes["a-mongo"].jewel_kind == "data_store"
    # the plain ipv4 host is an intermediate
    assert env.nodes["a-ip"].role is NodeRole.INTERMEDIATE
    assert env.nodes["a-ip"].reason == ""


def test_ipv4_node_gets_host_cidr():
    env = environment_from_graph(_graph())
    assert env.nodes["a-ip"].cidrs == ("10.0.0.5/32",)
    # non-address kinds carry no cidrs
    assert env.nodes["a-endpoint"].cidrs == ()
    assert env.nodes["a-db"].cidrs == ()


def test_ipv6_node_gets_128_cidr():
    g = _graph()
    g["assets"]["a-ip"]["kind"] = "ipv6"
    g["assets"]["a-ip"]["value"] = "2001:db8::1"
    env = environment_from_graph(g)
    assert env.nodes["a-ip"].cidrs == ("2001:db8::1/128",)


def test_edges_are_bidirectional_inferred_ungoverned():
    env = environment_from_graph(_graph())
    # 3 undirected links → 6 directed edges.
    assert len(env.edges) == 6
    for e in env.edges:
        assert e.rule_set_id is None
        assert e.base_labels == frozenset({EvidenceLabel.INFERRED})
        assert e.fix_candidate_id is not None

    # every undirected pair appears in both directions
    directed = {(e.src, e.dst) for e in env.edges}
    assert ("a-endpoint", "a-ip") in directed
    assert ("a-ip", "a-endpoint") in directed
    assert ("a-ip", "a-db") in directed
    assert ("a-db", "a-ip") in directed

    # both directions of a link share one fix candidate id
    fwd = env.find_edge("a-endpoint", "a-ip")
    rev = env.find_edge("a-ip", "a-endpoint")
    assert fwd.fix_candidate_id == rev.fix_candidate_id == "edge:a-endpoint->a-ip"


def test_no_rulesets():
    env = environment_from_graph(_graph())
    assert env.rulesets == {}


def test_reachability_finds_inferred_open_route():
    env = environment_from_graph(_graph())
    rr = env.reachability()
    # endpoint entry reaches the crown-jewel DB.
    assert ("a-endpoint", "a-db") in rr.open_pairs
    routes = rr.routes_for(("a-endpoint", "a-db"))
    assert routes
    # the whole model is inferred, so the route is only inferred-strong.
    assert routes[0].weakest_label is EvidenceLabel.INFERRED
    for r in routes:
        assert r.weakest_label is EvidenceLabel.INFERRED


def test_no_source_or_no_jewel_yields_no_routes():
    g = _graph()
    # drop the jewel flags → no crown jewels at all
    g["assets"]["a-db"]["metadata"] = {}
    g["assets"]["a-mongo"]["value"] = "nginx"
    env = environment_from_graph(g)
    rr = env.reachability()
    assert rr.open_pairs == set()


def test_deterministic():
    g = _graph()
    e1 = environment_from_graph(g)
    e2 = environment_from_graph(g)
    assert list(e1.nodes.keys()) == list(e2.nodes.keys())
    assert [(e.src, e.dst, e.fix_candidate_id) for e in e1.edges] == [
        (e.src, e.dst, e.fix_candidate_id) for e in e2.edges
    ]
    # edge ordering is stable and sorted by the unordered pair
    seq = [(e.src, e.dst) for e in e1.edges]
    assert seq == [
        ("a-db", "a-ip"),
        ("a-ip", "a-db"),
        ("a-endpoint", "a-ip"),
        ("a-ip", "a-endpoint"),
        ("a-ip", "a-mongo"),
        ("a-mongo", "a-ip"),
    ]


def test_run_wargame_scoped_is_importable():
    """The endpoint wiring exists and is importable (no DB work here)."""
    from app.main import ComputeWargameResponse, Service

    assert hasattr(Service, "run_wargame_scoped")
    # response model has the documented fields
    assert set(ComputeWargameResponse.model_fields) == {
        "assessments",
        "routes",
        "elapsed_ms",
    }


def test_adapter_never_fabricates_proved_config():
    """Honesty invariant: no hop is ever stronger than INFERRED."""
    env = environment_from_graph(_graph())
    rr = env.reachability()
    for route in rr.routes:
        for hop in route.hops:
            assert hop.labels == frozenset({EvidenceLabel.INFERRED})
