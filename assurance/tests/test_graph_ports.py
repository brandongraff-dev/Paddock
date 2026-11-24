import pytest

from paddock_assurance import GraphError, ReachGraph
from paddock_assurance import ports as P

from helpers import edge, graph, node


def test_ports_parse_merge_format():
    assert P.parse_ports("443,80,81-90,85") == ((80, 90), (443, 443))
    assert P.format_ports(P.parse_ports([80, "443", "8000-8100"])) == "80,443,8000-8100"
    assert P.parse_ports(22) == ((22, 22),)


@pytest.mark.parametrize("bad", ["", "0", "70000", "9-1", "abc", True, None, [], "1-", "80;rm"])
def test_ports_reject(bad):
    with pytest.raises(ValueError):
        P.parse_ports(bad)


def test_ports_subtract_intersect_count():
    full = P.parse_ports("1-65535")
    allowed = P.parse_ports("80,443")
    rest = P.subtract(full, allowed)
    assert rest == ((1, 79), (81, 442), (444, 65535))
    assert P.count(rest) == 65535 - 2
    assert P.intersect(P.parse_ports("1-100"), P.parse_ports("50-200")) == ((50, 100),)
    assert P.subtract(P.parse_ports("80"), P.parse_ports("80")) == ()


def test_graph_loader_ok_and_sorted():
    g = graph([node("b"), node("a")], [edge("b", "a"), edge("a", "b")])
    assert [e.src for e in g.edges] == ["a", "b"]
    assert [n.id for n in g.select(None)] == ["a", "b"]


@pytest.mark.parametrize("doc,needle", [
    ([], "object"),
    ({"version": 2}, "version"),
    ({"nodes": [{"id": "a"}, {"id": "a"}]}, "duplicate"),
    ({"nodes": [{"id": "a"}], "edges": [{"src": "a", "dst": "zz"}]}, "existing nodes"),
    ({"nodes": [{"id": "a"}, {"id": "b"}], "edges": [{"src": "a", "dst": "b", "proto": "gre"}]}, "proto"),
    ({"nodes": [{"id": "a"}, {"id": "b"}], "edges": [{"src": "a", "dst": "b", "basis": "vibes"}]}, "basis"),
    ({"nodes": [{"id": "a", "coverage": {"tier": "observed", "observed_at": "2026-12-01T00:00:00"}}]}, "timezone"),
    ({"nodes": [{"id": "a", "coverage": {"tier": "great", "observed_at": "2026-12-01T00:00:00Z"}}]}, "tier"),
    ({"nodes": [{"id": "a"}, {"id": "b"}], "edges": [{"src": "a", "dst": "b", "ports": "0"}]}, "port out of range"),
])
def test_graph_loader_rejects(doc, needle):
    with pytest.raises(GraphError, match=needle):
        ReachGraph.from_dict(doc)


def test_graph_bad_json():
    with pytest.raises(GraphError, match="invalid JSON"):
        ReachGraph.from_json("{nope")
