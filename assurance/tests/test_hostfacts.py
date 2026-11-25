"""``nodes[].facts``: strict loading of host facts into the graph (the P1 hardening style)."""
from __future__ import annotations

import copy
import datetime as dt

import pytest

from paddock_assurance import GraphError, ReachGraph
from paddock_assurance import hostfacts as HFX
from tests.hostfix import FRESH, fact, good_facts, hgraph, hnode, sshd


def load(facts, **node):
    return ReachGraph.from_dict({"version": 1, "nodes": [dict(hnode("h", facts), **node)], "edges": []})


def test_loads_and_exposes_frozen_host_facts():
    g = hgraph(hnode("web-1", good_facts()))
    h = g.nodes["web-1"].host
    assert h is not None and len(h) == 4
    f = h.get("sshd")
    assert f.status == "ok" and f.tier.value == "configured" and f.signed is True
    assert f.observed_at == dt.datetime(2026, 12, 1, 8, 30, tzinfo=dt.timezone.utc)
    assert (f.key_id, f.seq, f.evidence_ref, f.source) == ("0f3a9c1d77b24e5a8c10d2e4b6a8f012", 7,
                                                           "posture:7", "agent")
    assert f.conf == "exact" and f.partial is False and f.conflict is False
    with pytest.raises(TypeError):
        f.data["installed"] = False                    # deep-frozen
    with pytest.raises(TypeError):
        f.data["config"]["maxauthtries"] = 99
    assert isinstance(f.data["probes"]["deltas"], tuple)
    assert h.get("nope") is None


def test_node_without_facts_has_no_host_and_an_empty_dict_has_an_empty_one():
    assert hgraph(hnode("a")).nodes["a"].host is None
    assert ReachGraph.from_dict({"nodes": [{"id": "a", "facts": None}]}).nodes["a"].host is None
    e = hgraph(hnode("a", {})).nodes["a"].host
    assert e is not None and len(e) == 0


def test_missing_conf_and_partial_read_as_the_weak_answer():
    f = fact(sshd())
    del f["conf"], f["partial"]
    g = load({"sshd": f})
    got = g.nodes["h"].host.get("sshd")
    assert got.conf == "approximate" and got.partial is True       # never the strong default


@pytest.mark.parametrize("mut,needle", [
    (lambda f: f.update(status="fine"), "status"),
    (lambda f: f.update(status=None), "status"),
    (lambda f: f.pop("status"), "status"),
    (lambda f: f.update(tier="gold"), "tier"),
    (lambda f: f.update(tier=2), "tier"),
    (lambda f: f.pop("tier"), "tier"),
    (lambda f: f.update(signed="true"), "signed"),
    (lambda f: f.update(signed=1), "signed"),
    (lambda f: f.update(signed=None), "signed"),
    (lambda f: f.pop("signed"), "signed"),
    (lambda f: f.update(seq=True), "seq"),
    (lambda f: f.update(seq=-1), "seq"),
    (lambda f: f.update(seq="7"), "seq"),
    (lambda f: f.update(seq=2 ** 63), "seq"),
    (lambda f: f.update(seq=1.5), "seq"),
    (lambda f: f.update(observed_at="yesterday"), "timestamp"),
    (lambda f: f.update(observed_at="2026-12-01T08:30:00"), "timezone"),
    (lambda f: f.update(observed_at=1764577800), "ISO-8601"),
    (lambda f: f.update(observed_at=None), "ISO-8601"),
    (lambda f: f.pop("observed_at"), "ISO-8601"),
    (lambda f: f.update(observed_at="0001-01-01T00:00:00+14:00"), "out of range"),
    (lambda f: f.update(conf="maybe"), "conf"),
    (lambda f: f.update(conf=1), "conf"),
    (lambda f: f.update(partial="no"), "partial"),
    (lambda f: f.update(partial=0), "partial"),
    (lambda f: f.update(data=[1]), "data"),
    (lambda f: f.update(data="x"), "data"),
    (lambda f: f.update(source=5), "source"),
    (lambda f: f.update(key_id=["a"]), "key_id"),
    (lambda f: f.update(evidence_ref="x" * 300), "longer than"),
    (lambda f: f.update(reason="x" * 70), "longer than"),
    (lambda f: f.update(conflict="yes"), "conflict"),
    (lambda f: f.update(conflict=1), "conflict"),
    (lambda f: f.update(conflict={}), "conflict"),
    (lambda f: f.update(conflict=[1]), "conflict"),
    (lambda f: f.update(conflict=[{}]), "conflict"),
    (lambda f: f.update(conflicts=[{"k": 1}]), "'conflict'"),
    (lambda f: f.update(Conflicted=True), "'conflict'"),
])
def test_malformed_fact_fields_are_graph_errors(mut, needle):
    f = fact(sshd())
    mut(f)
    with pytest.raises(GraphError, match=needle):
        load({"sshd": f})


@pytest.mark.parametrize("value,expected", [
    (None, False), (False, False), ([], False), (True, True), ({"kind": "x"}, True),
    ([{"kind": "x"}], True)])
def test_conflict_marker_semantics(value, expected):
    f = fact(sshd())
    f["conflict"] = value
    assert load({"sshd": f}).nodes["h"].host.get("sshd").conflict is expected


@pytest.mark.parametrize("facts", [[], "x", 5, True])
def test_facts_must_be_an_object(facts):
    with pytest.raises(GraphError, match="facts"):
        load(facts)


def test_fact_must_be_an_object():
    with pytest.raises(GraphError, match="object"):
        load({"sshd": [1]})
    with pytest.raises(GraphError, match="object"):
        load({"sshd": None})


@pytest.mark.parametrize("name", ["", "SSHD", "ssh-d", "1sshd", "a" * 33, "ssh d"])
def test_collector_names_are_validated(name):
    with pytest.raises(GraphError, match="collector name"):
        load({name: fact(sshd())})


def test_collector_count_cap():
    ok = {f"c{i}": fact({}) for i in range(HFX.MAX_COLLECTORS_PER_NODE)}
    assert len(load(ok).nodes["h"].host) == 16
    with pytest.raises(GraphError, match="too many collectors"):
        load({f"c{i}": fact({}) for i in range(17)})


def test_row_and_size_caps():
    rows = list(range(HFX.MAX_ROWS))
    assert load({"listeners": fact({"listeners": rows})})
    with pytest.raises(GraphError, match="rows"):
        load({"listeners": fact({"listeners": rows + [1]})})
    with pytest.raises(GraphError, match="keys"):
        load({"x": fact({str(i): 1 for i in range(HFX.MAX_ROWS + 1)})})
    deep: object = 1
    for _ in range(HFX.MAX_DATA_DEPTH + 2):
        deep = {"a": deep}
    with pytest.raises(GraphError, match="nested deeper"):
        load({"x": fact({"d": deep})})
    with pytest.raises(GraphError, match="longer than"):
        load({"x": fact({"s": "a" * (HFX.MAX_STRING + 1)})})


def test_total_element_budget(monkeypatch):
    monkeypatch.setattr(HFX, "MAX_FACT_ELEMENTS", 50)
    monkeypatch.setattr(HFX, "MAX_TOTAL_ELEMENTS", 120)
    nodes = [hnode(f"h{i}", {"x": fact({"l": list(range(30))})}) for i in range(5)]
    with pytest.raises(GraphError, match="too much fact data"):
        ReachGraph.from_dict({"nodes": nodes})
    with pytest.raises(GraphError, match="too many values"):
        load({"x": fact({"l": list(range(60))})})


@pytest.mark.parametrize("bad", [1.5, float("nan"), float("inf"), b"x", (1, 2), {1, 2}, object()])
def test_floats_and_foreign_types_are_refused_in_data(bad):
    with pytest.raises(GraphError):
        load({"x": fact({"v": bad})})


def test_non_string_keys_in_data_are_refused():
    with pytest.raises(GraphError, match="keys must be strings"):
        load({"x": fact({1: "a"})})


def test_an_input_document_is_never_aliased_or_mutated():
    doc = {"version": 1, "nodes": [hnode("h", good_facts())], "edges": []}
    before = copy.deepcopy(doc)
    g = ReachGraph.from_dict(doc)
    doc["nodes"][0]["facts"]["sshd"]["data"]["config"]["maxauthtries"] = 99
    assert g.nodes["h"].host.get("sshd").data["config"]["maxauthtries"] == 3
    assert before["nodes"][0]["facts"]["sshd"]["data"]["config"]["maxauthtries"] == 3


def test_facts_do_not_disturb_selectors_or_coverage():
    g = hgraph(hnode("a", good_facts(), zone="prod"), hnode("b", None, tags=("x",)))
    from paddock_assurance.model import Selector
    assert [n.id for n in g.select(Selector(tag=["agent"]))] == ["a"]
    assert g.nodes["a"].coverage == ()


def test_unknown_fact_keys_are_tolerated():
    f = fact(sshd())
    f["received_at"] = FRESH
    f["note"] = "x"
    assert load({"sshd": f}).nodes["h"].host.get("sshd") is not None
