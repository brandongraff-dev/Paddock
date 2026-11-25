"""P2 round 2, package Z (zone membership, corroboration residuals, builder lows): pure builder/loader tests.

Z-3: an identity stored without ``peer_proxied`` is NOT trusted as a direct peer.
Z-5: honest, non-canonical-named protocol rules (``-p vrrp``, ``-p ospf``) stay exact; unknown tokens still widen.
Z-6: the listener cap keeps the true total, marks the cap, and a lying count cannot make a capped table complete.
Z-1 (builder/loader half): an agent node that nothing independent placed carries ``zone_unknown`` into the document.
"""
from __future__ import annotations

import json

import pytest

from app.assurance import graph_loader as gl
from app.assurance import refs
from app.assurance.builders import _ipmap
from app.assurance.builders import host_fw as hf

from .test_assurance_host_fw import (NOW, acc, agent_row, aid, chain, cloud, edges_of, fw_section, lis_section,
                                     listener, one, posture_row, ref1, rows_of, sections)

PRIV = "10.0.1.5"


def _inst():
    return cloud(100, priv=(PRIV,), pub=("54.1.2.3",))


def _nodes_of(out):
    return sorted(f.node_ref for f in out.facts)


# --------------------------------------------------------------------------- #
# Z-3: a stored identity without the ``peer_proxied`` key is read as "may be a forwarding hop"
# --------------------------------------------------------------------------- #

def _legacy(agent):
    agent["identity"].pop("peer_proxied", None)
    return agent


def test_z3_claim_of_reads_a_missing_peer_proxied_as_not_direct():
    assert _ipmap.claim_of("a", {"ips": [PRIV], "peer_ip": PRIV}).direct is False
    assert _ipmap.claim_of("a", {"ips": [PRIV], "peer_ip": PRIV, "peer_proxied": None}).direct is False
    assert _ipmap.claim_of("a", {"ips": [PRIV], "peer_ip": PRIV, "peer_proxied": "false"}).direct is False
    assert _ipmap.claim_of("a", {"ips": [PRIV], "peer_ip": PRIV, "peer_proxied": 0}).direct is False
    assert _ipmap.claim_of("a", {"ips": [PRIV], "peer_ip": PRIV, "peer_proxied": True}).direct is False
    assert _ipmap.claim_of("a", {"ips": [PRIV], "peer_ip": PRIV, "peer_proxied": False}).direct is True


def test_z3_a_legacy_identity_with_a_forged_private_peer_no_longer_corroborates(monkeypatch):
    """A row written before ``peer_proxied`` existed (its peer came from the old client_ip_strict) must not keep its
    corroboration until the agent's next posture."""
    a = _legacy(agent_row(1, ips=(PRIV,), peer=PRIV))
    out = hf.build(rows_of((a, posture_row()), assets=[_inst()]), NOW)
    assert _nodes_of(out) == [ref1(1)], "an identity of unknown provenance corroborated"
    idents = hf._resolve_identities([a], _ipmap.build_ip_map([_inst()]))
    assert idents[aid(1)].basis == "claimed" and idents[aid(1)].note == "peer_not_direct"
    # control (with the private-peer proof switched on, see Z-2): the same row with the flag written by the current
    # ingest still corroborates
    monkeypatch.setattr(_ipmap, "PRIVATE_PEER_IS_PROOF", True)
    b = agent_row(1, ips=(PRIV,), peer=PRIV)
    b["identity"]["peer_proxied"] = False
    out = hf.build(rows_of((b, posture_row()), assets=[_inst()]), NOW)
    assert _nodes_of(out) == [refs.asset_ref(_inst()["id"])]


def test_z3_a_legacy_identity_is_not_a_zone_hint_either():
    a = _legacy(agent_row(1, ips=("10.10.0.7",), peer="10.99.0.1"))
    assert hf._resolve_identities([a], _ipmap.build_ip_map([]))[aid(1)].observed == []


def test_z3_the_builders_row_reader_maps_a_missing_flag_to_proxied():
    for ident, want in (({"ips": [], "peer_ip": PRIV}, True), ({"peer_proxied": False, "peer_ip": PRIV}, False),
                        ({"peer_proxied": True, "peer_ip": PRIV}, True), ({"peer_proxied": "no"}, True),
                        ({"peer_proxied": None}, True), ({}, True)):
        assert hf._identity_view(ident)["peer_proxied"] is want, ident


def test_z2_residual_a_header_less_nat_with_one_agent_behind_it_does_not_corroborate():
    inst = _inst()
    b = agent_row(1, ips=(PRIV,), peer=PRIV)               # another machine whose packets leave N with N's address
    out = hf.build(rows_of((b, posture_row()), assets=[inst]), NOW)
    assert _nodes_of(out) != [refs.asset_ref(inst["id"])], "merged into the instance on its private source address alone"


def test_z2_a_private_peer_alone_is_not_proof_and_says_so():
    inst = _inst()
    b = agent_row(1, ips=(PRIV,), peer=PRIV)
    idents = hf._resolve_identities([b], _ipmap.build_ip_map([inst]))
    assert idents[aid(1)].basis == "claimed" and idents[aid(1)].note == "peer_address_not_proof"
    assert idents[aid(1)].ref == ref1(1)


def test_z2_the_switch_is_a_module_constant_off_by_default_and_the_other_rules_still_hold_when_it_is_on(monkeypatch):
    assert _ipmap.PRIVATE_PEER_IS_PROOF is False
    inst = _inst()
    cl = _ipmap.Claim("a", (PRIV,), PRIV, True)
    amap = _ipmap.build_ip_map([inst])
    assert _ipmap.corroborate([cl], amap)["a"] == _ipmap.Decision(None, "peer_address_not_proof")
    assert _ipmap.corroborate([cl], amap, private_peer_proof=True)["a"].ref == refs.asset_ref(inst["id"])
    two = [cl, _ipmap.Claim("b", ("10.9.9.9",), PRIV, True)]
    out = _ipmap.corroborate(two, amap, private_peer_proof=True)
    assert out["a"] == _ipmap.Decision(None, "shared_peer_address")      # rule 3 survives the switch


# --------------------------------------------------------------------------- #
# Z-5: honest protocol names stay exact; the rest still widens
# --------------------------------------------------------------------------- #

def _fw_with(rule_before):
    return sections(
        firewall=fw_section([chain([rule_before, acc(proto="tcp", dport=[[22, 22]])])]),
        listeners=lis_section([listener(22), listener(5432, comm="postgres")]))


@pytest.mark.parametrize("name", ["vrrp", "ospf", "pim", "l2tp", "ipcomp", "etherip", "rsvp", "eigrp", "isis",
                                  "ospfigp", "ipsec-esp", "ipsec-ah", "ipencap", "p112", "p89"])
def test_z5_an_honest_rule_for_another_ip_protocol_does_not_widen_every_listener(name):
    """Default-drop input chain with ``accept proto=<name>`` before ``accept tcp/22``, listeners 22 and 5432: the
    tcp edges are exactly the tcp/22 ones at confidence 100 (the rule never matches a tcp packet)."""
    out = one(_fw_with(acc(proto=name)))
    e = edges_of(out, "tcp")
    assert e == [("cidr:0.0.0.0/0", "tcp", 22, 22, hf.CONF_ALLOW), ("internet", "tcp", 22, 22, hf.CONF_ALLOW)], (name, e)


def test_z5_a_named_protocol_and_its_number_are_one_protocol():
    """``-p vrrp -j ACCEPT`` then ``-p 112 -j DROP`` (the agent writes p112): one protocol, first match wins."""
    for first, second in (("vrrp", "p112"), ("p112", "vrrp")):
        sec = sections(firewall=fw_section([chain([acc(proto=first), {"m": {"proto": second}, "v": "drop"}])]),
                       listeners=lis_section([listener(22)]))
        out = one(sec)
        both = [x for x in edges_of(out, "any")]
        assert both, (first, second)                    # protocol 112 is accepted by the first rule: an 'any' edge exists
        assert all(c == hf.CONF_ALLOW for *_x, c in both), (first, second, both)
    sec = sections(firewall=fw_section([chain([{"m": {"proto": "vrrp"}, "v": "drop"}, acc(proto="p112")])]),
                   listeners=lis_section([listener(22)]))
    assert edges_of(one(sec), "any") == [], "the drop of 'vrrp' did not apply to 'p112'"


@pytest.mark.parametrize("tok", ["TCP", "6", "Vrrp", "vrrp ", "p6", "p256", "all", "ipv6-icmp", "zz-unknown", "p01",
                                 "ax.25", "mptcp", 112, None, ""])
def test_z5_an_unknown_token_still_widens(tok):
    out = one(sections(firewall=fw_section([chain([acc(proto=tok, dport=[[22, 22]])])]),
                       listeners=lis_section([listener(22)])))
    e = edges_of(out, "tcp")
    assert e and all(c == hf.CONF_MAYBE for *_x, c in e), (tok, e)


# --------------------------------------------------------------------------- #
# Z-6: the cap keeps the agent-reported total and cannot be lied below the rows
# --------------------------------------------------------------------------- #

def _many(n, **kw):
    return [listener(1000 + i, ip=f"10.{i // 250}.{i % 250}.1", bind="specific", **kw) for i in range(n)]


def test_z6_a_lying_count_cannot_make_a_capped_table_complete():
    """A buggy or lying agent reports ``count == 200`` with 1500 rows: the capped table (200 rows) must not read as
    complete (count == len(rows) is what the library checks)."""
    out = one(sections(listeners=lis_section(_many(1500), count=200)))
    d = out.facts[0].facts["listeners"]["data"]
    assert len(d["listeners"]) == hf.MAX_FACT_LISTENERS
    assert d["count"] == 1500 != len(d["listeners"]), d["count"]
    assert d["omitted"] == 1300 and d["capped"] == hf.MAX_FACT_LISTENERS
    assert d["reported_count"] == 200                      # what the agent said is still visible ("200 of 1500")


def test_z6_the_agents_own_total_is_kept_and_the_cap_is_marked():
    out = one(sections(listeners=lis_section(_many(1500), count=1500)))
    d = out.facts[0].facts["listeners"]["data"]
    assert d["count"] == 1500 and d["omitted"] == 1300 and d["capped"] == 200
    assert "reported_count" not in d                       # nothing to contradict


def test_z6_an_agent_that_cut_rows_itself_cannot_hide_it_behind_an_equal_count():
    rows = [listener(1000 + i) for i in range(50)]
    sec = lis_section(rows, count=50)
    sec["v"]["dropped"] = 30                               # the agent's own cap: 30 more existed
    d = one(sections(listeners=sec)).facts[0].facts["listeners"]["data"]
    assert d["count"] == 80 != len(d["listeners"]) and d["dropped"] == 30 and d["reported_count"] == 50


@pytest.mark.parametrize("bad", ["7", True, -3, [], {}])
def test_z6_a_malformed_dropped_marker_cannot_leave_the_table_looking_complete(bad):
    """The agent says it cut rows (``dropped`` present) but the number is unusable: how many were cut is unknown, so
    ``count`` must differ from the rows kept (never read as complete)."""
    rows = [listener(1000 + i) for i in range(50)]
    sec = lis_section(rows, count=50)
    sec["v"]["dropped"] = bad
    d = one(sections(listeners=sec)).facts[0].facts["listeners"]["data"]
    assert d["count"] != len(d["listeners"]), d


def test_z6_a_float_dropped_marker_makes_the_whole_fact_an_error_never_a_table():
    sec = lis_section([listener(1000 + i) for i in range(50)], count=50)
    sec["v"]["dropped"] = 2.5
    e = one(sections(listeners=sec)).facts[0].facts["listeners"]
    assert e["status"] == "error" and e["data"] == {}


def test_z6_the_cap_markers_survive_the_store_and_the_loader_and_the_library_reads_the_table_as_partial():
    from app.assurance import store
    out = one(sections(listeners=lis_section(_many(1500), count=200)))
    rep = store.BuildReport()
    stored = store._clean_facts(out, rep)
    (ref, row), = stored.items()
    rows = [{"node_ref": ref, "source": "host_fw", "tier": row["tier"], "observed_at": row["observed_at"],
             "facts": json.dumps(row["entries"])}]
    diag = gl.LoadDiagnostics()
    merged, _have = gl._assemble_facts(rows, diag)
    assert diag.facts_dropped == 0, diag.fact_issues
    data = merged[ref]["listeners"]["data"]
    assert data["count"] == 1500 and data["capped"] == 200 and data["omitted"] == 1300 and data["reported_count"] == 200
    from paddock_assurance import ReachGraph
    g = ReachGraph.from_dict({"version": 1, "nodes": [{"id": ref, "kind": "host", "tags": ["agent"],
                                                       "facts": merged[ref]}], "edges": []})
    assert g.nodes[ref].host is not None


def test_z6_an_untouched_small_table_is_exactly_what_it_was():
    d = one(sections(listeners=lis_section([listener(22), listener(443)]))).facts[0].facts["listeners"]["data"]
    assert d["count"] == 2 and "omitted" not in d and "capped" not in d and "reported_count" not in d


# --------------------------------------------------------------------------- #
# Z-1: the loader turns "no independent placement" into a document attribute
# --------------------------------------------------------------------------- #

_ZONES = [{"id": "1", "name": "pos", "kind": "custom", "cidrs": ["10.10.0.0/24"], "description": "",
           "source": "declared", "created_by": None, "created_at": None, "updated_at": None},
          {"id": "2", "name": "guest", "kind": "custom", "cidrs": ["10.99.0.0/24"], "description": "",
           "source": "declared", "created_by": None, "created_at": None, "updated_at": None}]


def _doc(attrs, *, labels=(), ref="agent:00000000-0000-0000-0000-000000000001", extra_nodes=()):
    nodes = [{"node_ref": ref, "kind": "host", "asset_id": None, "attrs": json.dumps(attrs)}, *extra_nodes]
    snap = {"state": {"graph_version": 1}, "nodes": nodes, "edges": [], "cov": [], "facts": [],
            "labels": list(labels), "zones": _ZONES}
    return gl._assemble(snap, {}, NOW)


def _n(doc, ref="agent:00000000-0000-0000-0000-000000000001"):
    return next(n for n in doc["nodes"] if n["id"] == ref)


def test_z1_a_host_nothing_independent_placed_is_zone_unknown_in_the_document():
    doc, diag = _doc({"ips": [], "claimed_ips": ["192.168.77.7"]})
    assert _n(doc).get("zone_unknown") is True and "zone" not in _n(doc)
    doc, diag = _doc({"ips": [], "claimed_ips": ["10.10.0.7"]})                    # placed by its own word only
    n = _n(doc)
    assert n.get("zone_unknown") is True and n.get("zone") == "pos"
    assert diag.zone_from_claim == ["agent:00000000-0000-0000-0000-000000000001"]


def test_z1_an_independent_placement_is_not_zone_unknown():
    doc, _ = _doc({"ips": [], "claimed_ips": ["192.168.77.7"], "observed_ips": ["10.10.0.7"]})
    assert "zone_unknown" not in _n(doc) and _n(doc)["zone"] == "pos"
    lab = [{"node_ref": "agent:00000000-0000-0000-0000-000000000001", "tag": "zone", "value": "guest",
            "source": "declared"}]
    doc, _ = _doc({"ips": [], "claimed_ips": ["10.10.0.7"]}, labels=lab)
    assert "zone_unknown" not in _n(doc) and _n(doc)["zone"] == "guest"
    # a platform-written (non-declared) label is not the host's word: it places the node
    lab = [{"node_ref": "agent:00000000-0000-0000-0000-000000000001", "tag": "zone", "value": "guest",
            "source": "connector"}]
    doc, diag = _doc({"ips": [], "claimed_ips": ["10.10.0.7"]}, labels=lab)
    assert "zone_unknown" not in _n(doc) and _n(doc)["zone"] == "guest" and diag.zone_from_claim == []


def test_z1_nodes_that_are_not_agents_keep_their_old_semantics():
    doc, _ = _doc({"ips": ["10.10.0.9"]}, ref="asset:00000000-0000-0000-0000-0000000000aa")
    n = _n(doc, "asset:00000000-0000-0000-0000-0000000000aa")
    assert n["zone"] == "pos" and "zone_unknown" not in n


def test_z1_the_document_with_no_zone_unknown_node_is_unchanged():
    doc, _ = _doc({"ips": [], "claimed_ips": [], "observed_ips": ["10.10.0.7"]})
    assert all("zone_unknown" not in n for n in doc["nodes"])


# --------------------------------------------------------------------------- #
# Z-1 end to end: builder -> loader -> library, under the shipped Helm default (every request proxied)
# --------------------------------------------------------------------------- #

import itertools  # noqa: E402

from .test_node_identity_a1 import _node as _doc_node, _segmentation_doc, _verdict  # noqa: E402


@pytest.mark.parametrize("claimed,peer,proxied", list(itertools.product(
    ["192.168.77.7", "172.17.0.1", "10.99.0.7", "10.10.0.7", "127.0.0.2"],
    [None, "203.0.113.5", "127.0.0.1", "10.0.0.9", "10.10.0.7", "10.42.0.2"],
    [True, None])))
def test_z1_a_lying_host_behind_the_shipped_default_is_never_a_false_holds(claimed, peer, proxied):
    """Every request through the ingress (Helm ``trustedProxyCidrs`` empty) or an identity of unknown provenance: no
    peer is evidence, so whatever B claims the zone selector must not simply miss it."""
    doc, _diag = _segmentation_doc(claimed, peer=peer, proxied=proxied)
    assert _verdict(doc) in ("UNKNOWN", "VIOLATED"), (claimed, peer, proxied, _doc_node(doc, "agent:00000000-0000-0000-0000-000000000001"))
    node = _doc_node(doc, "agent:00000000-0000-0000-0000-000000000001")
    assert node.get("zone_unknown") is True                       # placed by nothing but its own word, or by nothing
    assert _verdict(doc) == "UNKNOWN"                              # and so never certain either way


def test_z1_an_independent_placement_keeps_the_verdict_certain():
    doc, _ = _segmentation_doc("192.168.77.7", peer="10.10.0.7")               # direct, unique, private: pos
    assert "zone_unknown" not in _doc_node(doc, "agent:00000000-0000-0000-0000-000000000001")
    assert _verdict(doc) == "VIOLATED"
    doc, _ = _segmentation_doc("192.168.77.7", label="pos")                    # declared label
    assert _verdict(doc) == "VIOLATED"


# --------------------------------------------------------------------------- #
# Z-1: the document, its digest, and a library that does not know the attribute
# --------------------------------------------------------------------------- #

def test_z1_the_document_hash_changes_exactly_when_a_node_becomes_zone_unknown_and_is_deterministic():
    placed, _ = _doc({"ips": [], "claimed_ips": ["10.10.0.7"], "observed_ips": ["10.10.0.7"]})
    guessed, _ = _doc({"ips": [], "claimed_ips": ["10.10.0.7"]})
    again, _ = _doc({"ips": [], "claimed_ips": ["10.10.0.7"]})
    assert _n(placed)["zone"] == _n(guessed)["zone"] == "pos"          # same display zone ...
    assert gl.doc_sha(placed) != gl.doc_sha(guessed)                      # ... a different document
    assert gl.doc_sha(guessed) == gl.doc_sha(again)


async def test_z1_a_library_that_does_not_know_zone_unknown_makes_the_graph_unavailable_not_wrong(monkeypatch):
    from app.assurance import runner
    doc, diag = _doc({"ips": [], "claimed_ips": ["192.168.77.7"]})
    snap = runner._Snapshot(doc=doc, diag=diag, version=1, doc_sha="x")
    monkeypatch.setattr(runner, "_lib_knows_zone_unknown", lambda: False)
    summary = {"errors": []}
    await runner._parse_graph(snap, summary)
    assert snap.graph is None and snap.reason == "graph_unavailable" and "zone_unknown" in snap.error
    monkeypatch.undo()
    snap = runner._Snapshot(doc=doc, diag=diag, version=1, doc_sha="x")
    await runner._parse_graph(snap, {"errors": []})
    assert snap.graph is not None and snap.graph.nodes["agent:00000000-0000-0000-0000-000000000001"].zone_unknown


def test_z1_the_runner_reports_how_many_nodes_are_zone_unknown():
    from app.assurance import runner
    doc, diag = _doc({"ips": [], "claimed_ips": ["192.168.77.7"]})
    d = runner._diagnostics(runner._Snapshot(doc=doc, diag=diag, version=1, doc_sha="x"), {})
    assert d["zone_unknown_count"] == 1 and d["zone_unknown"] == ["agent:00000000-0000-0000-0000-000000000001"]
