"""``assert: covered`` and ``std:coverage-complete``: coverage as a first-class statement."""
import datetime as dt
import json

import pytest

from paddock_assurance import ParseError, PlanKind, Verdict, compile_text, evaluate
from paddock_assurance.cli import main
from paddock_assurance.render import render_explain, render_result
from paddock_assurance.stdlib import load_std

from helpers import NOW, STALE, dnode, fact, graph

COVERED = """
apiVersion: paddock.dev/invariant/v1
id: acme:all-covered
title: Datastores are covered
severity: medium
subjects: {{ to: {{ class: data_store }} }}
assert: covered
{extra}
"""


def plan(extra="evidence: { min_tier: configured, max_age: 24h }"):
    return compile_text(COVERED.format(extra=extra))


def V(p, g, now=NOW):
    return evaluate(p, g, now)


def ds(id_, *facts, **kw):
    return dnode(id_, "prod", *facts, cls="data_store", **kw)


# ---- model / compile -------------------------------------------------------------------------

def test_compiles_to_its_own_plan_kind_and_ignores_the_graph_wide_floor():
    p = plan()
    assert p.kind is PlanKind.COVERED and p.coverage_required == 0.0


@pytest.mark.parametrize("doc,needle", [
    ("subjects: { from: { zone: a }, to: { class: data_store } }\nassert: covered\n", "subjects.from"),
    ("assert: covered\n", "subjects.to"),
    ("subjects: { to: { zone: a } }\nassert: covered\nports: [80]\n", "ports"),
    ("subjects: { to: { zone: a } }\nassert: covered\nvia: { max_hops: 2 }\n", "via"),
    ("subjects: { to: { zone: a } }\nassert: covered\nallow:\n  - { to: { zone: a }, reason: legacy box, expires: 2027-01-01 }\n", "allow"),
])
def test_covered_shape_is_enforced(doc, needle):
    head = "apiVersion: paddock.dev/invariant/v1\nid: acme:c\ntitle: coverage rule\n"
    with pytest.raises(ParseError) as e:
        compile_text(head + doc)
    assert needle in str(e.value)


def test_covered_has_its_own_digest_from_unreachable():
    a = plan().digest
    b = compile_text(COVERED.format(extra="evidence: { min_tier: observed }")).digest
    assert a != b and a.startswith("sha256:")


# ---- evaluation ------------------------------------------------------------------------------

def test_holds_when_every_selected_node_is_covered_both_ways():
    g = graph([ds("db1", fact("both")), ds("db2", fact("in", source="aws_sg"), fact("out", source="sentry")),
               dnode("other", "x")], [])
    r = V(plan(), g)
    assert r.verdict is Verdict.HOLDS and r.reasons == ["all_covered"] and r.witnesses == []
    assert r.assertion == "covered"
    assert r.evidence_tier.value == "observed"
    assert r.valid_until == dt.datetime(2026, 12, 2, 8, 30, tzinfo=dt.timezone.utc)
    # The unselected blind node is outside the claim; it does not break it.
    assert (r.coverage_covered, r.coverage_universe) == (2, 3)


def test_inbound_only_is_a_gap_with_a_hopless_witness_naming_the_missing_direction():
    g = graph([ds("db1", fact("in", "configured", source="aws_sg"))], [])
    r = V(plan(), g)
    assert r.verdict is Verdict.VIOLATED and r.violation_count == 1
    w, = r.witnesses
    assert w.hops == () and w.confirmed is False
    assert w.detail["node"] == "db1" and w.detail["direction"] == "out"
    assert w.detail["reason"] == "no_sensor" and w.detail["reason_out"] == "no_sensor"
    assert "reason_in" not in w.detail


def test_each_failure_reason_is_reported_with_its_direction():
    g = graph([ds("db_both"),                                                  # nothing at all
               ds("db_stale", fact("both", seen=STALE)),
               ds("db_weak", fact("both", "declared")),
               ds("db_future", fact("both", seen="2026-12-02T09:00:00Z")),
               ds("db_mixed", fact("in"), fact("out", seen=STALE)),
               ds("db_ok", fact("both"))], [])
    r = V(plan(), g)
    by = {w.detail["node"]: w.detail for w in r.witnesses}
    assert set(by) == {"db_both", "db_stale", "db_weak", "db_future", "db_mixed"}
    assert by["db_both"]["reason"] == "no_sensor" and by["db_both"]["direction"] == "both"
    assert by["db_stale"]["reason"] == "stale"
    assert by["db_weak"]["reason"] == "tier_below_min"
    assert by["db_future"]["reason"] == "future_timestamp"
    assert (by["db_mixed"]["direction"], by["db_mixed"]["reason"]) == ("out", "stale")


def test_root_causes_come_first():
    g = graph([ds("a-stale", fact("both", seen=STALE)), ds("b-weak", fact("both", "declared")),
               ds("c-half", fact("in")), ds("d-none")], [])
    order = [w.detail["node"] for w in V(plan(), g).witnesses]
    # nothing at all (both) -> nothing outbound -> weak evidence -> quiet sensor
    assert order == ["d-none", "c-half", "b-weak", "a-stale"]


def test_a_node_blind_in_both_directions_for_different_reasons_is_one_witness():
    g = graph([ds("db1", fact("in", seen=STALE))], [])
    r = V(plan(), g)
    w, = r.witnesses
    assert w.detail["direction"] == "both" and w.detail["reason"] == "no_sensor"
    assert (w.detail["reason_in"], w.detail["reason_out"]) == ("stale", "no_sensor")


def test_empty_selector_is_unknown_not_vacuously_covered():
    g = graph([dnode("n", "a", fact("both"))], [])
    r = V(plan(), g)
    assert r.verdict is Verdict.UNKNOWN and r.reasons == ["empty_selector:to"]


def test_fresh_facts_expire():
    g = graph([ds("db1", fact("both"))], [])
    r = V(plan(), g)
    assert r.status_at(NOW) == "HOLDS"
    assert r.status_at(r.valid_until + dt.timedelta(seconds=1)) == "EXPIRED"
    # ...and evaluating later actually fails the assertion.
    assert V(plan(), g, NOW + dt.timedelta(days=2)).verdict is Verdict.VIOLATED


def test_witness_list_is_capped_but_the_count_is_not():
    g = graph([ds(f"db{i:03d}") for i in range(80)], [])
    r = V(plan(), g)
    assert r.violation_count == 80 and len(r.witnesses) == 50
    assert [w.detail["node"] for w in r.witnesses] == [f"db{i:03d}" for i in range(50)]


def test_deterministic_under_input_order():
    nodes = [ds("d1", fact("in")), ds("d2"), ds("d3", fact("both", seen=STALE)), ds("d4", fact("both"))]
    a = V(plan(), graph(nodes, [])).to_dict()
    b = V(plan(), graph(nodes[::-1], [])).to_dict()
    assert a == b and a["assertion"] == "covered"


# ---- rendering -------------------------------------------------------------------------------

def test_render_names_the_node_direction_and_reason():
    g = graph([ds("db1", fact("in")), ds("db2", fact("both"))], [])
    r = V(plan(), g)
    text = render_result(r, NOW)
    assert "1 uncovered node" in text and "reachable" not in text
    assert "db1: not covered outbound, no_sensor" in text
    assert "need" not in text
    assert "blind spots that matter" not in text      # the witnesses already say it


def test_explain_has_no_from_or_via_lines():
    g = graph([ds("db1", fact("both"))], [])
    p = plan()
    text = render_explain(p, g, V(p, g), NOW)
    assert "(COVERED," in text and "  to " in text
    assert "  from " not in text and "  via " not in text


# ---- std:coverage-complete -------------------------------------------------------------------

def test_std_coverage_complete_is_the_documented_policy():
    p = load_std("std:coverage-complete")
    assert p.kind is PlanKind.COVERED and p.invariant.severity == "medium"
    assert p.invariant.subjects.to.kind == ("cloud_db", "cloud_instance", "cloud_lb", "device", "host")
    assert p.min_tier.value == "configured" and p.invariant.evidence.max_age == "24h"


def test_std_coverage_complete_selects_only_assets_that_can_be_instrumented():
    g = graph([dnode("internet", None, kind="internet"), dnode("cidr:10.0.0.0/8", None, kind="cidr"),
               dnode("i-1", None, fact("in"), kind="cloud_instance"),
               dnode("db", None, fact("both"), kind="cloud_db"),
               dnode("lb", None, fact("both"), kind="cloud_lb"),
               dnode("pc", None, fact("both"), kind="device"),
               dnode("h", None, fact("both"), kind="host")], [])
    r = V(load_std("std:coverage-complete"), g)
    assert r.verdict is Verdict.VIOLATED
    assert [w.detail["node"] for w in r.witnesses] == ["i-1"]      # internet and cidr are exempt


# ---- CLI -------------------------------------------------------------------------------------

def _graph_file(tmp_path, nodes):
    p = tmp_path / "g.json"
    p.write_text(json.dumps({"version": 1, "now": "2026-12-01T09:00:00Z", "nodes": nodes, "edges": []}))
    return str(p)


def test_cli_exit_codes_and_text(capsys, tmp_path):
    bad = _graph_file(tmp_path, [dnode("i-1", None, fact("in"), kind="cloud_instance")])
    assert main(["test", "std:coverage-complete", "--graph", bad]) == 1
    out = capsys.readouterr().out
    assert "VIOLATED" in out and "i-1: not covered outbound" in out
    ok = _graph_file(tmp_path, [dnode("i-1", None, fact("both"), kind="cloud_instance")])
    assert main(["test", "std:coverage-complete", "--graph", ok]) == 0
    stale = main(["test", "std:coverage-complete", "--graph", ok, "--now", "2026-12-05T00:00:00Z"])
    assert stale == 1      # past max_age the evidence is gone: the assertion itself fails


def test_cli_json_carries_directional_blind_spots_and_hopless_witnesses(capsys, tmp_path):
    g = _graph_file(tmp_path, [dnode("i-1", None, fact("in"), kind="cloud_instance")])
    assert main(["test", "std:coverage-complete", "--graph", g, "--json"]) == 1
    r = json.loads(capsys.readouterr().out)["results"][0]
    assert r["assertion"] == "covered"
    assert r["witnesses"][0]["hops"] == []
    assert r["witnesses"][0]["detail"] == {"node": "i-1", "direction": "out", "reason": "no_sensor",
                                           "reason_out": "no_sensor"}
    assert r["blind_spots"][0]["direction"] == "out"


def test_cli_explain_and_lint_accept_covered(capsys, tmp_path):
    g = _graph_file(tmp_path, [dnode("i-1", None, fact("both"), kind="cloud_instance")])
    assert main(["explain", "std:coverage-complete", "--graph", g]) == 0
    assert "COVERED" in capsys.readouterr().out
    assert main(["lint", "std:coverage-complete"]) == 0
