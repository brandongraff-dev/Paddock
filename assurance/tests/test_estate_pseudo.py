"""The ``estate`` pseudo kind (P2.1 section 5.2, D31): the residual node a cloud builder adds for
"members of a security group we could not prove complete".

An estate node is not a thing a sensor can be installed on, so it can never be covered and must not count
in the coverage universe (it would only lower the ratio, which is a policy overlay, never soundness).
What it MUST keep doing is what makes it sound: it is blind in both directions, so an unknown edge
reaches it and a known ``estate -> dst`` edge carries the search onward. Each test here pins one half.
"""
import importlib

import pytest

from paddock_assurance import Verdict, compile_text, evaluate

from helpers import NOW, dnode, edge, fact, graph

ev = importlib.import_module("paddock_assurance.evaluate")   # the package re-exports the function under this name

ESTATE = "estate:123456789012:us-east-1:vpc-0abc"
ANY = "evidence: { min_tier: observed, max_age: 24h }\ncoverage: { require: 0 }"
STRICT = "evidence: { min_tier: observed, max_age: 24h }\ncoverage: { require: 0.95 }"


def estate_node(**kw):
    """What the builder emits: no coverage at all, zone unknown (it may sit in any declared zone)."""
    n = {"id": ESTATE, "kind": "estate", "tags": [], "zone_unknown": True,
         "coverage": []}
    n.update(kw)
    return n


def plan(extra=ANY, frm="{ id: internet }", to="{ id: db }"):
    """Selectors by id by default: a zone selector would (rightly) also see the zone-unknown estate as a
    possible member, which is a different, separately pinned question."""
    return compile_text(f"""
apiVersion: paddock.dev/invariant/v1
id: acme:x-cannot-reach-y
title: x cannot reach y
severity: high
subjects:
  from: {frm}
  to: {to}
assert: unreachable
{extra}
""")


def covered_hosts(n=5):
    return [dnode(f"h{i}", "app", fact("both")) for i in range(n)]


def test_estate_is_a_pseudo_kind_next_to_internet_and_cidr():
    assert ev.PSEUDO_KINDS == frozenset({"internet", "cidr", "estate"})
    assert isinstance(ev.PSEUDO_KINDS, frozenset)


def test_an_estate_node_is_outside_the_coverage_universe():
    g = graph([dnode("internet", "internet", kind="internet"), dnode("db", "data", fact("in")),
               *covered_hosts(3), estate_node()], [])
    r = evaluate(plan(), g, NOW)
    assert g.nodes[ESTATE].kind == "estate"
    # internet and estate are pseudo (not counted); db + three hosts are real
    assert r.coverage_universe == 4


def test_an_estate_node_does_not_lower_the_relevant_ratio_when_it_cannot_reach_anything():
    # Five covered hosts and an estate residual with no edge out of it: the unknown edge internet ->
    # estate leads nowhere, so the verdict is HOLDS and the estate must not drag the floor below 0.95
    # (5/6 = 0.83 would turn a sound HOLDS into coverage_below_required).
    hosts = [dnode(f"h{i}", "data", fact("in"), tags=("db",)) for i in range(5)]
    g = graph([dnode("internet", "internet", kind="internet"), estate_node(), *hosts], [])
    r = evaluate(plan(STRICT, to="{ tag: db }"), g, NOW)
    assert r.verdict is Verdict.HOLDS, (r.verdict, r.reasons)
    assert r.relevant_universe == 5 and r.relevant_covered == 5
    assert "coverage_below_required" not in r.reasons


def test_an_estate_with_an_edge_to_the_datastore_keeps_the_verdict_unknown_with_the_estate_witness():
    # THE builders-7 shape: internet -(unknown)-> estate -(configured)-> db. The estate node is a
    # pseudo node and must STILL be searched through: leaving the coverage universe does not make it
    # invisible to the reach search.
    g = graph([dnode("internet", "internet", kind="internet"), estate_node(),
               dnode("db", "data", fact("in"))],
              [edge(ESTATE, "db", "5432", "tcp", "configured")])
    r = evaluate(plan(), g, NOW)
    assert r.verdict is Verdict.UNKNOWN and r.reasons == ["possible_via_unknown_edges"]
    hops = r.witnesses[0].hops
    assert [(h.src, h.dst, h.basis) for h in hops] == [
        ("internet", ESTATE, "unknown"), (ESTATE, "db", "configured")]
    assert r.verdict is not Verdict.HOLDS and r.valid_until is None


def test_estate_stays_unknown_whatever_the_coverage_floor():
    for extra in (ANY, STRICT):
        g = graph([dnode("internet", "internet", kind="internet"), estate_node(),
                   dnode("db", "data", fact("in"))],
                  [edge(ESTATE, "db", "5432", "tcp", "configured")])
        assert evaluate(plan(extra), g, NOW).verdict is Verdict.UNKNOWN


def test_an_estate_node_is_blind_so_a_modelled_blind_host_also_reaches_it_by_an_unknown_edge():
    # a modelled host with no outbound coverage may talk to the estate (and from there to the db)
    g = graph([dnode("web1", "web"), estate_node(), dnode("db", "data", fact("in"))],
              [edge(ESTATE, "db", "5432", "tcp", "configured")])
    r = evaluate(plan(frm="{ id: web1 }"), g, NOW)
    assert r.verdict is Verdict.UNKNOWN
    assert [(h.src, h.dst) for h in r.witnesses[0].hops] == [("web1", ESTATE), (ESTATE, "db")]


def test_a_zone_unknown_estate_makes_a_zone_invariant_unknown_not_holds():
    # the estate node may be in any declared zone: with a configured edge into the datastore, a zone
    # invariant whose source zone could include it cannot say HOLDS (section 5.2: zone invariants read UNKNOWN)
    g = graph([dnode("web1", "web", fact("both")), estate_node(), dnode("db", "data", fact("in"))],
              [edge(ESTATE, "db", "5432", "tcp", "configured")])
    r = evaluate(plan(frm="{ zone: web }", to="{ zone: data }"), g, NOW)
    assert r.verdict is Verdict.UNKNOWN and r.verdict is not Verdict.HOLDS
    assert r.reasons[0] == "possible_via_zone_unknown"
    assert r.witnesses and any(h.src == ESTATE for h in r.witnesses[0].hops)


@pytest.mark.parametrize("kind", ["host", "estates", "Estate", "cloud_lb"])
def test_only_the_exact_estate_kind_is_pseudo(kind):
    # a node of any other kind with the same (blind) shape still counts in the coverage universe
    g = graph([dnode("internet", "internet", kind="internet"), estate_node(kind=kind),
               dnode("db", "data", fact("in"))], [])
    r = evaluate(plan(), g, NOW)
    assert r.coverage_universe == 2     # db and the look-alike; the internet is the only pseudo node


def test_the_library_version_that_knows_the_estate_kind_is_0_4_0_everywhere():
    # the orchestrator pins ``paddock-assurance>=0.4.0`` (D38) because an older library counts an estate node in the
    # coverage ratio: the package and the module must agree on the number that carries the estate kind
    import pathlib
    import re
    import paddock_assurance
    pyproject = (pathlib.Path(__file__).resolve().parents[1] / "pyproject.toml").read_text()
    declared = re.search(r'^version = "([^"]+)"', pyproject, re.M).group(1)
    assert paddock_assurance.__version__ == declared == "0.4.0"
