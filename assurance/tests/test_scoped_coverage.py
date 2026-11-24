"""Origin- and protocol-qualified coverage (added by the P1 verification pass).

An outside-in TCP port scan proves what the *internet* can reach over TCP. It says nothing about
connections from inside the estate, or over UDP. If the library read it as plain inbound coverage,
an internal source -> scanned host edge would be "ruled out" and a guest-to-POS invariant could
HOLD on evidence that never looked at the guest network. Each test here fails if a qualified fact
is read wider than it speaks.
"""
import pytest

from paddock_assurance import GraphError, ReachGraph, Verdict, compile_text, evaluate

from helpers import FRESH, NOW, STALE, dnode, edge, fact, graph

TCP = "via: { protocols: [tcp] }\nevidence: { min_tier: observed, max_age: 24h }\ncoverage: { require: 0 }"
ANY = "evidence: { min_tier: observed, max_age: 24h }\ncoverage: { require: 0 }"


def scan_fact(seen=FRESH, **kw):
    return {**fact("in", "observed", seen, "external_scan"), "origin": "internet", "proto": "tcp", **kw}


def plan(src_zone, dst_zone, extra):
    return compile_text(f"""
apiVersion: paddock.dev/invariant/v1
id: acme:x-cannot-reach-y
title: x cannot reach y
severity: high
subjects:
  from: {{ zone: {src_zone} }}
  to: {{ zone: {dst_zone} }}
assert: unreachable
{extra}
""")


def world(*target_facts, lan_known=True):
    """internet, one LAN host and the scanned target. With ``lan_known`` the LAN host is covered
    inbound (nothing unknown can reach it from the internet), so any route to h1 is a direct one."""
    inet = dnode("internet", "internet")
    inside = dnode("lan1", "lan", *([fact("in")] if lan_known else []))
    return graph([inet, inside, dnode("h1", "dmz", *target_facts)], [])


def test_scan_coverage_rules_out_the_internet_over_tcp():
    r = evaluate(plan("internet", "dmz", TCP), world(scan_fact()), NOW)
    assert r.verdict is Verdict.HOLDS


def test_scan_coverage_does_not_rule_out_an_internal_source():
    # THE soundness case: lan1 -> h1 is unknown, the scan never looked from inside.
    r = evaluate(plan("lan", "dmz", TCP), world(scan_fact()), NOW)
    assert r.verdict is Verdict.UNKNOWN and r.reasons == ["possible_via_unknown_edges"]


def test_scan_coverage_does_not_rule_out_udp_or_icmp():
    # default protocols are icmp, tcp, udp: a TCP scan cannot speak for the other two.
    r = evaluate(plan("internet", "dmz", ANY), world(scan_fact()), NOW)
    assert r.verdict is Verdict.UNKNOWN


def test_a_plain_inbound_fact_still_covers_everything():
    plain = fact("in", "observed")
    assert evaluate(plan("lan", "dmz", ANY), world(plain), NOW).verdict is Verdict.HOLDS
    assert evaluate(plan("internet", "dmz", ANY), world(plain), NOW).verdict is Verdict.HOLDS


def test_unqualified_fact_wins_when_both_exist_and_scan_alone_does_not_count_as_covered():
    g = world(scan_fact())
    r = evaluate(plan("internet", "dmz", TCP), g, NOW)
    # covered for the internet only: the node is still a blind spot for the coverage count
    assert r.coverage_covered == 0
    assert any(b.node == "h1" and b.direction in ("in", "both") for b in r.blind_spots)


def test_expiry_comes_from_the_scan_fact_the_verdict_rests_on():
    r = evaluate(plan("internet", "dmz", TCP), world(scan_fact(seen=FRESH)), NOW)
    assert r.verdict is Verdict.HOLDS
    assert r.valid_until is not None and r.evidence_tier.value == "observed"
    # and a stale scan no longer covers anything
    stale = evaluate(plan("internet", "dmz", TCP), world(scan_fact(seen=STALE)), NOW)
    assert stale.verdict is Verdict.UNKNOWN


def test_exposure_set_scan_coverage_only_counts_against_the_internet():
    expose = compile_text("""
apiVersion: paddock.dev/invariant/v1
id: acme:only-web
title: only web
subjects:
  from: { zone: internet }
assert: exposes-only
ports: [80, 443]
via: { protocols: [tcp] }
evidence: { min_tier: observed, max_age: 24h }
coverage: { require: 0 }
""")
    g = graph([dnode("internet", "internet"), dnode("h1", "dmz", scan_fact())], [edge("internet", "h1", "443")])
    assert evaluate(expose, g, NOW).verdict is Verdict.HOLDS
    lan = compile_text(expose_text_from("lan"))
    g2 = graph([dnode("lan1", "lan"), dnode("h1", "dmz", scan_fact())], [edge("lan1", "h1", "443")])
    assert evaluate(lan, g2, NOW).verdict is Verdict.UNKNOWN


def expose_text_from(zone):
    return f"""
apiVersion: paddock.dev/invariant/v1
id: acme:only-web-{zone}
title: only web
subjects:
  from: {{ zone: {zone} }}
assert: exposes-only
ports: [80, 443]
via: {{ protocols: [tcp] }}
evidence: {{ min_tier: observed, max_age: 24h }}
coverage: {{ require: 0 }}
"""


def test_assert_covered_does_not_accept_a_scoped_fact():
    cov = compile_text("""
apiVersion: paddock.dev/invariant/v1
id: acme:covered
title: covered
subjects:
  to: { zone: dmz }
assert: covered
evidence: { min_tier: observed, max_age: 24h }
""")
    g = graph([dnode("h1", "dmz", scan_fact(), fact("out"))], [])
    assert evaluate(cov, g, NOW).verdict is Verdict.VIOLATED


@pytest.mark.parametrize("bad", [
    {"origin": "lan"}, {"proto": "sctp"}, {"origin": "internet", "direction": "out"},
    {"origin": "internet", "direction": "both"},
])
def test_bad_qualifiers_are_rejected_not_ignored(bad):
    doc = {"version": 1, "nodes": [dnode("h1", "dmz", {**scan_fact(), **bad})], "edges": []}
    with pytest.raises(GraphError):
        ReachGraph.from_dict(doc)


def test_internet_reaches_the_target_through_a_blind_internal_host():
    # internet -> lan1 is possible (lan1 blind inbound) and lan1 -> h1 is possible (lan1 blind
    # outbound, h1 not covered against internal sources): a scan of h1 alone cannot exclude that.
    r = evaluate(plan("internet", "dmz", TCP), world(scan_fact(), lan_known=False), NOW)
    assert r.verdict is Verdict.UNKNOWN


def test_origin_alone_is_enough_to_keep_an_internal_source_unruled():
    # no proto qualifier: only the origin keeps lan1 -> h1 possible. The qualifier is *omitted*:
    # since the P1 hardening an explicit empty/falsy qualifier is a GraphError (it used to be read
    # as "unqualified", which silently widened a fact whose builder meant to restrict it).
    only_origin = scan_fact()
    del only_origin["proto"]
    assert evaluate(plan("lan", "dmz", TCP), world(only_origin), NOW).verdict is Verdict.UNKNOWN
    assert evaluate(plan("internet", "dmz", ANY), world(only_origin), NOW).verdict is Verdict.HOLDS


def test_proto_alone_limits_a_fact_to_those_protocols_for_every_source():
    tcp_only = {**fact("in", "observed"), "proto": "tcp"}
    assert evaluate(plan("lan", "dmz", TCP), world(tcp_only), NOW).verdict is Verdict.HOLDS
    assert evaluate(plan("lan", "dmz", ANY), world(tcp_only), NOW).verdict is Verdict.UNKNOWN


def test_the_internet_and_cidr_nodes_are_not_in_the_coverage_universe():
    # 19 covered hosts + the internet would otherwise be 19/20 = 0.95 exactly; 5 + 1 = 0.83. A
    # small estate must be able to meet a 0.95 floor when every real host is covered.
    hosts = [dnode(f"h{i}", "a" if i == 0 else "b", fact("both")) for i in range(5)]
    nodes = [dnode("internet", "internet"), *hosts]
    nodes[0] = {**nodes[0], "kind": "internet"}
    nodes.append({**dnode("cidr:10.0.0.0/8", None), "kind": "cidr"})
    r = evaluate(plan("a", "b", "evidence: { min_tier: observed, max_age: 24h }\ncoverage: { require: 0.95 }"),
                 graph(nodes, []), NOW)
    assert (r.coverage_covered, r.coverage_universe) == (5, 5)
    assert r.verdict is Verdict.HOLDS


def test_an_all_traffic_edge_counts_for_an_icmp_only_invariant():
    # AWS "-1" / "all traffic" is proto any and includes ICMP; skipping it for an icmp-only
    # invariant would turn a rule that admits ping into a HOLDS.
    icmp = plan("a", "b", "via: { protocols: [icmp] }\nevidence: { min_tier: observed, max_age: 24h }\n"
                          "coverage: { require: 0 }")
    g = graph([dnode("a1", "a", fact("both")), dnode("b1", "b", fact("both"))],
              [edge("a1", "b1", "1-65535", proto="any")])
    assert evaluate(icmp, g, NOW).verdict is Verdict.VIOLATED
