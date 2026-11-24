from paddock_assurance import Verdict, evaluate

from helpers import NOW, edge, expose, graph, node


def base_nodes(**kw):
    return [node("internet", "internet", kind="internet"), node("web", "dmz"), node("db", "prod"), *kw.get("extra", [])]


def test_only_allowed_ports_holds():
    g = graph(base_nodes(), [edge("internet", "web", "80,443")])
    assert evaluate(expose(), g, NOW).verdict is Verdict.HOLDS


def test_extra_port_violates_with_detail():
    g = graph(base_nodes(), [edge("internet", "web", "22,80,443")])
    r = evaluate(expose(), g, NOW)
    assert r.verdict is Verdict.VIOLATED
    w = r.witnesses[0]
    assert w.detail["disallowed_ports"] == "22" and w.hops[0].dst == "web"


def test_full_range_reports_everything_but_the_allowlist():
    g = graph(base_nodes(), [edge("internet", "web", "1-65535")])
    w = evaluate(expose(), g, NOW).witnesses[0]
    assert w.detail["disallowed_count"] == str(65535 - 2)
    assert w.detail["disallowed_ports"].startswith("1-79,81-442")


def test_internal_edges_are_not_exposure():
    g = graph(base_nodes(), [edge("web", "db", "5432")])
    assert evaluate(expose(), g, NOW).verdict is Verdict.HOLDS


def test_icmp_ignored_and_udp_counted():
    g = graph(base_nodes(), [edge("internet", "web", proto="icmp"), edge("internet", "web", "53", proto="udp")])
    r = evaluate(expose(), g, NOW)
    assert r.verdict is Verdict.VIOLATED and r.witnesses[0].hops[0].proto == "udp"
    only_tcp = expose("via: { protocols: [tcp] }\nevidence: { min_tier: observed }\ncoverage: { require: 0 }")
    assert evaluate(only_tcp, g, NOW).verdict is Verdict.HOLDS


def _allow(ports, expires="2026-12-31"):
    return (f"allow:\n  - to: {{ id: web }}\n    ports: {ports}\n    reason: bastion for ops team\n"
            f"    expires: {expires}\nevidence: {{ min_tier: observed }}\ncoverage: {{ require: 0 }}")


def test_scoped_exception_allows_only_its_ports():
    g = graph(base_nodes(), [edge("internet", "web", "22,80,443")])
    ok = evaluate(expose(_allow(22)), g, NOW)
    assert ok.verdict is Verdict.HOLDS and ok.exceptions_used[0]["ports"] == "22"
    g2 = graph(base_nodes(), [edge("internet", "web", "22,3389,80")])
    r = evaluate(expose(_allow(22)), g2, NOW)
    assert r.verdict is Verdict.VIOLATED and r.witnesses[0].detail["disallowed_ports"] == "3389"


def test_exception_for_another_host_does_not_apply():
    g = graph(base_nodes(), [edge("internet", "db", "22")])
    assert evaluate(expose(_allow(22)), g, NOW).verdict is Verdict.VIOLATED


def test_expired_exception_is_ignored():
    g = graph(base_nodes(), [edge("internet", "web", "22")])
    r = evaluate(expose(_allow(22, expires="2026-11-30")), g, NOW)
    assert r.verdict is Verdict.VIOLATED and len(r.expired_exceptions) == 1


def test_blind_pair_is_unknown_and_covered_internet_side_rules_it_out():
    both_blind = graph([node("internet", "internet", tier=None), node("web", "dmz", tier=None)], [])
    r = evaluate(expose(), both_blind, NOW)
    assert r.verdict is Verdict.UNKNOWN
    external_scan_covers = graph([node("internet", "internet"), node("web", "dmz", tier=None)], [])
    assert evaluate(expose(), external_scan_covers, NOW).verdict is Verdict.HOLDS


def test_no_internet_zone_is_unknown_not_a_pass():
    g = graph([node("web", "dmz")], [])
    assert evaluate(expose(), g, NOW).reasons[0] == "empty_selector:from"
