"""Tests for the vendor-neutral rule solver (``app.engine.wargame.rules``).

Pure config-only reachability — no packets, no DB, no exploit. Covers
first-match ordering, deny-wins-by-order, default allow/deny, conditional
propagation, port/proto/CIDR match and non-match edges, IPv6, and the
exact header-space boundary decision (``boundary_permits``): every former
representative-host false-"closed" case, carve-outs, conditional
fall-through, the box cap, and a seeded property test against brute-force
:func:`rules.evaluate`.
"""
from __future__ import annotations

from app.engine.wargame import rules
from app.engine.wargame.model import (
    Action,
    Decision,
    PortRange,
    Proto,
    Rule,
    RuleSet,
)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _rule(
    rid: str,
    action: Action,
    order: int,
    src="0.0.0.0/0",
    dst="0.0.0.0/0",
    ports=(PortRange.any(),),
    conditional=False,
):
    return Rule(
        id=rid,
        action=action,
        order=order,
        src_cidrs=(src,) if isinstance(src, str) else tuple(src),
        dst_cidrs=(dst,) if isinstance(dst, str) else tuple(dst),
        ports=ports,
        conditional=conditional,
    )


# --------------------------------------------------------------------------
# first-match ordering
# --------------------------------------------------------------------------

def test_first_match_lower_order_wins():
    rs = RuleSet(
        id="fw",
        rules=[
            _rule("deny", Action.DENY, order=100),
            _rule("allow", Action.ALLOW, order=10),
        ],
        default_action=Action.DENY,
    )
    d = rules.evaluate(rs, "1.1.1.1", "2.2.2.2", Proto.TCP, 443)
    assert d.allowed is True
    assert d.matched_rule == "allow"
    assert d.conditional is False


def test_deny_wins_by_order():
    # A lower-order deny beats a higher-order allow for the same flow.
    rs = RuleSet(
        id="fw",
        rules=[
            _rule("deny", Action.DENY, order=5),
            _rule("allow", Action.ALLOW, order=10),
        ],
        default_action=Action.ALLOW,
    )
    d = rules.evaluate(rs, "1.1.1.1", "2.2.2.2", Proto.TCP, 443)
    assert d.allowed is False
    assert d.matched_rule == "deny"


def test_tie_broken_by_rule_id():
    # Equal order → stable tie-break by id ("aaa" < "zzz"), so "aaa" decides.
    rs = RuleSet(
        id="fw",
        rules=[
            _rule("zzz", Action.DENY, order=10),
            _rule("aaa", Action.ALLOW, order=10),
        ],
        default_action=Action.DENY,
    )
    d = rules.evaluate(rs, "1.1.1.1", "2.2.2.2", Proto.TCP, 443)
    assert d.matched_rule == "aaa"
    assert d.allowed is True


# --------------------------------------------------------------------------
# default action
# --------------------------------------------------------------------------

def test_default_deny_when_no_rule_matches():
    rs = RuleSet(
        id="fw",
        rules=[_rule("web", Action.ALLOW, order=1, dst="10.0.0.0/24")],
        default_action=Action.DENY,
    )
    d = rules.evaluate(rs, "1.1.1.1", "192.168.1.1", Proto.TCP, 443)
    assert d.allowed is False
    assert d.matched_rule is None
    assert d.conditional is False


def test_default_allow_when_no_rule_matches():
    rs = RuleSet(id="fw", rules=[], default_action=Action.ALLOW)
    d = rules.evaluate(rs, "1.1.1.1", "2.2.2.2", Proto.TCP, 443)
    assert d == Decision(allowed=True, matched_rule=None, conditional=False)


def test_permits_convenience():
    rs = RuleSet(
        id="fw",
        rules=[_rule("a", Action.ALLOW, order=1)],
        default_action=Action.DENY,
    )
    assert rules.permits(rs, "1.1.1.1", "2.2.2.2", Proto.TCP, 80) is True
    rs2 = RuleSet(id="fw2", rules=[], default_action=Action.DENY)
    assert rules.permits(rs2, "1.1.1.1", "2.2.2.2", Proto.TCP, 80) is False


# --------------------------------------------------------------------------
# conditional propagation
# --------------------------------------------------------------------------

def test_conditional_rule_sets_conditional_flag():
    rs = RuleSet(
        id="fw",
        rules=[_rule("appid", Action.ALLOW, order=1, conditional=True)],
        default_action=Action.DENY,
    )
    d = rules.evaluate(rs, "1.1.1.1", "2.2.2.2", Proto.TCP, 443)
    assert d.allowed is True
    assert d.conditional is True
    assert d.matched_rule == "appid"


def test_default_action_is_never_conditional():
    rs = RuleSet(id="fw", rules=[], default_action=Action.DENY)
    d = rules.evaluate(rs, "1.1.1.1", "2.2.2.2", Proto.TCP, 443)
    assert d.conditional is False


# --------------------------------------------------------------------------
# port / proto matching edges
# --------------------------------------------------------------------------

def test_port_in_range_matches_and_out_of_range_does_not():
    rs = RuleSet(
        id="fw",
        rules=[
            _rule(
                "https",
                Action.ALLOW,
                order=1,
                ports=(PortRange(Proto.TCP, 440, 450),),
            )
        ],
        default_action=Action.DENY,
    )
    assert rules.permits(rs, "1.1.1.1", "2.2.2.2", Proto.TCP, 443) is True
    assert rules.permits(rs, "1.1.1.1", "2.2.2.2", Proto.TCP, 439) is False
    assert rules.permits(rs, "1.1.1.1", "2.2.2.2", Proto.TCP, 451) is False


def test_proto_mismatch_does_not_match():
    rs = RuleSet(
        id="fw",
        rules=[
            _rule(
                "tcp443",
                Action.ALLOW,
                order=1,
                ports=(PortRange.single(Proto.TCP, 443),),
            )
        ],
        default_action=Action.DENY,
    )
    # UDP/443 must not match a TCP-only rule.
    assert rules.permits(rs, "1.1.1.1", "2.2.2.2", Proto.UDP, 443) is False
    assert rules.permits(rs, "1.1.1.1", "2.2.2.2", Proto.TCP, 443) is True


def test_proto_any_matches_any_proto():
    rs = RuleSet(
        id="fw",
        rules=[
            _rule(
                "anyproto",
                Action.ALLOW,
                order=1,
                ports=(PortRange.single(Proto.ANY, 53),),
            )
        ],
        default_action=Action.DENY,
    )
    assert rules.permits(rs, "1.1.1.1", "2.2.2.2", Proto.UDP, 53) is True
    assert rules.permits(rs, "1.1.1.1", "2.2.2.2", Proto.TCP, 53) is True


# --------------------------------------------------------------------------
# CIDR matching edges
# --------------------------------------------------------------------------

def test_src_and_dst_cidr_must_both_match():
    rs = RuleSet(
        id="fw",
        rules=[
            _rule(
                "scoped",
                Action.ALLOW,
                order=1,
                src="192.168.0.0/16",
                dst="10.0.0.0/8",
            )
        ],
        default_action=Action.DENY,
    )
    assert rules.permits(rs, "192.168.1.5", "10.1.2.3", Proto.TCP, 80) is True
    # src outside → no match → default deny
    assert rules.permits(rs, "172.16.0.1", "10.1.2.3", Proto.TCP, 80) is False
    # dst outside → no match → default deny
    assert rules.permits(rs, "192.168.1.5", "172.16.0.1", Proto.TCP, 80) is False


def test_bare_ip_treated_as_host():
    rs = RuleSet(
        id="fw",
        rules=[_rule("host", Action.ALLOW, order=1, src="10.0.0.5", dst="10.0.0.9")],
        default_action=Action.DENY,
    )
    assert rules.permits(rs, "10.0.0.5", "10.0.0.9", Proto.TCP, 22) is True
    assert rules.permits(rs, "10.0.0.6", "10.0.0.9", Proto.TCP, 22) is False


def test_ipv6_cidr_matching():
    rs = RuleSet(
        id="fw",
        rules=[
            _rule(
                "v6",
                Action.ALLOW,
                order=1,
                src="2001:db8::/32",
                dst="2001:db8:dead::/48",
            )
        ],
        default_action=Action.DENY,
    )
    assert rules.permits(rs, "2001:db8::1", "2001:db8:dead::5", Proto.TCP, 443) is True
    assert rules.permits(rs, "2001:dead::1", "2001:db8:dead::5", Proto.TCP, 443) is False


# --------------------------------------------------------------------------
# boundary_permits (exact)
# --------------------------------------------------------------------------

def test_boundary_permits_allowed():
    rs = RuleSet(
        id="fw",
        rules=[
            _rule(
                "to_cde",
                Action.ALLOW,
                order=1,
                src="0.0.0.0/0",
                dst="10.9.0.0/24",
                ports=(PortRange.single(Proto.TCP, 5432),),
            )
        ],
        default_action=Action.DENY,
    )
    d = rules.boundary_permits(
        rs, ("192.168.1.0/24",), ("10.9.0.0/24",), PortRange.single(Proto.TCP, 5432)
    )
    assert d.allowed is True
    assert d.conditional is False
    assert d.matched_rule == "to_cde"


def test_boundary_permits_denied():
    rs = RuleSet(id="fw", rules=[], default_action=Action.DENY)
    d = rules.boundary_permits(
        rs, ("192.168.1.0/24",), ("10.9.0.0/24",), PortRange.single(Proto.TCP, 5432)
    )
    assert d.allowed is False
    assert d.conditional is False


def test_boundary_permits_any_dst_cidr_opens_it():
    # Only the 10.9.0.0/24 dst is allowed; one allowed dst CIDR suffices.
    rs = RuleSet(
        id="fw",
        rules=[
            _rule("ok", Action.ALLOW, order=1, dst="10.9.0.0/24"),
        ],
        default_action=Action.DENY,
    )
    d = rules.boundary_permits(
        rs,
        ("192.168.1.0/24",),
        ("172.16.0.0/24", "10.9.0.0/24"),
        PortRange.any(),
    )
    assert d.allowed is True


def test_boundary_permits_prefers_non_conditional_allow():
    # One dst is a plain allow, another a conditional allow; the plain
    # (provable) allow must win so the boundary reads as proved-open.
    rs = RuleSet(
        id="fw",
        rules=[
            _rule("cond", Action.ALLOW, order=1, dst="10.0.0.0/24", conditional=True),
            _rule("plain", Action.ALLOW, order=2, dst="10.1.0.0/24"),
        ],
        default_action=Action.DENY,
    )
    d = rules.boundary_permits(
        rs, ("192.168.1.0/24",), ("10.0.0.0/24", "10.1.0.0/24"), PortRange.any()
    )
    assert d.allowed is True
    assert d.conditional is False
    assert d.matched_rule == "plain"


def test_boundary_permits_conditional_deny_then_default_deny_is_closed():
    # CHANGED EXPECTATION (precision, not soundness): this used to assert
    # allowed+conditional. The sole rule is a conditional deny and the
    # default is deny: whether or not the conditional deny really matches,
    # every flow ends in a deny, so the config proves the boundary closed.
    rs = RuleSet(
        id="fw",
        rules=[
            _rule("cond_deny", Action.DENY, order=1, dst="10.0.0.0/24", conditional=True),
        ],
        default_action=Action.DENY,
    )
    d = rules.boundary_permits(
        rs, ("192.168.1.0/24",), ("10.0.0.0/24",), PortRange.any()
    )
    assert d.allowed is False
    assert d.conditional is False


def test_boundary_permits_conditional_deny_then_allow_is_conditional():
    # A conditional deny in front of an allow: if the deny does not really
    # match, the allow admits the flow, so the boundary is possibly open.
    rs = RuleSet(
        id="fw",
        rules=[
            _rule("cond_deny", Action.DENY, order=1, dst="10.0.0.0/24", conditional=True),
            _rule("allow", Action.ALLOW, order=2, dst="10.0.0.0/24"),
        ],
        default_action=Action.DENY,
    )
    d = rules.boundary_permits(
        rs, ("192.168.1.0/24",), ("10.0.0.0/24",), PortRange.any()
    )
    assert d == Decision(allowed=True, matched_rule="allow", conditional=True)


def test_boundary_permits_conditional_deny_then_default_allow_is_conditional():
    rs = RuleSet(
        id="fw",
        rules=[_rule("cond_deny", Action.DENY, order=1, conditional=True)],
        default_action=Action.ALLOW,
    )
    d = rules.boundary_permits(rs, ("10.0.0.0/24",), ("10.1.0.0/24",), None)
    assert d.allowed is True and d.conditional is True


def test_boundary_permits_no_cidrs_is_unknown_never_closed():
    # CHANGED EXPECTATION (soundness fix): this used to assert allowed=False,
    # i.e. a governed boundary with an address-less side read as CLOSED even
    # though nothing was evaluated (here the rule set even allows all). An
    # unknown side is now possibly-open + conditional, never closed.
    rs = RuleSet(
        id="fw",
        rules=[_rule("a", Action.ALLOW, order=1)],
        default_action=Action.ALLOW,
    )
    d = rules.boundary_permits(rs, (), ("10.0.0.0/24",), None)
    assert d.allowed is True and d.conditional is True
    d2 = rules.boundary_permits(rs, ("10.0.0.0/24",), (), None)
    assert d2.allowed is True and d2.conditional is True
    # Even under a default-deny, empty rule set: unknown, not closed.
    empty = RuleSet(id="fw2", rules=[], default_action=Action.DENY)
    d3 = rules.boundary_permits(empty, (), (), None)
    assert d3.allowed is True and d3.conditional is True


def test_boundary_permits_handles_slash32_slash31_single_ip_and_ipv6():
    rs = RuleSet(
        id="fw",
        rules=[
            _rule("ok", Action.ALLOW, order=1, src="0.0.0.0/0", dst="0.0.0.0/0"),
            _rule("v6ok", Action.ALLOW, order=2, src="::/0", dst="::/0"),
        ],
        default_action=Action.DENY,
    )
    # /32, /31, bare IP, and IPv6 all resolve to a representative host.
    assert rules.boundary_permits(
        rs, ("10.0.0.5/32",), ("10.0.0.9/31",), None
    ).allowed is True
    assert rules.boundary_permits(
        rs, ("10.0.0.5",), ("10.0.0.9",), None
    ).allowed is True
    assert rules.boundary_permits(
        rs, ("2001:db8::/64",), ("2001:db8:1::/64",), None
    ).allowed is True


def test_boundary_permits_none_port_means_all_traffic():
    # CHANGED EXPECTATION (soundness fix): this used to assert allowed=False,
    # because port=None was tested as the single flow ANY/port 0. port=None
    # means *all* traffic, and tcp/443 is part of it, so the boundary is open.
    rs = RuleSet(
        id="fw",
        rules=[
            _rule(
                "only443",
                Action.ALLOW,
                order=1,
                ports=(PortRange.single(Proto.TCP, 443),),
            )
        ],
        default_action=Action.DENY,
    )
    d = rules.boundary_permits(rs, ("10.0.0.0/24",), ("10.1.0.0/24",), None)
    assert d == Decision(allowed=True, matched_rule="only443", conditional=False)


def test_deny_carveout_inside_allow_is_still_open():
    # A deny slice (10.0.0.128/25) inside an allowed /24: 10.0.0.0-127 still
    # gets through, so the boundary is open (exactly, not by sampling).
    rs = RuleSet(
        id="fw",
        rules=[
            _rule("carve", Action.DENY, order=1, src="10.0.0.128/25", dst="10.9.0.0/24"),
            _rule("allow", Action.ALLOW, order=2, src="10.0.0.0/24", dst="10.9.0.0/24"),
        ],
        default_action=Action.DENY,
    )
    d = rules.boundary_permits(
        rs, ("10.0.0.0/24",), ("10.9.0.0/24",), PortRange.any()
    )
    assert d == Decision(allowed=True, matched_rule="allow", conditional=False)
    # Querying only the carved-out half: closed, by the carve-out.
    d2 = rules.boundary_permits(
        rs, ("10.0.0.128/25",), ("10.9.0.0/24",), PortRange.any()
    )
    assert d2 == Decision(allowed=False, matched_rule="carve", conditional=False)


def test_determinism_same_input_same_output():
    rs = RuleSet(
        id="fw",
        rules=[
            _rule("a", Action.ALLOW, order=10, dst="10.0.0.0/24"),
            _rule("b", Action.DENY, order=5, dst="10.0.0.0/25"),
        ],
        default_action=Action.DENY,
    )
    first = rules.evaluate(rs, "1.1.1.1", "10.0.0.1", Proto.TCP, 80)
    for _ in range(5):
        assert rules.evaluate(rs, "1.1.1.1", "10.0.0.1", Proto.TCP, 80) == first


# --------------------------------------------------------------------------
# boundary_permits: former representative-host false-"closed" cases
# --------------------------------------------------------------------------

def test_false_closed_src_subcidr_allow_off_first_host():
    # Old solver tested only 10.0.0.1, which is denied, and said "closed";
    # but 10.0.0.200 is allowed by the /25.
    rs = RuleSet(
        id="fw",
        rules=[_rule("upper", Action.ALLOW, order=1, src="10.0.0.128/25", dst="10.9.0.0/24")],
        default_action=Action.DENY,
    )
    d = rules.boundary_permits(rs, ("10.0.0.0/24",), ("10.9.0.0/24",), PortRange.any())
    assert d == Decision(allowed=True, matched_rule="upper", conditional=False)
    # Cross-check the witness with the single-flow evaluator.
    assert rules.permits(rs, "10.0.0.200", "10.9.0.1", Proto.TCP, 1) is True
    assert rules.permits(rs, "10.0.0.1", "10.9.0.1", Proto.TCP, 1) is False


def test_false_closed_dst_subcidr_allow_off_first_host():
    rs = RuleSet(
        id="fw",
        rules=[_rule("one", Action.ALLOW, order=1, dst="10.9.0.77/32")],
        default_action=Action.DENY,
    )
    d = rules.boundary_permits(rs, ("192.168.0.0/16",), ("10.9.0.0/24",), None)
    assert d.allowed is True and d.conditional is False


def test_false_closed_port_range_low_port_only():
    # Old solver tested tcp/1 for a 1-65535 edge and said "closed".
    rs = RuleSet(
        id="fw",
        rules=[_rule("https", Action.ALLOW, order=1, ports=(PortRange.single(Proto.TCP, 443),))],
        default_action=Action.DENY,
    )
    d = rules.boundary_permits(
        rs, ("10.0.0.0/24",), ("10.1.0.0/24",), PortRange(Proto.TCP, 1, 65535)
    )
    assert d == Decision(allowed=True, matched_rule="https", conditional=False)


def test_false_closed_any_traffic_vs_tcp22_allow():
    # Old solver tested (ANY, 0) for port=None and said "closed".
    rs = RuleSet(
        id="fw",
        rules=[_rule("ssh", Action.ALLOW, order=1, ports=(PortRange.single(Proto.TCP, 22),))],
        default_action=Action.DENY,
    )
    d = rules.boundary_permits(rs, ("10.0.0.0/24",), ("10.1.0.0/24",), None)
    assert d == Decision(allowed=True, matched_rule="ssh", conditional=False)


def test_false_closed_unparsable_node_cidr_is_unknown():
    # Old solver skipped unparsable CIDRs, evaluated nothing, said "closed".
    rs = RuleSet(id="fw", rules=[_rule("a", Action.ALLOW, order=1)], default_action=Action.DENY)
    d = rules.boundary_permits(rs, ("web-tier",), ("10.1.0.0/24",), None)
    assert d.allowed is True and d.conditional is True
    # Even with a deny-everything rule set: we cannot place the node, so it
    # is unknown, never a closed proof.
    deny_all = RuleSet(id="fw", rules=[], default_action=Action.DENY)
    d2 = rules.boundary_permits(deny_all, ("10.0.0.0/33",), ("10.1.0.0/24",), None)
    assert d2.allowed is True and d2.conditional is True


def test_partly_unparsable_node_still_reports_proved_open():
    # The parsable part is proved open, so that wins over "unknown".
    rs = RuleSet(id="fw", rules=[_rule("a", Action.ALLOW, order=1)], default_action=Action.DENY)
    d = rules.boundary_permits(rs, ("junk", "10.0.0.0/24"), ("10.1.0.0/24",), None)
    assert d == Decision(allowed=True, matched_rule="a", conditional=False)


def test_governed_edge_with_addressless_node_is_traversable_conditional():
    # Reachability end-to-end: the hop must not be dropped as "closed".
    from app.engine.wargame import reachability
    from app.engine.wargame.model import Edge, EvidenceLabel, Node, NodeRole

    nodes = {
        "vendor": Node(id="vendor", role=NodeRole.ENTRY, cidrs=()),
        "db": Node(id="db", role=NodeRole.CROWN_JEWEL, cidrs=("10.9.0.0/24",)),
    }
    edges = [Edge(src="vendor", dst="db", rule_set_id="fw")]
    rs = {"fw": RuleSet(id="fw", rules=[], default_action=Action.DENY)}
    res = reachability.backward_reachability(nodes, edges, rs)
    assert ("vendor", "db") not in res.closed_pairs
    assert res.routes and EvidenceLabel.CONDITIONAL in res.routes[0].hops[0].labels


# --------------------------------------------------------------------------
# boundary_permits: carve-outs, ports, protocols
# --------------------------------------------------------------------------

def test_allow_slice_before_broad_deny_is_open():
    rs = RuleSet(
        id="fw",
        rules=[
            _rule("pin", Action.ALLOW, order=1, src="10.0.0.200/32", dst="10.9.0.0/24"),
            _rule("block", Action.DENY, order=2, src="10.0.0.0/24", dst="10.9.0.0/24"),
        ],
        default_action=Action.DENY,
    )
    d = rules.boundary_permits(rs, ("10.0.0.0/24",), ("10.9.0.0/24",), None)
    assert d == Decision(allowed=True, matched_rule="pin", conditional=False)


def test_allow_slice_shadowed_by_earlier_deny_is_closed():
    rs = RuleSet(
        id="fw",
        rules=[
            _rule("block", Action.DENY, order=1, src="10.0.0.0/24", dst="10.9.0.0/24"),
            _rule("pin", Action.ALLOW, order=2, src="10.0.0.200/32", dst="10.9.0.0/24"),
        ],
        default_action=Action.DENY,
    )
    d = rules.boundary_permits(rs, ("10.0.0.0/24",), ("10.9.0.0/24",), None)
    assert d == Decision(allowed=False, matched_rule="block", conditional=False)


def test_multiple_deny_slices_covering_whole_allow_is_closed():
    # Two /25 denies tile the /24, so the later allow is fully shadowed.
    rs = RuleSet(
        id="fw",
        rules=[
            _rule("lo", Action.DENY, order=1, src="10.0.0.0/25"),
            _rule("hi", Action.DENY, order=2, src="10.0.0.128/25"),
            _rule("all", Action.ALLOW, order=3),
        ],
        default_action=Action.DENY,
    )
    assert rules.boundary_permits(rs, ("10.0.0.0/24",), ("10.1.0.0/24",), None).allowed is False
    # Widen the source by one /24 and the allow is reachable again.
    d = rules.boundary_permits(rs, ("10.0.0.0/23",), ("10.1.0.0/24",), None)
    assert d == Decision(allowed=True, matched_rule="all", conditional=False)


def test_port_range_partial_overlap():
    query = PortRange(Proto.TCP, 400, 500)
    open_rs = RuleSet(
        id="fw",
        rules=[
            _rule("deny_low", Action.DENY, order=1, ports=(PortRange(Proto.TCP, 0, 449),)),
            _rule("allow_mid", Action.ALLOW, order=2, ports=(PortRange(Proto.TCP, 440, 460),)),
        ],
        default_action=Action.DENY,
    )
    d = rules.boundary_permits(open_rs, ("10.0.0.0/24",), ("10.1.0.0/24",), query)
    assert d == Decision(allowed=True, matched_rule="allow_mid", conditional=False)

    closed_rs = RuleSet(
        id="fw",
        rules=[
            _rule("deny_low", Action.DENY, order=1, ports=(PortRange(Proto.TCP, 0, 460),)),
            _rule("allow_mid", Action.ALLOW, order=2, ports=(PortRange(Proto.TCP, 440, 460),)),
            # Allows outside the query's port class never open it.
            _rule("allow_high", Action.ALLOW, order=3, ports=(PortRange(Proto.TCP, 501, 9000),)),
        ],
        default_action=Action.DENY,
    )
    d2 = rules.boundary_permits(closed_rs, ("10.0.0.0/24",), ("10.1.0.0/24",), query)
    assert d2 == Decision(allowed=False, matched_rule="deny_low", conditional=False)


def test_proto_any_query_vs_tcp_only_rules():
    udp_dns = RuleSet(
        id="fw",
        rules=[_rule("dns", Action.ALLOW, order=1, ports=(PortRange.single(Proto.UDP, 53),))],
        default_action=Action.DENY,
    )
    src, dst = ("10.0.0.0/24",), ("10.1.0.0/24",)
    # ANY/53 includes udp/53 → open; TCP/53 does not → closed.
    assert rules.boundary_permits(udp_dns, src, dst, PortRange.single(Proto.ANY, 53)).allowed is True
    assert rules.boundary_permits(udp_dns, src, dst, PortRange.single(Proto.TCP, 53)).allowed is False

    # A tcp-only deny does not close udp/icmp/other under an ANY query.
    tcp_deny = RuleSet(
        id="fw",
        rules=[
            _rule("no_tcp", Action.DENY, order=1, ports=(PortRange(Proto.TCP, 0, 65535),)),
            _rule("rest", Action.ALLOW, order=2),
        ],
        default_action=Action.DENY,
    )
    d = rules.boundary_permits(tcp_deny, src, dst, None)
    assert d == Decision(allowed=True, matched_rule="rest", conditional=False)
    assert rules.boundary_permits(tcp_deny, src, dst, PortRange(Proto.TCP, 0, 65535)).allowed is False


def test_other_ip_protocols_only_match_any_rules():
    # tcp, udp and icmp are each denied, but an ANY allow still admits other
    # IP protocols (GRE, ESP, ...), so all-traffic is open.
    rs = RuleSet(
        id="fw",
        rules=[
            _rule("t", Action.DENY, order=1, ports=(PortRange(Proto.TCP, 0, 65535),)),
            _rule("u", Action.DENY, order=2, ports=(PortRange(Proto.UDP, 0, 65535),)),
            _rule("i", Action.DENY, order=3, ports=(PortRange(Proto.ICMP, 0, 65535),)),
            _rule("ip", Action.ALLOW, order=4),
        ],
        default_action=Action.DENY,
    )
    d = rules.boundary_permits(rs, ("10.0.0.0/24",), ("10.1.0.0/24",), None)
    assert d == Decision(allowed=True, matched_rule="ip", conditional=False)
    # The same allow, tcp-only, leaves nothing open.
    rs.rules[-1] = _rule("ip", Action.ALLOW, order=4, ports=(PortRange(Proto.TCP, 0, 65535),))
    assert rules.boundary_permits(rs, ("10.0.0.0/24",), ("10.1.0.0/24",), None).allowed is False


def test_icmp_query_matches_parser_style_icmp_rule():
    rs = RuleSet(
        id="fw",
        rules=[_rule("ping", Action.ALLOW, order=1, ports=(PortRange(Proto.ICMP, 0, 65535),))],
        default_action=Action.DENY,
    )
    src, dst = ("10.0.0.0/24",), ("10.1.0.0/24",)
    assert rules.boundary_permits(rs, src, dst, PortRange(Proto.ICMP, 0, 65535)).allowed is True
    assert rules.boundary_permits(rs, src, dst, None).allowed is True
    assert rules.boundary_permits(rs, src, dst, PortRange.single(Proto.TCP, 443)).allowed is False


# --------------------------------------------------------------------------
# boundary_permits: IPv6 and address families
# --------------------------------------------------------------------------

def test_ipv6_carveout_and_subnet_allow():
    rs = RuleSet(
        id="fw",
        rules=[
            _rule("carve", Action.DENY, order=1, src="2001:db8::/33", dst="::/0"),
            _rule("allow", Action.ALLOW, order=2, src="2001:db8::/32", dst="::/0"),
        ],
        default_action=Action.DENY,
    )
    # 2001:db8:8000::/33 is outside the carve-out → open.
    d = rules.boundary_permits(rs, ("2001:db8::/32",), ("2001:db8:ffff::/48",), None)
    assert d == Decision(allowed=True, matched_rule="allow", conditional=False)
    d2 = rules.boundary_permits(rs, ("2001:db8::/34",), ("2001:db8:ffff::/48",), None)
    assert d2 == Decision(allowed=False, matched_rule="carve", conditional=False)


def test_families_never_cross():
    v6_only = RuleSet(
        id="fw", rules=[_rule("v6", Action.ALLOW, order=1, src="::/0", dst="::/0")],
        default_action=Action.DENY,
    )
    v4_only = RuleSet(
        id="fw", rules=[_rule("v4", Action.ALLOW, order=1)], default_action=Action.DENY,
    )
    # "::/0" covers IPv6 only, "0.0.0.0/0" IPv4 only.
    assert rules.boundary_permits(v6_only, ("10.0.0.0/8",), ("10.1.0.0/16",), None).allowed is False
    assert rules.boundary_permits(v4_only, ("2001:db8::/32",), ("2001:db8:1::/48",), None).allowed is False
    # A dual-stack node is open through whichever family is allowed.
    d = rules.boundary_permits(
        v6_only, ("10.0.0.0/8", "2001:db8::/32"), ("10.1.0.0/16", "2001:db8:1::/48"), None
    )
    assert d == Decision(allowed=True, matched_rule="v6", conditional=False)


# --------------------------------------------------------------------------
# boundary_permits: conditional rules
# --------------------------------------------------------------------------

def test_conditional_allow_is_conditional():
    rs = RuleSet(
        id="fw",
        rules=[_rule("appid", Action.ALLOW, order=1, conditional=True)],
        default_action=Action.DENY,
    )
    d = rules.boundary_permits(rs, ("10.0.0.0/24",), ("10.1.0.0/24",), None)
    assert d == Decision(allowed=True, matched_rule="appid", conditional=True)


def test_conditional_allow_then_plain_allow_same_space_is_conditional():
    # Every flow passes the conditional rule first, so no path is certain.
    rs = RuleSet(
        id="fw",
        rules=[
            _rule("appid", Action.ALLOW, order=1, conditional=True),
            _rule("plain", Action.ALLOW, order=2),
        ],
        default_action=Action.DENY,
    )
    d = rules.boundary_permits(rs, ("10.0.0.0/24",), ("10.1.0.0/24",), None)
    assert d.allowed is True and d.conditional is True


def test_certain_allow_beats_conditional():
    # The conditional rule only covers the lower half; the upper half reaches
    # the plain allow on a certain path.
    rs = RuleSet(
        id="fw",
        rules=[
            _rule("appid", Action.ALLOW, order=1, src="10.0.0.0/25", conditional=True),
            _rule("plain", Action.ALLOW, order=2, src="10.0.0.0/24"),
        ],
        default_action=Action.DENY,
    )
    d = rules.boundary_permits(rs, ("10.0.0.0/24",), ("10.1.0.0/24",), None)
    assert d == Decision(allowed=True, matched_rule="plain", conditional=False)


def test_conditional_deny_then_plain_deny_then_allow_is_closed():
    # The conditional deny's fall-through is caught by a definite deny before
    # the allow, so it is closed either way.
    rs = RuleSet(
        id="fw",
        rules=[
            _rule("fqdn_deny", Action.DENY, order=1, dst="10.1.0.0/24", conditional=True),
            _rule("deny", Action.DENY, order=2, dst="10.1.0.0/24"),
            _rule("allow", Action.ALLOW, order=3),
        ],
        default_action=Action.DENY,
    )
    d = rules.boundary_permits(rs, ("10.0.0.0/24",), ("10.1.0.0/24",), None)
    assert d.allowed is False and d.conditional is False


def test_unparsable_rule_cidr_allow_is_possibly_open():
    # Under evaluate() an unparsable CIDR never matches, so this allow would
    # be invisible; the boundary solver widens it to "any" + conditional.
    rs = RuleSet(
        id="fw",
        rules=[_rule("obj", Action.ALLOW, order=1, src="UNRESOLVED-OBJ")],
        default_action=Action.DENY,
    )
    d = rules.boundary_permits(rs, ("10.0.0.0/24",), ("10.1.0.0/24",), None)
    assert d == Decision(allowed=True, matched_rule="obj", conditional=True)
    # IPv6 too: the unparsable side widens to "any" in both families.
    rs6 = RuleSet(
        id="fw",
        rules=[_rule("obj", Action.ALLOW, order=1, src="UNRESOLVED-OBJ", dst="::/0")],
        default_action=Action.DENY,
    )
    d6 = rules.boundary_permits(rs6, ("2001:db8::/32",), ("2001:db8:1::/48",), None)
    assert d6.allowed is True and d6.conditional is True


def test_unparsable_rule_cidr_deny_falls_through():
    rs = RuleSet(
        id="fw",
        rules=[
            _rule("obj", Action.DENY, order=1, dst="bad/cidr"),
            _rule("allow", Action.ALLOW, order=2),
        ],
        default_action=Action.DENY,
    )
    d = rules.boundary_permits(rs, ("10.0.0.0/24",), ("10.1.0.0/24",), None)
    assert d == Decision(allowed=True, matched_rule="allow", conditional=True)


def test_rule_with_parsable_and_unparsable_cidrs_keeps_certain_part():
    # The parsable src is a definite match; only the rest is uncertain.
    rs = RuleSet(
        id="fw",
        rules=[_rule("mixed", Action.ALLOW, order=1, src=("10.0.0.0/24", "dyn-group"))],
        default_action=Action.DENY,
    )
    d = rules.boundary_permits(rs, ("10.0.0.0/24",), ("10.1.0.0/24",), None)
    assert d == Decision(allowed=True, matched_rule="mixed", conditional=False)
    d2 = rules.boundary_permits(rs, ("172.16.0.0/24",), ("10.1.0.0/24",), None)
    assert d2 == Decision(allowed=True, matched_rule="mixed", conditional=True)


# --------------------------------------------------------------------------
# boundary_permits: bounded work, sound fallback
# --------------------------------------------------------------------------

def _fragmenting_ruleset(n: int) -> RuleSet:
    # n single-host denies punch n holes in every dimension of the space.
    assert n <= 255
    rs_rules = [
        _rule(f"d{i:03d}", Action.DENY, order=i, src=f"10.0.{i}.1/32", dst=f"10.1.{i}.1/32",
              ports=(PortRange.single(Proto.TCP, 1000 + i),))
        for i in range(n)
    ]
    return RuleSet(id="fw", rules=rs_rules, default_action=Action.DENY)


def test_box_cap_falls_back_to_sound_unknown(monkeypatch):
    rs = _fragmenting_ruleset(40)
    src, dst = ("10.0.0.0/16",), ("10.1.0.0/16",)
    # Uncapped: every hole is a deny and the default is deny → closed.
    assert rules.boundary_permits(rs, src, dst, None).allowed is False
    monkeypatch.setattr(rules, "MAX_BOXES", 20)
    d = rules.boundary_permits(rs, src, dst, None)
    # Over budget: possibly open + conditional, NEVER closed.
    assert d == Decision(allowed=True, matched_rule=None, conditional=True)


def test_work_cap_falls_back_to_sound_unknown(monkeypatch):
    rs = _fragmenting_ruleset(40)
    monkeypatch.setattr(rules, "MAX_WORK", 50)
    d = rules.boundary_permits(rs, ("10.0.0.0/16",), ("10.1.0.0/16",), None)
    assert d.allowed is True and d.conditional is True


def test_query_cap_falls_back_to_sound_unknown(monkeypatch):
    monkeypatch.setattr(rules, "MAX_BOXES", 3)
    rs = RuleSet(id="fw", rules=[], default_action=Action.DENY)
    d = rules.boundary_permits(rs, ("10.0.0.0/24", "10.0.2.0/24"), ("10.1.0.0/24",), None)
    assert d.allowed is True and d.conditional is True


def test_many_rules_stay_fast_and_exact():
    # 250 disjoint /32 denies then an allow-all: open (most hosts get past).
    rs = _fragmenting_ruleset(250)
    rs.rules.append(_rule("all", Action.ALLOW, order=10_000))
    d = rules.boundary_permits(rs, ("10.0.0.0/16",), ("10.1.0.0/16",), None)
    assert d == Decision(allowed=True, matched_rule="all", conditional=False)


# --------------------------------------------------------------------------
# boundary_permits: seeded property test against brute-force evaluate()
# --------------------------------------------------------------------------

import ipaddress as _ipa  # noqa: E402
import itertools as _it  # noqa: E402
import random as _random  # noqa: E402

_PORT_PICKS = (0, 1, 22, 53, 80, 443, 1024, 8080, 65535)
_OTHER = "other"  # an IP protocol that only Proto.ANY rules match


def _rand_cidr(rng: _random.Random, base: str) -> str:
    net = _ipa.ip_network(base)
    if rng.random() < 0.1:
        return "0.0.0.0/0" if net.version == 4 else "::/0"
    extra = rng.randint(0, 4)  # /28../32 (or /124../128)
    sub = list(net.subnets(prefixlen_diff=extra))
    return str(rng.choice(sub))


def _rand_ports(rng: _random.Random) -> tuple[PortRange, ...]:
    out = []
    for _ in range(rng.randint(1, 2)):
        proto = rng.choice((Proto.TCP, Proto.UDP, Proto.ICMP, Proto.ANY))
        if proto is Proto.ICMP:
            # Parsers always widen ICMP to the full range.
            out.append(PortRange(Proto.ICMP, 0, 65535))
            continue
        a, b = sorted(rng.sample(_PORT_PICKS, 2))
        out.append(PortRange(proto, a, b))
    return tuple(out)


def _rand_case(rng: _random.Random):
    v6 = rng.random() < 0.25
    src_base = "2001:db8::/124" if v6 else "10.0.0.0/28"
    dst_base = "2001:db8::10/124" if v6 else "10.0.0.16/28"
    n_rules = rng.randint(1, 6)
    n_cond = 0
    rs_rules = []
    for i in range(n_rules):
        cond = n_cond < 2 and rng.random() < 0.5
        n_cond += cond
        # Conditional rules are often broad (an App-ID rule on a whole zone),
        # which is what makes them interact with the rest of the rule set.
        broad = cond and rng.random() < 0.5
        rs_rules.append(Rule(
            id=f"r{i}",
            action=rng.choice((Action.ALLOW, Action.DENY, Action.DENY)),
            order=rng.randint(1, 5),
            src_cidrs=(src_base,) if broad else tuple(
                _rand_cidr(rng, src_base) for _ in range(rng.randint(1, 2))),
            dst_cidrs=(dst_base,) if broad else tuple(
                _rand_cidr(rng, dst_base) for _ in range(rng.randint(1, 2))),
            ports=_rand_ports(rng),
            conditional=cond,
        ))
    rs = RuleSet(id="fw", rules=rs_rules,
                 default_action=rng.choice((Action.DENY,) * 4 + (Action.ALLOW,)))
    src_q = tuple(_rand_cidr(rng, src_base) for _ in range(rng.randint(1, 2)))
    dst_q = tuple(_rand_cidr(rng, dst_base) for _ in range(rng.randint(1, 2)))
    roll = rng.random()
    if roll < 0.3:
        port = None
    else:
        a, b = sorted(rng.sample(_PORT_PICKS, 2))
        port = PortRange(rng.choice((Proto.TCP, Proto.UDP, Proto.ICMP, Proto.ANY)), a, b)
    return rs, src_q, dst_q, port


def _critical(lo: int, hi: int, cuts) -> list[int]:
    """One representative per elementary segment of [lo, hi]: membership in
    every interval in ``cuts`` is constant between consecutive points."""
    pts = {lo}
    for a, b in cuts:
        for p in (a, b + 1):
            if lo <= p <= hi:
                pts.add(p)
    return sorted(pts)


def _addr_points(query: tuple[str, ...], rule_cidrs) -> list[str]:
    nets = [_ipa.ip_network(c) for c in rule_cidrs]
    out: set[str] = set()
    for q in query:
        qn = _ipa.ip_network(q)
        cuts = [(int(n.network_address), int(n.broadcast_address))
                for n in nets if n.version == qn.version]
        for p in _critical(int(qn.network_address), int(qn.broadcast_address), cuts):
            out.add(str(_ipa.ip_address(p) if qn.version == 4 else _ipa.IPv6Address(p)))
    return sorted(out)


def _flows(rs: RuleSet, src_q, dst_q, port):
    srcs = _addr_points(src_q, [c for r in rs.rules for c in r.src_cidrs])
    dsts = _addr_points(dst_q, [c for r in rs.rules for c in r.dst_cidrs])
    q_proto = Proto.ANY if port is None else port.proto
    lo, hi = (0, 65535) if port is None else (port.low, port.high)
    ports = _critical(lo, hi, [(pr.low, pr.high) for r in rs.rules for pr in r.ports])
    protos = ([Proto.TCP, Proto.UDP, Proto.ICMP, _OTHER]
              if q_proto is Proto.ANY else [q_proto])
    return list(_it.product(srcs, dsts, protos, ports))


def _for_proto(rule_list, proto):
    """Proto has no member for "some other IP protocol", which only a
    Proto.ANY rule matches; model it as TCP against just the ANY ranges."""
    if proto != _OTHER:
        return list(rule_list), proto
    reduced = [Rule(id=r.id, action=r.action, order=r.order, src_cidrs=r.src_cidrs,
                    dst_cidrs=r.dst_cidrs, conditional=r.conditional,
                    ports=tuple(pr for pr in r.ports if pr.proto is Proto.ANY))
               for r in rule_list]
    return reduced, Proto.TCP


def _world_eval(rs: RuleSet, world: frozenset, flow) -> Decision:
    """evaluate() in one 'world': conditional rules not in ``world`` are
    taken not to match."""
    s, d, proto, p = flow
    kept = [r for r in rs.rules if not r.conditional or r.id in world]
    kept, proto = _for_proto(kept, proto)
    return rules.evaluate(RuleSet(id=rs.id, rules=kept, default_action=rs.default_action),
                          s, d, proto, p)


def _conditional_matches(rs: RuleSet, flow) -> bool:
    s, d, proto, p = flow
    conds, proto = _for_proto([r for r in rs.rules if r.conditional], proto)
    return any(r.matches(s, d, proto, p) for r in conds)


def test_property_exact_matches_brute_force_evaluate():
    rng = _random.Random(0xC0FFEE)
    for case in range(80):
        rs, src_q, dst_q, port = _rand_case(rng)
        exact = rules.boundary_permits(rs, src_q, dst_q, port)
        cond_ids = sorted(r.id for r in rs.rules if r.conditional)
        worlds = [frozenset(c) for k in range(len(cond_ids) + 1)
                  for c in _it.combinations(cond_ids, k)]
        flows = _flows(rs, src_q, dst_q, port)

        possibly = False       # allowed in some world
        proved = False         # allowed in every world
        clean_allow = False    # allowed, and no conditional rule can match it
        cond_allow_hit = False  # evaluate() decides it by a conditional allow
        for f in flows:
            verdicts = [_world_eval(rs, w, f) for w in worlds]
            allowed = [v.allowed for v in verdicts]
            possibly |= any(allowed)
            proved |= all(allowed)
            full = verdicts[-1]  # the world where every conditional rule matches
            cond_allow_hit |= full.allowed and full.conditional
            if full.allowed and not _conditional_matches(rs, f):
                clean_allow = True

        ctx = (case, rs, src_q, dst_q, port, exact)
        # Exact on the allowed bit: open iff some flow is allowed in some world.
        assert exact.allowed == possibly, ctx
        # A non-conditional "open" must be witnessed by a flow open in every world.
        if exact.allowed and not exact.conditional:
            assert proved, ctx
        # A conditional allow some flow hits can never be reported closed.
        if cond_allow_hit:
            assert exact.allowed, ctx
        # Precision: a flow allowed with no conditional rule in play is proved.
        if clean_allow:
            assert exact == Decision(True, exact.matched_rule, False), ctx
        # Never a closed verdict labelled conditional.
        assert exact.allowed or not exact.conditional, ctx
