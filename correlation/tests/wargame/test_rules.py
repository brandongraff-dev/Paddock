"""Tests for the vendor-neutral rule solver (``app.engine.wargame.rules``).

Pure config-only reachability — no packets, no DB, no exploit. Covers
first-match ordering, deny-wins-by-order, default allow/deny, conditional
propagation, port/proto/CIDR match and non-match edges, IPv6, and the
representative-IP boundary approximation.
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
# boundary_permits (representative-IP)
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


def test_boundary_permits_any_representative_flow_opens_it():
    # Only the 10.9.0.0/24 dst is allowed; one allowed representative suffices.
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
    # One representative is a plain allow, another a conditional allow; the
    # plain (provable) allow must win so the boundary reads as proved-open.
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


def test_boundary_permits_conditional_when_only_conditional_matches():
    # The sole matching rule is a conditional deny: config cannot prove the
    # boundary closed, so it is reported allowed+conditional (never closed).
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
    assert d.allowed is True
    assert d.conditional is True
    assert d.matched_rule == "cond_deny"


def test_boundary_permits_no_cidrs_is_denied():
    rs = RuleSet(
        id="fw",
        rules=[_rule("a", Action.ALLOW, order=1)],
        default_action=Action.ALLOW,
    )
    d = rules.boundary_permits(rs, (), ("10.0.0.0/24",), None)
    assert d.allowed is False
    d2 = rules.boundary_permits(rs, ("10.0.0.0/24",), (), None)
    assert d2.allowed is False


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


def test_boundary_permits_none_port_uses_any_proto_port_zero():
    # With port=None the representative flow is proto ANY / port 0; a rule that
    # only allows a specific TCP port should NOT match it.
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
    assert d.allowed is False


def test_representative_ip_approximation_can_miss_subcidr_carveout():
    # Documented limitation: a deny carve-out that does NOT cover the
    # representative (first) host of the src block is missed, so the boundary
    # reads open. First host of 10.0.0.0/24 is 10.0.0.1 — the carve-out at
    # 10.0.0.128/25 does not touch it.
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
    # The representative host (10.0.0.1) is allowed; the carve-out is unseen.
    assert d.allowed is True
    assert d.matched_rule == "allow"


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
