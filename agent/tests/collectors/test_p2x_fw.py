"""Regression tests for the P2 adversarial review (coll-2, 3, 4, 6, 7): the firewall model.

Every test asserts that an unsafe input does NOT produce a false deny/HOLDS (or hang).
"""
import json
import os
import subprocess
import sys

from paddock_agent.collectors import base, firewall, fwmodel as fw

from .helpers import FakeRunner, make_ctx, res
from .test_fwmodel import ACC, BASE, DRP, EXT, META, PL, CT, default, mt, nft_model, nft_obj, pkt

AGENT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
POLICY_ACCEPT = dict(BASE, policy="accept")


def _fams_rules(m, fam):
    return [r for c in m["families"][fam]["chains"] for r in c["rules"]]


# ------------------------------------------------------------------------- coll-2
def test_coll2_reject_with_icmpv6_is_ipv6_only():
    # `meta nfproto ipv6 reject` / `reject with icmpv6` in an inet table: `nft -j` prints only the
    # reject statement; the kernel never matches IPv4 against it.
    obj = nft_obj([POLICY_ACCEPT], [("input", [{"reject": {"type": "icmpv6", "expr": "port-unreachable"}}])])
    m = nft_model(obj, v6=True)
    assert not any(r["v"] == "reject" for r in _fams_rules(m, "ip4"))
    assert any(r["v"] == "reject" for r in _fams_rules(m, "ip6"))
    assert default(m, "ip4") == "accept"
    assert fw.default_inbound_all_families(m) == "allow"
    assert fw.evaluate(m["families"]["ip4"], pkt()) == "allow"


def test_coll2_reject_with_icmp_is_ipv4_only():
    obj = nft_obj([POLICY_ACCEPT], [("input", [{"reject": {"type": "icmp", "expr": "port-unreachable"}}])])
    m = nft_model(obj, v6=True)
    assert not any(r["v"] == "reject" for r in _fams_rules(m, "ip6"))
    assert default(m, "ip6") == "accept"
    assert fw.default_inbound_all_families(m) != "deny"


def test_coll2_family_neutral_rejects_stay_in_both_families():
    for rej in ({"reject": {"type": "icmpx", "expr": "port-unreachable"}}, {"reject": None}):
        m = nft_model(nft_obj([POLICY_ACCEPT], [("input", [rej])]), v6=True)
        assert default(m, "ip4") == "reject" and default(m, "ip6") == "reject"
    m = nft_model(nft_obj([POLICY_ACCEPT], [("input", [
        mt(META("l4proto"), "tcp"), {"reject": {"type": "tcp reset"}}])]), v6=True)
    assert [r["m"] for r in _fams_rules(m, "ip4")] == [{"proto": "tcp"}]


def test_coll2_unknown_reject_type_is_an_opaque_condition_not_unconditional():
    obj = nft_obj([POLICY_ACCEPT], [("input", [{"reject": {"type": "from-the-future"}}])])
    m = nft_model(obj, v6=True)
    assert all("opaque_reason" in r for r in _fams_rules(m, "ip4") if r["v"] == "reject")
    assert default(m, "ip4") != "reject" and fw.default_inbound_all_families(m) != "deny"


# ------------------------------------------------------------------------- coll-3
def test_coll3_conditional_return_in_policy_accept_chain_is_an_accept_path():
    obj = nft_obj([POLICY_ACCEPT], [("input", [mt(CT("state"), ["established", "related"]), ACC]),
                                    ("input", [mt(CT("state"), "new"), {"return": None}]),
                                    ("input", [DRP])])
    m = nft_model(obj)
    assert fw.evaluate(m["families"]["ip4"], pkt()) == "allow"          # the packet walk accepts
    assert default(m, "ip4") != "drop"                                   # so the default is not deny
    assert fw.default_inbound_all_families(m) != "deny"


def test_coll3_return_in_policy_drop_chain_is_still_default_deny():
    obj = nft_obj([BASE], [("input", [mt(CT("state"), "new"), {"return": None}]), ("input", [DRP])])
    m = nft_model(obj)
    assert default(m, "ip4") == "drop" and fw.default_inbound_all_families(m) == "deny"


def test_coll3_narrow_return_keeps_default_deny():
    obj = nft_obj([POLICY_ACCEPT], [("input", [mt(PL("tcp", "dport"), 22), {"return": None}]),
                                    ("input", [DRP])])
    m = nft_model(obj)
    assert default(m, "ip4") == "drop"


def test_coll3_goto_into_a_chain_that_falls_off_returns_to_the_accept_policy():
    obj = nft_obj([POLICY_ACCEPT, {"name": "side"}],
                  [("input", [mt(CT("state"), "new"), {"goto": {"target": "side"}}]),
                   ("input", [DRP]),
                   ("side", [mt(PL("tcp", "dport"), 9999), DRP])])
    m = nft_model(obj)
    assert fw.evaluate(m["families"]["ip4"], pkt()) == "allow"
    assert default(m, "ip4") != "drop" and fw.default_inbound_all_families(m) != "deny"


def test_coll3_opaque_return_in_a_policy_accept_base_chain_is_not_exact():
    obj = nft_obj([POLICY_ACCEPT], [("input", [mt(META("mark"), 5), {"return": None}]), ("input", [DRP])])
    m = nft_model(obj)
    assert m["flat_view"]["confidence"] != "exact"
    assert "opaque_return" in m["confidence_reasons"]
    assert fw.default_inbound_all_families(m) != "deny"


def test_coll3_unconditional_jump_to_a_terminating_chain_still_deny_exact():
    # firewalld/ufw style layouts must keep their exact default-deny
    obj = nft_obj([POLICY_ACCEPT, {"name": "zone"}],
                  [("input", [mt(CT("state"), ["established", "related"]), ACC]),
                   ("input", [{"jump": {"target": "zone"}}]),
                   ("zone", [mt(PL("tcp", "dport"), 22), ACC]),
                   ("zone", [{"reject": None}])])
    m = nft_model(obj)
    assert default(m, "ip4") == "reject" and m["flat_view"]["confidence"] == "exact"


def test_coll3_jump_into_a_chain_with_a_conditional_return_is_an_accept_path():
    # input: ... jump x ; x: ct state new return ; drop   -> new packets return to the caller, fall
    # off the base chain and are taken by the accept policy (the kernel connects).
    m = nft_model(nft_obj([POLICY_ACCEPT, {"name": "x"}],
                          [("input", [mt(CT("state"), ["established", "related"]), ACC]),
                           ("input", [{"jump": {"target": "x"}}]),
                           ("x", [mt(CT("state"), "new"), {"return": None}]),
                           ("x", [DRP])]))
    assert fw.evaluate(m["families"]["ip4"], pkt()) == "allow"
    assert default(m, "ip4") != "drop"
    assert fw.default_inbound_all_families(m) != "deny"


def test_coll3_goto_chain_that_jumps_to_a_returning_chain_is_an_accept_path():
    m = nft_model(nft_obj([POLICY_ACCEPT, {"name": "x"}, {"name": "y"}],
                          [("input", [mt(CT("state"), ["established", "related"]), ACC]),
                           ("input", [{"goto": {"target": "x"}}]),
                           ("x", [{"jump": {"target": "y"}}]),
                           ("y", [mt(CT("state"), "new"), {"return": None}]),
                           ("y", [DRP])]))
    assert fw.evaluate(m["families"]["ip4"], pkt()) == "allow"
    assert default(m, "ip4") != "drop"
    assert fw.default_inbound_all_families(m) != "deny"


def test_coll3_second_jump_into_a_returning_chain_is_an_accept_path():
    m = nft_model(nft_obj([POLICY_ACCEPT, {"name": "x"}, {"name": "y"}],
                          [("input", [mt(CT("state"), ["established", "related"]), ACC]),
                           ("input", [{"jump": {"target": "x"}}]),
                           ("input", [{"jump": {"target": "y"}}]),
                           ("x", [mt(PL("tcp", "dport"), 22), ACC]),
                           ("y", [mt(CT("state"), "new"), {"return": None}]),
                           ("y", [DRP])]))
    assert fw.evaluate(m["families"]["ip4"], pkt()) == "allow"
    assert default(m, "ip4") != "drop"
    assert fw.default_inbound_all_families(m) != "deny"


def test_coll3_conditional_goto_that_may_return_does_not_make_a_chain_terminating():
    m = nft_model(nft_obj([POLICY_ACCEPT, {"name": "x"}, {"name": "z"}],
                          [("input", [{"jump": {"target": "x"}}]),
                           ("x", [mt(PL("tcp", "dport"), 22), {"goto": {"target": "z"}}]),
                           ("x", [DRP]),
                           ("z", [mt(CT("state"), "new"), {"return": None}]),
                           ("z", [DRP])]))
    assert fw.evaluate(m["families"]["ip4"], pkt()) == "allow"
    assert default(m, "ip4") != "drop"


def test_coll3_nested_terminating_jumps_stay_deny_exact():
    # no return anywhere on the path: the firewalld-like nesting keeps its exact default-deny
    m = nft_model(nft_obj([POLICY_ACCEPT, {"name": "x"}, {"name": "y"}],
                          [("input", [mt(CT("state"), ["established", "related"]), ACC]),
                           ("input", [{"jump": {"target": "x"}}]),
                           ("x", [mt(PL("tcp", "dport"), 22), ACC]),
                           ("x", [{"jump": {"target": "y"}}]),
                           ("y", [mt(PL("tcp", "dport"), 80), ACC]),
                           ("y", [DRP])]))
    assert default(m, "ip4") == "drop" and m["flat_view"]["confidence"] == "exact"


# ------------------------------------------------------------------------- coll-4
def _fw_collect(tmp_path, files, nft_json=None):
    nft_json = nft_json or json.dumps({"nftables": [{"metainfo": {"version": "1.0.9", "json_schema_version": 1}}]})
    ctx = make_ctx(tmp_path, runner=FakeRunner({"nft": res(nft_json)}), files=files, bins=["/usr/sbin/nft"])
    sec = firewall.collect(ctx)
    base.validate_section(sec)
    return ctx, sec


GLOBAL6 = "20010db8000000000000000000000001 02 40 00 80 eth0\n"


def test_coll4_a_global_ipv6_address_wins_over_all_disable_ipv6(tmp_path):
    files = {"/proc/sys/net/ipv6/conf/all/disable_ipv6": "1\n", "/proc/net/if_inet6": GLOBAL6}
    ctx, sec = _fw_collect(tmp_path, files)
    assert firewall.ipv6_enabled(ctx) is True
    assert sec["v"]["ipv6_enabled"] is True


def test_coll4_unreadable_if_inet6_is_unknown_not_disabled(tmp_path):
    ctx = make_ctx(tmp_path, runner=FakeRunner({"nft": res('{"nftables": []}')}), bins=["/usr/sbin/nft"],
                   files={"/proc/sys/net/ipv6/conf/all/disable_ipv6": "1\n"})
    os.makedirs(os.path.join(ctx.proc_root, "net", "if_inet6"))      # reading it fails (EISDIR)
    assert firewall.ipv6_enabled(ctx) is None
    sec = firewall.collect(ctx)
    assert sec["s"] == "ok" and sec["v"]["flat_view"]["confidence"] == "unknown"
    assert "ipv6_state_unknown" in sec["v"]["confidence_reasons"]
    assert fw.default_inbound_all_families(sec["v"]) == "unknown"
    assert sec["v"]["ipv6_enabled"] is True                       # unknown is modelled as in scope


def test_coll4_truncated_if_inet6_is_unknown(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path, files={"/proc/net/if_inet6": GLOBAL6})
    real = ctx.read_text
    monkeypatch.setattr(ctx, "read_text", lambda p, m=1 << 20: ("truncated", "") if p.endswith("if_inet6") else real(p, m))
    assert firewall.ipv6_enabled(ctx) is None


def test_coll4_no_ipv6_stack_and_loopback_only_are_disabled(tmp_path):
    assert firewall.ipv6_enabled(make_ctx(tmp_path / "a")) is False
    lo = {"/proc/net/if_inet6": "00000000000000000000000000000001 01 80 10 80 lo\n"}
    assert firewall.ipv6_enabled(make_ctx(tmp_path / "b", files=lo)) is False
    # the stack exists (tcp6 present) but if_inet6 is gone: cannot tell
    assert firewall.ipv6_enabled(make_ctx(tmp_path / "c", files={"/proc/net/tcp6": "x\n"})) is None


# ------------------------------------------------------------------------- coll-6
_DOS = r"""
import json, sys, time
sys.path.insert(0, %(agent)r)
from paddock_agent.collectors import fwmodel as fw
width, depth = %(width)d, %(depth)d
ents = [{"table": {"family": "inet", "name": "f", "handle": 1}},
        {"chain": {"family": "inet", "table": "f", "name": "input", "type": "filter", "hook": "input",
                   "prio": 0, "policy": "drop"}}]
def rule(chain, expr):
    ents.append({"rule": {"family": "inet", "table": "f", "chain": chain, "expr": expr}})
rule("input", [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 22}}, {"accept": None}])
rule("input", [{"match": {"op": "==", "left": {"ct": {"key": "state"}}, "right": "new"}}, {"jump": {"target": "c0"}}])
for i in range(depth + 1):
    ents.append({"chain": {"family": "inet", "table": "f", "name": "c%%d" %% i}})
for i in range(depth):
    for k in range(width):
        rule("c%%d" %% i, [{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                                      "right": {"prefix": {"addr": "10.%%d.0.0" %% k, "len": 16}}}},
                           {"jump": {"target": "c%%d" %% (i + 1)}}])
rule("c%%d" %% depth, [{"counter": None}])
t = time.time()
try:
    m = fw.build_model(fw.normalise_nft({"nftables": ents}), "nft", [], True)
    print("done", m["flat_view"]["confidence"], m["families"]["ip4"]["effective_default"])
except fw.FwTooLarge as exc:
    print("toolarge", exc)
"""


def _run_dos(width, depth, limit=20):
    code = _DOS % {"agent": AGENT_DIR, "width": width, "depth": depth}
    return subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=limit)


def test_coll6_layered_conditional_jumps_finish_quickly_and_never_claim_exact_deny():
    r = _run_dos(6, 14)
    assert r.returncode == 0, r.stderr
    out = r.stdout.split()
    assert out[0] in ("done", "toolarge")
    if out[0] == "done":
        assert out[1] != "exact" or out[2] != "drop"     # too deep: approximate (jump_depth), never exact deny


def test_coll6_walk_budget_raises_fwtoolarge(monkeypatch):
    monkeypatch.setattr(fw, "WALK_BUDGET", 50)
    rules = [("input", [mt(PL("ip", "saddr"), {"prefix": {"addr": "10.%d.0.0" % k, "len": 16}}),
                        {"jump": {"target": "c0"}}]) for k in range(60)]
    obj = nft_obj([BASE, {"name": "c0"}], rules + [("c0", [ACC])])
    try:
        nft_model(obj)
    except fw.FwTooLarge:
        return
    raise AssertionError("a ruleset beyond the step budget must raise FwTooLarge")


def test_coll6_collector_maps_budget_to_truncated_error(tmp_path, monkeypatch):
    monkeypatch.setattr(fw, "WALK_BUDGET", 5)
    rules = [{"rule": {"family": "ip", "table": "f", "chain": "input", "expr": [
        {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 1000 + i}},
        {"accept": None}]}} for i in range(40)]
    obj = {"nftables": [{"table": {"family": "ip", "name": "f", "handle": 1}},
                        {"chain": {"family": "ip", "table": "f", "name": "input", "type": "filter",
                                   "hook": "input", "prio": 0, "policy": "drop"}}] + rules}
    ctx = make_ctx(tmp_path, runner=FakeRunner({"nft": res(json.dumps(obj))}), bins=["/usr/sbin/nft"])
    sec = firewall.collect(ctx)
    assert sec["s"] == "error" and sec["reason"] == "truncated"
    assert "budget" in sec["detail"]


# ------------------------------------------------------------------------- coll-7
def test_coll7_th_dport_alone_is_not_folded_into_port_protocols():
    # `th dport 53 accept` reads bytes 2-3 of ANY transport header (ICMP, GRE, ...)
    obj = nft_obj([BASE], [("input", [mt(PL("th", "dport"), 53), ACC])])
    m = nft_model(obj)
    f4 = m["families"]["ip4"]
    assert fw.evaluate(f4, pkt(proto="icmp", dport=None, icmp=8)) != "deny"
    assert fw.evaluate(f4, pkt(proto="gre", dport=None)) != "deny"
    assert m["flat_view"]["confidence"] != "exact"
    assert fw.default_inbound_all_families(m) != "deny"


def test_coll7_th_dport_after_an_l4proto_match_stays_precise():
    obj = nft_obj([BASE], [("input", [mt(META("l4proto"), {"set": ["tcp", "udp"]}), mt(PL("th", "dport"), 53), ACC])])
    m = nft_model(obj)
    rules = _fams_rules(m, "ip4")
    assert sorted((r["m"]["proto"], tuple(map(tuple, r["m"]["dport"]))) for r in rules) == [
        ("tcp", ((53, 53),)), ("udp", ((53, 53),))]
    assert all("opaque_reason" not in r for r in rules)
    assert fw.evaluate(m["families"]["ip4"], pkt(proto="tcp", dport=53)) == "allow"
    assert fw.evaluate(m["families"]["ip4"], pkt(proto="tcp", dport=54)) == "deny"


def test_coll7_ip6_nexthdr_drop_is_not_a_definite_drop_of_tcp():
    # matches only when TCP is the *immediate* next header: packets with extension headers bypass it
    obj = nft_obj([POLICY_ACCEPT], [("input", [mt(PL("ip6", "nexthdr"), "tcp"), DRP])])
    m = nft_model(obj, v6=True)
    f6 = m["families"]["ip6"]
    assert fw.evaluate(f6, pkt(src="2001:db8::7", proto="tcp", dport=22)) == "maybe"
    assert m["flat_view"]["confidence"] != "exact" or default(m, "ip6") == "accept"
    assert fw.default_inbound_all_families(m) != "deny"


def test_coll7_ip6_nexthdr_accept_is_still_safe_to_fold():
    obj = nft_obj([BASE], [("input", [mt(PL("ip6", "nexthdr"), "ipv6-icmp"), ACC])])
    m = nft_model(obj, v6=True)
    assert [r["m"] for r in _fams_rules(m, "ip6")] == [{"proto": "icmpv6"}]
    assert all("opaque_reason" not in r for r in _fams_rules(m, "ip6"))


def test_coll7_ip4_protocol_drop_is_unchanged():
    obj = nft_obj([POLICY_ACCEPT], [("input", [mt(PL("ip", "protocol"), "tcp"), DRP])])
    m = nft_model(obj)
    assert fw.evaluate(m["families"]["ip4"], pkt(proto="tcp", dport=22)) == "deny"
