import ast
import json
import os

import pytest

from paddock_agent.collectors import fwmodel as fw
from paddock_agent.collectors import payload_bytes

from .helpers import fixture

U = "ubuntu2404/"
S = "synthetic/firewall/"
EXT = fw.IIF_EXTERNAL


def ipt(rules, policy="DROP", chains=(), fam=4, extra_tables="", v6=False, readable=None):
    """Model from a hand-written filter table (``rules`` is a list of ``-A`` lines)."""
    decl = "".join(":%s - [0:0]\n" % c for c in chains)
    text = "*filter\n:INPUT %s [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n%s%s\nCOMMIT\n%s" % (
        policy, decl, "\n".join(rules), extra_tables)
    d = fw.parse_iptables_save(text, fam, "legacy4" if fam == 4 else "legacy6")
    return fw.build_model(d, "legacy", [], v6, readable)


def default(model, fam="ip4"):
    return model["families"][fam]["effective_default"]


def conf(model):
    return model["flat_view"]["confidence"]


def pkt(**kw):
    p = {"src": "203.0.113.7", "proto": "tcp", "dport": 22, "ct": "new", "iif": EXT, "dtype": "local"}
    p.update(kw)
    return p


def nft_obj(chains, rules, sets=(), family="inet", table="filter"):
    ents = [{"metainfo": {"version": "1.0.9", "json_schema_version": 1}},
            {"table": {"family": family, "name": table, "handle": 1}}]
    for s in sets:
        ents.append({"set": dict(family=family, table=table, **s)})
    for c in chains:
        ents.append({"chain": dict(family=family, table=table, **c)})
    for chain, expr in rules:
        ents.append({"rule": {"family": family, "table": table, "chain": chain, "expr": expr}})
    return {"nftables": ents}


def nft_model(obj, v6=False):
    return fw.build_model(fw.normalise_nft(obj), "nft", [], v6)


def mt(left, right, op="=="):
    return {"match": {"op": op, "left": left, "right": right}}


PL = lambda p, f: {"payload": {"protocol": p, "field": f}}  # noqa: E731
META = lambda k: {"meta": {"key": k}}  # noqa: E731
CT = lambda k: {"ct": {"key": k}}  # noqa: E731
ACC, DRP = {"accept": None}, {"drop": None}
BASE = {"name": "input", "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}


# ----------------------------------------------------------- real captured rulesets
def test_real_nft_capture_normalised():
    m = fw.build_model(fw.normalise_nft(json.loads(fixture(U + "nft_json_unshare.json"))), "nft", [], False)
    c4 = m["families"]["ip4"]["chains"]
    assert [c["name"] for c in c4] == ["inet.filter.input"] and c4[0]["policy"] == "drop"
    rules = c4[0]["rules"]
    assert rules[0] == {"m": {"iif": "lo"}, "v": "accept"}
    assert rules[1]["m"] == {"ct": ["established", "related"]}
    assert rules[3]["m"] == {"src": ["10.0.0.0/8"], "proto": "tcp", "dport": [[22, 22]]}
    assert rules[4]["m"]["src"] == ["10.0.0.0/8", "192.168.1.0/24"]  # @trusted resolved
    assert rules[4]["m"]["dport"] == [[80, 80], [443, 443]]
    assert rules[5]["m"] == {"proto": "tcp", "dport": [[8000, 8100]]}
    assert rules[6] == {"m": {}, "v": "accept", "opaque_reason": "meta_mark"}
    assert rules[7] == {"m": {}, "v": "drop"}
    # the ip6-only rule is in ip6 only, and the ip-only ones are not
    r6 = m["families"]["ip6"]["chains"][0]["rules"]
    assert {"m": {"proto": "icmpv6"}, "v": "accept"} in r6
    assert not any("src" in r["m"] for r in r6)
    assert not any(r["m"].get("proto") == "icmpv6" for r in rules)
    assert default(m) == "drop" and default(m, "ip6") == "drop"
    assert conf(m) == "approximate" and "opaque_accept" in m["confidence_reasons"]
    assert m["other_hooks"] == ["forward"]


def test_real_iptables_capture_normalised():
    text = fixture(U + "iptables_save_unshare.txt").split("== iptables-save")[1].split("== iptables -S")[0]
    m = fw.build_model(fw.parse_iptables_save(text, 4, "legacy4"), "legacy", [], False)
    names = [c["name"] for c in m["families"]["ip4"]["chains"]]
    assert names == ["legacy4.filter.DOCKER-USER", "legacy4.filter.INPUT"]
    inp = [c for c in m["families"]["ip4"]["chains"] if c["base"]][0]["rules"]
    assert inp[3]["m"]["dport"] == [[80, 80], [443, 443]]  # multiport
    assert inp[4] == {"m": {"proto": "tcp"}, "v": "accept", "opaque_reason": "m_mark"}
    assert inp[5] == {"m": {}, "v": "jump:legacy4.filter.DOCKER-USER"}
    assert inp[6]["m"] == {"proto": "tcp", "dport": [[8000, 8100]]}  # comment ignored
    neg = inp[7]["m"]  # ! -s 192.0.2.0/24
    assert neg["proto"] == "udp" and neg["dport"] == [[53, 53]]
    ivs = fw._cidr_ivs(neg["src"])
    assert fw._in_iv(ivs, fw._ip_int("192.0.3.1")) and not fw._in_iv(ivs, fw._ip_int("192.0.2.77"))
    assert default(m) == "drop" and conf(m) == "approximate"


# ------------------------------------------------------------- frontends and stacks
def test_ufw_is_exact_default_deny_and_walks_correctly():
    d4 = fw.parse_iptables_save(fixture(S + "ufw_iptables_save.txt"), 4, "legacy4")
    d6 = fw.parse_iptables_save(fixture(S + "ufw6_ip6tables_save.txt"), 6, "legacy6")
    m = fw.build_model(fw.merge_dumps([d4, d6]), "legacy", [], True)
    assert conf(m) == "exact" and default(m) == "drop" and default(m, "ip6") == "drop"
    assert fw.default_inbound_all_families(m) == "deny"
    f4 = m["families"]["ip4"]
    assert fw.evaluate(f4, pkt(dport=22)) == "allow" and fw.evaluate(f4, pkt(dport=443)) == "allow"
    assert fw.evaluate(f4, pkt(dport=23)) == "deny"
    assert fw.evaluate(f4, pkt(dport=22, ct="invalid")) == "deny"
    assert fw.evaluate(f4, pkt(dport=9999, ct="established")) == "allow"
    assert fw.evaluate(f4, pkt(proto="icmp", dport=None, icmp=8)) == "allow"
    assert fw.evaluate(f4, pkt(proto="icmp", dport=None, icmp=13)) == "deny"
    assert fw.evaluate(m["families"]["ip6"], pkt(src="2001:db8::1", dport=443)) == "deny"
    assert fw.evaluate(m["families"]["ip6"], pkt(src="2001:db8::1", dport=22)) == "allow"


def test_ufw_with_ipv6_enabled_but_unread_is_unknown_not_deny():
    d4 = fw.parse_iptables_save(fixture(S + "ufw_iptables_save.txt"), 4, "legacy4")
    m = fw.build_model(d4, "legacy", [], True, {"ip4": True, "ip6": False})
    assert conf(m) == "unknown" and default(m) == "unknown" and default(m, "ip6") == "unknown"
    assert fw.default_inbound_all_families(m) == "unknown"


def test_ipv6_gap_is_allow_not_deny():
    d4 = fw.parse_iptables_save(fixture(S + "ufw_iptables_save.txt"), 4, "legacy4")
    m = fw.build_model(d4, "legacy", [], True)  # ip6 readable, no ip6 rules at all
    assert default(m) == "drop" and default(m, "ip6") == "accept"
    assert fw.default_inbound_all_families(m) == "allow"
    m = fw.build_model(d4, "legacy", [], False)  # IPv6 disabled: only ip4 counts
    assert fw.default_inbound_all_families(m) == "deny"


def test_firewalld_ends_in_a_terminal_reject_and_is_exact():
    m = nft_model(json.loads(fixture(S + "firewalld_nft.json")), v6=True)
    assert conf(m) == "exact"
    assert default(m) == "reject" and default(m, "ip6") == "reject"
    assert fw.default_inbound_all_families(m) == "deny"
    assert "assumes_no_dnat_without_rule" in m["opaque_features"]
    f = m["families"]["ip4"]
    assert fw.evaluate(f, pkt(dport=22, iif="eth0")) == "allow"
    assert fw.evaluate(f, pkt(dport=80, iif="eth0")) == "deny"
    assert fw.evaluate(f, pkt(dport=80, iif="eth0", ct="established")) == "allow"
    assert fw.evaluate(f, pkt(dport=80, iif="lo")) == "allow"
    assert m["other_hooks"] == ["forward", "prerouting"]


def test_firewalld_with_a_dnat_rule_is_approximate():
    obj = json.loads(fixture(S + "firewalld_nft.json"))
    obj["nftables"].append({"rule": {"family": "inet", "table": "firewalld", "chain": "nat_PREROUTING",
                                     "expr": [mt(PL("tcp", "dport"), 8080), {"dnat": {"addr": "10.0.0.2", "port": 80}}]}})
    m = nft_model(obj, v6=True)
    assert conf(m) == "approximate" and "nat_rewrite" in m["confidence_reasons"]
    assert fw.default_inbound_all_families(m) == "unknown"
    assert m["opaque_features"] == ["nat_rewrite"]


def test_docker_dnat_makes_the_model_approximate():
    m = fw.build_model(fw.parse_iptables_save(fixture(S + "docker_iptables_save.txt"), 4, "legacy4"),
                       "legacy", [], False)
    assert conf(m) == "approximate" and "nat_rewrite" in m["confidence_reasons"]
    assert default(m) == "drop" and fw.default_inbound_all_families(m) == "unknown"


def test_kubernetes_dataplane_is_unknown_and_never_deny():
    m = fw.build_model(fw.parse_iptables_save(fixture(S + "k8s_iptables_save.txt"), 4, "legacy4"),
                       "legacy", [], False)
    assert conf(m) == "unknown" and m["dataplane"] == ["k8s"]
    assert default(m) == "unknown" and fw.default_inbound_all_families(m) == "unknown"


def test_open_firewall_is_accept_exact():
    m = fw.build_model(fw.parse_iptables_save(fixture(S + "legacy_open_iptables_save.txt"), 4, "legacy4"),
                       "legacy", [], False)
    assert default(m) == "accept" and conf(m) == "exact" and fw.default_inbound_all_families(m) == "allow"


def test_fail2ban_dynamic_set_beside_a_drop_chain():
    f2b = fw.normalise_nft(json.loads(fixture(S + "fail2ban_nft.json")))
    r = f2b["chains"]["inet.f2b-table.f2b-chain"]["rules"][0]
    assert r["v"] == "reject" and r["opaque_reason"] == "dynamic_set" and r["m"]["proto"] == "tcp"
    alone = fw.build_model(f2b, "nft", [], False)
    assert default(alone) == "accept" and conf(alone) == "exact"  # opaque *reject* cannot accept
    both = fw.merge_dumps([f2b, fw.parse_iptables_save(fixture(S + "ufw_iptables_save.txt"), 4, "legacy4")])
    m = fw.build_model(both, "mixed", [], False)
    assert default(m) == "drop" and conf(m) == "exact"
    assert fw.evaluate(m["families"]["ip4"], pkt(dport=22)) == "maybe"  # the opaque reject may drop it
    assert fw.evaluate(m["families"]["ip4"], pkt(dport=23)) == "deny"


# ---------------------------------------------------------- effective_default cases
@pytest.mark.parametrize("rules,policy,expect", [
    ([], "ACCEPT", "accept"),
    ([], "DROP", "drop"),
    (["-A INPUT -j DROP"], "ACCEPT", "drop"),
    (["-A INPUT -j REJECT --reject-with icmp-port-unreachable"], "ACCEPT", "reject"),
    (["-A INPUT -j ACCEPT", "-A INPUT -j DROP"], "DROP", "accept"),
    (["-A INPUT -s 0.0.0.0/0 -j ACCEPT"], "DROP", "accept"),
    (["-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT"], "DROP", "drop"),
    (["-A INPUT -p tcp -m tcp --dport 22 -j DROP"], "ACCEPT", "accept"),
    (["-A INPUT -m conntrack --ctstate INVALID -j DROP"], "ACCEPT", "accept"),
    (["-A INPUT -i lo -j ACCEPT", "-A INPUT -j DROP"], "ACCEPT", "drop"),
    (["-A INPUT -j LOG --log-prefix x", "-A INPUT -j DROP"], "ACCEPT", "drop"),
    (["-A INPUT -j RETURN", "-A INPUT -j DROP"], "ACCEPT", "accept"),
    (["-A INPUT -j RETURN"], "DROP", "drop"),
    (["-A INPUT -m conntrack --ctstate NEW,ESTABLISHED,RELATED,INVALID,UNTRACKED -j ACCEPT"], "DROP", "accept"),
    (["-A INPUT -m addrtype --dst-type LOCAL -j ACCEPT"], "DROP", "accept"),
    (["-A INPUT -m addrtype --dst-type MULTICAST -j ACCEPT"], "DROP", "drop"),
    (["-A INPUT -s 224.0.0.0/4 -j ACCEPT"], "DROP", "drop"),
    # coverage: the conditions together cover every packet that can arrive
    (["-A INPUT -s 0.0.0.0/1 -j ACCEPT", "-A INPUT -s 128.0.0.0/1 -j ACCEPT"], "DROP", "unknown"),
    (["-A INPUT -p tcp -j ACCEPT", "-A INPUT -p udp -j ACCEPT"], "DROP", "unknown"),
    (["-A INPUT -p tcp -m tcp --dport 1:65535 -j ACCEPT", "-A INPUT -p udp -m udp --dport 1:65535 -j ACCEPT"],
     "DROP", "unknown"),
    (["-A INPUT -p tcp -m tcp --dport 1:1000 -j ACCEPT", "-A INPUT -p tcp -m tcp --dport 1001:65535 -j ACCEPT",
      "-A INPUT -p udp -j ACCEPT"], "DROP", "unknown"),
    (["-A INPUT -p tcp -j ACCEPT"], "DROP", "drop"),
    (["-A INPUT -i eth0 -j ACCEPT", "-A INPUT -i lo -j ACCEPT"], "DROP", "unknown"),
    (["-A INPUT -d 10.0.0.5/32 -j ACCEPT"], "DROP", "unknown"),
    (["-A INPUT -s 10.0.0.0/8 -j ACCEPT", "-A INPUT -s 192.168.0.0/16 -j ACCEPT"], "DROP", "drop"),
    (["-A INPUT -m conntrack --ctstate NEW -j ACCEPT", "-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED,INVALID,UNTRACKED -j ACCEPT"],
     "DROP", "unknown"),
    # an unconditional action we cannot interpret is never a drop
    (["-A INPUT -j NFQUEUE --queue-num 3"], "DROP", "unknown"),
    (["-A INPUT -j MISSINGCHAIN"], "DROP", "unknown"),
])
def test_effective_default_table(rules, policy, expect):
    assert default(ipt(rules, policy)) == expect


def test_jump_return_and_user_chain_semantics():
    assert default(ipt(["-A INPUT -j SUB"], "DROP", ["SUB"])) == "drop"
    assert default(ipt(["-A INPUT -j SUB", "-A SUB -j RETURN"], "DROP", ["SUB"])) == "drop"
    assert default(ipt(["-A INPUT -j SUB", "-A SUB -j ACCEPT"], "DROP", ["SUB"])) == "accept"
    assert default(ipt(["-A INPUT -j SUB", "-A INPUT -j DROP"], "ACCEPT", ["SUB"])) == "drop"  # jump returns
    assert default(ipt(["-A INPUT -p tcp -j SUB", "-A SUB -j ACCEPT"], "DROP", ["SUB"])) == "drop"  # conditional jump


def test_goto_does_not_return_to_the_caller():
    base = [{"name": "input", "type": "filter", "hook": "input", "prio": 0, "policy": "accept"},
            {"name": "sub"}]
    jump = nft_model(nft_obj(base, [("input", [{"jump": {"target": "sub"}}]), ("input", [DRP])]))
    goto = nft_model(nft_obj(base, [("input", [{"goto": {"target": "sub"}}]), ("input", [DRP])]))
    assert default(jump) == "drop"      # sub ends, control returns, the drop fires
    assert default(goto) == "accept"    # sub ends, the base policy applies, the drop never fires
    assert fw.evaluate(goto["families"]["ip4"], pkt()) == "allow"
    assert fw.evaluate(jump["families"]["ip4"], pkt()) == "deny"


def test_multiple_base_chains_and_together():
    mk = lambda pol, rules=(): {"name": "n", "type": "filter", "hook": "input", "prio": 0, "policy": pol}  # noqa: E731
    chains = [dict(mk("accept"), name="a"), dict(mk("drop"), name="b", prio=10)]
    m = nft_model(nft_obj(chains, [("b", [mt(META("iifname"), "lo"), ACC])]))
    assert default(m) == "drop"                       # chain b yields drop even though chain a accepts
    assert fw.evaluate(m["families"]["ip4"], pkt()) == "deny"
    assert fw.evaluate(m["families"]["ip4"], pkt(iif="lo")) == "allow"
    both_accept = nft_model(nft_obj([dict(mk("accept"), name="a"), dict(mk("accept"), name="b")], []))
    assert default(both_accept) == "accept"
    assert default(nft_model(nft_obj([], []))) == "accept"


def test_jump_depth_cycle_and_unresolved_are_approximate_never_deny_claims():
    chains = ["C%d" % i for i in range(12)]
    rules = ["-A INPUT -j C0"] + ["-A C%d -j C%d" % (i, i + 1) for i in range(11)]
    deep = ipt(rules, "DROP", chains)
    assert default(deep) == "unknown" and conf(deep) == "approximate" and "jump_depth" in deep["confidence_reasons"]
    shallow = ipt(["-A INPUT -j C0", "-A C0 -j C1", "-A C1 -j C2"], "DROP", ["C0", "C1", "C2"])
    assert default(shallow) == "drop" and conf(shallow) == "exact"
    cyc = ipt(["-A INPUT -j A", "-A A -j B", "-A B -j A"], "DROP", ["A", "B"])
    assert default(cyc) == "unknown" and conf(cyc) == "approximate"
    miss = ipt(["-A INPUT -j NOPE"], "DROP")
    assert conf(miss) == "approximate" and "unresolved_jump" in miss["confidence_reasons"]
    assert fw.evaluate(miss["families"]["ip4"], pkt()) == "maybe"


# ---------------------------------------------------------------------- confidence
def test_confidence_rules_for_opaque_rules():
    assert conf(ipt(["-A INPUT -p tcp -m mark --mark 1 -j ACCEPT"])) == "approximate"
    assert conf(ipt(["-A INPUT -m set --match-set s src -j ACCEPT"])) == "approximate"
    assert conf(ipt(["-A INPUT -m owner --uid-owner 0 -j ACCEPT"])) == "approximate"
    assert conf(ipt(["-A INPUT -m limit --limit 1/s -j ACCEPT"])) == "approximate"
    assert conf(ipt(["-A INPUT -p tcp -m tcp --tcp-flags SYN,ACK SYN -j ACCEPT"])) == "approximate"
    assert conf(ipt(["-A INPUT -j TPROXY --on-port 3128"])) == "approximate"
    assert conf(ipt(["-A INPUT -j NFQUEUE --queue-num 1"])) == "approximate"
    # opaque conditions that can only restrict (drop/reject/return) do not weaken an exact model
    assert conf(ipt(["-A INPUT -m recent --rcheck --seconds 60 -j DROP"])) == "exact"
    assert conf(ipt(["-A INPUT -m set --match-set bad src -j REJECT"])) == "exact"
    # but an opaque jump into something that can accept does
    assert conf(ipt(["-A INPUT -m mark --mark 1 -j SUB", "-A SUB -p tcp -m tcp --dport 22 -j ACCEPT"],
                    "DROP", ["SUB"])) == "approximate"
    assert conf(ipt(["-A INPUT -m mark --mark 1 -j SUB", "-A SUB -j DROP"], "DROP", ["SUB"])) == "exact"
    assert conf(ipt(["-A INPUT -m mark --mark 1 -j SUB", "-A SUB -j RETURN"], "DROP", ["SUB"])) == "exact"


def test_opaque_rules_only_widen_deny_to_maybe_in_the_walk():
    m = ipt(["-A INPUT -m mark --mark 1 -j ACCEPT"])
    assert fw.evaluate(m["families"]["ip4"], pkt()) == "maybe"
    m = ipt(["-A INPUT -m mark --mark 1 -j DROP"], "ACCEPT")
    assert fw.evaluate(m["families"]["ip4"], pkt()) == "maybe"
    m = ipt(["-A INPUT -m mark --mark 1 -j ACCEPT", "-A INPUT -j ACCEPT"], "DROP")
    assert fw.evaluate(m["families"]["ip4"], pkt()) == "allow"


def test_nat_rewrite_detected_in_any_table_and_by_ipvs_flag():
    nat = "*nat\n:PREROUTING ACCEPT [0:0]\n-A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8080\nCOMMIT\n"
    assert conf(ipt([], extra_tables=nat)) == "approximate"
    mangle = "*mangle\n:PREROUTING ACCEPT [0:0]\n-A PREROUTING -p tcp -j TPROXY --on-port 1\nCOMMIT\n"
    assert conf(ipt([], extra_tables=mangle)) == "approximate"
    masq = "*nat\n:POSTROUTING ACCEPT [0:0]\n-A POSTROUTING -j MASQUERADE\nCOMMIT\n"
    assert conf(ipt([], extra_tables=masq)) == "exact"
    d = fw.parse_iptables_save("*filter\n:INPUT DROP [0:0]\nCOMMIT\n", 4, "legacy4")
    d["nat_rewrite"] = True
    assert conf(fw.build_model(d, "legacy", [], False)) == "approximate"


def test_unreadable_or_unparsed_input_is_unknown():
    m = ipt([], readable={"ip4": False})
    assert conf(m) == "unknown" and default(m) == "unknown"
    d = fw.parse_iptables_save('*filter\n:INPUT DROP [0:0]\n-A INPUT -m comment --comment "oops -j ACCEPT\nCOMMIT\n', 4, "legacy4")
    assert d["problems"] and conf(fw.build_model(d, "legacy", [], False)) == "unknown"


def test_ct_status_dnat_rule_dropped_only_without_rewriting():
    base = [{"name": "input", "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}]
    rule = [mt(CT("status"), "dnat", "in"), ACC]
    m = nft_model(nft_obj(base, [("input", rule)]))
    assert m["families"]["ip4"]["chains"][0]["rules"] == [] and conf(m) == "exact"
    assert m["opaque_features"] == ["assumes_no_dnat_without_rule"]
    with_nat = nft_model(nft_obj(base, [("input", rule), ("input", [mt(PL("tcp", "dport"), 1), {"redirect": {"port": 2}}])]))
    assert with_nat["families"]["ip4"]["chains"][0]["rules"][0]["opaque_reason"] == "ct_status_dnat"
    assert conf(with_nat) == "approximate"


# ----------------------------------------------------------- iptables-save parsing
def test_iptables_matchers_and_negations():
    m = ipt(["-A INPUT -s 10.0.0.0/8,192.168.0.0/16 -p tcp -m multiport --dports 22,8000:8010 -j ACCEPT",
             "-A INPUT ! -s 10.0.0.0/8 -p tcp -m tcp ! --dport 22 -j DROP",
             "-A INPUT -p tcp -m state --state NEW -m comment --comment \"a b -j ACCEPT\" -j ACCEPT",
             "-A INPUT -p icmp -m icmp --icmp-type echo-request -j ACCEPT",
             "-A INPUT -i eth+ -j ACCEPT",
             "-A INPUT ! -i eth0 -j DROP",
             "-A INPUT ! -p tcp -j DROP",
             "-A INPUT -f -j DROP",
             "-A INPUT -g SUB",
             "-A INPUT -m udp -p udp --sport 67 --dport 68 -j ACCEPT",
             "-A INPUT -m conntrack ! --ctstate NEW -j DROP"],
            "DROP", ["SUB"])
    r = [c for c in m["families"]["ip4"]["chains"] if c["base"]][0]["rules"]
    assert r[0]["m"]["src"] == ["10.0.0.0/8", "192.168.0.0/16"] and r[0]["m"]["dport"] == [[22, 22], [8000, 8010]]
    assert "src" in r[1]["m"] and r[1]["m"]["dport"] == [[0, 21], [23, 65535]] and r[1]["v"] == "drop"
    assert r[2] == {"m": {"proto": "tcp", "ct": ["new"]}, "v": "accept"}
    assert r[3]["m"] == {"proto": "icmp", "icmp": [8]}
    assert r[4]["opaque_reason"] == "iif_pattern"
    assert r[5]["opaque_reason"] == "negated_iif"
    assert r[6]["opaque_reason"] == "negated_proto"
    assert r[7]["opaque_reason"] == "fragment"
    assert r[8]["v"] == "goto:legacy4.filter.SUB"
    assert r[9]["m"] == {"proto": "udp", "sport": [[67, 67]], "dport": [[68, 68]]}
    assert r[10]["m"] == {"ct": ["established", "invalid", "related", "untracked"]}


def test_iptables_ipv6_rules():
    m = ipt(["-A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 135 -j ACCEPT", "-A INPUT -s 2001:db8::/32 -p tcp -m tcp --dport 22 -j ACCEPT",
             "-A INPUT -p icmp -j ACCEPT"], fam=6, v6=True)
    r = m["families"]["ip6"]["chains"][0]["rules"]
    assert r[0]["m"] == {"proto": "icmpv6", "icmp": [135]}
    assert r[1]["m"]["src"] == ["2001:db8::/32"]
    assert len(r) == 2  # `-p icmp` can never match IPv6: dropped
    assert m["families"]["ip4"]["chains"] == []


def test_tables_other_than_filter_input_are_not_modelled_but_noted():
    m = ipt(["-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT"], extra_tables="*mangle\n:INPUT ACCEPT [0:0]\n-A INPUT -j DROP\nCOMMIT\n")
    assert default(m) == "drop" and m["rule_count"] == 1
    assert m["other_hooks"] == ["forward"]


# ---------------------------------------------------------------- nft parsing
def test_nft_matchers():
    ch = [{"name": "input", "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}, {"name": "sub"}]
    rules = [
        ("input", [mt(PL("ip", "saddr"), {"prefix": {"addr": "10.0.0.0", "len": 8}}, "!="), ACC]),
        ("input", [mt(PL("tcp", "dport"), 1023, ">"), ACC]),
        ("input", [mt(CT("state"), "established", "!="), DRP]),
        ("input", [mt(PL("tcp", "dport"), {"range": [1, 5]}, "!="), ACC]),
        ("input", [mt(META("iifname"), {"set": ["eth0", "eth1"]}), ACC]),
        ("input", [mt(META("iifname"), "eth*"), ACC]),
        ("input", [mt(PL("ip", "saddr"), {"set": ["1.1.1.1", {"range": ["1.1.1.5", "1.1.1.9"]}, {"prefix": {"addr": "9.0.0.0", "len": 8}}]}), ACC]),
        ("input", [{"counter": {"packets": 0, "bytes": 0}}]),
        ("input", [mt(META("nfproto"), "ipv6"), ACC]),
        ("input", [{"limit": {"rate": 5, "per": "second"}}, ACC]),
        ("input", [mt(PL("tcp", "dport"), "@nosuchset"), ACC]),
        ("input", [{"jump": {"target": "sub"}}]),
        ("input", [{"reject": {"type": "icmpx", "expr": "port-unreachable"}}]),
        ("sub", [mt(PL("icmp", "type"), {"set": ["echo-request", "destination-unreachable"]}), ACC]),
        ("sub", [mt(META("mark"), 5), DRP]),
        ("sub", [{"vmap": {"key": META("mark"), "data": {"set": []}}}]),
    ]
    m = nft_model(nft_obj(ch, rules))
    r4 = [c for c in m["families"]["ip4"]["chains"] if c["base"]][0]["rules"]
    assert "src" in r4[0]["m"] and fw._in_iv(fw._cidr_ivs(r4[0]["m"]["src"]), fw._ip_int("11.0.0.1"))
    assert r4[1]["m"]["dport"] == [[1024, 65535]]
    assert r4[2]["m"] == {"ct": ["invalid", "new", "related", "untracked"]} and r4[2]["v"] == "drop"
    assert r4[3]["m"]["dport"] == [[6, 65535]] or r4[3]["m"]["dport"] == [[0, 0], [6, 65535]]
    assert [x["m"]["iif"] for x in r4[4:6]] == ["eth0", "eth1"]  # set of names expands to exclusive rules
    assert r4[6]["opaque_reason"] == "iif_pattern"
    assert fw._cidr_ivs(r4[7]["m"]["src"]) == [(0x01010101, 0x01010101), (0x01010105, 0x01010109), (0x09000000, 0x09FFFFFF)]
    assert all("nfproto" not in str(x) for x in r4)
    assert r4[8]["opaque_reason"] == "limit" and r4[8]["v"] == "accept"
    assert r4[9]["opaque_reason"] == "unresolved_set"
    assert r4[10] == {"m": {}, "v": "jump:inet.filter.sub"} and r4[11] == {"m": {}, "v": "reject"}
    assert len(r4) == 12 and m["families"]["ip6"]["chains"][0]["rules"][7]["m"] == {}  # nfproto ipv6 only in ip6
    sub = [c for c in m["families"]["ip4"]["chains"] if c["name"].endswith(".sub")][0]["rules"]
    assert sub[0]["m"] == {"proto": "icmp", "icmp": [3, 8]}
    assert sub[1]["opaque_reason"] == "meta_mark" and sub[2]["v"] == "opaque"
    assert conf(m) == "approximate"


def test_nft_empty_and_dynamic_sets():
    ch = [{"name": "input", "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}]
    sets = [{"name": "empty", "type": "ipv4_addr", "flags": ["interval"]},
            {"name": "dyn", "type": "ipv4_addr", "flags": ["dynamic"], "elem": ["1.1.1.1"]},
            {"name": "ports", "type": "inet_service", "elem": [22, {"range": [8000, 8100]}]}]
    rules = [("input", [mt(PL("ip", "saddr"), "@empty"), ACC]), ("input", [mt(PL("ip", "saddr"), "@dyn"), ACC]),
             ("input", [mt(PL("tcp", "dport"), "@ports"), ACC])]
    r = nft_model(nft_obj(ch, rules, sets))["families"]["ip4"]["chains"][0]["rules"]
    assert len(r) == 2 and r[0]["opaque_reason"] == "dynamic_set" and r[1]["m"]["dport"] == [[22, 22], [8000, 8100]]


def test_nft_nat_notrack_xt_and_unknown_statements():
    ch = [{"name": "input", "type": "filter", "hook": "input", "prio": 0, "policy": "drop"},
          {"name": "pre", "type": "nat", "hook": "prerouting", "prio": -100, "policy": "accept"}]
    m = nft_model(nft_obj(ch, [("pre", [mt(PL("tcp", "dport"), 80), {"dnat": {"addr": "1.2.3.4"}}])]))
    assert conf(m) == "approximate" and "nat_rewrite" in m["confidence_reasons"]
    m = nft_model(nft_obj(ch, [("input", [{"notrack": None}])]))
    assert "notrack" in m["opaque_features"] and conf(m) == "approximate"
    m = nft_model(nft_obj(ch, [("input", [{"xt": {"type": "match", "name": "physdev"}}, ACC])]))
    assert m["families"]["ip4"]["chains"][0]["rules"][0]["opaque_reason"] == "xt_physdev" and conf(m) == "approximate"
    m = nft_model(nft_obj(ch, [("input", [{"somethingnew": {}}])]))
    assert m["families"]["ip4"]["chains"][0]["rules"][0]["v"] == "opaque" and default(m) == "unknown"
    assert fw.evaluate(m["families"]["ip4"], pkt()) == "maybe"


def test_nft_not_a_document_is_rejected():
    for bad in ({}, {"nftables": "x"}, [], "x"):
        with pytest.raises(fw.FwModelError):
            fw.normalise_nft(bad)


def test_non_inet_ip_families_and_other_hooks_are_skipped():
    obj = nft_obj([{"name": "in", "type": "filter", "hook": "ingress", "prio": 0, "policy": "accept"}], [], family="netdev")
    m = nft_model(obj)
    assert m["families"]["ip4"]["chains"] == [] and "netdev" in m["other_hooks"]
    obj = nft_obj([{"name": "in", "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}], [("in", [ACC])], family="ip")
    m = nft_model(obj, v6=True)
    assert default(m) == "accept" and default(m, "ip6") == "accept" and m["families"]["ip6"]["chains"] == []


# ---------------------------------------------------------------------- walker
def test_walker_unknown_attributes_and_interfaces():
    m = ipt(["-A INPUT -i lo -j ACCEPT", "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT"])
    f = m["families"]["ip4"]
    assert fw.evaluate(f, pkt(iif="lo", dport=9)) == "allow"
    assert fw.evaluate(f, pkt(iif=EXT, dport=9)) == "deny"     # external is never lo
    assert fw.evaluate(f, pkt(iif=None, dport=9)) == "maybe"   # unknown interface might be lo
    assert fw.evaluate(f, pkt(iif=EXT, dport=None)) == "maybe"
    assert fw.evaluate(f, pkt(iif=EXT, proto=None, dport=22)) == "maybe"
    assert fw.evaluate(f, {}) == "maybe"
    assert fw.evaluate(f, pkt(iif=EXT, proto="icmp", dport=None)) == "deny"  # icmp has no port


def test_walker_depth_limit_widens_to_maybe():
    chains = ["C%d" % i for i in range(12)]
    rules = ["-A INPUT -j C0"] + ["-A C%d -j C%d" % (i, i + 1) for i in range(11)]
    assert fw.evaluate(ipt(rules, "DROP", chains)["families"]["ip4"], pkt()) == "maybe"


def test_src_partition_covers_the_space_without_overlap():
    m = ipt(["-A INPUT -s 10.0.0.0/8 -j ACCEPT", "-A INPUT -s 10.1.0.0/16 -j DROP", "-A INPUT -s 192.0.2.0/24 -j ACCEPT"])
    atoms = fw.src_partition(m["families"]["ip4"], 4)
    total = 0
    for rep, cidrs in atoms:
        ivs = fw._cidr_ivs(cidrs)
        assert fw._in_iv(ivs, fw._ip_int(rep))
        total += sum(hi - lo + 1 for lo, hi in ivs)
    assert total == 1 << 32
    reps = [r for r, _ in atoms]
    assert "203.0.113.7" in reps and "10.255.255.1" in reps


# ------------------------------------------------------------------ model hygiene
def test_rule_cap():
    rules = ["-A INPUT -p tcp -m tcp --dport %d -j ACCEPT" % (i + 1) for i in range(2000)]
    assert ipt(rules)["rule_count"] == 2000
    with pytest.raises(fw.FwTooLarge):
        ipt(rules + ["-A INPUT -p tcp -m tcp --dport 9 -j DROP"])


def test_unreachable_chains_do_not_count_against_the_cap():
    rules = ["-A FORWARD -p tcp -m tcp --dport %d -j ACCEPT" % (i + 1) for i in range(3000)]
    assert ipt(rules, chains=["X"])["rule_count"] == 0


def test_model_is_json_deterministic_without_floats():
    a = ipt(fixture(S + "ufw_iptables_save.txt").splitlines()[0:0])
    for name in ("ufw_iptables_save.txt", "docker_iptables_save.txt"):
        d1 = fw.build_model(fw.parse_iptables_save(fixture(S + name), 4, "legacy4"), "legacy", [], False)
        d2 = fw.build_model(fw.parse_iptables_save(fixture(S + name), 4, "legacy4"), "legacy", [], False)
        assert payload_bytes(d1) == payload_bytes(d2)
    assert a["v"] == 1 and set(a) >= {"v", "backend", "frontends", "ipv6_enabled", "families", "flat_view"}
    assert set(a["flat_view"]) == {"default_input_policy", "rules", "confidence"}
    assert set(a["families"]["ip4"]) == {"read", "chains", "effective_default"}


def test_flat_view_is_informational_and_capped():
    m = ipt(["-A INPUT -s 10.0.0.0/8 -p tcp -m tcp --dport 22 -j ACCEPT", "-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT",
             "-A INPUT -m mark --mark 1 -j ACCEPT"])
    assert m["flat_view"]["rules"] == [
        {"src_cidr": "10.0.0.0/8", "proto": "tcp", "port_lo": 22, "port_hi": 22, "action": "accept"},
        {"src_cidr": "any", "proto": "tcp", "port_lo": 80, "port_hi": 80, "action": "accept"}]
    many = ipt(["-A INPUT -p tcp -m tcp --dport %d -j ACCEPT" % (i + 1) for i in range(500)])
    assert len(many["flat_view"]["rules"]) == 200


def test_fwmodel_is_dependency_free():
    path = os.path.join(os.path.dirname(fw.__file__), "fwmodel.py")
    tree = ast.parse(open(path).read())
    mods = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods |= set(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "fwmodel must not import sibling modules"
            mods.add((node.module or "").split(".")[0])
    assert mods <= {"functools", "ipaddress", "re", "shlex"}
