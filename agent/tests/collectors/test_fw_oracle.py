"""Independent brute-force packet-walk oracle for the firewall model.

The oracle never looks at the model's data structures. It takes a small ruleset description
(a list of dicts), evaluates concrete packets under real first-match semantics (jump/return,
base policy, several base chains ANDed, unknown conditions enumerated both ways), and checks
the model built from the *rendered* ``iptables-save`` text / ``nft -j`` JSON of the same ruleset:

* the model never says ``deny`` for a packet some assignment of the unknown conditions accepts;
* without opaque rules the walk is exactly the oracle's verdict;
* ``effective_default`` is drop/reject only if some base chain drops *every* packet that no
  conditional rule mentions (and such packets exist), and drops some new inbound TCP/UDP on every
  interface class; and an ``exact`` model contains no opaque rule that can accept.
"""
import itertools
import json
import random

import pytest

from paddock_agent.collectors import fwmodel as fw

SRC_VOCAB = ["10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24", "192.168.0.0/16", "192.0.2.0/24",
             "0.0.0.0/1", "128.0.0.0/1", "0.0.0.0/0"]
SRC_SAMPLES = ["10.1.2.3", "10.1.9.9", "10.9.9.9", "192.168.5.5", "192.0.2.9", "8.8.8.8", "200.1.1.1"]
PORT_VOCAB = [(22, 22), (80, 80), (443, 443), (8000, 8100), (1, 1023)]
PORT_SAMPLES = [1, 22, 23, 80, 81, 443, 444, 1024, 8000, 8101]
CT_ALL = ["new", "established", "related", "invalid", "untracked"]
CT_CHOICES = [["established", "related"], ["new"], ["invalid"], ["new", "untracked"], ["established"]]
IIF_SAMPLES = ["lo", "eth0", "eth1"]
PROTO_SAMPLES = ["tcp", "udp", "icmp", "gre"]


def nets(rule):
    import ipaddress
    return [ipaddress.ip_network(c) for c in rule["src"]]


# ------------------------------------------------------------------------ oracle
def trivially_all(rule):
    return rule["src"] is not None and "0.0.0.0/0" in rule["src"]


def conditional(rule):
    return bool(rule["iif"] or rule["proto"] or rule["dport"] or rule["ct"] or rule["opaque"]
                or (rule["src"] and not trivially_all(rule)))


def cond_true(rule, p, opaque_on):
    import ipaddress
    if rule["iif"] and p["iif"] != rule["iif"]:
        return False
    if rule["src"] and not trivially_all(rule):
        ip = ipaddress.ip_address(p["src"])
        if not any(ip in n for n in nets(rule)):
            return False
    if rule["proto"] and p["proto"] != rule["proto"]:
        return False
    if rule["dport"]:
        if p["proto"] not in ("tcp", "udp"):
            return False
        lo, hi = rule["dport"]
        if not lo <= p["dport"] <= hi:
            return False
    if rule["ct"] and p["ct"] not in rule["ct"]:
        return False
    if rule["opaque"] and not opaque_on[id(rule)]:
        return False
    return True


def walk_chain(chains, name, p, opaque_on, flag):
    """Return 'accept', 'drop' or None (fell off the end / returned)."""
    for rule in chains[name]:
        if not cond_true(rule, p, opaque_on):
            continue
        if conditional(rule):
            flag[0] = True
        act = rule["action"]
        if act in ("accept", "drop", "reject"):
            return "accept" if act == "accept" else "drop"
        if act == "return":
            return None
        v = walk_chain(chains, act[1], p, opaque_on, flag)
        if v is not None:
            return v
    return None


def chain_verdict(rs, base, p, opaque_on):
    flag = [False]
    v = walk_chain(rs["chains"], base["name"], p, opaque_on, flag)
    return (v if v is not None else base["policy"]), flag[0]


def reachable(rs):
    seen = set()
    work = [b["name"] for b in rs["bases"]]
    while work:
        n = work.pop()
        if n in seen:
            continue
        seen.add(n)
        work += [r["action"][1] for r in rs["chains"][n] if isinstance(r["action"], tuple)]
    return seen


def all_rules(rs):
    live = reachable(rs)
    return [r for name, rules in rs["chains"].items() if name in live for r in rules]


def assignments(rs):
    ops = [r for r in all_rules(rs) if r["opaque"]]
    for bits in itertools.product([False, True], repeat=len(ops)):
        yield dict((id(r), b) for r, b in zip(ops, bits))


def final_outcomes(rs, p):
    outs = set()
    for asg in assignments(rs):
        ok = all(chain_verdict(rs, b, p, asg)[0] == "accept" for b in rs["bases"])
        outs.add("accept" if ok else "drop")
    return outs


def all_packets():
    for src in SRC_SAMPLES:
        for proto in PROTO_SAMPLES:
            for dport in (PORT_SAMPLES if proto in ("tcp", "udp") else [None]):
                for ct in CT_ALL:
                    for iif in IIF_SAMPLES:
                        yield {"src": src, "proto": proto, "dport": dport, "ct": ct, "iif": iif}


def model_pkt(p):
    return {"src": p["src"], "proto": p["proto"], "dport": p["dport"], "ct": p["ct"], "iif": p["iif"],
            "dtype": "local"}


def residual_ok(rs, base):
    """(non-empty, all dropped) over the sample universe for one base chain, opaque rules off."""
    off = dict((id(r), False) for r in all_rules(rs) if r["opaque"])
    nonempty = True
    count = 0
    for p in all_packets():
        v, matched = chain_verdict(rs, base, p, off)
        if not matched:
            count += 1
            if v != "drop":
                return False, False
    nonempty = count > 0
    return nonempty, True


def acceptall_ok(rs, base, iif):
    """Some new inbound tcp/udp packet on ``iif`` is dropped by this chain (opaque rules off)."""
    off = dict((id(r), False) for r in all_rules(rs) if r["opaque"])
    for src in SRC_SAMPLES:
        for proto in ("tcp", "udp"):
            for dport in PORT_SAMPLES:
                p = {"src": src, "proto": proto, "dport": dport, "ct": "new", "iif": iif}
                if chain_verdict(rs, base, p, off)[0] == "drop":
                    return True
    return False


def opaque_can_accept(rs):
    """An opaque rule that is (or leads to) an accept."""
    def accepting(name, seen):
        if name in seen:
            return False
        for r in rs["chains"][name]:
            if r["action"] == "accept":
                return True
            if isinstance(r["action"], tuple) and accepting(r["action"][1], seen | {name}):
                return True
        return False
    for r in all_rules(rs):
        if not r["opaque"]:
            continue
        if r["action"] == "accept":
            return True
        if isinstance(r["action"], tuple) and accepting(r["action"][1], frozenset()):
            return True
    return False


# --------------------------------------------------------------------- generators
def gen_rule(rng, jumps):
    r = {"iif": None, "src": None, "proto": None, "dport": None, "ct": None, "opaque": False}
    if rng.random() < 0.9:  # 10% fully unconditional
        if rng.random() < 0.25:
            r["iif"] = rng.choice(["lo", "eth0"])
        if rng.random() < 0.40:
            r["src"] = rng.sample(SRC_VOCAB, rng.choice([1, 1, 2]))
        if rng.random() < 0.5:
            r["proto"] = rng.choice(["tcp", "udp", "tcp", "icmp"])
            if r["proto"] in ("tcp", "udp") and rng.random() < 0.55:
                r["dport"] = rng.choice(PORT_VOCAB)
        if rng.random() < 0.25:
            r["ct"] = rng.choice(CT_CHOICES)
    r["opaque"] = rng.random() < 0.08
    roll = rng.random()
    if roll < 0.40:
        r["action"] = "accept"
    elif roll < 0.62:
        r["action"] = "drop"
    elif roll < 0.68:
        r["action"] = "reject"
    elif roll < 0.76:
        r["action"] = "return"
    elif jumps:
        r["action"] = ("jump", rng.choice(jumps))
    else:
        r["action"] = "accept"
    return r


def gen_ruleset(rng, multi_base):
    users = ["c1", "c2"][:rng.randint(0, 2)]
    chains = {}
    n_base = 2 if multi_base and rng.random() < 0.5 else 1
    bases = []
    for i in range(n_base):
        name = "input" if i == 0 else "input2"
        bases.append({"name": name, "policy": rng.choice(["drop", "drop", "accept"])})
        chains[name] = [gen_rule(rng, users) for _ in range(rng.randint(0, 6))]
    for i, u in enumerate(users):
        chains[u] = [gen_rule(rng, users[i + 1:]) for _ in range(rng.randint(0, 3))]
    if rng.random() < 0.15:  # two halves that together cover every source
        chains["input"] += [dict(gen_rule(rng, []), iif=None, src=["0.0.0.0/1"], proto=None, dport=None,
                                 ct=None, opaque=False, action="accept"),
                            dict(gen_rule(rng, []), iif=None, src=["128.0.0.0/1"], proto=None, dport=None,
                                 ct=None, opaque=False, action="accept")]
    return {"bases": bases, "chains": chains}


# ----------------------------------------------------------------------- renderers
def ipt_text(rs):
    base = rs["bases"][0]
    out = ["*filter", ":INPUT %s [0:0]" % base["policy"].upper(), ":FORWARD ACCEPT [0:0]"]
    out += [":%s - [0:0]" % c for c in rs["chains"] if c not in ("input", "input2")]
    for name, rules in rs["chains"].items():
        if name == "input2":
            continue
        cname = "INPUT" if name == "input" else name
        for r in rules:
            parts = ["-A", cname]
            if r["iif"]:
                parts += ["-i", r["iif"]]
            if r["src"]:
                parts += ["-s", ",".join(r["src"])]
            if r["proto"]:
                parts += ["-p", r["proto"]]
                if r["dport"]:
                    parts += ["-m", r["proto"], "--dport", "%d:%d" % r["dport"]]
            if r["ct"]:
                parts += ["-m", "conntrack", "--ctstate", ",".join(c.upper() for c in r["ct"])]
            if r["opaque"]:
                parts += ["-m", "mark", "--mark", "0x1"]
            act = r["action"]
            tgt = {"accept": "ACCEPT", "drop": "DROP", "reject": "REJECT", "return": "RETURN"}.get(act) \
                if isinstance(act, str) else act[1]
            parts += ["-j", tgt]
            out.append(" ".join(parts))
    out.append("COMMIT")
    return "\n".join(out) + "\n"


def nft_obj(rs):
    def mt(left, right, op="=="):
        return {"match": {"op": op, "left": left, "right": right}}
    ents = [{"metainfo": {"version": "1.0.9", "json_schema_version": 1}},
            {"table": {"family": "inet", "name": "filter", "handle": 1}}]
    for i, b in enumerate(rs["bases"]):
        ents.append({"chain": {"family": "inet", "table": "filter", "name": b["name"], "type": "filter",
                               "hook": "input", "prio": i * 10, "policy": b["policy"]}})
    for c in rs["chains"]:
        if c not in ("input", "input2"):
            ents.append({"chain": {"family": "inet", "table": "filter", "name": c}})
    for name, rules in rs["chains"].items():
        for r in rules:
            ex = []
            if r["iif"]:
                ex.append(mt({"meta": {"key": "iifname"}}, r["iif"]))
            if r["src"]:
                pre = []
                for c in r["src"]:
                    a, l = c.split("/")
                    pre.append({"prefix": {"addr": a, "len": int(l)}})
                ex.append(mt({"payload": {"protocol": "ip", "field": "saddr"}},
                             pre[0] if len(pre) == 1 else {"set": pre}))
            if r["proto"]:
                if r["dport"]:
                    lo, hi = r["dport"]
                    ex.append(mt({"payload": {"protocol": r["proto"], "field": "dport"}},
                                 lo if lo == hi else {"range": [lo, hi]}))
                else:
                    ex.append(mt({"meta": {"key": "l4proto"}}, r["proto"]))
            if r["ct"]:
                ex.append(mt({"ct": {"key": "state"}}, r["ct"], "in"))
            if r["opaque"]:
                ex.append(mt({"meta": {"key": "mark"}}, 1))
            act = r["action"]
            if act == "accept":
                ex.append({"accept": None})
            elif act == "drop":
                ex.append({"drop": None})
            elif act == "reject":
                ex.append({"reject": {"type": "icmpx", "expr": "port-unreachable"}})
            elif act == "return":
                ex.append({"return": None})
            else:
                ex.append({"jump": {"target": act[1]}})
            ents.append({"rule": {"family": "inet", "table": "filter", "chain": name, "expr": ex}})
    return {"nftables": ents}


def models(rs):
    out = []
    if len(rs["bases"]) == 1:
        d = fw.parse_iptables_save(ipt_text(rs), 4, "legacy4")
        out.append(("iptables", fw.build_model(d, "legacy", [], False)))
    d = fw.normalise_nft(nft_obj(rs))
    out.append(("nft", fw.build_model(d, "nft", [], False)))
    return out


# --------------------------------------------------------------------------- tests
PACKETS = list(all_packets())


def check_walk(rs, label, model):
    fam = model["families"]["ip4"]
    sample = PACKETS if len(PACKETS) < 400 else random.Random(7).sample(PACKETS, 450)
    has_opaque = any(r["opaque"] for r in all_rules(rs))
    for p in sample:
        outs = final_outcomes(rs, p)
        got = fw.evaluate(fam, model_pkt(p))
        if got == "deny":
            assert "accept" not in outs, "FALSE DENY (%s) %r" % (label, p)
        if got == "allow":
            assert outs == {"accept"}, "FALSE ALLOW (%s) %r" % (label, p)
        if not has_opaque:
            assert got == ("allow" if outs == {"accept"} else "deny"), "inexact walk (%s) %r" % (label, p)


def check_default(rs, label, model):
    d = model["families"]["ip4"]["effective_default"]
    if d in ("drop", "reject"):
        good = False
        for b in rs["bases"]:
            nonempty, all_dropped = residual_ok(rs, b)
            if nonempty and all_dropped and all(acceptall_ok(rs, b, i) for i in ("eth0", "eth1")):
                good = True
        assert good, "UNSOUND default %s (%s)" % (d, label)
    if d == "accept":
        # accept is only reported when there is nothing denying the unmentioned packets
        assert all(final_outcomes(rs, p) for p in PACKETS[:1])
    if model["flat_view"]["confidence"] == "exact":
        assert not opaque_can_accept(rs), "exact model with an opaque accepting rule (%s)" % label


@pytest.mark.parametrize("seed", range(140))
def test_random_rulesets_against_the_oracle(seed):
    rng = random.Random(seed)
    rs = gen_ruleset(rng, multi_base=True)
    for label, model in models(rs):
        json.dumps(model)
        check_walk(rs, label, model)
        check_default(rs, label, model)


def test_oracle_is_not_vacuous():
    """The generator must exercise deny claims, accepts, opaque rules and coverage cases."""
    kinds = {"drop": 0, "accept": 0, "unknown": 0, "exact": 0, "approx": 0, "reject": 0}
    for seed in range(140):
        rs = gen_ruleset(random.Random(seed), multi_base=True)
        for _label, m in models(rs):
            kinds[m["families"]["ip4"]["effective_default"]] += 1
            kinds["exact" if m["flat_view"]["confidence"] == "exact" else "approx"] += 1
    assert kinds["drop"] >= 40 and kinds["accept"] >= 30 and kinds["unknown"] >= 10
    assert kinds["exact"] >= 60 and kinds["approx"] >= 15


def test_oracle_catches_a_false_deny_directly():
    """Self-check of the oracle: a hand-written wrong verdict must be flagged."""
    rs = {"bases": [{"name": "input", "policy": "drop"}],
          "chains": {"input": [{"iif": None, "src": None, "proto": "tcp", "dport": (22, 22), "ct": None,
                                "opaque": True, "action": "accept"}]}}
    p = {"src": "8.8.8.8", "proto": "tcp", "dport": 22, "ct": "new", "iif": "eth0"}
    assert final_outcomes(rs, p) == {"accept", "drop"}
    assert fw.evaluate(models(rs)[0][1]["families"]["ip4"], model_pkt(p)) == "maybe"


def test_partial_packets_are_sound_over_every_completion():
    rng = random.Random(99)
    for seed in range(40):
        rs = gen_ruleset(random.Random(1000 + seed), multi_base=False)
        for label, model in models(rs):
            fam = model["families"]["ip4"]
            for _ in range(12):
                full = rng.choice(PACKETS)
                part = dict(model_pkt(full))
                for k in rng.sample(["src", "proto", "dport", "ct", "iif"], rng.randint(1, 3)):
                    part[k] = None
                got = fw.evaluate(fam, part)
                comps = []
                for p in PACKETS:
                    if all(part.get(k) is None or part[k] == model_pkt(p)[k] for k in part):
                        comps.append(final_outcomes(rs, p))
                if got == "deny":
                    assert all("accept" not in c for c in comps), label
                if got == "allow":
                    assert all(c == {"accept"} for c in comps), label
