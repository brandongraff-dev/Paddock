"""An independent brute-force oracle for host-config evaluation.

It shares NO code with the implementation under test: it reads the raw graph-document dicts (not
``HostFacts``), parses timestamps itself, extracts every field value with its own plain-Python code
and decides each host by *possible worlds*: every unknown leaf is tried as both true and false,
and the host is true iff all worlds are true, false iff all are false, else unknown. (For a formula
in which every leaf occurs once, that is exactly Kleene strong logic; the oracle never uses it.)
Random fact tables and random formulas come from one seeded generator.
"""
from __future__ import annotations

import datetime as dt
import itertools
import operator
import random
from typing import Any, Callable, Optional

from tests.hostfix import FRESH, NOW, fact, firewall, listeners, patch, sshd

MAX_AGE = dt.timedelta(hours=6)
SLACK = dt.timedelta(minutes=5)
RANK = {"declared": 0, "configured": 1, "observed": 2, "tested": 3}
OPS: dict[str, Callable[[Any, Any], bool]] = {
    "==": operator.eq, "!=": operator.ne, "<": operator.lt, "<=": operator.le,
    ">": operator.gt, ">=": operator.ge}


def iso(t: dt.datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def when(s: str) -> dt.datetime:
    return dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


# --------------------------------------------------------------------------------------------
# the oracle: usability, values, worlds

def usable(f: Optional[dict], now: dt.datetime, min_tier: str, max_age: dt.timedelta) -> bool:
    if f is None:
        return False
    if min(RANK[f["tier"]], RANK["configured"]) < RANK[min_tier]:
        return False
    if f["signed"] is not True:
        return False
    if f.get("conflict"):
        return False
    seen = when(f["observed_at"])
    if seen > now + SLACK:
        return False
    return not (now - seen > max_age)


def _yn(v: Any) -> Optional[bool]:
    if isinstance(v, str) and v.lower() in ("yes", "no"):
        return v.lower() == "yes"
    return None


def _worlds(vals: list) -> list[list[bool]]:
    """All assignments of True/False to the None entries of ``vals``."""
    idx = [i for i, v in enumerate(vals) if v is None]
    out = []
    for combo in itertools.product([True, False], repeat=len(idx)):
        w = list(vals)
        for i, c in zip(idx, combo):
            w[i] = c
        out.append(w)
    return out


def _tri_of_worlds(results: list[bool]) -> Optional[bool]:
    if all(results):
        return True
    if not any(results):
        return False
    return None


def _sshd_exact(f: dict) -> Optional[dict]:
    d = f["data"]
    if f["status"] != "ok" or f["conf"] != "exact" or f["partial"]:
        return None
    if d.get("source") == "text" or d.get("match", {}).get("unprobed") is not False:
        return None
    return d


def _pubkey_only(am: Any) -> Optional[bool]:
    if not isinstance(am, str) or not am.strip() or len(am.strip()) > 200:
        return None
    v = am.strip().lower()
    if v == "any":
        return False
    toks = [t for part in v.split() for t in part.split(",")]
    return all(t == "publickey" for t in toks)


def _variants(d: dict) -> list[dict]:
    out = [dict(d["config"])]
    for item in d["probes"]["deltas"]:
        c = dict(d["config"])
        for k, v in item["delta"].items():
            if v is None:
                c.pop(k, None)
            else:
                c[k] = v
        out.append(c)
    return out


def _password_possible(d: dict) -> Optional[bool]:
    per_variant = []
    for c in _variants(d):
        pw, kbd, pam = _yn(c.get("passwordauthentication")), _yn(c.get("kbdinteractiveauthentication")), _yn(c.get("usepam"))
        pk = _pubkey_only(c.get("authenticationmethods"))
        per_variant.append([pw, kbd, pam, None if pk is None else (not pk)])
    flat = [x for v in per_variant for x in v]
    results = []
    for w in _worlds(flat):
        any_possible = False
        for i in range(len(per_variant)):
            pw, kbd, pam, notpk = w[4 * i:4 * i + 4]
            if pw or (kbd and pam and notpk):
                any_possible = True
        results.append(any_possible)
    return _tri_of_worlds(results)


def _scalar_changed(d: dict, key: str) -> bool:
    return any(key in item["delta"] for item in d["probes"]["deltas"])


def field_value(field: str, params: tuple, raw: Optional[dict], now: dt.datetime, min_tier: str,
                max_age: dt.timedelta) -> Any:
    """The value of a field on a host, or ``None`` for unknown (the oracle never returns a
    Python ``None`` as a real value; every real value here is a bool, int or str)."""
    if raw is None:
        return None
    col = {"sshd": "sshd", "fw": "firewall", "listener": "listeners", "patch": "patch"}[field.split(".")[1]]
    f = raw.get(col)
    if not usable(f, now, min_tier, max_age):
        return None
    d = f["data"]
    name = field.split(".", 2)[2]
    if col == "sshd":
        if name == "installed":
            return _installed(raw, f, now, min_tier, max_age)
        ex = _sshd_exact(f)
        if ex is None:
            return None
        if name == "password_login_possible":
            return _password_possible(ex)
        if name == "maxauthtries":
            v = ex["config"].get("maxauthtries")
            if _scalar_changed(ex, name) or type(v) is not int or v < 0:
                return None
            return v
        if name in ("pubkeyauthentication", "permitrootlogin"):
            if _scalar_changed(ex, name):
                return None
            v = ex["config"].get(name)
            if not isinstance(v, str):
                return None
            v = v.lower()
            if name == "permitrootlogin":
                v = "prohibit-password" if v == "without-password" else v
                return v if v in ("yes", "no", "prohibit-password", "forced-commands-only") else None
            return v if v in ("yes", "no") else None
        raise AssertionError(field)
    if col == "firewall":
        if f["status"] != "ok":
            return None
        if name == "engine":
            if f["partial"]:             # an unread family: the whole firewall section is incomplete
                return None
            return d["backend"] if d.get("backend") in ("nft", "legacy", "mixed", "none") else None
        if f["conf"] != "exact" or f["partial"]:
            return None
        if d["flat_view"].get("confidence") != "exact" or d.get("dataplane") or d.get("opaque_features"):
            return None
        fams = ["ip4"] + (["ip6"] if d["ipv6_enabled"] else [])
        rows = [(d["families"][n]["read"] is True, d["families"][n]["effective_default"]) for n in fams]
        if any(v not in ("accept", "drop", "reject", "unknown") for _, v in rows):
            return None
        if all(r and v in ("drop", "reject") for r, v in rows):
            return "deny"
        if any(r and v == "accept" for r, v in rows):
            return "allow"
        return None
    if col == "listeners":
        if f["status"] != "ok":
            return None
        port = params[0]
        rows = d["listeners"]
        if any(r["port"] == port for r in rows):
            return True
        complete = (not f["partial"]) and f["conf"] == "exact" and d["count"] == len(rows)
        return False if complete else None
    if col == "patch":
        if f["status"] != "ok" or f["conf"] != "exact":
            return None
        blk = d["pending" if name == "security_updates_pending" else "reboot"]
        if blk.get("state") != "ok":
            return None
        v = blk.get("security" if name == "security_updates_pending" else "required")
        if name == "security_updates_pending":
            return v if type(v) is int and v >= 0 else None
        return v if isinstance(v, bool) else None
    raise AssertionError(field)


def _installed(raw: dict, f: dict, now: dt.datetime, min_tier: str, max_age: dt.timedelta) -> Any:
    if f["status"] == "ok":
        v = f["data"].get("installed")
        if v is True:
            return True
        if v is not False:
            return None
    elif not (f["status"] == "unavailable" and f.get("reason") == "tool_missing"):
        return None
    lf = raw.get("listeners")
    if lf is not None and lf["status"] == "ok":
        if any(r["port"] == 22 or r.get("comm") in ("sshd", "sshd-session", "dropbear")
               for r in lf["data"]["listeners"]):
            return None
    if lf is None or not usable(lf, now, min_tier, max_age) or lf["status"] != "ok" or lf["partial"]:
        return None
    if lf["data"]["count"] != len(lf["data"]["listeners"]):
        return None
    if lf["conf"] != "exact" or lf["data"]["attribution"]["status"] != "ok":
        return None
    return False


def consulted_facts(field: str, raw: Optional[dict]) -> list[dict]:
    """Every fact a known value could have rested on (an upper bound for the relied set)."""
    if raw is None:
        return []
    col = {"sshd": "sshd", "fw": "firewall", "listener": "listeners", "patch": "patch"}[field.split(".")[1]]
    out = [raw[col]] if raw.get(col) is not None else []
    if field == "host.sshd.installed" and raw.get("listeners") is not None:
        out.append(raw["listeners"])
    return out


# a formula is ('leaf', field, params, op, literal) | ('all'|'any', [..]) | ('not', x)
def leaf_truth(node: tuple, raw: Optional[dict], now: dt.datetime, min_tier: str,
               max_age: dt.timedelta) -> Optional[bool]:
    _, field, params, op, lit = node
    v = field_value(field, params, raw, now, min_tier, max_age)
    if v is None:
        return None
    if op == "in":
        return v in lit
    return OPS[op](v, lit)


def _leaves(node: tuple) -> list[tuple]:
    if node[0] == "leaf":
        return [node]
    if node[0] == "not":
        return _leaves(node[1])
    return [x for c in node[1] for x in _leaves(c)]


def _eval_world(node: tuple, vals: dict[int, bool]) -> bool:
    if node[0] == "leaf":
        return vals[id(node)]
    if node[0] == "not":
        return not _eval_world(node[1], vals)
    results = [_eval_world(c, vals) for c in node[1]]
    return all(results) if node[0] == "all" else any(results)


def host_truth(tree: tuple, raw: Optional[dict], now: dt.datetime, min_tier: str,
               max_age: dt.timedelta) -> Optional[bool]:
    leaves = _leaves(tree)
    known = {id(lf): leaf_truth(lf, raw, now, min_tier, max_age) for lf in leaves}
    unk = [lf for lf in leaves if known[id(lf)] is None]
    results = []
    for combo in itertools.product([True, False], repeat=len(unk)):
        vals = {k: v for k, v in known.items() if v is not None}
        vals.update({id(lf): c for lf, c in zip(unk, combo)})
        results.append(_eval_world(tree, vals))
    return _tri_of_worlds(results)


def estate_verdict(tree: tuple, hosts: dict[str, Optional[dict]], now: dt.datetime, min_tier: str,
                   max_age: dt.timedelta, require: float) -> dict:
    tv = {h: host_truth(tree, raw, now, min_tier, max_age) for h, raw in sorted(hosts.items())}
    bad = [h for h, v in tv.items() if v is False]
    unk = [h for h, v in tv.items() if v is None]
    good = [h for h, v in tv.items() if v is True]
    if not tv:
        verdict = "UNKNOWN"
    elif bad:
        verdict = "VIOLATED"
    elif unk and not (require < 1.0 and good and len(good) / len(tv) + 1e-12 >= require):
        verdict = "UNKNOWN"
    else:
        verdict = "HOLDS"
    consulted = [fa for h in good for lf in _leaves(tree) for fa in consulted_facts(lf[1], hosts[h])
                 if leaf_truth(lf, hosts[h], now, min_tier, max_age) is not None]
    return {"verdict": verdict, "violating": bad, "unknown": unk, "holds": good,
            "consulted": consulted}


# --------------------------------------------------------------------------------------------
# random fact tables and formulas

def random_seen(r: random.Random) -> str:
    pick = r.random()
    if pick < 0.62:
        return iso(NOW - dt.timedelta(minutes=r.randint(1, 340)))
    if pick < 0.68:
        return iso(NOW - MAX_AGE)                                  # exactly at the limit: fresh
    if pick < 0.74:
        return iso(NOW - MAX_AGE - dt.timedelta(seconds=1))
    if pick < 0.84:
        return iso(NOW - dt.timedelta(hours=r.randint(7, 40)))
    if pick < 0.90:
        return iso(NOW + dt.timedelta(minutes=r.randint(0, 5)))   # inside the slack (5:00 included)
    return iso(NOW + dt.timedelta(minutes=5, seconds=r.randint(1, 3000)))


def random_collector_fact(r: random.Random, col: str, q: float = 1.0) -> dict:
    """``q`` scales how often a fact is defective (1.0: about half of all facts are unusable)."""
    kw: dict[str, Any] = {"seen": random_seen(r) if r.random() < q else iso(NOW - dt.timedelta(
        minutes=r.randint(1, 340))), "seq": r.randint(1, 50)}
    if r.random() < 0.08 * q:
        kw["signed"] = False
    if r.random() < 0.10 * q:
        kw["tier"] = r.choice(["declared", "observed"])
    if r.random() < 0.06 * q:
        kw["conflict"] = r.choice([True, [{"kind": "x"}]])
    if r.random() < 0.12 * q:
        kw["conf"] = "approximate"
    if r.random() < 0.10 * q:
        kw["partial"] = True
    pick = r.random()
    if pick < 0.06 * q:
        kw["status"], kw["reason"] = "error", "timeout"
    elif pick < 0.14 * q:
        kw["status"] = "unavailable"
        kw["reason"] = r.choice(["tool_missing", "tool_missing", "permission_denied"])
    elif col == "sshd" and pick < 0.14 * q + 0.10:      # a host without sshd (any quality)
        kw["status"], kw["reason"] = "unavailable", "tool_missing"
    if col == "sshd":
        cfg = {"passwordauthentication": r.choice(["yes", "no", "no"]),
               "kbdinteractiveauthentication": r.choice(["yes", "no", "no"]),
               "permitrootlogin": r.choice(["yes", "no", "prohibit-password", "without-password",
                                            "forced-commands-only"]),
               "pubkeyauthentication": r.choice(["yes", "yes", "no"]),
               "usepam": r.choice(["yes", "no"]), "maxauthtries": r.randint(1, 8),
               "authenticationmethods": r.choice(["any", "publickey", "publickey,password",
                                                  "publickey password"])}
        for k in list(cfg):
            if r.random() < 0.04:
                del cfg[k]
        deltas = []
        if r.random() < 0.2:
            deltas.append(r.choice([{"passwordauthentication": "yes"}, {"maxauthtries": 9},
                                    {"permitrootlogin": "yes"}, {"usepam": None},
                                    {"authenticationmethods": "publickey"}]))
        data = sshd(deltas=deltas, unprobed=r.random() < 0.08)
        data["config"] = cfg
        return fact(data, **kw)
    if col == "listeners":
        ports = tuple(sorted(r.sample([22, 80, 443, 8080], r.randint(0, 3))))
        comms = {22: r.choice(["sshd", "other", "other"])}
        d = listeners(ports=ports, comms=comms,
                      attribution=r.choice(["ok", "ok", "ok", "partial"]) if q > 0.2 else "ok",
                      count=None if r.random() < 0.95 else len(ports) + 2)
        return fact(d, **kw)
    if col == "firewall":
        d = firewall(ip4=r.choice(["drop", "reject", "accept", "unknown"]),
                     ip6=r.choice(["drop", "reject", "accept", "unknown"]), ipv6=r.random() < 0.7,
                     confidence=r.choice(["exact", "exact", "approximate"]),
                     backend=r.choice(["nft", "legacy", "mixed", "none"]), read6=r.random() < 0.9)
        if r.random() < 0.08:
            d["dataplane"] = ["cilium"]
        return fact(d, **kw)
    d = patch(security=r.randint(0, 5), reboot=r.random() < 0.3)
    if r.random() < 0.1:
        d["pending"] = {"state": "error", "reason": "timeout"}
    return fact(d, **kw)


def random_hosts(r: random.Random, q: Optional[float] = None) -> dict[str, Optional[dict]]:
    q = r.choice([0.1, 0.35, 1.0]) if q is None else q
    hosts: dict[str, Optional[dict]] = {}
    for i in range(r.randint(1, 4)):
        if r.random() < 0.1 * q:
            hosts[f"h{i}"] = None                      # a declared server with no agent
            continue
        facts = {c: random_collector_fact(r, c, q)
                 for c in ("sshd", "firewall", "listeners", "patch") if r.random() < 1 - 0.1 * q}
        hosts[f"h{i}"] = facts
    return hosts


LEAVES: list[Callable[[random.Random], tuple]] = [
    lambda r: ("host.sshd.maxauthtries", (), r.choice(list(OPS)), r.randint(1, 8)),
    lambda r: ("host.sshd.pubkeyauthentication", (), r.choice(["==", "!="]), r.choice(["yes", "no"])),
    lambda r: ("host.sshd.permitrootlogin", (), "in",
               tuple(sorted(r.sample(["yes", "no", "prohibit-password", "forced-commands-only"],
                                     r.randint(1, 3))))),
    lambda r: ("host.sshd.password_login_possible", (), r.choice(["==", "!="]), r.random() < 0.5),
    lambda r: ("host.sshd.installed", (), "==", r.random() < 0.5),
    lambda r: ("host.sshd.installed", (), "==", False),          # the std shape: weighted up
    lambda r: ("host.sshd.installed", (), "==", False),
    lambda r: ("host.listener.exists", (r.choice([22, 80, 443, 8080]),), "==", r.random() < 0.5),
    lambda r: ("host.patch.security_updates_pending", (), r.choice(list(OPS)), r.randint(0, 5)),
    lambda r: ("host.patch.reboot_required", (), "==", r.random() < 0.5),
    lambda r: ("host.fw.default_inbound_all_families", (), r.choice(["==", "!="]),
               r.choice(["deny", "allow"])),
    lambda r: ("host.fw.engine", (), "==", r.choice(["nft", "legacy", "mixed", "none"])),
]


def random_tree(r: random.Random, depth: int = 0, budget: Optional[list] = None) -> tuple:
    budget = budget if budget is not None else [r.randint(1, 6)]
    if depth >= 3 or budget[0] <= 1 or r.random() < 0.3:
        budget[0] -= 1
        field, params, op, lit = r.choice(LEAVES)(r)
        return ("leaf", field, params, op, lit)
    kind = r.choice(["all", "any", "not", "all", "any"])
    if kind == "not":
        return ("not", random_tree(r, depth + 1, budget))
    n = r.randint(2, 3)
    return (kind, [random_tree(r, depth + 1, budget) for _ in range(n)])


def _fmt(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    return '"' + v + '"'


def render_leaf(node: tuple, r: random.Random) -> str:
    _, field, params, op, lit = node
    path = field if not params else field.replace("host.listener.", f"host.listener({params[0]}).")
    sp = r.choice(["", " ", "  "])
    if op == "in":
        items = list(lit)
        r.shuffle(items)
        body = "[" + (","+sp).join(_fmt(x) for x in items) + "]"
        return f"{sp}{path} in {body}{sp}"
    return f"{sp}{path}{sp or ' '}{op}{sp or ' '}{_fmt(lit)}{sp}"


def render_doc(node: tuple, r: random.Random) -> Any:
    if node[0] == "leaf":
        return render_leaf(node, r)
    if node[0] == "not":
        return {"not": render_doc(node[1], r)}
    kids = [render_doc(c, r) for c in node[1]]
    r.shuffle(kids)
    return {node[0]: kids}


def to_graph_doc(hosts: dict[str, Optional[dict]], extra_nodes: int = 0) -> dict:
    nodes = []
    for h, facts in sorted(hosts.items()):
        n: dict[str, Any] = {"id": h, "kind": "host", "tags": ["agent", "server"]}
        if facts is not None:
            n["facts"] = facts
        nodes.append(n)
    for i in range(extra_nodes):
        nodes.append({"id": f"other{i}", "kind": "host", "tags": ["web"]})
    return {"version": 1, "nodes": nodes, "edges": []}


def scenario(seed: int):
    r = random.Random(seed)
    hosts = random_hosts(r)
    tree = random_tree(r)
    min_tier = r.choice(["configured", "configured", "declared"])
    require = r.choice([1.0, 1.0, 1.0, 0.5, 0.75])
    return r, hosts, tree, min_tier, require


def find_mismatch(seeds, evaluate_fn=None) -> list[str]:
    """Run the implementation and the oracle over ``seeds``; return a description per mismatch."""
    from paddock_assurance import ReachGraph, evaluate
    from tests.hostfix import host_plan_doc
    out: list[str] = []
    for seed in seeds:
        r, hosts, tree, min_tier, require = scenario(seed)
        doc = render_doc(tree, r)
        try:
            plan = host_plan_doc(doc, min_tier=min_tier, require=require)
        except Exception as exc:                     # noqa: BLE001
            out.append(f"seed {seed}: could not compile {doc!r}: {exc}")
            continue
        g = ReachGraph.from_dict(to_graph_doc(hosts, extra_nodes=1))
        res = (evaluate_fn or evaluate)(plan, g, NOW)
        want = estate_verdict(tree, hosts, NOW, min_tier, MAX_AGE, require)
        got_v = res.verdict.value
        if got_v != want["verdict"]:
            out.append(f"seed {seed}: verdict {got_v} != oracle {want['verdict']} for {doc!r}")
            continue
        if sorted(res.violating_targets) != want["violating"]:
            out.append(f"seed {seed}: violating {res.violating_targets} != {want['violating']}")
        if sorted(res.unproven_targets) != want["unknown"]:
            out.append(f"seed {seed}: unknown {res.unproven_targets} != {want['unknown']}")
        if res.hosts != {"selected": len(hosts), "holds": len(want["holds"]),
                         "violated": len(want["violating"]), "unknown": len(want["unknown"])}:
            out.append(f"seed {seed}: host counts {res.hosts}")
        if want["verdict"] == "HOLDS":
            lows = [when(f["observed_at"]) + MAX_AGE for f in want["consulted"]]
            # a lowered floor with an unknown host that holds a future-dated fact: that fact turns
            # usable five minutes before its timestamp, so validity must end no later than that
            for h in want["unknown"]:
                lows += [when(f["observed_at"]) - SLACK for f in (hosts[h] or {}).values()
                         if when(f["observed_at"]) > NOW + SLACK]
            if not lows or res.valid_until is None or res.valid_until < min(lows):
                out.append(f"seed {seed}: valid_until {res.valid_until} before {min(lows) if lows else None}")
            tiers = {min(RANK[f["tier"]], 1) for f in want["consulted"]}
            if res.evidence_tier is None or res.evidence_tier.rank < min(tiers):
                out.append(f"seed {seed}: evidence tier {res.evidence_tier} below the oracle bound")
        else:
            if res.valid_until is not None or res.evidence_tier is not None:
                out.append(f"seed {seed}: a non-HOLDS verdict carries evidence")
    return out
