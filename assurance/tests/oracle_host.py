"""An independent brute-force oracle for host-config evaluation.

It shares NO code with the implementation under test: it reads the raw graph-document dicts (not
``HostFacts``), parses timestamps itself, extracts every field value with its own plain-Python code
and decides each host by *possible worlds*: every unknown leaf is tried as both true and false,
and the host is true iff all worlds are true, false iff all are false, else unknown. (For a formula
in which every leaf occurs once, that is exactly Kleene strong logic; the oracle never uses it.)
Random fact tables and random formulas come from one seeded generator.

Semantics it encodes independently (P2 review): a key a Match block changes is judged per variant
(the base config and each probed user/address) outside ``not``. The meaning of the assertion on such
a host is "it holds in EVERY variant": ``host_semantics`` is that complete truth (brute force over
variants and possible worlds). The implementation may be less decided than it (unknown where the
semantics decide) but never disagree with it: a host that varies is checked for soundness only
(``find_mismatch``), every other host for equality. ``sshd -T`` facts need ``daemon.reload_pending == false``; a
host whose ``host_agent`` fact is a revoked/legacy tombstone is unknown on every leaf; ``installed ==
false`` needs every public TCP listener to be a known non-SSH program.
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
    dm = d.get("daemon")
    if not isinstance(dm, dict) or dm.get("reload_pending") is not False:
        return None
    found, masters = dm.get("found"), dm.get("masters")
    if not isinstance(found, bool) or type(masters) is not int:
        return None
    if not found:
        # no master daemon: only socket activation reads the files for every connection
        return d if masters == 0 else None
    # a running daemon: positive evidence of one master, the default file, no extra options and the
    # expected binary (an unreadable flag, null, is not evidence)
    if masters == 1 and dm.get("config_default") is True and dm.get("options_override") is False \
            and dm.get("binary_matches") is True:
        return d
    return None


def _pubkey_only(am: Any) -> Optional[bool]:
    if not isinstance(am, str) or not am.strip() or len(am) >= 200:
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


def _scalar_of(name: str, v: Any) -> Any:
    """One raw config value of a scalar sshd key as the field's value, or None if unreadable."""
    if name == "maxauthtries":
        return v if type(v) is int and v >= 0 else None
    if not isinstance(v, str):
        return None
    v = v.lower()
    if name == "permitrootlogin":
        v = "prohibit-password" if v == "without-password" else v
        return v if v in ("yes", "no", "prohibit-password", "forced-commands-only") else None
    return v if v in ("yes", "no") else None


def variant_values(field: str, raw: Optional[dict], now: dt.datetime, min_tier: str,
                   max_age: dt.timedelta) -> Optional[list]:
    """For a scalar sshd key some Match probe changes: the value (None = unreadable) in the base
    config and in every probed variant. ``None`` when the key is not varying or the host is not
    decidable at all."""
    if raw is None or raw.get("host_agent") is not None and _is_tombstone(raw["host_agent"]):
        return None
    name = field.split(".", 2)[2]
    if field.split(".")[1] != "sshd" or name not in ("maxauthtries", "pubkeyauthentication",
                                                      "permitrootlogin"):
        return None
    f = raw.get("sshd")
    if not usable(f, now, min_tier, max_age):
        return None
    ex = _sshd_exact(f)
    if ex is None or not _scalar_changed(ex, name):
        return None
    return [_scalar_of(name, c.get(name)) for c in _variants(ex)]


def _is_tombstone(f: dict) -> bool:
    d = f.get("data", {})
    return (str(d.get("agent_status", "")).lower() in ("revoked", "legacy", "rekeyed")
            or str(d.get("status", "")).lower() in ("revoked", "legacy", "rekeyed")
            or str(f.get("reason", "")).lower() in ("agent_revoked", "agent_legacy", "agent_rekeyed",
                                                    "revoked", "legacy", "rekeyed"))


def field_value(field: str, params: tuple, raw: Optional[dict], now: dt.datetime, min_tier: str,
                max_age: dt.timedelta) -> Any:
    """The value of a field on a host, or ``None`` for unknown (the oracle never returns a
    Python ``None`` as a real value; every real value here is a bool, int or str)."""
    if raw is None:
        return None
    if raw.get("host_agent") is not None and _is_tombstone(raw["host_agent"]):
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
        if name in ("maxauthtries", "pubkeyauthentication", "permitrootlogin"):
            if _scalar_changed(ex, name):
                return None                     # varies by user/address: see variant_values
            return _scalar_of(name, ex["config"].get(name))
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
        if any(r["port"] == 22 or "ssh" in (r.get("comm") or "").lower()
               or "dropbear" in (r.get("comm") or "").lower() for r in lf["data"]["listeners"]):
            return None
    if lf is None or not usable(lf, now, min_tier, max_age) or lf["status"] != "ok" or lf["partial"]:
        return None
    if lf["data"]["count"] != len(lf["data"]["listeners"]):
        return None
    if lf["conf"] != "exact" or lf["data"]["attribution"]["status"] != "ok":
        return None
    known_non_ssh = ("postgres", "redis-server", "named", "dovecot", "mysqld")
    if any(r.get("bind_class") != "loopback" and (r.get("comm") or "").lower() not in known_non_ssh
           for r in lf["data"]["listeners"]):
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
def _holds(op: str, v: Any, lit: Any) -> bool:
    return v in lit if op == "in" else OPS[op](v, lit)


def leaf_truth(node: tuple, raw: Optional[dict], now: dt.datetime, min_tier: str,
               max_age: dt.timedelta, under_not: bool = False) -> Optional[bool]:
    """The leaf's truth on a host where it has ONE value; a leaf over a key Match blocks change
    reads as unknown here (see ``host_semantics`` for the per-variant meaning)."""
    _, field, params, op, lit = node
    v = field_value(field, params, raw, now, min_tier, max_age)
    if v is None:
        return None
    return _holds(op, v, lit)


def _variant_truths(node: tuple, raw: Optional[dict], now: dt.datetime, min_tier: str,
                    max_age: dt.timedelta) -> Optional[list]:
    _, field, params, op, lit = node
    if field_value(field, params, raw, now, min_tier, max_age) is not None:
        return None
    vv = variant_values(field, raw, now, min_tier, max_age)
    if vv is None:
        return None
    return [None if x is None else _holds(op, x, lit) for x in vv]


def _pure_all(tree: tuple) -> bool:
    """Only ``all`` over leaves: there the implementation is exactly as decided as the semantics."""
    if tree[0] == "leaf":
        return True
    return tree[0] == "all" and all(_pure_all(c) for c in tree[1])


def host_varies(tree: tuple, raw: Optional[dict], now: dt.datetime, min_tier: str,
                max_age: dt.timedelta) -> bool:
    """Does some leaf (outside ``not``) read a key whose value differs between Match variants?"""
    neg = _negated(tree)
    return any(not neg[id(lf)] and _variant_truths(lf, raw, now, min_tier, max_age) is not None
               for lf in _leaves(tree))


def _leaves(node: tuple) -> list[tuple]:
    if node[0] == "leaf":
        return [node]
    if node[0] == "not":
        return _leaves(node[1])
    return [x for c in node[1] for x in _leaves(c)]


def _negated(node: tuple, neg: bool = False) -> dict[int, bool]:
    """``id(leaf) -> is it under a ``not```."""
    if node[0] == "leaf":
        return {id(node): neg}
    if node[0] == "not":
        return _negated(node[1], True)
    out: dict[int, bool] = {}
    for c in node[1]:
        out.update(_negated(c, neg))
    return out


def _eval_world(node: tuple, vals: dict[int, bool]) -> bool:
    if node[0] == "leaf":
        return vals[id(node)]
    if node[0] == "not":
        return not _eval_world(node[1], vals)
    results = [_eval_world(c, vals) for c in node[1]]
    return all(results) if node[0] == "all" else any(results)


def _truth_in_worlds(tree: tuple, known: dict) -> Optional[bool]:
    leaves = _leaves(tree)
    unk = [lf for lf in leaves if known[id(lf)] is None]
    results = []
    for combo in itertools.product([True, False], repeat=len(unk)):
        vals = {k: v for k, v in known.items() if v is not None}
        vals.update({id(lf): c for lf, c in zip(unk, combo)})
        results.append(_eval_world(tree, vals))
    return _tri_of_worlds(results)


def host_truth(tree: tuple, raw: Optional[dict], now: dt.datetime, min_tier: str,
               max_age: dt.timedelta) -> Optional[bool]:
    """The exact truth on a host where every leaf has one value. On a host that varies it is None:
    the implementation is only held to ``host_semantics`` there."""
    if host_varies(tree, raw, now, min_tier, max_age):
        return None
    neg = _negated(tree)
    known = {id(lf): leaf_truth(lf, raw, now, min_tier, max_age, neg[id(lf)])
             for lf in _leaves(tree)}
    return _truth_in_worlds(tree, known)


def host_semantics(tree: tuple, raw: Optional[dict], now: dt.datetime, min_tier: str,
                   max_age: dt.timedelta) -> Optional[bool]:
    """The complete meaning: the formula must hold in every variant (the base config and each probed
    user/address). False iff some variant makes it false whatever the unknown leaves are, true iff
    every variant makes it true. Equal to ``host_truth`` on a host that does not vary."""
    neg = _negated(tree)
    leaves = _leaves(tree)
    known = {id(lf): leaf_truth(lf, raw, now, min_tier, max_age, neg[id(lf)]) for lf in leaves}
    var = {}
    for lf in leaves:
        if not neg[id(lf)]:
            vt = _variant_truths(lf, raw, now, min_tier, max_age)
            if vt is not None:
                var[id(lf)] = vt
    if not var:
        return _truth_in_worlds(tree, known)
    per_variant = []
    for i in range(max(len(v) for v in var.values())):
        k = dict(known)
        for key, vt in var.items():
            k[key] = vt[i]
        per_variant.append(_truth_in_worlds(tree, k))
    if any(t is False for t in per_variant):
        return False
    return True if all(t is True for t in per_variant) else None


def estate_verdict(tree: tuple, hosts: dict[str, Optional[dict]], now: dt.datetime, min_tier: str,
                   max_age: dt.timedelta, require: float,
                   override: Optional[dict[str, Optional[bool]]] = None) -> dict:
    """Each host by its complete semantics. ``override``: the truth to use instead for a host that
    varies (the implementation's, once it has been checked sound against ``host_semantics``)."""
    tv = {h: host_semantics(tree, raw, now, min_tier, max_age) for h, raw in sorted(hosts.items())}
    tv.update(override or {})
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
    neg = _negated(tree)
    consulted = [fa for h in good for lf in _leaves(tree) for fa in consulted_facts(lf[1], hosts[h])
                 if leaf_truth(lf, hosts[h], now, min_tier, max_age, neg[id(lf)]) is not None
                 or _variant_truths(lf, hosts[h], now, min_tier, max_age) is not None]
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
        pool = [{"passwordauthentication": "yes"}, {"maxauthtries": 9}, {"permitrootlogin": "yes"},
                {"usepam": None}, {"pubkeyauthentication": "no"}, {"maxauthtries": 2},
                {"permitrootlogin": None}, {"authenticationmethods": "publickey"},
                {"maxauthtries": r.randint(1, 8)}, {"pubkeyauthentication": "yes"},
                {"permitrootlogin": r.choice(["no", "prohibit-password", "yes"])}]
        if r.random() < 0.3:                  # up to two Match variants, so two leaves can vary
            for _ in range(r.choice([1, 1, 2])):
                deltas.append(r.choice(pool))
        pending = r.random()
        daemon = ({"reload_pending": True} if pending < 0.03 else
                  {"reload_pending": None} if pending < 0.05 else
                  {"config_default": None, "options_override": None, "binary_matches": None}
                  if pending < 0.07 else
                  {"binary_matches": None} if pending < 0.08 else
                  {"found": False, "masters": 0} if pending < 0.09 else
                  {"found": False, "masters": 1} if pending < 0.10 else
                  {"masters": 2} if pending < 0.11 else True)
        data = sshd(deltas=deltas, unprobed=r.random() < 0.08, daemon=daemon)
        data["config"] = cfg
        return fact(data, **kw)
    if col == "listeners":
        ports = tuple(sorted(r.sample([22, 80, 443, 8080], r.randint(0, 3))))
        comms = {22: r.choice(["sshd", "other", "other", "postgres"]),
                 **{p: r.choice(["nginx", "postgres", "postgres", "redis-server", "Docker-Proxy"])
                    for p in (80, 443, 8080)}}
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
        if r.random() < 0.06 * q:                      # the host's agent is revoked: a tombstone
            facts["host_agent"] = fact({"agent_status": r.choice(["revoked", "legacy", "rekeyed"])},
                                       status="unavailable", signed=False, partial=True,
                                       conf="approximate")
        elif r.random() < 0.05:                        # a live summary is not a tombstone
            facts["host_agent"] = fact({"agent_status": "active"})
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
        # a host whose Match blocks change a key a leaf reads: the implementation must never disagree
        # with the complete semantics (unknown where they decide is allowed); its own answer then
        # stands in for the host in the estate verdict
        override: dict[str, Optional[bool]] = {}
        for h, raw in sorted(hosts.items()):
            if not host_varies(tree, raw, NOW, min_tier, MAX_AGE):
                continue
            sem = host_semantics(tree, raw, NOW, min_tier, MAX_AGE)
            mine = (True if h in res.passing_targets else False if h in res.violating_targets
                    else None)
            if sem is not None and mine is None and _pure_all(tree):
                out.append(f"seed {seed}: host {h} a plain conjunction is {sem} by the semantics "
                           f"but the implementation says unknown, for {doc!r}")
            if mine is not None and mine is not sem:
                out.append(f"seed {seed}: host {h} the implementation says {mine}, the semantics "
                           f"say {sem} for {doc!r}")
            override[h] = mine
        want = estate_verdict(tree, hosts, NOW, min_tier, MAX_AGE, require, override)
        got_v = res.verdict.value
        if got_v != want["verdict"]:
            out.append(f"seed {seed}: verdict {got_v} != oracle {want['verdict']} for {doc!r}")
            continue
        if sorted(res.violating_targets) != want["violating"]:
            out.append(f"seed {seed}: violating {res.violating_targets} != {want['violating']}")
        if sorted(res.unproven_targets) != want["unknown"]:
            out.append(f"seed {seed}: unknown {res.unproven_targets} != {want['unknown']}")
        if res.passing_targets != want["holds"]:
            out.append(f"seed {seed}: passing {res.passing_targets} != {want['holds']}")
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
