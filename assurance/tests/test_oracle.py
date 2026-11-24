"""Soundness by comparison: the evaluator must agree with an independent, deliberately naive
oracle on hundreds of seeded random estates, and must not depend on input order."""
from __future__ import annotations

import datetime as dt
import random

import pytest

from paddock_assurance import ReachGraph, Verdict, compile_text, evaluate

NOW = dt.datetime(2026, 12, 1, 9, 0, tzinfo=dt.timezone.utc)
YAML = """
apiVersion: paddock.dev/invariant/v1
id: acme:oracle
title: oracle check
subjects: {{ from: {{ zone: a }}, to: {{ zone: b }} }}
assert: unreachable
via: {{ protocols: [tcp], max_hops: {hops}, stop_at: {{ tag: app }} }}
evidence: {{ min_tier: observed, max_age: 24h }}
coverage: {{ require: 0 }}
"""


def random_doc(rng: random.Random) -> dict:
    n = rng.randint(3, 10)
    nodes = []
    for i in range(n):
        node = {"id": f"n{i}", "zone": rng.choice(["a", "b", "m", "m"]),
                "tags": ["app"] if rng.random() < 0.2 else []}
        if rng.random() < 0.8:                      # ~20% blind
            node["coverage"] = {"tier": "observed", "observed_at": "2026-12-01T08:30:00Z"}
        nodes.append(node)
    edges = []
    for _ in range(rng.randint(0, n * 2)):
        a, b = rng.sample(range(n), 2)
        edges.append({"src": f"n{a}", "dst": f"n{b}", "proto": rng.choice(["tcp", "tcp", "udp"]),
                      "ports": "443", "basis": "observed"})
    return {"version": 1, "nodes": nodes, "edges": edges}


def oracle(doc: dict, hops: int) -> Verdict | str:
    """Level-synchronous reachability; no BFS tree, no shared code with the evaluator."""
    zone = {n["id"]: n["zone"] for n in doc["nodes"]}
    app = {n["id"] for n in doc["nodes"] if "app" in n["tags"]}
    blind = {n["id"] for n in doc["nodes"] if "coverage" not in n}
    S = {i for i, z in zone.items() if z == "a"}
    T = {i for i, z in zone.items() if z == "b"} - S
    if not S or not T:
        return "EMPTY"
    known = {(e["src"], e["dst"]) for e in doc["edges"] if e["proto"] == "tcp"}

    def reach(extra: set[tuple[str, str]]) -> set[str]:
        adj = known | extra
        seen = set(S)
        for _ in range(hops):
            seen |= {d for (s, d) in adj if s in seen and (s not in app or s in S)}
        return seen

    if reach(set()) & T:
        return Verdict.VIOLATED
    clique = {(u, v) for u in blind for v in blind if u != v}
    return Verdict.UNKNOWN if reach(clique) & T else Verdict.HOLDS


@pytest.mark.parametrize("seed", range(400))
def test_matches_oracle(seed):
    # NB: zones a and b are disjoint here, so "T minus S" is the identity; overlapping selectors
    # are covered by the pairwise oracle at the end of this file.
    rng = random.Random(seed)
    doc = random_doc(rng)
    hops = rng.randint(1, 5)
    got = evaluate(compile_text(YAML.format(hops=hops)), ReachGraph.from_dict(doc), NOW)
    want = oracle(doc, hops)
    if want == "EMPTY":
        assert got.verdict is Verdict.UNKNOWN and got.reasons[0].startswith("empty_selector")
    else:
        assert got.verdict is want, (seed, hops, doc)


@pytest.mark.parametrize("seed", range(60))
def test_input_order_never_changes_the_answer(seed):
    rng = random.Random(1000 + seed)
    doc = random_doc(rng)
    plan = compile_text(YAML.format(hops=rng.randint(1, 5)))
    base = evaluate(plan, ReachGraph.from_dict(doc), NOW).to_dict()
    for _ in range(3):
        shuffled = {"version": 1, "nodes": rng.sample(doc["nodes"], len(doc["nodes"])),
                    "edges": rng.sample(doc["edges"], len(doc["edges"]))}
        assert evaluate(plan, ReachGraph.from_dict(shuffled), NOW).to_dict() == base


@pytest.mark.parametrize("seed", range(120))
def test_adding_an_edge_never_removes_a_violation(seed):
    rng = random.Random(5000 + seed)
    doc = random_doc(rng)
    plan = compile_text(YAML.format(hops=rng.randint(1, 5)))
    if evaluate(plan, ReachGraph.from_dict(doc), NOW).verdict is not Verdict.VIOLATED:
        return
    ids = [n["id"] for n in doc["nodes"]]
    a, b = rng.sample(ids, 2)
    doc["edges"].append({"src": a, "dst": b, "proto": "tcp", "ports": "22", "basis": "declared"})
    assert evaluate(plan, ReachGraph.from_dict(doc), NOW).verdict is Verdict.VIOLATED


@pytest.mark.parametrize("seed", range(120))
def test_gaining_coverage_never_creates_a_violation(seed):
    """Seeing more can turn UNKNOWN into HOLDS or VIOLATED-by-known-edge, but a HOLDS that stays
    covered must not flip: making a blind node covered cannot add a witness."""
    rng = random.Random(9000 + seed)
    doc = random_doc(rng)
    plan = compile_text(YAML.format(hops=rng.randint(1, 5)))
    before = evaluate(plan, ReachGraph.from_dict(doc), NOW)
    blind = [n for n in doc["nodes"] if "coverage" not in n]
    if not blind:
        return
    rng.choice(blind)["coverage"] = {"tier": "observed", "observed_at": "2026-12-01T08:30:00Z"}
    after = evaluate(plan, ReachGraph.from_dict(doc), NOW)
    if before.verdict is Verdict.HOLDS:
        assert after.verdict is Verdict.HOLDS
    if before.verdict is Verdict.VIOLATED:
        assert after.verdict is Verdict.VIOLATED


# =============================================================================================
# Directional, multi-source coverage. The oracle below re-derives coverage from the raw facts
# itself (no shared code with the evaluator) and enumerates the possible unknown edges as an
# explicit bipartite set {(u, v) : u blind outbound, v blind inbound, u != v}.
# =============================================================================================

TIER_RANK = {"declared": 0, "configured": 1, "observed": 2, "tested": 3}
SEEN_CHOICES = ["2026-12-01T08:30:00Z", "2026-12-01T08:30:00Z", "2026-12-01T08:30:00Z",
                "2026-11-30T12:00:00Z", "2026-12-01T00:00:00Z", "2026-11-30T20:00:00Z",  # fresh, expire at staggered times
                "2026-11-30T09:00:00Z",      # exactly max_age old: still fresh
                "2026-11-30T08:59:59Z",      # one second too old
                "2026-11-28T08:30:00Z",
                "2026-12-01T09:05:00Z",      # exactly the allowed 5 minutes ahead: fresh
                "2026-12-01T09:05:01Z",      # a second beyond: not trusted
                "2026-12-03T09:00:00Z"]
MAX_AGE = dt.timedelta(hours=24)


def _ts(s: str) -> dt.datetime:
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


def qualifies(f: dict, direction: str, now: dt.datetime, min_tier: str = "observed") -> bool:
    if f.get("direction", "both") not in (direction, "both"):
        return False
    seen = _ts(f["observed_at"])
    return (TIER_RANK[f["tier"]] >= TIER_RANK[min_tier] and seen <= now + dt.timedelta(minutes=5)
            and now - seen <= MAX_AGE)


def facts_of(n: dict) -> list[dict]:
    c = n.get("coverage")
    return [] if c is None else [c] if isinstance(c, dict) else list(c)


def covered_dir(n: dict, direction: str, now: dt.datetime = NOW) -> bool:
    return any(qualifies(f, direction, now) for f in facts_of(n))


def random_fact(rng: random.Random) -> dict:
    return {"direction": rng.choice(["in", "out", "both", "both"]),
            "tier": rng.choice(["declared", "configured", "observed", "observed", "observed", "tested"]),
            "observed_at": rng.choice(SEEN_CHOICES), "source": rng.choice(["aws_sg", "sentry", "scan"])}


def random_dir_doc(rng: random.Random) -> dict:
    n = rng.randint(3, 10)
    nodes = []
    for i in range(n):
        # n0 / n1 are a source and a target most of the time, so few documents are vacuous
        zone = ("a" if i == 0 else "b" if i == 1 else rng.choice(["a", "b", "m", "m"])) \
            if rng.random() < 0.9 else rng.choice(["a", "b", "m", "m"])
        node: dict = {"id": f"n{i}", "zone": zone, "tags": ["app"] if rng.random() < 0.2 else []}
        r = rng.random()
        if r < 0.12:          # the P0 single-object form, always fresh and observed
            node["coverage"] = {"tier": "observed", "observed_at": "2026-12-01T08:30:00Z"}
        elif r < 0.95:
            node["coverage"] = [random_fact(rng) for _ in range(rng.choice([0, 1, 1, 2, 2, 3]))]
        nodes.append(node)
    edges = []
    for _ in range(rng.randint(0, n * 2)):
        a, b = rng.sample(range(n), 2)
        edges.append({"src": f"n{a}", "dst": f"n{b}", "proto": rng.choice(["tcp", "tcp", "udp"]),
                      "ports": rng.choice(["443", "22", "80"]), "basis": "observed"})
    return {"version": 1, "nodes": nodes, "edges": edges}


def oracle_dir(doc: dict, hops: int, now: dt.datetime = NOW) -> Verdict | str:
    zone = {n["id"]: n["zone"] for n in doc["nodes"]}
    app = {n["id"] for n in doc["nodes"] if "app" in n["tags"]}
    bo = {n["id"] for n in doc["nodes"] if not covered_dir(n, "out", now)}
    bi = {n["id"] for n in doc["nodes"] if not covered_dir(n, "in", now)}
    S = {i for i, z in zone.items() if z == "a"}
    T = {i for i, z in zone.items() if z == "b"} - S
    if not S or not T:
        return "EMPTY"
    known = {(e["src"], e["dst"]) for e in doc["edges"] if e["proto"] == "tcp"}

    def reach(extra: set[tuple[str, str]]) -> set[str]:
        adj = known | extra
        seen = set(S)
        for _ in range(hops):
            seen |= {d for (s, d) in adj if s in seen and (s not in app or s in S)}
        return seen

    if reach(set()) & T:
        return Verdict.VIOLATED
    bipartite = {(u, v) for u in bo for v in bi if u != v}
    return Verdict.UNKNOWN if reach(bipartite) & T else Verdict.HOLDS


@pytest.mark.parametrize("seed", range(500))
def test_directional_reach_matches_oracle(seed):
    rng = random.Random(20000 + seed)
    doc = random_dir_doc(rng)
    hops = rng.randint(1, 5)
    got = evaluate(compile_text(YAML.format(hops=hops)), ReachGraph.from_dict(doc), NOW)
    want = oracle_dir(doc, hops)
    if want == "EMPTY":
        assert got.verdict is Verdict.UNKNOWN and got.reasons[0].startswith("empty_selector")
    else:
        assert got.verdict is want, (seed, hops, doc)


EXPOSE_ORACLE = """
apiVersion: paddock.dev/invariant/v1
id: acme:oracle-expose
title: oracle exposure check
subjects: { from: { zone: a }, to: { zone: b } }
assert: exposes-only
ports: [80, 443]
via: { protocols: [tcp] }
evidence: { min_tier: observed, max_age: 24h }
coverage: { require: 0 }
"""


def oracle_expose(doc: dict, now: dt.datetime = NOW) -> Verdict | str:
    zone = {n["id"]: n["zone"] for n in doc["nodes"]}
    bo = {n["id"] for n in doc["nodes"] if not covered_dir(n, "out", now)}
    bi = {n["id"] for n in doc["nodes"] if not covered_dir(n, "in", now)}
    S = {i for i, z in zone.items() if z == "a"}
    T = {i for i, z in zone.items() if z == "b"} - S
    if not S or not T:
        return "EMPTY"
    if any(e["src"] in S and e["dst"] in T and e["proto"] == "tcp" and e["ports"] not in ("80", "443")
           for e in doc["edges"]):
        return Verdict.VIOLATED
    return Verdict.UNKNOWN if any(s != t for s in S & bo for t in T & bi) else Verdict.HOLDS


@pytest.mark.parametrize("seed", range(300))
def test_directional_exposure_matches_oracle(seed):
    rng = random.Random(30000 + seed)
    doc = random_dir_doc(rng)
    got = evaluate(compile_text(EXPOSE_ORACLE), ReachGraph.from_dict(doc), NOW)
    want = oracle_expose(doc)
    if want == "EMPTY":
        assert got.verdict is Verdict.UNKNOWN
    else:
        assert got.verdict is want, (seed, doc)


COVERED_ORACLE = """
apiVersion: paddock.dev/invariant/v1
id: acme:oracle-covered
title: oracle coverage check
subjects: { to: { zone: b } }
assert: covered
evidence: { min_tier: observed, max_age: 24h }
"""


@pytest.mark.parametrize("seed", range(200))
def test_covered_assertion_matches_oracle(seed):
    rng = random.Random(40000 + seed)
    doc = random_dir_doc(rng)
    got = evaluate(compile_text(COVERED_ORACLE), ReachGraph.from_dict(doc), NOW)
    sel = [n for n in doc["nodes"] if n["zone"] == "b"]
    gaps = sorted(n["id"] for n in sel if not (covered_dir(n, "in") and covered_dir(n, "out")))
    if not sel:
        assert got.verdict is Verdict.UNKNOWN
    elif gaps:
        assert got.verdict is Verdict.VIOLATED and got.violation_count == len(gaps)
        assert sorted(w.detail["node"] for w in got.witnesses) == gaps
        for w in got.witnesses:
            n = next(x for x in sel if x["id"] == w.detail["node"])
            missing = [d for d in ("in", "out") if not covered_dir(n, d)]
            assert w.detail["direction"] == ("both" if len(missing) == 2 else missing[0])
    else:
        assert got.verdict is Verdict.HOLDS


def _shuffled(rng: random.Random, doc: dict) -> dict:
    nodes = []
    for n in doc["nodes"]:
        n = dict(n)
        if isinstance(n.get("coverage"), list):
            n["coverage"] = rng.sample(n["coverage"], len(n["coverage"]))
        nodes.append(n)
    return {"version": 1, "nodes": rng.sample(nodes, len(nodes)),
            "edges": rng.sample(doc["edges"], len(doc["edges"]))}


@pytest.mark.parametrize("seed", range(150))
def test_directional_results_do_not_depend_on_input_or_fact_order(seed):
    rng = random.Random(50000 + seed)
    doc = random_dir_doc(rng)
    plans = [compile_text(YAML.format(hops=rng.randint(1, 5))), compile_text(EXPOSE_ORACLE),
             compile_text(COVERED_ORACLE)]
    for plan in plans:
        base = evaluate(plan, ReachGraph.from_dict(doc), NOW).to_dict()
        for _ in range(3):
            got = evaluate(plan, ReachGraph.from_dict(_shuffled(rng, doc)), NOW).to_dict()
            assert got == base


_RANK = {Verdict.UNKNOWN: 0, Verdict.HOLDS: 1, Verdict.VIOLATED: 2}


@pytest.mark.parametrize("seed", range(250))
def test_more_coverage_never_makes_things_worse_and_less_never_better(seed):
    """Adding a fact can only shrink the set of possible unknown edges: VIOLATED stays VIOLATED
    (known edges are untouched), HOLDS stays HOLDS, UNKNOWN may become HOLDS but never VIOLATED.
    Removing a fact is the same statement read backwards."""
    rng = random.Random(60000 + seed)
    doc = random_dir_doc(rng)
    plan = compile_text(rng.choice([YAML.format(hops=rng.randint(1, 5)), EXPOSE_ORACLE]))
    before = evaluate(plan, ReachGraph.from_dict(doc), NOW).verdict
    target = rng.choice(doc["nodes"])
    facts = [{"direction": "both", **f} for f in facts_of(target)]   # P0 object = both
    target["coverage"] = facts + [{"direction": rng.choice(["in", "out", "both"]),
                                   "tier": "observed", "observed_at": "2026-12-01T08:30:00Z"}]
    after = evaluate(plan, ReachGraph.from_dict(doc), NOW).verdict
    if before is Verdict.VIOLATED:
        assert after is Verdict.VIOLATED
    elif before is Verdict.HOLDS:
        assert after is Verdict.HOLDS
    else:
        assert after is not Verdict.VIOLATED
    assert _RANK[after] >= _RANK[before] or before is Verdict.VIOLATED


@pytest.mark.parametrize("seed", range(1500))
def test_a_holds_stays_true_until_its_stated_expiry(seed):
    """``valid_until`` is a promise: re-evaluating the same graph at any later moment up to and
    including it must still say HOLDS. If a verdict leaned on a node-direction it did not count
    (e.g. a covered node that merely *blocks* an unknown edge), this fails."""
    rng = random.Random(70000 + seed)
    doc = random_dir_doc(rng)
    plan = compile_text(rng.choice([YAML.format(hops=rng.randint(1, 5)), EXPOSE_ORACLE,
                                    COVERED_ORACLE]))
    r = evaluate(plan, ReachGraph.from_dict(doc), NOW)
    if r.verdict is not Verdict.HOLDS or r.valid_until is None:
        return
    span = r.valid_until - NOW
    for t in (NOW + span / 5, NOW + span / 3, NOW + span / 2, NOW + span * 0.9, r.valid_until):
        if t < NOW:
            continue
        again = evaluate(plan, ReachGraph.from_dict(doc), t)
        assert again.verdict is Verdict.HOLDS, (seed, t, doc)


# =============================================================================================
# Overlapping selectors (P1 hardening, evaluator-1). The old oracles above subtract S from T, the
# same assumption the evaluator used to make, so they could never see a node selected by both
# ``from`` and ``to``. This one does NOT: it takes every ordered PAIR (s, t) with s in S, t in T and
# s != t on its own, and walks from that single source only (no multi-source search, no tree), so
# "t is in S" never removes t from consideration.
# =============================================================================================

OVERLAP_YAML = """
apiVersion: paddock.dev/invariant/v1
id: acme:oracle-overlap
title: overlap oracle check
subjects: {{ from: {{ zone: [a, m] }}, to: {{ zone: [b, m] }} }}
assert: unreachable
via: {{ protocols: [tcp], max_hops: {hops}, stop_at: {{ tag: app }} }}
{allow}
evidence: {{ min_tier: observed, max_age: 24h }}
coverage: {{ require: 0 }}
"""
ALLOW_M = "allow: [ { to: { zone: m }, reason: lab devices, expires: 2026-12-01 } ]"
OVERLAP_EXPOSE_YAML = """
apiVersion: paddock.dev/invariant/v1
id: acme:oracle-overlap-expose
title: overlap exposure oracle check
subjects: { from: { zone: [a, m] }, to: { zone: [b, m] } }
assert: exposes-only
ports: [80, 443]
via: { protocols: [tcp] }
evidence: { min_tier: observed, max_age: 24h }
coverage: { require: 0 }
"""


def _pairs(doc: dict) -> tuple[set[str], set[str], list[tuple[str, str]]]:
    zone = {n["id"]: n["zone"] for n in doc["nodes"]}
    S = {i for i, z in zone.items() if z in ("a", "m")}
    T = {i for i, z in zone.items() if z in ("b", "m")}
    return S, T, [(s, t) for s in sorted(S) for t in sorted(T) if s != t]


def oracle_overlap_reach(doc: dict, hops: int, exempt_zone: str | None = None) -> Verdict | str:
    zone = {n["id"]: n["zone"] for n in doc["nodes"]}
    app = {n["id"] for n in doc["nodes"] if "app" in n["tags"]}
    bo = {n["id"] for n in doc["nodes"] if not covered_dir(n, "out")}
    bi = {n["id"] for n in doc["nodes"] if not covered_dir(n, "in")}
    _, _, all_pairs = _pairs(doc)
    if not all_pairs:
        return "EMPTY"
    pairs = [(s, t) for s, t in all_pairs if zone[t] != exempt_zone]
    known = {(e["src"], e["dst"]) for e in doc["edges"] if e["proto"] == "tcp"}
    unknown = {(u, v) for u in bo for v in bi if u != v}

    def walk(src: str, adj: set[tuple[str, str]]) -> set[str]:
        seen = {src}
        for _ in range(hops):
            seen |= {d for (u, d) in adj if u in seen and (u not in app or u == src)}
        return seen

    if any(t in walk(s, known) for s, t in pairs):
        return Verdict.VIOLATED
    if any(t in walk(s, known | unknown) for s, t in pairs):
        return Verdict.UNKNOWN
    return Verdict.HOLDS


@pytest.mark.parametrize("seed", range(600))
def test_overlapping_reach_matches_the_pairwise_oracle(seed):
    rng = random.Random(80000 + seed)
    doc = random_dir_doc(rng)
    hops = rng.randint(1, 5)
    allow = rng.choice(["", "", ALLOW_M])
    got = evaluate(compile_text(OVERLAP_YAML.format(hops=hops, allow=allow)),
                   ReachGraph.from_dict(doc), NOW)
    want = oracle_overlap_reach(doc, hops, "m" if allow else None)
    if want == "EMPTY":
        assert got.verdict is Verdict.UNKNOWN and got.reasons[0].startswith("empty_selector")
    else:
        assert got.verdict is want, (seed, hops, allow, doc)
    if got.verdict is Verdict.VIOLATED:       # the pinned list is every violating target, sorted
        assert got.violating_targets == sorted(got.violating_targets)
        assert len(got.violating_targets) == got.violation_count


def oracle_overlap_expose(doc: dict) -> Verdict | str:
    bo = {n["id"] for n in doc["nodes"] if not covered_dir(n, "out")}
    bi = {n["id"] for n in doc["nodes"] if not covered_dir(n, "in")}
    S, T, pairs = _pairs(doc)
    if not pairs:
        return "EMPTY"
    if any((e["src"], e["dst"]) in set(pairs) and e["proto"] == "tcp" and e["ports"] not in ("80", "443")
           for e in doc["edges"]):
        return Verdict.VIOLATED
    return Verdict.UNKNOWN if any(s in bo and t in bi for s, t in pairs) else Verdict.HOLDS


@pytest.mark.parametrize("seed", range(400))
def test_overlapping_exposure_matches_the_pairwise_oracle(seed):
    rng = random.Random(81000 + seed)
    doc = random_dir_doc(rng)
    got = evaluate(compile_text(OVERLAP_EXPOSE_YAML), ReachGraph.from_dict(doc), NOW)
    want = oracle_overlap_expose(doc)
    if want == "EMPTY":
        assert got.verdict is Verdict.UNKNOWN and got.reasons[0].startswith("empty_selector")
    else:
        assert got.verdict is want, (seed, doc)


@pytest.mark.parametrize("seed", range(1500))
def test_overlap_and_exception_holds_stays_true_until_its_stated_expiry(seed):
    """The valid_until promise again, now with overlapping selectors and with an allow exception
    that expires inside the evidence window (the exception, not coverage, is then the limit)."""
    rng = random.Random(82000 + seed)
    doc = random_dir_doc(rng)
    plan = compile_text(rng.choice([
        OVERLAP_YAML.format(hops=rng.randint(1, 5), allow=""),
        OVERLAP_YAML.format(hops=rng.randint(1, 5), allow=ALLOW_M),
        OVERLAP_EXPOSE_YAML]))
    r = evaluate(plan, ReachGraph.from_dict(doc), NOW)
    if r.verdict is not Verdict.HOLDS:
        return
    assert r.valid_until is not None      # a HOLDS is never open-ended
    span = r.valid_until - NOW
    for t in (NOW + span / 5, NOW + span / 2, NOW + span * 0.9, r.valid_until):
        if t >= NOW:
            assert evaluate(plan, ReachGraph.from_dict(doc), t).verdict is Verdict.HOLDS, (seed, t, doc)
