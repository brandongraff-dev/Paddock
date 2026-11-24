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
