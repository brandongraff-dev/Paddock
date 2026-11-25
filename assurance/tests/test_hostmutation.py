"""Mutation checks: break one security-relevant rule at a time and prove the oracle notices.

Each test patches the implementation (never the oracle), runs the same comparison the regular
oracle test runs, and demands at least one mismatch. If a rule could be silently dropped, one of
these would fail. (The same mutations were also applied to the source files by hand; see the
package report.)
"""
from __future__ import annotations

import pytest

import importlib

from paddock_assurance import hostconfig as HC
from paddock_assurance import hostfields as HF
from paddock_assurance import kleene as K
from tests import oracle_host as O

ev_mod = importlib.import_module("paddock_assurance.evaluate")     # the module, not the function
SEEDS = range(700)


def detects() -> list[str]:
    """Mismatches the oracle finds; a crash of the mutated code counts as detected too."""
    try:
        return O.find_mismatch(SEEDS)
    except Exception as exc:                  # noqa: BLE001
        return [f"crashed: {exc!r}"]


def test_baseline_has_no_mismatch():
    assert O.find_mismatch(SEEDS) == []


def test_mutation_all_without_false_dominance(monkeypatch):
    """Flip a Kleene rule: ``all`` lets an unknown override a false."""
    def bad(values):
        values = list(values)
        if any(v is None for v in values):
            return None
        return all(values)
    monkeypatch.setattr(K, "k_all", bad)
    assert detects()


def test_mutation_any_without_true_dominance(monkeypatch):
    """Flip a Kleene rule: ``any`` lets an unknown override a true."""
    def bad(values):
        values = list(values)
        if any(v is None for v in values):
            return None
        return any(values)
    monkeypatch.setattr(K, "k_any", bad)
    assert detects()


def test_mutation_unknown_counts_as_true_in_any(monkeypatch):
    monkeypatch.setattr(K, "k_any", lambda values: True if any(v is not False for v in values) else False)
    assert detects()


def test_mutation_not_of_unknown_is_true(monkeypatch):
    monkeypatch.setattr(K, "k_not", lambda v: True if v is None else (not v))
    assert detects()


def test_mutation_drop_the_signed_requirement(monkeypatch):
    real = HF.trust_problem

    def bad(fact, tier, now, min_tier, max_age):
        if not fact.signed:
            return real(_signed_copy(fact), tier, now, min_tier, max_age)
        return real(fact, tier, now, min_tier, max_age)
    monkeypatch.setattr(HF, "trust_problem", bad)
    assert detects()


def _signed_copy(fact):
    import dataclasses
    return dataclasses.replace(fact, signed=True)


def test_mutation_stale_facts_count_as_fresh(monkeypatch):
    import datetime as dt
    real = HF.trust_problem

    def bad(fact, tier, now, min_tier, max_age):
        return real(fact, tier, now, min_tier, max_age + dt.timedelta(days=365))
    monkeypatch.setattr(HF, "trust_problem", bad)
    assert detects()


def test_mutation_no_future_slack_limit(monkeypatch):
    import datetime as dt
    monkeypatch.setattr(HF, "FUTURE_SLACK", dt.timedelta(days=365))
    assert detects()


def test_mutation_ignore_the_tier_gate(monkeypatch):
    real = HF.trust_problem
    monkeypatch.setattr(HF, "trust_problem",
                        lambda fact, tier, now, min_tier, max_age:
                        real(fact, HF.Tier.tested, now, min_tier, max_age))
    assert detects()


def test_mutation_ignore_conflict(monkeypatch):
    import dataclasses
    real = HF.trust_problem
    monkeypatch.setattr(HF, "trust_problem",
                        lambda fact, tier, now, min_tier, max_age:
                        real(dataclasses.replace(fact, conflict=False), tier, now, min_tier, max_age))
    assert detects()


def test_mutation_an_unusable_fact_reads_as_false(monkeypatch):
    """The cardinal sin: an unusable fact becomes a (false) value instead of unknown."""
    sentinel = object()
    orig_resolve, orig_compare = HC.HostEvaluator.resolve, HC.compare

    def bad_resolve(self, leaf):
        r = orig_resolve(self, leaf)
        if not r.known and r.fact is not None:
            return HF.Resolved(True, sentinel, "", r.fact, r.tier)
        return r

    def bad_compare(leaf, spec, value):
        return False if value is sentinel else orig_compare(leaf, spec, value)
    monkeypatch.setattr(HC.HostEvaluator, "resolve", bad_resolve)
    monkeypatch.setattr(HC, "compare", bad_compare)
    assert detects()


def test_mutation_accessors_ignore_exactness_and_status(monkeypatch):
    monkeypatch.setattr(HF, "_need", lambda fact, *, exact, partial_ok=False: None)
    assert detects()


def test_mutation_unknown_hosts_are_ignored(monkeypatch):
    """Aggregation mutation: a host that evaluates to unknown is treated as passing."""
    orig = HC.HostEvaluator.evaluate

    def bad(self, node):
        e = orig(self, node)
        if e.tv is None and self is not None and e.node is node and getattr(self, "_root", None) is None:
            pass
        return e
    # patch at the aggregation site: unknown hosts do not count
    real_eval = ev_mod._eval_hostconfig

    def lenient(plan, g, now):
        res = real_eval(plan, g, now)
        if res.verdict.value == "UNKNOWN" and res.reasons and res.reasons[0].startswith("hosts_unknown"):
            res.verdict = ev_mod.Verdict.HOLDS
        return res
    monkeypatch.setattr(ev_mod, "_eval_hostconfig", lenient)
    assert detects()


def test_mutation_a_violation_is_downgraded_by_an_unknown_host(monkeypatch):
    real_eval = ev_mod._eval_hostconfig

    def timid(plan, g, now):
        res = real_eval(plan, g, now)
        if res.verdict.value == "VIOLATED" and res.hosts.get("unknown"):
            res.verdict = ev_mod.Verdict.UNKNOWN
        return res
    monkeypatch.setattr(ev_mod, "_eval_hostconfig", timid)
    assert detects()


def test_mutation_valid_until_ignores_the_relied_facts(monkeypatch):
    real_eval = ev_mod._eval_hostconfig

    def forever(plan, g, now):
        res = real_eval(plan, g, now)
        if res.verdict.value == "HOLDS":
            import datetime as dt
            res.valid_until = now + dt.timedelta(days=3650)
        return res
    monkeypatch.setattr(ev_mod, "_eval_hostconfig", forever)
    # the generic comparison only bounds valid_until from below, so check the time-travel property
    import datetime as dt
    from paddock_assurance import ReachGraph, Verdict
    from tests.hostfix import NOW, host_plan_doc
    broke = 0
    for seed in range(400):
        r, hosts, tree, min_tier, require = O.scenario(seed)
        if require != 1.0:
            continue
        plan = host_plan_doc(O.render_doc(tree, r), min_tier=min_tier, require=require)
        res = ev_mod.evaluate(plan, ReachGraph.from_dict(O.to_graph_doc(hosts, 1)), NOW)
        if res.verdict is not Verdict.HOLDS:
            continue
        late = NOW + dt.timedelta(hours=30)
        if O.estate_verdict(tree, hosts, late, min_tier, O.MAX_AGE, require)["verdict"] != "HOLDS" \
                and res.valid_until > late:
            broke += 1
    assert broke


def test_mutation_installed_false_without_corroboration(monkeypatch):
    monkeypatch.setattr(HF, "_absence_corroborated", lambda ctx: None)
    assert detects()


def test_mutation_installed_false_ignores_the_ssh_veto(monkeypatch):
    monkeypatch.setattr(HF, "_sshd_seen_elsewhere", lambda host: False)
    assert detects()


def test_mutation_password_login_possible_is_always_false(monkeypatch):
    spec = HF.REGISTRY["host.sshd.password_login_possible"]
    monkeypatch.setitem(HF.REGISTRY, spec.name, HF.FieldSpec(
        spec.name, spec.type, spec.collector, spec.max_tier, lambda f, p, c: HF.Known(False),
        spec.doc, derived=True))
    assert detects()


def test_mutation_default_deny_ignores_ipv6(monkeypatch):
    """host.fw.default_inbound_all_families must count IPv6 while it is enabled."""
    spec = HF.REGISTRY["host.fw.default_inbound_all_families"]
    real = spec.accessor

    def v4_only(fact, params, ctx):
        out = real(fact, params, ctx)
        if isinstance(out, HF.Unknown):
            return out
        d = fact.data
        if d.get("ipv6_enabled") and out.value == "allow" \
                and d["families"]["ip4"]["effective_default"] != "accept":
            return HF.Known("deny")
        return out
    monkeypatch.setitem(HF.REGISTRY, spec.name, HF.FieldSpec(
        spec.name, spec.type, spec.collector, spec.max_tier, v4_only, spec.doc, derived=True,
        choices=spec.choices))
    assert detects()


# ---- P2 review (hostcfg-1..8): each new rule is pinned by a mutation the oracle must notice -------

def test_mutation_ignore_a_pending_reload(monkeypatch):
    """sshd -T describes the files on disk: the running daemon must be known to run them."""
    monkeypatch.setattr(HF, "_daemon_problem", lambda d: None)
    assert detects()


def test_mutation_any_listener_corroborates_an_absence(monkeypatch):
    """A proxy or an unlisted program may front an SSH server."""
    monkeypatch.setattr(HF, "_unlisted_listener", lambda rows: False)
    assert detects()


def test_mutation_a_tombstoned_host_is_read_normally(monkeypatch):
    monkeypatch.setattr(HF, "tombstone", lambda host: "")
    assert detects()


def test_mutation_a_varying_key_is_judged_even_under_not(monkeypatch):
    """not(x == "yes") over a key that varies per user must not read as "no variant has yes"."""
    real = HC.HostEvaluator.evaluate

    def always_plain(self, node, under_not=False):
        return real(self, node, False)
    monkeypatch.setattr(HC.HostEvaluator, "evaluate", always_plain)
    assert detects()


def test_mutation_a_varying_key_needs_only_one_satisfying_variant(monkeypatch):
    """Per variant it is a universal claim: one weakened variant is a violation."""
    real = HC.HostEvaluator._per_variant

    def lenient(self, node, spec, res):
        out = real(self, node, spec, res)
        if out.tv is False:
            return HC.Ev(node, None, leaf=HC.LeafEval(node, spec, res))
        return out
    monkeypatch.setattr(HC.HostEvaluator, "_per_variant", lenient)
    assert detects()


def test_mutation_read_only_reload_pending_as_daemon_evidence(monkeypatch):
    """A daemon whose command line or binary could not be read (null flags) is not positive evidence
    that it runs the default config: only reload_pending was checked before the rework."""
    real = HF._daemon_problem

    def weak(d):
        daemon = d.get("daemon")
        if hasattr(daemon, "get") and daemon.get("reload_pending") is False:
            return None
        return real(d)
    monkeypatch.setattr(HF, "_daemon_problem", weak)
    assert detects()


def test_mutation_a_false_per_variant_leaf_under_any_is_a_witness(monkeypatch):
    """Two leaves that each fail for SOME variant do not make an ``any`` fail in one variant."""
    real_ev = HC.Ev

    def no_wit(*a, **k):
        k["wit"] = False
        return real_ev(*a, **k)
    monkeypatch.setattr(HC, "Ev", no_wit)
    assert detects()
