"""Round-2 regressions for the host-config library (P2 review residuals L-4, L-5). Each test failed
against the round-1 source for the reason in its comment."""
from __future__ import annotations

import datetime as dt

import pytest

from paddock_assurance import Verdict, evaluate, stdlib
from paddock_assurance import hostfields as HF
from paddock_assurance.tier import Tier
from tests.hostfix import NOW, fact, good_facts, hgraph, hnode, host_plan, sshd

MAX_AGE = dt.timedelta(hours=6)
SSH = "std:server-ssh-hardened"


def host_of(facts):
    return hgraph(hnode("h", facts)).nodes["h"].host


def res(field, params, facts, *, min_tier=Tier.configured):
    return HF.resolve(HF.REGISTRY[field], params, host_of(facts), NOW, min_tier, MAX_AGE)


def sshd_facts(deltas=None, **kw):
    return good_facts(sshd=fact(sshd(deltas=deltas, **kw)))


def verdict(assert_yaml, facts):
    return evaluate(host_plan(assert_yaml), hgraph(hnode("h", facts)), NOW)


def std(facts):
    return evaluate(stdlib.load_std(SSH), hgraph(hnode("h", facts)), NOW)


# --------------------------------------------------------------------------------------------
# L-4: AllowUsers / AllowGroups with a wildcard or a negation do not restrict to a set
# failed before: 'host.sshd.allowusers_set == true' on allowusers=['*'] gave HOLDS, and so did
# 'count(host.sshd.allowusers) <= 1' (a '*' lets every account in)

PATTERNS = [["*"], ["dep*"], ["?"], ["deploy", "*"], ["!bob"], ["*@10.0.0.*"], ["deploy", "!bob"]]


@pytest.mark.parametrize("key", ["allowusers", "allowgroups"])
@pytest.mark.parametrize("val", PATTERNS)
def test_l4_a_pattern_list_is_never_reported_as_a_restrictive_set(key, val):
    f = sshd_facts(**{key: val})
    r = res("host.%s.%s_set" % ("sshd", key), (), f)
    assert not r.known, (key, val)                       # was Known(True)
    r = res("host.sshd." + key, (), f)
    assert not r.known, (key, val)
    for pred in ("host.sshd.%s_set == true" % key, "count(host.sshd.%s) <= 1" % key,
                 "host.sshd.%s subset_of [\"deploy\"]" % key):
        v = verdict("'%s'" % pred, f)
        assert v.verdict is Verdict.UNKNOWN and not v.violating_targets, (pred, val, v.verdict)


def test_l4_literal_lists_are_still_evaluated():
    f = sshd_facts(allowusers=["deploy", "ops@10.0.0.1"], allowgroups=["ops"])
    assert res("host.sshd.allowusers_set", (), f).value is True
    assert res("host.sshd.allowusers", (), f).value == frozenset(["deploy", "ops@10.0.0.1"])
    assert verdict("'count(host.sshd.allowgroups) <= 1'", f).verdict is Verdict.HOLDS


def test_l4_a_pattern_in_a_match_variant_is_unknown_and_an_absent_variant_stays_false():
    f = sshd_facts(deltas=[{"allowusers": ["*"]}], allowusers=["deploy"])
    assert not res("host.sshd.allowusers_set", (), f).known
    f = sshd_facts(deltas=[{"allowusers": None}, {"allowusers": ["*"]}], allowusers=["deploy"])
    assert res("host.sshd.allowusers_set", (), f).value is False      # one variant has none: a false stays false


# --------------------------------------------------------------------------------------------
# L-5: a probe delta (or config) key that is not the lower-case key the agent writes is not ignored
# failed before: std:server-ssh-hardened on deltas=[{'MaxAuthTries': 10}] gave HOLDS

@pytest.mark.parametrize("delta", [
    {"MaxAuthTries": 10}, {"PasswordAuthentication": "yes"}, {"permitRootLogin": "yes"},
    {"challengeresponseauthentication": "yes"},       # an alias the agent normalises; never sent as such
    {"unknownkey": "x"}, {"": 1}, {" maxauthtries": 10},
])
def test_l5_a_delta_with_an_unknown_or_non_lowercase_key_is_not_silently_ignored(delta):
    r = std(sshd_facts(deltas=[delta]))
    assert r.verdict is not Verdict.HOLDS, delta          # was HOLDS
    assert r.verdict is Verdict.UNKNOWN and not r.violating_targets, (delta, r.verdict)
    for field in ("host.sshd.maxauthtries", "host.sshd.passwordauthentication",
                  "host.sshd.password_login_possible", "host.sshd.allowusers_set"):
        assert not res(field, (), sshd_facts(deltas=[delta])).known, (field, delta)


def test_l5_a_non_lowercase_config_key_is_not_silently_ignored():
    f = good_facts(sshd=fact(sshd(**{"PasswordAuthentication": "yes"})))
    assert std(f).verdict is not Verdict.HOLDS


def test_l5_lower_case_allow_listed_deltas_still_work():
    assert std(sshd_facts(deltas=[{"maxauthtries": 2}])).verdict is Verdict.HOLDS
    assert std(sshd_facts(deltas=[{"maxauthtries": 10}])).verdict is Verdict.VIOLATED
    assert std(sshd_facts(deltas=[{"x11forwarding": "yes"}])).verdict is Verdict.HOLDS   # harmless, known key
