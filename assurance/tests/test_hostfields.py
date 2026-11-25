"""The typed registry's accessors: what each field reads, and every way a fact can be unusable."""
from __future__ import annotations

import datetime as dt
import ipaddress

import pytest

from paddock_assurance import hostfields as HF
from paddock_assurance.tier import Tier
from tests.hostfix import (FRESH, NOW, STALE, fact, firewall, good_facts, hgraph, hnode, listeners,
                           patch, sshd)

MAX_AGE = dt.timedelta(hours=6)


def host_of(facts):
    return hgraph(hnode("h", facts)).nodes["h"].host


def res(field, params, facts, *, min_tier=Tier.configured, now=NOW, max_age=MAX_AGE):
    return HF.resolve(HF.REGISTRY[field], params, host_of(facts), now, min_tier, max_age)


# (field, params, collector, the value on the good fixture)
GOOD = [
    ("host.sshd.installed", (), "sshd", True),
    ("host.sshd.password_login_possible", (), "sshd", False),
    ("host.sshd.root_login_possible", (), "sshd", False),
    ("host.sshd.passwordauthentication", (), "sshd", "no"),
    ("host.sshd.kbdinteractiveauthentication", (), "sshd", "no"),
    ("host.sshd.permitrootlogin", (), "sshd", "no"),
    ("host.sshd.permitemptypasswords", (), "sshd", "no"),
    ("host.sshd.pubkeyauthentication", (), "sshd", "yes"),
    ("host.sshd.usepam", (), "sshd", "yes"),
    ("host.sshd.authenticationmethods", (), "sshd", "any"),
    ("host.sshd.maxauthtries", (), "sshd", 3),
    ("host.sshd.allowusers_set", (), "sshd", False),        # no AllowUsers: everyone may log in
    ("host.sshd.allowgroups_set", (), "sshd", False),
    ("host.fw.default_inbound_all_families", (), "firewall", "deny"),
    ("host.fw.engine", (), "firewall", "nft"),
    ("host.fw.ipv6_enabled", (), "firewall", True),
    ("host.listener.exists", (22,), "listeners", True),
    ("host.listener.exists", (8080,), "listeners", False),
    ("host.listener.wildcard", (22,), "listeners", True),
    ("host.listener.process", (22,), "listeners", frozenset(["sshd"])),
    ("host.listeners.count", (), "listeners", 2),
    ("host.listeners.addresses", (), "listeners", frozenset([ipaddress.ip_network("0.0.0.0/32")])),
    ("host.patch.security_updates_pending", (), "patch", 0),
    ("host.patch.reboot_required", (), "patch", False),
]


@pytest.mark.parametrize("field,params,collector,value", GOOD)
def test_good_fixture_gives_the_value(field, params, collector, value):
    r = res(field, params, good_facts())
    assert r.known and r.value == value and r.tier is Tier.configured and r.fact is not None


def unusable_mutations():
    """(label, mutation of a collector fact, expected reason)."""
    return [
        ("unsigned", lambda f: f.update(signed=False), "unsigned"),
        ("stale", lambda f: f.update(observed_at=STALE), "stale"),
        ("future", lambda f: f.update(observed_at="2026-12-01T09:06:00Z"), "future_timestamp"),
        ("tier_declared", lambda f: f.update(tier="declared"), "tier_below_min"),
        ("conflict", lambda f: f.update(conflict=True), "evidence_conflict"),
        ("conflict_obj", lambda f: f.update(conflict={"kind": "scan_open"}), "evidence_conflict"),
        ("status_error", lambda f: f.update(status="error", reason="timeout"), "collector_error"),
        ("status_unavailable", lambda f: f.update(status="unavailable", reason="permission_denied"),
         "unavailable"),
    ]


@pytest.mark.parametrize("field,params,collector,value", GOOD)
@pytest.mark.parametrize("label,mut,reason", unusable_mutations(), ids=lambda x: x if isinstance(x, str) else "")
def test_an_unusable_fact_is_never_a_value(field, params, collector, value, label, mut, reason):
    facts = good_facts()
    mut(facts[collector])
    if field == "host.sshd.installed" and reason in ("unavailable",):
        pytest.skip("covered by the dedicated installed tests")
    r = res(field, params, facts)
    assert not r.known and r.value is None
    assert r.reason == reason


@pytest.mark.parametrize("field,params,collector,value", GOOD)
def test_missing_collector_and_missing_host(field, params, collector, value):
    facts = good_facts()
    del facts[collector]
    assert res(field, params, facts).reason == "no_sensor"
    r = HF.resolve(HF.REGISTRY[field], params, None, NOW, Tier.configured, MAX_AGE)
    assert not r.known and r.reason == "no_agent"


@pytest.mark.parametrize("field,params,collector,value", GOOD)
def test_a_fact_just_inside_the_windows_is_usable(field, params, collector, value):
    facts = good_facts()
    facts[collector]["observed_at"] = "2026-12-01T03:00:00Z"        # exactly max_age old
    assert res(field, params, facts).known
    facts[collector]["observed_at"] = "2026-12-01T02:59:59Z"
    assert res(field, params, facts).reason == "stale"
    facts[collector]["observed_at"] = "2026-12-01T09:05:00Z"        # exactly the 5 minute slack
    assert res(field, params, facts).known
    facts[collector]["observed_at"] = "2026-12-01T09:05:01Z"
    assert res(field, params, facts).reason == "future_timestamp"


def test_tier_is_capped_at_the_fields_max_and_never_lifted():
    facts = good_facts()
    facts["sshd"]["tier"] = "tested"
    r = res("host.sshd.maxauthtries", (), facts)
    assert r.known and r.tier is Tier.configured
    # a claimed `observed` does not satisfy a stricter policy either: the cap applies first
    # (compile rejects such a policy; resolve must agree if one slips through)
    assert not res("host.sshd.maxauthtries", (), facts, min_tier=Tier.observed).known
    assert res("host.sshd.maxauthtries", (), facts, min_tier=Tier.observed).reason == "tier_below_min"
    facts["sshd"]["tier"] = "declared"
    assert res("host.sshd.maxauthtries", (), facts, min_tier=Tier.declared).tier is Tier.declared


# --------------------------------------------------------------------------------------------
# exactness: approximate and partial facts

APPROX_FIELDS = [g for g in GOOD if g[2] in ("sshd", "firewall")
                 and g[0] not in ("host.fw.engine", "host.fw.ipv6_enabled", "host.sshd.installed")]


@pytest.mark.parametrize("field,params,collector,value", APPROX_FIELDS)
def test_approximate_facts_give_no_value_where_exactness_is_needed(field, params, collector, value):
    facts = good_facts()
    facts[collector]["conf"] = "approximate"
    r = res(field, params, facts)
    assert not r.known and r.reason == "approximate"


@pytest.mark.parametrize("field,params,collector,value", APPROX_FIELDS)
def test_partial_facts_give_no_value_where_completeness_is_needed(field, params, collector, value):
    facts = good_facts()
    facts[collector]["partial"] = True
    r = res(field, params, facts)
    assert not r.known and r.reason in ("partial", "approximate")


def test_unprobed_match_blocks_and_text_source_are_approximate():
    for facts in (good_facts(sshd=fact(sshd(unprobed=True))),
                  good_facts(sshd=fact(sshd(source="text"))),
                  good_facts(sshd=fact(dict(sshd(), match={"unprobed": True}))),
                  good_facts(sshd=fact({k: v for k, v in sshd().items() if k != "match"}))):
        for field in ("host.sshd.passwordauthentication", "host.sshd.password_login_possible",
                      "host.sshd.maxauthtries", "host.sshd.root_login_possible"):
            r = res(field, (), facts)
            assert not r.known and r.reason == "approximate", (field, r)


# --------------------------------------------------------------------------------------------
# sshd

def sshd_facts(deltas=None, **over):
    return good_facts(sshd=fact(sshd(deltas=deltas, **over)))


@pytest.mark.parametrize("cfg,expected", [
    ({"passwordauthentication": "yes"}, True),
    ({"passwordauthentication": "no"}, False),
    ({"passwordauthentication": "no", "kbdinteractiveauthentication": "yes", "usepam": "yes"}, True),
    ({"passwordauthentication": "no", "kbdinteractiveauthentication": "yes", "usepam": "no"}, False),
    ({"passwordauthentication": "no", "kbdinteractiveauthentication": "no", "usepam": "yes"}, False),
    # kbd-interactive + PAM, but only public keys are accepted: not password-capable
    ({"passwordauthentication": "no", "kbdinteractiveauthentication": "yes", "usepam": "yes",
      "authenticationmethods": "publickey"}, False),
    ({"passwordauthentication": "no", "kbdinteractiveauthentication": "yes", "usepam": "yes",
      "authenticationmethods": "publickey,publickey"}, False),
    ({"passwordauthentication": "no", "kbdinteractiveauthentication": "yes", "usepam": "yes",
      "authenticationmethods": "publickey,keyboard-interactive"}, True),
    ({"passwordauthentication": "no", "kbdinteractiveauthentication": "yes", "usepam": "yes",
      "authenticationmethods": "publickey keyboard-interactive"}, True),
    ({"passwordauthentication": "no", "kbdinteractiveauthentication": "yes", "usepam": "yes",
      "authenticationmethods": "any"}, True),
    ({"passwordauthentication": "YES"}, True),
])
def test_password_login_possible(cfg, expected):
    r = res("host.sshd.password_login_possible", (), sshd_facts(**cfg))
    assert r.known and r.value is expected


@pytest.mark.parametrize("cfg", [
    {"passwordauthentication": "maybe"},
    {"passwordauthentication": 1},
    {"passwordauthentication": None},
    {"passwordauthentication": "no", "kbdinteractiveauthentication": "yes", "usepam": "yes",
     "authenticationmethods": ""},
    {"passwordauthentication": "no", "kbdinteractiveauthentication": "yes", "usepam": "yes",
     "authenticationmethods": 5},
])
def test_password_login_possible_is_unknown_when_the_config_cannot_be_read(cfg):
    r = res("host.sshd.password_login_possible", (), sshd_facts(**cfg))
    assert not r.known and r.reason == "no_value"


def test_a_missing_key_is_unknown_not_false():
    facts = sshd_facts()
    del facts["sshd"]["data"]["config"]["passwordauthentication"]
    assert not res("host.sshd.password_login_possible", (), facts).known
    assert not res("host.sshd.passwordauthentication", (), facts).known
    facts = sshd_facts()
    del facts["sshd"]["data"]["config"]["kbdinteractiveauthentication"]
    assert not res("host.sshd.password_login_possible", (), facts).known   # pw=no but kbd unreadable


def test_match_block_deltas_count_for_derived_fields():
    # a Match block turns passwords on for one probed user/address
    facts = sshd_facts(deltas=[{"passwordauthentication": "yes"}])
    r = res("host.sshd.password_login_possible", (), facts)
    assert r.known and r.value is True
    # ... and removes the single-value answer for the plain field (it varies by user)
    r = res("host.sshd.passwordauthentication", (), facts)
    assert not r.known and r.reason == "match_override"
    facts = sshd_facts(deltas=[{"permitrootlogin": "yes"}])
    assert res("host.sshd.root_login_possible", (), facts).value is True
    assert res("host.sshd.permitrootlogin", (), facts).reason == "match_override"
    assert res("host.sshd.maxauthtries", (), facts).known           # untouched keys stay readable
    facts = sshd_facts(deltas=[{"maxauthtries": 10}])
    assert res("host.sshd.maxauthtries", (), facts).reason == "match_override"
    facts = sshd_facts(deltas=[{"allowusers": ["x"]}])
    assert res("host.sshd.allowusers", (), facts).reason == "match_override"


def test_a_delta_that_unsets_a_key_still_counts():
    facts = sshd_facts(deltas=[{"passwordauthentication": None}])
    assert res("host.sshd.passwordauthentication", (), facts).reason == "match_override"
    r = res("host.sshd.password_login_possible", (), facts)
    assert not r.known                                    # the variant has no password setting


@pytest.mark.parametrize("deltas", [
    [{"passwordauthentication": "no"}],
    [{"permitrootlogin": "no"}, {"permitrootlogin": "no"}],
])
def test_a_hardening_delta_does_not_make_it_worse(deltas):
    assert res("host.sshd.password_login_possible", (), sshd_facts(deltas=deltas)).value is False


@pytest.mark.parametrize("value,expected", [
    ("yes", True), ("no", False), ("prohibit-password", False), ("without-password", False),
    ("forced-commands-only", False), ("YES", True)])
def test_root_login_possible(value, expected):
    r = res("host.sshd.root_login_possible", (), sshd_facts(permitrootlogin=value))
    assert r.known and r.value is expected


def test_root_login_unreadable_or_unknown_value_is_unknown():
    for v in ("sometimes", None, 3):
        assert not res("host.sshd.root_login_possible", (), sshd_facts(permitrootlogin=v)).known


def test_permitrootlogin_normalises_the_legacy_spelling():
    r = res("host.sshd.permitrootlogin", (), sshd_facts(permitrootlogin="without-password"))
    assert r.value == "prohibit-password"


def test_scalar_values_outside_the_vocabulary_are_unknown():
    assert not res("host.sshd.passwordauthentication", (), sshd_facts(passwordauthentication="perhaps")).known
    assert not res("host.sshd.permitrootlogin", (), sshd_facts(permitrootlogin="x")).known
    assert not res("host.sshd.maxauthtries", (), sshd_facts(maxauthtries="3")).known
    assert not res("host.sshd.maxauthtries", (), sshd_facts(maxauthtries=-1)).known
    assert not res("host.sshd.maxauthtries", (), sshd_facts(maxauthtries=True)).known


def test_allow_lists_absent_has_no_value_present_means_set():
    # was "absent = the empty set": that made `subset_of` / `count()` pass the least restricted host
    # (P2 review hostcfg-1). An absent key now has no value; allowusers_set says it is not configured.
    r = res("host.sshd.allowusers", (), sshd_facts())
    assert not r.known and r.reason == "unrestricted"
    assert res("host.sshd.allowusers_set", (), sshd_facts()).value is False
    r = res("host.sshd.allowusers", (), sshd_facts(allowusers=["deploy", "ops"]))
    assert r.value == frozenset(["deploy", "ops"])
    assert not res("host.sshd.allowusers", (), sshd_facts(allowusers="deploy")).known
    assert not res("host.sshd.allowusers", (), sshd_facts(allowusers=[1])).known


def test_installed_true_only_from_an_ok_fact():
    r = res("host.sshd.installed", (), good_facts())
    assert r.known and r.value is True
    f = good_facts(sshd=fact({"installed": "yes"}))
    assert not res("host.sshd.installed", (), f).known


def absent_sshd(**lst):
    # a public listener of a program known to be no SSH server (nginx is NOT one: a web server or
    # proxy can front an SSH server, P2 review hostcfg-2)
    return good_facts(sshd=fact({}, status="unavailable", reason="tool_missing"),
                      listeners=fact(listeners(ports=(443,), comms={443: "postgres"}), **lst))


def test_installed_false_needs_a_corroborating_listener_table():
    r = res("host.sshd.installed", (), absent_sshd())
    assert r.known and r.value is False
    # no listener fact at all: an absence claim from a missing binary alone is not believed
    f = good_facts(sshd=fact({}, status="unavailable", reason="tool_missing"))
    del f["listeners"]
    r = res("host.sshd.installed", (), f)
    assert not r.known and r.reason == "no_sensor"


@pytest.mark.parametrize("lst_kwargs,reason", [
    ({"signed": False}, "unsigned"),
    ({"observed_at": STALE}, "stale"),
    ({"conflict": True}, "evidence_conflict"),
    ({"partial": True}, "partial"),
    ({"status": "error", "reason": "timeout"}, "collector_error"),
    ({"status": "unavailable", "reason": "permission_denied"}, "unavailable"),
])
def test_an_unusable_listener_table_cannot_corroborate_absence(lst_kwargs, reason):
    kw = dict(lst_kwargs)
    status = kw.pop("status", "ok")
    f = good_facts(sshd=fact({}, status="unavailable", reason="tool_missing"),
                   listeners=fact(listeners(ports=(443,)), status=status,
                                  **{("seen" if k == "observed_at" else k): v for k, v in kw.items()}))
    r = res("host.sshd.installed", (), f)
    assert not r.known and r.reason == reason


def test_installed_false_is_vetoed_by_anything_that_looks_like_ssh():
    for lst in (listeners(ports=(22,), comms={22: "weird"}),          # port 22
                listeners(ports=(2222,), comms={2222: "sshd"}),       # sshd on another port
                listeners(ports=(2200,), comms={2200: "dropbear"}),
                listeners(ports=(443,), attribution="partial"),      # cannot tell who listens
                listeners(ports=(443,), count=9)):                    # incomplete table
        f = good_facts(sshd=fact({}, status="unavailable", reason="tool_missing"),
                       listeners=fact(lst))
        r = res("host.sshd.installed", (), f)
        assert not r.known, lst


def test_installed_veto_works_even_from_an_untrusted_listener_fact():
    # an unsigned/stale listener table that shows sshd can only make the claim unknown
    f = good_facts(sshd=fact({}, status="unavailable", reason="tool_missing"),
                   listeners=fact(listeners(ports=(22,)), signed=False))
    r = res("host.sshd.installed", (), f)
    assert not r.known and r.reason == "evidence_conflict"


def test_other_unavailable_reasons_are_not_absence():
    for reason in ("permission_denied", "daemon_not_running", "no_data", "not_applicable"):
        f = good_facts(sshd=fact({}, status="unavailable", reason=reason))
        r = res("host.sshd.installed", (), f)
        assert not r.known and r.reason == "unavailable"


# --------------------------------------------------------------------------------------------
# firewall

@pytest.mark.parametrize("fw,expected", [
    (dict(ip4="drop", ip6="drop"), "deny"),
    (dict(ip4="reject", ip6="drop"), "deny"),
    (dict(ip4="drop", ip6="accept"), "allow"),            # ip6 open while IPv6 is on
    (dict(ip4="accept", ip6="drop"), "allow"),
    (dict(ip4="accept", ip6="accept"), "allow"),
    (dict(ip4="drop", ip6="accept", ipv6=False), "deny"), # IPv6 off: only ip4 counts
    (dict(ip4="accept", ip6="drop", ipv6=False), "allow"),
])
def test_default_inbound_all_families_known_answers(fw, expected):
    r = res("host.fw.default_inbound_all_families", (), good_facts(firewall=fact(firewall(**fw))))
    assert r.known and r.value == expected


@pytest.mark.parametrize("fw", [
    dict(ip4="unknown", ip6="drop"),
    dict(ip4="drop", ip6="unknown"),
    dict(ip4="unknown", ip6="unknown"),
    dict(ip4="drop", ip6="drop", read6=False),            # an enabled family that was not readable
    dict(ip4="drop", ip6="drop", confidence="approximate"),
    dict(ip4="accept", ip6="accept", confidence="approximate"),
    dict(ip4="drop", ip6="drop", confidence="unknown"),
    dict(ip4="drop", ip6="drop", dataplane=["cilium"]),
    dict(ip4="drop", ip6="drop", opaque_features=["nat_rewrite"]),
    dict(ip4="allow", ip6="drop"),                         # not a vocabulary value
])
def test_default_inbound_all_families_never_deny_when_not_sure(fw):
    r = res("host.fw.default_inbound_all_families", (), good_facts(firewall=fact(firewall(**fw))))
    assert not r.known


def test_default_inbound_all_families_needs_complete_model_fields():
    d = firewall()
    del d["ipv6_enabled"]
    assert not res("host.fw.default_inbound_all_families", (), good_facts(firewall=fact(d))).known
    d = firewall()
    del d["families"]["ip6"]
    assert not res("host.fw.default_inbound_all_families", (), good_facts(firewall=fact(d))).known
    d = firewall()
    del d["flat_view"]
    assert not res("host.fw.default_inbound_all_families", (), good_facts(firewall=fact(d))).known


def test_fw_engine_and_ipv6():
    assert res("host.fw.engine", (), good_facts()).value == "nft"
    assert res("host.fw.ipv6_enabled", (), good_facts(firewall=fact(firewall(ipv6=False)))).value is False
    assert not res("host.fw.engine", (), good_facts(firewall=fact(firewall(backend="weird")))).known
    # engine/ipv6 do not need exactness, but still need a usable fact
    assert res("host.fw.engine", (), good_facts(firewall=fact(firewall(), conf="approximate"))).known
    assert not res("host.fw.engine", (), good_facts(firewall=fact(firewall(), signed=False))).known


# --------------------------------------------------------------------------------------------
# listeners

def lst(**kw):
    return good_facts(listeners=fact(listeners(**kw)))


def lst_partial(**kw):
    return good_facts(listeners=fact(listeners(**kw), partial=True))


def test_listener_exists_positive_survives_a_partial_table_negative_does_not():
    assert res("host.listener.exists", (22,), lst()).value is True
    assert res("host.listener.exists", (23,), lst()).value is False
    p = lst_partial()
    assert res("host.listener.exists", (22,), p).value is True      # a seen listener is real
    r = res("host.listener.exists", (23,), p)
    assert not r.known and r.reason == "partial"                    # an unseen one proves nothing
    r = res("host.listener.exists", (23,), lst(count=9))            # count disagrees with rows
    assert not r.known
    approx = good_facts(listeners=fact(listeners(), conf="approximate"))
    assert not res("host.listener.exists", (23,), approx).known
    assert res("host.listener.exists", (22,), approx).value is True


def test_listener_wildcard():
    assert res("host.listener.wildcard", (22,), lst()).value is True
    assert res("host.listener.wildcard", (22,), lst(ip="127.0.0.1", bind="loopback4")).value is False
    assert res("host.listener.wildcard", (22,), lst(ip="::", bind="wildcard6")).value is True
    assert res("host.listener.wildcard", (80,), lst()).value is False
    assert not res("host.listener.wildcard", (80,), lst_partial()).known
    assert res("host.listener.wildcard", (22,), lst_partial()).value is True


def test_listener_process_needs_complete_attribution():
    assert res("host.listener.process", (22,), lst()).value == frozenset(["sshd"])
    assert res("host.listener.process", (80,), lst()).value == frozenset()
    assert not res("host.listener.process", (22,), lst(attribution="partial")).known
    assert not res("host.listener.process", (22,), lst(attribution="denied")).known
    assert not res("host.listener.process", (22,), lst_partial()).known
    d = listeners()
    d["listeners"][0]["comm"] = None
    assert not res("host.listener.process", (22,), good_facts(listeners=fact(d))).known


def test_listeners_count_and_addresses():
    assert res("host.listeners.count", (), lst(ports=(22, 80, 443))).value == 3
    assert not res("host.listeners.count", (), lst_partial()).known
    assert not res("host.listeners.count", (), lst(count=5)).known
    r = res("host.listeners.addresses", (), lst(ip="10.1.2.3"))
    assert r.value == frozenset([ipaddress.ip_network("10.1.2.3/32")])
    r = res("host.listeners.addresses", (), lst(ip="::1", bind="loopback6"))
    assert r.value == frozenset([ipaddress.ip_network("::1/128")])
    assert not res("host.listeners.addresses", (), lst(ip="not-an-ip")).known
    assert not res("host.listeners.addresses", (), lst_partial()).known


def test_malformed_listener_rows_are_unknown_not_empty():
    for rows in ([{"port": "22", "ip": "0.0.0.0"}], [{"port": 22}], ["x"], [None]):
        d = {"count": len(rows), "listeners": rows, "attribution": {"status": "ok"}}
        f = good_facts(listeners=fact(d))
        assert not res("host.listener.exists", (23,), f).known
        assert not res("host.listeners.count", (), f).known
    d = {"count": 0, "attribution": {"status": "ok"}}                 # no `listeners` key at all
    assert not res("host.listener.exists", (23,), good_facts(listeners=fact(d))).known


# --------------------------------------------------------------------------------------------
# patch

def test_patch_fields_and_their_failure_modes():
    assert res("host.patch.security_updates_pending", (), good_facts(patch=fact(patch(security=3)))).value == 3
    assert res("host.patch.reboot_required", (), good_facts(patch=fact(patch(reboot=True)))).value is True
    # a partial patch section (one block failed) still answers for the blocks that are ok
    f = good_facts(patch=fact(patch(), partial=True))
    assert res("host.patch.reboot_required", (), f).known
    bad = {"pending": {"state": "error", "reason": "timeout"}, "reboot": {"state": "unavailable"}}
    f = good_facts(patch=fact(bad, partial=True))
    assert not res("host.patch.security_updates_pending", (), f).known
    assert not res("host.patch.reboot_required", (), f).known
    for v in (-1, "3", True, None):
        d = {"pending": {"state": "ok", "security": v}, "reboot": {"state": "ok", "required": "no"}}
        f = good_facts(patch=fact(d))
        assert not res("host.patch.security_updates_pending", (), f).known
        assert not res("host.patch.reboot_required", (), f).known


# --------------------------------------------------------------------------------------------
# robustness

def test_an_accessor_that_raises_reads_as_unknown(monkeypatch):
    spec = HF.REGISTRY["host.sshd.maxauthtries"]

    def boom(fact, params, ctx):
        raise RuntimeError("bug")
    monkeypatch.setitem(HF.REGISTRY, spec.name, HF.FieldSpec(
        spec.name, spec.type, spec.collector, spec.max_tier, boom, spec.doc))
    r = res("host.sshd.maxauthtries", (), good_facts())
    assert not r.known and r.reason == "no_value"


def test_an_accessor_returning_the_wrong_type_is_unknown(monkeypatch):
    spec = HF.REGISTRY["host.sshd.maxauthtries"]
    monkeypatch.setitem(HF.REGISTRY, spec.name, HF.FieldSpec(
        spec.name, spec.type, spec.collector, spec.max_tier,
        lambda f, p, c: HF.Known("three"), spec.doc))
    assert not res("host.sshd.maxauthtries", (), good_facts()).known
    monkeypatch.setitem(HF.REGISTRY, spec.name, HF.FieldSpec(
        spec.name, spec.type, spec.collector, spec.max_tier,
        lambda f, p, c: HF.Known(True), spec.doc))                   # bool is not an int here
    assert not res("host.sshd.maxauthtries", (), good_facts()).known


def test_reason_order_puts_the_fundamental_reason_first():
    order = HF.REASON_ORDER
    assert order.index("no_agent") < order.index("unsigned") < order.index("stale")
    assert HF.reason_rank("never-heard-of-it") == len(order)


def test_a_stale_violating_value_is_unknown_not_false():
    facts = good_facts(sshd=fact(sshd(passwordauthentication="yes"), seen=STALE))
    r = res("host.sshd.password_login_possible", (), facts)
    assert not r.known and r.reason == "stale" and r.value is None
    fresh = good_facts(sshd=fact(sshd(passwordauthentication="yes"), seen=FRESH))
    assert res("host.sshd.password_login_possible", (), fresh).value is True
