"""The two shipped host-config invariants, the example estates and the CLI around them."""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest

from paddock_assurance import ReachGraph, Verdict, evaluate, stdlib
from paddock_assurance.cli import main
from paddock_assurance.compile import PlanKind
from paddock_assurance.tier import Tier
from tests.hostfix import NOW, fact, firewall, good_facts, hgraph, hnode, listeners, sshd

EX = Path(__file__).resolve().parent.parent / "examples"
SSH = "std:server-ssh-hardened"
FW = "std:server-default-deny-inbound"

# The std baseline is digest-bound: changing the text of either file is a new version, so the
# digest is pinned. If this fails you changed a shipped invariant; ship it under a new id instead.
PINNED = {
    SSH: "sha256:5604713d69137e7bbe84f589c6c042fece4de75fdeb9b734d0e5428560448737",
    FW: "sha256:d6cff000f1f14abac09b5f5099ab66a12ba894f44932cd1174ec731116fb7ec1",
}
P1_PINNED = {      # unchanged by P2: the structured form only applies to host-config
    "std:coverage-complete": "sha256:1d2fd7796bc97d756d7d501ea972d09f7d2935e4fb7695e3613783b1bf8c93b1",
    "std:guest-cannot-reach-pos": "sha256:e261c80c93ca592db7f8eb4c08a42e66d1748eab61038722b958bc33bb69fc1c",
    "std:no-internet-to-datastore": "sha256:a6a8227c5cc662a688f14fe5c79dbe929539369c6bd5639750e72c1b92298bc6",
    "std:public-ports-allowlist": "sha256:4d714ab54f086fbccb92a1369298c001cf03946c96203ffd7e7c0e14b3961206",
}


def run(capsys, *argv):
    code = main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_std_digests_are_pinned():
    for sid, d in {**PINNED, **P1_PINNED}.items():
        assert stdlib.load_std(sid).digest == d, sid


@pytest.mark.parametrize("sid", [SSH, FW])
def test_std_host_invariants_match_the_contract(sid):
    p = stdlib.load_std(sid)
    inv = p.invariant
    assert p.kind is PlanKind.HOSTCONFIG and inv.assert_ == "host-config" and inv.severity == "high"
    assert inv.subjects.to.tag == ("agent", "server") and inv.subjects.from_ is None
    assert p.min_tier is Tier.configured and p.max_age == dt.timedelta(hours=6)
    assert p.coverage_required == 1.0 and inv.on_violation.finding is True


def test_std_ssh_hardened_is_exactly_the_contract_predicate():
    from paddock_assurance import hostexpr as X
    got = stdlib.load_std(SSH).expr
    want = X.parse_assertion({"any": [
        "host.sshd.installed == false",
        {"all": ["host.sshd.password_login_possible == false", "host.sshd.root_login_possible == false",
                 'host.sshd.permitemptypasswords == "no"', 'host.sshd.pubkeyauthentication == "yes"',
                 "host.sshd.maxauthtries <= 4"]}]})
    assert got == want
    assert stdlib.load_std(FW).expr == X.parse_predicate(
        'host.fw.default_inbound_all_families == "deny"')


def good_host(id_="web-1", tags=("agent", "server"), **over):
    return hnode(id_, good_facts(**over), tags=tags)


def verdicts(g, now=NOW):
    return {sid: evaluate(stdlib.load_std(sid), g, now) for sid in (SSH, FW)}


def test_hardened_estate_holds_both_at_configured_tier():
    g = hgraph(good_host("a"), good_host("b"), good_host("c", tags=("agent",)))
    for sid, r in verdicts(g).items():
        assert r.verdict is Verdict.HOLDS, sid
        assert r.evidence_tier is Tier.configured and r.valid_until is not None
        assert r.hosts["selected"] == 3 and r.status_at(NOW) == "HOLDS"


@pytest.mark.parametrize("over", [
    {"passwordauthentication": "yes"},
    {"permitrootlogin": "yes"},
    {"permitemptypasswords": "yes"},
    {"pubkeyauthentication": "no"},
    {"maxauthtries": 5},
    {"passwordauthentication": "no", "kbdinteractiveauthentication": "yes", "usepam": "yes"},
])
def test_each_ssh_weakness_is_a_violation_with_a_witness(over):
    g = hgraph(good_host("a", sshd=fact(sshd(**over))))
    r = verdicts(g)[SSH]
    assert r.verdict is Verdict.VIOLATED and r.violating_targets == ["a"] and r.witnesses
    assert all(w.detail["node"] == "a" and w.detail["tier"] == "configured" for w in r.witnesses)


def test_flipping_password_authentication_flips_the_verdict():
    ok = hgraph(good_host("a"))
    bad = hgraph(good_host("a", sshd=fact(sshd(passwordauthentication="yes"))))
    assert verdicts(ok)[SSH].verdict is Verdict.HOLDS
    r = verdicts(bad)[SSH]
    assert r.verdict is Verdict.VIOLATED
    assert any(w.detail["field"] == "host.sshd.password_login_possible" and w.detail["observed"] == "true"
               for w in r.witnesses)


def test_a_match_block_that_enables_passwords_is_caught():
    g = hgraph(good_host("a", sshd=fact(sshd(deltas=[{"passwordauthentication": "yes"}]))))
    assert verdicts(g)[SSH].verdict is Verdict.VIOLATED


def test_text_parsed_or_unprobed_sshd_never_holds():
    for data in (sshd(source="text"), sshd(unprobed=True)):
        g = hgraph(good_host("a", sshd=fact(data, conf="approximate")))
        r = verdicts(g)[SSH]
        assert r.verdict is Verdict.UNKNOWN
        assert [(b.reason, b.collector) for b in r.blind_spots] == [("approximate", "sshd")]


def test_a_host_without_sshd_passes_only_when_a_listener_table_agrees():
    gone = fact({}, status="unavailable", reason="tool_missing")
    ok = hgraph(good_host("a", sshd=gone, listeners=fact(listeners(ports=(443,)))))
    assert verdicts(ok)[SSH].verdict is Verdict.HOLDS
    lonely = good_facts(sshd=gone)
    del lonely["listeners"]
    assert verdicts(hgraph(hnode("a", lonely)))[SSH].verdict is Verdict.UNKNOWN
    seen = hgraph(good_host("a", sshd=gone, listeners=fact(listeners(ports=(22,)))))
    assert verdicts(seen)[SSH].verdict is Verdict.UNKNOWN


def test_validity_of_a_sshd_absence_also_ends_with_the_listener_table():
    gone = fact({}, status="unavailable", reason="tool_missing", seen="2026-12-01T08:55:00Z")
    lst = fact(listeners(ports=(443,)), seen="2026-12-01T05:00:00Z")      # older: expires first
    r = verdicts(hgraph(good_host("a", sshd=gone, listeners=lst)))[SSH]
    assert r.verdict is Verdict.HOLDS
    assert r.valid_until == dt.datetime(2026, 12, 1, 11, 0, tzinfo=dt.timezone.utc)   # 05:00 + 6h


def test_default_deny_needs_every_family_and_an_exact_model():
    for fw, verdict in [(dict(ip4="drop", ip6="drop"), Verdict.HOLDS),
                        (dict(ip4="reject", ip6="reject"), Verdict.HOLDS),
                        (dict(ip4="drop", ip6="accept"), Verdict.VIOLATED),
                        (dict(ip4="accept", ip6="drop"), Verdict.VIOLATED),
                        (dict(ip4="drop", ip6="accept", ipv6=False), Verdict.HOLDS),
                        (dict(ip4="drop", ip6="drop", confidence="approximate"), Verdict.UNKNOWN),
                        (dict(ip4="drop", ip6="unknown"), Verdict.UNKNOWN)]:
        g = hgraph(good_host("a", firewall=fact(firewall(**fw))))
        assert verdicts(g)[FW].verdict is verdict, fw


def test_declared_server_without_an_agent_is_unknown_not_out_of_scope():
    g = hgraph(good_host("a"), hnode("ghost", None, tags=("server",)))
    for sid, r in verdicts(g).items():
        assert r.verdict is Verdict.UNKNOWN and r.reasons == ["hosts_unknown:1"], sid
        assert [(b.node, b.reason, b.collector) for b in r.blind_spots] == [("ghost", "no_agent", None)]


def test_a_silent_agent_goes_unknown_after_six_hours_and_a_violation_still_wins():
    g = hgraph(good_host("a"))
    later = NOW + dt.timedelta(hours=6, minutes=1)
    assert verdicts(g, NOW + dt.timedelta(hours=5))[SSH].verdict is Verdict.HOLDS
    assert verdicts(g, later)[SSH].verdict is Verdict.UNKNOWN
    mixed = hgraph(good_host("a"), good_host("b", sshd=fact(sshd(passwordauthentication="yes"))))
    assert verdicts(mixed, later)[SSH].verdict is Verdict.UNKNOWN          # the violation is stale too
    assert verdicts(mixed)[SSH].verdict is Verdict.VIOLATED


def test_unsigned_facts_are_never_a_pass():
    g = hgraph(good_host("a", sshd=fact(sshd(), signed=False), firewall=fact(firewall(), signed=False)))
    for r in verdicts(g).values():
        assert r.verdict is Verdict.UNKNOWN and r.blind_spots[0].reason == "unsigned"


# --------------------------------------------------------------------------------------------
# examples and the CLI

def test_example_estates_exit_codes(capsys):
    code, out, _ = run(capsys, "test", SSH, FW, "--graph", str(EX / "estate-hosts-clean.json"))
    assert code == 0 and out.count("HOLDS") == 2
    code, out, _ = run(capsys, "test", SSH, FW, "--graph", str(EX / "estate-hosts-violated.json"))
    assert code == 1
    assert "web-2: host.sshd.password_login_possible == false failed, observed true" in out
    assert "app-2: host.fw.default_inbound_all_families" in out and "batch-1 (no_agent)" in out
    code, out, _ = run(capsys, "test", SSH, "--graph", str(EX / "estate-hosts-clean.json"),
                       "--now", "2026-12-02T09:00:00Z")
    assert code == 2 and "UNKNOWN" in out and "hosts_unknown:3" in out


def test_json_output_carries_host_witness_details(capsys):
    code, out, _ = run(capsys, "test", SSH, "--graph", str(EX / "estate-hosts-violated.json"), "--json")
    assert code == 1
    (r,) = json.loads(out)["results"]
    assert r["assertion"] == "host-config" and r["verdict"] == "VIOLATED"
    assert r["hosts"] == {"selected": 6, "holds": 4, "violated": 1, "unknown": 1}
    assert r["violating_targets"] == ["web-2"] and r["unproven_targets"] == ["batch-1"]
    w = r["witnesses"][0]
    assert w["hops"] == [] and w["detail"]["node"] == "web-2" and w["detail"]["signed"] == "true"
    assert r["blind_spots"] == [{"node": "batch-1", "reason": "no_agent", "relevant": True,
                                 "direction": "host"}]


def test_lint_and_std_and_fields_and_explain(capsys):
    code, out, _ = run(capsys, "lint", SSH, FW)
    assert code == 0 and "host-config: any(" in out and "reads facts from: sshd" in out
    code, out, _ = run(capsys, "std")
    assert SSH in out and FW in out
    code, out, _ = run(capsys, "fields")
    assert code == 0 and "host.sshd.password_login_possible" in out and "host.listener(<port>).exists" in out
    code, out, _ = run(capsys, "explain", FW, "--graph", str(EX / "estate-hosts-violated.json"))
    assert code == 0 and "assert   host.fw.default_inbound_all_families" in out and "needs    signed facts" in out


def test_lint_rejects_a_bad_predicate_with_exit_3(capsys, tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("""
apiVersion: paddock.dev/invariant/v1
id: acme:bad
title: bad predicate
subjects: { to: { tag: [server] } }
assert: host.sshd.nope == 1
""")
    code, _, err = run(capsys, "lint", str(p))
    assert code == 3 and "unknown field" in err
    p.write_text(p.read_text().replace("host.sshd.nope == 1", "host.sshd.installed == false")
                 + "evidence: { min_tier: observed }\n")
    code, _, err = run(capsys, "lint", str(p))
    assert code == 3 and "never lifted" in err


def test_a_custom_host_invariant_with_a_lower_floor(capsys, tmp_path):
    p = tmp_path / "ok.yaml"
    p.write_text("""
apiVersion: paddock.dev/invariant/v1
id: acme:ssh-keys-only
title: Servers log in with keys only
subjects: { to: { tag: [server] } }
assert: host.sshd.password_login_possible == false
evidence: { min_tier: configured, max_age: 6h }
coverage: { require: 0.5 }
""")
    doc = json.loads((EX / "estate-hosts-clean.json").read_text())
    doc["nodes"].append({"id": "quiet", "kind": "host", "tags": ["server"]})
    gp = tmp_path / "g.json"
    gp.write_text(json.dumps(doc))
    code, out, _ = run(capsys, "test", str(p), "--graph", str(gp))
    assert code == 0 and "HOLDS" in out and "quiet (no_agent)" in out     # the floor allows it; the gap is listed
    r = evaluate(stdlib.load_std(SSH), ReachGraph.from_dict(doc), NOW)
    assert r.verdict is Verdict.UNKNOWN                                    # the std floor is strict
