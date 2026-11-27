# SPDX-License-Identifier: Apache-2.0
"""The pipeline (steps 0 to 10) in memory, against bundles built by the independent case generator.

The generator (``tools/gen_cases.py``) shares no code with the verifier; here it only supplies statements, keys,
certificates and lists that a test then breaks in one chosen way.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

from paddock_verify import anchor as anchor_mod
from paddock_verify import checks, codes, dsse, fetch, keys as keys_mod, limits, model, policy as policy_mod, report, revocation, schema, timefmt
from paddock_verify.dns import resolver as dns_resolver
from paddock_verify.state import State, StateError

SPEC = Path(__file__).resolve().parents[2] / "docs" / "spec" / "containment-attestation-v1"


def _load(name):
    spec = importlib.util.spec_from_file_location(name, str(SPEC / "tools" / (name + ".py")))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


GC = _load("gen_cases")
ROOTS = keys_mod.parse_roots((SPEC / "vectors" / "test-roots.json").read_bytes(), custom=True)
REG = model.load_default_registry()


def resolvers_for(b):
    rs = []
    for i, fx in enumerate(b.dns):
        answers = {}
        for name, e in fx["answers"].items():
            answers[name] = dns_resolver.DnsAnswer(e["status"], ["".join(t) if isinstance(t, list) else t for t in e.get("txt", [])], fx.get("ad"), "fx%d" % i)
        rs.append(dns_resolver.FakeResolver(answers, name="fx%d" % i))
    return dns_resolver.ResolverSet(rs, 1) if rs else None


def pol(**kw):
    d = {"policy_version": 1}
    d.update(kw)
    return policy_mod.parse_policy_text(json.dumps(d), filename="t.json")


def bundle_of(b):
    return model.Bundle(fetch.MemorySource(b.build()), "attestation/latest.json", label="mem")


def run(b=None, policy=None, state=None, roots=ROOTS, **kw):
    b = b or GC.Bk()
    return checks.verify(bundle_of(b), policy, now=b.now, resolver=resolvers_for(b), state=state, roots=roots, registry=REG, **kw)


def codes_of(r):
    return [x.code for x in r.reasons]


def warns_of(r):
    return sorted(x.code for x in r.warnings)


# --------------------------------------------------------------------------------------- the basic result
def test_valid_baseline_bundle_is_accepted_with_a_complete_report():
    r = run()
    assert (r.exit, r.decision, r.primary, r.profile, r.policy_sha256) == (0, "accepted", None, "baseline", None)
    assert [c["status"] for c in r.checks] == ["pass"] * 10 + ["skip"] and [c["id"] for c in r.checks][:3] == ["input", "schema", "signature"]
    assert r.subject == "dns:example.com" and r.key == {"kid": GC.KEYS["tenant-a"].kid, "custody": "hosted", "vendor_certified": True,
                                                         "dns_bound": True, "dnssec": "unknown"}
    assert r.statement["seq"] == 1 and r.statement["min_tier"] == "configured" and r.statement["policy"]["disabled"] == 0
    assert [x["status"] for x in r.results] == ["HOLDS", "HOLDS"] and r.results[0]["coverage"]["percent_floor"] == 97
    assert r.state_update["subject"]["seq"] == 1 and r.state_update["revocation"]["seq"] == 42


def test_verify_writes_nothing_and_a_second_run_gives_the_same_bytes():
    st = State()
    before = json.dumps(st.data, sort_keys=True)
    a, b = run(state=st), run(state=st)
    assert json.dumps(st.data, sort_keys=True) == before
    assert a.to_json() == b.to_json()


def test_report_dict_has_every_documented_field_and_is_ascii():
    d = run().to_dict()
    assert set(d) >= {"report_version", "verifier", "spec", "now", "target", "profile", "policy_sha256", "decision", "exit", "primary", "reasons",
                      "warnings", "checks", "subject", "key", "statement", "results", "human"}
    assert d["report_version"] == 1 and d["spec"] == "1.0" and d["verifier"]["name"] == "paddock-verify"
    run().to_json().encode("ascii")


def test_reports_validate_against_the_report_schema():
    jsonschema = pytest.importorskip("jsonschema")
    schema_doc = json.loads((SPEC / "schema" / "verifier-report.schema.json").read_text(encoding="ascii"))
    pred = json.loads((SPEC / "schema" / "predicate.schema.json").read_text(encoding="ascii"))
    from referencing import Registry, Resource
    reg = Registry().with_resources([(pred["$id"], Resource.from_contents(pred))])
    v = jsonschema.Draft202012Validator(schema_doc, registry=reg)
    samples = [run(), run(GC.Bk(), pol(require=[GC.req("std:public-ports-allowlist")]))]
    b = GC.Bk()
    b.now = "2026-12-02T10:00:00Z"
    samples.append(run(b))
    b = GC.Bk()
    b.dns = []
    samples.append(run(b))
    for r in samples:
        v.validate(json.loads(r.to_json()))
    assert {r.decision for r in samples} == {"accepted", "rejected", "unverifiable"}


def test_the_embedding_entry_points_are_reachable_from_the_package():
    import paddock_verify
    assert paddock_verify.verify is checks.verify and paddock_verify.verify_envelope is checks.verify_envelope
    with pytest.raises(AttributeError):
        paddock_verify.nothing_here


# --------------------------------------------------------------------------------- precedence, order, abort
def test_a_reject_beats_an_unverifiable_and_primary_is_the_first_decisive_reason():
    b = GC.Bk()
    b.dns = [GC.dns_fixture(status="servfail")]
    b.now = "2026-12-02T10:00:00Z"
    r = run(b)
    assert codes_of(r) == ["dns.lookup_failed", "time.expired"]
    assert (r.exit, r.decision, r.primary) == (1, "rejected", "time.expired")
    assert r.to_text().splitlines()[1] == "REJECTED: The attestation has expired."
    b = GC.Bk()
    b.dns = [GC.dns_fixture(status="servfail")]
    r = run(b)
    assert (r.exit, r.primary) == (2, "dns.lookup_failed") and r.to_text().splitlines()[1] == "UNVERIFIABLE: DNS lookup failed."


def test_reasons_come_in_step_order_even_when_found_in_another_order():
    b = GC.Bk()
    b.revoked_present = False
    b.dns = [GC.dns_fixture(status="servfail")]
    r = run(b)
    assert codes_of(r) == ["dns.lookup_failed", "revocation.missing"]
    assert [x.step for x in r.reasons] == [3, 4]


def test_a_code_is_reported_once_even_when_it_applies_to_several_results():
    b = GC.Bk()
    b.result(0)["tier"] = "tested"
    b.result(1)["tier"] = "declared"
    assert codes_of(run(b)) == ["result.tier_invalid"]


def test_a_reject_in_steps_two_to_four_leaves_five_to_ten_not_evaluated():
    b = GC.Bk()
    b.signer = "attacker"
    b.keyid = GC.KEYS["tenant-a"].kid
    r = run(b)
    assert codes_of(r) == ["sig.invalid"]
    assert [c["status"] for c in r.checks][5:] == ["not_evaluated"] * 6
    assert r.results == [] and r.state_update is None
    assert "No counterexample" not in r.to_text()


def test_results_of_a_statement_whose_authenticity_is_not_established_are_not_shown():
    for mutate in (lambda b: setattr(b, "dns", [GC.dns_fixture(status="servfail")]), lambda b: setattr(b, "revoked_present", False),
                   lambda b: setattr(b, "dns", [])):
        b = GC.Bk()
        mutate(b)
        r = run(b)
        assert r.exit == 2 and r.results == [] and r.state_update is None
        assert "No counterexample" not in r.to_text() and "correctly signed" not in r.to_text()
        assert [c["status"] for c in r.checks][5:] == ["pass"] * 5 + ["skip"]        # the later steps still ran and still count


def test_policy_is_never_judged_on_unauthentic_data():
    b = GC.Bk()
    b.signer = "attacker"
    b.keyid = GC.KEYS["tenant-a"].kid
    r = run(b, pol(require=[GC.req("std:public-ports-allowlist")], disclosure="complete"))
    assert codes_of(r) == ["sig.invalid"]


def test_an_unsupported_predicate_type_runs_steps_two_and_three_only():
    b = GC.Bk()
    b.stmt["predicateType"] = "https://paddock.dev/attestation/containment/v9"
    b.pred["anything"] = {"goes": [1, 2, 3]}
    r = run(b)
    assert codes_of(r) == ["predicate.unsupported_version"] and r.exit == 2
    assert [c["status"] for c in r.checks][1:] == ["unverifiable", "pass", "pass"] + ["not_evaluated"] * 7
    assert r.statement is None and r.results == []


def test_no_headline_of_acceptance_without_every_evaluated_step_passing():
    for mutate in (lambda b: setattr(b, "revoked_present", False), lambda b: setattr(b, "dns", []), lambda b: setattr(b, "now", "2027-01-01T00:00:00Z")):
        b = GC.Bk()
        mutate(b)
        r = run(b)
        assert r.exit != 0 and not r.to_text().splitlines()[1].startswith(("VALID", "ACCEPTED"))


def test_internal_errors_are_unverifiable_never_accepted(monkeypatch):
    def boom(doc):
        raise RuntimeError("bug")
    monkeypatch.setattr(schema, "validate_statement", boom)
    r = run()
    assert codes_of(r) == ["internal.error"] and r.exit == 2 and r.decision == "unverifiable"
    monkeypatch.undo()
    r = checks.verify(bundle_of(GC.Bk()), None, now=object())
    assert codes_of(r) == ["internal.error"] and r.exit == 2


def test_a_wording_failure_is_an_internal_error_never_a_printed_value_or_a_pass(monkeypatch):
    def boom(*a, **k):
        raise report.wording.WordingError("slot")
    monkeypatch.setattr(report.wording, "render", boom)
    r = run()
    assert codes_of(r) == ["internal.error"] and r.exit == 2 and r.state_update is None
    monkeypatch.undo()
    r = checks.verify(bundle_of(GC.Bk()), None, now=0, roots=ROOTS, registry=REG)       # a clock before the supported years
    assert r.now == "" and r.exit != 0


def test_failed_acquisition_codes_and_classes():
    for code, exit_ in (("input.not_found", 2), ("input.unreadable", 2), ("input.fetch_failed", 2), ("input.insecure_transport", 2), ("input.too_large", 1)):
        r = checks.verify(model.Bundle.failed(code, label="x"), None, now="2026-12-01T12:00:00Z", roots=ROOTS, registry=REG)
        assert codes_of(r) == [code] and r.exit == exit_ and r.primary == code
        assert all(c["status"] in ("fail", "unverifiable", "not_evaluated") for c in r.checks)


# ------------------------------------------------------------------------------------------ verify_envelope
def test_verify_envelope_selfcheck_skips_dns_and_consumer_policy():
    b = GC.Bk()
    files = b.build()
    r = checks.verify_envelope(files["attestation/latest.json"], files["keys.json"], ROOTS, b.now, revoked=files["revoked.json"], registry=REG)
    assert (r.exit, codes_of(r), r.checks[9]["status"]) == (0, [], "skip")
    assert r.key["dns_bound"] is None
    # a coverage the consumer baseline would reject is not the self-check's business
    b = GC.Bk()
    b.result(0)["coverage"].update({"universe": 40, "covered": 36, "required_bp": 9000})
    files = b.build()
    assert checks.verify_envelope(files["attestation/latest.json"], files["keys.json"], ROOTS, b.now, revoked=files["revoked.json"], registry=REG).exit == 0
    assert run(b).exit == 1


def test_verify_envelope_never_raises_for_arguments_of_the_wrong_type():
    b = GC.Bk()
    files = b.build()
    env, keys = files["attestation/latest.json"], files["keys.json"]
    kw = dict(revoked=files["revoked.json"], registry=REG)
    for args in ((None, keys, ROOTS, b.now), (env, "a string", ROOTS, b.now), (env, 12, ROOTS, b.now), (env, keys, b"garbage", b.now),
                 (env, keys, 3.5, b.now), (env, keys, ROOTS, object()), (env, None, ROOTS, b.now)):
        r = checks.verify_envelope(*args, **kw)
        assert r.exit == 2 and codes_of(r) == ["internal.error"], args                       # unverifiable, never an exception, never 0
    assert checks.verify_envelope(env, keys, ROOTS, b.now, revoked="a string", registry=REG).exit == 2


def test_verify_envelope_accepts_roots_as_bytes_or_dicts_and_refuses_damage():
    b = GC.Bk()
    files = b.build()
    kw = dict(revoked=files["revoked.json"], registry=REG)
    env, keys = files["attestation/latest.json"], files["keys.json"]
    assert checks.verify_envelope(env, keys, GC.compact(GC.roots_doc()), b.now, **kw).exit == 0
    assert checks.verify_envelope(env, json.loads(keys), GC.roots_doc(), b.now, **kw).exit == 0
    assert checks.verify_envelope(env, keys, keys_mod.TrustRoots(), b.now, **kw).exit == 2          # no roots: unverifiable
    bad = bytearray(env)
    bad[len(bad) // 2] ^= 1
    assert checks.verify_envelope(bytes(bad), keys, ROOTS, b.now, **kw).exit != 0
    assert checks.verify_envelope(env, keys, ROOTS, b.now, revoked=None, registry=REG).exit == 2   # the live list is part of the check


# -------------------------------------------------------------------------------------------------- time
@pytest.mark.parametrize("now,ok", [("2026-12-01T08:55:00Z", True), ("2026-12-01T08:54:59Z", False), ("2026-12-02T08:59:59Z", True),
                                    ("2026-12-02T09:00:00Z", False), ("2026-12-02T09:00:01Z", False)])
def test_window_boundaries_are_end_exclusive_and_skew_is_300_seconds(now, ok):
    b = GC.Bk()
    b.now = now
    assert (run(b).exit == 0) is ok


def test_max_age_applies_to_issued_at_and_to_snapshot_at():
    b = GC.Bk()
    b.now = "2026-12-01T12:00:00Z"
    assert codes_of(run(b, pol(max_age="2h"))) == ["time.too_old"]
    assert run(b, pol(max_age="3h10m".replace("10m", ""))).exit == 1             # issued_at is 3h old: 3h is not enough once snapshot.at is older
    b.pred["snapshot"]["at"] = "2026-12-01T08:46:00Z"          # still within 900 s of issue, but 3h14m old
    assert run(b, pol(max_age="3h")).exit == 1                                    # only snapshot.at is over the limit
    assert run(b, pol(max_age="4h")).exit == 0


# -------------------------------------------------------------------------------------------------- keys
def test_chain_to_a_pinned_issuer_has_length_one_and_a_pinned_root_cannot_sign_a_key_directly():
    iss = GC.KEYS["issuer-1"]
    pinned = keys_mod.parse_roots(GC.compact([{"kid": iss.kid, "public_key": GC.b64(iss.pub), "usage": "issue-cert", "not_before": GC.ROOT_NB,
                                              "not_after": GC.ROOT_NA}]), custom=True)
    assert run(roots=pinned).exit == 0
    # a root that certifies the estate key directly skips the issuer: not a valid chain
    b = GC.Bk()
    cert = GC.cert_env(GC.KEYS["tenant-a"].pub, "attest", GC.KEYS["root-1"], GC.ESTATE_NB, GC.ESTATE_NA, GC.ESTATE, 17)
    b.keys_doc["keys"][0] = GC.keys_entry(GC.KEYS["tenant-a"].pub, "attest", cert)
    assert "key.root_unknown" in codes_of(run(b))


def test_root_window_is_checked_at_the_issue_time():
    r1 = GC.KEYS["root-1"]
    late = keys_mod.parse_roots(GC.compact([{"kid": r1.kid, "public_key": GC.b64(r1.pub), "usage": "root", "not_before": "2026-12-01T10:00:00Z",
                                            "not_after": GC.ROOT_NA}]), custom=True)
    assert "key.root_unknown" in codes_of(run(roots=late))


def test_damage_in_a_part_of_keys_json_the_decision_does_not_read_is_still_caught():
    b = GC.Bk()
    a = b.keys_doc["keys"][1]                         # the anchor entry: not used by a statement
    a["custody"] = "byok-kms"
    assert codes_of(run(b)) == ["key.cert_subject_mismatch"]
    b = GC.Bk()
    cert = copy.deepcopy(b.keys_doc["keys"][1]["cert"])
    cert["signatures"][0]["sig"] = GC.b64(bytes(64))
    b.keys_doc["keys"][1]["cert"] = cert
    assert codes_of(run(b)) == ["key.cert_invalid"]
    b = GC.Bk()
    b.keys_doc["revoker"]["signatures"][0]["sig"] = GC.b64(bytes(64))
    assert "key.cert_invalid" in codes_of(run(b))


@pytest.mark.parametrize("mutate", [
    lambda d: d.__setitem__("spec", "paddock-keys/v2"), lambda d: d.__setitem__("estate", "E"), lambda d: d.__setitem__("extra", 1),
    lambda d: d.pop("revoker"), lambda d: d.__setitem__("issuers", []), lambda d: d.__setitem__("issuers", [d["issuers"][0]] * 5),
    lambda d: d.__setitem__("keys", d["keys"] + [dict(d["keys"][0])]), lambda d: d["keys"][0].__setitem__("public_key", "AAAA"),
    lambda d: d["keys"][0].__setitem__("usage", "revoke"), lambda d: d["keys"][0].__setitem__("custody", "cloud"),
    lambda d: d["keys"][0].__setitem__("not_before", "2026-12-01"), lambda d: d["keys"][0].__setitem__("cert", "x"),
    lambda d: d["keys"][0].__setitem__("surprise", 1), lambda d: d.__setitem__("keys", d["keys"] * 9),
])
def test_keys_json_structure_is_strict(mutate):
    b = GC.Bk()
    mutate(b.keys_doc)
    assert codes_of(run(b)) == ["keys.invalid"]


def test_keys_json_parse_errors_are_input_codes():
    for raw, code in ((b"{", "input.not_json"), (b"\xef\xbb\xbf{}", "input.not_ascii"), (b'{"a":1,"a":2}', "input.duplicate_key"),
                      (b" " * (limits.MAX_AUX_FILE_BYTES + 1), "input.too_large"), (b'{"a":1.5}', "input.number_invalid")):
        b = GC.Bk()
        b.keys_bytes = raw
        assert codes_of(run(b)) == [code], raw[:10]


def test_parse_roots_rejects_bad_files():
    good = GC.roots_doc()[0]
    for doc in ([dict(good, kid="0" * 32)], [dict(good, usage="admin")], [dict(good, extra=1)], [dict(good, public_key="AAAA")],
                [dict(good, not_before="x")], {"a": 1}, [1], [{"kid": "x", "usage": "issuer-revoked"}], [dict(kid=good["kid"], usage="issuer-revoked", x=1)]):
        with pytest.raises(keys_mod.ConfigError):
            keys_mod.parse_roots(GC.compact(doc) if isinstance(doc, (list, dict)) else doc)
    with pytest.raises(keys_mod.ConfigError):
        keys_mod.parse_roots(b"not json")
    assert not keys_mod.load_default_roots() and not keys_mod.load_default_roots().custom


def test_the_shipped_roots_contain_no_conformance_key():
    shipped = json.loads(limits.read_data("trust_roots.json").decode("ascii"))
    test_pubs = set(GC.b64(k.pub) for k in GC.KEYS.values())
    assert all(r["public_key"] not in test_pubs for r in shipped)


def test_certificate_kinds_must_match_their_use():
    keys_doc = keys_mod.parse_keys(GC.compact(GC.default_keys_doc()))
    chain = keys_mod.check_chain(keys_doc.revoker, keys_doc, ROOTS, 1796115600, None, "revoke", None)
    assert chain.codes == [] and chain.chain_ok
    assert keys_mod.check_chain(keys_doc.revoker, keys_doc, ROOTS, 1796115600, None, "attest", GC.ESTATE).codes == ["key.cert_subject_mismatch"]
    assert keys_mod.check_chain(keys_doc.issuers[0], keys_doc, ROOTS, 1796115600, None, "issue-cert", None).codes == []
    assert keys_mod.check_chain(keys_doc.issuers[0], keys_doc, keys_mod.TrustRoots(), 1796115600, None, "issue-cert", None).codes == ["key.root_unknown"]


# ------------------------------------------------------------------------------------------- revocation
def revoke(b, **over):
    b.revoked_payload.update(over)


def test_a_revocation_list_is_bound_to_its_estate_signer_and_freshness():
    b = GC.Bk()
    revoke(b, issued_at="2026-12-03T12:00:00Z", next_update="2026-12-04T12:00:00Z")
    assert codes_of(run(b)) == ["revocation.unverifiable"]                        # issued after now + skew
    b = GC.Bk()
    revoke(b, next_update="2026-12-01T05:00:00Z")
    assert codes_of(run(b)) == ["revocation.unverifiable"]                        # next_update before issued_at
    b = GC.Bk()
    b.now = "2026-12-04T06:00:00Z"                                                 # exactly next_update + 48h: not yet stale
    b.pred["valid_until"] = "2026-12-05T09:00:00Z"
    assert "revocation.stale" not in codes_of(run(b, pol(max_age="7d")))
    b.now = "2026-12-04T06:00:01Z"
    assert "revocation.stale" in codes_of(run(b, pol(max_age="7d")))


def test_the_policys_revocation_age_can_only_tighten_the_staleness_rule():
    b = GC.Bk()
    b.now = "2026-12-01T20:00:00Z"
    assert run(b).exit == 0
    assert codes_of(run(b, pol(trust={"revocation_max_age": "10h"}))) == ["revocation.stale"]
    assert run(b, pol(trust={"revocation_max_age": "72h"})).exit == 0


def test_an_issuer_may_sign_the_list_and_a_pinned_issuer_may_too():
    b = GC.Bk()
    b.revoked_signer = "issuer-1"
    assert run(b).exit == 0
    b = GC.Bk()
    b.revoked_signer = "attacker"
    assert codes_of(run(b)) == ["revocation.unverifiable"]
    b = GC.Bk()
    b.revoked_signer = "tenant-a"                                  # an estate key may not revoke
    assert codes_of(run(b)) == ["revocation.unverifiable"]


def test_a_stale_but_authentic_list_still_rejects_what_it_revokes():
    b = GC.Bk()
    revoke(b, issued_at="2026-11-20T06:00:00Z", next_update="2026-11-21T06:00:00Z",
           revoked=[{"kid": GC.KEYS["tenant-a"].kid, "reason": "key_compromise", "revoked_at": "2026-11-20T06:00:00Z"}])
    assert codes_of(run(b)) == ["revocation.stale", "key.revoked"] and run(b).exit == 1


def test_a_list_naming_the_signing_kid_twice_applies_every_entry_and_the_worst_wins():
    kid = GC.KEYS["tenant-a"].kid
    retired = {"kid": kid, "reason": "superseded", "revoked_at": "2026-12-01T11:00:00Z"}      # after issued_at: a warning alone
    compromised = {"kid": kid, "reason": "key_compromise", "revoked_at": "2026-12-01T11:30:00Z"}
    for entries in ([retired, compromised], [compromised, retired]):
        b = GC.Bk()
        revoke(b, revoked=entries)
        r = run(b)
        assert (r.exit, codes_of(r), warns_of(r)) == (1, ["key.revoked"], []), entries      # one finding, never order dependent
    b = GC.Bk()
    revoke(b, revoked=[retired, dict(retired, revoked_at="2026-12-01T12:00:00Z")])
    r = run(b)
    assert (r.exit, codes_of(r), warns_of(r)) == (0, [], ["key.revoked_superseded"])        # two warnings are still one warning
    b = GC.Bk()
    revoke(b, revoked=[retired, dict(retired, revoked_at="2026-12-01T08:00:00Z")])           # one of them predates issued_at
    assert codes_of(run(b)) == ["key.revoked"]


def test_revocation_best_effort_is_a_warning_and_says_so():
    b = GC.Bk()
    b.revoked_present = False
    r = run(b, pol(trust={"revocation": "best_effort"}))
    assert r.exit == 0 and warns_of(r) == ["revocation.missing"] and "revocation NOT checked" in r.to_text()


def test_the_revocation_sequence_number_never_goes_backwards_against_the_state():
    st = State({"state_version": 1, "subjects": {}, "revocation": {GC.ESTATE: {"seq": 43}}})
    assert codes_of(run(state=st)) == ["revocation.unverifiable"]
    assert run(state=State({"state_version": 1, "subjects": {}, "revocation": {GC.ESTATE: {"seq": 42}}})).exit == 0


def test_issuer_revocation_by_the_list_itself():
    b = GC.Bk()
    revoke(b, revoked=[{"kid": GC.KEYS["issuer-1"].kid, "reason": "key_compromise", "revoked_at": "2026-12-01T05:00:00Z"}])
    assert "issuer.revoked" in codes_of(run(b))


def test_supersession_only_rejects_older_sequence_numbers():
    b = GC.Bk()
    revoke(b, superseded=[{"subject": "dns:example.com", "min_seq": 1, "at": "2026-12-01T05:00:00Z"}])
    assert run(b).exit == 0
    revoke(b, superseded=[{"subject": "dns:other.example", "min_seq": 9, "at": "2026-12-01T05:00:00Z"}])
    assert run(b).exit == 0


# ----------------------------------------------------------------------------------------------- the chain
def three_statements():
    b = GC.Bk()
    s1 = copy.deepcopy(b.stmt)
    s2 = copy.deepcopy(b.stmt)
    s2["predicate"]["seq"] = 2
    s2["predicate"]["prev"] = "sha256:" + GC.sha(GC.render(s1)[0])
    b.pred["seq"] = 3
    b.pred["prev"] = "sha256:" + GC.sha(GC.render(s2)[0])
    b.history = {1: s1, 2: s2}
    b.write_current_numbered = True
    return b, s1, s2


def test_history_depth_walks_back_through_older_links():
    b, s1, s2 = three_statements()
    assert run(b, history_depth=3).exit == 0
    s2["predicate"]["prev"] = "sha256:" + "ab" * 32                        # statement 2 does not link to statement 1
    b.pred["prev"] = "sha256:" + GC.sha(GC.render(s2)[0])
    assert run(b, history_depth=1).exit == 0                               # depth 1 only checks the immediate link
    assert codes_of(run(b, history_depth=2)) == ["chain.prev_mismatch"]


def test_history_off_skips_the_history_but_not_the_state():
    b = GC.Bk()
    b.pred["seq"] = 2
    b.pred["prev"] = "sha256:" + "ab" * 32
    assert run(b, pol(history="off")).exit == 0
    assert codes_of(run(b, pol(history="off"), state=State(_state_doc(7)))) == ["chain.seq_rollback"]


def _state_doc(seq, digest=None):
    return {"state_version": 1, "subjects": {"dns:example.com": {"seq": seq, "digest": digest or "sha256:" + "11" * 32}}}


def test_state_high_water_mark_and_update_rules():
    st = State(_state_doc(1, "sha256:" + hashlib.sha256(GC.render(GC.base_statement())[0]).hexdigest()))
    r = run(state=st)
    assert r.exit == 0                                                      # the very same statement again
    upd = r.state_update
    st.apply(upd)
    assert st.subject("dns:example.com")["seq"] == 1
    st.apply({"subject": {"name": "dns:example.com", "seq": 0 + 1, "digest": "sha256:" + "22" * 32}})
    assert st.subject("dns:example.com")["digest"] != "sha256:" + "22" * 32  # a different digest at the same seq never replaces
    st.apply({"subject": {"name": "dns:example.com", "seq": 5, "digest": "sha256:" + "33" * 32}})
    assert st.subject("dns:example.com")["seq"] == 5
    st.apply({"subject": {"name": "dns:example.com", "seq": 2, "digest": "sha256:" + "44" * 32}})
    assert st.subject("dns:example.com")["seq"] == 5                         # never lowered


def test_no_state_update_unless_steps_zero_to_four_passed():
    b = GC.Bk()
    b.dns = []
    assert run(b).state_update is None                                       # the DNS binding was not checked
    b = GC.Bk()
    b.revoked_present = False
    assert run(b).state_update is None
    assert run().state_update is not None
    b = GC.Bk()
    b.now = "2026-12-02T10:00:00Z"
    assert run(b).state_update is not None                                    # a later step failing does not stop recording the sequence number


def test_state_documents_are_validated_and_files_written_atomically(tmp_path):
    for bad in ({}, {"state_version": 2}, {"state_version": 1, "subjects": {"x": {}}}, {"state_version": 1, "extra": 1},
                {"state_version": 1, "subjects": {"dns:a.example": {"seq": 0, "digest": "sha256:" + "0" * 64}}},
                {"state_version": 1, "subjects": {"dns:a.example": {"seq": 1, "digest": "nope"}}},
                {"state_version": 1, "revocation": {"e_x": {"seq": 1}}}):
        with pytest.raises(StateError):
            State(bad)
    p = tmp_path / "s.json"
    assert State.load(str(p)).data["subjects"] == {}                         # a missing file is the first run
    s = State.load(str(p))
    s.apply({"subject": {"name": "dns:a.example", "seq": 3, "digest": "sha256:" + "0" * 64}})
    s.save()
    assert State.load(str(p)).subject("dns:a.example")["seq"] == 3
    assert [x.name for x in tmp_path.iterdir()] == ["s.json"]            # no temporary file is left behind
    p.write_text("{not json")
    with pytest.raises(StateError):
        State.load(str(p))
    p.write_bytes(b"x" * (limits.MAX_AUX_FILE_BYTES + 1))
    with pytest.raises(StateError):
        State.load(str(p))


# ---------------------------------------------------------------------------------------- DNS and subject
def test_an_operator_supplied_record_is_reported_as_asserted_not_verified():
    b = GC.Bk()
    b.dns = []
    kw = dict(dns_record=GC.WORKED["dns_txt"])
    assert codes_of(checks.verify(bundle_of(b), None, now=b.now, roots=ROOTS, registry=REG, **kw)) == ["dns.skipped_offline"]
    r = checks.verify(bundle_of(b), pol(trust={"dns_binding": "optional"}), now=b.now, roots=ROOTS, registry=REG, **kw)
    assert r.exit == 0 and warns_of(r) == ["dns.skipped_offline"] and r.key["dns_bound"] is None
    other = GC.txt_for(GC.KEYS["tenant-a"], fp="sha256:" + GC.KEYS["tenant-a"].kid + "0" * 32)
    assert codes_of(checks.verify(bundle_of(b), None, now=b.now, roots=ROOTS, registry=REG, dns_record=other)) == ["dns.mismatch"]


def test_the_expected_domain_comes_from_the_caller_or_bundle_json():
    b = GC.Bk()
    r = checks.verify(bundle_of(b), None, now=b.now, resolver=resolvers_for(b), roots=ROOTS, registry=REG, expected_domain="example.org")
    assert codes_of(r) == ["dns.domain_mismatch"] and r.key["dns_bound"] is False
    b = GC.Bk()
    b.bundle_domain = None
    assert run(b).exit == 0                                                    # no bundle.json: nothing to compare with
    b.pred["snapshot"]["at"] = b.pred["snapshot"]["at"]
    b = GC.Bk()
    name = "paddock-estate:" + GC.ESTATE
    b.stmt["subject"] = [{"name": name, "digest": {"sha256": GC.sha(name.encode("ascii"))}}]
    r = checks.verify(bundle_of(b), None, now=b.now, roots=ROOTS, registry=REG, expected_domain="example.com")
    assert "dns.domain_mismatch" not in codes_of(r) and warns_of(r) == ["dns.not_applicable"]     # a domain target and an estate subject
    b.pred["estate"] = GC.OTHER_ESTATE
    assert "key.cert_subject_mismatch" in codes_of(run(b))                       # the subject's estate must be the statement's


# ------------------------------------------------------------------------------------ step 7, registry, advisories
def test_std_registry_warn_downgrades_registry_findings_to_warnings():
    b = GC.Bk()
    b.result(0)["digest"] = "sha256:" + "00" * 32
    assert codes_of(run(b)) == ["std.digest_mismatch"]
    r = run(b, pol(std_registry="warn"))
    assert r.exit == 0 and warns_of(r) == ["std.digest_mismatch"]
    b = GC.Bk()
    b.pred["engine"]["ruleset"] = "sha256:" + "11" * 32
    r = run(b, pol(std_registry="warn"))
    assert r.exit == 0 and warns_of(r) == ["engine.ruleset_unknown"]


def test_a_withdrawn_std_entry_is_rejected():
    reg = copy.deepcopy(GC.REGISTRY)
    reg["rulesets"][GC.RULESET]["std"]["std:no-internet-to-datastore"]["status"] = "withdrawn"
    custom = model.Registry.from_bytes(GC.compact(reg))
    b = GC.Bk()
    r = checks.verify(bundle_of(b), None, now=b.now, resolver=resolvers_for(b), roots=ROOTS, registry=custom)
    assert codes_of(r) == ["std.digest_mismatch"]


def test_registry_and_advisory_files_are_validated():
    for bad in (b"{", b'{"registry_version":2,"rulesets":{}}', b'{"registry_version":1,"rulesets":{"x":{}}}',
                b'{"registry_version":1,"rulesets":{},"advisories":[{"engine":"1"}]}', b'{"registry_version":1,"rulesets":{},"advisories":3}'):
        with pytest.raises(ValueError):
            model.Registry.from_bytes(bad)
    default = model.load_default_registry()
    assert default.advisories == [] and GC.RULESET in default.rulesets


def test_missing_std_ids_are_listed_from_the_registry_and_counted():
    r = run()
    assert r.statement["missing_std"] == ["std:coverage-complete", "std:guest-cannot-reach-pos", "std:public-ports-allowlist", "std:server-default-deny-inbound"]
    assert "Standard invariants enabled but not disclosed: 1." in r.to_text()


# ------------------------------------------------------------------------------------------- policy rules
def test_a_policy_changes_the_headline_and_prints_its_hash():
    r = run(None, pol(name="insurer", require=[GC.req("std:no-internet-to-datastore")]))
    assert r.exit == 0 and r.profile == "policy" and r.to_text().splitlines()[0] == "ACCEPTED under policy insurer"
    assert len(r.policy_sha256) == 64 and r.to_dict()["policy_sha256"] == r.policy_sha256
    assert "profile: baseline" not in r.to_text()


def test_required_invariants_must_hold_not_merely_be_present():
    for verdicts, code in ((("HOLDS", "UNKNOWN", "HOLDS"), "invariant.verdict_unknown"), (("HOLDS", "VIOLATED", "HOLDS"), "invariant.verdict_violated")):
        b = GC.Bk()
        GC.all_mode(b, verdicts)
        assert codes_of(run(b, pol(require=[GC.req("std:no-internet-to-datastore")]))) == [code]


def test_unknown_never_becomes_holds_anywhere_in_the_output():
    b = GC.Bk()
    GC.all_mode(b, ("UNKNOWN", "HOLDS", "HOLDS"))
    r = run(b)
    text = r.to_text()
    assert r.exit == 0 and "Undetermined for \"Guest networks cannot reach the point-of-sale segment\"" in text and "This is not a pass." in text
    assert [x["status"] for x in r.results] == ["UNKNOWN", "HOLDS", "HOLDS"]
    assert 'No counterexample found for "Guest networks' not in text


def test_an_expired_result_is_derived_not_issued_and_says_nothing_about_now():
    b = GC.Bk()
    b.now = "2026-12-01T15:00:00Z"
    r = run(b)
    assert r.exit == 0 and r.results[1]["status"] == "EXPIRED" and r.results[1]["verdict"] == "HOLDS"
    assert 'EXPIRED: the result for "Servers allow no SSH' in r.to_text() and "It says nothing about now." in r.to_text()


def test_require_latest_without_any_newer_statement_passes():
    b = GC.Bk()
    assert run(b, pol(require_latest=True)).exit == 0


def test_max_stop_at_share_and_exceptions_apply_to_required_invariants_only():
    b = GC.Bk()
    b.result(0)["selected"]["stop_at"] = 100
    b.result(0)["exceptions"] = 5
    assert run(b, pol(max_exceptions=0, max_stop_at_share="0.1")).exit == 0
    assert codes_of(run(b, pol(require=[GC.req("std:no-internet-to-datastore")], max_exceptions=0))) == ["invariant.exceptions_over_limit"]


# --------------------------------------------------------------------------------------- anchor and proofs
def test_anchor_checks_in_isolation():
    keys = keys_mod.parse_keys(GC.compact(GC.default_keys_doc()))
    claimed = {"max_id": 99120, "head": GC.ANCHOR_HEAD, "hash_alg": "hmac-sha256", "at": "2026-12-01T08:59:40Z", "kid": GC.KEYS["anchor-a"].kid,
               "digest": "sha256:" + GC.sha(GC.ANCHOR_BYTES)}
    issued = timefmt.parse("2026-12-01T09:00:00Z")
    assert anchor_mod.check_anchor(GC.ANCHOR_BYTES, claimed, GC.ESTATE, issued, keys, ROOTS, None, 7200) == []
    assert [f.code for f in anchor_mod.check_anchor(GC.ANCHOR_BYTES, claimed, GC.OTHER_ESTATE, issued, keys, ROOTS, None, 7200)] == ["anchor.invalid"]
    assert [f.code for f in anchor_mod.check_anchor(GC.ANCHOR_BYTES, dict(claimed, digest="sha256:" + "0" * 64), GC.ESTATE, issued, keys, ROOTS, None, 7200)] == ["anchor.mismatch"]
    assert [f.code for f in anchor_mod.check_anchor(GC.ANCHOR_BYTES, None, GC.ESTATE, issued, keys, ROOTS, None, 7200)] == ["anchor.mismatch"]
    assert [f.code for f in anchor_mod.check_anchor(GC.ANCHOR_BYTES, claimed, GC.ESTATE, issued + 3 * 3600, keys, ROOTS, None, 7200)] == ["anchor.too_old"]
    for junk, code in ((b"[]", "anchor.invalid"), (b"{", "anchor.invalid"), (b'{"v":1}', "anchor.not_ed25519"), (b'{"alg":"rsa","v":2}', "anchor.not_ed25519"),
                       (b'{"alg":"ed25519","v":2}', "anchor.invalid"), (b" " + GC.ANCHOR_BYTES, "anchor.invalid")):
        assert [f.code for f in anchor_mod.check_anchor(junk, claimed, GC.ESTATE, issued, keys, ROOTS, None, 7200)] == [code], junk
    rev = revocation.RevocationList(GC.ESTATE, 1, 0, 1, [(GC.KEYS["anchor-a"].kid, "key_compromise", 0)], [], "x")
    assert [f.code for f in anchor_mod.check_anchor(GC.ANCHOR_BYTES, claimed, GC.ESTATE, issued, keys, ROOTS, rev, 7200)] == ["anchor.invalid"]


def test_anchor_signature_is_over_a_context_no_statement_signature_can_share():
    doc = json.loads(GC.ANCHOR_BYTES.decode("ascii"))
    body = dict((k, v) for k, v in doc.items() if k != "sig")
    k = GC.KEYS["anchor-a"]
    wrong = k.sign(GC.pcj(body))                                            # without the context
    bad = dict(doc, sig=GC.b64(wrong))
    keys = keys_mod.parse_keys(GC.compact(GC.default_keys_doc()))
    claimed = {"max_id": 99120, "head": GC.ANCHOR_HEAD, "hash_alg": "hmac-sha256", "at": doc["at"], "kid": k.kid, "digest": "sha256:" + GC.sha(GC.pcj(bad))}
    got = anchor_mod.check_anchor(GC.pcj(bad), claimed, GC.ESTATE, timefmt.parse("2026-12-01T09:00:00Z"), keys, ROOTS, None, 7200)
    assert [f.code for f in got] == ["anchor.invalid"]


def test_proofs_are_checked_against_the_statements_own_roots_and_sizes():
    pred = GC.base_statement()["predicate"]
    ok = {"policy.json": GC.compact(GC.merkle_proof("policy", GC.POLICY_LEAVES, GC.POLICY_LEAVES[0])),
          "graph.json": GC.compact(GC.merkle_proof("graph", GC.GRAPH_LEAVES, GC.GRAPH_LEAVES[2])),
          "blind__std__no-internet-to-datastore.json": GC.compact(GC.merkle_proof("blind", GC.BLIND_LEAVES, GC.BLIND_LEAVES[0]))}
    assert anchor_mod.check_proofs(lambda seq: ok if seq == 1 else None, pred) == []
    assert anchor_mod.check_proofs(lambda seq: dict(ok, **{"notes.json": b"{}"}), pred) == []             # a file that is not a proof name is ignored
    assert [f.code for f in anchor_mod.check_proofs(lambda seq: None, pred)] == ["merkle.proof_missing"]
    only_unknown = {"other.json": b"{}"}
    assert [f.code for f in anchor_mod.check_proofs(lambda seq: only_unknown, pred)] == ["merkle.proof_missing"]
    wrong_inv = {"blind__std__nope.json": ok["blind__std__no-internet-to-datastore.json"]}
    assert [f.code for f in anchor_mod.check_proofs(lambda seq: wrong_inv, pred)] == ["merkle.proof_invalid"]
    big = {"policy.json": b" " * (limits.MAX_AUX_FILE_BYTES + 1)}
    assert [f.code for f in anchor_mod.check_proofs(lambda seq: big, pred)] == ["merkle.proof_invalid"]


# ------------------------------------------------------------------------------------------ limits, hostile
def test_oversize_inputs_are_rejected_not_exhausted():
    b = GC.Bk()
    b.payload = b" " * (limits.MAX_PAYLOAD_BYTES + 1)
    assert codes_of(run(b)) == ["schema.limit_exceeded"]
    b = GC.Bk()
    b.env_hook = lambda env, raw: env + b" " * (limits.MAX_ENVELOPE_BYTES)
    assert codes_of(run(b)) == ["input.too_large"]
    b = GC.Bk()
    b.revoked_bytes = b" " * (limits.MAX_AUX_FILE_BYTES + 1)
    assert codes_of(run(b)) == ["input.too_large"]


def test_the_run_budget_is_eight_mebibytes():
    b = GC.Bk()
    files = b.build()
    files["bundle.json"] = b"{}"
    bundle = model.Bundle(fetch.MemorySource(files), "attestation/latest.json", budget=len(files["attestation/latest.json"]) + 200)
    r = checks.verify(bundle, None, now=b.now, resolver=resolvers_for(b), roots=ROOTS, registry=REG)
    assert codes_of(r) == ["input.too_large"]


def test_256_results_verify_quickly():
    import time
    b = GC.Bk()
    GC.many_results(b, 256)
    t = time.time()
    r = run(b)
    assert r.exit == 0 and len(r.results) == 256 and time.time() - t < 5


def test_attacker_text_never_reaches_the_report_outside_validated_tokens():
    evil = "acme:x; DROP-<script>"
    assert not schema._INV.match(evil)
    b = GC.Bk()
    b.result(0)["invariant"] = "acme:placeholder-id-of-the-same-width"
    b.payload = GC.pcj(b.stmt).replace(b"acme:placeholder-id-of-the-same-width", evil.encode("ascii"))
    r = run(b)
    assert codes_of(r) == ["schema.digest_format"]
    text = r.to_text() + r.to_json()
    assert "script" not in text and "DROP" not in text
    for x in r.reasons:
        assert re.match(r"^[A-Za-z0-9_.\[\]]*$", x.params.get("path", "")), x.params


def test_a_registry_name_with_unprintable_content_falls_back_to_the_id():
    reg = copy.deepcopy(GC.REGISTRY)
    reg["rulesets"][GC.RULESET]["std"]["std:no-internet-to-datastore"]["name"] = 'bad "name" {x}'
    custom = model.Registry.from_bytes(GC.compact(reg))
    b = GC.Bk()
    r = checks.verify(bundle_of(b), None, now=b.now, resolver=resolvers_for(b), roots=ROOTS, registry=custom)
    assert r.exit == 0 and 'No counterexample found for "std:no-internet-to-datastore"' in r.to_text()


def test_hostile_custom_ids_appear_only_in_code_style_with_the_disclaimer():
    b = GC.Bk()
    GC.enable_custom(b, [GC.custom_result("acme:fully-secure")])
    r = run(b)
    lines = r.to_text().splitlines()
    i = [n for n, ln in enumerate(lines) if ln.startswith("Custom invariant `acme:fully-secure`")]
    assert i and "(defined by the operator; not reviewed by Paddock)" in lines[i[0]]
    assert report.wording.forbidden_hits("\n".join(lines), remove=[report.wording.render("W-FOOTER"), limits.limits_text("paddock-limits/1"), "acme:fully-secure"]) == []


# ---------------------------------------------------------------------------------------- schema cross-check
def _validators():
    jsonschema = pytest.importorskip("jsonschema")
    from referencing import Registry, Resource
    docs = dict((p.name, json.loads(p.read_text(encoding="ascii"))) for p in (SPEC / "schema").glob("*.schema.json"))
    reg = Registry().with_resources([(d["$id"], Resource.from_contents(d)) for d in docs.values()])
    return dict((n.split(".")[0], jsonschema.Draft202012Validator(d, registry=reg)) for n, d in docs.items())


def test_valid_documents_validate_against_the_json_schemas():
    v = _validators()
    b = GC.Bk()
    files = b.build()
    assert v["statement"].is_valid(b.stmt)
    assert v["keys"].is_valid(json.loads(files["keys.json"]))
    assert v["dsse-envelope"].is_valid(json.loads(files["attestation/latest.json"]))
    assert v["revoked"].is_valid(json.loads(GC.pcj(b.revoked_payload)))
    assert v["anchor"].is_valid(GC.ANCHOR_DOC)
    for env in (b.pki["issuer"], b.pki["revoker"], b.pki["attest"], b.pki["anchor"]):
        assert v["keycert"].is_valid(json.loads(base64_decode(env["payload"])))
    assert v["bundle-index"].is_valid(json.loads(files["bundle.json"]))
    b2 = GC.Bk()
    GC.all_mode(b2, ("UNKNOWN", "VIOLATED", "HOLDS"))
    assert v["statement"].is_valid(b2.stmt)


def base64_decode(s):
    import base64
    return base64.b64decode(s)


def _mutants(stmt):
    """Single-fault copies of a statement: delete a key, add a key, break a type, break a grammar."""
    def walk(node, path):
        if isinstance(node, dict):
            for k in list(node):
                yield path + [k]
                for p in walk(node[k], path + [k]):
                    yield p
        elif isinstance(node, list):
            for i, x in enumerate(node):
                for p in walk(x, path + [i]):
                    yield p

    def at(doc, path):
        for p in path[:-1]:
            doc = doc[p]
        return doc

    paths = list(walk(stmt, []))
    for path in paths:
        m = copy.deepcopy(stmt)
        parent = at(m, path)
        key = path[-1]
        original = parent[key]
        del parent[key]
        yield "delete " + ".".join(map(str, path)), m
        for label, bad in (("list", []), ("bool", True), ("neg", -1), ("str", "!x")):
            if isinstance(original, type(bad)) and not isinstance(original, bool):
                continue
            m = copy.deepcopy(stmt)
            at(m, path)[key] = bad
            yield "%s %s" % (label, ".".join(map(str, path))), m
        if isinstance(original, dict):
            m = copy.deepcopy(stmt)
            at(m, path)[key]["zz_unknown"] = 1
            yield "add " + ".".join(map(str, path)), m
    m = copy.deepcopy(stmt)
    m["zz_unknown"] = 1
    yield "add statement", m


def test_json_schemas_and_the_code_validators_agree_on_structure():
    v = _validators()["statement"]
    disagreements = []
    n = 0
    for label, m in _mutants(GC.base_statement()):
        n += 1
        issues, unsupported = schema.validate_statement(m)
        if v.is_valid(m) != (not issues and not unsupported):
            disagreements.append((label, [i.code for i in issues]))
    assert n > 300 and disagreements == []


def test_the_one_documented_divergence_between_schema_and_verifier():
    """The schema leaves the declared tier out of a HOLDS; the verifier reads the whole tier vocabulary at step 1 and
    rejects a declared (or tested) HOLDS at step 8 as result.tier_invalid, as spec/07 step 8 says."""
    v = _validators()["statement"]
    b = GC.Bk()
    b.result(0)["tier"] = "declared"
    assert not v.is_valid(b.stmt)
    assert schema.validate_statement(b.stmt) == ([], False)
    assert codes_of(run(b)) == ["result.tier_invalid"]
