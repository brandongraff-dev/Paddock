# SPDX-License-Identifier: Apache-2.0
"""Human wording: what the verifier prints, and what it can never print (spec/09, contract section 8.7).

HOLDS means "no counterexample under this evidence, coverage and freshness". The verifier never prints "secure",
"safe", a score or a bare pass, never shows UNKNOWN as holding, and never lets text chosen by an issuer reach the
terminal outside a validated token.
"""
from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

from paddock_verify import checks, codes, fetch, keys as keys_mod, limits, model, report, wording
from paddock_verify.dns import resolver as dns_resolver

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
FOOTER = wording.render("W-FOOTER")
LIMITS = limits.limits_text("paddock-limits/1")
STATIC = [FOOTER, LIMITS] + [ln for ln in LIMITS.splitlines() if ln]


def resolvers_for(b):
    answers = {}
    for name, e in (b.dns[0]["answers"].items() if b.dns else []):
        answers[name] = dns_resolver.DnsAnswer(e["status"], list(e.get("txt", [])), None, "fx")
    return dns_resolver.ResolverSet([dns_resolver.FakeResolver(answers, name="fx")], 1) if b.dns else None


def run(b, policy=None, **kw):
    bundle = model.Bundle(fetch.MemorySource(b.build()), "attestation/latest.json", label="mem")
    return checks.verify(bundle, policy, now=b.now, resolver=resolvers_for(b), roots=ROOTS, registry=REG, **kw)


def hits(text, ids=()):
    return wording.forbidden_hits(text, remove=STATIC + list(ids))


# --------------------------------------------------------------------------------------- pinned sentences
def test_the_worked_example_prints_the_pinned_lines():
    lines = run(GC.Bk()).to_text().splitlines()
    assert lines[0] == "profile: baseline (no acceptance policy given; nothing requires specific invariants)"
    assert lines[1] == "VALID under baseline profile"
    assert 'No counterexample found for "No internet path reaches a data store", based on configuration read from the systems ' \
           '(not tested from outside). 41 of 42 relevant assets had live evidence (97%). Evidence current until 2026-12-02T08:40:00Z.' in lines
    assert "This attestation is correctly signed by a key bound to dns:example.com, was issued 2026-12-01T09:00:00Z and is current until " \
           "2026-12-02T09:00:00Z. It lists results of specific checks. It is not an assessment of overall security." in lines
    assert "Signing key: held by the issuer (hosted); vouched for by the vendor root; named by the domain's DNS; DNSSEC: unknown." in lines
    assert lines[-1] == "A passing result means: no counterexample was found under this evidence, at this coverage, at this time. " \
                        "It is not a statement that the organisation is secure."


def test_the_percentage_is_floored_never_rounded_up():
    b = GC.Bk()
    b.result(0)["coverage"].update({"universe": 42, "covered": 41})
    assert "(97%)" in run(b).to_text() and "98%" not in run(b).to_text()
    b.result(0)["coverage"].update({"universe": 1000, "covered": 999, "required_bp": 9500})
    assert "(99%)" in run(b).to_text()


def test_the_counts_line_and_missing_std_line_say_what_is_not_shown():
    text = run(GC.Bk()).to_text()
    assert "2 of 3 enabled invariants are disclosed (0 declared invariants are disabled). 1 enabled invariants are not shown as holding: " \
           "they may be violated, undetermined, not yet evaluated, or not disclosed. The issuer chooses what to disclose." in text
    assert "Standard invariants enabled but not disclosed: 1." in text
    b = GC.Bk()
    b.pred["policy"].update({"total": 8, "enabled_std": 3, "enabled_custom": 2})
    assert "(3 declared invariants are disabled)" in run(b).to_text()


def test_each_tier_has_its_own_phrase():
    for tier, phrase in (("configured", "configuration read from the systems (not tested from outside)"),
                         ("observed", "observed network traffic or an outside-in scan")):
        b = GC.Bk()
        b.result(0)["tier"] = tier
        assert "based on %s." % phrase in run(b).to_text()


def test_violated_shows_a_count_and_never_a_witness():
    b = GC.Bk()
    GC.all_mode(b, ("VIOLATED", "HOLDS", "HOLDS"))
    text = run(b, None).to_text()
    assert 'A counterexample exists for "Guest networks cannot reach the point-of-sale segment" (2 found).' in text
    assert "REJECTED: A violated invariant is disclosed." in text


def test_unknown_lists_each_reason_phrase_and_says_it_is_not_a_pass():
    b = GC.Bk()
    GC.all_mode(b, ("UNKNOWN", "HOLDS", "HOLDS"))
    b.result(0)["reason_codes"] = ["possible_via_unknown_edges", "zone_unknown"]
    text = run(b).to_text()
    assert 'Undetermined for "Guest networks cannot reach the point-of-sale segment": a path may exist through connections that are not fully known. This is not a pass.' in text
    assert 'Undetermined for "Guest networks cannot reach the point-of-sale segment": some assets have no known network zone. This is not a pass.' in text


def test_exceptions_line_and_expired_attestation_line():
    b = GC.Bk()
    b.result(0)["exceptions"] = 2
    assert "2 declared exception(s) apply." in run(b).to_text()
    b = GC.Bk()
    b.now = "2026-12-02T10:00:00Z"
    r = run(b)
    assert r.exit == 1 and "REJECTED: The attestation has expired." in r.to_text()


def test_one_liners_for_the_chain_and_trust_failures():
    cases = ((lambda b: b.revoked_payload.update(superseded=[{"subject": "dns:example.com", "min_seq": 2, "at": "2026-12-01T10:00:00Z"}]),
              "W-SUPERSEDED"),
             (lambda b: b.revoked_payload.update(revoked=[{"kid": GC.KEYS["tenant-a"].kid, "reason": "key_compromise", "revoked_at": "2026-12-01T10:00:00Z"}]),
              "W-KEY-REVOKED"),
             (lambda b: b.result(0).__setitem__("digest", "sha256:" + "00" * 32), "W-STD-UNRECOGNISED"),
             (lambda b: (b.pred.__setitem__("seq", 2), b.pred.__setitem__("prev", "sha256:" + "ab" * 32), b.history.__setitem__(1, GC.base_statement())), "W-CHAIN-BROKEN"),
             (lambda b: b.dns.__setitem__(0, GC.dns_fixture(records=[GC.txt_for(GC.KEYS["tenant-b"])])), "W-DNS-UNBOUND"))
    for mutate, template in cases:
        b = GC.Bk()
        mutate(b)
        r = run(b)
        assert r.exit == 1 and ("- " + wording.render(template)) in r.to_text(), template


def test_a_warning_without_a_template_prints_the_codes_fixed_message():
    b = GC.Bk()
    b.result(0)["selected"]["stop_at"] = 70
    text = run(b).to_text()
    assert "- result.boundary_dominant: Boundary labels cover most of the estate." in text


# ----------------------------------------------------------------------------------------- headlines
def test_the_four_headlines():
    assert run(GC.Bk()).to_text().splitlines()[1] == "VALID under baseline profile"
    pol = __import__("paddock_verify.policy", fromlist=["x"]).parse_policy_text('{"policy_version":1,"name":"acme-insurer"}')
    assert run(GC.Bk(), pol).to_text().splitlines()[0] == "ACCEPTED under policy acme-insurer"
    b = GC.Bk()
    b.revoked_present = False
    assert run(b).to_text().splitlines()[1] == "UNVERIFIABLE: No revocation list available."
    b = GC.Bk()
    b.signer = "attacker"
    b.keyid = GC.KEYS["tenant-a"].kid
    assert run(b).to_text().splitlines()[1] == "REJECTED: The signature does not match the statement."


def test_every_code_message_fits_a_headline_and_every_headline_is_printable():
    for c in codes.CODES.values():
        for kind in ("rejected", "unverifiable"):
            line = wording.headline(kind, message=c.message)
            assert line.isascii() and "\n" not in line


# ------------------------------------------------------------------------------- the forbidden vocabulary
def test_no_template_message_registry_name_or_phrase_uses_a_forbidden_word():
    texts = [wording.raw_template(t) for t in wording.template_ids()] + [c.message for c in codes.CODES.values()]
    texts += [e["name"] for rs in REG.rulesets.values() for e in rs["std"].values()]
    texts += list(wording.TIER_PHRASES.values()) + list(wording.REASON_PHRASES.values())
    texts += [wording.profile_line(), report.CUSTOM_ROOTS_LINE, report.REVOCATION_NOT_CHECKED]
    for t in texts:
        assert wording.forbidden_hits(t, remove=[FOOTER]) == [], t


def test_registry_names_avoid_the_words_hardened_and_secure():
    for rs in REG.rulesets.values():
        for e in rs["std"].values():
            assert not re.search(r"hardened|secure", e["name"], re.I), e["name"]


def test_every_output_form_passes_the_scan_for_a_spread_of_outcomes():
    outs = []
    mutations = [lambda b: None, lambda b: setattr(b, "now", "2026-12-02T10:00:00Z"), lambda b: setattr(b, "revoked_present", False),
                 lambda b: GC.all_mode(b, ("VIOLATED", "UNKNOWN", "HOLDS")), lambda b: GC.enable_custom(b, [GC.custom_result("acme:fully-secure")]),
                 lambda b: setattr(b, "dns", [])]
    for m in mutations:
        b = GC.Bk()
        m(b)
        r = run(b)
        outs += [r.to_text(), r.to_text(quiet=True), r.to_json()]
    for t in outs:
        assert hits(t, ["acme:fully-secure"]) == [], t[:200]
    for code in codes.CODES:
        assert hits(codes.explain(code)) == [], code


def test_the_forbidden_scan_itself_catches_what_it_should():
    assert wording.forbidden_hits("This is SECURE and Safe.") == ["safe", "secure"]
    assert wording.forbidden_hits("fully-secure") == ["secure"]
    assert wording.forbidden_hits("insecure systems") == []
    assert wording.forbidden_hits("acme:fully-secure", remove=["acme:fully-secure"]) == []
    assert wording.forbidden_hits("vendor_certified") == []


def test_a_hostile_custom_id_is_shown_in_code_style_next_to_the_disclaimer_and_nowhere_else():
    b = GC.Bk()
    GC.enable_custom(b, [GC.custom_result("acme:fully-secure")])
    r = run(b)
    lines = r.to_text().splitlines()
    first = [i for i, ln in enumerate(lines) if "acme:fully-secure" in ln][0]
    assert lines[first] == "Custom invariant `acme:fully-secure` (defined by the operator; not reviewed by Paddock)"
    assert lines[first + 1].startswith('No counterexample found for "acme:fully-secure"')
    assert hits(r.to_text(), ["acme:fully-secure"]) == []


# ----------------------------------------------------------------------------- nothing the issuer writes
def test_output_is_ascii_and_json_params_are_plain_tokens():
    for mutate in (lambda b: setattr(b, "revoked_present", False), lambda b: b.result(0).__setitem__("covered", 1),
                   lambda b: b.pred.__setitem__("note", "x"), lambda b: b.result(0).__setitem__("tier", "gold")):
        b = GC.Bk()
        mutate(b)
        r = run(b)
        text = r.to_text() + r.to_json()
        text.encode("ascii")
        for x in r.reasons + r.warnings:
            for k, v in x.params.items():
                assert isinstance(v, (int, str)) and (not isinstance(v, str) or re.match(r"^[A-Za-z0-9_.\[\]-]{0,64}$", v)), (x.code, k, v)


def test_issuer_chosen_digits_and_names_cannot_inject_lines():
    b = GC.Bk()
    b.pred["engine"]["version"] = "1.0.0+evil"
    r = run(b)
    assert r.exit == 0 and "evil" not in r.to_text()                  # the engine version is never printed as text


def test_json_human_lines_equal_the_text_report():
    r = run(GC.Bk())
    assert json.loads(r.to_json())["human"] == r.text_lines()
    assert r.to_text() == "\n".join(r.text_lines()) + "\n"


def test_the_limits_text_is_printed_for_a_known_id_and_never_for_an_unknown_one():
    assert LIMITS.rstrip("\n") in run(GC.Bk()).to_text()
    b = GC.Bk()
    b.pred["limits"]["id"] = "paddock-limits/9"
    r = run(b)
    assert r.exit == 1 and LIMITS.rstrip("\n") not in r.to_text() and r.to_text().rstrip().endswith(FOOTER)


def test_the_footer_ends_every_report_and_quiet_omits_it():
    for mutate in (lambda b: None, lambda b: setattr(b, "now", "2030-01-01T00:00:00Z"), lambda b: setattr(b, "dns", [])):
        b = GC.Bk()
        mutate(b)
        r = run(b)
        assert r.to_text().rstrip("\n").splitlines()[-1] == FOOTER
        assert FOOTER not in r.to_text(quiet=True)


def test_slot_values_outside_their_type_are_errors_never_printed():
    for kwargs in (dict(name='a "quoted" name', violations=1), dict(name="a{b}", violations=1), dict(name="x" * 200, violations=1),
                   dict(name="ok", violations=True), dict(name="ok", violations=-1)):
        with pytest.raises(wording.WordingError):
            wording.render("W-VIOLATED", **kwargs)
    with pytest.raises(wording.WordingError):
        wording.render("W-VALID", subject="dns:example.com", issued_at="yesterday", valid_until="2026-12-01T09:00:00Z")
    with pytest.raises(wording.WordingError):
        wording.render("W-FOOTER", extra=1)
