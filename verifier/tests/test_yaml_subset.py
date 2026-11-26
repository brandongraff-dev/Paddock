# SPDX-License-Identifier: Apache-2.0
"""The strict YAML subset (PPY) and the acceptance policy built on it.

``policy-parse.json`` pins the accept and reject table (with line numbers). Accepted cases are also compared
with PyYAML's ``safe_load`` when PyYAML is installed (development only).
"""
from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path

import pytest

from paddock_verify import policy as policy_mod
from paddock_verify import yaml_subset

SPEC = Path(__file__).resolve().parents[2] / "docs" / "spec" / "containment-attestation-v1"
VEC = json.loads((SPEC / "vectors" / "primitives" / "policy-parse.json").read_text(encoding="ascii"))


def text_of(case):
    if "yaml" in case:
        return case["yaml"]
    r = case["yaml_recipe"]
    body = r["text"] + r["fill"] * (r["length"] - len(r["text"]) - (1 if r.get("newline") else 0))
    return body + ("\n" if r.get("newline") else "")


def decode(v):
    if isinstance(v, dict) and set(v) == {"$decimal"}:
        return Decimal(v["$decimal"])
    if isinstance(v, dict):
        return dict((k, decode(x)) for k, x in v.items())
    if isinstance(v, list):
        return [decode(x) for x in v]
    return v


def strict_equal(a, b):
    """Equality that does not conflate True with 1 or an int with a Decimal."""
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return set(a) == set(b) and all(strict_equal(a[k], b[k]) for k in a)     # the JSON vector file has sorted keys
    if isinstance(a, list):
        return len(a) == len(b) and all(strict_equal(x, y) for x, y in zip(a, b))
    return a == b


ACCEPT = [c for c in VEC["cases"] if c["accept"]]
REJECT = [c for c in VEC["cases"] if not c["accept"]]


@pytest.mark.parametrize("case", ACCEPT, ids=lambda c: c["id"])
def test_accepted_cases_parse_to_the_pinned_value(case):
    got = yaml_subset.loads(text_of(case))
    assert strict_equal(got, decode(case["value"])), got


@pytest.mark.parametrize("case", REJECT, ids=lambda c: c["id"])
def test_rejected_cases_name_the_pinned_line(case):
    with pytest.raises(yaml_subset.YamlError) as ei:
        yaml_subset.loads(text_of(case))
    assert ei.value.code == "config.policy_invalid"
    assert ei.value.line == case["line"], (ei.value.line, str(ei.value))


def test_accepted_cases_agree_with_pyyaml():
    yaml = pytest.importorskip("yaml")

    def norm(v):
        if isinstance(v, Decimal):
            return float(v)
        if isinstance(v, dict):
            return dict((k, norm(x)) for k, x in v.items())
        if isinstance(v, list):
            return [norm(x) for x in v]
        return v

    checked = 0
    for case in ACCEPT:
        text = text_of(case)
        theirs = yaml.safe_load(text)
        theirs = {} if theirs is None else theirs
        assert norm(yaml_subset.loads(text)) == theirs, case["id"]
        checked += 1
    assert checked == len(ACCEPT) and checked > 20


def test_bytes_input_and_error_type():
    assert yaml_subset.loads(b"a: 1\n") == {"a": 1}
    with pytest.raises(yaml_subset.YamlError) as ei:
        yaml_subset.loads(b"a: caf\xc3\xa9\n")
    assert ei.value.line == 1 and isinstance(ei.value, ValueError)


def test_numeric_looking_bare_tokens_are_not_silently_strings():
    for bad in ("a: 1.2.3\n", "a: -5\n", "a: +1\n", "a: 01\n", "a: 5.\n", "a: 1-2\n"):
        with pytest.raises(yaml_subset.YamlError):
            yaml_subset.loads(bad)
    assert yaml_subset.loads("a: 12:30\n") == {"a": "12:30"}                  # digits and colons: a string, per spec/08


def test_flow_collections_are_one_line_scalars_only():
    assert yaml_subset.loads("r:\n  - { a: 1, b: x }\n") == {"r": [{"a": 1, "b": "x"}]}
    for bad in ("a: [x,]\n", "a: [,x]\n", "r:\n  - { a: 1, }\n", "r:\n  - {a:1}\n", "a: [x y]\n", 'a: ["x]\n'):
        with pytest.raises(yaml_subset.YamlError):
            yaml_subset.loads(bad)


def test_depth_and_size_limits_are_enforced_not_recursed():
    deep = "".join("  " * i + "k%d:\n" % i for i in range(50)) + "  " * 50 + "x: 1\n"
    with pytest.raises(yaml_subset.YamlError) as ei:
        yaml_subset.loads(deep)
    assert ei.value.line == 7
    with pytest.raises(yaml_subset.YamlError):
        yaml_subset.loads("# " + "x" * 65535 + "\n")
    assert yaml_subset.loads("# " + "x" * 65532 + "\n") == {}


def test_parser_is_linear_on_wide_inputs():
    import time
    text = "".join("k%d: v%d\n" % (i, i) for i in range(4000))
    t = time.time()
    assert len(yaml_subset.loads(text)) == 4000
    assert time.time() - t < 2.0


# ------------------------------------------------------------------------------------------------ policy
BASELINE_POLICY_JSON = ('{"policy_version":1,"require":[{"invariant":"std:no-internet-to-datastore","verdict":"HOLDS","min_tier":"observed",'
                        '"min_coverage":"0.95","max_age":"24h","digest":"sha256:' + "ab" * 32 + '"}],"max_age":"48h","min_coverage":"0.95",'
                        '"disclosure":"any","violations":"reject","max_exceptions":null,"max_stop_at_share":null,'
                        '"trust":{"vendor_cert":"required","dns_binding":"required","dnssec":"off","revocation":"required","revocation_max_age":"72h"},'
                        '"history":"if_available","std_registry":"strict","engine_advisories":"reject","anchor":"off","require_latest":false}')


def test_baseline_profile_values():
    p = policy_mod.baseline()
    assert p.profile == "baseline" and p.require == () and p.sha256 is None and p.name is None
    assert (p.max_age_s, p.min_coverage_bp, p.disclosure, p.violations) == (48 * 3600, 9500, "any", "reject")
    assert (p.vendor_cert, p.dns_binding, p.dnssec, p.revocation, p.revocation_max_age_s) == ("required", "required", "off", "required", 72 * 3600)
    assert (p.history, p.std_registry, p.engine_advisories, p.anchor, p.require_latest) == ("if_available", "strict", "reject", "off", False)
    assert p.max_exceptions is None and p.max_stop_at_share_bp is None


def test_json_policy_parses_every_field():
    p = policy_mod.parse_policy_text(BASELINE_POLICY_JSON, filename="insurer.json")
    assert p.profile == "policy" and p.name == "insurer.json"
    r = p.require[0]
    assert (r.invariant, r.min_tier, r.min_coverage_bp, r.max_age_s, r.digest) == ("std:no-internet-to-datastore", "observed", 9500, 86400, "sha256:" + "ab" * 32)
    assert p.max_exceptions is None and p.max_stop_at_share_bp is None
    assert len(p.sha256) == 64


def test_yaml_and_json_forms_have_the_same_meaning_and_hash():
    j = policy_mod.parse_policy_text('{"policy_version":1,"require":[{"invariant":"std:a-b","verdict":"HOLDS","min_tier":"observed"}],'
                                     '"max_age":"48h","min_coverage":"0.95"}', filename="p.json")
    y = policy_mod.parse_policy_text("policy_version: 1\nrequire:\n  - { invariant: std:a-b, verdict: HOLDS, min_tier: observed }\n"
                                     "max_age: 48h\nmin_coverage: 0.95\n", filename="p.yaml")
    assert j.sha256 == y.sha256 and j.require == y.require and j.min_coverage_bp == y.min_coverage_bp == 9500


def test_policy_hash_changes_with_content():
    a = policy_mod.parse_policy_text('{"policy_version":1,"max_age":"24h"}')
    b = policy_mod.parse_policy_text('{"policy_version":1,"max_age":"25h"}')
    c = policy_mod.parse_policy_text('{"policy_version":1,"max_age":"24h","max_exceptions":null}')
    assert a.sha256 != b.sha256 and a.sha256 == c.sha256


@pytest.mark.parametrize("text", [
    '{}', '{"policy_version":2}', '{"policy_version":true}', '{"policy_version":1,"surprise":1}',
    '{"policy_version":1,"max_age":"48 hours"}', '{"policy_version":1,"max_age":"0x"}', '{"policy_version":1,"max_age":48}',
    '{"policy_version":1,"min_coverage":0.95}', '{"policy_version":1,"min_coverage":"0.95001"}', '{"policy_version":1,"min_coverage":"1.5"}',
    '{"policy_version":1,"min_coverage":"-0.1"}', '{"policy_version":1,"min_coverage":".5"}',
    '{"policy_version":1,"disclosure":"some"}', '{"policy_version":1,"violations":"ignore"}', '{"policy_version":1,"history":"never"}',
    '{"policy_version":1,"anchor":"yes"}', '{"policy_version":1,"std_registry":"off"}', '{"policy_version":1,"engine_advisories":"off"}',
    '{"policy_version":1,"trust":{"dnssec":"maybe"}}', '{"policy_version":1,"trust":{"unknown":"x"}}',
    '{"policy_version":1,"trust":{"revocation_max_age":"96h"}}',                                    # above the 72 hour staleness rule
    '{"policy_version":1,"max_exceptions":-1}', '{"policy_version":1,"max_exceptions":true}', '{"policy_version":1,"max_exceptions":"3"}',
    '{"policy_version":1,"require":[{"invariant":"nope"}]}', '{"policy_version":1,"require":[{"invariant":"std:x","verdict":"VIOLATED"}]}',
    '{"policy_version":1,"require":[{"invariant":"std:x","verdict":"UNKNOWN"}]}', '{"policy_version":1,"require":[{"invariant":"std:x","min_tier":"declared"}]}',
    '{"policy_version":1,"require":[{"invariant":"std:x","extra":1}]}', '{"policy_version":1,"require":[{"verdict":"HOLDS"}]}',
    '{"policy_version":1,"require":[{"invariant":"std:x"},{"invariant":"std:x"}]}',
    '{"policy_version":1,"require":[{"invariant":"std:x","digest":"abc"}]}', '{"policy_version":1,"require":"std:x"}',
    '{"policy_version":1,"require_latest":"yes"}', '{"policy_version":1,"name":"has space"}', '{"policy_version":1,"name":"%s"}' % ("a" * 65),
    '{"policy_version":1,"max_age":"1d","max_age":"2d"}',                                           # duplicate key
    '[1]', 'null', '"x"', '{"policy_version":1,', '{"policy_version":1,"x":NaN}', '{"policy_version":1.0}',
])
def test_invalid_policies_are_config_errors(text):
    with pytest.raises(policy_mod.PolicyError) as ei:
        policy_mod.parse_policy_text(text)
    assert ei.value.code == "config.policy_invalid"


def test_policy_yaml_errors_carry_the_line():
    with pytest.raises(policy_mod.PolicyError) as ei:
        policy_mod.parse_policy_text("policy_version: 1\nmax_age: 48h\nbogus line\n")
    assert ei.value.line == 3 and "line 3" in str(ei.value)


def test_policy_size_and_depth_are_bounded():
    with pytest.raises(policy_mod.PolicyError):
        policy_mod.parse_policy_text('{"policy_version":1,"require":[' + '{"invariant":"std:x"},' * 20000 + ']}')
    with pytest.raises(policy_mod.PolicyError):
        policy_mod.parse_policy_text("[" * 5000 + "]" * 5000)


def test_thresholds_are_exact_basis_points():
    for text, bp in (("0", 0), ("1", 10000), ("0.95", 9500), ("0.9999", 9999), ("0.0001", 1), ("1.0", 10000), ("0.5", 5000)):
        p = policy_mod.parse_policy_text('{"policy_version":1,"min_coverage":"%s"}' % text)
        assert p.min_coverage_bp == bp, text
    y = policy_mod.parse_policy_text("policy_version: 1\nmin_coverage: 1\nmax_stop_at_share: 0.25\n")
    assert (y.min_coverage_bp, y.max_stop_at_share_bp) == (10000, 2500)


def test_cli_overrides_change_the_policy_and_the_hash():
    base = policy_mod.parse_policy_text('{"policy_version":1,"max_age":"48h"}', filename="p.json")
    over = policy_mod.apply_overrides(base, max_age="6h", min_coverage="0.99", require=["std:a-b:observed", "std:c-d"])
    assert over.max_age_s == 6 * 3600 and over.min_coverage_bp == 9900 and over.sha256 != base.sha256
    assert [(r.invariant, r.min_tier) for r in over.require] == [("std:a-b", "observed"), ("std:c-d", None)]
    # overrides on the baseline make it a policy run
    b = policy_mod.apply_overrides(policy_mod.baseline(), max_age="6h")
    assert b.profile == "policy" and b.name == "command-line" and b.max_age_s == 6 * 3600
    for bad in (dict(max_age="soon"), dict(min_coverage="2"), dict(require=["nope"]), dict(require=["std:x:gold"])):
        with pytest.raises(policy_mod.PolicyError):
            policy_mod.apply_overrides(policy_mod.baseline(), **bad)


def test_policy_name_defaults_to_a_safe_token_from_the_file_name():
    p = policy_mod.parse_policy_text('{"policy_version":1}', filename="/tmp/dir/My Policy (v2).json")
    assert p.name == "My_Policy__v2_.json"
    q = policy_mod.parse_policy_text('{"policy_version":1,"name":"insurer-2026"}', filename="x.json")
    assert q.name == "insurer-2026"
