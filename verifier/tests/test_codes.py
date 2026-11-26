# SPDX-License-Identifier: Apache-2.0
"""codes.py must equal spec/A-reason-codes.md, and every code must be exercised by a vector."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from paddock_verify import codes, wording

SPEC = Path(__file__).resolve().parents[2] / "docs" / "spec" / "containment-attestation-v1"
APPX = SPEC / "spec" / "A-reason-codes.md"


def parse_appendix():
    rows = []
    for line in APPX.read_text(encoding="ascii").splitlines():
        m = re.match(r"^\| (\S+(?: \S+)?) \| `([a-z_]+\.[a-z0-9_]+)` \| (\S+) \| (\S+) \| (.*?) \| (.*) \|$", line)
        if m:
            rows.append(m.groups())
    return rows


def test_codes_py_equals_appendix_a():
    rows = parse_appendix()
    assert len(rows) >= 100
    table = {}
    order = []
    for step, code, cls, alt, msg, note in rows:
        assert code not in table, "duplicate row for %s" % code
        table[code] = (step, cls, alt, msg, note)
        order.append(code)
    assert set(table) == set(codes.CODES), (sorted(set(table) ^ set(codes.CODES)))
    assert order == list(codes.CODES), "table order differs"
    for code, (step, cls, alt, msg, note) in table.items():
        c = codes.CODES[code]
        assert c.note == note, code
        assert str(c.step_label) == step, code
        assert c.cls == cls, code
        assert (c.alt or "-") == (alt or "-"), code
        assert c.message == msg, code


def test_every_code_has_a_well_formed_definition():
    assert len(codes.CODES) == len(set(codes.CODES))
    for code, c in codes.CODES.items():
        assert re.fullmatch(r"[a-z]+\.[a-z0-9_]+", code), code
        assert c.code == code
        assert c.cls in ("R", "U", "W", "X"), code
        assert c.alt in (None, "R", "U", "W"), code
        assert c.message.isascii() and c.message.endswith("."), code
        assert wording.forbidden_hits(c.message) == [], code
        assert c.spec_ref.startswith("spec/"), code


def test_known_codes_from_the_contract():
    for code, cls, step in [("input.unreadable", "U", 0), ("input.too_large", "R", 0), ("schema.base64_invalid", "R", 1),
                            ("predicate.unsupported_version", "U", 1), ("sig.count_invalid", "R", 2),
                            ("config.no_trust_roots", "U", 3), ("dns.not_applicable", "W", 3),
                            ("revocation.stale", "U", 4), ("time.expired", "R", 5), ("policy.shrank", "R", 6),
                            ("limits.digest_mismatch", "R", 7), ("result.universe_empty", "R", 8),
                            ("policy.disclosure_incomplete", "R", 9), ("merkle.proof_invalid", "R", 10),
                            ("internal.error", "U", None), ("config.policy_invalid", "X", None)]:
        c = codes.CODES[code]
        assert (c.cls, c.step) == (cls, step), code
    assert codes.CODES["key.cert_missing"].alt == "W"
    assert codes.CODES["dns.not_applicable"].alt == "R"
    assert codes.CODES["dns.skipped_offline"].alt == "W"
    assert codes.CODES["anchor.unavailable"].alt == "W"
    assert codes.CODES["invariant.unrequired_violation"].alt == "W"


def test_exit_precedence_reject_then_unverifiable_then_accept():
    assert codes.exit_for(["W", "W"]) == 0
    assert codes.exit_for([]) == 0
    assert codes.exit_for(["U"]) == 2
    assert codes.exit_for(["U", "R", "W"]) == 1
    assert codes.exit_for(["R"]) == 1
    with pytest.raises(ValueError):
        codes.exit_for(["Z"])
    assert codes.EXIT_USAGE == 64


def test_explain():
    s = codes.explain("sig.invalid")
    assert "sig.invalid" in s and "The signature does not match the statement." in s and "step 2" in s
    assert codes.explain("nope.nope") is None
    assert "spec/07-verification-procedure.md" in codes.explain("time.expired")


def test_every_code_is_exercised_by_a_vector_once_the_corpus_exists():
    """Contract 8.4: every code appears in at least one vector. Skipped until P3.4's MANIFEST exists."""
    manifest = SPEC / "vectors" / "MANIFEST.json"
    if not manifest.exists():
        pytest.skip("the case corpus (P3.4) is not built yet")
    seen = set()
    for p in sorted((SPEC / "vectors" / "cases").glob("*/case.json")):
        exp = json.loads(p.read_text(encoding="ascii"))["expect"]
        seen.update(exp.get("codes", []))
        seen.update(exp.get("warnings", []))
    for p in sorted((SPEC / "vectors" / "primitives").glob("*.json")):
        seen.update(re.findall(r'"((?:input|schema|sig|key|merkle|dns|time)\.[a-z0-9_]+)"', p.read_text(encoding="ascii")))
    missing = sorted(set(codes.CODES) - seen)
    assert not missing, missing
