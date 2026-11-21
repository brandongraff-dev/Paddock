"""Adversarial verifier tests (THREAT-MODEL LAYER 4)."""
from __future__ import annotations

import pytest

from app import generators as gen
from app import verify as verify_mod


def _bump_diff():
    return gen.generate_dependency_bump({
        "ecosystem": "PyPI", "package": "flask",
        "current_version": "1.0.0", "fixed_version": "1.1.4", "osv_id": "GHSA-1",
    })


@pytest.mark.asyncio
async def test_verify_accepts_in_scope_bump():
    gd = _bump_diff()
    finding = {"id": "f1", "rule_source": "sca", "title": "flask vuln", "description": "bump"}
    res = await verify_mod.verify(finding, gd.change_class, gd.unified, gd.spec, llm=None)
    assert res.ok
    assert res.verdict == "addresses_finding"
    assert "no out-of-scope" in res.report["summary"]


@pytest.mark.asyncio
async def test_verify_flags_out_of_scope_second_file():
    gd = _bump_diff()
    # Append an out-of-scope edit to a second file.
    tampered = gd.unified + (
        "--- a/app/auth.py\n+++ b/app/auth.py\n@@ -1 +1 @@\n-ok = True\n+ok = backdoor()\n"
    )
    finding = {"id": "f1", "rule_source": "sca", "title": "flask vuln"}
    res = await verify_mod.verify(finding, gd.change_class, tampered, gd.spec, llm=None)
    assert not res.ok
    assert any("files" in r or "out-of-scope" in r for r in res.reasons)


@pytest.mark.asyncio
async def test_verify_flags_rule_source_mismatch():
    gd = _bump_diff()
    # A dependency_bump diff for a finding that is actually a header_check.
    finding = {"id": "f1", "rule_source": "header_check", "title": "missing header"}
    res = await verify_mod.verify(finding, gd.change_class, gd.unified, gd.spec, llm=None)
    assert not res.ok
    assert any("rule_source" in r for r in res.reasons)


@pytest.mark.asyncio
async def test_verify_llm_disagreement_rejects():
    gd = _bump_diff()
    finding = {"id": "f1", "rule_source": "sca", "title": "flask vuln"}

    class DisagreeingLLM:
        def is_enabled(self):
            return True

        async def verify_second_opinion(self, *_a, **_k):
            return {"addresses_finding": False, "out_of_scope": True,
                    "reason": "looks like it touches unrelated logic"}

    res = await verify_mod.verify(finding, gd.change_class, gd.unified, gd.spec, llm=DisagreeingLLM())
    assert not res.ok
    assert any("adversarial LLM" in r for r in res.reasons)
    assert res.report["llm_verifier"]["used"] is True


@pytest.mark.asyncio
async def test_verify_llm_agreement_keeps_pass():
    gd = _bump_diff()
    finding = {"id": "f1", "rule_source": "sca", "title": "flask vuln"}

    class AgreeingLLM:
        def is_enabled(self):
            return True

        async def verify_second_opinion(self, *_a, **_k):
            return {"addresses_finding": True, "out_of_scope": False, "reason": "ok"}

    res = await verify_mod.verify(finding, gd.change_class, gd.unified, gd.spec, llm=AgreeingLLM())
    assert res.ok
