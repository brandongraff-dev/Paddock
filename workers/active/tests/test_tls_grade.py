"""TLS posture grading tests. Pure, deterministic grading from fixed facts."""
from __future__ import annotations

import pytest

from app.modules import tls_grade

_FAR_FUTURE = "2030-01-01T00:00:00Z"
_PAST = "2020-01-01T00:00:00Z"
_ECDHE = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
_RC4 = "TLS_RSA_WITH_RC4_128_SHA"


def _facts(protocols, *, cipher=_ECDHE, not_after=_FAR_FUTURE, self_signed=False, host="host.example.com"):
    row = {
        "host": host,
        "tls_version": protocols,
        "cipher": cipher,
        "certificate": {
            "subject_cn": host,
            "issuer_cn": "Example CA",
            "not_before": "2024-01-01T00:00:00Z",
            "not_after": not_after,
            "self_signed": self_signed,
            "sha256": "ab" * 32,
            "subject_an": [host],
        },
    }
    return {"host": host, "port": 443, "available": True, "error": None, "rows": [row]}


# ---- the grade table: A+ down to F -----------------------------------------


@pytest.mark.parametrize("protocols,cipher,expected_grade,expected_score", [
    # A+  : TLS1.3 + TLS1.2, FS cipher, valid cert -> no deductions = 100
    (["TLSv1.3", "TLSv1.2"], _ECDHE, "A+", 100),
    # A   : TLS1.1 enabled (-20), TLS1.3 present (no -5) = 80
    (["TLSv1.3", "TLSv1.1"], _ECDHE, "A", 80),
    # B   : TLS1.0 enabled (-30), TLS1.3 present = 70
    (["TLSv1.3", "TLSv1.0"], _ECDHE, "B", 70),
    # C   : TLS1.0 (-30) + TLS1.1 (-20), TLS1.3 present = 50
    (["TLSv1.3", "TLSv1.1", "TLSv1.0"], _ECDHE, "C", 50),
    # D   : SSLv3 (-40) + TLS1.1 (-20), TLS1.3 present = 40
    (["TLSv1.3", "SSLv3", "TLSv1.1"], _ECDHE, "D", 40),
    # E   : SSLv3 (-40) + TLS1.0 (-30), TLS1.3 present = 30
    (["TLSv1.3", "SSLv3", "TLSv1.0"], _ECDHE, "E", 30),
    # F   : everything bad + weak cipher, no TLS1.3 -> floored at 0
    (["SSLv3", "TLSv1.0", "TLSv1.1"], _RC4, "F", 0),
])
def test_grade_table(protocols, cipher, expected_grade, expected_score):
    result = tls_grade.grade_facts(_facts(protocols, cipher=cipher), env="dev")
    assert result.grade == expected_grade
    assert result.score == expected_score


# ---- score -> grade boundaries ---------------------------------------------


@pytest.mark.parametrize("score,grade", [
    (100, "A+"), (95, "A+"), (94, "A"), (80, "A"), (79, "B"), (65, "B"),
    (64, "C"), (50, "C"), (49, "D"), (35, "D"), (34, "E"), (20, "E"), (19, "F"), (0, "F"),
])
def test_score_to_grade_boundaries(score, grade):
    assert tls_grade._score_to_grade(score) == grade


# ---- T: trust/validation failure -------------------------------------------


def test_expired_cert_is_grade_T():
    # Otherwise-perfect config, but the certificate is expired.
    result = tls_grade.grade_facts(_facts(["TLSv1.3", "TLSv1.2"], not_after=_PAST), env="dev")
    assert result.grade == "T"
    assert result.trust_failure is True
    assert "certificate expired" in result.issues


def test_self_signed_in_prod_is_grade_T():
    result = tls_grade.grade_facts(
        _facts(["TLSv1.3", "TLSv1.2"], self_signed=True), env="prod",
    )
    assert result.grade == "T"
    assert result.trust_failure is True


def test_self_signed_outside_prod_not_T():
    # Per the contract, the trust failure for self-signed is prod-only.
    result = tls_grade.grade_facts(
        _facts(["TLSv1.3", "TLSv1.2"], self_signed=True), env="dev",
    )
    assert result.grade != "T"


def test_no_rows_returns_none():
    facts = {"host": "h", "port": 443, "available": True, "error": None, "rows": []}
    assert tls_grade.grade_facts(facts, env="dev") is None


# ---- cert-expiry deductions -------------------------------------------------


def test_expiring_soon_deductions(monkeypatch):
    import app.modules.tls_grade as mod
    from datetime import datetime, timezone

    # Freeze "now" so day-math is stable.
    fixed_now = datetime(2025, 1, 1, tzinfo=timezone.utc)

    class _FrozenDT(datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed_now

    monkeypatch.setattr(mod, "datetime", _FrozenDT)

    # Expires in ~10 days -> -15.
    r = tls_grade.grade_facts(_facts(["TLSv1.3", "TLSv1.2"], not_after="2025-01-11T00:00:00Z"), env="dev")
    assert r.score == 85 and r.grade == "A"
    # Expires in ~20 days -> -5.
    r = tls_grade.grade_facts(_facts(["TLSv1.3", "TLSv1.2"], not_after="2025-01-21T00:00:00Z"), env="dev")
    assert r.score == 95 and r.grade == "A+"


# ---- finding emitted only at <= C ------------------------------------------


@pytest.mark.parametrize("protocols,cipher,should_emit,severity", [
    (["TLSv1.3", "TLSv1.2"], _ECDHE, False, None),          # A+
    (["TLSv1.3", "TLSv1.1"], _ECDHE, False, None),          # A
    (["TLSv1.3", "TLSv1.0"], _ECDHE, False, None),          # B
    (["TLSv1.3", "TLSv1.1", "TLSv1.0"], _ECDHE, True, "low"),      # C
    (["TLSv1.3", "SSLv3", "TLSv1.1"], _ECDHE, True, "medium"),     # D
    (["SSLv3", "TLSv1.0", "TLSv1.1"], _RC4, True, "high"),         # F
])
def test_finding_only_at_c_or_worse(protocols, cipher, should_emit, severity):
    result = tls_grade.grade_facts(_facts(protocols, cipher=cipher), env="dev")
    finding = tls_grade.result_to_finding(result)
    if should_emit:
        assert finding is not None
        assert finding["rule_source"] == "tls_grade"
        assert finding["severity"] == severity
        assert finding["evidence"]["grade"] == result.grade
    else:
        assert finding is None


def test_trust_failure_finding_is_high():
    result = tls_grade.grade_facts(_facts(["TLSv1.3", "TLSv1.2"], not_after=_PAST), env="dev")
    finding = tls_grade.result_to_finding(result)
    assert finding is not None
    assert finding["severity"] == "high"


# ---- grade_host: bulk emission + reuse of gathered facts --------------------


async def test_grade_host_posts_bulk_and_finding(fake_orch, scope, politeness):
    facts = _facts(["TLSv1.3", "TLSv1.1", "TLSv1.0"])  # grade C
    r = await tls_grade.grade_host(
        "host.example.com:443", scope=scope, politeness=politeness,
        orchestrator=fake_orch, asset_id="asset-123", facts=facts, env="dev",
    )
    # One tls-grades/bulk upsert with the documented item shape.
    assert len(fake_orch.tls_grades_calls) == 1
    item = fake_orch.tls_grades_calls[0][0]
    assert item["asset_id"] == "asset-123"
    assert item["host"] == "host.example.com"
    assert item["grade"] == "C"
    assert item["score"] == 50
    assert set(item.keys()) == {
        "asset_id", "host", "grade", "score", "protocols",
        "weak_ciphers", "issues", "cert_expires",
    }
    # Grade C -> a low-severity tls_grade finding.
    assert len(r["findings"]) == 1
    assert r["findings"][0]["rule_source"] == "tls_grade"
    assert r["summary"]["grade"] == "C"


async def test_grade_host_good_grade_no_finding(fake_orch, scope, politeness):
    facts = _facts(["TLSv1.3", "TLSv1.2"])  # grade A+
    r = await tls_grade.grade_host(
        "host.example.com:443", scope=scope, politeness=politeness,
        orchestrator=fake_orch, facts=facts, env="dev",
    )
    assert len(fake_orch.tls_grades_calls) == 1   # grade still recorded
    assert r["findings"] == []                    # but no finding


async def test_grade_host_tool_unavailable_emits_info(fake_orch, scope, politeness, fake_subprocess):
    # tlsx is not registered -> resolve_binary returns None -> ToolUnavailable.
    r = await tls_grade.grade_host(
        "host.example.com:443", scope=scope, politeness=politeness,
        orchestrator=fake_orch,
    )
    rules = {f["rule_id"] for f in r["findings"]}
    assert "tool-unavailable-tlsx" in rules
    assert r["findings"][0]["severity"] == "info"
    assert fake_orch.tls_grades_calls == []
