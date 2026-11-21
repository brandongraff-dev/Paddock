"""The fallback intent-matcher: every prewritten question maps to a safe,
guard-valid SELECT, and unknown questions don't match."""
from __future__ import annotations

import pytest

from app.ask import FALLBACKS, match_intent
from app.guard import validate


def test_at_least_eight_fallback_questions():
    assert len(FALLBACKS) >= 8


@pytest.mark.parametrize("entry", FALLBACKS, ids=[e["label"] for e in FALLBACKS])
def test_every_fallback_sql_is_guard_valid(entry):
    ok, reason = validate(entry["sql"])
    assert ok is True, f"{entry['label']}: {reason}"


@pytest.mark.parametrize("question,expected_substr", [
    ("which internet-facing hosts run software with a KEV CVE?", "ask_attack_paths"),
    ("show me the highest exploitability attack paths", "ask_attack_paths"),
    ("what assets were added this week?", "ask_assets"),
    ("worst TLS configuration", "tls"),
    ("highest blast radius assets", "blast_score"),
    ("any exposed secrets?", "secret_scan"),
    ("list production assets", "production"),
    ("how many open findings by severity?", "GROUP BY"),
    ("show critical findings", "critical"),
])
def test_known_questions_match_expected_sql(question, expected_substr):
    entry = match_intent(question)
    assert entry is not None, question
    assert expected_substr in entry["sql"]
    ok, reason = validate(entry["sql"])
    assert ok is True, reason


def test_unknown_question_does_not_match():
    assert match_intent("what is the meaning of life?") is None
    assert match_intent("") is None
