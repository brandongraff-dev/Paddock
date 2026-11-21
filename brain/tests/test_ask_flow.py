"""The ask() flow with a fake DB + fake LLM — no key, network, or real DB.

Proves: fallback SQL is built and executed without a key; LLM-proposed SQL
is still guard-checked; malicious SQL is rejected and never executed; every
attempt is audited to nl_queries."""
from __future__ import annotations

import pytest

from app.ask import answer, build_sql
from app.config import Config
from tests.conftest import FakeDB, FakeLLM

CFG = Config(anthropic_api_key=None, max_rows=500, stmt_timeout_ms=4000)


async def test_build_sql_falls_back_without_key():
    sql, engine = await build_sql("show critical findings", FakeLLM(enabled=False))
    assert engine == "fallback"
    assert sql and "ask_findings" in sql


async def test_build_sql_uses_llm_when_enabled():
    llm = FakeLLM(enabled=True, sql="SELECT value FROM ask_assets")
    sql, engine = await build_sql("anything at all", llm)
    assert engine == "llm"
    assert sql == "SELECT value FROM ask_assets"


async def test_build_sql_degrades_when_llm_returns_nothing():
    # LLM on but produced no usable SQL -> fall back to the intent matcher.
    llm = FakeLLM(enabled=True, sql=None)
    sql, engine = await build_sql("show critical findings", llm)
    assert engine == "fallback"
    assert sql is not None


async def test_answer_fallback_executes_and_audits():
    db = FakeDB(columns=["asset_value"], rows=[["a.com"], ["b.com"]])
    res = await answer(db, FakeLLM(enabled=False), CFG, "show critical findings", "alice")
    assert res["ok"] is True
    assert res["engine"] == "fallback"
    assert res["columns"] == ["asset_value"]
    assert len(res["rows"]) == 2
    assert "LIMIT 500" in res["generated_sql"].upper()  # limit enforced
    # audited as a successful query
    assert db.logged and db.logged[-1]["ok"] is True
    assert db.logged[-1]["row_count"] == 2
    assert db.logged[-1]["asked_by"] == "alice"


async def test_answer_rejects_malicious_llm_sql_without_executing():
    db = FakeDB()
    llm = FakeLLM(enabled=True, sql="DROP TABLE findings")
    res = await answer(db, llm, CFG, "drop everything", "mallory")
    assert res["ok"] is False
    assert res["generated_sql"] == "DROP TABLE findings"
    assert res["reason"]
    # never executed
    assert db.ran_sql == []
    # audited as a failed attempt
    assert db.logged[-1]["ok"] is False
    assert db.logged[-1]["engine"] == "llm"


async def test_answer_rejects_non_ask_table_from_llm():
    db = FakeDB()
    llm = FakeLLM(enabled=True, sql="SELECT * FROM credentials")
    res = await answer(db, llm, CFG, "show me the creds", None)
    assert res["ok"] is False
    assert "not allowed" in res["reason"]
    assert db.ran_sql == []


async def test_answer_unknown_question_no_sql():
    db = FakeDB()
    res = await answer(db, FakeLLM(enabled=False), CFG, "what is the meaning of life", None)
    assert res["ok"] is False
    assert res["reason"] == "no_sql"
    assert res["generated_sql"] is None
    assert db.ran_sql == []
    assert db.logged[-1]["ok"] is False


async def test_answer_handles_execution_error():
    db = FakeDB(raise_on_run=True)
    res = await answer(db, FakeLLM(enabled=False), CFG, "show critical findings", None)
    assert res["ok"] is False
    assert res["reason"] == "execution_error"
    assert db.logged[-1]["ok"] is False
