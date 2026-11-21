"""Natural-language -> validated read-only SQL over the ask_* views.

Flow for every question:
  1. Build candidate SQL — LLM when a key is present, otherwise a fallback
     intent-matcher that maps ~8 common questions to prewritten safe SELECTs.
     If the LLM is enabled but returns nothing usable, we still fall back.
  2. guard.validate() — on reject, return {ok:false, reason, generated_sql}
     and log the attempt. NEVER execute unvalidated SQL.
  3. Execute in a READ-ONLY transaction with a statement timeout, row-capped.
  4. Log every attempt to nl_queries (audit record).
  5. Return {ok, columns, rows, generated_sql, engine, note}.

The ask path touches the database ONLY through db.run_readonly_select over
the three ask_* views, which exclude scope secrets, alert targets and
credentials.
"""
from __future__ import annotations

import logging
from typing import Any

from . import guard
from .config import Config
from .db import Database
from .llm import LLM

log = logging.getLogger("brain.ask")

# Column reference handed to the LLM so it writes SQL against the real views.
SCHEMA_DESC = (
    "ask_assets(id, kind, value, canonical, first_seen, last_seen, source, "
    "env, blast_score)\n"
    "ask_findings(id, asset_id, asset_value, asset_kind, rule_id, rule_source, "
    "severity, title, status, cvss, epss, first_seen)\n"
    "ask_attack_paths(id, severity, exploitability, kev_on_path, length, title)"
)

# Fallback intent matcher: ~8 common analyst questions -> prewritten safe
# SELECTs. Each entry: (triggers, sql, label). Order matters — the more
# specific intents come first so a generic word doesn't shadow them. Every
# SQL here is a plain SELECT over an ask_* view and passes the guard.
FALLBACKS: list[dict[str, Any]] = [
    {
        "label": "internet-facing / KEV attack paths",
        "triggers": ["kev", "known exploited", "internet-facing", "internet facing"],
        "sql": (
            "SELECT id, title, severity, exploitability, kev_on_path, length "
            "FROM ask_attack_paths WHERE kev_on_path = true "
            "ORDER BY exploitability DESC NULLS LAST"
        ),
    },
    {
        "label": "highest exploitability attack paths",
        "triggers": ["exploitability", "attack path", "attack paths", "riskiest path"],
        "sql": (
            "SELECT id, title, severity, exploitability, length "
            "FROM ask_attack_paths ORDER BY exploitability DESC NULLS LAST"
        ),
    },
    {
        "label": "assets added this week",
        "triggers": ["added this week", "this week", "recently added", "new assets", "added recently"],
        "sql": (
            "SELECT kind, value, env, first_seen FROM ask_assets "
            "WHERE first_seen >= NOW() - INTERVAL '7 days' "
            "ORDER BY first_seen DESC"
        ),
    },
    {
        "label": "worst TLS findings",
        "triggers": ["tls", "ssl", "certificate", "cipher"],
        "sql": (
            "SELECT asset_value, rule_id, severity, title, cvss "
            "FROM ask_findings "
            "WHERE rule_source IN ('tls_check', 'tls_grade') AND status = 'open' "
            "ORDER BY cvss DESC NULLS LAST"
        ),
    },
    {
        "label": "highest blast-radius assets",
        "triggers": ["blast", "blast radius", "most connected", "crown jewel"],
        "sql": (
            "SELECT kind, value, env, blast_score FROM ask_assets "
            "WHERE blast_score IS NOT NULL ORDER BY blast_score DESC"
        ),
    },
    {
        "label": "exposed secrets and files",
        "triggers": ["secret", "leaked", "exposed file", "exposed files", "credential leak"],
        "sql": (
            "SELECT asset_value, rule_id, rule_source, severity, title "
            "FROM ask_findings "
            "WHERE rule_source IN ('secret_scan', 'exposed_file') AND status = 'open' "
            "ORDER BY severity DESC"
        ),
    },
    {
        "label": "production assets",
        "triggers": ["production", "prod env", "prod assets"],
        "sql": (
            "SELECT kind, value, env, blast_score FROM ask_assets "
            "WHERE env = 'production' ORDER BY blast_score DESC NULLS LAST"
        ),
    },
    {
        "label": "open findings grouped by severity",
        "triggers": ["how many", "count", "by severity", "breakdown", "group by severity"],
        "sql": (
            "SELECT severity, COUNT(*) AS count FROM ask_findings "
            "WHERE status = 'open' GROUP BY severity ORDER BY count DESC"
        ),
    },
    {
        "label": "open critical findings",
        "triggers": ["critical"],
        "sql": (
            "SELECT asset_value, rule_id, rule_source, severity, title, cvss "
            "FROM ask_findings "
            "WHERE severity = 'critical' AND status = 'open' "
            "ORDER BY cvss DESC NULLS LAST"
        ),
    },
    {
        "label": "open high-and-above findings",
        "triggers": ["high severity", "high and above", "severe findings", "top findings", "worst findings"],
        "sql": (
            "SELECT asset_value, rule_id, rule_source, severity, title, cvss "
            "FROM ask_findings "
            "WHERE severity IN ('critical', 'high') AND status = 'open' "
            "ORDER BY cvss DESC NULLS LAST"
        ),
    },
]


def match_intent(question: str) -> dict[str, Any] | None:
    """Return the first fallback whose any trigger appears in the question."""
    q = (question or "").lower()
    for entry in FALLBACKS:
        if any(t in q for t in entry["triggers"]):
            return entry
    return None


async def build_sql(question: str, llm: LLM) -> tuple[str | None, str]:
    """Return (sql, engine). engine is 'llm' when the model produced SQL,
    else 'fallback'. sql is None when nothing could be produced."""
    if llm.is_enabled():
        sql = await llm.nl_to_sql(question, SCHEMA_DESC)
        if sql:
            return sql, "llm"
        # LLM enabled but produced nothing usable — degrade to fallback.
    entry = match_intent(question)
    if entry is not None:
        return entry["sql"], "fallback"
    return None, "fallback"


async def answer(
    db: Database,
    llm: LLM,
    cfg: Config,
    question: str,
    asked_by: str | None = None,
) -> dict[str, Any]:
    sql, engine = await build_sql(question, llm)

    # No SQL could be produced.
    if not sql:
        note = (
            "No SQL could be generated for this question. Without an LLM key "
            "the Ask engine only answers a set of common questions."
        )
        await db.log_nl_query(question, None, engine, False, None, "no_sql", asked_by)
        return {
            "ok": False,
            "reason": "no_sql",
            "generated_sql": None,
            "engine": engine,
            "note": note,
        }

    # Hard guard. NEVER execute unvalidated SQL.
    ok, reason = guard.validate(sql)
    if not ok:
        await db.log_nl_query(question, sql, engine, False, None, reason, asked_by)
        log.warning("ask: rejected generated SQL (engine=%s): %s", engine, reason)
        return {
            "ok": False,
            "reason": reason,
            "generated_sql": sql,
            "engine": engine,
            "note": "The generated query was rejected by the read-only guard.",
        }

    safe_sql = guard.apply_limit(sql, cfg.max_rows)

    # Execute read-only, timed, row-capped.
    try:
        columns, rows = await db.run_readonly_select(
            safe_sql, cfg.stmt_timeout_ms, cfg.max_rows
        )
    except Exception as exc:
        err = f"{type(exc).__name__}: {exc}"
        await db.log_nl_query(question, safe_sql, engine, False, None, err, asked_by)
        log.warning("ask: execution failed: %s", err)
        return {
            "ok": False,
            "reason": "execution_error",
            "generated_sql": safe_sql,
            "engine": engine,
            "note": err,
        }

    await db.log_nl_query(question, safe_sql, engine, True, len(rows), None, asked_by)
    return {
        "ok": True,
        "columns": columns,
        "rows": rows,
        "generated_sql": safe_sql,
        "engine": engine,
        "note": "read-only, validated; executed in a READ ONLY transaction.",
    }
