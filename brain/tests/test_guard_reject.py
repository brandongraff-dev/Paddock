"""Guard rejection tests — the safety core. Every injection/escape attempt
must be rejected. These run with no key, no network, no DB."""
from __future__ import annotations

import pytest

from app.guard import validate


@pytest.mark.parametrize("sql", [
    # stacked / multiple statements
    "SELECT * FROM ask_findings; DROP TABLE findings",
    "SELECT 1; SELECT 2",
    "SELECT id FROM ask_assets;; SELECT id FROM ask_findings",
    # bare DDL / DML
    "DROP TABLE findings",
    "TRUNCATE ask_findings",
    "ALTER TABLE findings ADD COLUMN x TEXT",
    "CREATE TABLE evil (id INT)",
    "INSERT INTO ask_findings (id) VALUES ('x')",
    "UPDATE ask_findings SET severity = 'low'",
    "DELETE FROM ask_findings",
    "MERGE INTO ask_findings USING ask_assets ON true WHEN MATCHED THEN DELETE",
    "GRANT SELECT ON findings TO public",
    "COPY ask_findings TO '/tmp/out.csv'",
])
def test_rejects_ddl_dml_and_stacked(sql):
    ok, reason = validate(sql)
    assert ok is False
    assert reason


def test_rejects_union_onto_scope_entries():
    ok, reason = validate(
        "SELECT value FROM ask_assets UNION SELECT token FROM scope_entries"
    )
    assert ok is False


def test_rejects_cte_write():
    ok, reason = validate(
        "WITH w AS (INSERT INTO findings (id) VALUES ('x') RETURNING id) "
        "SELECT * FROM w"
    )
    assert ok is False
    assert "Insert" in reason or "statement" in reason


def test_rejects_select_into():
    ok, _ = validate("SELECT * INTO exfil FROM ask_findings")
    assert ok is False


@pytest.mark.parametrize("sql", [
    "SELECT pg_read_file('/etc/passwd')",
    "SELECT pg_read_binary_file('/etc/shadow')",
    "SELECT pg_ls_dir('/')",
    "SELECT pg_sleep(10)",
    "SELECT * FROM ask_findings WHERE title = (SELECT pg_read_file('/etc/passwd'))",
    "SELECT dblink('host=evil', 'SELECT 1')",
    "SELECT lo_import('/etc/passwd')",
    "SELECT lo_export(1, '/tmp/x')",
    "SELECT set_config('x', 'y', false)",
])
def test_rejects_denied_functions(sql):
    ok, reason = validate(sql)
    assert ok is False
    assert reason


@pytest.mark.parametrize("table", [
    "alert_rules", "scope_entries", "credentials", "findings", "assets",
    "attack_paths", "cves", "nl_queries", "finding_clusters",
    "pg_shadow", "information_schema.tables",
])
def test_rejects_non_ask_tables(table):
    ok, reason = validate(f"SELECT * FROM {table}")
    assert ok is False
    assert "not allowed" in reason or "SELECT" in reason


def test_rejects_subquery_onto_non_ask_table():
    ok, _ = validate(
        "SELECT asset_value FROM ask_findings "
        "WHERE asset_id IN (SELECT id FROM scope_entries)"
    )
    assert ok is False


def test_rejects_join_onto_non_ask_table():
    ok, _ = validate(
        "SELECT a.value FROM ask_assets a JOIN credentials c ON c.asset_id = a.id"
    )
    assert ok is False


def test_rejects_empty():
    ok, reason = validate("   ")
    assert ok is False
    assert reason == "empty query"


def test_rejects_non_select_statement():
    ok, _ = validate("SHOW statement_timeout")
    assert ok is False
