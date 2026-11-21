"""Tests for the YAML DSL loader and its safety gates."""
from __future__ import annotations

import os
import textwrap
from pathlib import Path

import pytest

from app.engine.policy import (
    ChainRule,
    PolicyRule,
    RuleLoader,
    UnsafeRuleError,
    validate_narrative_text,
    validate_sql,
)


def _mkrule(tmp_path: Path, sub: str, name: str, text: str) -> Path:
    d = tmp_path / sub
    d.mkdir(parents=True, exist_ok=True)
    p = d / name
    p.write_text(textwrap.dedent(text))
    return p


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_loader_loads_builtin_rules():
    builtin = os.path.join(
        os.path.dirname(__file__), "..", "app", "rules"
    )
    builtin = os.path.abspath(builtin)
    loader = RuleLoader(builtin_dir=builtin)
    loader.load_all()
    assert "exposed_git_plus_vuln_lib" in loader.chains
    assert "leaked_secret_live_endpoint" in loader.chains
    assert "outdated_tls_plus_sensitive_endpoint" in loader.chains
    assert "open_admin_plus_default_tech" in loader.chains
    assert "kev_on_public_host" in loader.chains
    assert "prod_requires_hsts" in loader.policies
    assert "no_public_dev" in loader.policies
    assert "cert_expiry_30d" in loader.policies
    assert loader.errors == []


def test_summary_shape():
    builtin = os.path.join(
        os.path.dirname(__file__), "..", "app", "rules"
    )
    loader = RuleLoader(builtin_dir=os.path.abspath(builtin))
    loader.load_all()
    s = loader.summary()
    assert "chains" in s and "policies" in s and "errors" in s
    assert all({"id", "name", "severity", "source"} <= set(c.keys()) for c in s["chains"])


# ---------------------------------------------------------------------------
# Safety: forbidden keys
# ---------------------------------------------------------------------------

def test_rejects_forbidden_key_exploit(tmp_path):
    _mkrule(
        tmp_path,
        "chains",
        "bad.yaml",
        """
        id: bad_one
        name: Bad rule
        severity: high
        all_of:
          - finding: {rule_source: nuclei}
            scope: same_host
          - finding: {rule_source: cve_match}
            scope: same_host
        exploit:
          steps:
            - do bad things
        """,
    )
    loader = RuleLoader(overlay_dir=str(tmp_path))
    loader.load_all()
    assert loader.chains == {}
    assert loader.errors and "forbidden key" in loader.errors[0]["error"]


@pytest.mark.parametrize(
    "forbidden_key",
    ["payload", "shell", "cmd", "injection_string", "reverse_shell"],
)
def test_rejects_other_forbidden_keys(tmp_path, forbidden_key):
    _mkrule(
        tmp_path,
        "chains",
        f"bad_{forbidden_key}.yaml",
        f"""
        id: bad_{forbidden_key.replace('_', '-')}
        name: Bad
        severity: high
        all_of:
          - finding: {{rule_source: nuclei}}
            scope: same_host
          - finding: {{rule_source: cve_match}}
            scope: same_host
        {forbidden_key}: nope
        """,
    )
    loader = RuleLoader(overlay_dir=str(tmp_path))
    loader.load_all()
    assert loader.chains == {}
    assert loader.errors


def test_rejects_exploit_text_in_impact(tmp_path):
    _mkrule(
        tmp_path,
        "chains",
        "bad_impact.yaml",
        """
        id: bad_impact
        name: Bad
        severity: high
        all_of:
          - finding: {rule_source: nuclei}
            scope: same_host
          - finding: {rule_source: cve_match}
            scope: same_host
        impact: |
          To exploit this, run: curl -X POST http://...
        """,
    )
    loader = RuleLoader(overlay_dir=str(tmp_path))
    loader.load_all()
    assert "bad_impact" not in loader.chains
    assert loader.errors


def test_narrative_validator_catches_shell():
    with pytest.raises(UnsafeRuleError):
        validate_narrative_text("Then run bash -c 'rm -rf /' on the host.")


def test_narrative_validator_allows_descriptive_text():
    validate_narrative_text(
        "An attacker could gain code execution on the host, "
        "leading to data disclosure."
    )  # no exception


# ---------------------------------------------------------------------------
# Safety: SQL
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "sql",
    [
        "DROP TABLE findings",
        "INSERT INTO assets (kind, value, canonical, source) VALUES ('org', 'x', 'x', 't')",
        "UPDATE findings SET status = 'fixed' WHERE id IS NOT NULL",
        "DELETE FROM findings",
        "TRUNCATE assets",
        "ALTER TABLE findings ADD COLUMN x TEXT",
        "CREATE TABLE evil (id INT)",
        "SELECT 1; DROP TABLE findings",
    ],
)
def test_validate_sql_rejects_ddl_dml(sql):
    with pytest.raises(UnsafeRuleError):
        validate_sql(sql)


def test_validate_sql_accepts_plain_select():
    validate_sql("SELECT id FROM assets WHERE kind = 'endpoint'")


def test_validate_sql_accepts_cte_select():
    validate_sql(
        "WITH recent AS (SELECT * FROM findings) "
        "SELECT asset_id AS id FROM recent"
    )


def test_policy_loader_rejects_ddl_in_query(tmp_path):
    _mkrule(
        tmp_path,
        "policies",
        "bad_policy.yaml",
        """
        id: bad_policy
        name: Bad
        severity: medium
        query: |
          DROP TABLE findings
        on_hit:
          create_finding: {title: x}
        """,
    )
    loader = RuleLoader(overlay_dir=str(tmp_path))
    loader.load_all()
    assert "bad_policy" not in loader.policies
    assert loader.errors


def test_policy_loader_rejects_multi_statement(tmp_path):
    _mkrule(
        tmp_path,
        "policies",
        "multi.yaml",
        """
        id: multi_stmt
        name: Multi
        severity: medium
        query: |
          SELECT id FROM assets; DELETE FROM findings
        on_hit:
          create_finding: {title: x}
        """,
    )
    loader = RuleLoader(overlay_dir=str(tmp_path))
    loader.load_all()
    assert "multi_stmt" not in loader.policies


# ---------------------------------------------------------------------------
# Overlay semantics
# ---------------------------------------------------------------------------

def test_overlay_replaces_builtin(tmp_path):
    builtin = tmp_path / "builtin"
    overlay = tmp_path / "overlay"
    (builtin / "chains").mkdir(parents=True)
    (overlay / "chains").mkdir(parents=True)
    (builtin / "chains" / "x.yaml").write_text(
        textwrap.dedent(
            """
            id: shared
            name: builtin
            severity: low
            all_of:
              - finding: {rule_source: nuclei}
                scope: same_host
              - finding: {rule_source: cve_match}
                scope: same_host
            """
        )
    )
    (overlay / "chains" / "x.yaml").write_text(
        textwrap.dedent(
            """
            id: shared
            name: overlayed
            severity: high
            all_of:
              - finding: {rule_source: nuclei}
                scope: same_host
              - finding: {rule_source: cve_match}
                scope: same_host
            """
        )
    )
    loader = RuleLoader(builtin_dir=str(builtin), overlay_dir=str(overlay))
    loader.load_all()
    assert loader.chains["shared"].name == "overlayed"
    assert loader.chains["shared"].severity == "high"


def test_invalid_regex_rejected(tmp_path):
    _mkrule(
        tmp_path,
        "chains",
        "regex.yaml",
        """
        id: bad_regex
        name: Bad regex
        severity: medium
        all_of:
          - finding: {rule_id_match: "["}
            scope: same_host
          - finding: {rule_source: cve_match}
            scope: same_host
        """,
    )
    loader = RuleLoader(overlay_dir=str(tmp_path))
    loader.load_all()
    assert "bad_regex" not in loader.chains
    assert loader.errors
