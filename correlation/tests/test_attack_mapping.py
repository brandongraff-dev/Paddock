"""Tests for the MITRE ATT&CK + CWE mapping engine.

Pure tests (matching, loader, safety gates) run with no infrastructure.
DB-backed tests (catalog upsert, map_findings, coverage) skip cleanly
without TEST_DATABASE_URL / DATABASE_URL.
"""
from __future__ import annotations

import os
import textwrap
import uuid
from pathlib import Path

import pytest

from app.engine.attack_mapping import (
    AttackMapLoader,
    AttackMapper,
    AttackMapRule,
    default_rules_path,
    rule_matches,
    techniques_for_finding,
)

from .conftest import mk_asset, mk_finding


def _builtin_rules_dir() -> str:
    return os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "app", "rules")
    )


def _load_builtin() -> AttackMapLoader:
    loader = AttackMapLoader(default_rules_path(_builtin_rules_dir()))
    loader.load()
    return loader


def _finding(**kw) -> dict:
    base = {
        "id": str(uuid.uuid4()),
        "rule_id": "r",
        "rule_source": "nuclei",
        "title": "",
    }
    base.update(kw)
    return base


def _ids(rules) -> set[str]:
    return {r.technique_id for r in rules}


# ---------------------------------------------------------------------------
# Catalog loads cleanly
# ---------------------------------------------------------------------------

def test_loads_builtin_technique_map():
    loader = _load_builtin()
    assert loader.errors == []
    # ~25 mapping rules, all valid.
    assert 20 <= len(loader.rules) <= 40
    tids = {r.technique_id for r in loader.rules}
    # Real ATT&CK technique ids are present.
    for t in ("T1190", "T1552.001", "T1584.001", "T1557", "T1595",
              "T1195.001", "T1078", "T1530", "T1203"):
        assert t in tids, f"expected {t} in catalog"


def test_catalog_ids_stable_and_unique():
    loader = _load_builtin()
    ids = [r.catalog_id() for r in loader.rules]
    assert len(ids) == len(set(ids))  # unique
    # deterministic across loads
    loader2 = _load_builtin()
    assert ids == [r.catalog_id() for r in loader2.rules]


# ---------------------------------------------------------------------------
# Rule matching per finding type
# ---------------------------------------------------------------------------

def test_exposed_file_dotgit_maps_t1190_cwe527():
    rules = _load_builtin().rules
    f = _finding(rule_source="exposed_file", title="Exposed .git/config directory")
    techs = techniques_for_finding(rules, f)
    by = {t.technique_id: t for t in techs}
    assert "T1190" in by
    assert by["T1190"].cwe == "CWE-527"
    assert by["T1190"].tactic == "Initial Access"


def test_exposed_file_dotenv_maps_credentials():
    rules = _load_builtin().rules
    f = _finding(rule_source="exposed_file", title="Publicly readable .env file")
    by = {t.technique_id: t for t in techniques_for_finding(rules, f)}
    assert "T1552.001" in by
    assert by["T1552.001"].tactic == "Credential Access"


def test_secret_scan_maps_unsecured_credentials():
    rules = _load_builtin().rules
    f = _finding(rule_source="secret_scan", title="Hardcoded credential detected")
    by = {t.technique_id: t for t in techniques_for_finding(rules, f)}
    assert "T1552.001" in by
    assert by["T1552.001"].cwe == "CWE-798"


def test_cve_rce_maps_t1190():
    rules = _load_builtin().rules
    f = _finding(
        rule_source="cve_match",
        title="CVE-2024-1234 Remote Code Execution in Acme",
    )
    by = {t.technique_id: t for t in techniques_for_finding(rules, f)}
    assert "T1190" in by
    assert by["T1190"].cwe == "CWE-94"


def test_cve_generic_maps_t1203_execution():
    rules = _load_builtin().rules
    f = _finding(rule_source="cve_match", title="CVE-2024-9999 info leak in widget")
    by = {t.technique_id: t for t in techniques_for_finding(rules, f)}
    assert "T1203" in by
    assert by["T1203"].tactic == "Execution"


def test_takeover_maps_t1584():
    rules = _load_builtin().rules
    f = _finding(rule_source="takeover", title="Dangling CNAME subdomain takeover")
    by = {t.technique_id: t for t in techniques_for_finding(rules, f)}
    assert "T1584.001" in by
    assert by["T1584.001"].tactic == "Resource Development"


def test_header_and_tls_map_t1557():
    rules = _load_builtin().rules
    csp = _finding(rule_source="header_check", title="Missing Content-Security-Policy header")
    tls = _finding(rule_source="tls_grade", title="TLS grade F")
    csp_by = {t.technique_id: t for t in techniques_for_finding(rules, csp)}
    tls_by = {t.technique_id: t for t in techniques_for_finding(rules, tls)}
    assert csp_by["T1557"].cwe == "CWE-693"
    assert tls_by["T1557"].tactic == "Collection"


def test_nuclei_exposure_maps_reconnaissance():
    rules = _load_builtin().rules
    f = _finding(rule_source="nuclei", title="Git config information disclosure exposure")
    by = {t.technique_id: t for t in techniques_for_finding(rules, f)}
    assert "T1595" in by
    assert by["T1595"].tactic == "Reconnaissance"


def test_nuclei_default_cred_maps_t1078():
    rules = _load_builtin().rules
    f = _finding(rule_source="nuclei", title="Grafana default login admin:admin")
    by = {t.technique_id: t for t in techniques_for_finding(rules, f)}
    assert "T1078" in by
    assert by["T1078"].tactic == "Initial Access"


def test_nuclei_open_datastore_maps_t1530():
    rules = _load_builtin().rules
    f = _finding(rule_source="nuclei", title="Unauthenticated Elasticsearch instance exposed")
    by = {t.technique_id: t for t in techniques_for_finding(rules, f)}
    assert "T1530" in by
    assert by["T1530"].tactic == "Collection"


def test_sca_maps_supply_chain():
    rules = _load_builtin().rules
    f = _finding(rule_source="sca", title="Vulnerable dependency lodash@4.17.11")
    by = {t.technique_id: t for t in techniques_for_finding(rules, f)}
    assert "T1195.001" in by
    assert by["T1195.001"].cwe == "CWE-1104"


# ---------------------------------------------------------------------------
# Multi-technique on one finding + priority
# ---------------------------------------------------------------------------

def test_multi_technique_on_one_finding():
    """An exposed .env containing an api_key tags both the credential-access
    technique and the initial-access exposure technique."""
    rules = _load_builtin().rules
    f = _finding(
        rule_source="exposed_file",
        title="Exposed .env file leaking aws_secret api_key",
    )
    techs = techniques_for_finding(rules, f)
    ids = _ids(techs)
    assert "T1552.001" in ids
    assert "T1190" in ids
    # Two distinct tactics.
    tactics = {t.tactic for t in techs}
    assert {"Credential Access", "Initial Access"} <= tactics


def test_priority_first_rule_per_technique_wins():
    """Two rules target the same technique; the lower-priority one wins and
    the technique is not duplicated."""
    rules = [
        AttackMapRule(
            id="low-pri",
            match={"rule_source": "cve_match"},
            technique_id="T1190",
            technique="Exploit Public-Facing Application",
            tactic="Initial Access",
            cwe="CWE-1",
            priority=5,
        ),
        AttackMapRule(
            id="high-pri",
            match={"rule_source": "cve_match"},
            technique_id="T1190",
            technique="Exploit Public-Facing Application",
            tactic="Initial Access",
            cwe="CWE-2",
            priority=90,
        ),
    ]
    f = _finding(rule_source="cve_match", title="x")
    techs = techniques_for_finding(rules, f)
    assert len(techs) == 1
    assert techs[0].cwe == "CWE-1"  # priority 5 wins


def test_disabled_rule_skipped():
    rules = [
        AttackMapRule(
            id="disabled-rule",
            match={"rule_source": "nuclei"},
            technique_id="T1190",
            technique="Exploit Public-Facing Application",
            tactic="Initial Access",
            enabled=False,
        )
    ]
    assert techniques_for_finding(rules, _finding(rule_source="nuclei")) == []


def test_rule_matches_title_and_source_anded():
    rule = AttackMapRule(
        id="anded",
        match={"rule_source": "nuclei", "title_regex": "(?i)admin"},
        technique_id="T1078",
        technique="Valid Accounts",
        tactic="Initial Access",
    )
    assert rule_matches(rule, _finding(rule_source="nuclei", title="admin panel"))
    # source matches but title does not
    assert not rule_matches(rule, _finding(rule_source="nuclei", title="nope"))
    # title matches but source does not
    assert not rule_matches(rule, _finding(rule_source="cve_match", title="admin"))


# ---------------------------------------------------------------------------
# Safety gates / loader rejection
# ---------------------------------------------------------------------------

def _write(tmp_path: Path, text: str) -> str:
    p = tmp_path / "technique_map.yaml"
    p.write_text(textwrap.dedent(text))
    return str(p)


def test_loader_rejects_forbidden_key(tmp_path):
    path = _write(
        tmp_path,
        """
        rules:
          - id: ok_rule
            match: {rule_source: nuclei}
            technique_id: T1190
            technique: Exploit Public-Facing Application
            tactic: Initial Access
          - id: bad_rule
            match: {rule_source: cve_match}
            technique_id: T1203
            technique: Exploitation for Client Execution
            tactic: Execution
            payload:
              steps: ["do bad things"]
        """,
    )
    loader = AttackMapLoader(path)
    loader.load()
    # forbidden key anywhere rejects the whole file
    assert loader.rules == []
    assert loader.errors and "forbidden key" in loader.errors[0]["error"]


def test_loader_skips_unsafe_narrative_rule(tmp_path):
    path = _write(
        tmp_path,
        """
        rules:
          - id: good_rule
            match: {rule_source: nuclei}
            technique_id: T1190
            technique: Exploit Public-Facing Application
            tactic: Initial Access
          - id: nasty_rule
            match: {rule_source: cve_match}
            technique_id: T1203
            technique: "run reverse shell on the host"
            tactic: Execution
        """,
    )
    loader = AttackMapLoader(path)
    loader.load()
    ids = {r.id for r in loader.rules}
    assert "good_rule" in ids
    assert "nasty_rule" not in ids
    assert loader.errors  # the bad rule was logged


def test_loader_skips_invalid_technique_id(tmp_path):
    path = _write(
        tmp_path,
        """
        rules:
          - id: good_rule
            match: {rule_source: nuclei}
            technique_id: T1190
            technique: Exploit Public-Facing Application
            tactic: Initial Access
          - id: bad_tid
            match: {rule_source: cve_match}
            technique_id: NOTATECH
            technique: Whatever
            tactic: Execution
        """,
    )
    loader = AttackMapLoader(path)
    loader.load()
    ids = {r.id for r in loader.rules}
    assert ids == {"good_rule"}
    assert loader.errors


def test_match_requires_at_least_one_predicate():
    with pytest.raises(Exception):
        AttackMapRule(
            id="empty-match",
            match={},
            technique_id="T1190",
            technique="Exploit Public-Facing Application",
            tactic="Initial Access",
        )


def test_missing_file_reports_error():
    loader = AttackMapLoader("/no/such/technique_map.yaml")
    loader.load()
    assert loader.rules == []
    assert loader.errors


# ---------------------------------------------------------------------------
# DB-backed: catalog upsert, map_findings, coverage (skip without a DB)
# ---------------------------------------------------------------------------

pytestmark_db = pytest.mark.asyncio


async def _clean_attack(db):
    await db.execute("DELETE FROM attack_technique_map")


@pytest.mark.asyncio
async def test_sync_catalog_idempotent(clean_db):
    rules = _load_builtin().rules
    mapper = AttackMapper(clean_db, rules)
    await _clean_attack(clean_db)
    n1 = await mapper.sync_catalog()
    c1 = await clean_db.fetchval("SELECT COUNT(*) FROM attack_technique_map")
    # second sync must not create duplicates
    n2 = await mapper.sync_catalog()
    c2 = await clean_db.fetchval("SELECT COUNT(*) FROM attack_technique_map")
    assert n1 == n2 == len(rules)
    assert c1 == c2 == len(rules)


@pytest.mark.asyncio
async def test_map_findings_writes_techniques(clean_db):
    rules = _load_builtin().rules
    mapper = AttackMapper(clean_db, rules)
    host = await mk_asset(clean_db, "ipv4", "10.9.0.1")
    await mk_finding(
        clean_db, asset_id=host, rule_id="exposed-git",
        rule_source="exposed_file", severity="high",
    )
    # rewrite title so the dotgit rule fires
    await clean_db.execute(
        "UPDATE findings SET title = 'Exposed .git directory' WHERE asset_id = $1::uuid",
        host,
    )
    res = await mapper.map_findings()
    assert res["mapped"] == 1
    rows = await clean_db.fetch(
        "SELECT technique_id, tactic, cwe FROM finding_techniques"
    )
    tids = {r["technique_id"] for r in rows}
    assert "T1190" in tids


@pytest.mark.asyncio
async def test_map_findings_multi_technique_row_count(clean_db):
    rules = _load_builtin().rules
    mapper = AttackMapper(clean_db, rules)
    host = await mk_asset(clean_db, "ipv4", "10.9.0.2")
    fid = await mk_finding(
        clean_db, asset_id=host, rule_id="exposed-env",
        rule_source="exposed_file", severity="high",
    )
    await clean_db.execute(
        "UPDATE findings SET title = 'Exposed .env with aws_secret api_key' "
        "WHERE id = $1::uuid",
        fid,
    )
    await mapper.map_findings()
    rows = await clean_db.fetch(
        "SELECT technique_id FROM finding_techniques WHERE finding_id = $1::uuid",
        fid,
    )
    tids = {r["technique_id"] for r in rows}
    assert {"T1190", "T1552.001"} <= tids


@pytest.mark.asyncio
async def test_map_findings_idempotent(clean_db):
    rules = _load_builtin().rules
    mapper = AttackMapper(clean_db, rules)
    host = await mk_asset(clean_db, "ipv4", "10.9.0.3")
    fid = await mk_finding(
        clean_db, asset_id=host, rule_id="sca-dep", rule_source="sca",
        severity="medium",
    )
    await clean_db.execute(
        "UPDATE findings SET title = 'Vulnerable dependency foo@1.0' WHERE id = $1::uuid",
        fid,
    )
    await mapper.map_findings()
    c1 = await clean_db.fetchval("SELECT COUNT(*) FROM finding_techniques")
    await mapper.map_findings()
    c2 = await clean_db.fetchval("SELECT COUNT(*) FROM finding_techniques")
    assert c1 == c2 >= 1


@pytest.mark.asyncio
async def test_coverage_counts(clean_db):
    rules = _load_builtin().rules
    mapper = AttackMapper(clean_db, rules)
    h1 = await mk_asset(clean_db, "ipv4", "10.9.1.1")
    h2 = await mk_asset(clean_db, "ipv4", "10.9.1.2")
    f1 = await mk_finding(clean_db, asset_id=h1, rule_id="g1", rule_source="exposed_file")
    f2 = await mk_finding(clean_db, asset_id=h2, rule_id="s1", rule_source="secret_scan")
    await clean_db.execute(
        "UPDATE findings SET title = 'Exposed .git directory' WHERE id = $1::uuid", f1
    )
    await clean_db.execute(
        "UPDATE findings SET title = 'leaked secret' WHERE id = $1::uuid", f2
    )
    await mapper.map_findings()
    cov = await mapper.coverage()
    assert cov["total"] == 2
    assert "Initial Access" in cov["by_tactic"]
    assert "Credential Access" in cov["by_tactic"]
    tids = {t["id"] for t in cov["by_technique"]}
    assert "T1190" in tids and "T1552.001" in tids
    for t in cov["by_technique"]:
        assert set(t.keys()) == {"id", "technique", "tactic", "count"}


@pytest.mark.asyncio
async def test_map_finding_single(clean_db):
    rules = _load_builtin().rules
    mapper = AttackMapper(clean_db, rules)
    host = await mk_asset(clean_db, "ipv4", "10.9.2.1")
    fid = await mk_finding(
        clean_db, asset_id=host, rule_id="tk", rule_source="takeover",
    )
    await clean_db.execute(
        "UPDATE findings SET title = 'Subdomain takeover' WHERE id = $1::uuid", fid
    )
    n = await mapper.map_finding(fid)
    assert n >= 1
    rows = await clean_db.fetch(
        "SELECT technique_id FROM finding_techniques WHERE finding_id = $1::uuid", fid
    )
    assert {r["technique_id"] for r in rows} == {"T1584.001"}
