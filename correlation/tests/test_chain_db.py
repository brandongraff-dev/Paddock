"""Chain-firing tests against seeded data."""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

from app.engine.chain import ChainMatcher, PolicyEvaluator
from app.engine.policy import RuleLoader

from .conftest import mk_asset, mk_edge, mk_finding


pytestmark = pytest.mark.asyncio


def _builtin_loader() -> RuleLoader:
    builtin = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "app", "rules")
    )
    loader = RuleLoader(builtin_dir=builtin)
    loader.load_all()
    return loader


async def test_exposed_git_plus_vuln_lib_fires(clean_db):
    host = await mk_asset(clean_db, "ipv4", "10.1.0.1")
    svc = await mk_asset(clean_db, "service", "nginx-g")
    await mk_edge(clean_db, host, svc, "hosts")

    f1 = await mk_finding(
        clean_db,
        asset_id=host,
        rule_id="exposed-dotgit-root",
        rule_source="exposed_file",
        severity="high",
    )
    f2 = await mk_finding(
        clean_db,
        asset_id=host,
        rule_id="cve-2024-9999",
        rule_source="cve_match",
        severity="critical",
        cvss=9.1,
    )

    loader = _builtin_loader()
    matcher = ChainMatcher(clean_db, loader)
    chains = await matcher.match_for_finding(f1)
    ids = {c["chain_rule_id"] for c in chains}
    assert "exposed_git_plus_vuln_lib" in ids
    chain = next(c for c in chains if c["chain_rule_id"] == "exposed_git_plus_vuln_lib")
    assert set(chain["finding_ids"]) == {f1, f2}


async def test_chain_does_not_fire_without_second_finding(clean_db):
    host = await mk_asset(clean_db, "ipv4", "10.1.0.2")
    f1 = await mk_finding(
        clean_db,
        asset_id=host,
        rule_id="exposed-dotgit-root",
        rule_source="exposed_file",
        severity="high",
    )
    loader = _builtin_loader()
    matcher = ChainMatcher(clean_db, loader)
    chains = await matcher.match_for_finding(f1)
    assert all(c["chain_rule_id"] != "exposed_git_plus_vuln_lib" for c in chains)


async def test_chain_respects_window_days(clean_db):
    host = await mk_asset(clean_db, "ipv4", "10.1.0.3")
    stale = datetime.now(timezone.utc) - timedelta(days=200)
    f1 = await mk_finding(
        clean_db,
        asset_id=host,
        rule_id="exposed-dotgit-root",
        rule_source="exposed_file",
        severity="high",
    )
    await mk_finding(
        clean_db,
        asset_id=host,
        rule_id="cve-2020-0001",
        rule_source="cve_match",
        severity="critical",
        cvss=9.0,
        last_seen=stale,
    )

    loader = _builtin_loader()
    matcher = ChainMatcher(clean_db, loader)
    chains = await matcher.match_for_finding(f1)
    assert not any(c["chain_rule_id"] == "exposed_git_plus_vuln_lib" for c in chains)


async def test_chain_cvss_threshold_enforced(clean_db):
    host = await mk_asset(clean_db, "ipv4", "10.1.0.4")
    f1 = await mk_finding(
        clean_db,
        asset_id=host,
        rule_id="exposed-dotgit-root",
        rule_source="exposed_file",
        severity="high",
    )
    await mk_finding(
        clean_db,
        asset_id=host,
        rule_id="cve-2024-lo",
        rule_source="cve_match",
        severity="medium",
        cvss=5.0,
    )
    loader = _builtin_loader()
    matcher = ChainMatcher(clean_db, loader)
    chains = await matcher.match_for_finding(f1)
    assert not any(c["chain_rule_id"] == "exposed_git_plus_vuln_lib" for c in chains)


async def test_kev_on_public_host_fires(clean_db):
    host = await mk_asset(clean_db, "ipv4", "10.1.0.5")
    ep = await mk_asset(clean_db, "endpoint", "https://pub5/")
    await mk_edge(clean_db, host, ep, "resolves_to", metadata={"public": True})
    f = await mk_finding(
        clean_db,
        asset_id=host,
        rule_id="cve-2024-kev",
        rule_source="cve_match",
        severity="critical",
        cvss=9.8,
        metadata={"kev": True},
    )
    loader = _builtin_loader()
    matcher = ChainMatcher(clean_db, loader)
    chains = await matcher.match_for_finding(f)
    assert any(c["chain_rule_id"] == "kev_on_public_host" for c in chains)


async def test_kev_requires_endpoint_asset(clean_db):
    host = await mk_asset(clean_db, "ipv4", "10.1.0.6")  # no endpoint
    f = await mk_finding(
        clean_db,
        asset_id=host,
        rule_id="cve-2024-kev2",
        rule_source="cve_match",
        severity="critical",
        cvss=9.8,
        metadata={"kev": True},
    )
    loader = _builtin_loader()
    matcher = ChainMatcher(clean_db, loader)
    chains = await matcher.match_for_finding(f)
    assert not any(c["chain_rule_id"] == "kev_on_public_host" for c in chains)


async def test_sweep_returns_all_chains(clean_db):
    host = await mk_asset(clean_db, "ipv4", "10.1.0.7")
    await mk_finding(
        clean_db,
        asset_id=host,
        rule_id="exposed-dotgit-root",
        rule_source="exposed_file",
        severity="high",
    )
    await mk_finding(
        clean_db,
        asset_id=host,
        rule_id="cve-2024-sweep",
        rule_source="cve_match",
        severity="critical",
        cvss=8.0,
    )
    loader = _builtin_loader()
    matcher = ChainMatcher(clean_db, loader)
    chains = await matcher.sweep_open_findings()
    assert any(c["chain_rule_id"] == "exposed_git_plus_vuln_lib" for c in chains)


async def test_policy_evaluator_fires_hsts(clean_db):
    ep = await mk_asset(
        clean_db, "endpoint", "https://prod.example.com/",
        metadata={"env": "prod"},
    )
    await mk_finding(
        clean_db,
        asset_id=ep,
        rule_id="header-hsts-missing",
        rule_source="header_check",
        severity="medium",
    )
    loader = _builtin_loader()
    evaluator = PolicyEvaluator(clean_db)
    rule = loader.policies["prod_requires_hsts"]
    payload = await evaluator.evaluate(rule)
    assert len(payload) == 1
    assert payload[0]["asset_id"] == ep
    assert payload[0]["rule_source"] == "policy"
    assert payload[0]["rule_id"] == "prod_requires_hsts"


async def test_policy_evaluator_does_not_fire_when_clean(clean_db):
    await mk_asset(
        clean_db, "endpoint", "https://prod.clean/",
        metadata={"env": "prod"},
    )
    loader = _builtin_loader()
    evaluator = PolicyEvaluator(clean_db)
    rule = loader.policies["prod_requires_hsts"]
    payload = await evaluator.evaluate(rule)
    assert payload == []
