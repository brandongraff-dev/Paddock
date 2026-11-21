"""Reachability × attack-path fusion tests.

The fusion computation (`compute_fusions`, `build_fusion_chain`, the
severity/scope/fingerprint helpers) is pure, so most behaviour is covered
without a database. A handful of DB-backed tests seed the full
sbom→project→asset + attack_paths graph and exercise bulk loading, upsert,
escalation and stale pruning; they skip cleanly when no TEST_DATABASE_URL /
DATABASE_URL is reachable.
"""
from __future__ import annotations

import uuid

import pytest
import pytest_asyncio

from app.engine.fusion import (
    FUSION_RULE_ID,
    FUSION_TITLE,
    FusionEngine,
    build_fusion_chain,
    compute_fusions,
    descendants,
    escalate_severity,
    fusion_fingerprint,
    host_scope,
    path_hop_finding_ids,
    path_qualifies,
    resolve_host,
    resolve_scopes,
    worst_severity,
)

from .conftest import mk_asset, mk_edge, mk_finding


# ----------------------------------------------------------------------------
# Pure fixtures / builders (no DB)
# ----------------------------------------------------------------------------

def _vuln(
    *,
    project_asset_id="pa",
    osv_id="OSV-1",
    cve_id="CVE-1",
    severity="medium",
    package="requests",
    sca_finding_id="sca-f1",
):
    return {
        "project_asset_id": project_asset_id,
        "osv_id": osv_id,
        "cve_id": cve_id,
        "vuln_severity": severity,
        "package": package,
        "ecosystem": "PyPI",
        "version": "1.0",
        "project_name": "proj",
        "sca_finding_id": sca_finding_id,
    }


def _path(*, fingerprint="fp-1", hop_assets=("ep", "host", "jewel"),
          hop_findings=("hop-f1",), exploit=72.5, length=2, target_kind="technology"):
    hops = []
    for i, aid in enumerate(hop_assets):
        hops.append(
            {
                "asset_id": aid,
                "kind": "endpoint" if i == 0 else "service",
                "value": aid,
                "finding_ids": list(hop_findings) if aid == "host" else [],
            }
        )
    return {
        "id": f"path-{fingerprint}",
        "source_asset_id": hop_assets[0],
        "target_asset_id": hop_assets[-1],
        "hops": hops,
        "length": length,
        "exploitability": exploit,
        "severity": "high",
        "narrative": "neutral",
        "fingerprint": fingerprint,
        "metadata": {"target_kind": target_kind},
    }


# ----------------------------------------------------------------------------
# Pure: severity escalation table
# ----------------------------------------------------------------------------

def test_escalation_table():
    assert escalate_severity("medium") == "high"
    assert escalate_severity("high") == "critical"
    assert escalate_severity("critical") == "critical"
    assert escalate_severity("low") == "medium"
    assert escalate_severity("info") == "low"
    # unknown/empty → never trivial
    assert escalate_severity(None) == "high"
    assert escalate_severity("bogus") == "high"


def test_worst_severity_picks_highest():
    assert worst_severity(["low", "critical", "medium"]) == "critical"
    assert worst_severity(["medium", "high"]) == "high"
    assert worst_severity([]) == "medium"


# ----------------------------------------------------------------------------
# Pure: fingerprint + path helpers
# ----------------------------------------------------------------------------

def test_fingerprint_stable_and_distinct():
    a = fusion_fingerprint("host-1", "pathfp-1")
    b = fusion_fingerprint("host-1", "pathfp-1")
    c = fusion_fingerprint("host-2", "pathfp-1")
    d = fusion_fingerprint("host-1", "pathfp-2")
    assert a == b
    assert a != c and a != d and c != d


def test_path_qualifies_and_hop_findings():
    p = _path()
    assert path_qualifies(p) is True
    assert path_qualifies({"source_asset_id": None, "hops": []}) is False
    assert path_hop_finding_ids(p) == ["hop-f1"]


# ----------------------------------------------------------------------------
# Pure: host scope resolution over in-memory adjacency
# ----------------------------------------------------------------------------

def test_resolve_host_walks_incoming_to_host_kind():
    kinds = {"repo": "repository", "host": "ipv4", "ep": "endpoint"}
    # host --runs--> repo  (repo's incoming edge is the host)
    in_adj = {"repo": {"host"}}
    assert resolve_host("repo", kinds, in_adj) == "host"
    # an asset that is itself host-like is its own host
    assert resolve_host("host", kinds, in_adj) == "host"
    # no host ancestor → None
    assert resolve_host("repo", {"repo": "repository"}, {}) is None


def test_host_scope_is_host_plus_descendants_plus_asset():
    kinds = {"repo": "repository", "host": "ipv4", "svc": "service"}
    in_adj = {"repo": {"host"}, "svc": {"host"}}
    out_adj = {"host": {"repo", "svc"}}
    anchor, scope = host_scope("repo", kinds, in_adj, out_adj)
    assert anchor == "host"
    assert scope == {"host", "repo", "svc"}


def test_descendants_follows_outgoing_only():
    out_adj = {"a": {"b"}, "b": {"c"}}
    assert descendants("a", out_adj) == {"a", "b", "c"}
    assert descendants("c", out_adj) == {"c"}


def test_resolve_scopes_falls_back_to_asset_when_no_host():
    kinds = {"repo": "repository"}
    scopes = resolve_scopes(["repo"], kinds, {}, {})
    assert scopes["repo"]["host"] == "repo"  # fallback anchor is the asset
    assert scopes["repo"]["scope"] == {"repo"}


# ----------------------------------------------------------------------------
# Pure: compute_fusions
# ----------------------------------------------------------------------------

def test_reachable_vuln_on_path_produces_escalated_chain():
    reachable = [_vuln(severity="medium")]
    paths = [_path(hop_assets=("ep", "host", "jewel"))]
    scope = {"pa": {"host": "host", "scope": {"host", "pa"}}}
    chains = compute_fusions(reachable, paths, scope)
    assert len(chains) == 1
    c = chains[0]
    assert c["chain_rule_id"] == FUSION_RULE_ID
    assert c["title"] == FUSION_TITLE
    # medium underlying → escalated to high
    assert c["severity"] == "high"
    assert c["anchor_asset_id"] == "host"
    # finding_ids merge the sca finding with the path's hop findings
    assert c["finding_ids"] == sorted({"sca-f1", "hop-f1"})
    # blast radius comes from the path exploitability
    assert c["blast_radius_score"] == 72.5
    assert c["metadata"]["underlying_severity"] == "medium"
    assert c["metadata"]["escalated_severity"] == "high"


def test_high_vuln_escalates_to_critical():
    reachable = [_vuln(severity="high")]
    paths = [_path()]
    scope = {"pa": {"host": "host", "scope": {"host", "pa"}}}
    chains = compute_fusions(reachable, paths, scope)
    assert chains[0]["severity"] == "critical"


def test_reachable_vuln_not_on_any_path_no_chain():
    reachable = [_vuln()]
    # path runs through host2, which is not in the project's scope
    paths = [_path(hop_assets=("ep", "host2", "jewel"))]
    scope = {"pa": {"host": "host", "scope": {"host", "pa"}}}
    assert compute_fusions(reachable, paths, scope) == []


def test_no_paths_no_chain():
    assert compute_fusions([_vuln()], [], {"pa": {"host": "h", "scope": {"h"}}}) == []


def test_reachable_vuln_without_sca_finding_skipped():
    # A reachable vuln with no resolvable open sca finding cannot anchor the
    # "reachable in code" half of the chain → no fusion.
    reachable = [_vuln(sca_finding_id=None)]
    paths = [_path()]
    scope = {"pa": {"host": "host", "scope": {"host", "pa"}}}
    assert compute_fusions(reachable, paths, scope) == []


def test_multiple_vulns_same_host_and_path_group_into_one_chain():
    reachable = [
        _vuln(osv_id="OSV-1", package="requests", severity="medium", sca_finding_id="sca-a"),
        _vuln(osv_id="OSV-2", package="urllib3", severity="high", sca_finding_id="sca-b"),
    ]
    paths = [_path()]
    scope = {"pa": {"host": "host", "scope": {"host", "pa"}}}
    chains = compute_fusions(reachable, paths, scope)
    assert len(chains) == 1
    c = chains[0]
    # worst underlying is high → escalated to critical
    assert c["severity"] == "critical"
    assert set(c["metadata"]["packages"]) == {"requests", "urllib3"}
    assert {"sca-a", "sca-b"}.issubset(set(c["finding_ids"]))


def test_compute_is_deterministic():
    reachable = [_vuln(project_asset_id="pa")]
    paths = [_path(fingerprint="fp-a"), _path(fingerprint="fp-b")]
    scope = {"pa": {"host": "host", "scope": {"host", "pa"}}}
    c1 = compute_fusions(reachable, paths, scope)
    c2 = compute_fusions(reachable, paths, scope)
    assert [c["fingerprint"] for c in c1] == [c["fingerprint"] for c in c2]
    assert [c["fingerprint"] for c in c1] == sorted(c["fingerprint"] for c in c1)


# ----------------------------------------------------------------------------
# Pure: narrative safety guard
# ----------------------------------------------------------------------------

def test_narrative_guard_fallback_on_unsafe_package_name():
    # A package name that reads like exploitation guidance must force the
    # neutral fallback narrative (same guard as the other narratives).
    path = _path()
    contributing = [_vuln(package="evil reverse shell kit")]
    c = build_fusion_chain("host-1", path, contributing)
    narrative = c["impact_narrative"].lower()
    assert "reverse shell" not in narrative
    # fallback still conveys the compound risk
    assert "reachable" in narrative
    assert "crown-jewel" in narrative


def test_narrative_clean_keeps_package_names():
    path = _path()
    contributing = [_vuln(package="requests")]
    c = build_fusion_chain("host-1", path, contributing)
    assert "requests" in c["impact_narrative"]
    assert "reachable in" in c["impact_narrative"].lower()


# ----------------------------------------------------------------------------
# DB-backed (skipped without a reachable Postgres)
# ----------------------------------------------------------------------------

async def _seed_sca_project(db, asset_id, name="proj"):
    pid = str(uuid.uuid4())
    await db.execute(
        "INSERT INTO sca_projects (id, name, asset_id) VALUES ($1::uuid, $2, $3::uuid)",
        pid, name, asset_id,
    )
    return pid


async def _seed_component(db, project_id, *, ecosystem="PyPI", name="requests", version="1.0"):
    cid = str(uuid.uuid4())
    await db.execute(
        """
        INSERT INTO sbom_components (id, project_id, ecosystem, name, version)
        VALUES ($1::uuid, $2::uuid, $3, $4, $5)
        """,
        cid, project_id, ecosystem, name, version,
    )
    return cid


async def _seed_vuln(db, component_id, *, reachability="reachable", severity="medium",
                     osv_id="OSV-TEST-1", cve_id="CVE-TEST-1"):
    vid = str(uuid.uuid4())
    await db.execute(
        """
        INSERT INTO sbom_component_vulns
          (id, component_id, osv_id, cve_id, severity, reachability)
        VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6)
        """,
        vid, component_id, osv_id, cve_id, severity, reachability,
    )
    return vid


async def _seed_attack_path(db, source, target, hop_assets, *, hop_findings,
                            exploit=72.5, fingerprint="fp-db-1", severity="high"):
    pid = str(uuid.uuid4())
    hops = []
    for i, aid in enumerate(hop_assets):
        hops.append(
            {
                "asset_id": aid,
                "kind": "service",
                "value": aid,
                "finding_ids": hop_findings if i == len(hop_assets) - 1 else [],
            }
        )
    # NB: the Database jsonb codec encodes Python objects, so pass the list /
    # dict directly here — json.dumps would double-encode into a JSON string.
    await db.execute(
        """
        INSERT INTO attack_paths
          (id, source_asset_id, target_asset_id, hops, length, total_cost,
           exploitability, severity, title, fingerprint, metadata)
        VALUES ($1::uuid, $2::uuid, $3::uuid, $4::jsonb, $5, $6::numeric,
                $7::numeric, $8, $9, $10, $11::jsonb)
        """,
        pid, source, target,
        hops,
        len(hop_assets) - 1, 10.0, exploit, severity,
        "src -> tgt", fingerprint,
        {"target_kind": "technology"},
    )
    return pid


@pytest_asyncio.fixture
async def fusion_db(db):
    async with db.acquire() as conn:
        await conn.execute(
            "TRUNCATE finding_chains, attack_paths, sbom_component_vulns, "
            "sbom_components, sca_projects, findings, asset_edges, assets "
            "RESTART IDENTITY CASCADE"
        )
    yield db


async def _seed_fuseable(db, *, reachability="reachable", vuln_severity="medium",
                         path_through_host=True):
    """Seed a repo deployed on a host that sits on an internet-facing path to
    a crown jewel, plus a dependency vuln + its sca finding. Returns ids."""
    host = await mk_asset(db, "ipv4", "203.0.113.5")
    repo = await mk_asset(db, "repository", "myapp")
    ep = await mk_asset(db, "endpoint", "https://app.example.com/")
    jewel = await mk_asset(db, "technology", "PostgreSQL 15")
    other = await mk_asset(db, "ipv4", "10.9.9.9")  # off-path host
    # host runs the repo => host_of(repo)=host, and the host's same-host scope
    # is {host, repo}. The crown jewel is deliberately NOT a same-host asset,
    # so a path only fuses when the HOST itself is one of its hops.
    await mk_edge(db, host, repo, "runs")
    # the endpoint resolves to the host (internet-facing front door)
    await mk_edge(db, ep, host, "resolves_to")

    project = await _seed_sca_project(db, repo)
    comp = await _seed_component(db, project, ecosystem="PyPI", name="requests")
    await _seed_vuln(db, comp, reachability=reachability, severity=vuln_severity)

    # the unified sca finding mirroring the component (rule_id = sca:eco:name)
    sca_fid = await mk_finding(
        db, asset_id=repo, rule_id="sca:PyPI:requests", rule_source="sca",
        severity=vuln_severity,
    )
    # a finding recorded on a path hop (merged into the chain's finding_ids)
    hop_fid = await mk_finding(
        db, asset_id=jewel, rule_id="cve-hop", rule_source="cve_match",
        severity="high",
    )

    on_path_host = host if path_through_host else other
    await _seed_attack_path(
        db, ep, jewel, [ep, on_path_host, jewel], hop_findings=[hop_fid],
    )
    return {
        "host": host, "repo": repo, "ep": ep, "jewel": jewel,
        "sca_fid": sca_fid, "hop_fid": hop_fid,
    }


@pytest.mark.asyncio
async def test_db_reachable_on_path_fuses_with_escalation(fusion_db):
    ids = await _seed_fuseable(fusion_db, reachability="reachable", vuln_severity="medium")
    eng = FusionEngine(fusion_db)
    res = await eng.run()
    assert res["computed"] == 1
    assert res["inserted"] == 1

    row = await fusion_db.fetchrow(
        "SELECT chain_rule_id, severity, title, anchor_asset_id::text AS anchor, "
        "blast_radius_score, finding_ids, metadata, impact_narrative "
        "FROM finding_chains WHERE chain_rule_id = $1",
        FUSION_RULE_ID,
    )
    assert row["chain_rule_id"] == FUSION_RULE_ID
    assert row["severity"] == "high"          # medium escalated one step
    assert row["title"] == FUSION_TITLE
    assert row["anchor"] == ids["host"]       # anchor is the host
    assert float(row["blast_radius_score"]) == 72.5  # from the path
    fids = {str(f) for f in row["finding_ids"]}
    assert ids["sca_fid"] in fids and ids["hop_fid"] in fids
    assert "reachable" in row["impact_narrative"].lower()


@pytest.mark.asyncio
async def test_db_reachable_not_on_path_no_chain(fusion_db):
    await _seed_fuseable(fusion_db, reachability="reachable", path_through_host=False)
    eng = FusionEngine(fusion_db)
    res = await eng.run()
    assert res["computed"] == 0
    assert await eng.count() == 0


@pytest.mark.asyncio
async def test_db_on_path_but_not_reachable_no_chain(fusion_db):
    # host is on the path, but the dependency vuln is only 'potential'
    await _seed_fuseable(fusion_db, reachability="potential")
    eng = FusionEngine(fusion_db)
    res = await eng.run()
    assert res["computed"] == 0
    assert await eng.count() == 0


@pytest.mark.asyncio
async def test_db_idempotent_upsert(fusion_db):
    await _seed_fuseable(fusion_db)
    eng = FusionEngine(fusion_db)
    r1 = await eng.run()
    r2 = await eng.run()
    assert r1["inserted"] == 1
    assert r2["inserted"] == 0  # same fingerprint re-upserts in place
    assert await eng.count() == 1


@pytest.mark.asyncio
async def test_db_stale_fusion_pruned_without_touching_other_chains(fusion_db):
    ids = await _seed_fuseable(fusion_db)
    # A chain from a DIFFERENT rule must survive fusion pruning.
    await fusion_db.execute(
        """
        INSERT INTO finding_chains
          (chain_rule_id, severity, title, description, finding_ids, anchor_asset_id, metadata)
        VALUES ('git_exposed_plus_outdated', 'high', 't', 'd', $1::uuid[], $2::uuid, '{}'::jsonb)
        """,
        [ids["sca_fid"]], ids["host"],
    )
    eng = FusionEngine(fusion_db)
    await eng.run()
    assert await eng.count() == 1

    # Remove the attack path → the fusion no longer holds → it is pruned,
    # but the other-rule chain stays.
    await fusion_db.execute("DELETE FROM attack_paths")
    res = await eng.run()
    assert res["computed"] == 0
    assert await eng.count() == 0
    survivors = await fusion_db.fetch(
        "SELECT chain_rule_id FROM finding_chains"
    )
    assert [r["chain_rule_id"] for r in survivors] == ["git_exposed_plus_outdated"]


@pytest.mark.asyncio
async def test_db_publishes_chain_detected_for_new(fusion_db):
    await _seed_fuseable(fusion_db)

    published: list[dict] = []

    class _FakeRedis:
        async def xadd(self, stream, fields):
            published.append(fields)
            return "1-0"

    eng = FusionEngine(fusion_db, redis=_FakeRedis())
    await eng.run()
    assert len(published) == 1
    payload = __import__("json").loads(published[0]["event"])
    assert payload["event"] == "chain_detected"
    assert payload["chain_rule_id"] == FUSION_RULE_ID
    assert payload["severity"] == "high"

    # second run inserts nothing new → no new event
    published.clear()
    await eng.run()
    assert published == []
