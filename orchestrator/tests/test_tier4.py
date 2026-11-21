"""Tier 4 endpoints: reachability rollup, code findings (SAST), adaptive ML
risk scores, active models, anomalies + ack, and the retrain proxy.

The codeanalysis / mlrisk services own the writes, so we seed `code_findings`,
`ml_risk_scores`, `ml_models`, `anomalies`, and reachability-graded
`sbom_component_vulns` directly and exercise the orchestrator's read/ack surface.

The retrain proxy (`/v1/ml/retrain`) is driven against a dead upstream port and
must DEGRADE to {ok:false, note:...} -- never raise, never 5xx.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.config import settings

# A port nothing listens on: the proxy call gets ECONNREFUSED immediately and
# must degrade gracefully instead of propagating an exception.
_DEAD_URL = "http://127.0.0.1:59999"


# --------------------------------------------------------------------------- #
# Seed helpers
# --------------------------------------------------------------------------- #

async def _mk_asset(con, kind: str, value: str) -> str:
    return str(
        await con.fetchval(
            "INSERT INTO assets (kind, value, canonical, source) "
            "VALUES ($1,$2,$3,'seed') RETURNING id",
            kind,
            value,
            value.lower(),
        )
    )


async def _mk_finding(con, asset_id: str, severity: str, title: str,
                      rule_source: str = "sast") -> str:
    return str(
        await con.fetchval(
            "INSERT INTO findings (asset_id, rule_id, rule_source, severity, "
            "title, description) VALUES ($1,$2,$3,$4,$5,'desc') RETURNING id",
            asset_id,
            f"rule-{title}",
            rule_source,
            severity,
            title,
        )
    )


async def _mk_project(con, *, name: str) -> str:
    return str(
        await con.fetchval(
            "INSERT INTO sca_projects (name) VALUES ($1) RETURNING id", name
        )
    )


async def _mk_component(con, *, project_id: str, ecosystem: str, name: str,
                        version: str) -> str:
    return str(
        await con.fetchval(
            """
            INSERT INTO sbom_components (project_id, ecosystem, name, version)
            VALUES ($1,$2,$3,$4) RETURNING id
            """,
            project_id,
            ecosystem,
            name,
            version,
        )
    )


async def _mk_vuln(con, *, component_id: str, osv_id: str, severity: str,
                   reachability: str = "unknown",
                   reachable_symbol: str | None = None,
                   call_path: list | None = None) -> str:
    return str(
        await con.fetchval(
            """
            INSERT INTO sbom_component_vulns
                (component_id, osv_id, severity, reachability,
                 reachable_symbol, call_path)
            VALUES ($1,$2,$3,$4,$5,$6::jsonb)
            RETURNING id
            """,
            component_id,
            osv_id,
            severity,
            reachability,
            reachable_symbol,
            json.dumps(call_path or []),
        )
    )


async def _mk_code_finding(con, *, project_id: str, rule: str, severity: str,
                           file: str, start_line: int = 1, end_line: int = 1,
                           source: str | None = None, sink: str | None = None,
                           dataflow: list | None = None,
                           cwe: str | None = None, engine: str = "semgrep",
                           message: str = "weakness", finding_id: str | None = None,
                           asset_id: str | None = None) -> str:
    return str(
        await con.fetchval(
            """
            INSERT INTO code_findings
                (project_id, asset_id, finding_id, engine, rule, message,
                 severity, file, start_line, end_line, source, sink,
                 dataflow, cwe)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14)
            RETURNING id
            """,
            project_id,
            asset_id,
            finding_id,
            engine,
            rule,
            message,
            severity,
            file,
            start_line,
            end_line,
            source,
            sink,
            json.dumps(dataflow or []),
            cwe,
        )
    )


async def _mk_risk_score(con, *, finding_id: str, ml_risk: float,
                         model_version: int = 1, features: dict | None = None,
                         rationale: list | None = None) -> str:
    return str(
        await con.fetchval(
            """
            INSERT INTO ml_risk_scores
                (finding_id, ml_risk, model_version, features, rationale)
            VALUES ($1,$2,$3,$4::jsonb,$5::jsonb)
            RETURNING id
            """,
            finding_id,
            ml_risk,
            model_version,
            json.dumps(features or {}),
            json.dumps(rationale or []),
        )
    )


async def _mk_model(con, *, version: int, kind: str, algo: str,
                    n_samples: int = 0, metrics: dict | None = None,
                    feature_importance: dict | None = None,
                    cold_start: bool = True, active: bool = True,
                    notes: str | None = None) -> str:
    return str(
        await con.fetchval(
            """
            INSERT INTO ml_models
                (version, kind, algo, n_samples, metrics, feature_importance,
                 cold_start, active, notes)
            VALUES ($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7,$8,$9)
            RETURNING id
            """,
            version,
            kind,
            algo,
            n_samples,
            json.dumps(metrics or {}),
            json.dumps(feature_importance or {}),
            cold_start,
            active,
            notes,
        )
    )


async def _mk_anomaly(con, *, subject_type: str, subject_label: str,
                      score: float, severity: str = "medium",
                      reason: str = "outlier", features: dict | None = None,
                      model_version: int | None = 1,
                      acknowledged: bool = False,
                      detected_at: datetime | None = None) -> str:
    return str(
        await con.fetchval(
            """
            INSERT INTO anomalies
                (subject_type, subject_label, score, severity, reason,
                 features, model_version, acknowledged, detected_at)
            VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9)
            RETURNING id
            """,
            subject_type,
            subject_label,
            score,
            severity,
            reason,
            json.dumps(features or {}),
            model_version,
            acknowledged,
            detected_at or datetime.now(timezone.utc),
        )
    )


# --------------------------------------------------------------------------- #
# Reachability rollup on /v1/sbom/components
# --------------------------------------------------------------------------- #

async def test_component_reachability_rollup(client, db_pool):
    async with db_pool.acquire() as con:
        pid = await _mk_project(con, name="webapp")
        # worst-case component: mix of unreachable + potential + reachable
        c1 = await _mk_component(con, project_id=pid, ecosystem="npm",
                                 name="lodash", version="4.17.20")
        await _mk_vuln(con, component_id=c1, osv_id="GHSA-r1",
                       severity="high", reachability="reachable",
                       reachable_symbol="lodash.template")
        await _mk_vuln(con, component_id=c1, osv_id="GHSA-r2",
                       severity="low", reachability="potential")
        await _mk_vuln(con, component_id=c1, osv_id="GHSA-r3",
                       severity="medium", reachability="unreachable")
        # a component whose vulns are only unreachable/unknown
        c2 = await _mk_component(con, project_id=pid, ecosystem="npm",
                                 name="left-pad", version="1.0.0")
        await _mk_vuln(con, component_id=c2, osv_id="GHSA-u1",
                       severity="high", reachability="unreachable")
        await _mk_vuln(con, component_id=c2, osv_id="GHSA-u2",
                       severity="low", reachability="unknown")
        # a clean component: no vulns -> null rollup
        await _mk_component(con, project_id=pid, ecosystem="npm",
                            name="clean-pkg", version="1.0.0")

    r = await client.get("/v1/sbom/components", params={"limit": 50})
    assert r.status_code == 200, r.text
    by_name = {c["name"]: c for c in r.json()["items"]}

    assert by_name["lodash"]["reachability"] == "reachable"
    assert by_name["lodash"]["reachable_vuln_count"] == 1
    assert by_name["lodash"]["vuln_count"] == 3

    assert by_name["left-pad"]["reachability"] == "unreachable"
    assert by_name["left-pad"]["reachable_vuln_count"] == 0

    assert by_name["clean-pkg"]["reachability"] is None
    assert by_name["clean-pkg"]["reachable_vuln_count"] == 0


async def test_component_detail_vulns_carry_reachability(client, db_pool):
    async with db_pool.acquire() as con:
        pid = await _mk_project(con, name="webapp")
        cid = await _mk_component(con, project_id=pid, ecosystem="npm",
                                  name="lodash", version="4.17.20")
        await _mk_vuln(con, component_id=cid, osv_id="GHSA-low-reach",
                       severity="low", reachability="reachable",
                       reachable_symbol="lodash.merge",
                       call_path=[{"fn": "app.main"}, {"fn": "lodash.merge"}])
        await _mk_vuln(con, component_id=cid, osv_id="GHSA-high-unreach",
                       severity="high", reachability="unreachable")

    r = await client.get(f"/v1/sbom/components/{cid}")
    assert r.status_code == 200, r.text
    body = r.json()
    # component rollup present on detail too
    assert body["component"]["reachability"] == "reachable"
    assert body["component"]["reachable_vuln_count"] == 1
    # reachable vuln ordered first despite lower severity
    first = body["vulns"][0]
    assert first["osv_id"] == "GHSA-low-reach"
    assert first["reachability"] == "reachable"
    assert first["reachable_symbol"] == "lodash.merge"
    assert first["call_path"] == [{"fn": "app.main"}, {"fn": "lodash.merge"}]
    # the other vuln keeps its fields with defaults
    other = body["vulns"][1]
    assert other["reachability"] == "unreachable"
    assert other["reachable_symbol"] is None
    assert other["call_path"] == []


# --------------------------------------------------------------------------- #
# Code findings (SAST)
# --------------------------------------------------------------------------- #

async def test_code_findings_list_shape(client, db_pool):
    async with db_pool.acquire() as con:
        pid = await _mk_project(con, name="webapp")
        await _mk_code_finding(
            con, project_id=pid, rule="python.sqli", severity="high",
            file="app/db.py", start_line=42, end_line=44,
            source="request.args", sink="cursor.execute",
            dataflow=[{"file": "app/db.py", "line": 40, "note": "tainted"},
                      {"file": "app/db.py", "line": 44, "note": "sink"}],
            cwe="CWE-89",
        )

    r = await client.get("/v1/code-findings", params={"limit": 50, "offset": 0})
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body.keys()) == {"items", "total", "limit", "offset"}
    assert body["total"] == 1
    assert body["limit"] == 50 and body["offset"] == 0
    row = body["items"][0]
    assert row["rule"] == "python.sqli"
    assert row["severity"] == "high"
    assert row["file"] == "app/db.py"
    assert row["start_line"] == 42 and row["end_line"] == 44
    assert row["source"] == "request.args"
    assert row["sink"] == "cursor.execute"
    assert row["cwe"] == "CWE-89"
    assert row["project_id"] == pid
    assert row["project_name"] == "webapp"
    assert len(row["dataflow"]) == 2


async def test_code_findings_filter_project(client, db_pool):
    async with db_pool.acquire() as con:
        pid1 = await _mk_project(con, name="proj-one")
        pid2 = await _mk_project(con, name="proj-two")
        await _mk_code_finding(con, project_id=pid1, rule="r1", severity="low",
                               file="a.py")
        await _mk_code_finding(con, project_id=pid1, rule="r2", severity="low",
                               file="b.py")
        await _mk_code_finding(con, project_id=pid2, rule="r3", severity="low",
                               file="c.py")

    # by uuid
    r = await client.get("/v1/code-findings", params={"project": pid1})
    assert r.status_code == 200, r.text
    assert r.json()["total"] == 2
    # by name
    r2 = await client.get("/v1/code-findings", params={"project": "proj-two"})
    assert r2.status_code == 200, r2.text
    assert r2.json()["total"] == 1
    assert r2.json()["items"][0]["rule"] == "r3"


async def test_code_findings_filter_severity_and_ordering(client, db_pool):
    async with db_pool.acquire() as con:
        pid = await _mk_project(con, name="webapp")
        await _mk_code_finding(con, project_id=pid, rule="low-rule",
                               severity="low", file="a.py")
        await _mk_code_finding(con, project_id=pid, rule="crit-rule",
                               severity="critical", file="b.py")
        await _mk_code_finding(con, project_id=pid, rule="med-rule",
                               severity="medium", file="c.py")

    # severity filter
    r = await client.get("/v1/code-findings", params={"severity": "critical"})
    assert r.status_code == 200, r.text
    assert r.json()["total"] == 1
    assert r.json()["items"][0]["rule"] == "crit-rule"

    # default ordering: highest severity first
    r2 = await client.get("/v1/code-findings")
    assert r2.status_code == 200, r2.text
    rules = [c["rule"] for c in r2.json()["items"]]
    assert rules[0] == "crit-rule"
    assert rules.index("med-rule") < rules.index("low-rule")


async def test_code_findings_detail_with_dataflow(client, db_pool):
    async with db_pool.acquire() as con:
        pid = await _mk_project(con, name="webapp")
        aid = await _mk_asset(con, "repository", "git@example.com:webapp.git")
        fid = await _mk_finding(con, aid, "high", "sast-mirror")
        cfid = await _mk_code_finding(
            con, project_id=pid, rule="python.cmdi", severity="critical",
            file="app/exec.py", start_line=10, end_line=12,
            source="request.form['cmd']", sink="subprocess.run",
            dataflow=[{"file": "app/exec.py", "line": 8, "note": "source"},
                      {"file": "app/exec.py", "line": 10, "note": "propagated"},
                      {"file": "app/exec.py", "line": 12, "note": "sink"}],
            cwe="CWE-78", finding_id=fid, asset_id=aid,
        )

    r = await client.get(f"/v1/code-findings/{cfid}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["id"] == cfid
    assert body["rule"] == "python.cmdi"
    assert body["cwe"] == "CWE-78"
    assert body["finding_id"] == fid
    assert body["asset_id"] == aid
    assert len(body["dataflow"]) == 3
    assert body["dataflow"][0]["note"] == "source"
    assert body["dataflow"][-1]["note"] == "sink"


async def test_code_findings_detail_404(client, db_pool):
    r = await client.get(f"/v1/code-findings/{uuid.uuid4()}")
    assert r.status_code == 404


# --------------------------------------------------------------------------- #
# ML risk scores
# --------------------------------------------------------------------------- #

async def test_ml_risk_ordering_and_rationale(client, db_pool):
    async with db_pool.acquire() as con:
        aid = await _mk_asset(con, "endpoint", "https://app.example.com/x")
        f_hi = await _mk_finding(con, aid, "high", "reachable-dep")
        f_lo = await _mk_finding(con, aid, "low", "quiet-dep")
        await _mk_risk_score(
            con, finding_id=f_lo, ml_risk=21.5, model_version=3,
            rationale=[{"feature": "severity", "contribution": 10.0}],
        )
        await _mk_risk_score(
            con, finding_id=f_hi, ml_risk=88.25, model_version=3,
            rationale=[
                {"feature": "reachable", "contribution": 22.0},
                {"feature": "on_kev_path", "contribution": 18.0},
                {"feature": "prod", "contribution": 10.0},
            ],
        )

    r = await client.get("/v1/ml/risk")
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body.keys()) == {"items", "total", "limit", "offset"}
    assert body["total"] == 2
    # ml_risk DESC
    assert body["items"][0]["finding_id"] == f_hi
    assert abs(body["items"][0]["ml_risk"] - 88.25) < 1e-6
    assert body["items"][0]["model_version"] == 3
    # rationale present + explainable
    rat = body["items"][0]["rationale"]
    assert rat[0] == {"feature": "reachable", "contribution": 22.0}
    assert len(rat) == 3
    # finding + asset summary joined (no N+1)
    assert body["items"][0]["finding"]["title"] == "reachable-dep"
    assert body["items"][0]["finding"]["severity"] == "high"
    assert body["items"][0]["finding"]["rule_source"] == "sast"
    assert body["items"][0]["asset"]["value"] == "https://app.example.com/x"
    assert body["items"][0]["asset"]["kind"] == "endpoint"
    assert body["items"][1]["finding_id"] == f_lo


async def test_ml_risk_paged(client, db_pool):
    async with db_pool.acquire() as con:
        aid = await _mk_asset(con, "endpoint", "https://app.example.com/y")
        for i in range(5):
            fid = await _mk_finding(con, aid, "medium", f"f{i}")
            await _mk_risk_score(con, finding_id=fid, ml_risk=float(i) * 10)

    r = await client.get("/v1/ml/risk", params={"limit": 2, "offset": 0})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 5
    assert len(body["items"]) == 2
    # highest first
    assert body["items"][0]["ml_risk"] >= body["items"][1]["ml_risk"]


# --------------------------------------------------------------------------- #
# Active models
# --------------------------------------------------------------------------- #

async def test_ml_model_active_shape_incl_cold_start(client, db_pool):
    async with db_pool.acquire() as con:
        # two versions of the ranker; only the newest is active
        await _mk_model(con, version=1, kind="risk_ranker",
                        algo="heuristic_prior", cold_start=True, active=False)
        await _mk_model(
            con, version=2, kind="risk_ranker", algo="gradient_boosting",
            n_samples=140, cold_start=False, active=True,
            metrics={"auc": 0.91, "precision_at_10": 0.8},
            feature_importance={"reachable": 0.3, "kev": 0.25},
            notes="trained on analyst triage",
        )
        await _mk_model(
            con, version=1, kind="anomaly_detector", algo="isolation_forest",
            n_samples=60, cold_start=False, active=True,
            feature_importance={"open_ports": 0.4},
        )

    r = await client.get("/v1/ml/model")
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body.keys()) == {"risk_ranker", "anomaly_detector"}
    rr = body["risk_ranker"]
    assert rr["version"] == 2
    assert rr["algo"] == "gradient_boosting"
    assert rr["n_samples"] == 140
    assert rr["cold_start"] is False
    assert rr["metrics"]["auc"] == 0.91
    assert rr["feature_importance"]["reachable"] == 0.3
    ad = body["anomaly_detector"]
    assert ad["algo"] == "isolation_forest"
    assert ad["cold_start"] is False


async def test_ml_model_cold_start_flag(client, db_pool):
    async with db_pool.acquire() as con:
        await _mk_model(con, version=1, kind="risk_ranker",
                        algo="heuristic_prior", n_samples=3, cold_start=True,
                        active=True)

    r = await client.get("/v1/ml/model")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["risk_ranker"]["cold_start"] is True
    assert body["risk_ranker"]["algo"] == "heuristic_prior"
    # no anomaly detector trained yet
    assert body["anomaly_detector"] is None


async def test_ml_model_null_when_none(client, db_pool):
    r = await client.get("/v1/ml/model")
    assert r.status_code == 200, r.text
    assert r.json() == {"risk_ranker": None, "anomaly_detector": None}


# --------------------------------------------------------------------------- #
# Anomalies
# --------------------------------------------------------------------------- #

async def test_anomalies_list_score_desc(client, db_pool):
    async with db_pool.acquire() as con:
        await _mk_anomaly(con, subject_type="host", subject_label="low-host",
                          score=30.0, reason="2 ports")
        await _mk_anomaly(con, subject_type="host", subject_label="hot-host",
                          score=92.5, severity="high",
                          reason="host exposes 6 ports; peer median is 2")
        await _mk_anomaly(con, subject_type="change_velocity",
                          subject_label="repo-x", score=70.0,
                          reason="change velocity 5x baseline")

    r = await client.get("/v1/anomalies")
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body.keys()) == {"items", "total", "limit", "offset"}
    assert body["total"] == 3
    scores = [a["score"] for a in body["items"]]
    assert scores == sorted(scores, reverse=True)
    top = body["items"][0]
    assert top["subject_label"] == "hot-host"
    assert abs(top["score"] - 92.5) < 1e-6
    assert top["reason"] == "host exposes 6 ports; peer median is 2"
    assert top["acknowledged"] is False


async def test_anomalies_filter_acknowledged(client, db_pool):
    async with db_pool.acquire() as con:
        await _mk_anomaly(con, subject_type="host", subject_label="acked",
                          score=50.0, acknowledged=True)
        await _mk_anomaly(con, subject_type="host", subject_label="open",
                          score=60.0, acknowledged=False)

    r = await client.get("/v1/anomalies", params={"acknowledged": "false"})
    assert r.status_code == 200, r.text
    assert r.json()["total"] == 1
    assert r.json()["items"][0]["subject_label"] == "open"

    r2 = await client.get("/v1/anomalies", params={"acknowledged": "true"})
    assert r2.status_code == 200, r2.text
    assert r2.json()["total"] == 1
    assert r2.json()["items"][0]["subject_label"] == "acked"


async def test_anomalies_filter_severity(client, db_pool):
    async with db_pool.acquire() as con:
        await _mk_anomaly(con, subject_type="host", subject_label="h1",
                          score=50.0, severity="high")
        await _mk_anomaly(con, subject_type="host", subject_label="h2",
                          score=40.0, severity="medium")

    r = await client.get("/v1/anomalies", params={"severity": "high"})
    assert r.status_code == 200, r.text
    assert r.json()["total"] == 1
    assert r.json()["items"][0]["subject_label"] == "h1"


async def test_anomaly_ack_flips(client, db_pool):
    async with db_pool.acquire() as con:
        aid = await _mk_anomaly(con, subject_type="host",
                                subject_label="flip-host", score=80.0)

    # starts unacknowledged
    r0 = await client.get("/v1/anomalies", params={"acknowledged": "false"})
    assert r0.json()["total"] == 1

    r = await client.post(f"/v1/anomalies/{aid}/ack")
    assert r.status_code == 200, r.text
    assert r.json()["acknowledged"] is True
    assert r.json()["id"] == aid

    # now excluded from the unacknowledged feed
    r1 = await client.get("/v1/anomalies", params={"acknowledged": "false"})
    assert r1.json()["total"] == 0
    r2 = await client.get("/v1/anomalies", params={"acknowledged": "true"})
    assert r2.json()["total"] == 1


async def test_anomaly_ack_404(client, db_pool):
    r = await client.post(f"/v1/anomalies/{uuid.uuid4()}/ack")
    assert r.status_code == 404


# --------------------------------------------------------------------------- #
# Retrain proxy -- degrade when mlrisk is down
# --------------------------------------------------------------------------- #

async def test_ml_retrain_degrades_when_mlrisk_down(client, monkeypatch):
    monkeypatch.setattr(settings, "mlrisk_url", _DEAD_URL)
    r = await client.post("/v1/ml/retrain", json={})
    # Never a 5xx: degrade cleanly.
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is False
    assert "note" in body and body["note"]
