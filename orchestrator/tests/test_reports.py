"""Reporting: exact metrics, triggers, digest, compliance packs, rendering."""

from __future__ import annotations

import io
import json
import re
import sys
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from app.reports import compliance, digest, metrics, render
from app.reports.brand import HORSE_MARK_PATH

NOW = datetime(2026, 11, 21, 12, 0, tzinfo=timezone.utc)
START = NOW - timedelta(days=7)
D = timedelta(days=1)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


async def _asset(con, value, kind="subdomain", last_seen=NOW, classification="internal"):
    return await con.fetchval(
        """INSERT INTO assets (kind, value, canonical, source, first_seen, last_seen, classification)
           VALUES ($1,$2,$2,'test',$3,$4,$5) RETURNING id""",
        kind,
        value,
        NOW - timedelta(days=60),
        last_seen,
        classification,
    )


async def _finding(
    con,
    asset,
    rule,
    sev,
    first_seen,
    *,
    fixed_at=None,
    status=None,
    last_seen=None,
    team=None,
    sla_due=None,
    classification="internal",
    source="nuclei",
):
    fid = await con.fetchval(
        """INSERT INTO findings (asset_id, rule_id, rule_source, severity, title, description,
                                 first_seen, last_seen, classification)
           VALUES ($1,$2,$3,$4,$2,$2,$5,$5,$6) RETURNING id""",
        asset,
        rule,
        source,
        sev,
        first_seen,
        classification,
    )
    if team or sla_due:
        await con.execute(
            "INSERT INTO tickets (finding_id, title, severity, owner_team, sla_due, opened_at) "
            "VALUES ($1,$2,$3,$4,$5,$6)",
            fid,
            rule,
            sev,
            team,
            sla_due,
            first_seen,
        )
    if status or fixed_at:
        await con.execute(
            "UPDATE findings SET status=$2, last_seen=$3 WHERE id=$1",
            fid,
            status or "fixed",
            last_seen or fixed_at,
        )
        await con.execute(
            "UPDATE finding_resolutions SET resolved_at=$2 WHERE finding_id=$1", fid, fixed_at
        )
    return fid


async def _seed_exact(pool):
    """The worked example in docs/REPORTS.md (window = 7 days ending NOW)."""
    async with pool.acquire() as con:
        a1 = await _asset(con, "a.example")
        a2 = await _asset(con, "b.example")
        ids = {}
        ids["F1"] = await _finding(
            con, a1, "F1", "critical", START - 2 * D, fixed_at=START + D, team="Platform"
        )
        ids["F2"] = await _finding(
            con,
            a1,
            "F2",
            "high",
            START + D / 2,
            fixed_at=START + 2.5 * D,
            last_seen=START + 2.5 * D + timedelta(hours=2),
            team="Web",
            sla_due=START + D / 2 + timedelta(hours=72),
        )
        ids["F3"] = await _finding(con, a2, "F3", "medium", START + 3.25 * D)
        ids["F4"] = await _finding(con, a2, "F4", "high", START - 10 * D)
        ids["F5"] = await _finding(
            con, a2, "F5", "low", START + 5 * D, status="accepted_risk", fixed_at=START + 6 * D
        )
        ids["F6"] = await _finding(
            con, a2, "F6", "critical", START - 9 * D, classification="restricted"
        )
        ids["F7"] = await _finding(con, a1, "F7", "high", START - 3 * D, fixed_at=START - D)
        ids["F8"] = await _finding(con, a2, "F8", "critical", START + 4 * D)
        # attack paths: P1 open before the window, closed inside; P2 opened inside
        for fp in ("P1", "P2"):
            await con.execute(
                """INSERT INTO attack_paths (source_asset_id, target_asset_id, hops, length, total_cost,
                     exploitability, severity, title, fingerprint)
                   VALUES ($1,$2,'[]',2,1,50,'high',$3,$3)""",
                a1,
                a2,
                fp,
            )
        await con.execute(
            "UPDATE attack_path_ledger SET opened_at=$1 WHERE fingerprint='P1'", START - 5 * D
        )
        await con.execute("DELETE FROM attack_paths WHERE fingerprint='P1'")
        await con.execute(
            "UPDATE attack_path_ledger SET closed_at=$1 WHERE fingerprint='P1'", START + 2 * D
        )
        await con.execute(
            "UPDATE attack_path_ledger SET opened_at=$1 WHERE fingerprint='P2'", START + D
        )
    return ids


# --------------------------------------------------------------------------- #
# metrics: exact
# --------------------------------------------------------------------------- #


async def test_metrics_exact(db_pool):
    ids = await _seed_exact(db_pool)
    r = await metrics.build_report(db_pool, days=7, end=NOW, clearance="restricted")

    assert r.window.start == START
    assert [p.value for p in r.exposure.points] == [25, 30, 20, 15, 17, 27, 28, 27]
    assert (r.exposure.start_value, r.exposure.end_value, r.exposure.delta) == (25, 27, 2)
    assert r.exposure.delta_pct == 8.0
    assert r.exposure.open_end == {"critical": 2, "high": 1, "medium": 1, "low": 0, "info": 0}

    nf = r.new_findings
    assert (nf.critical, nf.high, nf.previous_critical_high) == (1, 1, 2)
    assert nf.by_severity == {"critical": 1, "high": 1, "medium": 1, "low": 1, "info": 0}
    assert [f.title for f in nf.top] == ["F8", "F2"]

    rs = r.resolutions
    assert (rs.fixed, rs.verified, rs.regressed, rs.pending_verification) == (2, 1, 1, 0)
    assert rs.accepted_risk == 1

    mt = r.mttr
    assert (
        mt.overall.count == 2 and mt.overall.mean_hours == 60.0 and mt.overall.median_hours == 60.0
    )
    assert [(m.key, m.mean_hours) for m in mt.by_severity] == [("critical", 72.0), ("high", 48.0)]
    assert sorted((m.key, m.median_hours) for m in mt.by_team) == [
        ("Platform", 72.0),
        ("Web", 48.0),
    ]

    sla = r.sla
    assert (sla.met, sla.late, sla.breached_open, sla.overdue_end) == (1, 1, 1, 3)
    assert sla.compliance_pct == 33.3
    bys = {s.severity: s for s in sla.by_severity}
    assert bys["critical"].compliance_pct == 0.0 and bys["high"].compliance_pct == 100.0
    assert bys["critical"].policy_hours == 24
    assert [b.title for b in sla.breaches] == ["F6", "F8", "F4"]
    assert sla.breaches[0].overdue_hours == 15 * 24.0  # due START-8d, window end START+7d

    ap = r.attack_paths
    assert (ap.opened, ap.closed, ap.open_start, ap.open_end) == (1, 1, 1, 1)
    assert ap.top_closed[0].fingerprint == "P1" and ap.top_closed[0].open_days == 7.0

    assert [(a.value, a.score, a.critical) for a in r.risky_assets] == [("b.example", 27, 2)]
    assert any("Exposure rose 8%" in h for h in r.highlights)
    assert ids  # seeded


async def test_metrics_abac_excludes_over_classified(db_pool):
    await _seed_exact(db_pool)
    r = await metrics.build_report(db_pool, days=7, end=NOW, clearance="internal")
    # F6 (restricted critical, weight 10) is invisible at 'internal'
    assert r.exposure.end_value == 17
    assert r.exposure.open_end["critical"] == 1
    assert "F6" not in [b.title for b in r.sla.breaches]


async def test_metrics_empty_db(db_pool):
    r = await metrics.build_report(db_pool, days=30, end=NOW)
    assert len(r.exposure.points) == 31 and r.exposure.end_value == 0
    assert r.sla.compliance_pct is None and r.mttr.overall is None
    assert r.highlights == ["No new critical or high findings."]


def test_parse_period():
    assert metrics.parse_period("7d") == 7
    assert metrics.parse_period("2w") == 14
    assert metrics.parse_period(None) == 30
    for bad in ("0d", "400d", "abc", "7m"):
        with pytest.raises(ValueError):
            metrics.parse_period(bad)


# --------------------------------------------------------------------------- #
# triggers (schema 023)
# --------------------------------------------------------------------------- #


async def test_status_trigger_via_api(client, db_pool):
    async with db_pool.acquire() as con:
        a = await _asset(con, "t.example")
        fid = await _finding(con, a, "T1", "high", NOW - 2 * D)
    assert (await client.patch(f"/v1/findings/{fid}", json={"status": "fixed"})).status_code == 200
    async with db_pool.acquire() as con:
        res = await con.fetchrow(
            "SELECT status, resolved_at FROM finding_resolutions WHERE finding_id=$1", fid
        )
        assert res["status"] == "fixed" and res["resolved_at"] is not None
    assert (await client.patch(f"/v1/findings/{fid}", json={"status": "open"})).status_code == 200
    async with db_pool.acquire() as con:
        assert (
            await con.fetchval("SELECT COUNT(*) FROM finding_resolutions WHERE finding_id=$1", fid)
            == 0
        )
        hist = await con.fetch(
            "SELECT old_status, new_status FROM finding_status_events WHERE finding_id=$1 ORDER BY id",
            fid,
        )
    assert [(h["old_status"], h["new_status"]) for h in hist] == [
        ("open", "fixed"),
        ("fixed", "open"),
    ]


async def test_attack_path_ledger_episodes(db_pool):
    async with db_pool.acquire() as con:
        a = await _asset(con, "p.example")
        ins = """INSERT INTO attack_paths (source_asset_id, target_asset_id, hops, length, total_cost,
                   exploitability, severity, title, fingerprint) VALUES ($1,$1,'[]',1,1,$2,'high','t','fp')
                 ON CONFLICT (tenant_id, fingerprint) DO UPDATE SET exploitability = EXCLUDED.exploitability"""
        await con.execute(ins, a, 10)
        await con.execute(ins, a, 20)  # upsert: same episode, refreshed
        await con.execute("DELETE FROM attack_paths WHERE fingerprint='fp'")
        await con.execute(ins, a, 30)  # reappears: a new episode
        rows = await con.fetch(
            "SELECT exploitability, closed_at FROM attack_path_ledger ORDER BY id"
        )
    assert [float(r["exploitability"]) for r in rows] == [20.0, 30.0]
    assert rows[0]["closed_at"] is not None and rows[1]["closed_at"] is None


# --------------------------------------------------------------------------- #
# API + rendering
# --------------------------------------------------------------------------- #


async def test_executive_json_api(client, db_pool):
    await _seed_exact(db_pool)
    r = await client.get("/v1/reports/executive", params={"period": "7d", "end": NOW.isoformat()})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["exposure"]["end_value"] == 27  # dev principal has restricted clearance
    assert body["sla"]["compliance_pct"] == 33.3
    assert (await client.get("/v1/reports/executive", params={"period": "999d"})).status_code == 422


async def test_executive_html_snapshot_sanity(client, db_pool):
    from tests.reports_seed import seed_demo

    await seed_demo(db_pool, NOW)
    r = await client.get("/v1/reports/executive", params={"format": "html", "end": NOW.isoformat()})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    html = r.text
    assert html.startswith("<!doctype html>")
    assert HORSE_MARK_PATH in html  # the brand mark
    assert "Security posture" in html and "Appendix" in html
    assert html.count("<svg") >= 4  # mark x2 + trend + bars/strip
    assert "src:url(data:font/woff2;base64," in html  # self-contained fonts
    assert "<script" not in html.lower()
    assert re.search(r"(src|href)=\"https?://", html) is None  # no network fetches
    assert "{{" not in html and "{%" not in html
    # every section of the appendix is present
    for sec in (
        "A · New critical",
        "B · Remediation",
        "C · Attack paths",
        "D · Riskiest",
        "E · Surface changes",
        "F · Devices",
        "G · Coverage",
        "H · Definitions",
    ):
        assert sec in html


async def test_executive_pdf_smoke(client, db_pool):
    pypdf = pytest.importorskip("pypdf")
    pytest.importorskip("weasyprint")
    from tests.reports_seed import seed_demo

    await seed_demo(db_pool, NOW)
    r = await client.get(
        "/v1/reports/executive", params={"format": "pdf", "end": NOW.isoformat(), "download": "1"}
    )
    assert r.status_code == 200, r.text[:300]
    assert r.headers["content-type"] == "application/pdf"
    assert "attachment" in r.headers["content-disposition"]
    assert r.content[:5] == b"%PDF-" and r.content.rstrip().endswith(b"%%EOF")
    reader = pypdf.PdfReader(io.BytesIO(r.content))
    assert 2 <= len(reader.pages) <= 8
    first = reader.pages[0].extract_text()
    assert "Security posture" in first and "Exposure index" in first
    assert "Appendix" in reader.pages[1].extract_text()


async def test_pdf_unavailable_is_501(client, monkeypatch):
    def boom(_html):
        raise render.PdfUnavailable("no pango")

    monkeypatch.setattr(render, "html_to_pdf", boom)
    r = await client.get("/v1/reports/executive", params={"format": "pdf"})
    assert r.status_code == 501 and "no pango" in r.json()["detail"]


def test_brand_mark_matches_dashboard():
    ts = Path(__file__).resolve().parents[2] / "dashboard" / "src" / "brand" / "horseFrames.ts"
    if not ts.exists():
        pytest.skip("dashboard sources not present")
    m = re.search(r'HORSE_MARK_PATH =\s*"([^"]+)"', ts.read_text())
    assert m and m.group(1) == HORSE_MARK_PATH


def test_report_rbac_rules():
    from app.auth import required_capability

    assert required_capability("GET", "/v1/reports/executive") == "read"
    assert required_capability("GET", "/v1/reports/compliance/pci-dss-4.0") == "read"
    assert required_capability("POST", "/v1/reports/digest/send") == "admin"


# --------------------------------------------------------------------------- #
# digest
# --------------------------------------------------------------------------- #


@pytest.fixture
def fake_integrations(monkeypatch):
    sent: list = []
    mod = types.ModuleType("app.integrations.service")

    async def emit(pool, event):
        sent.append(event)
        return {"queued": 1}

    mod.emit = emit
    monkeypatch.setitem(sys.modules, "app.integrations.service", mod)
    return sent


def test_current_slot(monkeypatch):
    from app.reports.config import report_settings

    monkeypatch.setattr(report_settings, "digest_weekday", 0)
    monkeypatch.setattr(report_settings, "digest_hour", 8)
    # Sat 21 Nov 2026 12:00 -> Mon 16 Nov 08:00
    assert digest.current_slot(NOW) == datetime(2026, 11, 16, 8, tzinfo=timezone.utc)
    mon = datetime(2026, 11, 23, 7, 59, tzinfo=timezone.utc)
    assert digest.current_slot(mon) == datetime(2026, 11, 16, 8, tzinfo=timezone.utc)
    assert digest.current_slot(mon + timedelta(minutes=1)) == datetime(
        2026, 11, 23, 8, tzinfo=timezone.utc
    )


async def test_digest_emits_once_per_slot(db_pool, fake_integrations, monkeypatch):
    from app.reports.config import report_settings

    await _seed_exact(db_pool)
    monkeypatch.setattr(report_settings, "digest_weekday", NOW.weekday())
    monkeypatch.setattr(report_settings, "digest_hour", 9)
    monkeypatch.setattr(report_settings, "public_url", "https://paddock.example")
    out = await digest.run_due_digests(db_pool, now=NOW)
    assert len(out) == 1 and out[0].status == "emitted"
    assert await digest.run_due_digests(db_pool, now=NOW + timedelta(hours=1)) == []  # idempotent

    (ev,) = fake_integrations
    assert ev.type == "report.digest" and ev.url == "https://paddock.example/reports"
    assert ev.data["period"]["days"] == 7
    assert ev.data["metrics"]["new"]["critical"] == 1
    assert "Paddock weekly digest" in ev.data["text"] and "<table" in ev.data["html"]
    assert "<svg" not in ev.data["html"] and "<script" not in ev.data["html"]
    # digest is built at REPORTS_DIGEST_CLEARANCE=internal: restricted F6 is absent
    assert ev.data["metrics"]["exposure"]["end"] < 27
    async with db_pool.acquire() as con:
        row = await con.fetchrow("SELECT status, event_id, summary FROM report_digests")
    assert row["status"] == "emitted" and row["event_id"] == ev.id
    assert json.loads(row["summary"])["highlights"] == ev.data["highlights"]


async def test_digest_stale_slot_skipped(db_pool, fake_integrations, monkeypatch):
    from app.reports.config import report_settings

    monkeypatch.setattr(report_settings, "digest_weekday", (NOW.weekday() - 3) % 7)
    assert await digest.run_due_digests(db_pool, now=NOW) == []
    assert fake_integrations == []


async def test_digest_without_integrations_records_unavailable(db_pool, monkeypatch):
    monkeypatch.setitem(sys.modules, "app.integrations.service", None)  # import -> ImportError
    res = await digest.send_digest(db_pool, kind="manual", slot=NOW)
    assert res.status == "emit_unavailable"


async def test_digest_send_and_preview_api(client, db_pool, fake_integrations):
    r = await client.post("/v1/reports/digest/send")
    assert r.status_code == 200 and r.json()["status"] == "emitted"
    hist = (await client.get("/v1/reports/digests")).json()
    assert len(hist) == 1
    t = await client.get("/v1/reports/digest/preview", params={"format": "text"})
    assert t.status_code == 200 and t.text.startswith("Paddock weekly digest")


def test_sparkline():
    assert digest.sparkline([0, 7]) == "▁█"
    assert digest.sparkline([3, 3]) == "▄▄"
    assert digest.sparkline([]) == ""


# --------------------------------------------------------------------------- #
# compliance
# --------------------------------------------------------------------------- #

FRAMEWORKS = {"pci-dss-4.0", "nist-csf-2.0", "cis-v8", "iso-27001-2022", "iec-62443-3-3", "eu-cra"}


def test_catalogues_are_well_formed():
    assert set(compliance.framework_ids()) == FRAMEWORKS
    for fw in FRAMEWORKS:
        cat = compliance.load_catalogue(fw)
        ids = [c["id"] for c in cat["controls"]]
        assert len(ids) == len(set(ids)), fw
        assert len(ids) >= 10, fw
        for c in cat["controls"]:
            mode = c.get("mode", "automated")
            assert mode in ("automated", "manual")
            assert c.get("max_status", "satisfied") in ("satisfied", "partial")
            assert c["title"] and c["summary"] and c["rationale"], (fw, c["id"])
            if mode == "manual":
                assert not c["evidence"] and c.get("attestation"), (fw, c["id"])
            else:
                assert c["evidence"], (fw, c["id"])
                for k in c["evidence"]:
                    assert k in compliance.PROVIDERS, (fw, c["id"], k)
            if c.get("max_status") == "partial":
                assert c.get("attestation") or c["rationale"], (fw, c["id"])
    pci = {c["id"]: c for c in compliance.load_catalogue("pci-dss-4.0")["controls"]}
    for must in ("1.3.1", "6.3.1", "6.3.2", "6.3.3", "11.3.1", "11.3.2", "11.4.5"):
        assert must in pci
    # Paddock is not an ASV and doesn't pentest: never fully satisfied
    assert pci["11.3.2"]["max_status"] == "partial" and pci["11.4.5"]["max_status"] == "partial"
    assert pci["11.4.1"]["mode"] == "manual"


def test_control_status_rules():
    cs = compliance.control_status
    assert cs("manual", [], "satisfied") == "requires_attestation"
    assert cs("automated", ["pass", "pass"], "satisfied") == "satisfied"
    assert cs("automated", ["pass", "pass"], "partial") == "partial"
    assert cs("automated", ["pass", "fail"], "satisfied") == "partial"
    assert cs("automated", ["partial"], "satisfied") == "partial"
    assert cs("automated", ["none", "fail"], "satisfied") == "gap"


async def test_empty_install_claims_nothing(db_pool):
    for fw in FRAMEWORKS:
        pack = await compliance.build_pack(db_pool, fw, clearance="restricted", now=NOW)
        assert pack.framework.counts["satisfied"] == 0, fw
        assert pack.framework.counts["partial"] == 0, fw
        manual = sum(1 for c in pack.controls if c.mode == "manual")
        assert pack.framework.counts["requires_attestation"] == manual
        assert pack.framework.counts["gap"] == pack.framework.total - manual


async def _seed_segments(con, *, violation: bool):
    s1 = await _asset(con, "10.0.1.0/24", kind="network_segment", last_seen=NOW - D)
    s2 = await _asset(con, "10.0.2.0/24", kind="network_segment", last_seen=NOW - D)
    await con.execute(
        "INSERT INTO asset_edges (src_id, dst_id, kind) VALUES ($1,$2,'can_reach_observed')", s1, s2
    )
    plc = await _asset(con, "plc-1", kind="ot_device", last_seen=NOW - D)
    if violation:
        await _finding(con, plc, "ot_it_exposure", "high", NOW - 2 * D, source="policy")


async def test_pci_segmentation_mapping(db_pool):
    async with db_pool.acquire() as con:
        await _seed_segments(con, violation=False)
    pack = await compliance.build_pack(db_pool, "pci-dss-4.0", clearance="restricted", now=NOW)
    c = {x.id: x for x in pack.controls}
    ev = {e.key: e for e in c["11.4.5"].evidence}
    assert ev["segmentation_map"].status == "pass"
    assert ev["segmentation_map"].rows == [
        {
            "from": "10.0.1.0/24",
            "to": "10.0.2.0/24",
            "last_seen": ev["segmentation_map"].rows[0]["last_seen"],
        }
    ]
    assert ev["segmentation_violations"].status == "pass"
    assert c["11.4.5"].status == "partial"  # capped: a pentest is still required
    assert c["11.4.5"].attestation
    assert c["6.3.2"].status == "gap"  # no SBOM

    async with db_pool.acquire() as con:
        plc = await con.fetchval("SELECT id FROM assets WHERE value='plc-1'")
        await _finding(con, plc, "ot_it_exposure", "high", NOW - 2 * D, source="policy")
    pack = await compliance.build_pack(db_pool, "pci-dss-4.0", clearance="restricted", now=NOW)
    c = {x.id: x for x in pack.controls}
    viol = next(e for e in c["1.3.1"].evidence if e.key == "segmentation_violations")
    assert viol.status == "fail" and viol.rows[0]["rule_id"] == "ot_it_exposure"
    assert c["1.3.1"].status == "partial"


async def test_sbom_satisfies_inventory_controls(db_pool):
    async with db_pool.acquire() as con:
        pid = await con.fetchval(
            "INSERT INTO sca_projects (name, last_scanned) VALUES ('fw', $1) RETURNING id", NOW - D
        )
        await con.execute(
            "INSERT INTO sbom_components (project_id, ecosystem, name, version) VALUES ($1,'npm','x','1')",
            pid,
        )
    pci = await compliance.build_pack(db_pool, "pci-dss-4.0", now=NOW)
    assert {c.id: c for c in pci.controls}["6.3.2"].status == "satisfied"
    cra = await compliance.build_pack(db_pool, "eu-cra", now=NOW)
    ii1 = {c.id: c for c in cra.controls}["II.1"]
    assert ii1.status == "satisfied"  # SBOM present, no component vulns
    assert {c.id: c for c in cra.controls}["II.5"].status == "requires_attestation"


async def test_compliance_api(client, db_pool):
    r = await client.get("/v1/reports/compliance")
    assert r.status_code == 200
    assert {f["id"] for f in r.json()} == FRAMEWORKS
    r = await client.get("/v1/reports/compliance/iec-62443-3-3")
    assert r.status_code == 200 and any(c["id"] == "SR 5.1" for c in r.json()["controls"])
    h = await client.get("/v1/reports/compliance/pci-dss-4.0", params={"format": "html"})
    assert h.status_code == 200 and "PCI DSS" in h.text and HORSE_MARK_PATH in h.text
    assert (await client.get("/v1/reports/compliance/sox")).status_code == 404
    assert (await client.get("/v1/reports/compliance/..%2Fpci-dss-4.0")).status_code == 404


async def test_compliance_pdf_smoke(client, db_pool):
    pypdf = pytest.importorskip("pypdf")
    pytest.importorskip("weasyprint")
    r = await client.get("/v1/reports/compliance/eu-cra", params={"format": "pdf"})
    assert r.status_code == 200 and r.content[:5] == b"%PDF-"
    reader = pypdf.PdfReader(io.BytesIO(r.content))
    assert len(reader.pages) >= 2
    assert "Cyber Resilience Act" in reader.pages[0].extract_text()
