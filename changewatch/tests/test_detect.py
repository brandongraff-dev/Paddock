"""Detection tests against seeded data (skip without a test DB)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.config import Config
from app.detect import ChangeDetector

from .conftest import mk_asset, mk_edge, mk_finding

pytestmark = pytest.mark.asyncio


def _cfg() -> Config:
    return Config()


def _by_type(rows):
    out: dict[str, list] = {}
    for r in rows:
        out.setdefault(r["change_type"], []).append(r)
    return out


async def test_each_change_type_produced_with_severity(clean_db):
    now = datetime.now(timezone.utc)
    cursor = now - timedelta(hours=1)
    before = now - timedelta(hours=2)        # pre-cursor: must be ignored
    stale_ts = now - timedelta(days=10)      # older than the 7d stale window

    # --- new assets (first_seen > cursor), one per mapped kind -------------
    await mk_asset(clean_db, "subdomain", "new.example.com", first_seen=now)
    await mk_asset(clean_db, "endpoint", "https://new.example.com/app", first_seen=now)
    await mk_asset(clean_db, "ipv4", "203.0.113.9", first_seen=now)
    await mk_asset(clean_db, "technology", "nginx 1.18", first_seen=now)
    await mk_asset(clean_db, "certificate", "cert:new-leaf", first_seen=now)
    await mk_asset(clean_db, "secret_candidate", "aws-key-leak", first_seen=now)
    await mk_asset(clean_db, "repository", "github.com/acme/app", first_seen=now)

    # pre-cursor asset — should NOT be detected as new.
    await mk_asset(clean_db, "subdomain", "old.example.com", first_seen=before)

    # --- new + resolved findings ------------------------------------------
    host = await mk_asset(clean_db, "service", "api-service", first_seen=before, last_seen=now)
    await mk_finding(clean_db, host, "cve-2024-0001", severity="critical", first_seen=now)
    await mk_finding(
        clean_db, host, "cve-2023-9999", severity="medium",
        status="fixed", first_seen=before, last_seen=now,
    )

    # --- stale asset (asset_removed) --------------------------------------
    await mk_asset(clean_db, "service", "ghost-service",
                   first_seen=stale_ts, last_seen=stale_ts)

    # --- expiring cert (cert_expiring) ------------------------------------
    not_after = (now + timedelta(days=10)).isoformat()
    await mk_asset(clean_db, "certificate", "cert:expiring-soon",
                   metadata={"not_after": not_after},
                   first_seen=before, last_seen=now)

    # --- exposure increased (host gained a new open port) ------------------
    exposed_host = await mk_asset(clean_db, "subdomain", "exposed.example.com",
                                  first_seen=before, last_seen=now)
    port = await mk_asset(clean_db, "port", "443/tcp", first_seen=now)
    await mk_edge(clean_db, exposed_host, port, "hosts", first_seen=now)

    det = ChangeDetector(clean_db, _cfg())
    rows = await det.run(cursor)
    by_type = _by_type(rows)

    expected_sev = {
        "subdomain_discovered": "low",
        "endpoint_discovered": "low",
        "ip_discovered": "low",
        "port_opened": "medium",
        "tech_detected": "medium",
        "cert_added": "info",
        "secret_found": "high",
        "repository_found": "low",
        "finding_opened": "critical",
        "finding_resolved": "info",
        "asset_removed": "low",
        "cert_expiring": "medium",
        "exposure_increased": "high",
    }
    for ct, sev in expected_sev.items():
        assert ct in by_type, f"missing change_type {ct}"
        assert by_type[ct][0]["severity"] == sev, f"{ct} severity"

    # finding_opened inherits the finding severity.
    assert by_type["finding_opened"][0]["severity"] == "critical"
    # pre-cursor subdomain was not re-emitted (only the new one).
    assert len(by_type["subdomain_discovered"]) == 1


async def test_dedupe_on_rerun(clean_db):
    now = datetime.now(timezone.utc)
    cursor = now - timedelta(hours=1)

    await mk_asset(clean_db, "subdomain", "dedupe.example.com", first_seen=now)
    await mk_asset(clean_db, "service", "ghost", first_seen=now - timedelta(days=10),
                   last_seen=now - timedelta(days=10))
    not_after = (now + timedelta(days=5)).isoformat()
    await mk_asset(clean_db, "certificate", "cert:soon",
                   metadata={"not_after": not_after}, last_seen=now)

    det = ChangeDetector(clean_db, _cfg())
    first = await det.run(cursor)
    assert {r["change_type"] for r in first} >= {
        "subdomain_discovered", "asset_removed", "cert_expiring"
    }

    # Re-run with the SAME cursor: everything should dedupe to zero inserts.
    second = await det.run(cursor)
    assert second == []


async def test_private_endpoint_does_not_increase_exposure(clean_db):
    now = datetime.now(timezone.utc)
    cursor = now - timedelta(hours=1)

    host = await mk_asset(clean_db, "subdomain", "internal.example.com",
                          first_seen=now - timedelta(hours=2), last_seen=now)
    # endpoint without public=true → not an exposure increase.
    ep = await mk_asset(clean_db, "endpoint", "https://internal.example.com/",
                        metadata={"public": False}, first_seen=now)
    await mk_edge(clean_db, host, ep, "resolves_to", first_seen=now)

    det = ChangeDetector(clean_db, _cfg())
    rows = await det.run(cursor)
    assert all(r["change_type"] != "exposure_increased" for r in rows)
