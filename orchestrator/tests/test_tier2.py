"""Tier 2 endpoints: TLS grades, tickets, owners, SLA, schedules + the
continuous-monitoring scheduler.

Tickets/grades are normally written by the active worker / triage service, so
where those are the system-under-test we seed rows directly and exercise the
orchestrator's read/CRUD/dispatch surface. The scheduler's next-run helper is
unit-tested in isolation for both the croniter and interval-fallback paths.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from app import scheduler as scheduler_mod


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


async def _mk_finding(con, asset_id: str, severity: str, title: str) -> str:
    return str(
        await con.fetchval(
            "INSERT INTO findings (asset_id, rule_id, rule_source, severity, "
            "title, description) VALUES ($1,$2,'manual',$3,$4,'desc') RETURNING id",
            asset_id,
            f"rule-{title}",
            severity,
            title,
        )
    )


async def _mk_ticket(
    con,
    *,
    finding_id: str,
    title: str,
    severity: str,
    owner_team: str | None = None,
    contact: str | None = None,
    status: str = "open",
    breached: bool = False,
    sla_hours: int | None = None,
    sla_due: datetime | None = None,
    closed_at: datetime | None = None,
    system: str = "internal",
) -> str:
    return str(
        await con.fetchval(
            """
            INSERT INTO tickets (
                finding_id, title, severity, owner_team, contact, status,
                breached, sla_hours, sla_due, closed_at, system
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
            RETURNING id
            """,
            finding_id,
            title,
            severity,
            owner_team,
            contact,
            status,
            breached,
            sla_hours,
            sla_due,
            closed_at,
            system,
        )
    )


async def _add_scope(client, kind, value):
    r = await client.post(
        "/v1/scope", json={"kind": kind, "value": value, "added_by": "t"}
    )
    assert r.status_code == 201, r.text


# --------------------------------------------------------------------------- #
# TLS grades
# --------------------------------------------------------------------------- #

async def test_tls_grades_bulk_upsert_insert_then_update(client, db_pool):
    async with db_pool.acquire() as con:
        asset_id = await _mk_asset(con, "subdomain", "tls.example.com")

    r = await client.post(
        "/v1/tls-grades/bulk",
        json={
            "items": [
                {
                    "asset_id": asset_id,
                    "host": "tls.example.com",
                    "grade": "B",
                    "score": 70,
                    "protocols": ["TLS1.3", "TLS1.2"],
                    "weak_ciphers": [],
                    "issues": ["no TLS1.3 on one vhost"],
                    "cert_expires": "2027-01-01T00:00:00Z",
                }
            ]
        },
    )
    assert r.status_code == 200, r.text
    assert r.json() == {"inserted": 1, "updated": 0}

    # Re-post the same asset with a worse grade -> update, not insert.
    r2 = await client.post(
        "/v1/tls-grades/bulk",
        json={
            "items": [
                {
                    "asset_id": asset_id,
                    "host": "tls.example.com",
                    "grade": "F",
                    "score": 10,
                    "protocols": ["TLS1.0"],
                    "weak_ciphers": ["RC4"],
                    "issues": ["TLS1.0 enabled", "weak cipher present"],
                }
            ]
        },
    )
    assert r2.status_code == 200, r2.text
    assert r2.json() == {"inserted": 0, "updated": 1}

    async with db_pool.acquire() as con:
        n = await con.fetchval("SELECT COUNT(*) FROM tls_grades")
        grade = await con.fetchval("SELECT grade FROM tls_grades WHERE asset_id=$1", asset_id)
    assert n == 1
    assert grade == "F"


async def test_tls_grades_list_joins_asset_value_and_filters(client, db_pool):
    async with db_pool.acquire() as con:
        a1 = await _mk_asset(con, "subdomain", "a.example.com")
        a2 = await _mk_asset(con, "subdomain", "b.example.com")
    await client.post(
        "/v1/tls-grades/bulk",
        json={
            "items": [
                {"asset_id": a1, "host": "a.example.com", "grade": "A+", "score": 98},
                {"asset_id": a2, "host": "b.example.com", "grade": "F", "score": 12},
            ]
        },
    )

    r = await client.get("/v1/tls-grades")
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"items", "total", "limit", "offset"}
    assert body["total"] == 2
    # Worst score first; asset value joined in.
    assert body["items"][0]["grade"] == "F"
    vals = {i["host"]: i["asset_value"] for i in body["items"]}
    assert vals["a.example.com"] == "a.example.com"

    r2 = await client.get("/v1/tls-grades", params={"grade": "F"})
    assert r2.json()["total"] == 1
    assert r2.json()["items"][0]["host"] == "b.example.com"


async def test_tls_grades_summary_counts_per_grade(client, db_pool):
    async with db_pool.acquire() as con:
        ids = [await _mk_asset(con, "subdomain", f"h{i}.example.com") for i in range(3)]
    await client.post(
        "/v1/tls-grades/bulk",
        json={
            "items": [
                {"asset_id": ids[0], "host": "h0.example.com", "grade": "A", "score": 85},
                {"asset_id": ids[1], "host": "h1.example.com", "grade": "A", "score": 82},
                {"asset_id": ids[2], "host": "h2.example.com", "grade": "T", "score": 0},
            ]
        },
    )
    r = await client.get("/v1/tls-grades/summary")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 3
    assert body["counts"]["A"] == 2
    assert body["counts"]["T"] == 1
    assert body["counts"]["F"] == 0
    # All buckets present and zero-filled.
    assert set(body["counts"]) == {"A+", "A", "B", "C", "D", "E", "F", "T"}


# --------------------------------------------------------------------------- #
# Tickets
# --------------------------------------------------------------------------- #

async def test_tickets_list_includes_asset_and_finding_summary(client, db_pool):
    async with db_pool.acquire() as con:
        asset_id = await _mk_asset(con, "endpoint", "https://app.example.com/login")
        finding_id = await _mk_finding(con, asset_id, "high", "XSS")
        await _mk_ticket(
            con,
            finding_id=finding_id,
            title="Fix XSS",
            severity="high",
            owner_team="appsec",
        )

    r = await client.get("/v1/tickets")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 1
    t = body["items"][0]
    assert t["asset"] == {
        "value": "https://app.example.com/login",
        "kind": "endpoint",
    }
    assert t["finding"] == {"title": "XSS", "rule_source": "manual"}
    assert t["owner_team"] == "appsec"


async def test_ticket_detail_and_404(client, db_pool):
    async with db_pool.acquire() as con:
        asset_id = await _mk_asset(con, "subdomain", "d.example.com")
        finding_id = await _mk_finding(con, asset_id, "medium", "Open redirect")
        tid = await _mk_ticket(
            con, finding_id=finding_id, title="Redirect", severity="medium"
        )

    r = await client.get(f"/v1/tickets/{tid}")
    assert r.status_code == 200, r.text
    assert r.json()["title"] == "Redirect"

    r2 = await client.get("/v1/tickets/00000000-0000-0000-0000-000000000000")
    assert r2.status_code == 404


async def test_ticket_patch_close_sets_closed_at_then_reopen_clears(client, db_pool):
    async with db_pool.acquire() as con:
        asset_id = await _mk_asset(con, "subdomain", "c.example.com")
        finding_id = await _mk_finding(con, asset_id, "low", "Info leak")
        tid = await _mk_ticket(
            con, finding_id=finding_id, title="Leak", severity="low"
        )

    r = await client.patch(f"/v1/tickets/{tid}", json={"status": "resolved"})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "resolved"
    assert r.json()["closed_at"] is not None

    # Re-opening clears closed_at.
    r2 = await client.patch(f"/v1/tickets/{tid}", json={"status": "in_progress"})
    assert r2.status_code == 200, r2.text
    assert r2.json()["status"] == "in_progress"
    assert r2.json()["closed_at"] is None


async def test_ticket_patch_owner_and_contact(client, db_pool):
    async with db_pool.acquire() as con:
        asset_id = await _mk_asset(con, "subdomain", "o.example.com")
        finding_id = await _mk_finding(con, asset_id, "high", "RCE")
        tid = await _mk_ticket(con, finding_id=finding_id, title="RCE", severity="high")

    r = await client.patch(
        f"/v1/tickets/{tid}",
        json={"owner_team": "platform", "contact": "oncall@example.com"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["owner_team"] == "platform"
    assert r.json()["contact"] == "oncall@example.com"


async def test_tickets_filters(client, db_pool):
    async with db_pool.acquire() as con:
        a = await _mk_asset(con, "subdomain", "f.example.com")
        f1 = await _mk_finding(con, a, "high", "one")
        f2 = await _mk_finding(con, a, "medium", "two")
        f3 = await _mk_finding(con, a, "high", "three")
        await _mk_ticket(con, finding_id=f1, title="one", severity="high",
                         owner_team="alpha", breached=True)
        await _mk_ticket(con, finding_id=f2, title="two", severity="medium",
                         owner_team="beta", status="resolved",
                         closed_at=datetime.now(timezone.utc))
        await _mk_ticket(con, finding_id=f3, title="three", severity="high",
                         owner_team="alpha")

    assert (await client.get("/v1/tickets", params={"severity": "high"})).json()["total"] == 2
    assert (await client.get("/v1/tickets", params={"team": "beta"})).json()["total"] == 1
    assert (await client.get("/v1/tickets", params={"status": "resolved"})).json()["total"] == 1
    assert (await client.get("/v1/tickets", params={"breached": "true"})).json()["total"] == 1


async def test_tickets_summary(client, db_pool):
    now = datetime.now(timezone.utc)
    async with db_pool.acquire() as con:
        a = await _mk_asset(con, "subdomain", "s.example.com")
        f1 = await _mk_finding(con, a, "high", "s1")
        f2 = await _mk_finding(con, a, "medium", "s2")
        f3 = await _mk_finding(con, a, "low", "s3")
        await _mk_ticket(con, finding_id=f1, title="s1", severity="high",
                         owner_team="alpha")
        await _mk_ticket(con, finding_id=f2, title="s2", severity="medium",
                         owner_team="beta", breached=True)
        await _mk_ticket(con, finding_id=f3, title="s3", severity="low",
                         owner_team="alpha", status="resolved", closed_at=now)

    r = await client.get("/v1/tickets/summary")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["open"] == 2
    assert body["breached"] == 1
    assert body["resolved_7d"] == 1
    assert body["by_team"] == {"alpha": 1, "beta": 1}
    assert body["by_severity"] == {"high": 1, "medium": 1}


# --------------------------------------------------------------------------- #
# Owners
# --------------------------------------------------------------------------- #

async def test_owners_crud(client):
    # Create
    r = await client.post(
        "/v1/owners",
        json={
            "name": "web team",
            "match": {"kinds": ["subdomain"], "value_regex": r"\.web\."},
            "team": "web",
            "contact": "web@example.com",
            "priority": 10,
        },
    )
    assert r.status_code == 201, r.text
    oid = r.json()["id"]
    assert r.json()["team"] == "web"
    assert r.json()["match"]["kinds"] == ["subdomain"]

    # List (ordered by priority asc)
    r2 = await client.get("/v1/owners")
    assert r2.status_code == 200
    assert any(o["id"] == oid for o in r2.json())

    # Patch
    r3 = await client.patch(f"/v1/owners/{oid}", json={"enabled": False, "priority": 5})
    assert r3.status_code == 200, r3.text
    assert r3.json()["enabled"] is False
    assert r3.json()["priority"] == 5

    # Delete
    r4 = await client.delete(f"/v1/owners/{oid}")
    assert r4.status_code == 204
    r5 = await client.delete(f"/v1/owners/{oid}")
    assert r5.status_code == 404


# --------------------------------------------------------------------------- #
# SLA policies
# --------------------------------------------------------------------------- #

async def test_sla_policies_list_and_patch(client):
    r = await client.get("/v1/sla-policies")
    assert r.status_code == 200, r.text
    policies = {p["severity"]: p["hours"] for p in r.json()}
    # Seeded by schema/008.
    assert policies["critical"] == 24
    assert policies["high"] == 72

    r2 = await client.patch("/v1/sla-policies/high", json={"hours": 48})
    assert r2.status_code == 200, r2.text
    assert r2.json() == {"severity": "high", "hours": 48}

    r3 = await client.get("/v1/sla-policies")
    assert {p["severity"]: p["hours"] for p in r3.json()}["high"] == 48


# --------------------------------------------------------------------------- #
# Schedules CRUD
# --------------------------------------------------------------------------- #

async def test_schedule_crud_lifecycle(client):
    r = await client.post(
        "/v1/schedules",
        json={
            "name": "nightly passive",
            "scan_kind": "passive_subdomains",
            "target_scope": "all",
            "config": {"every_n_minutes": 1440},
        },
    )
    assert r.status_code == 201, r.text
    sid = r.json()["id"]
    assert r.json()["enabled"] is True
    assert r.json()["next_run_at"] is not None  # seeded on create

    r2 = await client.get("/v1/schedules")
    assert any(s["id"] == sid for s in r2.json())

    r3 = await client.patch(f"/v1/schedules/{sid}", json={"enabled": False})
    assert r3.status_code == 200, r3.text
    assert r3.json()["enabled"] is False

    r4 = await client.delete(f"/v1/schedules/{sid}")
    assert r4.status_code == 204
    assert (await client.delete(f"/v1/schedules/{sid}")).status_code == 404


async def test_schedule_create_requires_interval_without_croniter(client):
    # croniter is not installed in CI -> a schedule with neither a usable cron
    # nor every_n_minutes is rejected.
    if scheduler_mod.croniter_available():
        pytest.skip("croniter installed; interval not required")
    r = await client.post(
        "/v1/schedules",
        json={
            "name": "bad",
            "scan_kind": "passive_subdomains",
            "target_scope": "all",
            "cron": "*/5 * * * *",
            "config": {},
        },
    )
    assert r.status_code == 422, r.text


async def test_schedule_run_now_enqueues_job(client, db_pool, fake_redis):
    await _add_scope(client, "subdomain_wildcard", "example.com")
    r = await client.post(
        "/v1/schedules",
        json={
            "name": "run-me",
            "scan_kind": "passive_subdomains",
            "target_scope": "example.com",
            "config": {"every_n_minutes": 60},
        },
    )
    assert r.status_code == 201, r.text
    sid = r.json()["id"]

    run = await client.post(f"/v1/schedules/{sid}/run-now")
    assert run.status_code == 200, run.text
    body = run.json()
    assert body["enqueued"] >= 1
    assert body["status"] == "ok"
    assert len(body["scan_ids"]) >= 1

    # The job landed on the passive stream, and bookkeeping was updated.
    entries = await fake_redis.xrange("queue:passive")
    assert len(entries) >= 1
    job = json.loads(entries[0][1]["job"])
    assert job["kind"] == "passive_subdomains"
    assert job["target"] == "example.com"
    assert body["schedule"]["last_status"] == "ok"
    assert body["schedule"]["last_run_at"] is not None


# --------------------------------------------------------------------------- #
# Scheduler internals
# --------------------------------------------------------------------------- #

def test_compute_next_run_interval_fallback_no_croniter():
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    # cron present but croniter forced off -> interval is used.
    nxt = scheduler_mod.compute_next_run(
        now, cron="*/5 * * * *", config={"every_n_minutes": 5}, croniter_cls=None
    )
    assert nxt == now + timedelta(minutes=5)

    # no cron, no interval -> default minutes.
    nxt2 = scheduler_mod.compute_next_run(now, cron="", config={}, croniter_cls=None)
    from app.config import settings

    assert nxt2 == now + timedelta(minutes=settings.scheduler_default_minutes)


def test_compute_next_run_uses_croniter_when_present():
    now = datetime(2026, 1, 1, 12, 34, 0, tzinfo=timezone.utc)

    class _FakeCron:
        def __init__(self, expr, start):
            self.start = start

        def get_next(self, _type):
            # Pretend "top of the next hour".
            return self.start.replace(minute=0, second=0) + timedelta(hours=1)

    nxt = scheduler_mod.compute_next_run(
        now, cron="0 * * * *", config={}, croniter_cls=_FakeCron
    )
    assert nxt == datetime(2026, 1, 1, 13, 0, 0, tzinfo=timezone.utc)


async def test_run_due_schedules_dispatches_due_only(client, db_pool, fake_redis):
    await _add_scope(client, "subdomain_wildcard", "example.com")
    async with db_pool.acquire() as con:
        # Due now (next_run_at NULL).
        due_id = await con.fetchval(
            """
            INSERT INTO schedules (name, scan_kind, target_scope, cron, enabled,
                                   config, next_run_at)
            VALUES ('due','active_http_probe','example.com','',TRUE,
                    '{"every_n_minutes":30}'::jsonb, NULL)
            RETURNING id
            """
        )
        # Not due (next_run_at far in the future).
        await con.execute(
            """
            INSERT INTO schedules (name, scan_kind, target_scope, cron, enabled,
                                   config, next_run_at)
            VALUES ('later','active_http_probe','example.com','',TRUE,
                    '{"every_n_minutes":30}'::jsonb, NOW() + INTERVAL '1 day')
            """
        )

    ran = await scheduler_mod.run_due_schedules(db_pool, fake_redis)
    assert ran == 1

    async with db_pool.acquire() as con:
        row = await con.fetchrow(
            "SELECT last_status, last_run_at, next_run_at, last_scan_id "
            "FROM schedules WHERE id=$1",
            due_id,
        )
    assert row["last_status"] == "ok"
    assert row["last_run_at"] is not None
    assert row["next_run_at"] is not None  # recomputed forward
    assert row["last_scan_id"] is not None

    # The due schedule enqueued an active scan; the not-due one did not.
    assert len(await fake_redis.xrange("queue:active")) == 1


async def test_run_schedule_out_of_scope_target_is_skipped(db_pool, fake_redis):
    # No scope entries at all -> the literal target fails the scope check and
    # nothing is enqueued, but the schedule is still bookkept (never crashes).
    async with db_pool.acquire() as con:
        sid = await con.fetchval(
            """
            INSERT INTO schedules (name, scan_kind, target_scope, cron, enabled,
                                   config, next_run_at)
            VALUES ('oos','passive_subdomains','notscoped.example.org','',TRUE,
                    '{"every_n_minutes":30}'::jsonb, NULL)
            RETURNING id
            """
        )
        row = await con.fetchrow(
            "SELECT id, name, scan_kind, target_scope, cron, enabled, "
            "last_run_at, next_run_at, last_status, config FROM schedules WHERE id=$1",
            sid,
        )
    result = await scheduler_mod.run_schedule(db_pool, fake_redis, row)
    assert result.enqueued == 0
    assert result.status == "scope_denied"
    assert len(await fake_redis.xrange("queue:passive")) == 0
