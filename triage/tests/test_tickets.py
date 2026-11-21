"""Ticket pass + SLA logic tests. No DB, no network (fakes throughout).

Covers: SLA due calculation from sla_policies, the breach sweep, dedupe (one
ticket per finding), owner resolution during a pass, and external dispatch
recording (internal = DB only; webhook/github/jira = POST to the target).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.config import Config
from app.dispatch import TicketDispatcher, choose_target, parse_external
from app.tickets import TicketManager, compute_sla_due, severities_at_least

from .conftest import FakePoster, FakePublisher, FakeTicketDB


def _cfg(**over):
    # Config reads env at construction; build then override frozen fields via a copy.
    cfg = Config()
    if over:
        from dataclasses import replace
        cfg = replace(cfg, **over)
    return cfg


def _finding(fid, severity="high", first_seen=None, asset_kind="subdomain",
             asset_value="api.prod.example.com", asset_metadata=None):
    return {
        "finding_id": fid,
        "severity": severity,
        "title": f"finding {fid}",
        "first_seen": first_seen or datetime(2026, 1, 1, tzinfo=timezone.utc),
        "asset_id": "a-" + fid,
        "asset_kind": asset_kind,
        "asset_value": asset_value,
        "asset_metadata": asset_metadata or {"env": "prod", "tags": ["payments"]},
    }


# ----------------------------------------------------------------------------
# pure helpers
# ----------------------------------------------------------------------------

def test_severities_at_least():
    assert severities_at_least("medium") == ["medium", "high", "critical"]
    assert severities_at_least("critical") == ["critical"]
    assert set(severities_at_least("info")) == {"info", "low", "medium", "high", "critical"}


def test_compute_sla_due():
    first = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    assert compute_sla_due(first, 72) == first + timedelta(hours=72)
    assert compute_sla_due(first, None) is None     # no policy for severity
    assert compute_sla_due(None, 24) is None


# ----------------------------------------------------------------------------
# dispatch target selection + response parsing
# ----------------------------------------------------------------------------

def test_choose_target_prefers_url_contact_then_webhook():
    assert choose_target("internal", "https://x", "https://wh") is None
    assert choose_target("webhook", "https://contact", "https://wh") == "https://contact"
    assert choose_target("github", "team@example.com", "https://wh") == "https://wh"
    assert choose_target("jira", "team@example.com", None) is None


def test_parse_external_variants():
    assert parse_external('{"number": 7, "html_url": "https://gh/7"}') == ("7", "https://gh/7")
    assert parse_external('{"key": "SEC-1", "self": "https://jira/SEC-1"}') == ("SEC-1", "https://jira/SEC-1")
    assert parse_external("not json") == (None, None)


# ----------------------------------------------------------------------------
# ticket pass: SLA due calc, owner resolution, internal vs dispatch
# ----------------------------------------------------------------------------

async def test_pass_sets_sla_due_from_policies_and_owner():
    owners = [{"id": "o1", "team": "payments-team", "match": {"tag": "payments"},
               "priority": 10, "enabled": True, "contact": "pay@example.com",
               "system": None}]
    db = FakeTicketDB(
        findings=[_finding("f1", severity="high")],
        owners=owners,
        policies={"high": 72, "medium": 168},
    )
    mgr = TicketManager(db, _cfg(), TicketDispatcher(_cfg()), publish=FakePublisher())
    counts = await mgr.run_pass()

    assert counts["tickets_created"] == 1
    t = db.inserted[0]
    assert t["owner_team"] == "payments-team"
    assert t["sla_hours"] == 72
    assert t["sla_due"] == datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(hours=72)
    # internal by default -> no external update, no dispatch.
    assert t["system"] == "internal"
    assert db.external_updates == []


async def test_unowned_finding_still_ticketed_internal():
    db = FakeTicketDB(
        findings=[_finding("f1", asset_metadata={"env": "dev", "tags": []})],
        owners=[{"id": "o1", "team": "pay", "match": {"tag": "payments"},
                 "priority": 10, "enabled": True, "contact": None, "system": None}],
        policies={"high": 72},
    )
    mgr = TicketManager(db, _cfg(), TicketDispatcher(_cfg()), publish=FakePublisher())
    counts = await mgr.run_pass()
    assert counts["tickets_created"] == 1
    assert counts["unowned"] == 1
    assert db.inserted[0]["owner_team"] is None
    assert db.inserted[0]["system"] == "internal"


async def test_ticket_opened_event_published():
    pub = FakePublisher()
    db = FakeTicketDB(findings=[_finding("f1")], owners=[], policies={"high": 72})
    mgr = TicketManager(db, _cfg(), TicketDispatcher(_cfg()), publish=pub)
    await mgr.run_pass()
    assert [e["event"] for e in pub.events] == ["ticket_opened"]
    assert pub.events[0]["finding_id"] == "f1"


# ----------------------------------------------------------------------------
# dedupe: one ticket per finding
# ----------------------------------------------------------------------------

async def test_dedupe_one_ticket_per_finding():
    db = FakeTicketDB(findings=[_finding("f1")], owners=[], policies={"high": 72})
    mgr = TicketManager(db, _cfg(), TicketDispatcher(_cfg()), publish=FakePublisher())

    first = await mgr.run_pass()
    assert first["tickets_created"] == 1
    # Second pass: insert_ticket returns None (UNIQUE conflict) -> deduped.
    second = await mgr.run_pass()
    assert second["tickets_created"] == 0
    assert second["dedupe_skipped"] == 1
    assert len(db.inserted) == 1


# ----------------------------------------------------------------------------
# external dispatch recording
# ----------------------------------------------------------------------------

async def test_non_internal_posts_to_target_and_records_external():
    owners = [{"id": "o1", "team": "sec", "match": {"metadata_env": "prod"},
               "priority": 10, "enabled": True,
               "contact": "https://tracker.example/ingest", "system": "webhook"}]
    db = FakeTicketDB(findings=[_finding("f1")], owners=owners, policies={"high": 72})
    poster = FakePoster(ok=True, status=201,
                        body='{"id": "ABC-9", "html_url": "https://tracker.example/ABC-9"}')
    disp = TicketDispatcher(_cfg(), post_fn=poster)
    mgr = TicketManager(db, _cfg(), disp, publish=FakePublisher())

    counts = await mgr.run_pass()
    assert counts["dispatched"] == 1
    # SAFETY: the POST goes only to the owner rule's URL contact.
    assert len(poster.calls) == 1
    assert poster.calls[0]["url"] == "https://tracker.example/ingest"
    assert poster.calls[0]["payload"]["finding_id"] == "f1"
    # external id/url recorded from the response.
    assert db.external_updates == [("ticket-1", "ABC-9", "https://tracker.example/ABC-9")]
    assert db.internal_updates == []


async def test_dispatch_failure_falls_back_to_internal_with_note():
    owners = [{"id": "o1", "team": "sec", "match": {},
               "priority": 10, "enabled": True,
               "contact": "https://tracker.example/x", "system": "jira"}]
    db = FakeTicketDB(findings=[_finding("f1")], owners=owners, policies={"high": 72})
    poster = FakePoster(ok=False, status=500, body="boom")
    disp = TicketDispatcher(_cfg(), post_fn=poster)
    mgr = TicketManager(db, _cfg(), disp, publish=FakePublisher())

    counts = await mgr.run_pass()
    assert counts["dispatch_failed"] == 1
    assert db.external_updates == []
    assert len(db.internal_updates) == 1
    assert db.internal_updates[0][0] == "ticket-1"
    assert "500" in db.internal_updates[0][1]


async def test_non_internal_without_target_stays_internal():
    # system is non-internal but neither contact nor webhook_url is a URL.
    owners = [{"id": "o1", "team": "sec", "match": {},
               "priority": 10, "enabled": True,
               "contact": "sec@example.com", "system": "github"}]
    db = FakeTicketDB(findings=[_finding("f1")], owners=owners, policies={"high": 72})
    poster = FakePoster()
    disp = TicketDispatcher(_cfg(webhook_url=None), post_fn=poster)
    mgr = TicketManager(db, _cfg(), disp, publish=FakePublisher())

    counts = await mgr.run_pass()
    assert counts["dispatch_failed"] == 1
    assert poster.calls == []  # nothing posted anywhere
    assert db.internal_updates[0][0] == "ticket-1"


async def test_service_webhook_used_when_contact_not_url():
    owners = [{"id": "o1", "team": "sec", "match": {},
               "priority": 10, "enabled": True,
               "contact": "sec@example.com", "system": "webhook"}]
    db = FakeTicketDB(findings=[_finding("f1")], owners=owners, policies={"high": 72})
    poster = FakePoster(ok=True, status=200, body='{"id": 1, "url": "https://wh/1"}')
    disp = TicketDispatcher(_cfg(webhook_url="https://wh.example/ingest"), post_fn=poster)
    mgr = TicketManager(db, _cfg(), disp, publish=FakePublisher())

    await mgr.run_pass()
    assert poster.calls[0]["url"] == "https://wh.example/ingest"
    assert db.external_updates == [("ticket-1", "1", "https://wh/1")]


# ----------------------------------------------------------------------------
# SLA sweep + breach events
# ----------------------------------------------------------------------------

async def test_sla_sweep_marks_breached_and_publishes():
    breach_rows = [
        {"id": "ticket-7", "finding_id": "f7", "severity": "high",
         "owner_team": "sec", "sla_due": datetime(2026, 1, 1, tzinfo=timezone.utc)},
    ]
    pub = FakePublisher()
    db = FakeTicketDB(findings=[], breach_rows=breach_rows)
    mgr = TicketManager(db, _cfg(), TicketDispatcher(_cfg()), publish=pub)

    counts = await mgr.run_pass()
    assert counts["breached"] == 1
    assert [e["event"] for e in pub.events] == ["ticket_breached"]
    assert pub.events[0]["ticket_id"] == "ticket-7"


# ----------------------------------------------------------------------------
# resolve-owners re-evaluation
# ----------------------------------------------------------------------------

async def test_resolve_owners_updates_changed_only():
    owners = [{"id": "o1", "team": "payments-team", "match": {"tag": "payments"},
               "priority": 10, "enabled": True, "contact": "pay@example.com",
               "system": None}]
    open_tickets = [
        # already correct -> no update.
        {"id": "ticket-1", "owner_team": "payments-team", "contact": "pay@example.com",
         "asset_kind": "subdomain", "asset_value": "a.example.com",
         "asset_metadata": {"tags": ["payments"]}},
        # stale owner -> should be re-pointed.
        {"id": "ticket-2", "owner_team": "old-team", "contact": None,
         "asset_kind": "subdomain", "asset_value": "b.example.com",
         "asset_metadata": {"tags": ["payments"]}},
        # no rule matches -> owner cleared to None (was set).
        {"id": "ticket-3", "owner_team": "old-team", "contact": None,
         "asset_kind": "subdomain", "asset_value": "c.example.com",
         "asset_metadata": {"tags": ["infra"]}},
    ]
    db = FakeTicketDB(owners=owners, open_tickets=open_tickets)
    mgr = TicketManager(db, _cfg(), TicketDispatcher(_cfg()), publish=FakePublisher())

    result = await mgr.resolve_owners()
    assert result == {"tickets": 3, "updated": 2}
    updated_ids = {u[0] for u in db.owner_updates}
    assert updated_ids == {"ticket-2", "ticket-3"}
