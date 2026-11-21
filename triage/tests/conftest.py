"""Shared test fixtures.

Integration tests need a working Postgres: they use ``TEST_DATABASE_URL``
(falling back to ``DATABASE_URL``) and skip cleanly when neither is set or
reachable — mirroring changewatch/intel/correlation. The owners and ticket
logic suites are pure-Python (fake DB + fake async poster + fake publisher)
and always run without a database or the network.
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Optional

import pytest
import pytest_asyncio

from app.config import _normalize_dsn
from app.db import Database


def _test_dsn() -> Optional[str]:
    raw = os.environ.get("TEST_DATABASE_URL") or os.environ.get("DATABASE_URL")
    if not raw:
        return None
    return _normalize_dsn(raw)


@pytest_asyncio.fixture(scope="session")
async def db() -> AsyncIterator[Database]:
    dsn = _test_dsn()
    if dsn is None:
        pytest.skip("no TEST_DATABASE_URL / DATABASE_URL set")
    d = Database(dsn)
    try:
        await d.connect(min_size=1, max_size=4)
    except Exception as e:
        pytest.skip(f"test postgres unreachable: {e}")
    # Ensure the required tables exist; apply schema if not.
    try:
        await d.execute("SELECT 1 FROM tickets LIMIT 1")
    except Exception:
        schema_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "..", "schema")
        )
        if os.path.isdir(schema_dir):
            for fname in sorted(os.listdir(schema_dir)):
                if fname.endswith(".sql"):
                    with open(os.path.join(schema_dir, fname)) as f:
                        try:
                            await d.execute(f.read())
                        except Exception:
                            pass
    try:
        yield d
    finally:
        await d.close()


@pytest_asyncio.fixture
async def clean_db(db: Database) -> AsyncIterator[Database]:
    """Truncate every table triage reads or writes between tests."""
    async with db.acquire() as conn:
        await conn.execute(
            "TRUNCATE tickets, asset_owners, findings, assets RESTART IDENTITY CASCADE"
        )
    yield db


# ----------------------------------------------------------------------------
# Seed helpers (integration suite)
# ----------------------------------------------------------------------------

async def mk_asset(
    db: Database,
    kind: str,
    value: str,
    metadata: Optional[dict] = None,
    source: str = "test",
) -> str:
    aid = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    await db.execute(
        """
        INSERT INTO assets (id, kind, value, canonical, source, metadata, first_seen, last_seen)
        VALUES ($1::uuid, $2, $3, $4, $5, $6::jsonb, $7, $8)
        """,
        aid, kind, value, value.lower(), source,
        json.dumps(metadata or {}), now, now,
    )
    return aid


async def mk_finding(
    db: Database,
    asset_id: str,
    rule_id: str,
    rule_source: str = "nuclei",
    severity: str = "high",
    status: str = "open",
    title: Optional[str] = None,
    first_seen: Optional[datetime] = None,
) -> str:
    fid = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    await db.execute(
        """
        INSERT INTO findings (
          id, asset_id, rule_id, rule_source, severity, title, description,
          status, first_seen, last_seen
        ) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10)
        """,
        fid, asset_id, rule_id, rule_source, severity,
        title or rule_id, rule_id, status,
        first_seen or now, now,
    )
    return fid


async def mk_owner(
    db: Database,
    name: str,
    team: str,
    match: Optional[dict] = None,
    contact: Optional[str] = None,
    priority: int = 100,
    enabled: bool = True,
) -> str:
    oid = str(uuid.uuid4())
    await db.execute(
        """
        INSERT INTO asset_owners (id, name, match, team, contact, priority, enabled)
        VALUES ($1::uuid, $2, $3::jsonb, $4, $5, $6, $7)
        """,
        oid, name, json.dumps(match or {}), team, contact, priority, enabled,
    )
    return oid


# ----------------------------------------------------------------------------
# Fakes for the (network-free, DB-free) logic suites
# ----------------------------------------------------------------------------

class FakePoster:
    """Records POSTs instead of hitting the network."""

    def __init__(self, ok: bool = True, status: int = 201,
                 body: str = '{"id": 42, "html_url": "https://tracker.example/42"}') -> None:
        self.ok = ok
        self.status = status
        self.body = body
        self.calls: list[dict[str, Any]] = []

    async def __call__(self, url, payload, headers, timeout_s):
        self.calls.append({
            "url": url, "payload": payload, "headers": headers, "timeout_s": timeout_s,
        })
        return self.ok, self.status, self.body


class FakePublisher:
    """Captures events published by the ticket manager."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    async def __call__(self, event: dict[str, Any]) -> None:
        self.events.append(event)


class FakeTicketDB:
    """In-memory stand-in exposing just the methods TicketManager calls."""

    def __init__(
        self,
        findings: Optional[list[dict[str, Any]]] = None,
        owners: Optional[list[dict[str, Any]]] = None,
        policies: Optional[dict[str, int]] = None,
        breach_rows: Optional[list[dict[str, Any]]] = None,
        open_tickets: Optional[list[dict[str, Any]]] = None,
    ) -> None:
        self._findings = findings or []
        self._owners = owners or []
        self._policies = policies or {}
        self._breach_rows = breach_rows or []
        self._open_tickets = open_tickets or []
        self._seen_finding_ids: set[str] = set()
        self.inserted: list[dict[str, Any]] = []
        self.external_updates: list[tuple] = []
        self.internal_updates: list[tuple] = []
        self.owner_updates: list[tuple] = []
        self._id_seq = 0

    async def open_findings_without_ticket(self, severities):
        return [f for f in self._findings if f["severity"] in severities]

    async def enabled_owners(self):
        return list(self._owners)

    async def sla_policies(self):
        return dict(self._policies)

    async def insert_ticket(self, data):
        fid = data["finding_id"]
        if fid in self._seen_finding_ids:
            return None  # UNIQUE(finding_id) conflict -> dedupe
        self._seen_finding_ids.add(fid)
        self._id_seq += 1
        row = {
            "id": f"ticket-{self._id_seq}",
            "finding_id": fid,
            "title": data["title"],
            "severity": data["severity"],
            "owner_team": data.get("owner_team"),
            "contact": data.get("contact"),
            "system": data.get("system", "internal"),
            "external_id": None,
            "external_url": None,
            "status": "open",
            "sla_hours": data.get("sla_hours"),
            "sla_due": data.get("sla_due"),
            "breached": False,
            "opened_at": datetime.now(timezone.utc),
        }
        self.inserted.append(row)
        return row

    async def set_ticket_external(self, ticket_id, external_id, external_url):
        self.external_updates.append((ticket_id, external_id, external_url))

    async def mark_ticket_internal(self, ticket_id, note):
        self.internal_updates.append((ticket_id, note))

    async def breach_open_tickets_past_due(self):
        return list(self._breach_rows)

    async def open_tickets_with_asset(self):
        return list(self._open_tickets)

    async def update_ticket_owner(self, ticket_id, owner_team, contact):
        self.owner_updates.append((ticket_id, owner_team, contact))
