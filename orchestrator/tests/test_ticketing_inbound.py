"""POST /v1/integrations/{id}/inbound against a real Postgres, plus link
persistence and end-to-end loop prevention."""
from __future__ import annotations

import base64
import json
import os
import sys
import types
import uuid

import httpx
import pytest

from app.config import settings
from app.integrations import links, netsafety, ticketing
from app.integrations.connectors.jira import JiraConnector
from app.integrations.secrets import encrypt_secrets
from app.routers import integrations_inbound

from .ticketing_fakes import FakeJira, allow_all, finding_event, jira_webhook, linear_webhook, sign


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("PADDOCK_SECRET_KEY", base64.urlsafe_b64encode(os.urandom(32)).decode())
    monkeypatch.setattr(netsafety, "validate_outbound_url", allow_all)
    integrations_inbound.rate_limiter.reset()
    yield
    integrations_inbound.rate_limiter.reset()


@pytest.fixture
def emitted(monkeypatch):
    """A stand-in for the integrations core's ``service.emit``."""
    events: list = []

    async def emit(pool, event):
        events.append(event)

    mod = types.ModuleType("app.integrations.service")
    mod.emit = emit
    monkeypatch.setitem(sys.modules, "app.integrations.service", mod)
    import app.integrations as pkg

    monkeypatch.setattr(pkg, "service", mod, raising=False)
    return events


async def _finding(pool, status="open", title="Weak TLS") -> str:
    async with pool.acquire() as con:
        aid = await con.fetchval(
            "INSERT INTO assets (kind, value, canonical, source) VALUES ('subdomain', $1, $1, 'seed') "
            "RETURNING id", f"h{uuid.uuid4().hex[:8]}.example.com")
        fid = await con.fetchval(
            "INSERT INTO findings (asset_id, rule_id, rule_source, severity, title, description, status) "
            "VALUES ($1, $2, 'manual', 'high', $3, 'd', $4) RETURNING id",
            aid, f"r-{uuid.uuid4().hex[:6]}", title, status)
    return str(fid)


async def _integration(pool, kind="jira", *, secrets=None, config=None, token="auto",
                       enabled=True, name=None) -> str:
    if token == "auto":
        token = f"tok-{uuid.uuid4().hex}"
    async with pool.acquire() as con:
        iid = await con.fetchval(
            "INSERT INTO integrations (kind, name, enabled, config, secrets, inbound_token) "
            "VALUES ($1, $2, $3, $4::jsonb, $5, $6) RETURNING id",
            kind, name or f"{kind}-prod", enabled,
            json.dumps(config or {"base_url": "https://acme.atlassian.net", "project_key": "SEC"}),
            encrypt_secrets(secrets if secrets is not None else {"webhook_secret": "whsec"}), token)
    return str(iid)


async def _set_status_constraint(pool, values: tuple[str, ...]) -> None:
    """Replace every findings.status CHECK with one allowing exactly ``values``."""
    async with pool.acquire() as con:
        names = await con.fetch(
            "SELECT conname FROM pg_constraint WHERE conrelid = 'findings'::regclass AND contype = 'c' "
            "AND pg_get_constraintdef(oid) ILIKE '%status%'")
        for n in names:
            await con.execute(f'ALTER TABLE findings DROP CONSTRAINT "{n["conname"]}"')
        allowed = ",".join(f"'{v}'" for v in values)
        await con.execute(f"ALTER TABLE findings ADD CONSTRAINT findings_status_check CHECK (status IN ({allowed}))")


LEGACY_STATUSES = ("open", "triaged", "false_positive", "accepted_risk", "fixed", "wontfix")


async def _status(pool, fid):
    async with pool.acquire() as con:
        return await con.fetchrow("SELECT status, metadata FROM findings WHERE id = $1", uuid.UUID(fid))


def _signed(body: bytes, secret="whsec", **extra) -> dict[str, str]:
    return {"X-Hub-Signature": "sha256=" + sign(secret, body), "Content-Type": "application/json", **extra}


async def test_jira_signed_webhook_closes_finding_with_audit_and_link(client, db_pool, emitted):
    fid = await _finding(db_pool)
    iid = await _integration(db_pool)
    await links.upsert(db_pool, iid, fid, "SEC-1", "https://acme.atlassian.net/browse/SEC-1")
    body = jira_webhook("SEC-1", "Done")
    r = await client.post(f"/v1/integrations/{iid}/inbound", content=body, headers=_signed(body))
    assert r.status_code == 200, r.text
    assert r.json()["applied"] == 1 and r.json()["results"][0]["status"] == "fixed"
    row = await _status(db_pool, fid)
    meta = json.loads(row["metadata"])
    assert row["status"] == "fixed"
    assert meta["status_origin"]["integration_id"] == iid and meta["status_origin"]["from"] == "open"
    assert "SEC-1" in meta["integration_notes"][-1]["text"]
    link = await links.get_by_finding(db_pool, iid, fid)
    assert link.external_status == "Done"
    async with db_pool.acquire() as con:
        a = await con.fetchrow("SELECT * FROM audit_log WHERE actor = 'integration:jira:jira-prod'")
    assert a is not None and a["resource_id"] == fid and a["actor_role"] == "integration"
    assert json.loads(a["details"])["to"] == "fixed"
    # the follow-up event carries the origin marker
    assert [e.type for e in emitted] == ["finding.resolved"]
    assert emitted[0].data["origin"]["integration_id"] == iid
    assert "whsec" not in r.text


async def test_bad_signature_is_401_and_changes_nothing(client, db_pool):
    fid = await _finding(db_pool)
    iid = await _integration(db_pool, token="tok-123")
    await links.upsert(db_pool, iid, fid, "SEC-1")
    body = jira_webhook()
    r = await client.post(f"/v1/integrations/{iid}/inbound", content=body,
                          headers=_signed(body, secret="wrong"))
    assert r.status_code == 401
    r = await client.post(f"/v1/integrations/{iid}/inbound?token=tok-123", content=body)
    assert r.status_code == 401                     # a token never excuses a missing signature
    assert (await _status(db_pool, fid))["status"] == "open"


async def test_token_mode(client, db_pool):
    fid = await _finding(db_pool)
    iid = await _integration(db_pool, secrets={}, token="tok-123")
    await links.upsert(db_pool, iid, fid, "SEC-1")
    body = jira_webhook(status="In Progress")
    assert (await client.post(f"/v1/integrations/{iid}/inbound", content=body)).status_code == 401
    assert (await client.post(f"/v1/integrations/{iid}/inbound?token=nope", content=body)).status_code == 401
    r = await client.post(f"/v1/integrations/{iid}/inbound?token=tok-123", content=body)
    assert r.status_code == 200 and (await _status(db_pool, fid))["status"] == "triaged"
    body = jira_webhook(status="Done")
    r = await client.post(f"/v1/integrations/{iid}/inbound", content=body,
                          headers={"X-Paddock-Token": "tok-123"})
    assert r.status_code == 200 and (await _status(db_pool, fid))["status"] == "fixed"
    # integration with no inbound_token configured: any token is wrong
    iid2 = await _integration(db_pool, secrets={}, token=None, name="jira-2")
    assert (await client.post(f"/v1/integrations/{iid2}/inbound?token=x", content=body)).status_code == 401


async def test_unknown_disabled_and_non_ticket_are_404(client, db_pool):
    body = b"{}"
    assert (await client.post(f"/v1/integrations/{uuid.uuid4()}/inbound", content=body)).status_code == 404
    assert (await client.post("/v1/integrations/not-a-uuid/inbound", content=body)).status_code == 404
    off = await _integration(db_pool, enabled=False)
    assert (await client.post(f"/v1/integrations/{off}/inbound", content=body)).status_code == 404
    other = await _integration(db_pool, kind="no_such_kind")
    assert (await client.post(f"/v1/integrations/{other}/inbound", content=body)).status_code == 404


async def test_rate_limit_per_integration(client, db_pool, monkeypatch):
    monkeypatch.setenv("PADDOCK_INBOUND_RATE_PER_MIN", "2")
    iid = await _integration(db_pool)
    iid2 = await _integration(db_pool, name="jira-2")
    codes = [(await client.post(f"/v1/integrations/{iid}/inbound", content=b"{}")).status_code
             for _ in range(3)]
    assert codes == [401, 401, 429]
    assert (await client.post(f"/v1/integrations/{iid2}/inbound", content=b"{}")).status_code == 401


async def test_payload_too_large(client, db_pool):
    iid = await _integration(db_pool)
    big = b"{" + b" " * (integrations_inbound.MAX_BODY + 1) + b"}"
    assert (await client.post(f"/v1/integrations/{iid}/inbound", content=big)).status_code == 413


async def test_malformed_json_is_400(client, db_pool):
    iid = await _integration(db_pool)
    body = b"not json"
    assert (await client.post(f"/v1/integrations/{iid}/inbound", content=body,
                              headers=_signed(body))).status_code == 400


async def test_accepted_degrades_to_legacy_status_until_constraint_allows_it(client, db_pool):
    await _set_status_constraint(db_pool, LEGACY_STATUSES)
    fid = await _finding(db_pool)
    iid = await _integration(db_pool)
    await links.upsert(db_pool, iid, fid, "SEC-1")
    body = jira_webhook(status="Done", resolution="Won't Do")
    r = await client.post(f"/v1/integrations/{iid}/inbound", content=body, headers=_signed(body))
    assert r.json()["results"][0] == {"external_id": "SEC-1", "finding_id": fid, "result": "status_changed",
                                      "status": "accepted_risk", "degraded_from": "accepted"}
    assert (await _status(db_pool, fid))["status"] == "accepted_risk"
    # once the other stream widens the constraint, the real status is stored
    await _set_status_constraint(db_pool, LEGACY_STATUSES + ("accepted",))
    body = jira_webhook(status="Done", resolution="Not a Bug")
    r = await client.post(f"/v1/integrations/{iid}/inbound", content=body, headers=_signed(body))
    assert (await _status(db_pool, fid))["status"] == "false_positive"


async def test_status_helpers():
    assert ticketing.resolve_status("accepted", {"accepted_risk"}) == "accepted_risk"
    assert ticketing.resolve_status("false_positive", {"open"}) is None
    assert ticketing.resolve_status("fixed", None) == "fixed"
    assert ticketing.event_type_for("open", "fixed") == "finding.reopened"
    assert ticketing.event_type_for("triaged", "open") == "finding.updated"


async def test_unparseable_status_keeps_status_but_notes(client, db_pool, monkeypatch):
    monkeypatch.setitem(ticketing.STATUS_FALLBACKS, "false_positive", ("false_positive",))
    await _set_status_constraint(db_pool, ("open", "triaged", "fixed"))
    fid = await _finding(db_pool)
    iid = await _integration(db_pool)
    await links.upsert(db_pool, iid, fid, "SEC-1")
    body = jira_webhook(status="Done", resolution="Not a Bug")
    r = await client.post(f"/v1/integrations/{iid}/inbound", content=body, headers=_signed(body))
    assert r.status_code == 200 and r.json()["results"][0]["result"] == "noted"
    row = await _status(db_pool, fid)
    assert row["status"] == "open" and "cannot store" in json.loads(row["metadata"])["integration_notes"][-1]["text"]


async def test_comment_only_appends_note(client, db_pool, emitted):
    fid = await _finding(db_pool)
    iid = await _integration(db_pool)
    await links.upsert(db_pool, iid, fid, "SEC-1")
    body = jira_webhook(changelog_field=None, comment="rolled out the fix", event="comment_created")
    r = await client.post(f"/v1/integrations/{iid}/inbound", content=body, headers=_signed(body))
    assert r.json()["applied"] == 1
    row = await _status(db_pool, fid)
    assert row["status"] == "open"
    note = json.loads(row["metadata"])["integration_notes"][-1]
    assert note["text"] == "rolled out the fix" and note["actor"] == "Alice"
    assert emitted == []                         # no status change -> no event


async def test_replayed_delivery_is_ignored(client, db_pool):
    fid = await _finding(db_pool)
    iid = await _integration(db_pool)
    await links.upsert(db_pool, iid, fid, "SEC-1")
    body = jira_webhook(status="Done")
    h = _signed(body, **{"X-Atlassian-Webhook-Identifier": "dlv-1"})
    assert (await client.post(f"/v1/integrations/{iid}/inbound", content=body, headers=h)).json()["applied"] == 1
    async with db_pool.acquire() as con:
        await con.execute("UPDATE findings SET status = 'open' WHERE id = $1", uuid.UUID(fid))
    r = await client.post(f"/v1/integrations/{iid}/inbound", content=body, headers=h)
    assert r.json()["duplicate"] is True and (await _status(db_pool, fid))["status"] == "open"


async def test_adopts_unlinked_ticket_by_marker_but_never_hijacks(client, db_pool):
    fid = await _finding(db_pool)
    iid = await _integration(db_pool)
    body = jira_webhook("SEC-7", "Done", fid=fid)
    r = await client.post(f"/v1/integrations/{iid}/inbound", content=body, headers=_signed(body))
    assert r.json()["applied"] == 1
    assert (await links.get_by_external(db_pool, iid, "SEC-7")).finding_id == fid
    # another issue claiming the same (already linked) finding is ignored
    body = jira_webhook("SEC-8", "To Do", fid=fid)
    r = await client.post(f"/v1/integrations/{iid}/inbound", content=body, headers=_signed(body))
    assert r.json()["results"][0]["result"] == "unlinked"
    assert (await _status(db_pool, fid))["status"] == "fixed"
    # an unknown finding id is ignored too
    body = jira_webhook("SEC-9", "Done", fid=str(uuid.uuid4()))
    r = await client.post(f"/v1/integrations/{iid}/inbound", content=body, headers=_signed(body))
    assert r.json()["ignored"] == 1


async def test_inbound_is_public_in_enforce_mode_but_only_this_route(client, db_pool, monkeypatch):
    monkeypatch.setattr(settings, "auth_mode", "enforce")
    fid = await _finding(db_pool)
    iid = await _integration(db_pool)
    await links.upsert(db_pool, iid, fid, "SEC-1")
    body = jira_webhook("SEC-1", "Done")
    r = await client.post(f"/v1/integrations/{iid}/inbound", content=body, headers=_signed(body))
    assert r.status_code == 200 and (await _status(db_pool, fid))["status"] == "fixed"
    assert (await client.post(f"/v1/integrations/{iid}/inbound/extra", content=body)).status_code == 401
    assert (await client.get(f"/v1/integrations/{iid}/inbound")).status_code == 401
    assert (await client.patch(f"/v1/findings/{fid}", json={"status": "open"})).status_code == 401


async def test_deliver_ticket_persists_and_reuses_link(db_pool):
    fid = await _finding(db_pool)
    iid = await _integration(db_pool, secrets={"api_token": "t", "email": "e@x.test"})
    async with db_pool.acquire() as con:
        row = dict(await con.fetchrow("SELECT * FROM integrations WHERE id = $1", uuid.UUID(iid)))
    fake = FakeJira()
    async with httpx.AsyncClient(transport=fake.transport()) as http:
        r1 = await ticketing.deliver_ticket(db_pool, row, finding_event(fid=fid), http=http)
        link = await links.get_by_finding(db_pool, iid, fid)
        assert r1.ok and link.external_id == "SEC-1" and link.external_url.endswith("/browse/SEC-1")
        searches = len(fake.calls("GET", "/search"))
        r2 = await ticketing.deliver_ticket(db_pool, row, finding_event("finding.updated", fid=fid), http=http)
        assert r2.ok and r2.external_id == "SEC-1"
        assert len(fake.calls("GET", "/search")) == searches    # used the link, not a search
        assert len(fake.issues) == 1
        # ticket deleted remotely -> link is stale -> a new ticket replaces it
        fake.issues.clear()
        r3 = await ticketing.deliver_ticket(db_pool, row, finding_event("finding.opened", fid=fid), http=http)
        assert r3.ok and r3.external_id == "SEC-2"
        assert (await links.get_by_finding(db_pool, iid, fid)).external_id == "SEC-2"


async def test_loop_prevention_end_to_end(client, db_pool, emitted):
    """Jira closes the ticket -> finding fixed -> finding.resolved (origin=jira)
    -> the Jira connector does NOT transition/comment again."""
    fid = await _finding(db_pool)
    iid = await _integration(db_pool, secrets={"webhook_secret": "whsec", "api_token": "t", "email": "e@x"})
    fake = FakeJira()
    async with httpx.AsyncClient(transport=fake.transport()) as http:
        conn = JiraConnector({"base_url": "https://acme.atlassian.net", "project_key": "SEC"},
                             {"api_token": "t", "email": "e@x"}, http).bind(integration_id=iid, pool=db_pool)
        await conn.deliver(finding_event(fid=fid))
        body = jira_webhook("SEC-1", "Done", fid=fid)
        r = await client.post(f"/v1/integrations/{iid}/inbound", content=body, headers=_signed(body))
        assert r.json()["applied"] == 1
        n = len(fake.requests)
        res = await conn.deliver(emitted[0])
        assert res.ok and "originated" in res.detail and len(fake.requests) == n
        # a different Jira integration (another project) still gets the event
        iid2 = await _integration(db_pool, name="jira-other")
        other = JiraConnector({"base_url": "https://acme.atlassian.net", "project_key": "SEC"},
                              {"api_token": "t", "email": "e@x"}, http).bind(integration_id=iid2, pool=db_pool)
        assert "originated" not in (await other.deliver(emitted[0])).detail


async def test_servicenow_and_linear_endpoints(client, db_pool):
    fid = await _finding(db_pool)
    sn = await _integration(db_pool, "servicenow", secrets={"inbound_secret": "sn-shared"},
                            config={"instance_url": "https://acme.service-now.com"})
    await links.upsert(db_pool, sn, fid, "a" * 32)
    body = json.dumps({"sys_id": "a" * 32, "state": "2", "state_label": "In Progress"}).encode()
    r = await client.post(f"/v1/integrations/{sn}/inbound", content=body, headers={"X-Paddock-Secret": "sn-shared"})
    assert r.status_code == 200 and (await _status(db_pool, fid))["status"] == "triaged"
    r = await client.post(f"/v1/integrations/{sn}/inbound", content=body, headers={"X-Paddock-Secret": "x"})
    assert r.status_code == 401

    fid2 = await _finding(db_pool)
    lin = await _integration(db_pool, "linear", secrets={"webhook_secret": "lin-sec"}, config={"team_id": "t"})
    await links.upsert(db_pool, lin, fid2, "iss-1")
    body = linear_webhook("iss-1", "completed")
    r = await client.post(f"/v1/integrations/{lin}/inbound", content=body,
                          headers={"Linear-Signature": sign("lin-sec", body)})
    assert r.status_code == 200 and (await _status(db_pool, fid2))["status"] == "fixed"
    link = await links.get_by_external(db_pool, lin, "iss-1")
    assert link.external_status == "Done"


async def test_links_helpers_move_external_id(db_pool):
    f1, f2 = await _finding(db_pool), await _finding(db_pool, title="b")
    iid = await _integration(db_pool)
    await links.upsert(db_pool, iid, f1, "SEC-1", "u1", "To Do")
    moved = await links.upsert(db_pool, iid, f2, "SEC-1")
    assert moved.finding_id == f2
    assert await links.get_by_finding(db_pool, iid, f1) is None
    assert await links.set_external_status(db_pool, iid, "SEC-1", "Done")
    assert not await links.set_external_status(db_pool, iid, "SEC-404", "Done")
    assert await links.delete(db_pool, iid, f2)
