"""Ticket connectors against mock APIs (no DB): create, update, transition,
idempotency, signature verification, state mapping, loop prevention."""
from __future__ import annotations

import json

import httpx
import pytest

from app.integrations import REGISTRY, Capability, Event, netsafety
from app.integrations import connectors
from app.integrations.connectors._ticketing import TicketInboundUpdate, verify_hmac_sha256
from app.integrations.connectors.jira import JiraConnector
from app.integrations.connectors.linear import LinearConnector
from app.integrations.connectors.servicenow import ServiceNowConnector

from .ticketing_fakes import (
    FID,
    FakeJira,
    FakeLinear,
    FakeServiceNow,
    allow_all,
    basic,
    finding_event,
    jira_webhook,
    linear_webhook,
    sign,
)


@pytest.fixture(autouse=True)
def _no_dns(monkeypatch):
    seen: list[tuple[str, bool]] = []

    async def fake(url, *, allow_private=False):
        seen.append((url, allow_private))
        return await allow_all(url, allow_private=allow_private)

    monkeypatch.setattr(netsafety, "validate_outbound_url", fake)
    return seen


def test_registered_with_ticket_capability():
    connectors.load_all()
    for kind in ("jira", "servicenow", "linear"):
        cls = REGISTRY[kind]
        assert Capability.TICKET in cls.capabilities
        d = cls.describe()
        assert d["category"] == "ticketing" and d["secret_fields"]


# --------------------------------------------------------------------------- #
# Jira
# --------------------------------------------------------------------------- #

JIRA_CFG = {"base_url": "https://acme.atlassian.net", "project_key": "SEC", "email": "bot@acme.test",
            "component": "Security", "labels": ["asm"]}
JIRA_SECRETS = {"api_token": "jira-TOKEN-123", "webhook_secret": "whsec-jira"}


def _jira(fake: FakeJira, cfg=None, secrets=None) -> JiraConnector:
    return JiraConnector(JIRA_CFG if cfg is None else cfg, JIRA_SECRETS if secrets is None else secrets, httpx.AsyncClient(transport=fake.transport()))


async def test_jira_create_adf_priority_labels_and_auth(_no_dns):
    fake = FakeJira()
    res = await _jira(fake).deliver(finding_event())
    assert res.ok and res.external_id == "SEC-1"
    assert res.external_url == "https://acme.atlassian.net/browse/SEC-1"
    create = fake.calls("POST", "/issue")[0]
    assert create.headers["authorization"] == basic("bot@acme.test", "jira-TOKEN-123")
    f = json.loads(create.content)["fields"]
    assert f["project"] == {"key": "SEC"} and f["issuetype"] == {"name": "Bug"}
    assert f["priority"] == {"name": "High"}
    assert f["summary"] == "[Paddock][HIGH] Weak TLS on shop"
    assert set(f["labels"]) == {"paddock", f"paddock-{FID}", "asm"}
    assert f["components"] == [{"name": "Security"}]
    adf = f["description"]
    assert adf["type"] == "doc" and adf["version"] == 1
    flat = json.dumps(adf)
    for needle in ("Severity", "HIGH", "shop.example.com", "Why it matters",
                   "Attackers can downgrade", "Remediation", "Disable TLS",
                   f"https://paddock.example.com/findings/{FID}"):
        assert needle in flat
    # every outbound URL went through netsafety
    assert _no_dns and all(u.startswith("https://acme.atlassian.net/") for u, _ in _no_dns)


async def test_jira_idempotent_via_remote_marker():
    fake = FakeJira()
    c = _jira(fake)
    r1 = await c.deliver(finding_event())
    r2 = await c.deliver(finding_event())                      # dispatcher retry
    r3 = await c.deliver(finding_event("finding.updated", severity="critical"))
    assert r1.external_id == r2.external_id == r3.external_id == "SEC-1"
    assert len(fake.issues) == 1 and len(fake.calls("POST", "/issue")) == 1
    assert fake.issues["SEC-1"]["fields"]["priority"] == {"name": "Highest"}
    assert "updated" in r3.detail


async def test_jira_resolve_reopen_accept_lifecycle():
    fake = FakeJira()
    c = _jira(fake)
    await c.deliver(finding_event())
    r = await c.deliver(finding_event("finding.resolved"))
    assert r.ok and fake.issues["SEC-1"]["status"]["name"] == "Done"
    assert json.loads(fake.calls("POST", "/transitions")[0].content) == {"transition": {"id": "31"}}
    again = await c.deliver(finding_event("finding.resolved"))
    assert again.ok and again.detail.startswith("skipped: ticket already done")
    assert len(fake.calls("POST", "/transitions")) == 1
    r = await c.deliver(finding_event("finding.reopened"))
    assert r.ok and fake.issues["SEC-1"]["status"]["name"] == "To Do"
    r = await c.deliver(finding_event("finding.accepted", status="accepted", note="compensating WAF"))
    assert r.ok and "commented" in r.detail
    last = json.dumps(fake.comments["SEC-1"][-1])
    assert "accepted" in last and "compensating WAF" in last
    # resolve for a finding with no ticket is a clean no-op
    other = await c.deliver(finding_event("finding.resolved", fid="99999999-2222-4333-8444-555555555555"))
    assert other.ok and "no ticket" in other.detail


async def test_jira_done_transition_by_name_and_resolution():
    fake = FakeJira()
    c = _jira(fake, {**JIRA_CFG, "done_transition": "Done", "done_resolution": "Fixed"})
    await c.deliver(finding_event())
    await c.deliver(finding_event("finding.resolved"))
    body = json.loads(fake.calls("POST", "/transitions")[0].content)
    assert body == {"transition": {"id": "31"}, "fields": {"resolution": {"name": "Fixed"}}}


async def test_jira_datacenter_v2_pat_and_wiki_markup():
    fake = FakeJira(base="https://jira.corp.example", version="2")
    c = _jira(fake, {"base_url": "https://jira.corp.example", "deployment": "datacenter",
                     "project_key": "OPS"}, {"pat": "PAT-xyz"})
    res = await c.deliver(finding_event())
    assert res.ok and res.external_id == "SEC-1"
    req = fake.calls("POST", "/rest/api/2/issue")[0]
    assert req.headers["authorization"] == "Bearer PAT-xyz"
    desc = json.loads(req.content)["fields"]["description"]
    assert isinstance(desc, str) and "h3. Why it matters" in desc and f"paddock-{FID}" in desc
    await c.deliver(finding_event("finding.accepted"))
    assert isinstance(fake.comments["SEC-1"][0], str)
    assert fake.calls("GET", "/rest/api/2/search")


async def test_jira_errors_are_mapped_and_scrubbed():
    fake = FakeJira()
    fake.fail_with = 401
    r = await _jira(fake).deliver(finding_event())
    assert not r.ok and not r.retryable and r.status_code == 401
    fake.fail_with = 503
    r = await _jira(fake).deliver(finding_event())
    assert not r.ok and r.retryable
    fake.fail_with, fake.fail_body = 400, {"errorMessages": ["bad token jira-TOKEN-123 echoed"]}
    r = await _jira(fake).deliver(finding_event())
    assert not r.ok and not r.retryable
    assert "jira-TOKEN-123" not in r.detail and "****" in r.detail


async def test_jira_unsafe_url_refused_without_request():
    fake = FakeJira()
    c = _jira(fake, {**JIRA_CFG, "base_url": "https://blocked.invalid"})
    r = await c.deliver(finding_event())
    assert not r.ok and not r.retryable and "unsafe URL" in r.detail
    assert fake.requests == []


async def test_jira_real_netsafety_blocks_metadata(monkeypatch):
    monkeypatch.undo()                                          # real validator
    fake = FakeJira()
    c = _jira(fake, {**JIRA_CFG, "base_url": "https://169.254.169.254"})
    r = await c.deliver(finding_event())
    assert not r.ok and "unsafe URL" in r.detail and fake.requests == []
    c.bind(allow_private=True)
    r = await c.deliver(finding_event())
    assert not r.ok and fake.requests == []                    # metadata is never allowed


async def test_jira_test_button():
    fake = FakeJira()
    h = await _jira(fake).test()
    assert h.ok and "Paddock Bot" in h.detail and "SEC" in h.detail
    fake.fail_with = 401
    h = await _jira(fake).test()
    assert not h.ok and "jira-TOKEN" not in h.detail


async def test_jira_loop_prevention_origin():
    fake = FakeJira()
    c = _jira(fake)
    await c.deliver(finding_event())
    echo = finding_event("finding.resolved", origin={"kind": "jira", "external_id": "SEC-1"})
    r = await c.deliver(echo)
    assert r.ok and "originated" in r.detail
    assert not fake.calls("POST", "/transitions")
    # a bound connector skips before touching the network
    c2 = _jira(fake).bind(integration_id="aaaaaaaa-0000-4000-8000-000000000001")
    n = len(fake.requests)
    r = await c2.deliver(finding_event("finding.resolved",
                                       origin={"integration_id": "aaaaaaaa-0000-4000-8000-000000000001"}))
    assert r.ok and "originated" in r.detail and len(fake.requests) == n
    # ...but a change that came from ANOTHER integration is delivered
    r = await c2.deliver(finding_event("finding.resolved",
                                       origin={"integration_id": "bbbbbbbb-0000-4000-8000-000000000002"}))
    assert r.ok and "closed" in r.detail


async def test_jira_integration_test_event_and_unrelated_events():
    fake = FakeJira()
    c = _jira(fake)
    assert (await c.deliver(Event(type="integration.test", title="t"))).ok
    r = await c.deliver(Event(type="scan.completed", title="s"))
    assert r.ok and r.detail.startswith("skipped")
    r = await c.deliver(Event(type="finding.opened", title="x", data={}))
    assert not r.ok and not r.retryable


# -- Jira inbound ------------------------------------------------------------- #

async def test_jira_inbound_signature_ok_and_mapping():
    c = _jira(FakeJira())
    body = jira_webhook("SEC-1", "Done")
    ups = await c.handle_inbound({"X-Hub-Signature": "sha256=" + sign("whsec-jira", body)}, body)
    assert len(ups) == 1
    u = ups[0]
    assert isinstance(u, TicketInboundUpdate)
    assert (u.external_id, u.finding_id, u.status, u.actor, u.external_status) == \
        ("SEC-1", FID, "fixed", "Alice", "Done")


@pytest.mark.parametrize("sig", [None, "sha256=" + "0" * 64, "sha1=abc", "garbage"])
async def test_jira_inbound_bad_signature(sig):
    c = _jira(FakeJira())
    body = jira_webhook()
    headers = {"X-Hub-Signature": sig} if sig else {}
    c.inbound_token_verified = True          # a token does NOT excuse a bad signature
    with pytest.raises(PermissionError):
        await c.handle_inbound(headers, body)


async def test_jira_inbound_token_mode_without_secret():
    c = _jira(FakeJira(), secrets={"api_token": "t"})
    body = jira_webhook()
    with pytest.raises(PermissionError):
        await c.handle_inbound({}, body)
    c.inbound_token_verified = True
    assert (await c.handle_inbound({}, body))[0].status == "fixed"


@pytest.mark.parametrize("status,resolution,expected", [
    ("Done", None, "fixed"),
    ("Done", "Won't Do", "accepted"),
    ("Done", "Not a Bug", "false_positive"),
    ("Done", "Duplicate", None),
    ("In Progress", None, "triaged"),
    ("To Do", None, "open"),
])
async def test_jira_state_mapping(status, resolution, expected):
    c = _jira(FakeJira(), secrets={})
    c.inbound_token_verified = True
    ups = await c.handle_inbound({}, jira_webhook(status=status, resolution=resolution))
    assert (ups[0].status if ups else None) == expected


async def test_jira_status_map_override_changelog_and_comments():
    c = _jira(FakeJira(), {**JIRA_CFG, "status_map": {"In Progress": "fixed", "bogus": "nope"}}, {})
    c.inbound_token_verified = True
    assert (await c.handle_inbound({}, jira_webhook(status="In Progress")))[0].status == "fixed"
    # an edit that did not touch status is not a status change
    assert await c.handle_inbound({}, jira_webhook(changelog_field=None)) == []
    ups = await c.handle_inbound({}, jira_webhook(changelog_field=None, comment="patched on prod",
                                                  event="comment_created"))
    assert ups[0].comment == "patched on prod" and ups[0].status is None and ups[0].actor == "Alice"
    # our own comments are not echoed back as notes
    assert await c.handle_inbound({}, jira_webhook(changelog_field=None, comment="[Paddock] x",
                                                   event="comment_created")) == []
    assert await c.handle_inbound({}, jira_webhook(event="jira:issue_created")) == []
    with pytest.raises(ValueError):
        await c.handle_inbound({}, b"not json")
    assert c.delivery_id({"X-Atlassian-Webhook-Identifier": "abc"}, b"") == "abc"


def test_hmac_helper_is_strict():
    body = b'{"a":1}'
    good = sign("k", body)
    assert verify_hmac_sha256("k", body, good)
    assert verify_hmac_sha256("k", body, "sha256=" + good.upper())
    assert not verify_hmac_sha256("k", body, "sha512=" + good)
    assert not verify_hmac_sha256("k", body + b" ", good)
    assert not verify_hmac_sha256("k", body, "")


# --------------------------------------------------------------------------- #
# ServiceNow
# --------------------------------------------------------------------------- #

SN_CFG = {"instance_url": "https://acme.service-now.com", "username": "paddock",
          "assignment_group": "Security Ops"}
SN_SECRETS = {"password": "sn-PASSWORD-9", "inbound_secret": "sn-inbound-shared"}


def _sn(fake: FakeServiceNow, cfg=None, secrets=None) -> ServiceNowConnector:
    return ServiceNowConnector(SN_CFG if cfg is None else cfg, SN_SECRETS if secrets is None else secrets, httpx.AsyncClient(transport=fake.transport()))


async def test_servicenow_create_update_resolve_reopen():
    fake = FakeServiceNow()
    c = _sn(fake)
    r = await c.deliver(finding_event(severity="critical"))
    assert r.ok
    rec = fake.records[r.external_id]
    assert r.external_url == f"https://acme.service-now.com/incident.do?sys_id={r.external_id}"
    assert rec["correlation_id"] == f"paddock-{FID}" and rec["impact"] == 1 and rec["urgency"] == 1
    assert rec["assignment_group"] == "Security Ops"
    assert "Why it matters" in rec["description"] and "shop.example.com" in rec["description"]
    assert fake.calls("POST")[0].headers["authorization"] == basic("paddock", "sn-PASSWORD-9")
    # idempotent: second "opened" updates the same record
    r2 = await c.deliver(finding_event())
    assert r2.external_id == r.external_id and len(fake.records) == 1 and len(fake.calls("POST")) == 1
    r3 = await c.deliver(finding_event("finding.resolved"))
    assert r3.ok and rec["state"] == "6" and rec["close_code"] == "Solution provided"
    assert (await c.deliver(finding_event("finding.resolved"))).detail.startswith("skipped")
    r4 = await c.deliver(finding_event("finding.reopened"))
    assert r4.ok and rec["state"] == "2" and rec["_work_notes"]
    await c.deliver(finding_event("finding.accepted", status="accepted"))
    assert "accepted" in rec["_work_notes"][-1]


async def test_servicenow_oauth_and_vulnerable_item_table():
    fake = FakeServiceNow(table="sn_vul_vulnerable_item")
    c = _sn(fake, {"instance_url": "https://acme.service-now.com", "table": "sn_vul_vulnerable_item",
                   "auth_method": "oauth"}, {"client_id": "cid", "client_secret": "cs3cr3t"})
    r = await c.deliver(finding_event())
    assert r.ok and "sn_vul_vulnerable_item.do" in r.external_url
    await c.deliver(finding_event("finding.resolved"))
    assert fake.records[r.external_id]["state"] == "3"
    assert fake.token_calls == 1
    assert all(req.headers["authorization"] == "Bearer tok-abc" for req in fake.calls("GET"))
    bad = _sn(FakeServiceNow(), {**SN_CFG, "auth_method": "oauth"}, {"client_id": "c", "client_secret": "wrong"})
    res = await bad.deliver(finding_event())
    assert not res.ok and not res.retryable and "wrong" not in res.detail


async def test_servicenow_rejects_bad_table_name():
    r = await _sn(FakeServiceNow(), {**SN_CFG, "table": "incident?sysparm_x=1"}).deliver(finding_event())
    assert not r.ok and not r.retryable


async def test_servicenow_inbound_secret_header():
    c = _sn(FakeServiceNow())
    body = json.dumps({"sys_id": "a" * 32, "number": "INC1", "table": "incident", "state": "6",
                       "state_label": "Resolved", "correlation_id": f"paddock-{FID}",
                       "updated_by": "dave"}).encode()
    ups = await c.handle_inbound({"X-Paddock-Secret": "sn-inbound-shared"}, body)
    assert ups[0].status == "fixed" and ups[0].finding_id == FID and ups[0].external_status == "Resolved"
    for hdrs in ({}, {"X-Paddock-Secret": "nope"}, {"X-Other": "sn-inbound-shared"}):
        with pytest.raises(PermissionError):
            await c.handle_inbound(hdrs, body)


@pytest.mark.parametrize("rec,expected", [
    ({"state": "1"}, "open"),
    ({"state": "2"}, "triaged"),
    ({"state": "6"}, "fixed"),
    ({"state": "7", "close_code": "Risk Accepted"}, "accepted"),
    ({"state": "6", "close_code": "False positive"}, "false_positive"),
    ({"state": "8"}, "accepted"),
    ({"state": "99"}, None),
])
async def test_servicenow_state_mapping(rec, expected):
    c = _sn(FakeServiceNow(), secrets={})
    c.inbound_token_verified = True
    body = json.dumps({"sys_id": "b" * 32, **rec}).encode()
    ups = await c.handle_inbound({}, body)
    assert (ups[0].status if ups else None) == expected


async def test_servicenow_override_batch_and_table_filter():
    c = _sn(FakeServiceNow(), {**SN_CFG, "status_map": {"Awaiting Patch": "triaged"}}, {})
    c.inbound_token_verified = True
    body = json.dumps([
        {"sys_id": "c" * 32, "state": "18", "state_label": "Awaiting Patch"},
        {"sys_id": "d" * 32, "table": "change_request", "state": "6"},
        {"sys_id": "e" * 32, "comment": "patched"},
        {"sys_id": "f" * 32, "comment": "[Paddock] ours"},
    ]).encode()
    ups = await c.handle_inbound({}, body)
    assert [(u.external_id[0], u.status, u.comment) for u in ups] == [("c", "triaged", None), ("e", None, "patched")]


# --------------------------------------------------------------------------- #
# Linear
# --------------------------------------------------------------------------- #

LIN_CFG = {"team_id": "team-1", "label_ids": ["lbl-sec"], "label_map": {"critical": "lbl-crit"}}
LIN_SECRETS = {"api_key": "lin_api_KEY123", "webhook_secret": "lin-whsec"}


def _lin(fake: FakeLinear, cfg=None, secrets=None) -> LinearConnector:
    return LinearConnector(LIN_CFG if cfg is None else cfg, LIN_SECRETS if secrets is None else secrets, httpx.AsyncClient(transport=fake.transport()))


async def test_linear_create_idempotent_close_reopen_comment():
    fake = FakeLinear()
    c = _lin(fake)
    r = await c.deliver(finding_event(severity="critical"))
    assert r.ok and r.external_url.endswith("ENG-1") and "ENG-1" in r.detail
    issue = fake.issues[r.external_id]
    assert issue["priority"] == 1 and issue["labelIds"] == ["lbl-crit", "lbl-sec"]
    assert f"paddock-{FID}" in issue["description"] and "### Why it matters" in issue["description"]
    assert fake.requests[0].headers["authorization"] == "lin_api_KEY123"
    r2 = await _lin(fake).deliver(finding_event())          # fresh instance: found by marker
    assert r2.external_id == r.external_id and fake.ops.count("create") == 1
    await c.deliver(finding_event("finding.resolved"))
    assert issue["stateId"] == "st-done"
    assert (await c.deliver(finding_event("finding.resolved"))).detail.startswith("skipped")
    await c.deliver(finding_event("finding.reopened"))
    assert issue["stateId"] == "st-todo"
    await c.deliver(finding_event("finding.accepted"))
    assert fake.comments[-1]["issueId"] == r.external_id


async def test_linear_bearer_for_oauth_and_errors():
    fake = FakeLinear()
    await _lin(fake, secrets={"api_key": "oauth-token"}).deliver(finding_event())
    assert fake.requests[0].headers["authorization"] == "Bearer oauth-token"
    fake.rate_limited = True
    r = await _lin(fake).deliver(finding_event())
    assert not r.ok and r.retryable
    r = await _lin(FakeLinear(), secrets={}).deliver(finding_event())
    assert not r.ok and not r.retryable


async def test_linear_test_button():
    h = await _lin(FakeLinear()).test()
    assert h.ok and "Paddock Bot" in h.detail


async def test_linear_loop_prevention():
    fake = FakeLinear()
    c = _lin(fake)
    r = await c.deliver(finding_event())
    res = await c.deliver(finding_event("finding.resolved", origin={"kind": "linear", "external_id": r.external_id}))
    assert "originated" in res.detail and fake.issues[r.external_id]["stateId"] == "st-todo"
    # identifier form (ENG-1) is recognised too
    res = await c.deliver(finding_event("finding.resolved", origin={"kind": "linear", "external_id": "ENG-1"}))
    assert "originated" in res.detail


async def test_linear_inbound_signature_timestamp_mapping():
    c = _lin(FakeLinear())
    body = linear_webhook("iss-1", description=f"x `paddock-{FID}`")
    ups = await c.handle_inbound({"Linear-Signature": sign("lin-whsec", body)}, body)
    assert (ups[0].external_id, ups[0].status, ups[0].finding_id, ups[0].actor) == ("iss-1", "fixed", FID, "Carol")
    with pytest.raises(PermissionError):
        await c.handle_inbound({"Linear-Signature": sign("wrong", body)}, body)
    with pytest.raises(PermissionError):
        await c.handle_inbound({}, body)
    old = linear_webhook("iss-1", ts_ms=1_000)
    with pytest.raises(PermissionError):
        await c.handle_inbound({"Linear-Signature": sign("lin-whsec", old)}, old)


@pytest.mark.parametrize("stype,cfg,expected", [
    ("completed", {}, "fixed"),
    ("started", {}, "triaged"),
    ("unstarted", {}, "open"),
    ("backlog", {}, "open"),
    ("canceled", {}, "accepted"),
    ("canceled", {"canceled_status": "false_positive"}, "false_positive"),
    ("started", {"status_map": {"In Review": "fixed"}}, "fixed"),
])
async def test_linear_state_mapping(stype, cfg, expected):
    c = _lin(FakeLinear(), {**LIN_CFG, **cfg}, {"api_key": "k"})
    c.inbound_token_verified = True
    body = linear_webhook("iss-1", stype, "In Review" if "status_map" in cfg else "S")
    assert (await c.handle_inbound({}, body))[0].status == expected


async def test_linear_inbound_ignores_non_state_updates_and_takes_comments():
    c = _lin(FakeLinear(), secrets={"api_key": "k"})
    c.inbound_token_verified = True
    assert await c.handle_inbound({}, linear_webhook("iss-1", state_changed=False)) == []
    comment = json.dumps({"action": "create", "type": "Comment", "actor": {"name": "Eve"},
                          "data": {"body": "fixed in v2", "issueId": "iss-1", "user": {"name": "Eve"}}}).encode()
    ups = await c.handle_inbound({}, comment)
    assert ups[0].comment == "fixed in v2" and ups[0].status is None
    own = json.dumps({"action": "create", "type": "Comment",
                      "data": {"body": "[Paddock] verified", "issueId": "iss-1"}}).encode()
    assert await c.handle_inbound({}, own) == []


def test_no_secret_in_repr_or_describe():
    for cls in (JiraConnector, ServiceNowConnector, LinearConnector):
        d = json.dumps(cls.describe())
        for v in list(JIRA_SECRETS.values()) + list(SN_SECRETS.values()) + list(LIN_SECRETS.values()):
            assert v not in d
