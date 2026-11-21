"""Integrations core, no database: schema validation, matching, signing,
connector payloads, outbound safety and error mapping."""
from __future__ import annotations

import json
import random
import smtplib
from datetime import datetime, timezone

import httpx
import pytest

from app.integrations import Event, netsafety, service
from app.integrations.base import REGISTRY
from app.integrations.configschema import ConfigError, validate_config
from app.integrations.connectors import email as email_mod
from app.integrations.connectors import pagerduty, slack, teams, webhook
from app.integrations.outbound import GuardedAsyncClient, make_client, result_from_response, scrub

from .integrations_helpers import PUBLIC_IP, Recorder, fake_dns  # noqa: F401

service.load_connectors()


def _finding_event(**kw) -> Event:
    base = dict(
        type="finding.opened", title="Exposed .git directory", summary="Source code is downloadable.",
        severity="high", url="http://dash.test/findings?focus=f1",
        data={"finding_id": "f1", "asset": "app.example.com", "asset_kind": "subdomain",
              "rule_id": "exposed-git", "rule_source": "exposed_file", "owner": "payments", "tags": ["prod"]},
        occurred_at=datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc),
    )
    base.update(kw)
    return Event(**base)


# --------------------------------------------------------------------------- #
# registry
# --------------------------------------------------------------------------- #

def test_all_push_connectors_registered_and_describable():
    for kind in ("webhook", "slack", "teams", "pagerduty", "email"):
        d = REGISTRY[kind].describe()
        assert d["capabilities"] == ["notify"]
        assert d["config_schema"]["type"] == "object"
        assert d["display_name"]


# --------------------------------------------------------------------------- #
# config schema validator
# --------------------------------------------------------------------------- #

def test_config_validator_fills_defaults_and_rejects_bad_input():
    schema = REGISTRY["email"].config_schema
    ok = validate_config({"host": "smtp.example.com", "from_addr": "a@example.com", "to": ["b@example.com"]}, schema)
    assert ok["port"] == 587 and ok["security"] == "starttls" and ok["subject_prefix"] == "[Paddock]"

    with pytest.raises(ConfigError) as ei:
        validate_config({"host": "bad host!", "port": 70000, "from_addr": "nope", "to": [], "security": "none",
                         "extra": 1}, schema)
    errs = " | ".join(ei.value.errors)
    for frag in ("host: must be a hostname", "port: must be <= 65535", "from_addr: must be an email",
                 "to: needs at least 1", "security: must be one of", "extra: unknown field"):
        assert frag in errs, errs


def test_config_validator_types_and_required():
    schema = {"type": "object", "required": ["url"],
              "properties": {"url": {"type": "string", "format": "uri"}, "n": {"type": "integer"},
                             "flag": {"type": "boolean"}}}
    with pytest.raises(ConfigError) as ei:
        validate_config({"n": True, "flag": "yes"}, schema)
    assert any("url: is required" in e for e in ei.value.errors)
    assert any("n: expected integer" in e for e in ei.value.errors)
    assert any("flag: expected boolean" in e for e in ei.value.errors)
    with pytest.raises(ConfigError):
        validate_config({"url": "ftp://x"}, schema)
    assert validate_config({"url": "https://x.example", "n": None}, schema) == {"url": "https://x.example"}


# --------------------------------------------------------------------------- #
# matching
# --------------------------------------------------------------------------- #

def test_severity_gate():
    assert service.severity_passes("high", "medium")
    assert not service.severity_passes("low", "medium")
    assert service.severity_passes(None, "critical")       # lifecycle events carry no severity


def test_matches_subscription_severity_and_filters():
    ev = _finding_event()
    integ = {"enabled": True, "events": ["finding.opened"], "min_severity": "medium", "filters": {}}
    assert service.matches(integ, ev)
    assert not service.matches({**integ, "enabled": False}, ev)
    assert not service.matches({**integ, "events": ["scan.failed"]}, ev)
    assert not service.matches({**integ, "min_severity": "critical"}, ev)
    assert service.matches({**integ, "filters": {"asset_kinds": ["subdomain"], "owners": ["Payments"]}}, ev)
    assert not service.matches({**integ, "filters": {"asset_kinds": ["ipv4"]}}, ev)
    assert service.matches({**integ, "filters": {"tags": ["prod", "pci"]}}, ev)
    assert not service.matches({**integ, "filters": {"tags": ["staging"]}}, ev)
    assert service.matches({**integ, "filters": json.dumps({"assets": ["*.example.com"]})}, ev)
    assert not service.matches({**integ, "filters": {"assets": ["*.corp.internal"]}}, ev)
    # filters narrow: an event without the attribute does not match
    scan = Event(type="finding.opened", title="t", severity="high", data={})
    assert not service.matches({**integ, "filters": {"owners": ["payments"]}}, scan)
    # unknown filter keys are ignored at match time (rejected by the API)
    assert service.matches({**integ, "filters": {"bogus": ["x"]}}, ev)


def test_event_roundtrip_and_stable_ids():
    ev = _finding_event()
    back = service.event_from_dict(json.loads(service.event_payload(ev)))
    assert back.as_dict() == ev.as_dict()
    assert service.stable_event_id("finding.opened:x") == service.stable_event_id("finding.opened:x")
    assert service.stable_event_id("a") != service.stable_event_id("b")


def test_decode_stream_fields_both_encodings():
    assert service.decode_stream_fields({"event": json.dumps({"event": "finding_opened", "finding_id": "1"})}) == \
        {"event": "finding_opened", "finding_id": "1"}
    flat = {"event": "scan_completed", "scan_id": "s", "kind": "http_probe", "target": "a.example"}
    assert service.decode_stream_fields(flat) == flat


async def test_stream_mapper_without_db_rows():
    class NoRows:
        async def fetchrow(self, *a):
            return None

        async def fetchval(self, *a):
            return None

    pool = NoRows()
    ev = await service.event_from_stream(pool, {"event": "scan_failed", "scan_id": "s1", "kind": "nuclei",
                                                "target": "a.example", "error": "boom", "ts": "1700000000"}, "1-0")
    assert ev.type == "scan.failed" and ev.data["error"] == "boom" and ev.severity is None
    assert ev.occurred_at.year == 2023
    again = await service.event_from_stream(pool, {"event": "scan_failed", "scan_id": "s1"}, "2-0")
    assert again.id == ev.id                      # same fact -> same id -> delivered once
    assert await service.event_from_stream(pool, {"event": "scope_added"}, "3-0") is None
    closed = await service.event_from_stream(pool, {"event": json.dumps(
        {"event": "finding_closed", "finding_id": "f", "status": "accepted_risk"})}, "4-0")
    assert closed.type == "finding.accepted"


def test_backoff_is_exponential_capped_and_jittered():
    rng = random.Random(1)
    d1, d2, d3 = (service.backoff_seconds(n, rng=rng) for n in (1, 2, 3))
    assert 27 <= d1 <= 33 and 54 <= d2 <= 66 and 108 <= d3 <= 132
    assert service.backoff_seconds(30, rng=rng) <= 3600 * 1.1


# --------------------------------------------------------------------------- #
# outbound safety
# --------------------------------------------------------------------------- #

async def test_guarded_client_blocks_private_and_metadata(fake_dns):
    rec = Recorder()
    async with make_client(transport=rec.transport) as http:
        for url in ("https://lan.example.com/hook", "https://meta.example.com/", "http://hooks.example.com/"):
            with pytest.raises(netsafety.UnsafeURL):
                await http.post(url, json={})
        assert rec.requests == []
        r = await http.post("https://hooks.example.com/ok", json={})
        assert r.status_code == 200
    async with make_client(allow_private=True, transport=rec.transport) as http:
        assert (await http.post("https://lan.example.com/hook", json={})).status_code == 200
        with pytest.raises(netsafety.UnsafeURL):
            await http.post("https://meta.example.com/", json={})    # metadata: never


async def test_guarded_client_never_follows_redirects(fake_dns):
    rec = Recorder(lambda req: httpx.Response(302, headers={"Location": "http://169.254.169.254/"}))
    async with make_client(transport=rec.transport) as http:
        assert isinstance(http, GuardedAsyncClient)
        r = await http.post("https://hooks.example.com/x", json={})
        assert r.status_code == 302 and len(rec.requests) == 1
    res = result_from_response(r)
    assert not res.ok and not res.retryable and "redirect" in res.detail


async def test_check_host_for_smtp(fake_dns):
    async with make_client() as http:
        await http.check_host("smtp.example.com", 587)
        with pytest.raises(netsafety.UnsafeURL):
            await http.check_host("lan.example.com", 25)


@pytest.mark.parametrize("code,ok,retry", [(200, True, True), (202, True, True), (400, False, False),
                                           (404, False, False), (429, False, True), (503, False, True)])
def test_status_mapping(code, ok, retry):
    res = result_from_response(httpx.Response(code, text="x"))
    assert res.ok is ok and (ok or res.retryable is retry) and res.status_code == code


def test_scrub_removes_echoed_secrets():
    assert "s3cr3t-token" not in scrub("invalid token s3cr3t-token", ["s3cr3t-token"])


# --------------------------------------------------------------------------- #
# webhook
# --------------------------------------------------------------------------- #

async def test_webhook_signs_and_receiver_can_verify(fake_dns):
    rec = Recorder()
    async with make_client(transport=rec.transport) as http:
        c = webhook.WebhookConnector({"url": "https://hooks.example.com/paddock"}, {"signing_secret": "whsec_abc"}, http)
        ev = _finding_event()
        res = await c.deliver(ev)
    assert res.ok
    req = rec.requests[0]
    assert req.headers["Paddock-Event"] == "finding.opened"
    assert req.headers["Paddock-Delivery"] == ev.id
    sig = req.headers["Paddock-Signature"]
    assert sig.startswith("t=") and ",v1=" in sig
    assert webhook.verify_signature("whsec_abc", req.content, sig)
    assert not webhook.verify_signature("wrong", req.content, sig)
    assert not webhook.verify_signature("whsec_abc", req.content + b" ", sig)
    # replay window: 5 minutes
    t = int(sig.split(",")[0][2:])
    assert not webhook.verify_signature("whsec_abc", req.content, sig, now=t + 301)
    assert webhook.verify_signature("whsec_abc", req.content, sig, now=t + 299)
    body = json.loads(req.content)
    assert body["id"] == ev.id and body["data"]["finding_id"] == "f1"
    assert "whsec_abc" not in req.content.decode() and "whsec_abc" not in res.detail


def test_webhook_signature_known_vector():
    # hmac_sha256("secret", "1700000000.{}") -- lets receivers check their implementation
    assert webhook.signature_header("secret", b"{}", 1700000000) == \
        "t=1700000000,v1=" + webhook.compute_signature("secret", b"{}", 1700000000)
    import hashlib
    import hmac
    assert webhook.compute_signature("secret", b"{}", 1700000000) == \
        hmac.new(b"secret", b"1700000000.{}", hashlib.sha256).hexdigest()


async def test_webhook_missing_secret_and_unsafe_url(fake_dns):
    async with make_client() as http:
        c = webhook.WebhookConnector({"url": "https://hooks.example.com/"}, {}, http)
        res = await c.deliver(_finding_event())
        assert not res.ok and not res.retryable
        c = webhook.WebhookConnector({"url": "https://lan.example.com/"}, {"signing_secret": "x"}, http)
        res = await c.deliver(_finding_event())
        assert not res.ok and not res.retryable and "outbound URL policy" in res.detail


async def test_webhook_network_errors_are_retryable_and_secret_free(fake_dns):
    def boom(req):
        raise httpx.ConnectError(f"cannot connect to {req.url}")
    async with make_client(transport=httpx.MockTransport(boom)) as http:
        c = webhook.WebhookConnector({"url": "https://hooks.example.com/tok123456"}, {"signing_secret": "x"}, http)
        res = await c.deliver(_finding_event())
    assert not res.ok and res.retryable and "tok123456" not in res.detail


# --------------------------------------------------------------------------- #
# slack / teams / pagerduty
# --------------------------------------------------------------------------- #

async def test_slack_block_kit(fake_dns):
    url = "https://hooks.slack.com/services/T000/B000/XXXXSECRET"
    rec = Recorder()
    async with make_client(transport=rec.transport) as http:
        c = slack.SlackConnector({"mention": "<!here>"}, {"webhook_url": url}, http)
        res = await c.deliver(_finding_event(severity="critical"))
    assert res.ok and "XXXXSECRET" not in res.detail
    msg = rec.json()
    assert str(rec.requests[0].url) == url
    assert msg["blocks"][0]["type"] == "header" and "Exposed .git" in msg["blocks"][0]["text"]["text"]
    fields = " ".join(f["text"] for f in msg["blocks"][1]["fields"])
    assert "Critical" in fields and "app.example.com" in fields and "payments" in fields
    assert "<!here>" in msg["text"] and "Why it matters" in msg["blocks"][2]["text"]["text"]
    assert msg["blocks"][-1]["elements"][0]["url"] == "http://dash.test/findings?focus=f1"
    low = slack.build_message(_finding_event(severity="low"), mention="<!here>")
    assert "<!here>" not in low["text"]


async def test_slack_dead_hook_is_not_retried(fake_dns):
    rec = Recorder(lambda req: httpx.Response(404, text="no_service"))
    async with make_client(transport=rec.transport) as http:
        res = await slack.SlackConnector({}, {"webhook_url": "https://hooks.slack.com/services/x"}, http).deliver(
            _finding_event())
    assert not res.ok and not res.retryable and "no_service" in res.detail


async def test_teams_adaptive_card(fake_dns):
    rec = Recorder(lambda req: httpx.Response(202))
    url = "https://prod-00.westus.logic.azure.com:443/workflows/abc/triggers/manual/paths/invoke?sig=SIGSECRET"
    async with make_client(transport=rec.transport) as http:
        res = await teams.TeamsConnector({}, {"webhook_url": url}, http).deliver(_finding_event())
    assert res.ok and res.status_code == 202 and "SIGSECRET" not in res.detail
    body = rec.json()
    att = body["attachments"][0]
    assert body["type"] == "message" and att["contentType"] == "application/vnd.microsoft.card.adaptive"
    card = att["content"]
    assert card["type"] == "AdaptiveCard" and card["version"] == "1.4"
    facts = {f["title"]: f["value"] for f in card["body"][2]["facts"]}
    assert facts["Severity"] == "High" and "app.example.com" in facts["Asset"]
    assert card["actions"][0]["type"] == "Action.OpenUrl"


async def test_pagerduty_trigger_and_resolve_share_dedup_key(fake_dns):
    rec = Recorder(lambda req: httpx.Response(202, json={"status": "success", "dedup_key": "f1"}))
    async with make_client(transport=rec.transport) as http:
        c = pagerduty.PagerDutyConnector({"region": "eu"}, {"routing_key": "R" * 32}, http)
        r1 = await c.deliver(_finding_event())
        r2 = await c.deliver(_finding_event(type="finding.resolved", title="Resolved: x"))
    assert r1.ok and r2.ok and r1.external_id == "f1"
    t, r = rec.json(0), rec.json(1)
    assert str(rec.requests[0].url) == "https://events.eu.pagerduty.com/v2/enqueue"
    assert t["event_action"] == "trigger" and t["dedup_key"] == "f1" and t["payload"]["severity"] == "error"
    assert t["payload"]["source"] == "app.example.com" and t["links"][0]["href"].endswith("focus=f1")
    assert r["event_action"] == "resolve" and r["dedup_key"] == "f1" and "payload" not in r
    assert "R" * 32 not in r1.detail


async def test_pagerduty_test_event_triggers_then_resolves(fake_dns):
    rec = Recorder(lambda req: httpx.Response(202, json={"status": "success"}))
    async with make_client(transport=rec.transport) as http:
        h = await pagerduty.PagerDutyConnector({}, {"routing_key": "k" * 32}, http).test()
    assert h.ok and [rec.json(i)["event_action"] for i in (0, 1)] == ["trigger", "resolve"]
    assert rec.json(0)["dedup_key"] == rec.json(1)["dedup_key"]


async def test_pagerduty_bad_key_not_retryable(fake_dns):
    rec = Recorder(lambda req: httpx.Response(400, json={"status": "invalid event", "message": "Invalid routing key"}))
    async with make_client(transport=rec.transport) as http:
        res = await pagerduty.PagerDutyConnector({}, {"routing_key": "bad"}, http).deliver(_finding_event())
    assert not res.ok and not res.retryable


# --------------------------------------------------------------------------- #
# email
# --------------------------------------------------------------------------- #

class FakeSMTP:
    instances: list["FakeSMTP"] = []
    offer_starttls = True
    fail_login = False

    def __init__(self, host, port, timeout=None, context=None):
        self.host, self.port, self.calls, self.sent = host, port, [], []
        FakeSMTP.instances.append(self)

    def ehlo(self):
        self.calls.append("ehlo")

    def has_extn(self, name):
        return self.offer_starttls and name == "starttls"

    def starttls(self, context=None):
        assert context is not None and context.verify_mode.name == "CERT_REQUIRED"
        self.calls.append("starttls")

    def login(self, user, pw):
        if self.fail_login:
            raise smtplib.SMTPAuthenticationError(535, b"bad creds")
        self.calls.append(f"login:{user}")

    def noop(self):
        self.calls.append("noop")
        return 250, b"OK"

    def send_message(self, msg):
        self.calls.append("send")
        self.sent.append(msg)
        return {}

    def quit(self):
        self.calls.append("quit")


@pytest.fixture
def fake_smtp(monkeypatch):
    FakeSMTP.instances = []
    FakeSMTP.offer_starttls = True
    FakeSMTP.fail_login = False
    monkeypatch.setattr(email_mod.EmailConnector, "smtp_class", FakeSMTP)
    monkeypatch.setattr(email_mod.EmailConnector, "smtp_ssl_class", FakeSMTP)
    return FakeSMTP


_EMAIL_CFG = {"host": "smtp.example.com", "port": 587, "security": "starttls",
              "from_addr": "paddock@example.com", "to": ["sec@example.com", "oncall@example.com"]}


async def test_email_starttls_login_and_multipart(fake_dns, fake_smtp):
    async with make_client() as http:
        c = email_mod.EmailConnector(_EMAIL_CFG, {"username": "u", "password": "pw-secret"}, http)
        res = await c.deliver(_finding_event(title="Bad\r\nBcc: evil@x.test"))
    assert res.ok, res.detail
    s = fake_smtp.instances[0]
    assert s.calls == ["ehlo", "starttls", "ehlo", "login:u", "send", "quit"]
    msg = s.sent[0]
    assert "\n" not in msg["Subject"] and msg["Subject"].startswith("[Paddock] [High]")
    assert msg["Bcc"] is None
    assert msg["To"] == "sec@example.com, oncall@example.com"
    kinds = [p.get_content_type() for p in msg.iter_parts()]
    assert kinds == ["text/plain", "text/html"]
    html = msg.get_body(("html",)).get_content()
    assert "app.example.com" in html and "Open in Paddock" in html
    assert "pw-secret" not in msg.as_string() and "pw-secret" not in res.detail


async def test_email_html_is_escaped(fake_dns, fake_smtp):
    msg = email_mod.build_message(_finding_event(title="<script>alert(1)</script>"),
                                  from_addr="a@example.com", to=["b@example.com"])
    assert "<script>" not in msg.get_body(("html",)).get_content()


async def test_email_refuses_plaintext_and_maps_auth_failure(fake_dns, fake_smtp):
    async with make_client() as http:
        fake_smtp.offer_starttls = False
        res = await email_mod.EmailConnector(_EMAIL_CFG, {}, http).deliver(_finding_event())
        assert not res.ok and not res.retryable and "STARTTLS" in res.detail
        fake_smtp.offer_starttls = True
        fake_smtp.fail_login = True
        res = await email_mod.EmailConnector(_EMAIL_CFG, {"username": "u", "password": "p"}, http).deliver(
            _finding_event())
        assert not res.ok and not res.retryable and "authentication" in res.detail


async def test_email_test_is_handshake_only_and_host_is_policed(fake_dns, fake_smtp):
    async with make_client() as http:
        h = await email_mod.EmailConnector(_EMAIL_CFG, {"username": "u", "password": "p"}, http).test()
        assert h.ok and fake_smtp.instances[-1].calls == ["ehlo", "starttls", "ehlo", "login:u", "noop", "quit"]
        lan = {**_EMAIL_CFG, "host": "lan.example.com"}
        res = await email_mod.EmailConnector(lan, {}, http).deliver(_finding_event())
        assert not res.ok and "outbound URL policy" in res.detail
    async with make_client(allow_private=True) as http:
        res = await email_mod.EmailConnector({**_EMAIL_CFG, "host": "lan.example.com"}, {}, http).deliver(
            _finding_event())
        assert res.ok


async def test_email_connection_error_is_retryable(fake_dns, monkeypatch):
    class Refuse:
        def __init__(self, *a, **k):
            raise ConnectionRefusedError("nope")
    monkeypatch.setattr(email_mod.EmailConnector, "smtp_class", Refuse)
    async with make_client() as http:
        res = await email_mod.EmailConnector(_EMAIL_CFG, {}, http).deliver(_finding_event())
    assert not res.ok and res.retryable


def test_public_ip_constant_is_public():
    import ipaddress

    from app import scope
    assert not scope.is_internal(ipaddress.ip_address(PUBLIC_IP))
