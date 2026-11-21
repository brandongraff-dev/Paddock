"""Alert matching + delivery tests. No network, no DB."""
from __future__ import annotations

import pytest

from app.alerts import AlertDispatcher, rule_matches

from .conftest import FakeAlertDB, FakePoster


def _change(**over):
    base = {
        "id": "11111111-1111-1111-1111-111111111111",
        "change_type": "secret_found",
        "severity": "high",
        "asset_kind": "secret_candidate",
        "asset_value": "aws-key",
        "summary": "secret found: aws-key",
    }
    base.update(over)
    return base


# ----------------------------------------------------------------------------
# matching
# ----------------------------------------------------------------------------

def test_wildcard_match():
    assert rule_matches({}, _change()) is True
    assert rule_matches({}, _change(change_type="cert_added", severity="info")) is True


def test_min_severity():
    m = {"min_severity": "high"}
    assert rule_matches(m, _change(severity="high")) is True
    assert rule_matches(m, _change(severity="critical")) is True
    assert rule_matches(m, _change(severity="medium")) is False
    assert rule_matches(m, _change(severity="info")) is False


def test_change_types():
    m = {"change_types": ["secret_found", "exposure_increased"]}
    assert rule_matches(m, _change(change_type="secret_found")) is True
    assert rule_matches(m, _change(change_type="exposure_increased")) is True
    assert rule_matches(m, _change(change_type="port_opened")) is False


def test_kinds():
    m = {"kinds": ["secret_candidate"]}
    assert rule_matches(m, _change(asset_kind="secret_candidate")) is True
    assert rule_matches(m, _change(asset_kind="endpoint")) is False


def test_and_of_predicates():
    m = {"change_types": ["secret_found"], "min_severity": "high", "kinds": ["secret_candidate"]}
    assert rule_matches(m, _change()) is True
    # fails on one predicate → no match.
    assert rule_matches(m, _change(severity="low")) is False
    assert rule_matches(m, _change(asset_kind="endpoint")) is False
    assert rule_matches(m, _change(change_type="port_opened")) is False


# ----------------------------------------------------------------------------
# delivery
# ----------------------------------------------------------------------------

def _cfg():
    from app.config import Config
    return Config()


async def test_log_delivery_recorded_sent():
    rules = [{"id": "r-log", "name": "all-to-log", "channel": "log", "target": None, "match": {}}]
    db = FakeAlertDB(rules)
    disp = AlertDispatcher(db, _cfg(), post_fn=FakePoster())
    counts = await disp.dispatch([_change()])

    assert counts["sent"] == 1 and counts["attempted"] == 1
    assert db.deliveries[0]["status"] == "sent"
    assert db.deliveries[0]["channel"] == "log"
    assert db.bumped == ["r-log"]


async def test_webhook_delivery_posts_to_target_only():
    target = "https://hooks.example.com/ingest"
    rules = [{"id": "r-wh", "name": "wh", "channel": "webhook", "target": target,
              "match": {"min_severity": "high"}}]
    db = FakeAlertDB(rules)
    poster = FakePoster(ok=True, status=200, body="accepted")
    disp = AlertDispatcher(db, _cfg(), post_fn=poster)

    counts = await disp.dispatch([_change(), _change(id="2", severity="low")])

    # Only the high-severity change matched.
    assert counts["sent"] == 1
    assert len(poster.calls) == 1
    call = poster.calls[0]
    # SAFETY: the POST goes to rule.target and nowhere else.
    assert call["url"] == target
    assert set(call["payload"].keys()) == {"change", "rule", "ts"}
    assert call["payload"]["change"]["change_type"] == "secret_found"
    assert db.deliveries[0]["status"] == "sent"
    assert "200" in db.deliveries[0]["response"]


async def test_slack_delivery_uses_text_shape():
    target = "https://hooks.slack.com/services/XXX"
    rules = [{"id": "r-sl", "name": "sl", "channel": "slack", "target": target, "match": {}}]
    db = FakeAlertDB(rules)
    poster = FakePoster()
    disp = AlertDispatcher(db, _cfg(), post_fn=poster)

    await disp.dispatch([_change()])

    assert poster.calls[0]["url"] == target
    assert list(poster.calls[0]["payload"].keys()) == ["text"]
    assert "secret_found" in poster.calls[0]["payload"]["text"]


async def test_webhook_failure_recorded_failed():
    rules = [{"id": "r-wh", "name": "wh", "channel": "webhook",
              "target": "https://hooks.example.com/x", "match": {}}]
    db = FakeAlertDB(rules)
    poster = FakePoster(ok=False, status=500, body="boom")
    disp = AlertDispatcher(db, _cfg(), post_fn=poster)

    counts = await disp.dispatch([_change()])
    assert counts["failed"] == 1
    assert db.deliveries[0]["status"] == "failed"


async def test_missing_target_is_suppressed_not_posted():
    rules = [{"id": "r-wh", "name": "wh", "channel": "webhook", "target": None, "match": {}}]
    db = FakeAlertDB(rules)
    poster = FakePoster()
    disp = AlertDispatcher(db, _cfg(), post_fn=poster)

    counts = await disp.dispatch([_change()])
    assert counts["suppressed"] == 1
    assert poster.calls == []  # nothing was sent anywhere
    assert db.deliveries[0]["status"] == "suppressed"


async def test_disabled_rule_never_fires():
    rules = [{"id": "r", "name": "off", "channel": "log", "target": None,
              "match": {}, "enabled": False}]
    db = FakeAlertDB(rules)
    disp = AlertDispatcher(db, _cfg(), post_fn=FakePoster())
    counts = await disp.dispatch([_change()])
    assert counts["attempted"] == 0
    assert db.deliveries == []
