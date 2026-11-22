"""HTTP surface of the Wargame twin + change gate (correlation service).

The routes are driven in-process through ASGI. ``twin_store`` is faked so the
tests need no database; the DB-backed behaviours (RLS isolation, replace vs
append) live in ``test_twin_store_db.py``.
"""
from __future__ import annotations

import json
from typing import Any

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app import main as main_mod
from app.engine.wargame import store, twin_store
from app.engine.wargame.environment import Environment
from app.engine.wargame.model import (
    Action, Edge, Node, NodeRole, PortRange, Proto, Rule, RuleSet,
)

PG = PortRange.single(Proto.TCP, 5432)


def _env(with_allow: bool) -> Environment:
    """entry (10.9.0.0/24) -> jewel (10.1.0.0/24) across sg-db."""
    env = Environment()
    env.add_node(Node("entry", NodeRole.ENTRY, ("10.9.0.0/24",)))
    env.add_node(Node("jewel", NodeRole.CROWN_JEWEL, ("10.1.0.0/24",)))
    rules = []
    if with_allow:
        rules.append(Rule("aws_security_group_rule.allow_pg", Action.ALLOW, 0,
                          ("10.9.0.0/24",), ("0.0.0.0/0",), (PG,)))
    env.add_ruleset(RuleSet("sg-db", rules, default_action=Action.DENY))
    env.add_edge(Edge("entry", "jewel", rule_set_id="sg-db", port=PG))
    return env


def _sg_rule_change(address: str, actions: list[str], *, sg: str = "sg-db",
                    cidr: str = "10.9.0.0/24", port: int = 5432) -> dict[str, Any]:
    vals = {
        "type": "ingress", "protocol": "tcp", "from_port": port, "to_port": port,
        "cidr_blocks": [cidr], "security_group_id": sg,
    }
    return {
        "address": address, "type": "aws_security_group_rule",
        "change": {
            "actions": actions,
            "before": vals if "delete" in actions else None,
            "after": None if actions == ["delete"] else vals,
            "after_unknown": {},
        },
    }


def _plan(*changes) -> dict[str, Any]:
    return {"format_version": "1.2", "resource_changes": list(changes)}


@pytest_asyncio.fixture
async def client(monkeypatch):
    monkeypatch.setattr(main_mod.service, "_ready", True)
    # Anything that would persist must never be reached by a read-only call.
    async def _boom(*a, **k):
        raise AssertionError("change-impact must not persist anything")
    for mod, names in ((twin_store, ("persist_rulesets", "persist_topology")),
                       (store, ("persist",))):
        for n in names:
            monkeypatch.setattr(mod, n, _boom)
    async with AsyncClient(transport=ASGITransport(app=main_mod.app),
                           base_url="http://t") as c:
        yield c


def _twin(monkeypatch, env):
    async def _load(db):
        return env
    monkeypatch.setattr(twin_store, "load_environment", _load)


async def test_change_impact_no_twin_is_409(client, monkeypatch):
    _twin(monkeypatch, None)
    r = await client.post("/change-impact", json={"plan": _plan()})
    assert r.status_code == 409
    assert "twin" in r.json()["detail"]


async def test_change_impact_opens_route(client, monkeypatch):
    _twin(monkeypatch, _env(with_allow=False))
    plan = _plan(_sg_rule_change("aws_security_group_rule.new_pg", ["create"]))
    r = await client.post("/change-impact", json={"plan": plan})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["verdict"] == "opens_route_to_crown_jewel"
    assert body["routes_opened"] == [{"entry": "entry", "jewel": "jewel"}]
    assert body["routes_closed"] == []
    assert body["newly_denied_flows"] == [] and body["newly_allowed_flows"] == []
    assert body["complete"] is True
    assert body["affected_boundaries"] == ["sg-db"]
    assert isinstance(body["summary"], str) and body["summary"]


async def test_change_impact_breaks_live_flows(client, monkeypatch):
    _twin(monkeypatch, _env(with_allow=True))
    plan = _plan(_sg_rule_change("aws_security_group_rule.allow_pg", ["delete"]))
    flows = json.dumps([{"src": "10.9.0.5", "dst": "10.1.0.9", "proto": "tcp",
                         "dport": 5432, "state": "established"}])
    r = await client.post("/change-impact",
                          json={"plan": plan, "flows": flows, "flows_format": "generic"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["verdict"] == "breaks_live_flows"
    assert body["routes_closed"] == [{"entry": "entry", "jewel": "jewel"}]
    assert body["newly_denied_flows"] == [{
        "src_ip": "10.9.0.5", "dst_ip": "10.1.0.9", "proto": "tcp",
        "dst_port": 5432, "ruleset_id": "sg-db"}]
    assert body["flows_parsed"] == 1 and body["flows_skipped"] == 0


async def test_change_impact_safe_noop(client, monkeypatch):
    _twin(monkeypatch, _env(with_allow=True))
    r = await client.post("/change-impact", json={"plan": _plan()})
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "safe"
    assert any("no network rule changes" in w for w in body["warnings"])


async def test_change_impact_unmodelled_ruleset_is_a_warning_not_a_500(client, monkeypatch):
    _twin(monkeypatch, _env(with_allow=False))
    plan = _plan(
        _sg_rule_change("aws_security_group_rule.elsewhere", ["create"], sg="sg-unknown"),
        {"address": "aws_instance.web", "type": "aws_instance",
         "change": {"actions": ["create"], "before": None, "after": {}, "after_unknown": {}}},
    )
    r = await client.post("/change-impact", json={"plan": plan})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["complete"] is False       # a safe verdict here is NOT a proof
    assert any("sg-unknown" in w for w in body["warnings"])
    assert any("aws_instance" in w for w in body["warnings"])
    assert "NOT a full proof" in body["summary"]


async def test_change_impact_rejects_bad_input(client, monkeypatch):
    _twin(monkeypatch, _env(with_allow=False))
    assert (await client.post("/change-impact", json={})).status_code == 422
    assert (await client.post("/change-impact", json={"plan": [1, 2]})).status_code == 422
    big = await client.post("/change-impact", json={"plan": {}, "flows": "x" * (8 * 1024 * 1024 + 1)})
    assert big.status_code == 422


async def test_change_impact_error_does_not_leak_internals(client, monkeypatch):
    _twin(monkeypatch, _env(with_allow=False))
    from app.engine.wargame import changegate

    def _explode(*a, **k):
        raise RuntimeError("secret-dsn postgres://user:pw@db/x")
    monkeypatch.setattr(changegate, "evaluate_change", _explode)
    r = await client.post("/change-impact", json={"plan": _plan()})
    assert r.status_code == 422
    assert "secret" not in r.text and "postgres" not in r.text


# -- ingest-config / set-topology -------------------------------------------

async def test_ingest_config_vendor_allowlist_and_size(client):
    r = await client.post("/ingest-config", json={"vendor": "evilcorp", "raw": "x"})
    assert r.status_code == 422
    r = await client.post("/ingest-config", json={"vendor": "aws", "raw": ""})
    assert r.status_code == 422
    r = await client.post("/ingest-config",
                          json={"vendor": "aws", "raw": "x" * (8 * 1024 * 1024 + 1)})
    assert r.status_code == 422
    r = await client.post("/ingest-config", json={"vendor": "aws", "raw": "{not json"})
    assert r.status_code == 422 and "invalid aws json" in r.json()["detail"]


async def test_ingest_config_replaces_by_source(client, monkeypatch):
    seen: dict[str, Any] = {}

    async def _persist(db, rulesets, *, replace=True, snapshots=(), source=""):
        seen.update(keys=sorted(rulesets), replace=replace, source=source,
                    snaps=list(snapshots))
    monkeypatch.setattr(twin_store, "persist_rulesets", _persist)
    aws = {"SecurityGroups": [{"GroupId": "sg-1", "IpPermissions": [], "IpPermissionsEgress": []}]}
    r = await client.post("/ingest-config", json={
        "vendor": "aws", "raw": json.dumps(aws), "source": "acct-1/us-east-1"})
    assert r.status_code == 200, r.text
    assert seen["replace"] is False and seen["source"] == "acct-1/us-east-1"
    assert seen["snaps"][0]["sha256"] and seen["snaps"][0]["source"] == "acct-1/us-east-1"


async def test_ingest_config_unparseable_is_422_not_500(client, monkeypatch):
    def _bad(vendor, raw, **k):
        raise RuntimeError("internal path /srv/x")
    monkeypatch.setattr(main_mod, "parse", _bad)
    r = await client.post("/ingest-config", json={"vendor": "cisco_asa", "raw": "garbage"})
    assert r.status_code == 422
    assert "/srv" not in r.text


async def test_set_topology_validation(client, monkeypatch):
    async def _persist(db, segments, edges, *, replace=True):
        return None
    monkeypatch.setattr(twin_store, "persist_topology", _persist)
    ok = await client.post("/set-topology", json={
        "segments": [{"id": "a", "cidrs": ["10.0.0.0/24"], "role": "entry"}], "edges": []})
    assert ok.status_code == 200 and ok.json() == {"segments": 1, "edges": 0}
    dup = await client.post("/set-topology", json={
        "segments": [{"id": "a"}, {"id": "a"}], "edges": []})
    assert dup.status_code == 422 and "duplicate" in dup.json()["detail"]
    bad_role = await client.post("/set-topology", json={
        "segments": [{"id": "a", "role": "wizard"}], "edges": []})
    assert bad_role.status_code == 422
    no_id = await client.post("/set-topology", json={"segments": [{}], "edges": []})
    assert no_id.status_code == 422
