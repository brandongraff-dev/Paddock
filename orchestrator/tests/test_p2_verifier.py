"""Regression tests added by the independent P2 verifier (docs/ASSURANCE_P2.md section 13.6).

Each test here FAILED against the tree the work packages delivered and passes with the fix named in its docstring.
"""
from __future__ import annotations

import datetime as dt
import random
import time
import uuid

import pytest

from app.assurance.builders import host_fw as hf

from .test_assurance_host_fw import (
    NOW, acc, agent_row, chain, fw_section, listener, lis_section, posture_row, rows_of, scan_edge, sections)


def _pathological(n_rules: int, n_listeners: int, seed: int = 1):
    """A schema-valid posture whose firewall has ``n_rules`` rules with distinct source CIDRs and distinct ports and
    ``n_listeners`` listeners: every (listener, source atom) walk visits every rule."""
    rnd = random.Random(seed)
    rules = [acc(proto="tcp", dport=[[1000 + i, 1000 + i]],
                 src=[f"{rnd.randint(1, 223)}.{rnd.randint(0, 255)}.{rnd.randint(0, 255)}.0/24"])
             for i in range(n_rules)]
    lis = [listener(1000 + i, comm="app") for i in range(n_listeners)]
    return sections(firewall=fw_section([chain(rules)]), listeners=lis_section(lis))


def test_a_pathological_ruleset_is_widened_within_a_small_budget_not_walked_for_hours(monkeypatch):
    """host_fw: the per-agent rule-evaluation budget (STEP_BUDGET). Before: 2000 rules x 2000 listeners (a 700 KB
    schema-valid posture) cost billions of rule evaluations in a worker thread no timeout can stop."""
    monkeypatch.setattr(hf, "STEP_BUDGET", 100_000)
    secs = _pathological(300, 300)
    t = time.monotonic()
    out = hf.build(rows_of((agent_row(), posture_row(secs))), NOW)
    assert time.monotonic() - t < 10
    assert out.coverage == [], "an over-budget host is widened and gets no coverage"
    assert out.edges, "widened, not dropped: every listener from every source"
    assert all("walk_budget_exceeded" in e.evidence["assumptions"] for e in out.edges)
    assert all(e.confidence <= hf.CONF_MAYBE for e in out.edges)
    fact = out.facts[0].facts
    assert fact["host_agent"]["data"]["coverage"]["blocked_by"]


def test_default_budget_bounds_the_worst_posture_the_server_accepts():
    """The largest firewall the ingest schema accepts (2000 rules, 2000 listeners) is bounded by the DEFAULT budget."""
    secs = _pathological(2000, 2000)
    t = time.monotonic()
    out = hf.build(rows_of((agent_row(), posture_row(secs))), NOW)
    took = time.monotonic() - t
    assert took < 60, took
    assert out.coverage == [] and out.edges
    assert all("walk_budget_exceeded" in e.evidence["assumptions"] for e in out.edges)


def test_the_build_wide_budget_stops_many_pathological_agents_from_adding_up(monkeypatch):
    monkeypatch.setattr(hf, "STEP_BUDGET", 400_000)
    monkeypatch.setattr(hf, "BUILD_STEP_BUDGET", 600_000)
    pairs = [(agent_row(n, ips=(f"10.1.0.{n}",)), posture_row(_pathological(120, 120, seed=n))) for n in range(1, 9)]
    t = time.monotonic()
    out = hf.build(rows_of(*pairs), NOW)
    assert time.monotonic() - t < 20
    # the first agents may be walked exactly; once the pool is gone the rest are widened without coverage
    assert len(out.coverage) < 8
    assert out.facts and len(out.facts) == 8


def test_a_scan_check_that_cannot_finish_is_a_conflict_not_a_pass(monkeypatch):
    """_scan_conflicts under the budget: a host whose closed-port claim cannot be checked against the scan within
    budget carries a conflict marker (no coverage, no usable fact), it is never silently treated as consistent."""
    secs = sections(firewall=fw_section([chain([acc(proto="tcp", dport=[[22, 22]], src=["10.0.0.0/8"])])]))
    scans = [scan_edge(22)]
    # with the default budget the walk finishes: the agent says "closed to the world", the scan saw it open
    out = hf.build(rows_of((agent_row(), posture_row(secs)), scans=scans), NOW)
    assert out.facts[0].facts["firewall"]["conflict"][0]["kind"] == "agent_closed_scan_open"
    # with no budget the same check cannot finish: still a conflict, of its own kind
    monkeypatch.setattr(hf, "STEP_BUDGET", 1)
    out = hf.build(rows_of((agent_row(), posture_row(secs)), scans=scans), NOW)
    assert out.coverage == []
    conflict = out.facts[0].facts["firewall"]["conflict"]
    assert [c["kind"] for c in conflict] == ["agent_scan_check_budget_exceeded"]


def test_default_budget_does_not_change_a_normal_host():
    """61 rules, 42 listeners (about 0.2 M rule evaluations) is far below the default budget: exact, covered."""
    rules = [acc(proto="tcp", dport=[[1000 + i, 1000 + i]], src=[f"10.{i % 200}.0.0/16"]) for i in range(60)]
    rules.append(acc(proto="tcp", dport=[[22, 22]]))
    lis = [listener(1000 + i, comm="app") for i in range(41)] + [listener(22)]
    out = hf.build(rows_of((agent_row(), posture_row(sections(firewall=fw_section([chain(rules)]),
                                                              listeners=lis_section(lis))))), NOW)
    assert len(out.coverage) == 1
    assert not any("walk_budget_exceeded" in e.evidence["assumptions"] for e in out.edges)


# --------------------------------------------------------------------------- #
# database-backed (the e2e world: real agent, real server, real library)
# --------------------------------------------------------------------------- #

import json  # noqa: E402

from .p2_support import hdr  # noqa: E402
from .test_assurance_p2_e2e import (  # noqa: E402,F401
    FWD, SSH, _fresh_limiters, enable_std, enforce, evaluate, invariant, mint, runtime, verdicts, world)


async def test_a_declared_server_with_no_node_and_no_agent_is_unknown_not_out_of_scope(world):
    """graph_loader (E5): before, a `server` label on an asset no builder drew a node for was ignored, so the std host
    invariants HOLD with `hosts.selected == 1` while a declared server was silently out of scope."""
    w = world
    rt = runtime(w)
    await rt.enroll((await mint(w))["token"])
    await enable_std(w)
    await rt.posture()
    await evaluate(w)
    assert await verdicts(w) == {SSH: "HOLDS", FWD: "HOLDS"}
    asset = await w.db.fetchval(
        "INSERT INTO assets (kind, value, canonical, source, metadata, last_seen) VALUES "
        "('cloud_resource', 'i-0decl', 'i-0decl', 'aws', $1::jsonb, NOW()) RETURNING id",
        json.dumps({"resource_type": "instance", "private_ips": ["10.9.9.9"], "public_ips": [], "security_groups": []}))
    assert await w.db.fetchval("SELECT count(*) FROM reach_nodes WHERE node_ref = $1", f"asset:{asset}") == 0
    r = await w.http.put("/v1/labels", headers=hdr(w.admin_a), json={
        "node_ref": f"asset:{asset}", "tag": "server", "value": "", "justification": "a declared server"})
    assert r.status_code == 200, r.text
    await evaluate(w)
    for sid in (SSH, FWD):
        res = (await invariant(w, sid))["last_result"]
        assert res["verdict"] == "UNKNOWN", (sid, res["verdict"], res.get("hosts"))
        assert res["hosts"]["selected"] == 2 and res["hosts"]["unknown"] == 1 and res["hosts"]["holds"] == 1
        assert f"asset:{asset}" in res["unproven_targets"]
        assert any(b["node"] == f"asset:{asset}" and b["reason"] == "no_agent" for b in res["blind_spots"]), res["blind_spots"]
    # a label that says "false" is not a declaration
    r = await w.http.put("/v1/labels", headers=hdr(w.admin_a), json={
        "node_ref": f"asset:{asset}", "tag": "server", "value": "false", "justification": "not a server after all"})
    assert r.status_code == 200, r.text
    await evaluate(w)
    assert await verdicts(w) == {SSH: "HOLDS", FWD: "HOLDS"}


async def test_a_silent_agent_raises_agent_offline_then_agent_online_integration_events(world, monkeypatch):
    """integrations.base.EVENT_TYPES (docs/ASSURANCE_P2.md section 6): before, `agent.offline` and `agent.online`
    were not registered, so fleet_monitor.emit_transition wrote the audit row and silently skipped the event."""
    from app import fleet_monitor
    from app.integrations import service as isvc
    from app.integrations.base import EVENT_TYPES

    assert "agent.offline" in EVENT_TYPES and "agent.online" in EVENT_TYPES
    seen = []

    async def fake_emit(pool, event):
        seen.append(event)

    monkeypatch.setattr(isvc, "emit", fake_emit)
    w = world
    rt = runtime(w)
    creds = await rt.enroll((await mint(w))["token"])
    await rt.posture()
    await w.db.execute("UPDATE fleet_agents SET last_seen = NOW() - interval '20 minutes' WHERE id = $1",
                       uuid.UUID(creds.agent_id))
    assert await fleet_monitor.sweep_all_tenants(w.app_pool) == 1
    assert await fleet_monitor.sweep_all_tenants(w.app_pool) == 0
    assert [e.type for e in seen] == ["agent.offline"]
    assert seen[0].severity == "high" and seen[0].data["hostname"] == "web-1"
    await rt.heartbeat()
    assert [e.type for e in seen] == ["agent.offline", "agent.online"]


# --------------------------------------------------------------------------- #
# corroboration must not be forgeable through X-Forwarded-For
# --------------------------------------------------------------------------- #

def _req(peer: str, xff: str):
    from starlette.requests import Request

    return Request({"type": "http", "client": (peer, 1234), "method": "GET", "path": "/",
                    "headers": [(b"x-forwarded-for", xff.encode())] if xff else []})


def test_client_ip_strict_reads_x_forwarded_for_from_the_right(monkeypatch):
    """auth.client_ip_strict: the leftmost entry is whatever the client sent; only what the trusted proxy appended counts.

    Rewritten for review finding wire-1: the old assertions ("two trusted hops" skipped an entry because it lay inside
    10.0.0.0/8, and a lone private entry fell back to the proxy) encoded the unsafe rule that let a private host's own
    appended address be skipped so that its forged left-hand entry won. The entry is now chosen by POSITION (the Nth
    from the right, N = trusted_proxy_hops), never by CIDR membership."""
    from app import auth
    from app.config import settings as cfg

    monkeypatch.setattr(cfg, "trusted_proxy_cidrs", "127.0.0.1/32,10.0.0.0/8")
    monkeypatch.setattr(cfg, "trusted_proxy_hops", 1, raising=False)
    assert auth.client_ip_strict(_req("203.0.113.9", "198.51.100.77")) == "203.0.113.9"          # untrusted peer: XFF ignored
    assert auth.client_ip_strict(_req("127.0.0.1", "198.51.100.77, 203.0.113.9")) == "203.0.113.9"  # forged first entry
    assert auth.client_ip_strict(_req("127.0.0.1", "203.0.113.9")) == "203.0.113.9"
    assert auth.client_ip_strict(_req("127.0.0.1", "198.51.100.77, 203.0.113.9, 10.1.2.3")) == "10.1.2.3"   # the rightmost
    assert auth.client_ip_strict(_req("127.0.0.1", "10.1.2.3")) == "10.1.2.3"          # a private client is a client
    monkeypatch.setattr(cfg, "trusted_proxy_hops", 2, raising=False)
    assert auth.client_ip_strict(_req("127.0.0.1", "198.51.100.77, 203.0.113.9, 10.1.2.3")) == "203.0.113.9"  # two hops
    assert auth.client_ip_strict(_req("127.0.0.1", "10.1.2.3")) == "127.0.0.1"          # shorter than the chain: fail closed
    monkeypatch.setattr(cfg, "trusted_proxy_hops", 1, raising=False)
    assert auth.client_ip_strict(_req("127.0.0.1", "198.51.100.77, <script>")) == "127.0.0.1"     # garbage fails closed
    assert auth.client_ip_strict(_req("127.0.0.1", "")) == "127.0.0.1"


async def test_a_host_cannot_forge_the_address_it_is_corroborated_from(world, monkeypatch):
    """fleet router (E3): before, ``peer_ip`` was the LEFTMOST X-Forwarded-For entry of a trusted proxy, so a compromised
    host behind an appending proxy sent the victim instance's public address and was merged into ``asset:<victim>``."""
    from app.config import settings as cfg

    monkeypatch.setattr(cfg, "trusted_proxy_cidrs", "127.0.0.1/32")      # the test transport's peer is 127.0.0.1
    w = world
    rt = runtime(w)
    creds = await rt.enroll((await mint(w))["token"])
    aid = uuid.UUID(creds.agent_id)
    await rt.posture()
    ips = await w.db.fetchval("SELECT identity->'ips' FROM fleet_agents WHERE id=$1", aid)
    ips = json.loads(ips) if isinstance(ips, str) else ips
    assert ips
    victim_public = "198.51.100.77"
    asset = await w.db.fetchval(
        "INSERT INTO assets (kind, value, canonical, source, metadata, last_seen) VALUES "
        "('cloud_resource', 'i-0victim', 'i-0victim', 'aws', $1::jsonb, NOW()) RETURNING id",
        json.dumps({"resource_type": "instance", "private_ips": ips, "public_ips": [victim_public]}))

    def via_proxy(xff):
        def hook(method, path, headers, body):
            if path.endswith("/posture"):
                headers["X-Forwarded-For"] = xff
            return None
        return hook

    # the host forges the victim's public address in front of the one the proxy appended (its real address)
    rt.bridge.interceptor = via_proxy(f"{victim_public}, 203.0.113.9")
    rt.host.password_auth = "yes"
    await rt.posture()
    row = await w.db.fetchrow("SELECT node_ref, identity FROM fleet_agents WHERE id=$1", aid)
    ident = json.loads(row["identity"]) if isinstance(row["identity"], str) else row["identity"]
    assert row["node_ref"] == f"agent:{aid}", row["node_ref"]
    assert ident["basis"] == "claimed" and ident["peer_ip"] == "203.0.113.9"
    # (rewritten for review finding hostfw-2) the instance's PUBLIC address as the peer is no longer enough: a host
    # behind a NAT or proxy instance shares it. The proxy really seeing one of the instance's PRIVATE addresses is.
    rt.bridge.interceptor = via_proxy(f"203.0.113.9, {victim_public}")
    rt.host.password_auth = "no"
    await rt.posture()
    row = await w.db.fetchrow("SELECT node_ref FROM fleet_agents WHERE id=$1", aid)
    assert row["node_ref"] == f"agent:{aid}", row["node_ref"]
    rt.bridge.interceptor = via_proxy(f"203.0.113.9, {ips[0]}")
    await rt.posture()
    row = await w.db.fetchrow("SELECT node_ref FROM fleet_agents WHERE id=$1", aid)
    from app.assurance.builders import _ipmap
    want = f"agent:{aid}" if _ipmap.is_public_ip(ips[0]) else f"asset:{asset}"
    assert row["node_ref"] == want, row["node_ref"]
