"""HTTP surface of the twin evidence (``/ingest-flows``, ``/ingest-probes``) and
the end-to-end path into ``_wargame_tenant``: stored evidence changes the
verdict a twin assessment persists.

Driven in-process through ASGI. The evidence store, the twin and
``store.persist`` are replaced by an in-memory fake (no database); the stored
rows still go through the real ser/de (``flow_to_row`` / ``row_to_flow``) and
the real pair mapping + staleness rules. DB-backed behaviour (RLS, pruning)
lives in ``test_evidence_db.py``.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app import main as main_mod
from app.engine.wargame import evidence, store, twin_store
from app.engine.wargame.environment import Environment
from app.engine.wargame.model import (
    Action, Edge, Node, NodeRole, PortRange, Proto, RuleSet,
)

PG = PortRange.single(Proto.TCP, 5432)


def _env() -> Environment:
    """entry (10.9.0.0/24) -> jewel (10.1.0.0/24) across sg-db (deny all):
    a pair the config proves closed."""
    env = Environment()
    env.add_node(Node("entry", NodeRole.ENTRY, ("10.9.0.0/24",)))
    env.add_node(Node("mid", NodeRole.INTERMEDIATE, ("10.2.0.0/24",)))
    env.add_node(Node("jewel", NodeRole.CROWN_JEWEL, ("10.1.0.0/24",)))
    env.add_ruleset(RuleSet("sg-db", [], default_action=Action.DENY))
    env.add_edge(Edge("entry", "jewel", rule_set_id="sg-db", port=PG))
    return env


class _Fake:
    """In-memory stand-in for the evidence tables, the twin and the
    assessment store (one tenant)."""

    def __init__(self):
        self.flow_rows: list[dict[str, Any]] = []
        self.probes: list[evidence.ProbeResult] = []
        self.segments = {"entry", "mid", "jewel"}
        self.bundles: list[store.AssessmentBundle] = []

    def install(self, mp):
        fake = self

        async def persist_flows(db, rows, *, now):
            fake.flow_rows.extend(rows)
            return {"stored": len(rows), "pruned": 0}

        async def load_flows(db, *, now):
            rows = [r for r in fake.flow_rows
                    if r["observed_at"] >= now - timedelta(days=evidence.FLOW_WINDOW_DAYS)]
            oldest = min((r["observed_at"] for r in rows), default=None)
            return ([evidence.row_to_flow(r) for r in rows],
                    evidence.observation_window_days(oldest, now=now))

        async def persist_probes(db, results, *, now):
            fake.probes.extend(results)
            return {"stored": len(results), "pruned": 0}

        async def load_probes(db, *, now, max_age_hours=evidence.PROBE_MAX_AGE_HOURS):
            return list(fake.probes)          # pair_probes applies the age rule

        async def segment_keys(db):
            return set(fake.segments)

        async def standing_certificates(db, *, now):
            if not fake.bundles:
                return []
            return [c for c in fake.bundles[-1].certificates if c["status"] == "valid"]

        async def persist(db, bundle):
            fake.bundles.append(bundle)
            return "aid"

        async def has_twin(db):
            return True

        async def load_environment(db):
            return _env()

        async def config_hashes(db):
            return ["sha-1"]

        for name, fn in (("persist_flows", persist_flows), ("load_flows", load_flows),
                         ("persist_probes", persist_probes), ("load_probes", load_probes),
                         ("segment_keys", segment_keys),
                         ("standing_certificates", standing_certificates)):
            mp.setattr(evidence, name, fn)
        mp.setattr(store, "persist", persist)
        mp.setattr(twin_store, "has_twin", has_twin)
        mp.setattr(twin_store, "load_environment", load_environment)
        mp.setattr(twin_store, "config_hashes", config_hashes)

    async def assess(self) -> store.AssessmentBundle:
        await main_mod.service._wargame_tenant()
        return self.bundles[-1]


@pytest.fixture
def fake(monkeypatch):
    f = _Fake()
    f.install(monkeypatch)
    return f


@pytest_asyncio.fixture
async def client(monkeypatch, fake):
    monkeypatch.setattr(main_mod.service, "_ready", True)
    async with AsyncClient(transport=ASGITransport(app=main_mod.app),
                           base_url="http://t") as c:
        yield c


def _now_iso(hours_ago: float = 0.0) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).isoformat()


def _probe(src="entry", dst="jewel", result="blocked", hours_ago=0.5, port=5432):
    return {"src": src, "dst": dst, "port": port, "result": result,
            "observed_at": _now_iso(hours_ago), "source": "scanner-1"}


def _flows(*rows) -> str:
    return json.dumps(list(rows))


CROSSING = {"src": "10.9.0.5", "dst": "10.1.0.9", "proto": "tcp", "dport": 5432,
            "state": "established"}


def _verdict(bundle) -> str:
    (b,) = bundle.boundaries
    return b["verdict"]


# -- /ingest-flows ---------------------------------------------------------------

async def test_ingest_flows_stores_only_rows_that_parse(client, fake):
    raw = _flows({**CROSSING, "ts": _now_iso(1)}, {"src": "10.9.0.7", "dst": "10.1.0.9"},
                 {"src": "10.9.0.6", "dst": "10.1.0.9", "proto": "udp", "dport": 53})
    r = await client.post("/ingest-flows", json={"raw": raw, "format": "generic",
                                                 "source": "fw-1"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["flows_parsed"] == 2 and body["flows_skipped"] == 1
    assert body["flows_stored"] == 2
    assert any("row 1" in w for w in body["warnings"])
    assert len(fake.flow_rows) == 2 and fake.flow_rows[0]["source"] == "fw-1"
    assert {r["proto"] for r in fake.flow_rows} == {"tcp", "udp"}


async def test_ingest_flows_nothing_parsed_is_200_with_warning(client, fake):
    r = await client.post("/ingest-flows", json={"raw": "not json at all"})
    assert r.status_code == 200
    body = r.json()
    assert body["flows_stored"] == 0 and "no flows parsed" in body["warnings"]
    assert fake.flow_rows == []


async def test_ingest_flows_validation(client):
    assert (await client.post("/ingest-flows", json={"raw": ""})).status_code == 422
    assert (await client.post("/ingest-flows",
                              json={"raw": "[]", "format": "pcap"})).status_code == 422
    big = {"raw": "x" * (8 * 1024 * 1024 + 1)}
    assert (await client.post("/ingest-flows", json=big)).status_code == 422


# -- /ingest-probes ----------------------------------------------------------------

async def test_ingest_probes_validates_segments(client, fake):
    r = await client.post("/ingest-probes", json={"results": [
        _probe(), _probe(src="ghost"), _probe(dst="entry", src="entry"),
        _probe(hours_ago=-2), _probe(result="error"), _probe(hours_ago=30),
    ]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["stored"] == 3 and body["rejected"] == 3
    joined = " ".join(body["warnings"])
    assert "'ghost' is not in the twin" in joined
    assert "same segment" in joined and "future" in joined
    assert "do not count" in joined          # the 30 h old one is kept but stale
    assert [p.result for p in fake.probes] == ["blocked", "error", "blocked"]


async def test_ingest_probes_without_topology_is_409(client, fake):
    fake.segments = set()
    r = await client.post("/ingest-probes", json={"results": [_probe()]})
    assert r.status_code == 409 and "topology" in r.json()["detail"]
    assert fake.probes == []


@pytest.mark.parametrize("body", [
    {}, {"results": []},
    {"results": [{**_probe(), "result": "open"}]},
    {"results": [{**_probe(), "port": 70000}]},
    {"results": [{**_probe(), "proto": "sctp"}]},
    {"results": [{k: v for k, v in _probe().items() if k != "observed_at"}]},
    {"results": [_probe()] * 10_001},
])
async def test_ingest_probes_shape_is_422(client, fake, body):
    assert (await client.post("/ingest-probes", json=body)).status_code == 422
    assert fake.probes == []


# -- end to end: stored evidence -> _wargame_tenant -> persisted verdict ---------

async def test_e2e_no_evidence_is_still_proved_config(client, fake):
    b = await fake.assess()
    assert _verdict(b) == "proved_config"
    (c,) = b.certificates
    assert c["corroboration"]["probe_tested"] is False
    assert any(a["key"] == "proof_basis" for a in c["assumptions"])


async def test_e2e_stored_blocked_probe_yields_pass(client, fake):
    r = await client.post("/ingest-probes", json={"results": [_probe()]})
    assert r.status_code == 200 and r.json()["stored"] == 1
    b = await fake.assess()
    assert _verdict(b) == "pass"
    (c,) = b.certificates
    assert c["corroboration"]["probe_tested"] is True
    assert not any(a["key"] == "proof_basis" for a in c["assumptions"])
    assert b.assessment["metadata"]["probed_pairs"] == 1


async def test_e2e_hop_stale_and_error_probes_do_not_yield_pass(client, fake):
    r = await client.post("/ingest-probes", json={"results": [
        _probe(src="entry", dst="mid"), _probe(src="mid", dst="jewel"),   # hops
        _probe(hours_ago=25),                                              # stale
        _probe(result="error"),                                            # no probe
    ]})
    assert r.status_code == 200 and r.json()["stored"] == 4
    b = await fake.assess()
    assert _verdict(b) == "proved_config"
    assert b.assessment["metadata"]["probed_pairs"] == 0


async def test_e2e_stored_crossing_probe_yields_fail_open(client, fake):
    await client.post("/ingest-probes", json={"results": [_probe(result="crossed")]})
    b = await fake.assess()
    assert _verdict(b) == "fail_open" and b.certificates == []


async def test_e2e_stored_real_flow_yields_fail_open_and_alert(client, fake):
    # Run 1: no evidence -> a proved_config certificate is issued.
    first = await fake.assess()
    (cert,) = first.certificates
    # A real flow then crosses the proved-closed boundary.
    r = await client.post("/ingest-flows", json={
        "raw": _flows({**CROSSING, "ts": _now_iso(0.1)}), "format": "generic"})
    assert r.json()["flows_stored"] == 1
    b = await fake.assess()
    assert _verdict(b) == "fail_open"
    assert b.certificates == []                  # never certify a fail_open pair
    (bd,) = b.boundaries
    assert any("observed" in d for d in bd["disagreements"])
    md = b.assessment["metadata"]
    assert md["observed_flows"] == 1 and md["observation_window_days"] == 1
    assert md["impossible_traffic_alerts"] == 1
    assert md["impossible_traffic_sample"][0]["contradicts_certificate"] == cert["fingerprint"]


async def test_e2e_dropped_attempt_does_not_open_the_pair(client, fake):
    dropped = {**CROSSING, "state": "", "action": "deny"}
    await client.post("/ingest-flows", json={"raw": _flows(dropped), "format": "firewall"})
    assert len(fake.flow_rows) == 1
    b = await fake.assess()
    assert _verdict(b) == "proved_config"
    assert b.assessment["metadata"]["impossible_traffic_alerts"] == 0


async def test_e2e_missing_evidence_tables_assess_without_evidence(client, fake, monkeypatch):
    import asyncpg

    async def _missing(db, *, now):
        raise asyncpg.UndefinedTableError('relation "wargame_observed_flows" does not exist')
    monkeypatch.setattr(evidence, "load_flows", _missing)
    b = await fake.assess()
    assert _verdict(b) == "proved_config"
    assert b.assessment["metadata"]["observed_flows"] == 0
