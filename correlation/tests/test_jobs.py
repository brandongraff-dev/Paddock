"""Redis fallback job consumer (``queue:correlate``): dispatch, tenancy, ack rules."""
from __future__ import annotations

import json
import logging

import pytest
from fastapi import HTTPException

from app import jobs, main as main_mod, tenancy

TA = "11111111-1111-1111-1111-111111111111"
TB = "22222222-2222-2222-2222-222222222222"


def _fields(op, tenant=TA, payload=None, **extra):
    job = {"kind": f"correlate_{op}", "op": op, **extra}
    if tenant is not None:
        job["tenant_id"] = tenant
    if payload is not None:
        job["payload"] = payload
    return {"job": json.dumps(job)}


def _recorder(calls, name, exc=None):
    async def h(payload):
        calls.append((name, payload, tenancy.requested_tenant()))
        if exc:
            raise exc
    return h


@pytest.fixture
def calls():
    return []


@pytest.fixture
def handlers(calls):
    return {n: _recorder(calls, n) for n in ("a", "b")}


async def test_dispatch_runs_in_job_tenant(handlers, calls):
    assert await jobs.process(handlers, _fields("a", TA, {"x": 1}))
    assert await jobs.process(handlers, _fields("b", TB))
    assert calls == [("a", {"x": 1}, TA), ("b", None, TB)]
    assert tenancy.requested_tenant() is None  # context restored


@pytest.mark.parametrize("tenant", [None, "", "not-a-uuid"])
async def test_missing_or_bad_tenant_rejected_not_run(handlers, calls, tenant, monkeypatch):
    monkeypatch.delenv("TENANCY_STRICT", raising=False)  # even non-strict
    f = _fields("a", None)
    if tenant is not None:
        f = {"job": json.dumps({"op": "a", "tenant_id": tenant})}
    assert await jobs.process(handlers, f) is True  # acked
    assert calls == []


async def test_unknown_op_logged_and_acked(handlers, calls, caplog):
    with caplog.at_level(logging.WARNING, logger="correlation.jobs"):
        assert await jobs.process(handlers, _fields("nope"))
    assert "unknown op" in caplog.text and calls == []


@pytest.mark.parametrize("fields", [{}, {"job": "{not json"}, {"job": "[1]"}])
async def test_malformed_entry_acked(handlers, calls, fields):
    assert await jobs.process(handlers, fields) is True and calls == []


async def test_poison_and_4xx_acked(calls):
    h = {"p": _recorder(calls, "p", jobs.PoisonJob("bad")),
         "q": _recorder(calls, "q", HTTPException(status_code=422, detail="bad"))}
    assert await jobs.process(h, _fields("p"))
    assert await jobs.process(h, _fields("q"))
    assert len(calls) == 2


async def test_transient_error_propagates(calls):
    h = {"t": _recorder(calls, "t", RuntimeError("db down")),
         "u": _recorder(calls, "u", HTTPException(status_code=503, detail="x"))}
    with pytest.raises(RuntimeError):
        await jobs.process(h, _fields("t"))
    with pytest.raises(HTTPException):
        await jobs.process(h, _fields("u"))


class FakeRedis:
    def __init__(self, deliveries=1):
        self.acked, self.dead, self.deliveries = [], [], deliveries

    async def xack(self, stream, group, mid):
        self.acked.append(mid)

    async def xadd(self, stream, fields):
        self.dead.append((stream, fields))

    async def xpending_range(self, *a, **k):
        return [{"times_delivered": self.deliveries}]


async def test_ack_only_after_success_and_bounded_retry(calls):
    h = {"t": _recorder(calls, "t", RuntimeError("boom")), "ok": _recorder(calls, "ok")}
    r = FakeRedis(deliveries=1)
    await jobs._handle(r, "s", "g", h, "1-0", _fields("t"))
    assert r.acked == [] and r.dead == []  # left pending for retry
    r.deliveries = jobs.MAX_ATTEMPTS
    await jobs._handle(r, "s", "g", h, "1-0", _fields("t"))
    assert r.acked == ["1-0"] and r.dead[0][0] == "s:dead"
    await jobs._handle(r, "s", "g", h, "2-0", _fields("ok"))
    assert r.acked == ["1-0", "2-0"]


# --- wiring to the real shared functions ------------------------------------

@pytest.fixture
def wired(monkeypatch):
    seen = []

    def rec(name):
        async def f(*a):
            seen.append((name, a, tenancy.requested_tenant()))
            return {"assessments": 0, "routes": 0, "computed": 0}
        return f

    monkeypatch.setattr(main_mod.service, "run_pathcompute_scoped", rec("paths"))
    monkeypatch.setattr(main_mod.service, "run_wargame_scoped", rec("wargame"))
    monkeypatch.setattr(main_mod, "do_ingest_config", rec("config"))
    monkeypatch.setattr(main_mod, "do_set_topology", rec("topology"))
    monkeypatch.setattr(main_mod, "do_ingest_flows", rec("flows"))
    monkeypatch.setattr(main_mod, "do_ingest_probes", rec("probes"))
    return seen, main_mod._job_handlers(main_mod.service)


async def test_real_handlers_dispatch_under_tenant(wired):
    seen, h = wired
    assert set(h) >= {"recompute_paths", "recompute_wargame", "twin_ingest_config", "twin_set_topology"}
    await jobs.process(h, _fields("recompute_paths", TA))
    await jobs.process(h, _fields("recompute_wargame", TB))
    await jobs.process(h, _fields("twin_ingest_config", TA, {"vendor": "asa", "raw": "x", "source": "s"}))
    await jobs.process(h, _fields("twin_set_topology", TB, {"segments": [], "edges": []}))
    assert [(n, t) for n, _, t in seen] == [
        ("paths", TA), ("wargame", TB), ("config", TA), ("topology", TB)]
    assert seen[2][1][0].vendor == "asa"
    assert seen[3][1][0].segments == []


async def test_real_handlers_invalid_payload_is_poison(wired):
    seen, h = wired
    assert await jobs.process(h, _fields("twin_ingest_config", TA, {"vendor": "asa"}))  # no raw
    assert await jobs.process(h, _fields("twin_set_topology", TA, {"segments": "x"}))
    assert seen == []


async def test_real_handlers_dispatch_twin_evidence(wired):
    seen, h = wired
    assert {"twin_ingest_flows", "twin_ingest_probes"} <= set(h)
    await jobs.process(h, _fields("twin_ingest_flows", TB,
                                  {"raw": "[]", "format": "zeek", "source": "s"}))
    probe = {"src": "a", "dst": "b", "port": 443, "result": "blocked",
             "observed_at": "2026-11-22T10:00:00+00:00", "source": "scanner"}
    await jobs.process(h, _fields("twin_ingest_probes", TA, {"results": [probe]}))
    assert [(n, t) for n, _, t in seen] == [("flows", TB), ("probes", TA)]
    assert seen[0][1][0].format == "zeek"
    (p,) = seen[1][1][0].results
    assert p.result == "blocked" and p.observed_at.tzinfo is not None


async def test_real_handlers_invalid_evidence_payload_is_poison(wired):
    seen, h = wired
    assert await jobs.process(h, _fields("twin_ingest_flows", TA, {"format": "zeek"}))  # no raw
    assert await jobs.process(h, _fields("twin_ingest_probes", TA, {"results": [
        {"src": "a", "dst": "b", "port": 1, "result": "open", "observed_at": "x"}]}))
    assert seen == []
