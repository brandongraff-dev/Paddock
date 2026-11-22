"""Persistence tests (DB-backed; skip without TEST_DATABASE_URL): runs + proofs
round-trip, re-run replaces the chain, proofs are append-only, catalogue sync."""
from __future__ import annotations

import pytest

from app.engine.prover import Prover
from app.engine.signing import ProofSigner, verify_chain
from app.sandbox.backend import FakeBackend
from app.sandbox.guard import IsolationGuard
from app.sandbox.types import SandboxSpec
from app.scenarios.base import Scenario, ScenarioCtx, ScenarioResult
from app.scenarios.registry import catalogue
from app.store import WargameStore


class _Toggle(Scenario):
    id = "toggle"
    title = "t"
    category = "other"

    def matches(self, ctx):  # pragma: no cover
        return True

    def build_spec(self, ctx):
        return SandboxSpec(component="svc", image="svc:1.0", port=8080)

    def fixed_spec(self, ctx):
        return SandboxSpec(component="svc", image="svc:2.0", port=8080)

    def fix_ref(self, ctx):
        return "upgrade svc 1.0 -> 2.0"

    async def probe(self, runner, replica, ctx):
        return (ScenarioResult.vulnerable("affected")
                if replica.image.endswith(":1.0")
                else ScenarioResult.not_vulnerable("fixed"))


async def _run_once(ctx):
    signer = ProofSigner("k", "sek")
    prover = Prover(IsolationGuard(FakeBackend()), signer)
    return await prover.prove(ctx, _Toggle()), signer


@pytest.mark.asyncio
async def test_record_and_read_back(clean_db):
    store = WargameStore(clean_db)
    ctx = ScenarioCtx(component={"product": "svc"}, path={"attack_path_id": None})
    result, signer = await _run_once(ctx)
    run_id = await store.record(result, ctx)

    run = await store.get_run(run_id)
    assert run is not None and run["outcome"] == "proven_fixed"
    assert run["before_verdict"] == "vulnerable" and run["after_verdict"] == "not_vulnerable"

    proofs = await store.get_proofs(run_id)
    assert [p["phase"] for p in proofs] == ["setup", "before", "fix", "after", "summary"]
    ok, reason = verify_chain(proofs, signer)
    assert ok, reason


@pytest.mark.asyncio
async def test_rerun_replaces_chain(clean_db):
    store = WargameStore(clean_db)
    ctx = ScenarioCtx(component={"product": "svc"}, path={"attack_path_id": None})
    r1, _ = await _run_once(ctx)
    id1 = await store.record(r1, ctx)
    r2, signer = await _run_once(ctx)  # same fingerprint
    id2 = await store.record(r2, ctx)
    assert id1 == id2  # upsert by (tenant, fingerprint)
    proofs = await store.get_proofs(id2)
    # exactly one chain, dense from 0
    assert [p["seq"] for p in proofs] == [0, 1, 2, 3, 4]
    ok, _ = verify_chain(proofs, signer)
    assert ok
    assert await store.count_runs() == 1


@pytest.mark.asyncio
async def test_proofs_are_append_only(clean_db):
    store = WargameStore(clean_db)
    ctx = ScenarioCtx(component={"product": "svc"}, path={"attack_path_id": None})
    result, _ = await _run_once(ctx)
    run_id = await store.record(result, ctx)
    # Any UPDATE to a proof row must be refused by the immutability trigger.
    with pytest.raises(Exception):
        async with clean_db.acquire() as conn:
            await conn.execute(
                "UPDATE wargame_proofs SET signature = 'x' WHERE run_id = $1::uuid",
                run_id,
            )


@pytest.mark.asyncio
async def test_catalogue_sync(clean_db):
    store = WargameStore(clean_db)
    n = await store.sync_catalog(catalogue())
    assert n == len(catalogue()) >= 3
    rows = await store.scenarios()
    ids = {r["id"] for r in rows}
    assert {"cve-container-repro", "default-cred-replica", "unauth-endpoint-replica"} <= ids
