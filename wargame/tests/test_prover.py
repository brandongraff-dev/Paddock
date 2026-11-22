"""Prover orchestration tests: before/after loop, outcome classification, and a
verifiable signed proof chain. FakeBackend only -- no containers."""
from __future__ import annotations

import pytest

from app.engine.prover import Prover, run_fingerprint
from app.engine.signing import ProofSigner, verify_chain
from app.sandbox.backend import FakeBackend
from app.sandbox.guard import IsolationGuard
from app.sandbox.types import ExecResult, SandboxSpec
from app.scenarios.base import Scenario, ScenarioCtx, ScenarioResult, Verdict
from app.scenarios.cve_repro import CveContainerRepro


class _ToggleScenario(Scenario):
    """Vulnerable on the current image tag, not-vulnerable on the fixed tag."""
    id = "toggle"
    title = "t"
    category = "other"

    def __init__(self, with_fix=True):
        self._with_fix = with_fix

    def matches(self, ctx):  # pragma: no cover - not used via registry
        return True

    def build_spec(self, ctx):
        return SandboxSpec(component="svc", image="svc:1.0", port=8080)

    def fixed_spec(self, ctx):
        return SandboxSpec(component="svc", image="svc:2.0", port=8080) if self._with_fix else None

    def fix_ref(self, ctx):
        return "upgrade svc 1.0 -> 2.0"

    async def probe(self, runner, replica, ctx):
        if replica.image.endswith(":1.0"):
            return ScenarioResult.vulnerable("affected version present")
        return ScenarioResult.not_vulnerable("fixed version present")


def _prover(backend=None, secret="sek"):
    backend = backend or FakeBackend()
    guard = IsolationGuard(backend)
    return Prover(guard, ProofSigner("k", secret)), guard


@pytest.mark.asyncio
async def test_proven_fixed_outcome_and_chain():
    prover, _ = _prover()
    signer = ProofSigner("k", "sek")
    ctx = ScenarioCtx(component={"product": "svc"}, path={"attack_path_id": "p1"})
    res = await prover.prove(ctx, _ToggleScenario(with_fix=True))
    assert res.status == "done"
    assert res.before_verdict == "vulnerable"
    assert res.after_verdict == "not_vulnerable"
    assert res.outcome == "proven_fixed"
    # chain: setup, before, fix, after, summary
    phases = [e.phase for e in res.proofs]
    assert phases == ["setup", "before", "fix", "after", "summary"]
    ok, reason = verify_chain([e.as_row() for e in res.proofs], signer)
    assert ok, reason


@pytest.mark.asyncio
async def test_proven_exploitable_without_fix():
    prover, _ = _prover()
    ctx = ScenarioCtx(component={"product": "svc"})
    res = await prover.prove(ctx, _ToggleScenario(with_fix=False))
    assert res.outcome == "proven_exploitable"
    assert res.before_verdict == "vulnerable" and res.after_verdict is None


@pytest.mark.asyncio
async def test_not_exploitable_when_before_clean():
    class _Clean(_ToggleScenario):
        async def probe(self, runner, replica, ctx):
            return ScenarioResult.not_vulnerable("already patched")
    prover, _ = _prover()
    res = await prover.prove(ScenarioCtx(component={"product": "svc"}), _Clean())
    assert res.outcome == "not_exploitable" and res.after_verdict is None


@pytest.mark.asyncio
async def test_refused_when_isolation_cannot_be_proven():
    # Backend claims a replica but its network can't be proven internal.
    prover, _ = _prover(backend=FakeBackend(isolated=False))
    res = await prover.prove(ScenarioCtx(component={"product": "svc"}), _ToggleScenario())
    assert res.status == "refused" and res.outcome == "refused"
    assert res.proofs and res.proofs[-1].phase == "summary"


@pytest.mark.asyncio
async def test_fingerprint_stable():
    ctx = ScenarioCtx(component={"product": "svc", "image": "svc:1.0"},
                      path={"attack_path_id": "p1"})
    s = _ToggleScenario()
    assert run_fingerprint(ctx, s) == run_fingerprint(ctx, s)


@pytest.mark.asyncio
async def test_cve_scenario_end_to_end_proven_fixed():
    # Real CVE scenario through the GuardedRunner + FakeBackend: the version
    # command reports the replica's own image tag, so 6.0 (< fixed 6.2) is
    # vulnerable and the fixed replica (6.2) is not.
    backend = FakeBackend()

    def version_cmd(replica, argv):
        tag = replica.image.rsplit(":", 1)[-1]
        return ExecResult(0, stdout=f"redis {tag}")
    backend.register(version_cmd, argv_prefix=("redis-server", "--version"))
    backend.register(ExecResult(0, ""), argv_prefix=("python3", "-c"))  # tcp reachable

    prover, _ = _prover(backend=backend)
    ctx = ScenarioCtx(
        component={"product": "redis", "image": "library/redis:6.0", "version": "6.0",
                   "port": 6379, "version_cmd": ["redis-server", "--version"]},
        finding={"rule_source": "sca", "cve": "CVE-2022-0001",
                 "metadata": {"fixed_version": "6.2"}},
        path={"attack_path_id": "p9", "target_asset_id": None},
    )
    res = await prover.prove(ctx, CveContainerRepro())
    assert res.before_verdict == "vulnerable", res.proofs
    assert res.after_verdict == "not_vulnerable"
    assert res.outcome == "proven_fixed"
    assert res.fix_ref == "upgrade redis 6.0 -> 6.2"
