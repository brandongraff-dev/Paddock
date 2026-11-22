"""The Prover: run a scenario against a replica, before and after the fix, and
emit a signed, hash-chained proof.

Flow (every replica built + torn down through the IsolationGuard's session):

    1. build the component's CURRENT (suspect) replica  -> probe -> BEFORE verdict
    2. if BEFORE is vulnerable and the scenario has a fix:
         build the FIXED replica                        -> probe -> AFTER verdict
    3. classify the outcome and seal the proof chain

Outcomes:
    proven_exploitable  before vulnerable, no fix proven to shut it
    proven_fixed        before vulnerable, after not vulnerable
    not_exploitable     before not vulnerable (the hop is already shut)
    inconclusive        the replica couldn't give a clear answer
    refused             isolation/ownership refused the run (IsolationError)
    error               an unexpected failure

Nothing here ever targets a live system: the only way it reaches anything is
``guard.session`` / ``GuardedRunner``, both of which are replica-only and fail
closed.
"""
from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from ..sandbox.guard import IsolationGuard
from ..sandbox.types import IsolationError
from ..scenarios.base import Scenario, ScenarioCtx, ScenarioResult, Verdict
from .runner import GuardedRunner
from .signing import ProofChain, ProofEntry, ProofSigner

log = logging.getLogger(__name__)


@dataclass
class ProverResult:
    scenario_id: str
    status: str                      # done | refused | error
    outcome: Optional[str]           # proven_exploitable | proven_fixed | ...
    before_verdict: Optional[str] = None
    after_verdict: Optional[str] = None
    fix_ref: str = ""
    isolation: dict[str, Any] = field(default_factory=dict)
    reason: Optional[str] = None
    component: dict[str, Any] = field(default_factory=dict)
    fingerprint: str = ""
    proofs: list[ProofEntry] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "status": self.status,
            "outcome": self.outcome,
            "before_verdict": self.before_verdict,
            "after_verdict": self.after_verdict,
            "fix_ref": self.fix_ref,
            "reason": self.reason,
        }


def run_fingerprint(ctx: ScenarioCtx, scenario: Scenario) -> str:
    """Stable dedupe key for a run: the hop + scenario + component identity."""
    parts = [
        str(ctx.path.get("attack_path_id") or ""),
        str(ctx.path.get("target_asset_id") or ""),
        scenario.id,
        str(ctx.component.get("image") or ctx.product),
        str(ctx.version),
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


class Prover:
    def __init__(self, guard: IsolationGuard, signer: ProofSigner) -> None:
        self._guard = guard
        self._signer = signer

    async def _probe_once(
        self, scenario: Scenario, spec, ctx: ScenarioCtx
    ) -> tuple[ScenarioResult, dict[str, Any]]:
        """Build one verified replica, probe it, tear it down. Returns the
        scenario result and the isolation record that held."""
        async with self._guard.session(spec) as replica:
            runner = GuardedRunner(self._guard)
            result = await scenario.probe(runner, replica, ctx)
            return result, replica.isolation_record()

    async def prove(self, ctx: ScenarioCtx, scenario: Scenario) -> ProverResult:
        fp = run_fingerprint(ctx, scenario)
        chain = ProofChain(self._signer)
        res = ProverResult(
            scenario_id=scenario.id,
            status="error",
            outcome=None,
            component=dict(ctx.component),
            fingerprint=fp,
        )
        started = time.monotonic()
        try:
            before_spec = scenario.build_spec(ctx)
            chain.add("setup", {
                "scenario": scenario.id,
                "component": ctx.product,
                "image": before_spec.image,
                "version": before_spec.version,
            })
            before, isolation = await self._probe_once(scenario, before_spec, ctx)
            res.isolation = isolation
            res.before_verdict = before.verdict.value
            chain.add("before", {
                "verdict": before.verdict.value,
                "summary": before.summary,
                "evidence": before.evidence,
                "isolation": isolation,
            })

            if before.verdict == Verdict.VULNERABLE:
                fixed_spec = scenario.fixed_spec(ctx)
                res.fix_ref = scenario.fix_ref(ctx)
                if fixed_spec is not None:
                    chain.add("fix", {"fix_ref": res.fix_ref})
                    after, _ = await self._probe_once(scenario, fixed_spec, ctx)
                    res.after_verdict = after.verdict.value
                    chain.add("after", {
                        "verdict": after.verdict.value,
                        "summary": after.summary,
                        "evidence": after.evidence,
                    })
                    if after.verdict == Verdict.NOT_VULNERABLE:
                        res.outcome = "proven_fixed"
                    elif after.verdict == Verdict.VULNERABLE:
                        res.outcome = "proven_exploitable"   # fix did NOT hold
                        res.reason = "candidate fix did not close the hop"
                    else:
                        res.outcome = "inconclusive"
                        res.reason = "fixed replica gave an inconclusive result"
                else:
                    res.outcome = "proven_exploitable"
                    res.reason = "no automatic fix to prove"
            elif before.verdict == Verdict.NOT_VULNERABLE:
                res.outcome = "not_exploitable"
            else:
                res.outcome = "inconclusive"
                res.reason = before.summary

            res.status = "done"
        except IsolationError as e:
            res.status = "refused"
            res.outcome = "refused"
            res.reason = str(e)[:500]
            chain.add("summary", {"outcome": "refused", "reason": res.reason})
            log.warning("wargame.prove.refused fp=%s: %s", fp[:12], res.reason)
        except Exception as e:  # noqa: BLE001
            res.status = "error"
            res.outcome = "error"
            res.reason = f"{type(e).__name__}: {str(e)[:300]}"
            chain.add("summary", {"outcome": "error", "reason": res.reason})
            log.exception("wargame.prove.error fp=%s", fp[:12])

        if res.status == "done":
            chain.add("summary", {
                "outcome": res.outcome,
                "before_verdict": res.before_verdict,
                "after_verdict": res.after_verdict,
                "fix_ref": res.fix_ref,
            })
        res.proofs = chain.entries
        elapsed_ms = round((time.monotonic() - started) * 1000.0, 2)
        log.info(
            "wargame.prove scenario=%s outcome=%s status=%s in %.1fms",
            scenario.id, res.outcome, res.status, elapsed_ms,
        )
        return res
