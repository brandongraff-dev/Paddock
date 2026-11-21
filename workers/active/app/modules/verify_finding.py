"""``verify_finding`` job: run one safe check and report the verdict.

The orchestrator only enqueues this job after (1) the scope check allowed the
target and (2) the matched scope entry's proof-of-control is verified or
attested. The worker re-checks (2) from the job (a job without it is refused)
and (1) on every request through the scope guard, so a verification can never
reach further than the scanners already can.

The worker reports the verdict to ``POST /v1/verifications/{id}/result``; the
orchestrator owns every consequence (finding state, priority, reopening,
events). Nothing here writes to the finding.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

import structlog

from app.modules import safe_checks
from app.modules.safe_checks import CheckEnv, FindingCtx, MethodRefused, ScopeDenied

log = structlog.get_logger(__name__)

PROVEN = frozenset({"verified", "attested"})
CHECK_TIMEOUT_SEC = 90


async def verify(
    target: str,
    *,
    scope,
    politeness,
    orchestrator,
    scan_id: str | None,
    config: dict[str, Any],
    env_overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    vid = str(config.get("verification_id") or "")
    now = datetime.now(timezone.utc).isoformat()
    payload: dict[str, Any]
    if not vid:
        raise ValueError("verify_finding job without verification_id")

    if str(config.get("scope_proof") or "") not in PROVEN:
        payload = {"status": "refused", "checked_at": now,
                   "reason": "job carries no verified/attested proof-of-control; refusing to touch the target"}
    else:
        finding = FindingCtx.from_job(config.get("finding") or {})
        env = CheckEnv(scope=scope, politeness=politeness, orchestrator=orchestrator,
                       **(env_overrides or {}))
        try:
            result = await asyncio.wait_for(safe_checks.run(finding, env), CHECK_TIMEOUT_SEC)
        except ScopeDenied as e:
            payload = {"status": "refused", "checked_at": now, "reason": f"scope guard: {e.reason}"}
        except asyncio.TimeoutError:
            payload = {"status": "done", "verdict": "inconclusive", "checked_at": now,
                       "reason": f"check exceeded {CHECK_TIMEOUT_SEC}s", "evidence": {}}
        except MethodRefused as e:  # a bug in a check: never send, report loudly
            log.error("verify.method_refused", method=str(e))
            payload = {"status": "error", "checked_at": now, "reason": f"check attempted method {e}"}
        except Exception as e:  # noqa: BLE001
            log.exception("verify.error")
            payload = {"status": "error", "checked_at": now, "reason": f"{type(e).__name__}: {str(e)[:200]}"}
        else:
            if result is None:
                payload = {"status": "unsupported", "checked_at": now,
                           "reason": f"no safe check for {finding.rule_source}/{finding.rule_id}"}
            else:
                d = result.as_dict()
                payload = {"status": "done", **d}

    try:
        await orchestrator.verification_result(vid, payload, tenant_id=config.get("tenant_id"))
    except Exception as e:  # noqa: BLE001 -- surface to the dispatcher (scan_fail); the sweep also times it out
        log.error("verify.report_failed", error=str(e))
        raise
    return {"assets": [], "edges": [], "findings": [],
            "summary": {"verification_id": vid, "status": payload["status"],
                        "verdict": payload.get("verdict"), "check_id": payload.get("check_id")}}
