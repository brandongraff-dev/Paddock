"""The agent-side action state machine + the host-local safety guard.

This is the heart of the safety rails as seen from the host:

  * SAFETY RAIL #1 (host-local only): ``assert_host_local`` validates that a
    target names a thing to block/quarantine ON THIS HOST. There is no field,
    anywhere in the agent, that names another machine to act on. ``apply`` calls
    the platform enforcer, which only ever touches the local host.
  * SAFETY RAIL #2 (approve before apply): ``apply_action`` refuses to touch the
    host unless the action's status is ``approved``.
  * SAFETY RAIL #3 (dry-run by default): if the action is ``dry_run`` OR the
    agent is running dry, ``apply_action`` SIMULATES -- it calls the enforcer's
    ``simulate`` (never ``apply``) and mutates nothing.
  * SAFETY RAIL #5 (reversible): a real apply records the enforcer's revert plan
    on the result; ``revert_action`` feeds that plan back to the enforcer.
  * SAFETY RAIL #6 (allowed actions only): anything outside ALLOWED_ACTIONS is
    refused before it reaches the enforcer.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from . import ALLOWED_ACTIONS

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_](-?[a-z0-9_]){0,62}\.)+[a-z]{2,63}$", re.I)
_PORTSPEC_RE = re.compile(r"^(in|out)?:?(tcp|udp):(\d{1,5})$", re.I)
_REMOTEISH = ("://", "@", "ssh:", "\\\\")


class HostLocalError(ValueError):
    """A target cannot be enforced host-locally (or is malformed)."""


class ActionError(RuntimeError):
    """An illegal state-machine transition was attempted."""


class Status(str, Enum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    APPLIED = "applied"
    FAILED = "failed"
    REVERTED = "reverted"
    DENIED = "denied"


def assert_host_local(action_type: str, target: str) -> str:
    """Validate + normalise a target for a host-local action, or raise.

    Mirrors the orchestrator's guard so the agent independently refuses anything
    that is not strictly host-local -- defence in depth, not trust in the server.
    """
    if action_type not in ALLOWED_ACTIONS:
        raise HostLocalError(f"action_type {action_type!r} is not allowed")
    t = (target or "").strip()
    if not t:
        raise HostLocalError("target is required")
    low = t.lower()
    for bad in _REMOTEISH:
        if bad in low:
            raise HostLocalError(
                f"target {t!r} looks like a remote reference; actions are host-local only"
            )
    if action_type == "block_ip":
        try:
            ipaddress.ip_address(t)
        except ValueError as exc:
            raise HostLocalError(f"block_ip target must be a bare IP: {exc}") from exc
        return t
    if action_type == "block_domain":
        if not _DOMAIN_RE.match(t):
            raise HostLocalError("block_domain target must be a bare domain name")
        return low
    if action_type == "quarantine_file":
        if not t.startswith("/"):
            raise HostLocalError("quarantine_file target must be an absolute local path")
        if ".." in t.split("/"):
            raise HostLocalError("quarantine_file target must not contain '..'")
        return t
    if action_type == "firewall_rule":
        if not _PORTSPEC_RE.match(t):
            raise HostLocalError("firewall_rule target must be a local port spec like 'in:tcp:22'")
        return low
    if action_type == "revert":
        return t
    raise HostLocalError(f"unknown action_type {action_type!r}")


@dataclass
class Action:
    """A server action as the agent sees it."""
    id: str
    action_type: str
    target: str
    status: str
    dry_run: bool = True
    reason: str | None = None
    revert_of: str | None = None
    result: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_server(cls, d: dict[str, Any]) -> "Action":
        return cls(
            id=str(d["id"]),
            action_type=d["action_type"],
            target=d["target"],
            status=d.get("status", "proposed"),
            dry_run=bool(d.get("dry_run", True)),
            reason=d.get("reason"),
            revert_of=d.get("revert_of"),
            result=dict(d.get("result") or {}),
        )


@dataclass
class Outcome:
    """What apply/simulate produced. ``applied`` is False for every dry run."""
    status: str                      # 'applied' | 'failed' | 'simulated'
    dry_run: bool
    applied: bool
    output: dict[str, Any]
    revert: dict[str, Any] | None = None


def apply_action(action: Action, enforcer, *, agent_dry_run: bool) -> Outcome:
    """Execute (or simulate) one action under the full safety gate.

    Returns an :class:`Outcome`; raises :class:`ActionError` if the action is not
    approved, or :class:`HostLocalError` if the target is not host-local.
    """
    if action.action_type not in ALLOWED_ACTIONS:
        raise ActionError(f"action_type {action.action_type!r} is not allowed")
    # RAIL #2: cannot apply without an explicit server approval.
    if action.status != Status.APPROVED.value:
        raise ActionError(
            f"cannot apply action {action.id}: status is '{action.status}', not 'approved'"
        )
    # RAIL #1: host-local only (also re-validated independently of the server).
    assert_host_local(action.action_type, action.target)

    # RAIL #3: dry-run unless the server approved it for real AND the agent is
    # not forced into dry-run. A dry run SIMULATES and mutates nothing.
    simulate_only = action.dry_run or agent_dry_run
    if simulate_only:
        plan = enforcer.simulate(action.action_type, action.target)
        return Outcome(status="simulated", dry_run=True, applied=False, output=plan)

    try:
        applied = enforcer.apply(action.action_type, action.target)
    except Exception as exc:  # noqa: BLE001 -- report failure, never crash the loop
        return Outcome(status="failed", dry_run=False, applied=False,
                       output={"error": str(exc)})
    # RAIL #5: a real apply MUST carry its own revert plan.
    revert = applied.get("revert")
    if not revert:
        raise ActionError("enforcer did not return a revert plan for an applied action")
    return Outcome(status="applied", dry_run=False, applied=True,
                   output=applied.get("output", {}), revert=revert)


def revert_action(action: Action, enforcer, *, agent_dry_run: bool) -> Outcome:
    """Undo an applied block using the recorded revert plan (RAIL #5)."""
    plan = action.result.get("revert") or {}
    simulate_only = agent_dry_run
    if simulate_only:
        preview = enforcer.simulate_revert(plan)
        return Outcome(status="simulated", dry_run=True, applied=False, output=preview)
    try:
        out = enforcer.revert(plan)
    except Exception as exc:  # noqa: BLE001
        return Outcome(status="failed", dry_run=False, applied=False,
                       output={"error": str(exc)})
    return Outcome(status="applied", dry_run=False, applied=True, output=out)
