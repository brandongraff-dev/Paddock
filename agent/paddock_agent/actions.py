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
    on the result. On revert that plan is untrusted DATA from the server: the
    enforcer re-derives the one fixed plan it could have produced from the
    original typed action and refuses everything else (audit 7.4: a server-
    supplied ``rm -rf`` argv used to be executed verbatim).
  * SAFETY RAIL #6 (allowed actions only): anything outside ALLOWED_ACTIONS is
    refused before it reaches the enforcer.
  * SAFETY RAIL #7 (no self-lockout): ``SelfGuard`` refuses a block of this agent's own server (by address, by
    name or by port), of loopback and of the unspecified / broadcast addresses.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Optional
from urllib.parse import urlsplit

from . import ALLOWED_ACTIONS

_DOMAIN_RE = re.compile(r"(?=.{1,253}$)([a-z0-9_](-?[a-z0-9_]){0,62}\.)+[a-z]{2,63}", re.I)
_PORTSPEC_RE = re.compile(r"(in|out)?:?(tcp|udp):(\d{1,5})", re.I)
_REMOTEISH = ("://", "@", "ssh:", "\\\\")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


class EnforcerError(RuntimeError):
    """An enforcer could not do what it was asked."""


class NotSupportedError(EnforcerError):
    """The running platform cannot apply this action (dry-run only)."""


class RevertRefused(EnforcerError):
    """A revert plan that this agent could not have produced (or cannot safely follow)."""


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
    The returned value is the CANONICAL form; enforcers build commands only from it.
    """
    if action_type not in ALLOWED_ACTIONS:
        raise HostLocalError("action_type %r is not allowed" % (action_type,))
    t = (target or "").strip() if isinstance(target, str) else ""
    if not t:
        raise HostLocalError("target is required")
    if _CONTROL_RE.search(t):
        raise HostLocalError("target must not contain control characters")
    low = t.lower()
    for bad in _REMOTEISH:
        if bad in low:
            raise HostLocalError(
                "target %r looks like a remote reference; actions are host-local only" % t
            )
    if action_type == "block_ip":
        if "%" in t:
            raise HostLocalError("block_ip target must be a bare IP (no zone id)")
        try:
            return str(ipaddress.ip_address(t))
        except ValueError as exc:
            raise HostLocalError("block_ip target must be a bare IP: %s" % exc) from exc
    if action_type == "block_domain":
        if not _DOMAIN_RE.fullmatch(t):
            raise HostLocalError("block_domain target must be a bare domain name")
        return low
    if action_type == "quarantine_file":
        if not t.startswith("/"):
            raise HostLocalError("quarantine_file target must be an absolute local path")
        if ".." in t.split("/"):
            raise HostLocalError("quarantine_file target must not contain '..'")
        return t
    if action_type == "firewall_rule":
        m = _PORTSPEC_RE.fullmatch(t)
        if not m:
            raise HostLocalError("firewall_rule target must be a local port spec like 'in:tcp:22'")
        port = int(m.group(3))
        if not 1 <= port <= 65535:
            raise HostLocalError("firewall_rule port must be 1-65535")
        return "%s:%s:%d" % ((m.group(1) or "in").lower(), m.group(2).lower(), port)
    if action_type == "revert":
        return t
    raise HostLocalError("unknown action_type %r" % (action_type,))


@dataclass
class Action:
    """A server action as the agent sees it."""
    id: str
    action_type: str
    target: str
    status: str
    dry_run: bool = True
    reason: Optional[str] = None
    revert_of: Optional[str] = None
    result: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_server(cls, d: Dict[str, Any]) -> "Action":
        """An action as the server sent it. The id must be a UUID (it names the result route and the local
        record); anything else is refused BEFORE the action can touch the host."""
        try:
            action_id = str(uuid.UUID(str(d["id"])))
        except (ValueError, TypeError, KeyError, AttributeError):
            raise ActionError("the action id is not a UUID; the action is refused")
        if not isinstance(d.get("action_type"), str) or not isinstance(d.get("target"), str):
            raise ActionError("the action type and target must be strings; the action is refused")
        return cls(
            id=action_id,
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
    output: Dict[str, Any]
    revert: Optional[Dict[str, Any]] = None
    # the typed rule this outcome applied / reverted: {"action_type", "target", "tag"?}; recorded locally so a
    # later revert can be bound to something this agent really did
    rule: Optional[Dict[str, Any]] = None


def _refusal(simulate_only: bool, code: str, detail: str) -> Outcome:
    """A refusal is a ``failed`` outcome for a real action; a dry run only ever simulates (and so never
    changes server state)."""
    if simulate_only:
        return Outcome(status="simulated", dry_run=True, applied=False,
                       output={"dry_run": True, "refused": code, "detail": detail})
    return Outcome(status="failed", dry_run=False, applied=False,
                   output={"error": code, "detail": detail})


def _is_ipv6(target: str) -> bool:
    try:
        return ipaddress.ip_address(target).version == 6
    except ValueError:
        return False


class SelfGuard:
    """Refuses actions that would cut this agent off from its own server (RAIL #7).

    The server address is resolved at validation time (never cached): if the server is a name that cannot be
    resolved we cannot prove a ``block_ip`` target is not the server, so it is refused (fail safe). The
    resolver is injectable for tests."""

    def __init__(self, server_url: str, resolver: Optional[Callable[..., Any]] = None) -> None:
        parts = urlsplit(server_url or "")
        self.host = (parts.hostname or "").lower()
        self.port = parts.port or (443 if parts.scheme == "https" else 80)
        self._resolver = resolver or socket.getaddrinfo
        try:
            ipaddress.ip_address(self.host)
            self._literal = True
        except ValueError:
            self._literal = False

    def addresses(self) -> set:
        if self._literal:
            return {str(ipaddress.ip_address(self.host))}
        try:
            infos = self._resolver(self.host, self.port, 0, socket.SOCK_STREAM)
        except (OSError, UnicodeError) as exc:
            raise SelfLockoutError("cannot resolve the server %r to prove the target is not the server "
                                   "(%s); refusing" % (self.host, exc))
        out = set()
        for info in infos:
            try:
                out.add(str(ipaddress.ip_address(info[4][0])))
            except (ValueError, IndexError, TypeError):
                continue
        return out

    def check(self, action_type: str, target: str) -> None:
        """``target`` is the canonical form from :func:`assert_host_local`. Raises :class:`SelfLockoutError`."""
        if action_type == "block_ip":
            ip = ipaddress.ip_address(target)
            if ip.is_loopback or ip.is_unspecified or ip == ipaddress.ip_address("255.255.255.255"):
                raise SelfLockoutError("block_ip %s would block loopback / the unspecified or broadcast "
                                       "address, which cuts the host off from itself" % target)
            if str(ip) in self.addresses():
                raise SelfLockoutError("block_ip %s is this agent's own server (%s); that is a lockout"
                                       % (target, self.host))
        elif action_type == "block_domain":
            if target == self.host:
                raise SelfLockoutError("block_domain %s is this agent's own server; that is a lockout" % target)
        elif action_type == "firewall_rule":
            direction, _proto, port = target.split(":")
            if direction == "out" and int(port) == self.port:
                raise SelfLockoutError("firewall_rule %s drops outbound traffic to the server's port %d; "
                                       "that is a lockout" % (target, self.port))
            if direction == "out" and int(port) == 53 and not self._literal:
                raise SelfLockoutError("firewall_rule %s drops DNS, which this agent needs to find its "
                                       "server; that is a lockout" % target)


class SelfLockoutError(HostLocalError):
    """The target would sever the agent from its own server (or from itself)."""


def apply_action(action: Action, enforcer, *, agent_dry_run: bool,
                 guard: Optional[SelfGuard] = None,
                 intent: Optional[Callable[[str, str], None]] = None) -> Outcome:
    """Execute (or simulate) one action under the full safety gate.

    Returns an :class:`Outcome`; raises :class:`ActionError` if the action is not
    approved, or :class:`HostLocalError` if the target is not host-local. ``guard`` (the agent passes one)
    adds the self-lockout rail; ``intent(action_type, target)`` is called right before the first change to
    the host, so the caller can write its write-ahead record.
    """
    if action.action_type not in ALLOWED_ACTIONS:
        raise ActionError("action_type %r is not allowed" % (action.action_type,))
    # RAIL #2: cannot apply without an explicit server approval.
    if action.status != Status.APPROVED.value:
        raise ActionError(
            "cannot apply action %s: status is '%s', not 'approved'" % (action.id, action.status)
        )
    # RAIL #1: host-local only (also re-validated independently of the server).
    target = assert_host_local(action.action_type, action.target)

    # RAIL #3: dry-run unless the server approved it for real AND the agent is
    # not forced into dry-run. A dry run SIMULATES and mutates nothing.
    simulate_only = action.dry_run or agent_dry_run

    # RAIL #7: never block the server, loopback, or the agent's own way out.
    if guard is not None:
        try:
            guard.check(action.action_type, target)
        except SelfLockoutError as exc:
            return _refusal(simulate_only, "self_lockout", str(exc))

    # The iptables back end is IPv4-only: refuse an IPv6 block loudly instead of failing silently.
    if action.action_type == "block_ip" and _is_ipv6(target):
        return _refusal(simulate_only, "ipv6_not_supported",
                        "block_ip for IPv6 is not supported (the enforcer drives IPv4 iptables); "
                        "nothing was applied")

    if simulate_only:
        try:
            if getattr(enforcer, "tags_rules", False):
                plan = enforcer.simulate(action.action_type, target, action_id=action.id)
            else:
                plan = enforcer.simulate(action.action_type, target)
        except EnforcerError as exc:
            return _refusal(True, "refused", str(exc))
        return Outcome(status="simulated", dry_run=True, applied=False, output=plan)

    rule = {"action_type": action.action_type, "target": target}
    try:
        if intent is not None:
            intent(action.action_type, target)           # write-ahead: the record exists before the effect
        if getattr(enforcer, "tags_rules", False):
            applied = enforcer.apply(action.action_type, target, action_id=action.id)
        else:
            applied = enforcer.apply(action.action_type, target)
    except Exception as exc:  # noqa: BLE001 -- report failure, never crash the loop
        # a partial apply whose rollback failed leaves a rule on the host: keep its revert plan
        leftover = getattr(exc, "revert", None)
        return Outcome(status="failed", dry_run=False, applied=False,
                       output=dict({"error": str(exc)}, **({"partial": True} if leftover else {})),
                       revert=leftover if isinstance(leftover, dict) else None,
                       rule=rule if leftover else None)
    # RAIL #5: a real apply MUST carry its own revert plan.
    revert = applied.get("revert")
    if not revert:
        raise ActionError("enforcer did not return a revert plan for an applied action")
    tag = revert.get("tag") if isinstance(revert, dict) else None
    if isinstance(tag, str):
        rule["tag"] = tag
    return Outcome(status="applied", dry_run=False, applied=True,
                   output=applied.get("output", {}), revert=revert, rule=rule)


def revert_action(action: Action, enforcer, *, agent_dry_run: bool,
                  ledger: Optional[Callable[[str, str], Optional[Dict[str, Any]]]] = None) -> Outcome:
    """Undo an applied block (RAIL #5).

    The plan in ``action.result["revert"]`` is **untrusted server data**. The enforcer re-derives the
    trusted plan from the typed action it describes (``validate_revert``) and the agent only ever
    executes that; a plan the agent could not have produced is refused and nothing runs.

    ``ledger(action_type, target)`` is this host's own record of what the agent applied (the agent always
    passes one): a revert is refused unless the host has an unreverted record of applying exactly that, so a
    revert can only ever undo this agent's own work (never an admin's pre-existing rule).
    """
    if action.action_type != "revert":
        raise ActionError("revert_action needs a 'revert' action, not %r" % (action.action_type,))
    # RAIL #2 applies to reverts too: no unapproved revert touches the host.
    if action.status != Status.APPROVED.value:
        raise ActionError(
            "cannot revert via action %s: status is '%s', not 'approved'" % (action.id, action.status)
        )
    simulate_only = action.dry_run or agent_dry_run
    untrusted = (action.result or {}).get("revert")
    try:
        plan = (enforcer.validate_revert(untrusted, ledger=ledger) if ledger is not None
                else enforcer.validate_revert(untrusted))
    except EnforcerError as exc:
        return _refusal(simulate_only, "revert_plan_rejected", str(exc))
    if simulate_only:
        try:
            preview = enforcer.simulate_revert(plan)
        except EnforcerError as exc:
            return _refusal(True, "revert_plan_rejected", str(exc))
        return Outcome(status="simulated", dry_run=True, applied=False, output=preview)
    try:
        out = enforcer.revert(plan)
    except Exception as exc:  # noqa: BLE001
        return Outcome(status="failed", dry_run=False, applied=False,
                       output={"error": str(exc)})
    rule = None
    if isinstance(plan, dict) and isinstance(plan.get("action_type"), str) and isinstance(plan.get("target"), str):
        rule = {"action_type": plan["action_type"], "target": plan["target"]}
    return Outcome(status="applied", dry_run=False, applied=True, output=out, rule=rule)
