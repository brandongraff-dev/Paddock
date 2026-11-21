"""Fleet agents + GATED defensive enforcement (schema 014).

A lightweight host agent enrolls here, reports inventory, and can apply
HOST-LOCAL defensive blocks -- but only through a strict, auditable gate:

    propose  --(admin approve, four-eyes)-->  approved  --(agent)-->  applied
       |                                          |                      |
       +--(admin deny)--> denied                  +--> failed            +--(revert)--> reverted

Every enforcement action is proposed first, cannot become ``applied`` without an
explicit human ``approved_by``, defaults to ``dry_run = TRUE`` (a real apply
requires ``dry_run = false`` AND ``approved`` status), is host-local only (an
agent can act only on the host it runs on -- there is NO field to target a
remote host), is fully reversible (each applied block records how to revert and
``revert`` is a first-class action), and writes every transition to the
tamper-evident audit log.

This router holds inline Pydantic models (we do not touch shared models.py) and
is wired by hand in production (see docs/FLEET_WIRING.md) -- main.py is not
edited here.

Allowed action types ONLY: block_ip, block_domain, quarantine_file,
firewall_rule, revert. Nothing else. No scanning, no offensive capability.

Network quarantine (schema 025) reuses this exact gate: a
``quarantine_device`` / ``release_device`` row has NO agent and an
``integration_id``; it is proposed and executed by
``app/routers/network_actions.py`` and approved / denied / reverted here.
"""
from __future__ import annotations

import hmac
import ipaddress
import logging
import os
import re
import secrets
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from .. import audit
from .. import auth as auth_svc
from ..auth import Principal, current_principal, require
from ..db import get_pool

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/fleet", tags=["fleet"])


# --------------------------------------------------------------------------- #
# Constants / policy
# --------------------------------------------------------------------------- #

# The ONLY actions an agent may ever be asked to perform. Host-local, defensive.
PROPOSABLE_ACTIONS: frozenset[str] = frozenset(
    {"block_ip", "block_domain", "quarantine_file", "firewall_rule"}
)
# `revert` is real but is never *proposed* directly -- it is minted by the
# /revert endpoint against an already-applied action.
ALL_ACTIONS: frozenset[str] = PROPOSABLE_ACTIONS | {"revert"}

ACTION_STATUSES: frozenset[str] = frozenset(
    {"proposed", "approved", "applied", "failed", "reverted", "denied"}
)

# An agent is "stale" if we have not heard from it in this long.
STALE_AFTER_SEC = 180

# Agent credential: fat_<prefix>_<secret>. Only the sha256 is ever stored, in
# fleet_agents.token_hash (mirrors the api_keys pattern in auth.py).
_AGENT_TOKEN_SCHEME = "fat"


def _enroll_secret() -> str | None:
    """Shared enrollment bootstrap secret (env), or None in dev.

    When ``FLEET_ENROLL_TOKEN`` is set, an enrollment must present exactly that
    token. When unset (dev / tests) any non-empty token is accepted and the
    event is logged -- the gate that actually matters is approve-before-apply,
    not enrollment strength.
    """
    v = os.environ.get("FLEET_ENROLL_TOKEN")
    return v or None


def _allow_self_approve() -> bool:
    """Four-eyes toggle. Default False: approver must differ from requester."""
    return (os.environ.get("FLEET_ALLOW_SELF_APPROVE", "").strip().lower()
            in {"1", "true", "yes", "on"})


def generate_agent_token() -> tuple[str, str, str]:
    """Return (full_token, prefix, token_hash). Full token shown once."""
    prefix = secrets.token_hex(4)
    secret = secrets.token_urlsafe(32)
    full = f"{_AGENT_TOKEN_SCHEME}_{prefix}_{secret}"
    return full, prefix, auth_svc.hash_api_key(full)


# --------------------------------------------------------------------------- #
# Host-local guard (safety rail #1): the target describes WHAT to block on the
# agent's OWN host. There is structurally no way to say WHERE -- no execution
# host, no remote target. We additionally reject targets that smell remote.
# --------------------------------------------------------------------------- #

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_](-?[a-z0-9_]){0,62}\.)+[a-z]{2,63}$", re.I)
_PORTSPEC_RE = re.compile(r"^(in|out)?:?(tcp|udp):(\d{1,5})$", re.I)
_REMOTEISH = ("://", "@", "ssh:", "\\\\")


class HostLocalError(ValueError):
    """Raised when a target cannot be enforced host-locally."""


def assert_host_local(action_type: str, target: str) -> str:
    """Validate + normalise a target for a host-local action, or raise.

    Guarantees the target names a thing to block/quarantine ON THIS HOST and can
    never designate a remote execution host.
    """
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
            ipaddress.ip_address(t)  # single address only -- the local drop rule
        except ValueError as exc:
            raise HostLocalError(f"block_ip target must be a bare IP address: {exc}") from exc
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
            raise HostLocalError(
                "firewall_rule target must be a local port spec like 'in:tcp:22'"
            )
        return low
    if action_type == "revert":
        return t
    raise HostLocalError(f"unknown action_type {action_type!r}")


# --------------------------------------------------------------------------- #
# Inline models
# --------------------------------------------------------------------------- #

class EnrollIn(BaseModel):
    model_config = {"extra": "forbid"}
    hostname: str = Field(min_length=1, max_length=253)
    platform: str = Field(description="linux | windows | macos")
    token: str = Field(min_length=1, description="enrollment bootstrap token")
    agent_version: str | None = None
    labels: list[str] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=lambda: ["inventory"])


class EnrollOut(BaseModel):
    id: UUID
    hostname: str
    platform: str | None
    status: str
    agent_token: str = Field(description="shown ONCE; store it securely on the host")
    token_prefix: str
    capabilities: list[str]


class HeartbeatIn(BaseModel):
    model_config = {"extra": "forbid"}
    agent_version: str | None = None
    status: str | None = Field(default=None, description="agent-reported health note")


class PendingAction(BaseModel):
    id: UUID
    action_type: str
    target: str
    dry_run: bool
    status: str
    reason: str | None = None
    revert_of: UUID | None = None
    result: dict[str, Any] = Field(default_factory=dict)


class HeartbeatOut(BaseModel):
    id: UUID
    status: str
    last_seen: datetime
    # Approved, real (dry_run=false) work the agent should carry out now.
    pending_actions: list[PendingAction] = Field(default_factory=list)


class InventoryIn(BaseModel):
    model_config = {"extra": "forbid"}
    os_info: dict[str, Any] = Field(default_factory=dict)
    packages: list[dict[str, Any]] = Field(default_factory=list)
    listeners: list[dict[str, Any]] = Field(default_factory=list)
    posture: dict[str, Any] = Field(default_factory=dict)


class InventoryOut(BaseModel):
    ok: bool
    inventory_id: UUID
    collected_at: datetime


class AgentOut(BaseModel):
    id: UUID
    hostname: str
    platform: str | None
    agent_version: str | None
    labels: list[str]
    capabilities: list[str]
    status: str
    last_seen: datetime | None
    enrolled_at: datetime
    stale: bool


class InventorySnapshot(BaseModel):
    id: UUID
    collected_at: datetime
    os_info: dict[str, Any]
    packages: list[dict[str, Any]]
    listeners: list[dict[str, Any]]
    posture: dict[str, Any]


class AgentDetailOut(AgentOut):
    inventory: InventorySnapshot | None = None
    action_counts: dict[str, int] = Field(default_factory=dict)


class ActionProposeIn(BaseModel):
    # extra=forbid is itself a host-local guard: a sneaky `exec_host` / `host`
    # field is a 422, so a proposal can never name another machine to act on.
    model_config = {"extra": "forbid"}
    agent_id: UUID
    action_type: Literal["block_ip", "block_domain", "quarantine_file", "firewall_rule"]
    target: str = Field(min_length=1, max_length=1024)
    reason: str | None = Field(default=None, max_length=2048)
    indicator_id: UUID | None = None
    finding_id: UUID | None = None


class ActionOut(BaseModel):
    id: UUID
    # NULL for network actions (schema 025): those are executed by an ACTION
    # integration through app/routers/network_actions.py, never by an agent.
    agent_id: UUID | None = None
    action_type: str
    target: str
    reason: str | None
    indicator_id: UUID | None
    finding_id: UUID | None
    dry_run: bool
    status: str
    requested_by: str | None
    approved_by: str | None
    result: dict[str, Any]
    created_at: datetime
    decided_at: datetime | None
    applied_at: datetime | None
    revert_of: UUID | None
    integration_id: UUID | None = None   # schema 025: set on network actions


class ActionPage(BaseModel):
    items: list[ActionOut]
    total: int


class ApproveIn(BaseModel):
    model_config = {"extra": "forbid"}
    # The explicit, conscious human decision to permit a REAL host change. When
    # False (default) the approval authorises a dry-run simulation only.
    apply_for_real: bool = False
    note: str | None = Field(default=None, max_length=2048)


class DenyIn(BaseModel):
    model_config = {"extra": "forbid"}
    note: str | None = Field(default=None, max_length=2048)


class ResultIn(BaseModel):
    model_config = {"extra": "forbid"}
    status: Literal["applied", "failed"]
    output: dict[str, Any] = Field(default_factory=dict)
    # How to undo this block (so revert is always possible). Required for an
    # applied, non-dry-run block.
    revert: dict[str, Any] | None = None


class RevertIn(BaseModel):
    model_config = {"extra": "forbid"}
    note: str | None = Field(default=None, max_length=2048)


# --------------------------------------------------------------------------- #
# Row helpers
# --------------------------------------------------------------------------- #

def _as_dict(v: Any) -> dict[str, Any]:
    if v is None:
        return {}
    if isinstance(v, str):
        import json
        try:
            return json.loads(v)
        except Exception:  # noqa: BLE001
            return {}
    return dict(v)


def _row_to_action(row) -> ActionOut:
    d = dict(row)
    d["result"] = _as_dict(d.get("result"))
    return ActionOut.model_validate(d)


def _stale(last_seen: datetime | None) -> bool:
    if last_seen is None:
        return True
    ref = last_seen if last_seen.tzinfo else last_seen.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - ref).total_seconds() > STALE_AFTER_SEC


def _effective_status(db_status: str, last_seen: datetime | None) -> str:
    if db_status in ("revoked", "enrolled"):
        return db_status
    return "stale" if _stale(last_seen) else db_status


async def _audit(
    request: Request,
    pool,
    *,
    action: str,
    resource_type: str,
    resource_id: str,
    actor: str,
    actor_role: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Write one audit row for a transition (best-effort, never fails the req)."""
    try:
        await audit.record(
            pool,
            action=action,
            actor=actor,
            actor_role=actor_role,
            resource_type=resource_type,
            resource_id=resource_id,
            method=request.method,
            path=request.url.path,
            status=200,
            request_id=getattr(request.state, "request_id", None),
            details=details or {},
        )
    except Exception:  # noqa: BLE001
        logger.exception("fleet_audit_failed", extra={"action": action, "id": resource_id})


async def _require_agent(pool, agent_id: UUID, token: str | None) -> dict[str, Any]:
    """Authenticate an agent-facing call by its minted credential (defence in depth).

    The governance middleware already gates the route; this additionally proves
    the caller is *this* agent, so one agent can never act as another.
    """
    if not token:
        raise HTTPException(status_code=401, detail="missing agent token")
    token_hash = auth_svc.hash_api_key(token.strip())
    async with pool.acquire() as con:
        row = await con.fetchrow(
            "SELECT id, hostname, platform, status, token_hash FROM fleet_agents WHERE id = $1",
            agent_id,
        )
    if row is None:
        raise HTTPException(status_code=404, detail="agent not found")
    if row["status"] == "revoked":
        raise HTTPException(status_code=403, detail="agent revoked")
    stored = row["token_hash"]
    if not stored or not hmac.compare_digest(stored, token_hash):
        raise HTTPException(status_code=401, detail="invalid agent token")
    return dict(row)


# --------------------------------------------------------------------------- #
# Enrollment
# --------------------------------------------------------------------------- #

@router.post("/enroll", response_model=EnrollOut, status_code=status.HTTP_201_CREATED)
async def enroll(
    body: EnrollIn,
    request: Request,
    pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    """Enroll a host agent. Validates the bootstrap token, mints an agent id +
    a one-time credential (only its sha256 is stored), upserts by hostname."""
    secret = _enroll_secret()
    if secret is not None:
        if not hmac.compare_digest(body.token, secret):
            raise HTTPException(status_code=401, detail="invalid enrollment token")
    else:
        logger.warning(
            "FLEET_ENROLL_TOKEN unset -- accepting enrollment for %r without a "
            "shared secret (dev mode). Set FLEET_ENROLL_TOKEN in production.",
            body.hostname,
        )

    platform = body.platform.lower().strip()
    if platform not in ("linux", "windows", "macos"):
        raise HTTPException(status_code=422, detail="platform must be linux|windows|macos")

    full, prefix, token_hash = generate_agent_token()
    caps = sorted({c for c in (body.capabilities or ["inventory"]) if c}) or ["inventory"]

    async with pool.acquire() as con:
        row = await con.fetchrow(
            """
            INSERT INTO fleet_agents
                (hostname, platform, agent_version, labels, capabilities,
                 status, token_prefix, token_hash, enrolled_by)
            VALUES ($1,$2,$3,$4::text[],$5::text[],'enrolled',$6,$7,$8)
            ON CONFLICT (hostname) DO UPDATE SET
                platform = EXCLUDED.platform,
                agent_version = EXCLUDED.agent_version,
                labels = EXCLUDED.labels,
                capabilities = EXCLUDED.capabilities,
                status = 'enrolled',
                token_prefix = EXCLUDED.token_prefix,
                token_hash = EXCLUDED.token_hash,
                enrolled_by = EXCLUDED.enrolled_by,
                enrolled_at = NOW()
            RETURNING id, hostname, platform, status, capabilities
            """,
            body.hostname, platform, body.agent_version, list(body.labels),
            caps, prefix, token_hash, principal.actor,
        )

    await _audit(
        request, pool, action="enroll", resource_type="fleet_agent",
        resource_id=str(row["id"]), actor=principal.actor, actor_role=principal.role,
        details={"hostname": body.hostname, "platform": platform, "token_prefix": prefix},
    )
    return EnrollOut(
        id=row["id"], hostname=row["hostname"], platform=row["platform"],
        status=row["status"], agent_token=full, token_prefix=prefix,
        capabilities=list(row["capabilities"] or []),
    )


# --------------------------------------------------------------------------- #
# Heartbeat (agent-auth) -- updates last_seen + returns approved, real work
# --------------------------------------------------------------------------- #

@router.post("/{agent_id}/heartbeat", response_model=HeartbeatOut)
async def heartbeat(
    agent_id: UUID,
    body: HeartbeatIn,
    pool=Depends(get_pool),
    x_agent_token: str | None = Header(default=None, alias="X-Agent-Token"),
):
    await _require_agent(pool, agent_id, x_agent_token)
    async with pool.acquire() as con:
        row = await con.fetchrow(
            """
            UPDATE fleet_agents
               SET last_seen = NOW(), status = 'online',
                   agent_version = COALESCE($2, agent_version)
             WHERE id = $1
         RETURNING id, status, last_seen
            """,
            agent_id, body.agent_version,
        )
        # Pull the work the agent may actually carry out: approved AND real
        # (dry_run = false). Dry-run simulations are driven by the operator CLI,
        # never auto-applied by the run loop.
        pend = await con.fetch(
            """
            SELECT id, action_type, target, dry_run, status, reason, revert_of, result
              FROM agent_actions
             WHERE agent_id = $1 AND status = 'approved' AND dry_run = FALSE
             ORDER BY created_at ASC
            """,
            agent_id,
        )
    pending = [
        PendingAction(
            id=p["id"], action_type=p["action_type"], target=p["target"],
            dry_run=p["dry_run"], status=p["status"], reason=p["reason"],
            revert_of=p["revert_of"], result=_as_dict(p["result"]),
        )
        for p in pend
    ]
    return HeartbeatOut(id=row["id"], status=row["status"], last_seen=row["last_seen"],
                        pending_actions=pending)


# --------------------------------------------------------------------------- #
# Inventory (agent-auth)
# --------------------------------------------------------------------------- #

@router.post("/{agent_id}/inventory", response_model=InventoryOut, status_code=201)
async def post_inventory(
    agent_id: UUID,
    body: InventoryIn,
    pool=Depends(get_pool),
    x_agent_token: str | None = Header(default=None, alias="X-Agent-Token"),
):
    import json
    await _require_agent(pool, agent_id, x_agent_token)
    async with pool.acquire() as con:
        row = await con.fetchrow(
            """
            INSERT INTO agent_inventory (agent_id, os_info, packages, listeners, posture)
            VALUES ($1, $2::jsonb, $3::jsonb, $4::jsonb, $5::jsonb)
            RETURNING id, collected_at
            """,
            agent_id, json.dumps(body.os_info), json.dumps(body.packages),
            json.dumps(body.listeners), json.dumps(body.posture),
        )
        await con.execute(
            "UPDATE fleet_agents SET last_seen = NOW() WHERE id = $1", agent_id
        )
    return InventoryOut(ok=True, inventory_id=row["id"], collected_at=row["collected_at"])


# --------------------------------------------------------------------------- #
# Agents list / detail
# --------------------------------------------------------------------------- #

@router.get("/agents", response_model=list[AgentOut])
async def list_agents(pool=Depends(get_pool)):
    async with pool.acquire() as con:
        rows = await con.fetch(
            """
            SELECT id, hostname, platform, agent_version, labels, capabilities,
                   status, last_seen, enrolled_at
              FROM fleet_agents
             ORDER BY hostname ASC
            """
        )
    out: list[AgentOut] = []
    for r in rows:
        out.append(AgentOut(
            id=r["id"], hostname=r["hostname"], platform=r["platform"],
            agent_version=r["agent_version"], labels=list(r["labels"] or []),
            capabilities=list(r["capabilities"] or []),
            status=_effective_status(r["status"], r["last_seen"]),
            last_seen=r["last_seen"], enrolled_at=r["enrolled_at"],
            stale=_stale(r["last_seen"]),
        ))
    return out


@router.get("/agents/{agent_id}", response_model=AgentDetailOut)
async def get_agent(agent_id: UUID, pool=Depends(get_pool)):
    async with pool.acquire() as con:
        r = await con.fetchrow(
            """
            SELECT id, hostname, platform, agent_version, labels, capabilities,
                   status, last_seen, enrolled_at
              FROM fleet_agents WHERE id = $1
            """,
            agent_id,
        )
        if r is None:
            raise HTTPException(status_code=404, detail="agent not found")
        inv = await con.fetchrow(
            """
            SELECT id, collected_at, os_info, packages, listeners, posture
              FROM agent_inventory WHERE agent_id = $1
             ORDER BY collected_at DESC LIMIT 1
            """,
            agent_id,
        )
        counts = await con.fetch(
            "SELECT status, COUNT(*) AS c FROM agent_actions WHERE agent_id = $1 GROUP BY status",
            agent_id,
        )
    snapshot = None
    if inv is not None:
        snapshot = InventorySnapshot(
            id=inv["id"], collected_at=inv["collected_at"],
            os_info=_as_dict(inv["os_info"]),
            packages=_as_dict_list(inv["packages"]),
            listeners=_as_dict_list(inv["listeners"]),
            posture=_as_dict(inv["posture"]),
        )
    return AgentDetailOut(
        id=r["id"], hostname=r["hostname"], platform=r["platform"],
        agent_version=r["agent_version"], labels=list(r["labels"] or []),
        capabilities=list(r["capabilities"] or []),
        status=_effective_status(r["status"], r["last_seen"]),
        last_seen=r["last_seen"], enrolled_at=r["enrolled_at"],
        stale=_stale(r["last_seen"]), inventory=snapshot,
        action_counts={c["status"]: int(c["c"]) for c in counts},
    )


def _as_dict_list(v: Any) -> list[dict[str, Any]]:
    if v is None:
        return []
    if isinstance(v, str):
        import json
        try:
            v = json.loads(v)
        except Exception:  # noqa: BLE001
            return []
    return [x for x in v if isinstance(x, dict)]


# --------------------------------------------------------------------------- #
# Actions: propose / approve / deny / list / result / revert
# --------------------------------------------------------------------------- #

@router.post("/actions", response_model=ActionOut, status_code=201)
async def propose_action(
    body: ActionProposeIn,
    request: Request,
    pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    """Propose an enforcement action. ALWAYS created dry_run=TRUE and
    status='proposed'. A requester can never self-grant a real apply."""
    import json
    if body.action_type not in PROPOSABLE_ACTIONS:
        raise HTTPException(status_code=422, detail="action_type not proposable")
    try:
        target = assert_host_local(body.action_type, body.target)
    except HostLocalError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    async with pool.acquire() as con:
        agent = await con.fetchrow("SELECT id FROM fleet_agents WHERE id = $1", body.agent_id)
        if agent is None:
            raise HTTPException(status_code=404, detail="agent not found")
        row = await con.fetchrow(
            """
            INSERT INTO agent_actions
                (agent_id, action_type, target, reason, indicator_id, finding_id,
                 dry_run, status, requested_by, result)
            VALUES ($1,$2,$3,$4,$5,$6, TRUE, 'proposed', $7, $8::jsonb)
            RETURNING id, agent_id, action_type, target, reason, indicator_id,
                      finding_id, dry_run, status, requested_by, approved_by,
                      result, created_at, decided_at, applied_at, revert_of
            """,
            body.agent_id, body.action_type, target, body.reason,
            body.indicator_id, body.finding_id, principal.actor,
            json.dumps({"host_local": True}),
        )
    await _audit(
        request, pool, action="propose", resource_type="fleet_action",
        resource_id=str(row["id"]), actor=principal.actor, actor_role=principal.role,
        details={"action_type": body.action_type, "target": target, "dry_run": True},
    )
    return _row_to_action(row)


@router.post(
    "/actions/{action_id}/approve",
    response_model=ActionOut,
    dependencies=[Depends(require("admin"))],
)
async def approve_action(
    action_id: UUID,
    body: ApproveIn,
    request: Request,
    pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    """Admin-only. proposed -> approved. Sets approved_by + decided_at.
    Four-eyes: the approver must differ from the requester. A REAL host change
    requires ``apply_for_real=true`` (which flips dry_run to false) -- the
    single, conscious human act that satisfies safety rails #2 and #3."""
    async with pool.acquire() as con:
        cur = await con.fetchrow(
            "SELECT status, requested_by, action_type FROM agent_actions WHERE id = $1",
            action_id,
        )
        if cur is None:
            raise HTTPException(status_code=404, detail="action not found")
        if cur["status"] != "proposed":
            raise HTTPException(
                status_code=409,
                detail=f"cannot approve an action in status '{cur['status']}'",
            )
        self_approve = (cur["requested_by"] is not None
                        and cur["requested_by"] == principal.actor)
        if self_approve and not _allow_self_approve():
            # Four-eyes enforced AND recorded.
            await _audit(
                request, pool, action="approve_denied_four_eyes",
                resource_type="fleet_action", resource_id=str(action_id),
                actor=principal.actor, actor_role=principal.role,
                details={"requested_by": cur["requested_by"], "reason": "four_eyes"},
            )
            raise HTTPException(
                status_code=409,
                detail="four-eyes: approver must differ from requester",
            )
        row = await con.fetchrow(
            """
            UPDATE agent_actions
               SET status = 'approved', approved_by = $2, decided_at = NOW(),
                   dry_run = $3
             WHERE id = $1
         RETURNING id, agent_id, action_type, target, reason, indicator_id,
                   finding_id, dry_run, status, requested_by, approved_by,
                   result, created_at, decided_at, applied_at, revert_of
            """,
            action_id, principal.actor, (not body.apply_for_real),
        )
    await _audit(
        request, pool, action="approve", resource_type="fleet_action",
        resource_id=str(action_id), actor=principal.actor, actor_role=principal.role,
        details={
            "apply_for_real": body.apply_for_real,
            "dry_run": (not body.apply_for_real),
            "self_approve": self_approve,
            "note": body.note,
        },
    )
    return _row_to_action(row)


@router.post(
    "/actions/{action_id}/deny",
    response_model=ActionOut,
    dependencies=[Depends(require("admin"))],
)
async def deny_action(
    action_id: UUID,
    body: DenyIn,
    request: Request,
    pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    """Admin-only. proposed -> denied."""
    async with pool.acquire() as con:
        cur = await con.fetchrow("SELECT status FROM agent_actions WHERE id = $1", action_id)
        if cur is None:
            raise HTTPException(status_code=404, detail="action not found")
        if cur["status"] != "proposed":
            raise HTTPException(
                status_code=409, detail=f"cannot deny an action in status '{cur['status']}'"
            )
        row = await con.fetchrow(
            """
            UPDATE agent_actions
               SET status = 'denied', approved_by = $2, decided_at = NOW()
             WHERE id = $1
         RETURNING id, agent_id, action_type, target, reason, indicator_id,
                   finding_id, dry_run, status, requested_by, approved_by,
                   result, created_at, decided_at, applied_at, revert_of
            """,
            action_id, principal.actor,
        )
    await _audit(
        request, pool, action="deny", resource_type="fleet_action",
        resource_id=str(action_id), actor=principal.actor, actor_role=principal.role,
        details={"note": body.note},
    )
    return _row_to_action(row)


@router.get("/actions", response_model=ActionPage)
async def list_actions(
    agent: UUID | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    pool=Depends(get_pool),
):
    clauses: list[str] = []
    args: list[Any] = []
    if agent is not None:
        args.append(agent)
        clauses.append(f"agent_id = ${len(args)}")
    if status_filter is not None:
        if status_filter not in ACTION_STATUSES:
            raise HTTPException(status_code=422, detail="invalid status filter")
        args.append(status_filter)
        clauses.append(f"status = ${len(args)}")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    sql_count = f"SELECT COUNT(*) FROM agent_actions {where}"
    args_list = list(args)
    args_list.extend([limit, offset])
    sql = f"""
        SELECT id, agent_id, action_type, target, reason, indicator_id,
               finding_id, dry_run, status, requested_by, approved_by,
               result, created_at, decided_at, applied_at, revert_of
          FROM agent_actions
          {where}
         ORDER BY created_at DESC
         LIMIT ${len(args_list) - 1} OFFSET ${len(args_list)}
    """
    async with pool.acquire() as con:
        total = await con.fetchval(sql_count, *args)
        rows = await con.fetch(sql, *args_list)
    return ActionPage(items=[_row_to_action(r) for r in rows], total=int(total or 0))


@router.post("/actions/{action_id}/result", response_model=ActionOut)
async def post_result(
    action_id: UUID,
    body: ResultIn,
    request: Request,
    pool=Depends(get_pool),
    x_agent_token: str | None = Header(default=None, alias="X-Agent-Token"),
):
    """Agent reports the outcome of a real apply. Guards enforce rails #2 + #3:
    an action may only be reported ``applied`` when it is ``approved`` AND
    ``dry_run = false``. A dry-run can never mutate, so it can never be
    ``applied`` here."""
    import json
    async with pool.acquire() as con:
        cur = await con.fetchrow(
            "SELECT agent_id, status, dry_run, action_type, revert_of FROM agent_actions WHERE id = $1",
            action_id,
        )
        if cur is None:
            raise HTTPException(status_code=404, detail="action not found")
        await _require_agent(pool, cur["agent_id"], x_agent_token)

        if cur["status"] != "approved":
            raise HTTPException(
                status_code=409,
                detail=f"action must be 'approved' to report a result (is '{cur['status']}')",
            )
        if body.status == "applied" and cur["dry_run"]:
            # Rail #3: a dry-run action can never become a real applied block.
            raise HTTPException(
                status_code=409,
                detail="dry-run action cannot be applied; approve for real first",
            )
        if body.status == "applied" and cur["action_type"] != "revert" and not body.revert:
            # Rail #5: an applied block MUST record how to undo it.
            raise HTTPException(
                status_code=422,
                detail="applied action must include a 'revert' plan",
            )

        result_payload = {"output": body.output}
        if body.revert is not None:
            result_payload["revert"] = body.revert

        row = await con.fetchrow(
            """
            UPDATE agent_actions
               SET status = $2,
                   applied_at = CASE WHEN $2 = 'applied' THEN NOW() ELSE applied_at END,
                   result = result || $3::jsonb
             WHERE id = $1
         RETURNING id, agent_id, action_type, target, reason, indicator_id,
                   finding_id, dry_run, status, requested_by, approved_by,
                   result, created_at, decided_at, applied_at, revert_of
            """,
            action_id, body.status, json.dumps(result_payload),
        )

        # When a REVERT action completes, the original action becomes 'reverted'.
        if (body.status == "applied" and cur["action_type"] == "revert"
                and cur["revert_of"] is not None):
            await con.execute(
                "UPDATE agent_actions SET status = 'reverted' WHERE id = $1",
                cur["revert_of"],
            )

    await _audit(
        request, pool,
        action=("apply" if body.status == "applied" else "fail"),
        resource_type="fleet_action", resource_id=str(action_id),
        actor=f"agent:{cur['agent_id']}", actor_role="agent",
        details={"status": body.status, "action_type": cur["action_type"]},
    )
    if (body.status == "applied" and cur["action_type"] == "revert"
            and cur["revert_of"] is not None):
        await _audit(
            request, pool, action="reverted", resource_type="fleet_action",
            resource_id=str(cur["revert_of"]), actor=f"agent:{cur['agent_id']}",
            actor_role="agent", details={"by_revert_action": str(action_id)},
        )
    return _row_to_action(row)


@router.post("/actions/{action_id}/revert", response_model=ActionOut, status_code=201)
async def revert_action(
    action_id: UUID,
    body: RevertIn,
    request: Request,
    pool=Depends(get_pool),
    principal: Principal = Depends(current_principal),
):
    """Mint a first-class, pre-approved REVERT action for an applied block.
    Reverting is de-escalation (removing a block), so it is auto-approved but
    still audited; the agent executes it and reports a result, at which point
    the original action transitions to 'reverted'."""
    import json
    async with pool.acquire() as con:
        orig = await con.fetchrow(
            """
            SELECT id, agent_id, action_type, target, status, result
              FROM agent_actions WHERE id = $1
            """,
            action_id,
        )
        if orig is None:
            raise HTTPException(status_code=404, detail="action not found")
        if orig["status"] != "applied":
            raise HTTPException(
                status_code=409,
                detail=f"only an 'applied' action can be reverted (is '{orig['status']}')",
            )
        revert_plan = _as_dict(orig["result"]).get("revert", {})
        child = await con.fetchrow(
            """
            INSERT INTO agent_actions
                (agent_id, action_type, target, reason, dry_run, status,
                 requested_by, approved_by, decided_at, revert_of, result)
            VALUES ($1,'revert',$2,$3, FALSE, 'approved', $4, $4, NOW(), $5, $6::jsonb)
            RETURNING id, agent_id, action_type, target, reason, indicator_id,
                      finding_id, dry_run, status, requested_by, approved_by,
                      result, created_at, decided_at, applied_at, revert_of
            """,
            orig["agent_id"], orig["target"],
            (body.note or f"revert of {action_id}"),
            principal.actor, action_id,
            json.dumps({"revert": revert_plan, "reverts_action": str(action_id)}),
        )
    await _audit(
        request, pool, action="revert", resource_type="fleet_action",
        resource_id=str(child["id"]), actor=principal.actor, actor_role=principal.role,
        details={"reverts_action": str(action_id), "note": body.note},
    )
    return _row_to_action(child)
