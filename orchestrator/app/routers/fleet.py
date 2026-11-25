"""Fleet agents + GATED defensive enforcement (schema 014) + signed host evidence (schema 041).

A host agent enrolls here with a per-tenant one-time token, proves possession of an Ed25519 key, and from then on
speaks through SIGNED envelopes (docs/ASSURANCE_P2.md section 2): heartbeat, posture, key rotation. It can also
apply HOST-LOCAL defensive blocks, but only through a strict, auditable gate:

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

Audiences (see ``auth._RULES``):

* **agents** (``X-Agent-Token: fat_...`` -> the *agent principal*, capability ``agent``, held by no role, key or
  scope): ``/{id}/heartbeat``, ``/{id}/posture``, ``/{id}/keys/rotate``, ``/{id}/inventory`` (v1, unsigned, never
  evidence) and ``/actions/{id}/result``. Every handler asserts ``principal.agent_id`` equals the id it acts on.
* **enrollment** (``POST /enroll``): public to the middleware, authenticated here by the ``fet_`` token.
* **admins**: enrollment tokens, agent and key revocation, the action gate.
* **triage**: the full latest posture of one agent. ``GET /agents[/{id}]`` stays a viewer-safe summary.

Signature verification, replay protection and persistence live in ``app/fleet_posture.py``; token and key
binding in ``app/fleet_enroll.py``; liveness in ``app/fleet_monitor.py``.

This router holds inline Pydantic models (we do not touch shared models.py).

Allowed action types ONLY: block_ip, block_domain, quarantine_file,
firewall_rule, revert. Nothing else. No scanning, no offensive capability.

Network quarantine (schema 025) reuses this exact gate: a
``quarantine_device`` / ``release_device`` row has NO agent and an
``integration_id``; it is proposed and executed by
``app/routers/network_actions.py`` and approved / denied / reverted here.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Annotated, Any, Literal
from uuid import UUID

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, StringConstraints, ValidationError

from .. import audit, fleet_enroll, fleet_monitor, fleet_posture
from ..auth import Principal, client_ip, client_ip_strict, current_principal, require
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

def _allow_self_approve() -> bool:
    """Four-eyes toggle. Default False: approver must differ from requester."""
    return (os.environ.get("FLEET_ALLOW_SELF_APPROVE", "").strip().lower()
            in {"1", "true", "yes", "on"})


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
    """``POST /v1/fleet/enroll``. The token travels in the body, never in a header or URL."""
    model_config = {"extra": "forbid"}
    token: str = Field(min_length=1, max_length=256, description="per-tenant enrollment token (fet_...)")
    hostname: str = Field(min_length=1, max_length=253)
    public_key_b64: str = Field(min_length=1, max_length=128, description="raw 32-byte Ed25519 public key")
    proof_b64: str = Field(min_length=1, max_length=256,
                           description="the key's signature over 'paddock-enroll/v1\\n<token prefix>\\n<hostname>'")
    agent_version: str | None = Field(default=None, max_length=64)
    platform: str = Field(default="linux", max_length=16, description="linux | windows | macos")
    capabilities: list[Annotated[str, StringConstraints(max_length=32)]] | None = Field(
        default=None, max_length=16)


class EnrollOut(BaseModel):
    agent_id: UUID
    agent_token: str = Field(description="shown ONCE; store it 0600 on the host")
    key_id: str
    tenant_id: UUID
    server_time: str
    hostname: str
    token_prefix: str
    rekey: bool = Field(description="true when this enrollment rebound an existing agent (history kept)")


class TokenMintIn(BaseModel):
    model_config = {"extra": "forbid"}
    label: str | None = Field(default=None, max_length=128)
    labels: list[str] = Field(default_factory=list, max_length=fleet_enroll.MAX_LABELS,
                              description="labels given to the agents this token enrolls")
    max_uses: int = Field(default=1, ge=1, le=fleet_enroll.MAX_USES_LIMIT)
    ttl_minutes: int = Field(default=fleet_enroll.DEFAULT_TTL_MINUTES, ge=1,
                             le=fleet_enroll.MAX_TTL_MINUTES_SINGLE,
                             description="at most 24 h when max_uses > 1")
    for_agent: UUID | None = Field(
        default=None, description="re-key token: rebinds this EXISTING agent (history kept); single use")


class TokenOut(BaseModel):
    id: UUID
    token_prefix: str
    label: str
    labels: list[str]
    max_uses: int
    uses: int
    for_agent: UUID | None
    created_by: str | None
    created_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    revoked_by: str | None
    state: str = Field(description="pending | active | used | expired | revoked")


class TokenCreated(TokenOut):
    token: str = Field(description="the enrollment token; shown ONCE")


class RevokeIn(BaseModel):
    model_config = {"extra": "forbid"}
    reason: str | None = Field(default=None, max_length=512)


class AgentRevokeIn(RevokeIn):
    revoke_enroll_token: bool = Field(
        default=True,
        description="also revoke the multi-use enrollment token this agent was first enrolled with (if it has uses "
                    "left), so a revoked host cannot re-enroll under a new name. False keeps the fleet token for "
                    "the hosts that have not enrolled yet")


class KeyRevokeIn(RevokeIn):
    successors: Literal["revoke", "keep"] | None = Field(
        default=None,
        description="required when the key was rotated and its successor is still active: 'revoke' revokes the whole "
                    "chain (the stolen-key case), 'keep' revokes only this key (cleanup after a legitimate "
                    "rotation). Without it the call changes nothing and answers 409 listing active_successors. "
                    "Revoking the AGENT is the incident action")


class PostureAck(BaseModel):
    ok: bool
    seq: int
    stored: bool = Field(description="a posture row was written (content changed, or the hourly refresh)")
    changed: bool = Field(description="the content digest differs from the last stored posture")
    idempotent: bool = False
    server_time: str


class RotateAck(BaseModel):
    ok: bool
    key_id: str = Field(description="the new, now active, key id")
    server_time: str


class EnvelopeDoc(BaseModel):
    """Documentation of the signed envelope (docs/ASSURANCE_P2.md section 2). The handler parses the raw bytes
    itself (strict JSON, duplicate keys refused); this model only describes them."""
    v: int
    alg: str = "ed25519"
    kid: str
    agent_id: UUID
    tenant_id: UUID
    kind: Literal["posture", "heartbeat", "rotate"]
    seq: int = Field(ge=1)
    issued_at: str
    nonce: str
    payload_type: str
    payload_sha256: str
    payload_len: int
    collectors: dict[str, str]
    payload_b64: str
    sig: str


def _envelope_body_doc() -> dict[str, Any]:
    return {"requestBody": {"required": True, "content": {
        "application/json": {"schema": EnvelopeDoc.model_json_schema()}}}}


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
    server_time: str | None = None
    idempotent: bool = False


class InventoryIn(BaseModel):
    """The v1 inventory body (Fleet page only). UNSIGNED: it is never evidence for an invariant."""
    model_config = {"extra": "forbid"}
    os_info: dict[str, Any] = Field(default_factory=dict)
    packages: list[dict[str, Any]] = Field(default_factory=list, max_length=20000)
    listeners: list[dict[str, Any]] = Field(default_factory=list, max_length=5000)
    posture: dict[str, Any] = Field(default_factory=dict)


class InventoryOut(BaseModel):
    ok: bool
    inventory_id: UUID
    collected_at: datetime
    signed: bool = Field(default=False, description="always false: the v1 inventory is never evidence")


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
    # schema 041
    online: bool = True
    legacy: bool = Field(default=False, description="a v1 agent without a key: it must re-enroll")
    node_ref: str | None = None
    silent_after_s: int = 300
    key_id: str | None = Field(default=None, description="the agent's active signing key")
    last_posture_at: datetime | None = None


class InventorySnapshot(BaseModel):
    id: UUID
    collected_at: datetime
    os_info: dict[str, Any]
    packages: list[dict[str, Any]]
    listeners: list[dict[str, Any]]
    posture: dict[str, Any]
    signed: bool = Field(default=False, description="always false: the v1 inventory is never evidence")


class KeyOut(BaseModel):
    key_id: str
    alg: str
    status: str
    last_seq: int
    created_at: datetime
    retired_at: datetime | None = None
    revoked_at: datetime | None = None
    revoke_reason: str | None = None


class AgentRevokeOut(AgentOut):
    enroll_token_prefix: str | None = Field(
        default=None, description="prefix of the enrollment token this agent was first enrolled with (None: unknown)")
    enroll_token_revoked: bool = Field(
        default=False, description="that token was revoked by this call (it still had uses left)")


class AgentDetailOut(AgentOut):
    inventory: InventorySnapshot | None = None
    action_counts: dict[str, int] = Field(default_factory=dict)
    keys: list[KeyOut] = Field(default_factory=list)
    identity: dict[str, Any] = Field(default_factory=dict, description="claimed identity (hostname, ips, basis)")


class PostureOut(BaseModel):
    """The full latest signed posture of an agent (``triage``). Tier is ``configured`` at best: signed is not true."""
    agent_id: UUID
    key_id: str
    key_status: str | None = Field(description="status of the key that signed it (a revoked key's posture is untrusted)")
    seq: int
    schema_version: int
    collected_at: datetime
    received_at: datetime
    signed: bool
    tier: str
    payload_sha256: str
    size_bytes: int
    header: dict[str, Any]
    payload: dict[str, Any] | None
    agent_status: str
    online: bool
    last_seen: datetime | None
    silent_after_s: int
    node_ref: str | None


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


# Network quarantine/release cuts a device off a customer's network, so the
# decision must say why. Host-agent actions keep the optional note.
_NETWORK_ACTION_TYPES = frozenset({"quarantine_device", "release_device"})


def _require_decision_reason(action_type: str | None, note: str | None) -> None:
    if action_type in _NETWORK_ACTION_TYPES and not (note or "").strip():
        raise HTTPException(
            status_code=422, detail="a reason (note) is required to decide a network action",
        )


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


def _effective_status(db_status: str, last_seen: datetime | None, online: bool = True,
                      legacy: bool = False) -> str:
    if db_status in ("revoked", "enrolled"):
        return db_status
    if legacy:
        return "stale"          # a v1 agent can no longer report: it only ages
    if not online:
        return "offline"
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


def _assert_agent(principal: Principal, agent_id: UUID | str) -> None:
    """The caller must BE the agent it acts on: an agent principal (capability ``agent``, which no user, key or
    service credential holds) whose ``agent_id`` equals ``agent_id``. Anything else is a 403, so one agent can never
    act as, or post evidence for, another, and an admin key can never post agent evidence."""
    if (principal.kind != "agent" or not principal.has("agent")
            or principal.agent_id is None or principal.agent_id != str(agent_id)):
        raise HTTPException(status_code=403, detail="this route is for the agent itself")


def _agent_principal(agent_id: UUID, principal: Principal = Depends(current_principal)) -> Principal:
    _assert_agent(principal, agent_id)
    return principal


def _note_sampled(request: Request, rej: fleet_posture.Rejection) -> None:
    """Tell the per-request audit middleware that this rejection was folded into an aggregate / counter instead of
    getting its own ``fleet.evidence.*`` row, so it may skip its own outcome row for the same request (it is the
    middleware's one-row-per-request that would otherwise still grow the chain without bound under a flood)."""
    if not rej.audit_row:
        request.state.audit_aggregated = True


async def _require_active_key(pool, agent_id: UUID | str) -> JSONResponse | None:
    """The bearer alone is not a usable credential: every agent route needs an ACTIVE signing key, so revoking the
    key (the key-compromise runbook) cuts the unsigned routes too. ``None`` when there is one. The signed routes
    (heartbeat, posture, rotate) check their own key; re-keying is by a new enrollment token, never by this bearer."""
    async with pool.acquire() as con:
        ok = await con.fetchval(
            "SELECT 1 FROM fleet_agent_keys WHERE agent_id = $1 AND status = 'active' LIMIT 1", UUID(str(agent_id)))
    if ok:
        return None
    return JSONResponse({"detail": "the agent has no active signing key; re-enroll it", "reason": "key_not_active"},
                        status_code=401)


def _rejection_response(rej: fleet_posture.Rejection, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse(rej.response_body(), status_code=rej.status, headers=headers)


async def _read_body(request: Request, limit: int) -> bytes:
    """The raw request body, never more than ``limit`` bytes (declared length first, then the stream)."""
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > limit:
        raise fleet_posture.Rejection(413, "body_too_large", f"the body exceeds {limit} bytes")
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            raise fleet_posture.Rejection(413, "body_too_large", f"the body exceeds {limit} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


async def _ingest(request: Request, pool, principal: Principal, agent_id: UUID, kind: str):
    """The shared body of heartbeat / posture / rotate. Order, cheapest first:

    1. a pre-auth slot keyed by (agent, STRICT peer address), taken in one synchronous step: if that pair already
       holds too many unverified requests this minute the request is a 429 before any body is read (the per-agent
       budget is not touched). The slot is given back once the signature verified;
    2. the capped body read, then ``fleet_posture`` checks 1-10 with the per-agent budget charged only for an ACCEPTED
       envelope (a fresh seq in the clock window), so neither a holder of the bearer alone nor a replay of a captured
       signed envelope can exhaust the real agent's budget (replays have a bucket of their own);
    3. any other exception is audited as a rejection too (these routes are exempt from the per-request audit row).

    Returns ``(IngestResult, None)`` or ``(None, JSONResponse)``."""
    route = "rotate" if kind == "rotate" else kind
    tenant = str(principal.tenant_id)
    rid = getattr(request.state, "request_id", None)
    ip = client_ip_strict(request)       # the host's address is a corroboration input: never the forgeable leftmost entry
    # ONE synchronous step: take a slot in the (agent, address) bucket. Check-then-act (blocked(), then a hit after the
    # body was read) let every concurrent request through the check before any of them recorded a failure.
    slot = fleet_posture.preauth_take(agent_id, ip)
    if slot is None:
        rej = fleet_posture.Rejection(429, "rate_limited", "too many failed requests for this agent from this address")
        await fleet_posture.record_rejection(pool, tenant_id=tenant, agent_id=agent_id, rej=rej, request_id=rid,
                                             client_ip=ip, kind=kind, actor=principal.actor)
        _note_sampled(request, rej)
        return None, _rejection_response(rej, {"Retry-After": "60"})

    def verified() -> None:
        """The signature verified: this request is not a failure, give its slot back."""
        fleet_posture.preauth_refund(agent_id, ip, slot)

    try:
        body = await _read_body(request, fleet_posture.MAX_BODY_BYTES)
    except fleet_posture.Rejection as rej:
        await fleet_posture.record_rejection(pool, tenant_id=tenant, agent_id=agent_id, rej=rej,
                                             request_id=rid, client_ip=ip, kind=kind, actor=principal.actor)
        _note_sampled(request, rej)
        return None, _rejection_response(rej)
    try:
        res = await fleet_posture.ingest_envelope(
            pool, agent_id=agent_id, tenant_id=tenant, kind=kind, body=body,
            content_encoding=request.headers.get("content-encoding"), client_ip=ip, request_id=rid,
            actor=principal.actor, budget=lambda: not fleet_posture.rate_limited(route, agent_id),
            replay_budget=lambda: not fleet_posture.rate_limited("replay", agent_id))
    except fleet_posture.Rejection as rej:
        _note_sampled(request, rej)
        if rej.verified or rej.status == 429:     # a signed envelope (or a budget answer, which only follows one)
            verified()
        return None, _rejection_response(rej, {"Retry-After": "60"} if rej.status == 429 else None)
    except Exception:  # noqa: BLE001 -- heartbeat/posture are exempt from the per-request audit row: audit the crash
        logger.exception("fleet_ingest_failed", extra={"agent": str(agent_id), "kind": kind})
        rej = fleet_posture.Rejection(500, "internal_error", "the server could not process this envelope")
        await fleet_posture.record_rejection(pool, tenant_id=tenant, agent_id=agent_id, rej=rej,
                                             request_id=rid, client_ip=ip, kind=kind, actor=principal.actor)
        _note_sampled(request, rej)
        return None, _rejection_response(rej)
    verified()
    if res.came_online:
        await fleet_monitor.emit_transition(
            pool, {"id": agent_id, "tenant_id": tenant, "hostname": res.agent.get("hostname", "")},
            "online", at=res.server_time)
    return res, None


def _pending(rows: list[dict[str, Any]]) -> list[PendingAction]:
    return [
        PendingAction(
            id=p["id"], action_type=p["action_type"], target=p["target"], dry_run=p["dry_run"],
            status=p["status"], reason=p["reason"], revert_of=p["revert_of"], result=_as_dict(p["result"]))
        for p in rows
    ]


# --------------------------------------------------------------------------- #
# Enrollment (public to the middleware; authenticated here by the fet_ token)
# --------------------------------------------------------------------------- #

@router.post("/enroll", response_model=EnrollOut, status_code=status.HTTP_201_CREATED)
async def enroll(body: EnrollIn, request: Request, pool=Depends(get_pool)):
    """Redeem a per-tenant enrollment token, bind an Ed25519 key (proof of possession required) and receive the
    agent credential, ONCE. Every token failure is the same generic 401; failures are rate limited and lock the
    client out; a taken hostname or key is a 409 that does not spend the token. A ``for_agent`` (re-key) token
    rebinds an existing agent and keeps its history. The body (it holds the token) is never logged."""
    try:
        out = await fleet_enroll.enroll_agent(
            pool, token=body.token, hostname=body.hostname, public_key_b64=body.public_key_b64,
            proof_b64=body.proof_b64, agent_version=body.agent_version, platform=body.platform,
            capabilities=body.capabilities, client_ip=client_ip_strict(request))
    except fleet_enroll.EnrollError as exc:
        headers = {"Retry-After": str(exc.retry_after)} if exc.retry_after else None
        raise HTTPException(status_code=exc.status, detail=exc.detail, headers=headers) from exc
    return EnrollOut(
        agent_id=out["agent_id"], agent_token=out["agent_token"], key_id=out["key_id"],
        tenant_id=out["tenant_id"], server_time=out["server_time"], hostname=out["hostname"],
        token_prefix=out["token_prefix"], rekey=out["rekey"])


# --------------------------------------------------------------------------- #
# Enrollment tokens (admin)
# --------------------------------------------------------------------------- #

def _token_out(view: dict[str, Any]) -> dict[str, Any]:
    return {k: view[k] for k in TokenOut.model_fields}


@router.post("/enroll-tokens", response_model=TokenCreated, status_code=201,
             dependencies=[Depends(require("admin"))])
async def mint_enroll_token(body: TokenMintIn, request: Request, pool=Depends(get_pool),
                            principal: Principal = Depends(current_principal)):
    """Mint a per-tenant enrollment token. Shown ONCE; only its sha256 is stored. Single use by default;
    ``max_uses`` up to 50 needs a ttl of at most 24 h (cloud-init fleets). ``for_agent`` mints a re-key token."""
    try:
        full, view = await fleet_enroll.mint_token(
            pool, actor=principal.actor, label=body.label, labels=body.labels, max_uses=body.max_uses,
            ttl_minutes=body.ttl_minutes, for_agent=body.for_agent)
    except fleet_enroll.TokenPolicyError as exc:
        raise HTTPException(status_code=404 if exc.code == "not_found" else 422, detail=exc.detail) from exc
    await _audit(request, pool, action="fleet.enroll_token.create", resource_type="fleet_enroll_token",
                 resource_id=str(view["id"]), actor=principal.actor, actor_role=principal.role,
                 details={"prefix": view["token_prefix"], "max_uses": view["max_uses"],
                          "ttl_minutes": body.ttl_minutes, "labels": view["labels"],
                          "for_agent": str(view["for_agent"]) if view["for_agent"] else None})
    return TokenCreated(token=full, **_token_out(view))


@router.get("/enroll-tokens", response_model=list[TokenOut], dependencies=[Depends(require("admin"))])
async def list_enroll_tokens(request: Request, pool=Depends(get_pool),
                             principal: Principal = Depends(current_principal),
                             limit: int = Query(default=100, ge=1, le=500)):
    """Token metadata (prefix, uses, state): never the token or its hash. Listing is audited."""
    rows = await fleet_enroll.list_tokens(pool, limit=limit)
    await _audit(request, pool, action="fleet.enroll_token.list", resource_type="fleet_enroll_token",
                 resource_id="*", actor=principal.actor, actor_role=principal.role,
                 details={"returned": len(rows)})
    return [TokenOut(**_token_out(v)) for v in rows]


@router.get("/enroll-tokens/{token_id}", response_model=TokenOut, dependencies=[Depends(require("admin"))])
async def get_enroll_token(token_id: UUID, pool=Depends(get_pool)):
    view = await fleet_enroll.get_token(pool, token_id)
    if view is None:
        raise HTTPException(status_code=404, detail="token not found")
    return TokenOut(**_token_out(view))


@router.delete("/enroll-tokens/{token_id}", status_code=204, dependencies=[Depends(require("admin"))])
async def revoke_enroll_token(token_id: UUID, request: Request, pool=Depends(get_pool),
                              principal: Principal = Depends(current_principal)):
    if not await fleet_enroll.revoke_token(pool, token_id, principal.actor):
        raise HTTPException(status_code=404, detail="token not found, already used up or already revoked")
    await _audit(request, pool, action="fleet.enroll_token.revoke", resource_type="fleet_enroll_token",
                 resource_id=str(token_id), actor=principal.actor, actor_role=principal.role, details={})


# --------------------------------------------------------------------------- #
# Signed evidence (agent principal): heartbeat, posture, key rotation
# --------------------------------------------------------------------------- #

@router.post("/{agent_id}/heartbeat", response_model=HeartbeatOut, openapi_extra=_envelope_body_doc())
async def heartbeat(agent_id: UUID, request: Request, pool=Depends(get_pool),
                    principal: Principal = Depends(_agent_principal)):
    """A SIGNED ``kind=heartbeat`` envelope. The only proof of life: an unsigned (stolen bearer) call can never
    refresh ``last_seen``. The reply lists the approved, real work for this host."""
    res, err = await _ingest(request, pool, principal, agent_id, "heartbeat")
    if err is not None:
        return err
    a = res.agent
    return HeartbeatOut(id=a["id"], status=a["status"], last_seen=a["last_seen"],
                        pending_actions=_pending(res.pending_actions), server_time=res.server_time,
                        idempotent=res.idempotent)


@router.post("/{agent_id}/posture", response_model=PostureAck, openapi_extra=_envelope_body_doc())
async def post_posture(agent_id: UUID, request: Request, pool=Depends(get_pool),
                       principal: Principal = Depends(_agent_principal)):
    """A SIGNED ``kind=posture`` envelope (paddock.host.posture/v2). Verified, replay-protected and schema-checked
    (docs/ASSURANCE_P2.md section 2); a rejected envelope leaves the previous posture in place."""
    res, err = await _ingest(request, pool, principal, agent_id, "posture")
    if err is not None:
        return err
    return PostureAck(ok=True, seq=res.seq, stored=res.stored, changed=res.changed,
                      idempotent=res.idempotent, server_time=res.server_time)


@router.post("/{agent_id}/keys/rotate", response_model=RotateAck, openapi_extra=_envelope_body_doc())
async def rotate_key(agent_id: UUID, request: Request, pool=Depends(get_pool),
                     principal: Principal = Depends(_agent_principal)):
    """A ``kind=rotate`` envelope signed by the CURRENT key carrying the new key and its proof of possession.
    The old key becomes ``rotated`` in the same transaction the new one becomes ``active``."""
    res, err = await _ingest(request, pool, principal, agent_id, "rotate")
    if err is not None:
        return err
    return RotateAck(ok=True, key_id=res.new_key_id or "", server_time=res.server_time)


# --------------------------------------------------------------------------- #
# Inventory (v1, agent principal): UNSIGNED, a Fleet-page convenience, never evidence
# --------------------------------------------------------------------------- #

#: v1 inventory bounds (unsigned, so tighter than the signed path): body size, rows kept per agent
INVENTORY_MAX_BODY_BYTES = 2 * 1024 * 1024
INVENTORY_KEEP_PER_AGENT = 5
_UNSTORABLE_RE = re.compile("[\x00\ud800-\udfff]")


@router.post("/{agent_id}/inventory", response_model=InventoryOut, status_code=201)
async def post_inventory(agent_id: UUID, request: Request, pool=Depends(get_pool),
                         principal: Principal = Depends(_agent_principal)):
    """The v1 inventory. Accepted only from an enrolled (non-legacy, non-revoked) agent WITH an active key, stored
    marked ``signed: false`` and NEVER used as evidence: it does not refresh ``last_seen`` (only a signed envelope
    can prove life) and no builder reads it. Bounded: at most 2 MiB, an inventory identical to the newest one only
    refreshes it (same id), and only the newest few per agent are kept."""
    if fleet_posture.rate_limited("inventory", agent_id):
        return JSONResponse({"detail": "too many requests from this agent; slow down"}, status_code=429,
                            headers={"Retry-After": "60"})
    denied = await _require_active_key(pool, agent_id)
    if denied is not None:
        return denied
    try:
        raw = await _read_body(request, INVENTORY_MAX_BODY_BYTES)
    except fleet_posture.Rejection as rej:
        return _rejection_response(rej)
    try:
        body = InventoryIn.model_validate_json(raw)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=[{"loc": e["loc"], "type": e["type"]}
                                                     for e in exc.errors()[:10]]) from exc
    if _unstorable_text(body.model_dump()):
        # Postgres jsonb cannot hold U+0000 (or a lone surrogate): answer 422 here, never a 500 from the insert
        raise HTTPException(status_code=422, detail="the inventory holds text that cannot be stored (NUL or a lone "
                                                    "surrogate)")
    try:
        digest = hashlib.sha256(json.dumps(body.model_dump(), sort_keys=True, separators=(",", ":")).encode()
                                ).hexdigest()
    except (UnicodeError, ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail="the inventory holds text that cannot be encoded") from exc
    posture = {**body.posture, "_evidence": {"signed": False, "tier": "declared"}, "_inventory_sha256": digest}
    try:
        return await _store_inventory(pool, agent_id, body, posture, digest)
    except asyncpg.exceptions.DataError as exc:             # belt and braces: any value the database refuses
        logger.warning("fleet_inventory_unstorable", extra={"agent": str(agent_id), "error": type(exc).__name__})
        raise HTTPException(status_code=422, detail="the inventory holds a value that cannot be stored") from exc


def _unstorable_text(value: Any) -> bool:
    """True if any string or key in ``value`` holds U+0000 or a lone surrogate (what jsonb refuses)."""
    stack = [value]
    while stack:
        v = stack.pop()
        if isinstance(v, str):
            if _UNSTORABLE_RE.search(v):
                return True
        elif isinstance(v, dict):
            for k, x in v.items():
                if isinstance(k, str) and _UNSTORABLE_RE.search(k):
                    return True
                stack.append(x)
        elif isinstance(v, (list, tuple)):
            stack.extend(v)
    return False


async def _store_inventory(pool, agent_id: UUID, body: InventoryIn, posture: dict[str, Any],
                           digest: str) -> InventoryOut:
    async with pool.acquire() as con:
        async with con.transaction():
            ok = await con.fetchrow(
                "SELECT tenant_id FROM fleet_agents WHERE id = $1 AND status <> 'revoked' AND legacy = FALSE "
                "FOR UPDATE", agent_id)
            if ok is None:
                raise HTTPException(status_code=403, detail="this agent is revoked or must re-enroll")
            same = await con.fetchrow(
                """UPDATE agent_inventory SET collected_at = NOW()
                    WHERE id = (SELECT id FROM agent_inventory WHERE agent_id = $1
                                 ORDER BY collected_at DESC LIMIT 1)
                      AND posture->>'_inventory_sha256' = $2
                RETURNING id, collected_at""", agent_id, digest)
            if same is not None:
                return InventoryOut(ok=True, inventory_id=same["id"], collected_at=same["collected_at"],
                                    signed=False)
            row = await con.fetchrow(
                """INSERT INTO agent_inventory (agent_id, os_info, packages, listeners, posture)
                   VALUES ($1, $2::jsonb, $3::jsonb, $4::jsonb, $5::jsonb) RETURNING id, collected_at""",
                agent_id, json.dumps(body.os_info), json.dumps(body.packages),
                json.dumps(body.listeners), json.dumps(posture))
            await con.execute(
                """DELETE FROM agent_inventory WHERE agent_id = $1 AND id NOT IN (
                       SELECT id FROM agent_inventory WHERE agent_id = $1
                        ORDER BY collected_at DESC, id LIMIT $2)""", agent_id, INVENTORY_KEEP_PER_AGENT)
            await fleet_posture.evict_inventory(con, ok["tenant_id"])
    return InventoryOut(ok=True, inventory_id=row["id"], collected_at=row["collected_at"], signed=False)


# --------------------------------------------------------------------------- #
# Agents list / detail
# --------------------------------------------------------------------------- #

_AGENT_COLS = (
    "a.id, a.hostname, a.platform, a.agent_version, a.labels, a.capabilities, a.status, a.last_seen, "
    "a.enrolled_at, a.online, a.legacy, a.node_ref, a.silent_after_s, a.last_posture_at, a.identity, "
    "(SELECT k.key_id FROM fleet_agent_keys k WHERE k.agent_id = a.id AND k.status = 'active' "
    " ORDER BY k.created_at DESC LIMIT 1) AS key_id"
)


def _agent_out(r: Any) -> AgentOut:
    return AgentOut(
        id=r["id"], hostname=r["hostname"], platform=r["platform"],
        agent_version=r["agent_version"], labels=list(r["labels"] or []),
        capabilities=list(r["capabilities"] or []),
        status=_effective_status(r["status"], r["last_seen"], r["online"], r["legacy"]),
        last_seen=r["last_seen"], enrolled_at=r["enrolled_at"],
        stale=_stale(r["last_seen"]), online=r["online"], legacy=r["legacy"], node_ref=r["node_ref"],
        silent_after_s=r["silent_after_s"], key_id=r["key_id"], last_posture_at=r["last_posture_at"],
    )


_PUBLIC_IDENTITY_KEYS = ("hostname", "basis", "note", "ips")


def _public_identity(raw: Any) -> dict[str, Any]:
    """The viewer-safe part of the claimed identity: hostname, basis (claimed | corroborated), the node note and
    the claimed bind addresses (the v1 inventory already shows listeners to viewers). The machine-id hash, the boot
    id, the address the server saw the agent connect from and the ingest bookkeeping (``_ingest``) stay server-side."""
    ident = _as_dict(raw)
    return {k: ident[k] for k in _PUBLIC_IDENTITY_KEYS if k in ident}


@router.get("/agents", response_model=list[AgentOut])
async def list_agents(pool=Depends(get_pool)):
    async with pool.acquire() as con:
        rows = await con.fetch(f"SELECT {_AGENT_COLS} FROM fleet_agents a ORDER BY a.hostname ASC")
    return [_agent_out(r) for r in rows]


@router.get("/agents/{agent_id}", response_model=AgentDetailOut)
async def get_agent(agent_id: UUID, pool=Depends(get_pool)):
    async with pool.acquire() as con:
        r = await con.fetchrow(f"SELECT {_AGENT_COLS} FROM fleet_agents a WHERE a.id = $1", agent_id)
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
            signed=False,
        )
    keys = [KeyOut(**k) for k in await fleet_posture.list_keys(pool, agent_id)]
    return AgentDetailOut(
        **_agent_out(r).model_dump(), inventory=snapshot,
        action_counts={c["status"]: int(c["c"]) for c in counts},
        keys=keys, identity=_public_identity(r["identity"]),
    )


@router.get("/agents/{agent_id}/posture", response_model=PostureOut)
async def get_agent_posture(agent_id: UUID, request: Request, pool=Depends(get_pool)):
    """The full latest SIGNED posture (``triage``): firewall rules, listeners, sshd and patch state. Reading it
    is audited. ``tier`` is ``configured`` at best (E2): signed is not true."""
    request.state.audit_restricted = True
    async with pool.acquire() as con:
        r = await con.fetchrow(f"SELECT {_AGENT_COLS} FROM fleet_agents a WHERE a.id = $1", agent_id)
    if r is None:
        raise HTTPException(status_code=404, detail="agent not found")
    p = await fleet_posture.latest_posture(pool, agent_id)
    if p is None:
        raise HTTPException(status_code=404, detail="no signed posture has been accepted for this agent yet")
    return PostureOut(
        **{k: p[k] for k in ("agent_id", "key_id", "key_status", "seq", "schema_version", "collected_at",
                             "received_at", "signed", "tier", "payload_sha256", "size_bytes", "header",
                             "payload")},
        agent_status=_effective_status(r["status"], r["last_seen"], r["online"], r["legacy"]),
        online=r["online"], last_seen=r["last_seen"], silent_after_s=r["silent_after_s"],
        node_ref=r["node_ref"])


@router.post("/agents/{agent_id}/revoke", response_model=AgentRevokeOut, dependencies=[Depends(require("admin"))])
async def revoke_agent(agent_id: UUID, body: AgentRevokeIn, request: Request, pool=Depends(get_pool),
                       principal: Principal = Depends(current_principal)):
    """THE incident action for a stolen or compromised host. Revoke an agent NOW: its credential and every key stop
    working on the very next call, its pending re-key tokens are revoked, and the host drops out of the reach graph's
    coverage (it stays in the graph as a tombstone and reads UNKNOWN). Nothing is cached.

    By default it also revokes the multi-use fleet enrollment token the agent came from (``revoke_enroll_token``),
    so the host cannot re-enroll as a new agent; the response says which token and whether it was revoked."""
    info: dict[str, Any] = {}
    out = await fleet_posture.revoke_agent(
        pool, agent_id, actor=principal.actor, actor_role=principal.role, reason=body.reason or "",
        client_ip=client_ip(request), request_id=getattr(request.state, "request_id", None),
        revoke_enroll_token=body.revoke_enroll_token, info=info)
    if out == "not_found":
        raise HTTPException(status_code=404, detail="agent not found")
    if out == "already_revoked":
        raise HTTPException(status_code=409, detail="agent is already revoked")
    async with pool.acquire() as con:
        r = await con.fetchrow(f"SELECT {_AGENT_COLS} FROM fleet_agents a WHERE a.id = $1", agent_id)
    return AgentRevokeOut(**_agent_out(r).model_dump(), enroll_token_prefix=info.get("enroll_token_prefix"),
                          enroll_token_revoked=bool(info.get("enroll_token_revoked")))


@router.post("/agents/{agent_id}/keys/{key_id}/revoke", dependencies=[Depends(require("admin"))])
async def revoke_agent_key(agent_id: UUID, request: Request, body: KeyRevokeIn,
                           key_id: str = Path(pattern=r"^[0-9a-f]{32}$"), pool=Depends(get_pool),
                           principal: Principal = Depends(current_principal)):
    """Revoke one signing key. Evidence it signs is refused from the next call on; revoking the active key
    leaves the agent unable to post until an admin mints it a re-key token. A ROTATED key whose successor is still
    active needs ``successors``: 'revoke' (the whole chain, for a stolen key) or 'keep'; otherwise 409 and nothing
    changes. For an incident revoke the agent instead (``POST /agents/{id}/revoke``)."""
    info: dict[str, Any] = {}
    out = await fleet_posture.revoke_key(
        pool, agent_id, key_id, actor=principal.actor, actor_role=principal.role, reason=body.reason or "",
        client_ip=client_ip(request), request_id=getattr(request.state, "request_id", None),
        successors=body.successors, info=info)
    if out == "not_found":
        raise HTTPException(status_code=404, detail="agent or key not found")
    if out == "already_revoked":
        raise HTTPException(status_code=409, detail="key is already revoked")
    if out == "successor_active":
        return JSONResponse(
            {"detail": "this key was rotated and its successor is still active: revoking only this key leaves the "
                       "successor usable. Send successors='revoke' to revoke the chain, 'keep' to revoke only this "
                       "key, or revoke the agent",
             "reason": "successor_active", "active_successors": info.get("active_successors", [])},
            status_code=409)
    return {"ok": True, "agent_id": str(agent_id), "key_id": key_id, "status": "revoked",
            "revoked_successors": info.get("revoked_successors", [])}


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
        agent = await con.fetchrow(
            "SELECT id, status, legacy FROM fleet_agents WHERE id = $1", body.agent_id)
        if agent is None:
            raise HTTPException(status_code=404, detail="agent not found")
        if agent["status"] == "revoked" or agent["legacy"]:
            # It could never receive the action (a revoked or legacy agent is refused on every agent route).
            raise HTTPException(status_code=409,
                                detail="agent is revoked or must re-enroll; it cannot receive actions")
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
        _require_decision_reason(cur["action_type"], body.note)
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
        cur = await con.fetchrow("SELECT status, action_type FROM agent_actions WHERE id = $1", action_id)
        if cur is None:
            raise HTTPException(status_code=404, detail="action not found")
        if cur["status"] != "proposed":
            raise HTTPException(
                status_code=409, detail=f"cannot deny an action in status '{cur['status']}'"
            )
        _require_decision_reason(cur["action_type"], body.note)
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
    principal: Principal = Depends(current_principal),
):
    """Agent reports the outcome of a real apply. Guards enforce rails #2 + #3:
    an action may only be reported ``applied`` when it is ``approved`` AND
    ``dry_run = false``. A dry-run can never mutate, so it can never be
    ``applied`` here. Principal-bound: only the agent the action belongs to may report on it."""
    async with pool.acquire() as con:
        cur = await con.fetchrow(
            "SELECT agent_id, status, dry_run, action_type, revert_of FROM agent_actions WHERE id = $1",
            action_id,
        )
        if cur is None:
            raise HTTPException(status_code=404, detail="action not found")
        _assert_agent(principal, cur["agent_id"])
        denied = await _require_active_key(pool, cur["agent_id"])
        if denied is not None:
            return denied

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
        if _unstorable_text(result_payload):
            raise HTTPException(status_code=422, detail="the result holds text that cannot be stored (NUL or a lone "
                                                        "surrogate)")

        row = await con.fetchrow(
            """
            UPDATE agent_actions
               SET status = $2,
                   applied_at = CASE WHEN $2 = 'applied' THEN NOW() ELSE applied_at END,
                   result = result || $3::jsonb
             WHERE id = $1 AND status = 'approved'
         RETURNING id, agent_id, action_type, target, reason, indicator_id,
                   finding_id, dry_run, status, requested_by, approved_by,
                   result, created_at, decided_at, applied_at, revert_of
            """,
            action_id, body.status, json.dumps(result_payload),
        )
        if row is None:     # a concurrent report won the race
            raise HTTPException(status_code=409, detail="action is no longer 'approved'")

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
