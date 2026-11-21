"""Network quarantine through the EXISTING fleet approve gate (schema 025).

A Sentry ``device_lateral_scan`` finding (or an operator) PROPOSES quarantining
a device on a UniFi / Meraki network. The proposal is an ordinary
``agent_actions`` row -- no agent, an ``integration_id``, ``dry_run = TRUE``,
``status = 'proposed'`` -- so it goes through the very same gate as host
blocks:

    POST /v1/fleet/network-actions                      propose (any MAC)
    POST /v1/fleet/network-actions/from-finding         propose from a Sentry finding
    POST /v1/fleet/actions/{id}/approve                 admin, four-eyes, apply_for_real   (fleet.py)
    POST /v1/fleet/actions/{id}/deny                    admin                              (fleet.py)
    POST /v1/fleet/network-actions/{id}/execute         admin; runs the ACTION connector
    POST /v1/fleet/actions/{id}/revert                  mints the release                  (fleet.py)
    POST /v1/fleet/network-actions/{revert_id}/execute  performs the release
    GET  /v1/fleet/network-actions                      list

Rails (on top of fleet's):
* ``execute`` refuses anything not ``approved``; an approval WITHOUT
  ``apply_for_real`` only ever yields a dry-run preview (read calls only);
* the connector refuses protected / non-unicast MACs and unknown action types;
* the integration must be enabled and declare the ACTION capability;
* one execution at a time per action (claim flag), every transition audited,
  every quarantine stores a revert plan, and ``release`` is first-class.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from ..auth import Principal, current_principal, require
from ..db import get_pool
from ..integrations.base import Capability
from ..integrations.connectors._common import is_unicast_mac, normalize_mac
from . import fleet

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/fleet/network-actions", tags=["fleet"])

# Sentry detectors whose finding may be turned into a quarantine proposal.
QUARANTINABLE_RULES: frozenset[str] = frozenset({"device_lateral_scan"})
NETWORK_ACTIONS = ("quarantine_device", "release_device")
_CLAIM_STALE_SEC = 600

_COLS = (
    "id, agent_id, integration_id, action_type, target, reason, indicator_id, finding_id, "
    "dry_run, status, requested_by, approved_by, result, created_at, decided_at, applied_at, "
    "revert_of"
)


class NetworkProposeIn(BaseModel):
    model_config = {"extra": "forbid"}
    integration_id: UUID
    action_type: Literal["quarantine_device", "release_device"] = "quarantine_device"
    mac: str = Field(min_length=12, max_length=32)
    reason: str | None = Field(default=None, max_length=2048)
    finding_id: UUID | None = None


class FromFindingIn(BaseModel):
    model_config = {"extra": "forbid"}
    finding_id: UUID
    integration_id: UUID
    reason: str | None = Field(default=None, max_length=2048)


class ExecuteIn(BaseModel):
    model_config = {"extra": "forbid"}
    note: str | None = Field(default=None, max_length=2048)


class ExecuteOut(BaseModel):
    action: fleet.ActionOut
    ok: bool
    dry_run: bool
    detail: str
    planned: list[str] = Field(default_factory=list)


def _row(row) -> fleet.ActionOut:
    d = dict(row)
    d["result"] = fleet._as_dict(d.get("result"))
    return fleet.ActionOut.model_validate(d)


async def _action_integration(con, integration_id: UUID) -> dict[str, Any]:
    from ..integrations.runtime import connector_class

    row = await con.fetchrow(
        "SELECT id, kind, name, enabled, config, secrets, allow_private "
        "FROM integrations WHERE id = $1", integration_id)
    if row is None:
        raise HTTPException(status_code=404, detail="integration not found")
    try:
        cls = connector_class(row["kind"])
    except KeyError:
        raise HTTPException(status_code=422, detail=f"unknown integration kind {row['kind']!r}") from None
    if Capability.ACTION not in cls.capabilities:
        raise HTTPException(status_code=422, detail=f"{row['kind']} cannot execute network actions")
    if not row["enabled"]:
        raise HTTPException(status_code=409, detail="integration is disabled")
    return dict(row)


def _check_mac(raw: str, integ: dict[str, Any]) -> str:
    mac = normalize_mac(raw)
    if not mac or not is_unicast_mac(mac):
        raise HTTPException(status_code=422, detail="a valid unicast MAC address is required")
    cfg = fleet._as_dict(integ.get("config"))
    if mac in {normalize_mac(m) for m in cfg.get("protected_macs") or []}:
        raise HTTPException(status_code=422, detail=f"{mac} is on the integration's protected list")
    return mac


async def _insert(request: Request, pool, principal: Principal, *, integ: dict[str, Any],
                  action_type: str, mac: str, reason: str | None,
                  finding_id: UUID | None, extra: dict[str, Any] | None = None) -> fleet.ActionOut:
    async with pool.acquire() as con:
        dup = await con.fetchval(
            "SELECT id FROM agent_actions WHERE integration_id = $1 AND target = $2 "
            "AND action_type = $3 AND (status = 'proposed' OR "
            "(status = 'approved' AND dry_run = FALSE))",
            integ["id"], mac, action_type)
        if dup is not None:
            raise HTTPException(status_code=409,
                                detail=f"an open {action_type} for {mac} already exists: {dup}")
        result = {"network": True, "integration_kind": integ["kind"],
                  "integration_name": integ["name"], **(extra or {})}
        row = await con.fetchrow(
            f"""
            INSERT INTO agent_actions
                (agent_id, integration_id, action_type, target, reason, finding_id,
                 dry_run, status, requested_by, result)
            VALUES (NULL, $1, $2, $3, $4, $5, TRUE, 'proposed', $6, $7::jsonb)
            RETURNING {_COLS}
            """,
            integ["id"], action_type, mac, reason, finding_id, principal.actor, json.dumps(result))
    await fleet._audit(
        request, pool, action="propose", resource_type="fleet_action", resource_id=str(row["id"]),
        actor=principal.actor, actor_role=principal.role,
        details={"network": True, "action_type": action_type, "target": mac,
                 "integration_id": str(integ["id"]), "integration_kind": integ["kind"],
                 "finding_id": str(finding_id) if finding_id else None, "dry_run": True})
    return _row(row)


@router.post("", response_model=fleet.ActionOut, status_code=201)
async def propose(body: NetworkProposeIn, request: Request, pool=Depends(get_pool),
                  principal: Principal = Depends(current_principal)):
    """Propose a quarantine/release of one device. Always dry_run + proposed."""
    async with pool.acquire() as con:
        integ = await _action_integration(con, body.integration_id)
    mac = _check_mac(body.mac, integ)
    return await _insert(request, pool, principal, integ=integ, action_type=body.action_type,
                         mac=mac, reason=body.reason, finding_id=body.finding_id)


def _mac_from_finding(row) -> str | None:
    for src in (fleet._as_dict(row["asset_md"]), fleet._as_dict(row["evidence"]),
                fleet._as_dict(row["metadata"])):
        for key in ("mac", "device_id", "src_mac"):
            mac = normalize_mac(src.get(key)) if isinstance(src.get(key), str) else None
            if mac:
                return mac
    return normalize_mac(row["asset_value"]) if row["asset_kind"] in ("iot_device", "ot_device") else None


@router.post("/from-finding", response_model=fleet.ActionOut, status_code=201)
async def propose_from_finding(body: FromFindingIn, request: Request, pool=Depends(get_pool),
                               principal: Principal = Depends(current_principal)):
    """Turn a Sentry lateral-scan finding into a quarantine PROPOSAL (never an apply)."""
    async with pool.acquire() as con:
        f = await con.fetchrow(
            """
            SELECT f.id, f.rule_id, f.status, f.severity, f.title, f.evidence, f.metadata,
                   a.kind AS asset_kind, a.value AS asset_value, a.metadata AS asset_md
              FROM findings f JOIN assets a ON a.id = f.asset_id
             WHERE f.id = $1
            """, body.finding_id)
        if f is None:
            raise HTTPException(status_code=404, detail="finding not found")
        if f["rule_id"] not in QUARANTINABLE_RULES:
            raise HTTPException(status_code=422,
                                detail=f"finding rule {f['rule_id']!r} does not warrant quarantine")
        if f["status"] not in ("open", "triaged"):
            raise HTTPException(status_code=409, detail=f"finding is {f['status']}")
        integ = await _action_integration(con, body.integration_id)
    raw = _mac_from_finding(f)
    if not raw:
        raise HTTPException(status_code=422, detail="the device's MAC address is unknown; "
                                                    "propose manually with its MAC")
    mac = _check_mac(raw, integ)
    reason = body.reason or f"Sentry {f['rule_id']}: {f['title']}"[:2048]
    return await _insert(request, pool, principal, integ=integ, action_type="quarantine_device",
                         mac=mac, reason=reason, finding_id=f["id"],
                         extra={"source_rule": f["rule_id"], "device": f["asset_value"]})


@router.get("", response_model=fleet.ActionPage)
async def list_network_actions(
    status_filter: str | None = Query(default=None, alias="status"),
    limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
    pool=Depends(get_pool),
):
    where = "(integration_id IS NOT NULL OR (action_type = 'revert' AND agent_id IS NULL))"
    args: list[Any] = []
    if status_filter is not None:
        if status_filter not in fleet.ACTION_STATUSES:
            raise HTTPException(status_code=422, detail="invalid status filter")
        args.append(status_filter)
        where += f" AND status = ${len(args)}"
    async with pool.acquire() as con:
        total = await con.fetchval(f"SELECT COUNT(*) FROM agent_actions WHERE {where}", *args)
        rows = await con.fetch(
            f"SELECT {_COLS} FROM agent_actions WHERE {where} ORDER BY created_at DESC "
            f"LIMIT ${len(args) + 1} OFFSET ${len(args) + 2}", *args, limit, offset)
    return fleet.ActionPage(items=[_row(r) for r in rows], total=int(total or 0))


@router.post("/{action_id}/execute", response_model=ExecuteOut,
             dependencies=[Depends(require("admin"))])
async def execute(action_id: UUID, body: ExecuteIn, request: Request, pool=Depends(get_pool),
                  principal: Principal = Depends(current_principal)):
    """Run an APPROVED network action through its ACTION integration.

    dry_run rows (approved without ``apply_for_real``) only produce a preview
    and stay ``approved``; real rows become ``applied`` (with a revert plan)
    or ``failed``. A ``revert`` row releases the device its original action
    quarantined and marks that original ``reverted``.
    """
    from ..integrations.connectors._common import ActionResult
    from ..integrations.runtime import connector_for, default_http, scrub
    from ..integrations.secrets import decrypt_secrets

    async with pool.acquire() as con:
        row = await con.fetchrow(f"SELECT {_COLS} FROM agent_actions WHERE id = $1", action_id)
        if row is None:
            raise HTTPException(status_code=404, detail="action not found")
        result = fleet._as_dict(row["result"])
        orig = None
        if row["action_type"] == "revert":
            orig = await con.fetchrow(f"SELECT {_COLS} FROM agent_actions WHERE id = $1",
                                      row["revert_of"])
            if orig is None or orig["integration_id"] is None \
                    or orig["action_type"] not in NETWORK_ACTIONS:
                raise HTTPException(status_code=409, detail="not a network action")
            if orig["action_type"] != "quarantine_device":
                # Reverts are auto-approved as de-escalation; undoing a RELEASE
                # would re-quarantine without a human decision. Refuse.
                raise HTTPException(status_code=409, detail="a release cannot be reverted; "
                                                            "propose a new quarantine instead")
            integration_id, mac = orig["integration_id"], orig["target"]
            typ = "release_device"
            plan = result.get("revert") or {}
        elif row["integration_id"] is not None and row["action_type"] in NETWORK_ACTIONS:
            integration_id, mac, typ, plan = row["integration_id"], row["target"], row["action_type"], {}
        else:
            raise HTTPException(status_code=409, detail="not a network action")
        if row["status"] != "approved":
            raise HTTPException(status_code=409,
                                detail=f"action must be 'approved' to execute (is '{row['status']}')")
        integ = await _action_integration(con, integration_id)
        # Claim: one execution at a time per action.
        claimed = await con.fetchval(
            """
            UPDATE agent_actions SET result = result || jsonb_build_object('executing_at', $2::text)
             WHERE id = $1 AND status = 'approved'
               AND (NOT (result ? 'executing_at')
                    OR (result->>'executing_at')::timestamptz < NOW() - make_interval(secs => $3))
            RETURNING id
            """, action_id, datetime.now(timezone.utc).isoformat(), float(_CLAIM_STALE_SEC))
    if claimed is None:
        raise HTTPException(status_code=409, detail="this action is already being executed")

    dry_run = bool(row["dry_run"])
    payload = {"type": typ, "mac": mac, "dry_run": dry_run, "action_id": str(action_id),
               "reason": row["reason"], "revert": plan}
    integ_cfg = fleet._as_dict(integ.get("config"))
    integ_cfg["allow_private"] = bool(integ.get("allow_private"))
    secrets: dict[str, str] = {}
    try:
        secrets = decrypt_secrets(integ.get("secrets"))
        factory = getattr(request.app.state, "integration_http_factory", None) or default_http
        async with factory(integ_cfg) as http:
            res = await connector_for(integ, http).act(payload)
    except Exception as exc:  # noqa: BLE001 - never leak; record a typed failure
        logger.exception("network_action_crashed", extra={"action_id": str(action_id)})
        res = ActionResult(ok=False, detail=f"internal error ({type(exc).__name__})", dry_run=dry_run)
    detail = scrub(res.detail or "", secrets)
    planned = [scrub(p, secrets) for p in (getattr(res, "planned", None) or [])]
    output = {"ok": res.ok, "status_code": res.status_code, "detail": detail, "planned": planned,
              "external_id": res.external_id, "dry_run": dry_run,
              "at": datetime.now(timezone.utc).isoformat(), "executed_by": principal.actor}

    async with pool.acquire() as con:
        async with con.transaction():
            if dry_run:
                new = await con.fetchrow(
                    f"UPDATE agent_actions SET result = (result - 'executing_at') || "
                    f"jsonb_build_object('dry_run_preview', $2::jsonb) WHERE id = $1 RETURNING {_COLS}",
                    action_id, json.dumps(output))
            else:
                status = "applied" if res.ok else "failed"
                extra: dict[str, Any] = {"output": output}
                revert = getattr(res, "revert", None)
                if res.ok and revert and row["action_type"] != "revert":
                    extra["revert"] = revert
                new = await con.fetchrow(
                    f"""
                    UPDATE agent_actions
                       SET status = $2,
                           applied_at = CASE WHEN $2 = 'applied' THEN NOW() ELSE applied_at END,
                           integration_id = COALESCE(integration_id, $4),
                           result = (result - 'executing_at') || $3::jsonb
                     WHERE id = $1 RETURNING {_COLS}
                    """, action_id, status, json.dumps(extra), integration_id)
                if res.ok and orig is not None:
                    await con.execute("UPDATE agent_actions SET status = 'reverted' WHERE id = $1",
                                      orig["id"])

    common = {"network": True, "integration_id": str(integration_id),
              "integration_kind": integ["kind"], "type": typ, "target": mac, "dry_run": dry_run,
              "ok": res.ok, "status_code": res.status_code, "detail": detail, "note": body.note}
    audit_action = "execute_dry_run" if dry_run else ("apply" if res.ok else "fail")
    await fleet._audit(request, pool, action=audit_action, resource_type="fleet_action",
                       resource_id=str(action_id), actor=principal.actor,
                       actor_role=principal.role, details=common)
    if not dry_run and res.ok and orig is not None:
        await fleet._audit(request, pool, action="reverted", resource_type="fleet_action",
                           resource_id=str(orig["id"]), actor=principal.actor,
                           actor_role=principal.role,
                           details={"by_revert_action": str(action_id), "network": True})
    return ExecuteOut(action=_row(new), ok=res.ok, dry_run=dry_run, detail=detail, planned=planned)


class EvidenceOut(BaseModel):
    action_id: UUID
    finding: dict[str, Any] | None = None
    device: dict[str, Any] = Field(default_factory=dict)


@router.get("/{action_id}/evidence", response_model=EvidenceOut)
async def action_evidence(action_id: UUID, pool=Depends(get_pool)):
    """What the approver needs to decide: the Sentry finding behind a proposal
    (rule, severity, evidence JSON) and the device it points at. Read-only."""
    async with pool.acquire() as con:
        row = await con.fetchrow(
            f"SELECT {_COLS} FROM agent_actions WHERE id = $1 AND integration_id IS NOT NULL",
            action_id)
        if row is None:
            raise HTTPException(status_code=404, detail="network action not found")
        f = None
        if row["finding_id"] is not None:
            f = await con.fetchrow(
                """
                SELECT f.id, f.rule_id, f.severity, f.status, f.title, f.description, f.evidence,
                       f.first_seen, f.last_seen, a.kind AS asset_kind, a.value AS asset_value,
                       a.metadata AS asset_md
                  FROM findings f JOIN assets a ON a.id = f.asset_id WHERE f.id = $1
                """, row["finding_id"])
    res = fleet._as_dict(row["result"])
    finding = None
    device: dict[str, Any] = {"mac": row["target"], "name": res.get("device")}
    if f is not None:
        md = fleet._as_dict(f["asset_md"])
        finding = {"id": str(f["id"]), "rule_id": f["rule_id"], "severity": f["severity"],
                   "status": f["status"], "title": f["title"], "description": f["description"],
                   "evidence": fleet._as_dict(f["evidence"]),
                   "first_seen": f["first_seen"].isoformat() if f["first_seen"] else None,
                   "last_seen": f["last_seen"].isoformat() if f["last_seen"] else None}
        is_dev = f["asset_kind"] in ("iot_device", "ot_device")
        device.update({"asset_kind": f["asset_kind"], "asset_value": f["asset_value"],
                       "vendor": md.get("vendor"), "type": md.get("type"),
                       "ips": md.get("ips") or ([f["asset_value"]] if is_dev else [])})
    return EvidenceOut(action_id=action_id, finding=finding,
                       device={k: v for k, v in device.items() if v not in (None, [], "")})
