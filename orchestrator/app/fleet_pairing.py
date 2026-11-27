"""The identity trust root: operator pairing of an agent with a cloud instance, and acknowledgement of a scan
conflict (docs/ASSURANCE_P2_1.md section 4, decisions D26 to D30).

What a pairing attests: *agent row A is the machine that is cloud asset X*, asserted by an admin with a justification.
It changes IDENTITY only: the node reference, the node's addresses, where its zone comes from, which edges and coverage
its facts attach to. It does NOT lift a tier (a signed fact is not a true fact, E2), bypass a P2 gate (signature, key,
freshness, silence, exactness, listener completeness, conflicts) or hide a conflict. The peer address the server saw
survives only as a NEGATIVE detector (``paired_peer_mismatch``: it can withdraw trust, never grant it).

What an acknowledgement attests: the operator looked at ONE observation of ``agent_closed_scan_open`` for
``(agent, proto, port)`` and accepts that the scan hit something else. It clears that conflict RECORD for coverage
purposes and nothing else; a LATER observation re-raises the conflict; it expires; it is disclosed in the facts, the
coverage detail and the audit chain.

Everything here runs in ONE transaction per call, in the lock order of ``fleet_posture`` (token rows, then the agent
row ``FOR UPDATE``, then pairing rows), with the audit row written on the same connection so it commits or rolls back
with the change. The decision itself (:func:`app.assurance.builders._ipmap.pairing_decision`) is shared with the
builder, so the ingest, the column ``fleet_agents.node_ref`` and the graph cannot disagree.

``PairingError`` carries the HTTP status and body; the router maps it. Foreign and random ids answer exactly alike
(``404 {"detail": "agent not found"}``): nothing here is an existence oracle across tenants or clearance.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import uuid
from typing import Any, Mapping, Optional

import asyncpg

from . import audit, fleet_enroll
from .assurance.builders import _ipmap
from .auth import classification_rank_sql
from .config import settings

logger = logging.getLogger(__name__)

#: the only conflict that can be acknowledged (``host_fw.ACKABLE_KIND``).
ACKABLE_KIND = "agent_closed_scan_open"
MAX_TTL_H = 720
DEFAULT_TTL_H = 168
MAX_CANDIDATES = 20
MAX_RECONCILE = 5000

_VM_TYPES = ("instance", "virtual_machine", "vm", "compute_instance")
_INERT_STATE = {"asset_missing": "inert_asset_missing", "asset_stale": "inert_asset_stale",
                "asset_not_vm": "inert_asset_not_vm", "pairing_ambiguous": "inert_asset_missing"}
_AGENT_LOCK_SQL = ("SELECT id, hostname, status, revoked_at, legacy, identity, node_ref FROM fleet_agents "
                   "WHERE id = $1 FOR UPDATE")


class PairingError(Exception):
    """An answer the router sends as is: ``status`` and a JSON ``body`` (always with ``detail``)."""

    def __init__(self, status: int, detail: str, reason: Optional[str] = None, **extra: Any) -> None:
        super().__init__(f"{status} {detail}")
        self.status = status
        self.body: dict[str, Any] = {"detail": detail}
        if reason:
            self.body["reason"] = reason
        self.body.update(extra)


def _no_agent() -> PairingError:
    return PairingError(404, "agent not found")


def _no_asset() -> PairingError:
    return PairingError(404, "asset not found")


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #

def _loads(value: Any, default: Any) -> Any:
    if value is None:
        return default
    if isinstance(value, (str, bytes)):
        try:
            return json.loads(value)
        except ValueError:
            return default
    return value


def _aware(t: dt.datetime) -> dt.datetime:
    return t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)


def _iso(t: Optional[dt.datetime]) -> Optional[str]:
    return None if t is None else _aware(t).astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def asset_max_age() -> dt.timedelta:
    return dt.timedelta(hours=int(settings.assurance_pairing_asset_max_age_h))


def ack_max_hours() -> int:
    return max(1, min(MAX_TTL_H, int(settings.assurance_conflict_ack_max_h)))


def _live(agent: Mapping[str, Any]) -> bool:
    return agent["legacy"] is False and agent["status"] != "revoked" and agent["revoked_at"] is None


def _is_agent_live_or_raise(agent: Mapping[str, Any]) -> None:
    if not _live(agent):
        raise PairingError(409, "the agent is revoked or must re-enroll", "agent_not_live")


async def _lock_agent(con: Any, agent_id: uuid.UUID) -> Mapping[str, Any]:
    row = await con.fetchrow(_AGENT_LOCK_SQL, agent_id)
    if row is None:
        raise _no_agent()
    return row


async def _peer_shared(con: Any, agent_id: uuid.UUID, peer: Optional[str]) -> bool:
    """Does another live agent present the same peer address (a NAT, a proxy, a shared egress)?"""
    if not peer:
        return False
    from . import fleet_posture            # lazy: fleet_posture imports this module's callers
    row = await con.fetchrow(
        "SELECT 1 FROM fleet_agents WHERE id <> $1 AND status <> 'revoked' AND revoked_at IS NULL AND legacy = FALSE "
        "AND lower(identity->>'peer_ip') = ANY($2::text[]) LIMIT 1", agent_id, fleet_posture._peer_forms(peer))
    return row is not None


# --------------------------------------------------------------------------- #
# the pairing row joined with its asset, and what is effective
# --------------------------------------------------------------------------- #

_PAIRING_SQL = (
    f"SELECT {_ipmap.PAIRING_COLUMNS}, p.status, p.justification, p.paired_by, p.paired_at, p.asset_canonical, "
    "p.checks, p.ended_at, p.ended_by, p.ended_reason, a.classification AS a_class, a.canonical AS a_canonical "
    f"{_ipmap.PAIRING_FROM}"
)


def _rec(r: Mapping[str, Any]) -> dict[str, Any]:
    return {"pairing_id": r["pairing_id"], "agent_id": r["agent_id"], "asset_id": r["asset_id"], "a_id": r["a_id"],
            "kind": r["kind"], "last_seen": r["last_seen"], "md": r["md"]}


async def effective_of(con: Any, agent: Mapping[str, Any], pr: Mapping[str, Any], now: dt.datetime) -> dict[str, str]:
    """``{node_ref, basis, state, note}`` of a pairing row ``pr`` (from ``_PAIRING_SQL``) for ``agent``."""
    own = f"agent:{agent['id']}"
    if pr["status"] != "active":
        return {"node_ref": own, "basis": "claimed", "state": "ended", "note": ""}
    if not _live(agent):
        return {"node_ref": own, "basis": "claimed", "state": "inert_agent_not_live", "note": "agent_not_live"}
    ident = _loads(agent["identity"], {})
    claim = _ipmap.claim_of(str(agent["id"]), ident)
    row = _ipmap.pairing_row(_rec(pr))
    d = _ipmap.pairing_decision(claim, row, now, asset_max_age(), await _peer_shared(con, agent["id"], claim.peer)) \
        if row is not None else _ipmap.Decision(None, "pairing_inert:asset_missing")
    if d.ref is not None:
        return {"node_ref": d.ref, "basis": "paired", "state": "peer_mismatch" if d.conflict else "active",
                "note": d.conflict}
    why = d.note.partition(":")[2]
    return {"node_ref": own, "basis": "claimed", "state": _INERT_STATE.get(why, "inert_asset_missing"), "note": d.note}


def _checks(identity: Any, md: Mapping[str, Any], asset_kind: str, last_seen: Optional[dt.datetime]) -> dict[str, Any]:
    """What the server compared at pairing time (an operator-mistake guard, NOT a proof)."""
    claimed = _ipmap.claimed_ips(identity)
    asset_ips = _ipmap._ips_in(md)
    claim = _ipmap.claim_of("x", identity if isinstance(identity, Mapping) else {})
    peer = claim.peer if claim.direct else None
    peer_in_asset: Optional[bool] = None
    if peer is not None and not _ipmap.is_public_ip(peer):
        peer_in_asset = peer in asset_ips
    return {"claimed_ips": claimed, "asset_ips": asset_ips,
            "claimed_subset": (set(claimed) <= set(asset_ips)) if claimed else None,
            "observed_peer": peer, "peer_direct": bool(claim.direct and claim.peer is not None),
            "peer_in_asset": peer_in_asset, "asset_kind": asset_kind, "asset_last_seen": _iso(last_seen)}


def _asset_md(rec: Mapping[str, Any]) -> dict[str, Any]:
    md = _loads(rec.get("md"), {})
    return md if isinstance(md, dict) else {}


def _out(pr: Mapping[str, Any], agent: Mapping[str, Any], eff: Mapping[str, str], *, changed: bool,
         hidden: bool = False) -> dict[str, Any]:
    """The ``PairingOut`` dict. ``hidden`` (the caller's clearance is below the asset's classification) redacts every
    field that could describe the asset or the operator's reasoning."""
    checks = dict(_loads(pr["checks"], {}))
    base = {"claimed_ips": [], "asset_ips": [], "claimed_subset": None, "observed_peer": None, "peer_direct": False,
            "peer_in_asset": None, "asset_kind": "", "asset_last_seen": None, "acknowledged_mismatch": False}
    base.update({k: v for k, v in checks.items() if k in base})
    out = {
        "id": pr["pairing_id"], "agent_id": pr["agent_id"], "asset_id": pr["asset_id"],
        "asset_canonical": pr["asset_canonical"] or "", "status": pr["status"],
        "justification": pr["justification"], "paired_by": pr["paired_by"], "paired_at": pr["paired_at"],
        "ended_at": pr["ended_at"], "ended_by": pr["ended_by"], "ended_reason": pr["ended_reason"] or None,
        "checks": base, "effective": dict(eff), "changed": changed,
    }
    if hidden:
        out.update(asset_canonical="", justification="", paired_by="")
        out["checks"] = {**base, "claimed_ips": [], "asset_ips": [], "observed_peer": None, "asset_kind": "",
                         "asset_last_seen": None}
    return out


def _hidden(pr: Mapping[str, Any], clearance_rank: int) -> bool:
    from .auth import CLASS_RANK
    cls = pr.get("a_class")
    return cls is not None and CLASS_RANK.get(cls, CLASS_RANK["internal"]) > clearance_rank


async def _latest_pairing(con: Any, agent_id: uuid.UUID) -> Optional[Mapping[str, Any]]:
    return await con.fetchrow(
        _PAIRING_SQL + " WHERE p.agent_id = $1 ORDER BY (p.status = 'active') DESC, p.paired_at DESC, p.id LIMIT 1",
        agent_id)


# --------------------------------------------------------------------------- #
# PUT / DELETE / GET pairing
# --------------------------------------------------------------------------- #

async def put_pairing(pool: Any, agent_id: uuid.UUID, *, asset_id: uuid.UUID, justification: str,
                      acknowledge_mismatch: bool = False, actor: str, actor_role: Optional[str],
                      clearance_rank: int, client_ip: Any = None, request_id: Optional[str] = None) -> dict[str, Any]:
    """The algorithm of 4.4, one transaction. Returns the ``PairingOut`` dict (``changed`` False for an idempotent
    repeat). Raises :class:`PairingError`."""

    async def run() -> dict[str, Any]:
        async with pool.acquire() as con:
            async with con.transaction():
                agent = await _lock_agent(con, agent_id)
                _is_agent_live_or_raise(agent)
                if await con.fetchval("SELECT 1 FROM fleet_agent_keys WHERE agent_id = $1 AND status = 'active' LIMIT 1",
                                      agent_id) is None:
                    raise PairingError(409, "the agent has no active signing key", "agent_has_no_active_key")
                asset = await con.fetchrow(
                    f"SELECT a.id, a.kind, a.canonical, a.last_seen, a.metadata FROM assets a WHERE a.id = $1 "
                    f"AND {classification_rank_sql('a.classification')} <= $2", asset_id, clearance_rank)
                if asset is None:
                    raise _no_asset()
                md = _loads(asset["metadata"], {})
                md = md if isinstance(md, dict) else {}
                if asset["kind"] != "cloud_resource" or _ipmap.node_kind("cloud_resource", md) != _ipmap.INSTANCE_KIND:
                    raise PairingError(422, "only a cloud virtual machine can be paired with an agent", "asset_not_a_vm")
                seen = asset["last_seen"]
                now = _now()
                if seen is None or now - _aware(seen) > asset_max_age():
                    raise PairingError(409, "the asset has not been seen recently enough to pair", "asset_stale",
                                       asset_last_seen=_iso(seen))
                have = await con.fetchrow(
                    "SELECT id, asset_id FROM fleet_agent_pairings WHERE agent_id = $1 AND status = 'active' FOR UPDATE",
                    agent_id)
                if have is not None:
                    if have["asset_id"] == asset_id:
                        pr = await con.fetchrow(_PAIRING_SQL + " WHERE p.id = $1", have["id"])
                        eff = await effective_of(con, agent, pr, now)
                        return _out(pr, agent, eff, changed=False)
                    raise PairingError(409, "the agent is already paired with another asset; unpair it first",
                                       "agent_already_paired", asset_id=str(have["asset_id"]))
                other = await con.fetchval(
                    "SELECT agent_id FROM fleet_agent_pairings WHERE asset_id = $1 AND status = 'active'", asset_id)
                if other is not None:
                    raise PairingError(409, "the asset is already paired with another agent", "asset_already_paired",
                                       agent_id=str(other))
                ident = _loads(agent["identity"], {})
                checks = _checks(ident, md, _ipmap.INSTANCE_KIND, seen)
                disagree = checks["claimed_subset"] is False or checks["peer_in_asset"] is False
                if disagree and not acknowledge_mismatch:
                    raise PairingError(
                        409, "the addresses the host claims or connects from do not match the asset; check the asset "
                             "and repeat with acknowledge_mismatch if you are sure", "identity_claims_disagree",
                        checks={**checks, "acknowledged_mismatch": False})
                checks["acknowledged_mismatch"] = bool(disagree and acknowledge_mismatch)
                try:
                    async with con.transaction():        # savepoint: a lost race must not abort the outer transaction
                        pid = await con.fetchval(
                            "INSERT INTO fleet_agent_pairings (agent_id, asset_id, justification, paired_by, "
                            "asset_canonical, checks) VALUES ($1,$2,$3,$4,$5,$6::jsonb) RETURNING id",
                            agent_id, asset_id, justification, actor, asset["canonical"], json.dumps(checks))
                except asyncpg.UniqueViolationError as exc:
                    who = await con.fetchval(
                        "SELECT agent_id FROM fleet_agent_pairings WHERE asset_id = $1 AND status = 'active'", asset_id)
                    if who is not None and who != agent_id:
                        raise PairingError(409, "the asset is already paired with another agent",
                                           "asset_already_paired", agent_id=str(who)) from exc
                    raise PairingError(409, "the agent is already paired with another asset; unpair it first",
                                       "agent_already_paired") from exc
                old_ref = agent["node_ref"] or f"agent:{agent_id}"
                new_ref = f"asset:{asset_id}"
                await con.execute(
                    "UPDATE fleet_agents SET node_ref = $2, "
                    "identity = (COALESCE(identity, '{}'::jsonb) || jsonb_build_object('basis', 'paired')) - 'note' "
                    "WHERE id = $1", agent_id, new_ref)
                from .assurance import finding_follow
                await finding_follow.migrate_targets(con, {old_ref: new_ref, f"agent:{agent_id}": new_ref})
                await _invalidate(con)
                await audit.record(
                    None, action="fleet.pairing.create", actor=actor, actor_role=actor_role,
                    resource_type="fleet_agent", resource_id=str(agent_id), ip=client_ip, request_id=request_id,
                    justification=justification,
                    details={"asset_id": str(asset_id), "asset_canonical": asset["canonical"],
                             "justification": justification, "checks": checks,
                             "acknowledge_mismatch": bool(acknowledge_mismatch), "pairing_id": str(pid)}, con=con)
                pr = await con.fetchrow(_PAIRING_SQL + " WHERE p.id = $1", pid)
                agent = await con.fetchrow(_AGENT_LOCK_SQL.replace(" FOR UPDATE", ""), agent_id)
                return _out(pr, agent, await effective_of(con, agent, pr, now), changed=True)

    return await fleet_enroll.retry_on_deadlock(run)


async def end_pairing(pool: Any, agent_id: uuid.UUID, *, justification: str, actor: str, actor_role: Optional[str],
                      clearance_rank: int, client_ip: Any = None, request_id: Optional[str] = None) -> dict[str, Any]:
    """``DELETE``: end the agent's active pairing. Never billing-gated, never refused for a stale asset."""

    async def run() -> dict[str, Any]:
        async with pool.acquire() as con:
            async with con.transaction():
                agent = await _lock_agent(con, agent_id)
                ended = await _end_active(con, agent_id, ended_by=actor, reason="unpaired")
                if ended is None:
                    raise PairingError(404, "no active pairing")
                old_ref = agent["node_ref"] or f"agent:{agent_id}"
                own = f"agent:{agent_id}"
                await con.execute(
                    "UPDATE fleet_agents SET node_ref = $2, "
                    "identity = (COALESCE(identity, '{}'::jsonb) || jsonb_build_object('basis', 'claimed')) - 'note' "
                    "WHERE id = $1", agent_id, own)
                from .assurance import finding_follow
                await finding_follow.migrate_targets(con, {old_ref: own, f"asset:{ended['asset_id']}": own})
                await _invalidate(con)
                await audit.record(
                    None, action="fleet.pairing.end", actor=actor, actor_role=actor_role, resource_type="fleet_agent",
                    resource_id=str(agent_id), ip=client_ip, request_id=request_id, justification=justification,
                    details={"asset_id": str(ended["asset_id"]), "pairing_id": str(ended["id"]),
                             "reason": "unpaired", "justification": justification}, con=con)
                pr = await con.fetchrow(_PAIRING_SQL + " WHERE p.id = $1", ended["id"])
                agent = await con.fetchrow(_AGENT_LOCK_SQL.replace(" FOR UPDATE", ""), agent_id)
                out = _out(pr, agent, await effective_of(con, agent, pr, _now()), changed=True,
                           hidden=_hidden(pr, clearance_rank))
                return out

    return await fleet_enroll.retry_on_deadlock(run)


async def get_pairing(pool: Any, agent_id: uuid.UUID, *, clearance_rank: int) -> dict[str, Any]:
    """The agent's active pairing, else its most recent ended one; 404 when it was never paired."""
    async with pool.acquire() as con:
        agent = await con.fetchrow(_AGENT_LOCK_SQL.replace(" FOR UPDATE", ""), agent_id)
        if agent is None:
            raise _no_agent()
        pr = await _latest_pairing(con, agent_id)
        if pr is None:
            raise PairingError(404, "no pairing")
        eff = await effective_of(con, agent, pr, _now())
        return _out(pr, agent, eff, changed=False, hidden=_hidden(pr, clearance_rank))


async def agent_pairing_summary(con: Any, agent: Mapping[str, Any]) -> Optional[dict[str, Any]]:
    """The viewer-safe subset for ``AgentDetailOut.pairing``: no justification, no operator, no asset name, no
    address (the same redaction as a pairing whose asset is above the caller's clearance)."""
    pr = await _latest_pairing(con, agent["id"])
    if pr is None:
        return None
    eff = await effective_of(con, agent, pr, _now())
    return _out(pr, agent, eff, changed=False, hidden=True)


async def list_pairings(pool: Any, *, status: Optional[str], asset_id: Optional[uuid.UUID], limit: int, offset: int,
                        clearance_rank: int) -> list[dict[str, Any]]:
    """The ledger, newest first."""
    clauses, args = [], []
    if status:
        args.append(status)
        clauses.append(f"p.status = ${len(args)}")
    if asset_id is not None:
        args.append(asset_id)
        clauses.append(f"p.asset_id = ${len(args)}")
    args += [limit, offset]
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = (_PAIRING_SQL + where + f" ORDER BY p.paired_at DESC, p.id LIMIT ${len(args) - 1} OFFSET ${len(args)}")
    now = _now()
    out = []
    async with pool.acquire() as con:
        for pr in await con.fetch(sql, *args):
            agent = await con.fetchrow(_AGENT_LOCK_SQL.replace(" FOR UPDATE", ""), pr["agent_id"])
            if agent is None:
                continue
            out.append(_out(pr, agent, await effective_of(con, agent, pr, now), changed=False,
                            hidden=_hidden(pr, clearance_rank)))
    return out


async def candidates(pool: Any, agent_id: uuid.UUID, *, clearance_rank: int) -> list[dict[str, Any]]:
    """Up to 20 fresh VM assets the agent could be: their addresses intersect the agent's claimed ones. Read only;
    creates nothing."""
    async with pool.acquire() as con:
        agent = await con.fetchrow(_AGENT_LOCK_SQL.replace(" FOR UPDATE", ""), agent_id)
        if agent is None:
            raise _no_agent()
        ident = _loads(agent["identity"], {})
        claimed = _ipmap.claimed_ips(ident)
        if not claimed:
            return []
        rows = await con.fetch(
            "SELECT a.id, a.canonical, a.last_seen, a.metadata, "
            "(SELECT p.agent_id FROM fleet_agent_pairings p WHERE p.asset_id = a.id AND p.status = 'active') AS paired_to "
            "FROM assets a WHERE a.kind = 'cloud_resource' AND lower(a.metadata->>'resource_type') = ANY($1::text[]) "
            "AND a.last_seen >= $2 AND (a.metadata->'private_ips' ?| $3::text[] OR a.metadata->'public_ips' ?| $3::text[] "
            "OR a.metadata->'ips' ?| $3::text[] OR a.metadata->'ip' ?| $3::text[]) "
            f"AND {classification_rank_sql('a.classification')} <= $4 ORDER BY a.last_seen DESC, a.id LIMIT 200",
            list(_VM_TYPES), _now() - asset_max_age(), claimed, clearance_rank)
    out: list[dict[str, Any]] = []
    for r in rows:
        md = _loads(r["metadata"], {})
        md = md if isinstance(md, dict) else {}
        ips = set(_ipmap._ips_in(md))
        if not ips & set(claimed):
            continue
        out.append({"asset_id": r["id"], "asset_canonical": r["canonical"], "asset_last_seen": r["last_seen"],
                    "paired_to": r["paired_to"],
                    "checks": {**_checks(ident, md, _ipmap.INSTANCE_KIND, r["last_seen"]), "acknowledged_mismatch": False}})
        if len(out) >= MAX_CANDIDATES:
            break
    return out


# --------------------------------------------------------------------------- #
# in-transaction helpers shared with revoke / re-key / reconcile
# --------------------------------------------------------------------------- #

async def _invalidate(con: Any) -> None:
    from . import fleet_posture
    await fleet_posture.invalidate_assurance(con)


async def _end_active(con: Any, agent_id: uuid.UUID, *, ended_by: str, reason: str) -> Optional[Mapping[str, Any]]:
    """End the agent's active pairing (a ledger row: only status and ``ended_*`` change, nothing is deleted)."""
    return await con.fetchrow(
        "UPDATE fleet_agent_pairings SET status = 'ended', ended_at = NOW(), ended_by = $2, ended_reason = $3 "
        "WHERE agent_id = $1 AND status = 'active' RETURNING id, agent_id, asset_id", agent_id, ended_by, reason)


async def _clear_acks(con: Any, agent_id: uuid.UUID, *, by: str, reason: str) -> list[Mapping[str, Any]]:
    return list(await con.fetch(
        "UPDATE fleet_conflict_acks SET status = 'cleared', cleared_by = $2, cleared_at = NOW(), cleared_reason = $3 "
        "WHERE agent_id = $1 AND status = 'active' RETURNING id, kind, proto, port", agent_id, by, reason))


async def end_for_agent(con: Any, agent_id: uuid.UUID, *, reason: str, by: str, actor: str,
                        actor_role: Optional[str] = None, client_ip: Any = None,
                        request_id: Optional[str] = None) -> dict[str, Any]:
    """Revoke and re-key cascade (same transaction as the caller, which holds the agent row lock): end the pairing and
    clear the acks, one audit row each. Does NOT touch ``fleet_agents.node_ref`` (the revoke path leaves it so the
    tombstone stays on the asset) and moves no findings (the caller decides). Returns what ended."""
    ended = await _end_active(con, agent_id, ended_by=by, reason=reason)
    if ended is not None:
        await audit.record(
            None, action="fleet.pairing.end", actor=actor, actor_role=actor_role, resource_type="fleet_agent",
            resource_id=str(agent_id), ip=client_ip, request_id=request_id,
            details={"asset_id": str(ended["asset_id"]), "pairing_id": str(ended["id"]), "reason": reason}, con=con)
    cleared = await _clear_acks(con, agent_id, by=by, reason=reason)
    for a in cleared:
        await audit.record(
            None, action="fleet.conflict.ack_clear", actor=actor, actor_role=actor_role, resource_type="fleet_agent",
            resource_id=str(agent_id), ip=client_ip, request_id=request_id,
            details={"ack_id": str(a["id"]), "kind": a["kind"], "proto": a["proto"], "port": a["port"],
                     "reason": reason}, con=con)
    return {"pairing": ended, "acks": cleared}


# --------------------------------------------------------------------------- #
# conflicts and acknowledgements
# --------------------------------------------------------------------------- #

_ACK_COLS = ("id, agent_id, kind, proto, port, through_seen_at, status, justification, acked_by, acked_at, "
             "expires_at, cleared_by, cleared_at, cleared_reason")


def _ack_out(r: Mapping[str, Any]) -> dict[str, Any]:
    return {k: r[k] for k in ("id", "agent_id", "kind", "proto", "port", "through_seen_at", "status", "justification",
                              "acked_by", "acked_at", "expires_at", "cleared_by", "cleared_at", "cleared_reason")}


async def _facts_of(con: Any, agent: Mapping[str, Any]) -> tuple[Optional[dt.datetime], list[dict[str, Any]],
                                                                 list[dict[str, Any]], str]:
    """``(observed_at, open conflicts, acknowledged conflicts, node_ref)`` from the CURRENT ``host_fw`` fact row of the
    agent's node (the row whose ``host_agent.data.agent_id`` is this agent)."""
    own = f"agent:{agent['id']}"
    refs_ = sorted({own, agent["node_ref"] or own})
    for row in await con.fetch(
            "SELECT node_ref, observed_at, facts FROM reach_node_facts WHERE source = 'host_fw' "
            "AND node_ref = ANY($1::text[]) ORDER BY node_ref", refs_):
        facts = _loads(row["facts"], {})
        ha = facts.get("host_agent") if isinstance(facts, dict) else None
        data = ha.get("data") if isinstance(ha, dict) else None
        if not isinstance(data, dict) or str(data.get("agent_id")) != str(agent["id"]):
            continue
        keep = lambda v: [c for c in v if isinstance(c, dict)] if isinstance(v, list) else []   # noqa: E731
        return row["observed_at"], keep(data.get("conflicts")), keep(data.get("conflicts_acknowledged")), row["node_ref"]
    return None, [], [], agent["node_ref"] or own


async def list_conflicts(pool: Any, agent_id: uuid.UUID) -> dict[str, Any]:
    """The conflicts of the agent's node as of its last build, joined with their acknowledgements."""
    async with pool.acquire() as con:
        agent = await con.fetchrow(_AGENT_LOCK_SQL.replace(" FOR UPDATE", ""), agent_id)
        if agent is None:
            raise _no_agent()
        as_of, open_, acked, node = await _facts_of(con, agent)
        built = await con.fetchval("SELECT last_build_at FROM assurance_state LIMIT 1")
        by_id = {str(r["id"]): r for r in await con.fetch(
            f"SELECT {_ACK_COLS} FROM fleet_conflict_acks WHERE agent_id = $1 AND status = 'active'", agent_id)}
    items = []
    for c in open_:
        items.append({"kind": str(c.get("kind")), "proto": str(c.get("proto")), "port": c.get("port"),
                      "scan_seen_at": c.get("scan_seen_at"), "ackable": c.get("kind") == ACKABLE_KIND, "ack": None})
    for c in acked:
        row = by_id.get(str(c.get("ack_id")))
        items.append({"kind": str(c.get("kind")), "proto": str(c.get("proto")), "port": c.get("port"),
                      "scan_seen_at": c.get("scan_seen_at"), "ackable": c.get("kind") == ACKABLE_KIND,
                      "ack": _ack_out(row) if row is not None else None})
    items.sort(key=lambda i: (i["proto"], i["port"] if isinstance(i["port"], int) else 0, i["kind"]))
    return {"agent_id": agent_id, "node_ref": node, "as_of": as_of, "graph_built_at": built, "conflicts": items}


def _same_second(a: Any, b: dt.datetime) -> bool:
    if not isinstance(a, str):
        return False
    try:
        t = dt.datetime.fromisoformat(a.replace("Z", "+00:00"))
    except ValueError:
        return False
    return _iso(_aware(t)) == _iso(b)


async def create_ack(pool: Any, agent_id: uuid.UUID, *, kind: str, proto: str, port: int, scan_seen_at: dt.datetime,
                     justification: str, ttl_hours: int = DEFAULT_TTL_H, actor: str, actor_role: Optional[str],
                     client_ip: Any = None, request_id: Optional[str] = None) -> dict[str, Any]:
    """Acknowledge ONE conflict observation. The conflict must be in the node's CURRENT facts and ``scan_seen_at`` must
    equal the observation shown there (no blind pre-acknowledgement); a re-ack supersedes the previous active row."""
    if kind != ACKABLE_KIND:
        raise PairingError(422, "only agent_closed_scan_open can be acknowledged", "not_ackable", kind=kind[:64])
    if ttl_hours > ack_max_hours():
        raise PairingError(422, f"ttl_hours may be at most {ack_max_hours()}", "ttl_exceeds_limit",
                           max_hours=ack_max_hours())

    async def run() -> dict[str, Any]:
        async with pool.acquire() as con:
            async with con.transaction():
                agent = await _lock_agent(con, agent_id)
                _is_agent_live_or_raise(agent)
                _, open_, acked, _node = await _facts_of(con, agent)
                same = [c for c in open_ + acked if c.get("kind") == kind and c.get("proto") == proto
                        and c.get("port") == port]
                if not same:
                    raise PairingError(409, "the agent has no such conflict right now", "no_such_conflict")
                cur = same[0]
                if not _same_second(cur.get("scan_seen_at"), scan_seen_at):
                    raise PairingError(409, "the conflict changed: acknowledge the observation that is current",
                                       "conflict_changed", scan_seen_at=cur.get("scan_seen_at"))
                through = _aware(dt.datetime.fromisoformat(str(cur["scan_seen_at"]).replace("Z", "+00:00")))
                superseded = [str(r["id"]) for r in await con.fetch(
                    "UPDATE fleet_conflict_acks SET status = 'superseded', cleared_by = $5, cleared_at = NOW(), "
                    "cleared_reason = 'superseded' WHERE agent_id = $1 AND kind = $2 AND proto = $3 AND port = $4 "
                    "AND status = 'active' RETURNING id", agent_id, kind, proto, port, actor)]
                record = {k: cur.get(k) for k in ("kind", "proto", "port", "scan_seen_at")}
                row = await con.fetchrow(
                    "INSERT INTO fleet_conflict_acks (agent_id, kind, proto, port, through_seen_at, justification, "
                    "acked_by, expires_at, evidence) VALUES ($1,$2,$3,$4,$5,$6,$7, NOW() + make_interval(hours => $8), "
                    f"$9::jsonb) RETURNING {_ACK_COLS}",
                    agent_id, kind, proto, port, through, justification, actor, ttl_hours, json.dumps(record))
                await _invalidate(con)
                await audit.record(
                    None, action="fleet.conflict.ack", actor=actor, actor_role=actor_role, resource_type="fleet_agent",
                    resource_id=str(agent_id), ip=client_ip, request_id=request_id, justification=justification,
                    details={"ack_id": str(row["id"]), "kind": kind, "proto": proto, "port": port,
                             "scan_seen_at": record["scan_seen_at"], "ttl_hours": ttl_hours,
                             "expires_at": _iso(row["expires_at"]), "conflict": record, "superseded": superseded,
                             "justification": justification}, con=con)
                return _ack_out(row)

    return await fleet_enroll.retry_on_deadlock(run)


async def clear_ack(pool: Any, agent_id: uuid.UUID, ack_id: uuid.UUID, *, justification: str, actor: str,
                    actor_role: Optional[str], client_ip: Any = None, request_id: Optional[str] = None) -> dict[str, Any]:
    """Clear an active acknowledgement at once; the conflict is back from the next build."""

    async def run() -> dict[str, Any]:
        async with pool.acquire() as con:
            async with con.transaction():
                await _lock_agent(con, agent_id)
                row = await con.fetchrow(
                    "UPDATE fleet_conflict_acks SET status = 'cleared', cleared_by = $3, cleared_at = NOW(), "
                    f"cleared_reason = $4 WHERE id = $1 AND agent_id = $2 AND status = 'active' RETURNING {_ACK_COLS}",
                    ack_id, agent_id, actor, justification)
                if row is None:
                    raise PairingError(404, "ack not found")
                await _invalidate(con)
                await audit.record(
                    None, action="fleet.conflict.ack_clear", actor=actor, actor_role=actor_role,
                    resource_type="fleet_agent", resource_id=str(agent_id), ip=client_ip, request_id=request_id,
                    justification=justification,
                    details={"ack_id": str(ack_id), "kind": row["kind"], "proto": row["proto"], "port": row["port"],
                             "reason": "cleared", "justification": justification}, con=con)
                return _ack_out(row)

    return await fleet_enroll.retry_on_deadlock(run)


# --------------------------------------------------------------------------- #
# reconcile: runs in ``runner.build_tenant`` BEFORE the builders (tenant context)
# --------------------------------------------------------------------------- #

_RECONCILE_SQL = (
    f"SELECT {_ipmap.PAIRING_COLUMNS} {_ipmap.PAIRING_FROM} "
    "JOIN fleet_agents f ON f.id = p.agent_id WHERE p.status = 'active' AND f.legacy = FALSE "
    f"AND f.status <> 'revoked' AND f.revoked_at IS NULL ORDER BY p.agent_id LIMIT {MAX_RECONCILE + 1}"
)


async def reconcile(con: Any, now: dt.datetime) -> dict[str, int]:
    """Mark expired acks ``expired`` and bring ``fleet_agents.node_ref`` / ``identity.basis`` in line with what each
    ACTIVE pairing now decides (inert when the asset is missing, stale or not a VM; restored when it is back). One
    audit row per transition (``fleet.pairing.inert`` / ``fleet.pairing.restored``) and per expiry
    (``fleet.conflict.ack_expire``); findings follow the node. The builder never writes, and an idempotent second
    run changes nothing. Returns ``{"acks_expired": n, "transitions": n}``."""
    now = _aware(now)
    out = {"acks_expired": 0, "transitions": 0}
    async with con.transaction():
        for a in await con.fetch(
                "UPDATE fleet_conflict_acks SET status = 'expired', cleared_at = $1, cleared_reason = 'expired' "
                "WHERE status = 'active' AND expires_at <= $1 RETURNING id, agent_id, kind, proto, port", now):
            out["acks_expired"] += 1
            await audit.record(
                None, action="fleet.conflict.ack_expire", actor="system:reconcile", actor_role="system",
                resource_type="fleet_agent", resource_id=str(a["agent_id"]),
                details={"ack_id": str(a["id"]), "kind": a["kind"], "proto": a["proto"], "port": a["port"]}, con=con)
    rows = await con.fetch(_RECONCILE_SQL)
    if len(rows) > MAX_RECONCILE:
        logger.warning("pairing_reconcile_capped", extra={"max": MAX_RECONCILE})
        rows = rows[:MAX_RECONCILE]
    for r in rows:
        try:
            if await _reconcile_one(con, _rec(r), now):
                out["transitions"] += 1
        except Exception:  # noqa: BLE001 -- one agent's surprise must not stop the others (nothing is guessed)
            logger.warning("pairing_reconcile_failed", exc_info=True, extra={"agent": str(r["agent_id"])})
    return out


async def _reconcile_one(con: Any, rec: Mapping[str, Any], now: dt.datetime) -> bool:
    from .assurance import finding_follow
    async with con.transaction():
        agent = await _lock_agent(con, rec["agent_id"])
        if not _live(agent):
            return False
        if await con.fetchval("SELECT 1 FROM fleet_agent_pairings WHERE id = $1 AND status = 'active' FOR UPDATE",
                              rec["pairing_id"]) is None:
            return False
        aid = str(agent["id"])
        own = f"agent:{aid}"
        ident = dict(_loads(agent["identity"], {}))
        claim = _ipmap.claim_of(aid, ident)
        row = _ipmap.pairing_row(rec)
        d = _ipmap.pairing_decision(claim, row, now, asset_max_age(), await _peer_shared(con, agent["id"], claim.peer)) \
            if row is not None else _ipmap.Decision(None, "pairing_inert:asset_missing")
        want_ref, want_basis, want_note = (d.ref, "paired", "") if d.ref else (own, "claimed", d.note)
        have_ref = agent["node_ref"] or own
        have_basis, have_note = ident.get("basis") or "claimed", ident.get("note") or ""
        if (have_ref, have_basis, have_note) == (want_ref, want_basis, want_note):
            return False
        ident["basis"] = want_basis
        if want_note:
            ident["note"] = want_note
        else:
            ident.pop("note", None)
        await con.execute("UPDATE fleet_agents SET node_ref = $2, identity = $3::jsonb WHERE id = $1",
                          agent["id"], want_ref, json.dumps(ident))
        transition = (have_ref, have_basis) != (want_ref, want_basis)
        if have_ref != want_ref:
            await finding_follow.migrate_targets(con, {have_ref: want_ref})
        if not transition:
            return False                                           # only the note moved: no audit row, no count
        paired = want_basis == "paired"
        state = "active" if paired else _INERT_STATE.get(d.note.partition(":")[2], "inert_asset_missing")
        await audit.record(
            None, action="fleet.pairing.restored" if paired else "fleet.pairing.inert", actor="system:reconcile",
            actor_role="system", resource_type="fleet_agent", resource_id=aid,
            details={"asset_id": str(rec["asset_id"]), "state": state, "node_ref": want_ref, "was": have_ref,
                     "note": want_note}, con=con)
        return True


__all__ = ["PairingError", "put_pairing", "end_pairing", "get_pairing", "list_pairings", "candidates",
           "agent_pairing_summary", "list_conflicts", "create_ack", "clear_ack", "reconcile", "end_for_agent",
           "effective_of", "asset_max_age", "ack_max_hours"]
