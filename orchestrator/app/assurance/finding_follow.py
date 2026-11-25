"""A finding follows its host when the host's node reference changes (``agent:<uuid>`` <-> ``asset:<uuid>``).

Only HOST-CONFIG findings follow (see ``_SELECT``). Invariant findings are keyed by their TARGET node (``findings_sync``): an asset-backed target is the finding of that
asset with the plain ``invariant:<id>`` rule id, every other target (an ``agent:<uuid>`` host) is a finding of the
estate asset with ``invariant:<id>@<target>``. When a host is corroborated with a cloud instance, or loses the
corroboration, the same host has a different target. Without this the old finding closes as "fixed" (the old target
is no longer in the verdict's target list) and a duplicate opens on the new one: the SLA clock resets, tickets and
history stay on the closed row, and a "fixed" event is emitted although nothing was fixed (review findings wire-5 and
hostfw-5).

:func:`migrate_targets` moves the OPEN-side rows (everything but ``fixed``) in place: same finding id, so tickets,
history and aging follow. It never overwrites: if the destination key ``(asset, rule_id, 'invariant')`` is taken the
row stays where it is (the next evaluation settles it the ordinary way) and is not counted. It touches nothing but
``asset_id``, ``rule_id`` and the ``target_ref`` in ``evidence`` and ``metadata``; the next sync refreshes title,
description and witness.

The tenant comes from the connection (RLS). Called from the posture ingest on a node-ref change; the runner can call
it with ``{old_ref: new_ref}`` for a change it sees only in the graph.
"""
from __future__ import annotations

import logging
from typing import Any, Mapping, Optional

from .findings_sync import ESTATE_KIND, ESTATE_VALUE, agent_uuid, asset_uuid, rule_id_for

logger = logging.getLogger(__name__)

#: Only a HOST-CONFIG finding is about the host itself. Its witness is hop-less and its ``detail`` names the host
#: node AND the failing clause (``detail.clause``, ``detail.node == target_ref``). Every other finding on the same
#: asset (a cloud-sourced reachability finding, a coverage finding) is about the ASSET and stays where it is when the
#: agent is merged into or demoted from it; moving it would re-key a finding that nothing changed for and open a
#: duplicate on the next evaluation (verifier finding wire-5, collateral).
_SELECT = """
SELECT id, rule_id, evidence->>'invariant' AS invariant
  FROM findings
 WHERE rule_source = 'invariant' AND status <> 'fixed' AND evidence->>'target_ref' = $1
   AND jsonb_typeof(evidence->'witness'->'detail'->'clause') = 'string'
   AND evidence->'witness'->'detail'->>'node' = $1
 ORDER BY id
   FOR UPDATE
"""

_MOVE = """
UPDATE findings f
   SET asset_id = $2, rule_id = $3,
       evidence = jsonb_set(f.evidence, '{target_ref}', to_jsonb($4::text)),
       metadata = CASE WHEN f.metadata ? 'target_ref'
                       THEN jsonb_set(f.metadata, '{target_ref}', to_jsonb($4::text)) ELSE f.metadata END
 WHERE f.id = $1
   AND NOT EXISTS (SELECT 1 FROM findings g
                    WHERE g.asset_id = $2 AND g.rule_id = $3 AND g.rule_source = 'invariant' AND g.id <> f.id)
RETURNING f.id
"""


def _valid(ref: Any) -> bool:
    return isinstance(ref, str) and (asset_uuid(ref) is not None or agent_uuid(ref) is not None)


async def _destination(con: Any, ref: str) -> Optional[tuple[Any, bool]]:
    """``(asset id, estate?)`` the findings of target ``ref`` live on, or ``None`` when that asset does not exist."""
    aid = asset_uuid(ref)
    if aid is not None:
        found = await con.fetchval("SELECT id FROM assets WHERE id = $1", aid)
        return (found, False) if found is not None else None
    found = await con.fetchval(
        "INSERT INTO assets (kind, value, canonical, source, confidence, metadata) "
        "VALUES ($1, $2, $2, 'finding-bulk', 100, '{}'::jsonb) "
        "ON CONFLICT (tenant_id, kind, canonical) DO UPDATE SET last_seen = NOW() RETURNING id",
        ESTATE_KIND, ESTATE_VALUE)           # the very row the findings upsert resolves for every estate target
    return (found, True) if found is not None else None


async def migrate_targets(con: Any, moves: Mapping[str, str]) -> int:
    """Move the live invariant findings of each ``old_ref`` to ``new_ref``; returns how many rows moved.

    Both refs must be ``agent:<uuid>`` or ``asset:<uuid>``; anything else is ignored. Never raises on a conflict."""
    moved = 0
    for old, new in sorted(moves.items()):
        if not (_valid(old) and _valid(new)) or old == new:
            continue
        try:
            async with con.transaction():
                dest = await _destination(con, new)
                if dest is None:
                    continue
                dest_id, estate = dest
                for row in await con.fetch(_SELECT, old):
                    inv = row["invariant"]
                    if not isinstance(inv, str) or not inv:
                        continue
                    rule_id = rule_id_for(inv, new, estate=estate)
                    if await con.fetchval(_MOVE, row["id"], dest_id, rule_id, new) is not None:
                        moved += 1
        except Exception:  # noqa: BLE001 -- following is best effort: a failure leaves the finding where it was
            logger.warning("finding_follow_failed", exc_info=True, extra={"old": old, "new": new})
    return moved


__all__ = ["migrate_targets"]
