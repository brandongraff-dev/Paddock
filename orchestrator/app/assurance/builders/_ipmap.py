"""IP address -> reach-graph node identity, shared by the builders (docs/ASSURANCE_P1.md section 2).

WHY this exists: the same machine shows up under several names (an EC2 ``cloud_resource`` asset,
the ``ipv4`` asset for its Elastic IP, a Sentry-discovered device). A reach graph that models them
as separate nodes cannot see a path through the merged machine, which is how a false ``HOLDS``
happens. Builders therefore resolve every IP through one map so they agree on the node ref.

The map is **pure** (no database, clock or network) and **collision-safe**: the same private
address legitimately exists in several VPCs, so when an address is claimed by more than one asset we
do not guess an owner. ``resolve`` then falls back to the ``ip:<addr>`` ref (never to an arbitrary
asset) and the collision is reported so the builder can note it. Callers that must not lose a
path (an exposure edge, for example) use ``resolve_all`` to reach *every* candidate (contract D6:
over-approximate when a fact is unknown).

Rows are plain mappings (an asyncpg ``Record`` works): ``id``, ``kind``, ``value`` and ``metadata``
(a dict or its JSON text). Only these asset kinds carry machine identity: ``cloud_resource`` and
the two device kinds. Plain ``ipv4``/``ipv6`` assets are *not* mapped; they are the bare address.

Managed hosts (docs/ASSURANCE_P2.md E3): a ``fleet_agents`` row is an identity too, with
``kind == "agent"`` and the addresses the agent CLAIMS in ``identity.ips`` (its specific bind
addresses). It maps to ``agent:<uuid>``. A claim is only a claim, so it NEVER owns an address and never
makes one ambiguous (review findings hostfw-5 and wire-5): ownership, ``unique``, ``ambiguous``,
``resolve``, ``is_ambiguous`` and ``ips_of`` come from assets alone, so a host that claims a victim's
public or private address cannot withdraw the victim's coverage or take it over. The claimant is only an
extra CANDIDATE for edges (``resolve_all`` adds ``agent:<uuid>`` to what the address could be, so no path
is lost; more candidates only add edges). An agent already merged into a cloud instance (``node_ref``
``asset:...``) adds nothing: its addresses are the asset's. Revoked and legacy agents never reach the map
(the SQL excludes them).

The corroboration decision (:func:`corroborate`) lives here too, so the ingest (``fleet_posture``) and the
builder (``host_fw``) run ONE function and the graph and ``fleet_agents.node_ref`` cannot diverge.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import json
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Optional

from .. import refs

logger = logging.getLogger(__name__)

#: asset kinds that give an address a machine identity.
IDENTITY_KINDS = ("cloud_resource", "iot_device", "ot_device")
#: the row kind of a managed host (a ``fleet_agents`` row), see ``AGENT_IDENTITY_SQL``.
AGENT_KIND = "agent"
#: metadata keys that hold addresses (``ips`` for devices, the rest for cloud resources).
IP_KEYS = ("public_ips", "private_ips", "ips", "ip")

#: SQL a loader can use to fetch the rows ``build_ip_map`` wants (tenant-bound connection, read-only).
IDENTITY_SQL = (
    "SELECT id, kind, value, canonical, metadata FROM assets "
    "WHERE kind IN ('cloud_resource','iot_device','ot_device') "
    "AND (metadata ? 'public_ips' OR metadata ? 'private_ips' OR metadata ? 'ips' OR metadata ? 'ip') "
    "ORDER BY first_seen, id"
)

#: Live v2 agents (not legacy, not revoked) and the addresses they claim. ``identity`` holds the claimed
#: ``ips``; the router never exposes the rest of it, and neither does this map.
AGENT_IDENTITY_SQL = (
    "SELECT id, hostname, node_ref, identity FROM fleet_agents "
    "WHERE legacy = FALSE AND status <> 'revoked' AND revoked_at IS NULL "
    "ORDER BY enrolled_at, id"
)

#: Longest textual address we look at (a v6 literal with a v4 tail is 45 chars); the rest is junk.
_MAX_IP_TEXT = 64
_MAX_IPS_PER_ASSET = 256   # a hostile/buggy asset must not make the map unbounded


def norm_ip(value: Any) -> Optional[str]:
    """Canonical (compressed, lowercase, v4-mapped unwrapped) address text, or ``None``.

    Tolerates one ``[v6]`` bracket pair and surrounding spaces; rejects everything else (CIDRs,
    hostnames, ``ip:port``) so a malformed metadata value never becomes a node. An IPv6 *scope id*
    (``fe80::1%eth0``) is rejected too, never stripped: ``ipaddress`` keeps it in ``.compressed``,
    so ``2001:db8::1%9`` would become a second, phantom node for the machine ``2001:db8::1`` whose
    edges and coverage never meet the real one (review finding security-8). Rejecting is the
    sound choice: an input we cannot canonicalise is dropped (and counted by the caller), it is
    not invented into an identity.
    """
    if not isinstance(value, str) or len(value) > _MAX_IP_TEXT:
        return None
    text = value.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    if "%" in text:
        return None
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.compressed.lower()


def is_public_ip(addr: str) -> bool:
    """True for a globally routable address (not private, loopback, link-local, CGNAT, reserved...).

    Python's ``is_global`` is the right test here: it is False for the documentation ranges and
    100.64/10, neither of which is ever an internet exposure.
    """
    try:
        return ipaddress.ip_address(addr).is_global
    except ValueError:
        return False


def _md(row: Mapping[str, Any]) -> dict[str, Any]:
    md = row.get("metadata")
    if isinstance(md, (str, bytes)):
        try:
            md = json.loads(md)
        except ValueError:
            return {}
    return md if isinstance(md, dict) else {}


def _agent_identity(row: Mapping[str, Any]) -> tuple[Optional[str], dict[str, Any]]:
    """``(agent ref, {"ips": [...]})`` of a ``fleet_agents`` row, or ``(None, {})`` when it adds nothing.

    A row whose ``node_ref`` is an ``asset:`` ref is a corroborated agent: its addresses ARE the
    asset's, so it adds nothing (and must not make its own asset's addresses look ambiguous).
    """
    try:
        ref = refs.agent_ref(row["id"])
    except (refs.RefError, KeyError):
        return None, {}
    node_ref = row.get("node_ref")
    if isinstance(node_ref, str) and node_ref.startswith("asset:"):
        return None, {}
    ident = row.get("identity")
    if isinstance(ident, (str, bytes)):
        try:
            ident = json.loads(ident)
        except ValueError:
            return None, {}
    if not isinstance(ident, dict):
        return None, {}
    ips = ident.get("ips")
    return ref, {"ips": ips if isinstance(ips, list) else []}


def _ips_in(md: Mapping[str, Any]) -> list[str]:
    out: set[str] = set()
    for key in IP_KEYS:
        v = md.get(key)
        for item in ([v] if isinstance(v, str) else v if isinstance(v, list) else []):
            n = norm_ip(item)
            if n:
                out.add(n)
            if len(out) >= _MAX_IPS_PER_ASSET:
                break
    return sorted(out)


def node_kind(asset_kind: str, md: Mapping[str, Any]) -> str:
    """The ``refs.KINDS`` node kind of an asset row (``host`` when we cannot tell)."""
    if asset_kind in ("iot_device", "ot_device"):
        return "device"
    rtype = str(md.get("resource_type") or "").lower()
    if rtype in ("instance", "virtual_machine", "vm", "compute_instance"):
        return "cloud_instance"
    if rtype in ("db_instance", "database", "sql_instance", "cloud_sql") or rtype.endswith("_db"):
        return "cloud_db"
    if rtype.endswith("load_balancer") or rtype in ("lb", "alb", "nlb", "elb"):
        return "cloud_lb"
    return "host"


@dataclass(frozen=True)
class IpMap:
    """Immutable IP -> ref map. Build with :func:`build_ip_map`."""

    unique: Mapping[str, str] = field(default_factory=dict)             # ip -> asset ref
    ambiguous: Mapping[str, tuple[str, ...]] = field(default_factory=dict)  # ip -> sorted refs (>1)
    kinds: Mapping[str, str] = field(default_factory=dict)              # asset ref -> node kind
    ips: Mapping[str, tuple[str, ...]] = field(default_factory=dict)    # asset ref -> all its ips
    claims: Mapping[str, tuple[str, ...]] = field(default_factory=dict)  # ip -> agent refs CLAIMING it (hints)

    def resolve(self, ip: str) -> str:
        """``asset:<uuid>`` when exactly one asset owns ``ip``, else ``ip:<addr>``.

        Raises ``refs.RefError`` for something that is not an address.
        """
        n = norm_ip(ip)
        if n is None:
            raise refs.RefError(f"bad ip {ip!r}")
        return self.unique.get(n) or refs.ip_ref(n)

    def resolve_all(self, ip: str) -> tuple[str, ...]:
        """Every ref this address could be: unique -> that asset; unknown -> ``ip:``; ambiguous ->
        all candidate assets **and** ``ip:`` (so no path is lost by guessing one owner). Agents that merely
        CLAIM the address are added as further candidates (an over-approximation, never an owner)."""
        n = norm_ip(ip)
        if n is None:
            raise refs.RefError(f"bad ip {ip!r}")
        extra = self.claims.get(n, ())          # agent claimants: candidates for edges, never owners
        if n in self.unique:
            return tuple(sorted({self.unique[n], *extra}))
        if n in self.ambiguous:
            return tuple(sorted({*self.ambiguous[n], refs.ip_ref(n), *extra}))
        return tuple(sorted({refs.ip_ref(n), *extra}))

    def is_ambiguous(self, ip: str) -> bool:
        n = norm_ip(ip)
        return n is not None and n in self.ambiguous

    def node_kind(self, ref: str) -> str:
        """Kind for a ref: the asset's kind, ``ip`` for ``ip:`` refs, ``host`` otherwise."""
        if ref in self.kinds:
            return self.kinds[ref]
        return "ip" if ref.startswith("ip:") else "host"

    def ips_of(self, ref: str) -> tuple[str, ...]:
        """All addresses the asset ``ref`` claims (including ambiguous ones); ``()`` if unknown."""
        return tuple(self.ips.get(ref, ()))

    def report(self, limit: int = 5) -> list[str]:
        """Human notes about dropped (ambiguous) mappings, deterministic and bounded."""
        if not self.ambiguous:
            return []
        items = sorted(self.ambiguous.items())
        lines = [f"{len(items)} address(es) claimed by more than one asset were not merged "
                 f"(identity left as ip:<addr>)"]
        lines += [f"  {ip}: {', '.join(rs)}" for ip, rs in items[:limit]]
        if len(items) > limit:
            lines.append(f"  ... and {len(items) - limit} more")
        return lines


def build_ip_map(rows: Iterable[Mapping[str, Any]]) -> IpMap:
    """Build the map from asset rows. Order of ``rows`` never changes the result.

    Agent rows (``kind == "agent"``) only fill ``IpMap.claims``: they never own an address."""
    owners: dict[str, set[str]] = {}
    kinds: dict[str, str] = {}
    ips_by_ref: dict[str, tuple[str, ...]] = {}
    claims: dict[str, set[str]] = {}
    for row in rows:
        kind = row.get("kind")
        if kind == AGENT_KIND:
            aref, amd = _agent_identity(row)
            if aref is not None:
                for ip in _ips_in({"ips": amd.get("ips")}):
                    claims.setdefault(ip, set()).add(aref)
            continue
        if kind not in IDENTITY_KINDS:
            continue
        try:
            ref = refs.asset_ref(row["id"])
        except (refs.RefError, KeyError):
            continue
        md = _md(row)
        ips = _ips_in(md)
        if not ips:
            continue
        kinds[ref] = node_kind(str(kind), md)
        ips_by_ref[ref] = tuple(ips)
        for ip in ips:
            owners.setdefault(ip, set()).add(ref)
    unique = {ip: next(iter(rs)) for ip, rs in owners.items() if len(rs) == 1}
    ambiguous = {ip: tuple(sorted(rs)) for ip, rs in owners.items() if len(rs) > 1}
    return IpMap(unique=dict(sorted(unique.items())), ambiguous=dict(sorted(ambiguous.items())),
                 kinds=dict(sorted(kinds.items())), ips=dict(sorted(ips_by_ref.items())),
                 claims={ip: tuple(sorted(rs)) for ip, rs in sorted(claims.items())})


# --------------------------------------------------------------------------- #
# corroboration of an agent with a cloud instance (E3): ONE decision for ingest and builder
# --------------------------------------------------------------------------------------------

#: the node kind (``node_kind``) of a cloud VM, the only asset that can absorb an agent.
INSTANCE_KIND = "cloud_instance"
_MAX_CLAIMED_IPS = 32


@dataclass(frozen=True)
class Claim:
    """What one live agent says about itself (``identity.ips``, claimed) and what the server saw of it
    (``peer_ip``, the strict client address)."""

    agent_id: str
    ips: tuple[str, ...]
    peer: Optional[str]
    #: True ONLY when the ingest recorded ``peer_proxied: false`` (``auth.ClientAddr.proxied``). Everything else, a
    #: forwarding hop, a missing key (a row written before the flag existed, possibly with a forged peer from the old
    #: ``client_ip_strict``) or a malformed value, reads as "may be a hop": a peer of unknown provenance proves nothing
    #: (review finding Z-3).
    direct: bool = False


@dataclass(frozen=True)
class Decision:
    """``ref`` is the ``asset:<uuid>`` the agent is merged into, or ``None`` (it stays ``agent:<uuid>``,
    ``claimed``). ``note`` says why not (``""`` when merged or nothing to say). ``basis`` is ``paired`` only for an
    operator pairing (:func:`pairing_decision`); ``conflict`` is ``paired_peer_mismatch`` when the server saw a direct,
    private, unshared peer address that is not one of the asset's addresses (a negative detector, D28)."""

    ref: Optional[str]
    note: str = ""
    basis: str = "claimed"
    conflict: str = ""


def claimed_ips(identity: Any) -> list[str]:
    """The agent's claimed bind addresses, canonical, without loopback/unspecified/multicast/link-local, capped."""
    out: set[str] = set()
    raw = identity.get("ips") if isinstance(identity, Mapping) else None
    for v in raw if isinstance(raw, list) else []:
        n = norm_ip(v)
        if n is None:
            continue
        ip = ipaddress.ip_address(n)
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
            continue
        out.add(n)
        if len(out) >= _MAX_CLAIMED_IPS:
            break
    return sorted(out)


def claim_of(agent_id: Any, identity: Any) -> Claim:
    """A :class:`Claim` from a ``fleet_agents`` row's id and identity JSON (decoded)."""
    ident = identity if isinstance(identity, Mapping) else {}
    peer = ident.get("peer_ip")
    return Claim(str(agent_id), tuple(claimed_ips(ident)), norm_ip(peer) if isinstance(peer, str) else None,
                 direct=ident.get("peer_proxied") is False)


#: Whether a PRIVATE source address the server saw is accepted as proof that an agent IS a cloud instance (rules 1 to 4
#: of :func:`corroborate`). It is OFF: owner decision (2) says corroboration must be impossible to forge from inside
#: the network, and a header-less NAT or VPN instance that rewrites another machine's source to its own private
#: address, with one enrolled agent behind it, is indistinguishable from the instance (review finding Z-2). A weak
#: proof is no proof: the agent stays ``agent:<uuid>``, ``claimed``, which is safe (the host is judged on its own
#: facts, the instance node keeps no host facts and so reads UNKNOWN, never a false HOLDS). The switch exists so a
#: P2.1 trust root (a server-verified instance-identity document, or an operator pairing of agent and asset) can
#: turn the proof back on per claim; there is deliberately no setting, route or UI for it in P2.
PRIVATE_PEER_IS_PROOF = False


def corroborate(claims: Iterable[Claim], amap: IpMap, *, private_peer_proof: Optional[bool] = None) -> dict[str, Decision]:
    """Decide, for every claim, whether the agent is merged into a cloud instance. ``amap`` holds ASSETS only.

    An agent is merged into instance ``X`` only when ALL hold:

    1. its claimed addresses are a non-empty subset of the PRIVATE addresses of exactly one cloud instance ``X``
       that owns them uniquely (not ambiguous with another asset);
    2. the address the server saw it connect from is one of ``X``'s PRIVATE addresses, and that address is a direct
       peer (``Claim.direct``): a request that carried forwarding headers the server does not trust, or came from
       a trusted proxy that reported nothing usable, shows the PROXY's address (a single agent behind the
       ingress node would otherwise corroborate as that node). A public peer address is NOT proof either: every
       host behind a NAT instance, proxy or bastion shares that instance's public address (review finding
       hostfw-2). A private source address cannot be forged from another network, and a host cannot borrow it
       unless it is routed through ``X`` itself, which the next rule catches when another enrolled agent shares
       it. BUT (review finding Z-2): a header-less NAT or VPN instance that rewrites the source of ANOTHER machine
       to ``X``'s own private address, with exactly ONE enrolled agent behind it, is not distinguishable from ``X``
       itself, so that machine would be merged into ``X`` and its facts and inbound coverage would speak for ``X``.
       The agent's hostname proves nothing (the host's own word, derivable from the address) and the inventory has
       no signed per-instance identity. A private peer address alone is therefore NOT proof
       (:data:`PRIVATE_PEER_IS_PROOF` is off, owner decision 2): a claim that passes rules 1 and 2 still stays
       ``claimed`` (note ``peer_address_not_proof``). Merging needs a new trust root (a signed instance-identity
       document the server verifies, or an operator pairing of agent and asset), P2.1. Rules 3 and 4 below are
       kept as they are, so the day the proof is turned on they already hold;
    3. no OTHER enrolled agent presents the same peer address (shared egress: the address says nothing about
       which machine it is). Every agent counts, whatever it claims;
    4. no other agent that passed rules 1 and 2 for the same instance exists (two agents on one cloud node merge
       NEITHER).

    Only an agent that itself passed 1 and 2 takes part in rule 4: a claim that never passed cannot demote or
    clash with a corroborated agent (review findings hostfw-5 and wire-5); it only stays ``claimed``. Rule 3
    counts the OTHER agents' observed peer, which is server-observed evidence, not a claim. Pure and
    deterministic; input order never changes the result."""
    proof = PRIVATE_PEER_IS_PROOF if private_peer_proof is None else bool(private_peer_proof)
    claims = sorted(claims, key=lambda c: c.agent_id)
    by_peer: dict[str, set[str]] = {}
    for c in claims:
        if c.peer:
            by_peer.setdefault(c.peer, set()).add(c.agent_id)
    out: dict[str, Decision] = {}
    passed: dict[str, str] = {}
    for c in claims:
        out[c.agent_id] = Decision(None, "")
        if not c.ips:
            continue
        owners = {amap.unique.get(ip) for ip in c.ips}
        if len(owners) != 1 or None in owners or any(amap.is_ambiguous(ip) for ip in c.ips):
            if any(amap.is_ambiguous(ip) or amap.unique.get(ip) for ip in c.ips):
                out[c.agent_id] = Decision(None, "ambiguous_cloud_node")
            continue
        ref = next(iter(owners))
        if amap.node_kind(ref) != INSTANCE_KIND:
            continue
        private = {ip for ip in amap.ips_of(ref) if not is_public_ip(ip)}
        if not set(c.ips) <= private:
            continue
        if c.peer is None or c.peer not in private:
            out[c.agent_id] = Decision(None, "peer_address_not_instance")
            continue
        if not c.direct:
            out[c.agent_id] = Decision(None, "peer_not_direct")
            continue
        if not proof:
            out[c.agent_id] = Decision(None, "peer_address_not_proof")
            continue
        passed[c.agent_id] = ref
    by_ref: dict[str, list[str]] = {}
    for aid, ref in passed.items():
        by_ref.setdefault(ref, []).append(aid)
    peer_of = {c.agent_id: c.peer for c in claims}
    for aid, ref in sorted(passed.items()):
        if len(by_peer.get(peer_of[aid], ())) > 1:
            out[aid] = Decision(None, "shared_peer_address")
        elif len(by_ref[ref]) > 1:
            out[aid] = Decision(None, "ambiguous_cloud_node")
        else:
            out[aid] = Decision(ref, "")
    return out


# --------------------------------------------------------------------------- #
# the operator pairing of an agent with a cloud instance (docs/ASSURANCE_P2_1.md section 4): ONE decision for the
# ingest (``fleet_posture._resolve_node``) and the builder (``host_fw``)
# --------------------------------------------------------------------------------------------

#: a pairing says "agent row A is the machine that is cloud asset X"; it changes IDENTITY only (D27).
PAIRED = "paired"
#: the one conflict a pairing can raise itself: the peer address the server saw is not the asset's (D28).
PEER_MISMATCH = "paired_peer_mismatch"
#: how far in the future an asset's ``last_seen`` may be before it stops counting as "seen" (a date nothing can age).
ASSET_FUTURE_SKEW = dt.timedelta(minutes=5)

#: SQL both the ingest and the builder read an active pairing with (tenant-bound connection, read-only). The asset is
#: LEFT JOINed: a deleted asset must make the pairing inert, never erase it. ``md`` holds only the address metadata.
PAIRING_COLUMNS = (
    "p.id AS pairing_id, p.agent_id, p.asset_id, a.id AS a_id, a.kind, a.last_seen, "
    "jsonb_build_object('resource_type', a.metadata->'resource_type', 'private_ips', a.metadata->'private_ips', "
    "'public_ips', a.metadata->'public_ips', 'ips', a.metadata->'ips', 'ip', a.metadata->'ip') AS md"
)
PAIRING_FROM = "FROM fleet_agent_pairings p LEFT JOIN assets a ON a.id = p.asset_id"
PAIRING_SELECT_SQL = f"SELECT {PAIRING_COLUMNS} {PAIRING_FROM} WHERE p.status = 'active'"


@dataclass(frozen=True)
class PairingRow:
    """An ACTIVE pairing joined with its asset. ``node_kind is None`` means the asset row is missing."""

    agent_id: str
    pairing_id: str
    asset_ref: str
    node_kind: Optional[str]
    asset_ips: tuple[str, ...] = ()
    asset_last_seen: Optional[dt.datetime] = None


def pairing_row(rec: Mapping[str, Any]) -> Optional[PairingRow]:
    """A :class:`PairingRow` from a ``PAIRING_SELECT_SQL`` record, or ``None`` for a malformed one (it then never
    pairs). Only a ``cloud_resource`` asset can be a VM: a device or any other kind that merely carries VM-looking
    metadata is ``host`` (not a VM)."""
    try:
        agent_id = str(uuid.UUID(str(rec["agent_id"])))
        asset_ref = refs.asset_ref(rec["asset_id"])
    except (KeyError, ValueError, TypeError, refs.RefError):
        return None
    pid = rec.get("pairing_id")
    if rec.get("a_id") is None:
        return PairingRow(agent_id, str(pid), asset_ref, None, (), None)
    md = rec.get("md")
    if isinstance(md, (str, bytes)):
        try:
            md = json.loads(md)
        except ValueError:
            md = {}
    md = md if isinstance(md, dict) else {}
    kind = rec.get("kind")
    node = node_kind(str(kind), md) if kind == "cloud_resource" else "host"
    seen = rec.get("last_seen")
    return PairingRow(agent_id, str(pid), asset_ref, node, tuple(_ips_in(md)),
                      seen if isinstance(seen, dt.datetime) else None)


def _utc(t: dt.datetime) -> dt.datetime:
    return t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)


def pairing_decision(claim: Claim, row: Optional[PairingRow], now: dt.datetime, max_age: dt.timedelta,
                     peer_shared: bool) -> Decision:
    """What an agent's operator pairing decides. Pure; ingest and builder run this one function.

    * no row                           -> ``Decision(None, "")``: falls through to :func:`corroborate` (inert);
    * the asset row is gone            -> ``pairing_inert:asset_missing``;
    * the asset is not a cloud VM      -> ``pairing_inert:asset_not_vm``;
    * ``last_seen`` older than ``max_age`` (or undated, or in the future) -> ``pairing_inert:asset_stale``;
    * otherwise ``Decision(asset_ref, "", basis="paired", conflict=...)``.

    An inert pairing falls back to ``agent:<uuid>`` / ``claimed`` with that note: nothing is ended automatically and
    nothing is silently dropped. ``conflict`` is ``paired_peer_mismatch`` iff the claim is DIRECT (no forwarding hop),
    its peer is a PRIVATE address no other agent presents (``peer_shared`` False) and the asset does not own it: the
    peer can only withdraw trust, so a false conflict costs availability, never a false HOLDS (D28)."""
    if row is None:
        return Decision(None, "")
    if row.node_kind is None:
        return Decision(None, "pairing_inert:asset_missing")
    if row.node_kind != INSTANCE_KIND:
        return Decision(None, "pairing_inert:asset_not_vm")
    seen = row.asset_last_seen
    now = _utc(now)
    if (seen is None or now - _utc(seen) > max_age or _utc(seen) - now > ASSET_FUTURE_SKEW):
        return Decision(None, "pairing_inert:asset_stale")
    conflict = ""
    if claim.direct and claim.peer is not None and not is_public_ip(claim.peer) and not peer_shared \
            and claim.peer not in row.asset_ips:
        conflict = PEER_MISMATCH
    return Decision(row.asset_ref, "", PAIRED, conflict)


def resolve(ip_map: IpMap, ip: str) -> str:
    """Module-level spelling of :meth:`IpMap.resolve` (``'asset:<uuid>'`` or ``'ip:<addr>'``)."""
    return ip_map.resolve(ip)


async def load_ip_rows(conn) -> list[dict[str, Any]]:
    """Fetch the identity rows ``build_ip_map`` needs: cloud/device assets, then live agents.

    Tenancy comes from the connection (RLS). A failure reading the agents (a schema without them)
    must not take the asset identities, and with them every builder that shares this map, down: the
    agents are skipped and the hosts keep their ``ip:`` identity, which only ever loses a merge.
    """
    rows = [dict(r) for r in await conn.fetch(IDENTITY_SQL)]
    try:
        for r in await conn.fetch(AGENT_IDENTITY_SQL):
            d = dict(r)
            rows.append({"id": d["id"], "kind": AGENT_KIND, "node_ref": d.get("node_ref"),
                         "identity": d.get("identity")})
    except Exception:  # noqa: BLE001 -- see docstring; asyncpg.PostgresError and friends
        logger.warning("ipmap_agents_unreadable", exc_info=True)
    return rows
