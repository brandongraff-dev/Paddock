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
addresses). It maps to ``agent:<uuid>``. A claim is only a claim: an address that an asset also owns
is ambiguous (``resolve_all`` then returns the asset, the agent AND ``ip:``, so no path is lost),
and an agent already merged into a cloud instance (``node_ref`` ``asset:...``) adds nothing, its
addresses are the asset's. Revoked and legacy agents never reach the map (the SQL excludes them).
"""
from __future__ import annotations

import ipaddress
import json
import logging
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
        all candidate assets **and** ``ip:`` (so no path is lost by guessing one owner)."""
        n = norm_ip(ip)
        if n is None:
            raise refs.RefError(f"bad ip {ip!r}")
        if n in self.unique:
            return (self.unique[n],)
        if n in self.ambiguous:
            return tuple(sorted({*self.ambiguous[n], refs.ip_ref(n)}))
        return (refs.ip_ref(n),)

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
    """Build the map from asset rows. Order of ``rows`` never changes the result."""
    owners: dict[str, set[str]] = {}
    kinds: dict[str, str] = {}
    ips_by_ref: dict[str, tuple[str, ...]] = {}
    for row in rows:
        kind = row.get("kind")
        if kind == AGENT_KIND:
            ref, md = _agent_identity(row)
            if ref is None:
                continue
        elif kind in IDENTITY_KINDS:
            try:
                ref = refs.asset_ref(row["id"])
            except (refs.RefError, KeyError):
                continue
            md = _md(row)
        else:
            continue
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
                 kinds=dict(sorted(kinds.items())), ips=dict(sorted(ips_by_ref.items())))


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
