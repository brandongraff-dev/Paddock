"""Route-table + NAT reachability model for the Wargame engine.

DEFENSIVE. This module answers one narrow, honest question: **does a network
*route* exist between two addresses?** That is a different question from
"does a firewall *permit* it?" (which the rule solver in :mod:`.rules`
answers). A firewall *allow* with no underlying route is not a real hop, so
folding routing into reachability can only make the model *stronger* (close
hops that look open at the firewall but have nowhere to go). Nothing here
sends a packet, carries a payload, or represents an exploit — it reasons over
route tables the way the config solver reasons over rules (``docs/WARGAME.md``
§2.2: "priority, deny, object and security-group references, NAT, route
tables, NACLs").

The oracle this exposes, :meth:`RoutingFabric.reachable`, has the signature
:data:`app.engine.wargame.fabric.RouteReachable` (``Callable[[str, str],
bool]``) so :mod:`.topology` can pass ``fabric.reachable`` straight in as its
``route_reachable`` hook.

Modelling choices, made explicit (the honesty rule):

* **Unmodelled routing never blocks.** If no route table is associated with
  the source, :meth:`reachable` returns ``True`` and records an assumption
  (see :meth:`assumptions`). A defensive tool must not claim a boundary is
  closed merely because routing was not modelled — "absence of a model" is not
  "absence of a route". This mirrors :func:`fabric.always_reachable`, the
  default oracle, which returns ``True`` for everything.

* **Longest-prefix match, like real routers.** Within the set of route tables
  whose associated subnet CIDRs overlap the source, the entry whose
  ``dest_cidr`` covers the destination with the *longest* prefix wins — exactly
  as a router picks the most-specific route. A ``0.0.0.0/0`` default (an
  internet or NAT gateway) therefore only wins when nothing more specific
  matches, and it makes any public destination reachable. ``local`` / VPC-CIDR
  routes are always injected so intra-VPC traffic routes even if a table
  omits an explicit local entry.

* **Blackhole routes drop.** A route whose target is ``"blackhole"`` (AWS
  ``State="blackhole"``, e.g. a route to a detached gateway) is *not*
  reachable: if it is the longest-prefix match, the packet is dropped, so the
  destination is unreachable through that table — just like a real router.

* **Overlapping tables are merged by LPM.** In real AWS a subnet uses exactly
  one route table; a source *CIDR* that overlaps several subnets is a modelling
  imprecision. We resolve it deterministically by taking the single
  longest-prefix match across all associated tables (ties broken by table id),
  which is the same answer a merged table would give.

* **NAT is a conditional, not a block.** A hop whose matched route target is a
  NAT/translation gateway still *routes* — but the identity on the far side of
  the translation differs from the address this model reasoned about. This
  module never mutates a rule or a route to reflect that. Instead it exposes
  :meth:`crosses_nat` and :meth:`translate` so the **caller** (topology / the
  solver) can mark the hop ``ConditionalFeature``-style conditional (see
  :class:`app.engine.wargame.parsers.base.ConditionalFeature`): the post-NAT
  address is runtime state the static route table cannot pin down, so the hop
  can only ever yield a CONDITIONAL label, never a *closed* proof.

Pure, deterministic, stdlib only. No I/O: :meth:`from_aws` takes
already-read JSON (a dict or a JSON string). Output is a pure function of the
input.
"""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from typing import Optional, Union

#: A route target meaning "the packet is dropped here" (AWS blackhole).
BLACKHOLE = "blackhole"

_IPNet = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


# ---------------------------------------------------------------------------
# internal address helpers (never raise)
# ---------------------------------------------------------------------------

def _as_network(token: str) -> Optional[_IPNet]:
    """Parse ``token`` (a CIDR or a bare host) to an ip_network, or ``None``.

    A bare address becomes its host network (``/32`` or ``/128``). Never
    raises — an unparseable token is ``None``.
    """
    if not isinstance(token, str):
        return None
    t = token.strip()
    if not t:
        return None
    try:
        return ipaddress.ip_network(t, strict=False)
    except ValueError:
        pass
    try:
        addr = ipaddress.ip_address(t)
    except ValueError:
        return None
    suffix = 32 if addr.version == 4 else 128
    return ipaddress.ip_network(f"{addr}/{suffix}", strict=False)


def _overlaps(a: str, b: str) -> bool:
    """True if CIDRs/hosts ``a`` and ``b`` share any address. Never raises."""
    na, nb = _as_network(a), _as_network(b)
    if na is None or nb is None or na.version != nb.version:
        return False
    return na.overlaps(nb)


def _covers(dest_cidr: str, target_cidr: str) -> bool:
    """True if a route to ``dest_cidr`` carries traffic destined for
    ``target_cidr`` — i.e. ``target_cidr`` is contained in ``dest_cidr``
    (``target`` is a subnet of, or equal to, ``dest``). Never raises."""
    dest, tgt = _as_network(dest_cidr), _as_network(target_cidr)
    if dest is None or tgt is None or dest.version != tgt.version:
        return False
    return tgt.subnet_of(dest)


# ---------------------------------------------------------------------------
# data model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RouteEntry:
    """One route table entry: a destination prefix and where it points.

    ``target`` is the next hop as the export names it — ``"local"``, an
    ``igw-…`` / ``nat-…`` / ``tgw-…`` / ``pcx-…`` gateway id, a next-hop
    address/ENI, or :data:`BLACKHOLE` for a dropped route.
    """

    dest_cidr: str
    target: str

    @property
    def is_blackhole(self) -> bool:
        return self.target == BLACKHOLE


@dataclass(frozen=True)
class RouteTableModel:
    """A route table and the subnet CIDRs that use it."""

    id: str
    entries: tuple[RouteEntry, ...] = ()
    #: CIDRs of the subnets associated with (using) this table.
    associated_cidrs: tuple[str, ...] = ()


@dataclass(frozen=True)
class NatRule:
    """A source/destination NAT rule. Empty ``translated_*`` means that side
    is left unchanged. This module never applies a NAT rule to a route or a
    firewall rule; it only reports matches so the caller can mark the hop
    conditional."""

    match_src_cidr: str
    match_dst_cidr: str
    translated_src: str = ""
    translated_dst: str = ""

    def matches(self, src: str, dst: str) -> bool:
        return _overlaps(src, self.match_src_cidr) and _overlaps(dst, self.match_dst_cidr)


# ---------------------------------------------------------------------------
# the fabric
# ---------------------------------------------------------------------------

class RoutingFabric:
    """A deterministic route-table reachability oracle.

    Built from route tables (plus optional VPC CIDRs for the implicit local
    route, and optional NAT rules). :meth:`reachable` is the oracle the
    topology layer consumes.
    """

    def __init__(
        self,
        tables: "list[RouteTableModel] | tuple[RouteTableModel, ...]" = (),
        *,
        vpc_cidrs: "tuple[str, ...] | list[str]" = (),
        nat_rules: "tuple[NatRule, ...] | list[NatRule]" = (),
    ) -> None:
        # Sort tables by id so cross-table tie-breaks are deterministic.
        self.tables: tuple[RouteTableModel, ...] = tuple(
            sorted(tables, key=lambda t: t.id)
        )
        self.vpc_cidrs: tuple[str, ...] = tuple(vpc_cidrs)
        self.nat_rules: tuple[NatRule, ...] = tuple(nat_rules)
        self._assumptions: list[str] = []

    # -- effective entries (table entries + implicit local/VPC routes) -----
    def _effective_entries(self, table: RouteTableModel) -> tuple[RouteEntry, ...]:
        """The table's own entries plus an implicit ``local`` route for every
        VPC CIDR, so intra-VPC traffic always routes even if the export omits
        the local entry. Duplicates (same dest + target) are dropped."""
        seen: set[tuple[str, str]] = set()
        out: list[RouteEntry] = []
        for e in table.entries:
            key = (e.dest_cidr, e.target)
            if key not in seen:
                seen.add(key)
                out.append(e)
        for c in self.vpc_cidrs:
            key = (c, "local")
            if key not in seen:
                seen.add(key)
                out.append(RouteEntry(dest_cidr=c, target="local"))
        return tuple(out)

    def _tables_for(self, src_cidr: str) -> list[RouteTableModel]:
        """Route tables whose associated subnet CIDRs overlap ``src_cidr``."""
        return [
            t
            for t in self.tables
            if any(_overlaps(src_cidr, c) for c in t.associated_cidrs)
        ]

    def _table_match(
        self, table: RouteTableModel, dst_cidr: str
    ) -> tuple[Optional[RouteEntry], bool]:
        """``(entry, routable)`` for ``dst_cidr`` in one table.

        ``entry`` is the longest-prefix route covering the *whole* destination
        (``None`` if none does). ``routable`` is True if any non-blackhole
        route carries at least part of ``dst_cidr`` and is not wholly
        shadowed by a longer blackhole. A destination wider than any single
        route (e.g. ``0.0.0.0/0`` asked of a table with only a local route)
        is therefore routable when *some* of its addresses are: reachability
        is over-approximated, never narrowed.
        """
        tgt = _as_network(dst_cidr)
        best: Optional[RouteEntry] = None
        best_len = -1
        routable = False
        entries = self._effective_entries(table)
        holes = [
            (n, e) for e in entries
            if e.is_blackhole and (n := _as_network(e.dest_cidr)) is not None
        ]
        for e in entries:
            net = _as_network(e.dest_cidr)
            if net is None or tgt is None or net.version != tgt.version:
                continue
            if _covers(e.dest_cidr, dst_cidr):
                if net.prefixlen > best_len or (
                    net.prefixlen == best_len and best is not None
                    and best.is_blackhole and not e.is_blackhole
                ):
                    best, best_len = e, net.prefixlen
            if e.is_blackhole or not net.overlaps(tgt):
                continue
            inter = tgt if tgt.subnet_of(net) else net     # T ∩ R
            shadowed = any(
                h.version == inter.version and h.prefixlen > net.prefixlen
                and inter.subnet_of(h)
                for h, _ in holes
            )
            if not shadowed:
                routable = True
        return best, routable

    def _best_match(self, src_cidr: str, dst_cidr: str) -> Optional[RouteEntry]:
        """The route that would carry ``src_cidr`` -> ``dst_cidr``, or ``None``
        if no associated table covers the destination.

        Each associated table is longest-prefix-matched on its own. When the
        source overlaps several tables (a modelling imprecision: a subnet uses
        exactly one), the answer favours *reachable*: a non-blackhole match
        beats a blackhole one, then the longer prefix wins, then table id. A
        blackhole in one table can therefore never close a path another
        candidate table carries."""
        best: Optional[RouteEntry] = None
        best_key: tuple[int, int] = (-1, -1)
        for table in self._tables_for(src_cidr):  # already id-sorted
            entry, _ = self._table_match(table, dst_cidr)
            if entry is None:
                continue
            net = _as_network(entry.dest_cidr)
            key = (0 if entry.is_blackhole else 1, net.prefixlen if net else -1)
            if key > best_key:
                best, best_key = entry, key
        return best

    # -- public API --------------------------------------------------------
    def reachable(self, src_cidr: str, dst_cidr: str) -> bool:
        """Does a route exist carrying traffic from ``src_cidr`` to
        ``dst_cidr``?

        * No route table associated with the source → **True** (routing not
          modelled; a defensive tool must not block on ignorance) and an
          assumption is recorded (see :meth:`assumptions`).
        * Otherwise, the longest-prefix-matching route decides: reachable
          unless that route is a :data:`BLACKHOLE` (a dropped route), or no
          table has any covering route for the destination.

        Signature matches :data:`app.engine.wargame.fabric.RouteReachable`.
        """
        if _as_network(src_cidr) is None or _as_network(dst_cidr) is None:
            self._record_assumption(
                f"unparseable address in {src_cidr!r} -> {dst_cidr!r}; assumed reachable"
            )
            return True
        tables = self._tables_for(src_cidr)
        if not tables:
            self._record_assumption(
                f"no route table modelled for {src_cidr}; assumed reachable"
            )
            return True
        # Reachable if ANY candidate table routes it: with a broad association
        # we cannot tell which table the source really uses, and a blackhole or
        # missing route in a different table must not close this path.
        return any(self._table_match(t, dst_cidr)[1] for t in tables)

    def route_target(self, src_cidr: str, dst_cidr: str) -> Optional[str]:
        """The target of the route that would carry ``src_cidr`` → ``dst_cidr``
        (longest-prefix match), or ``None`` if no associated table covers the
        destination. Useful for NAT / conditional detection. A blackhole match
        returns :data:`BLACKHOLE`."""
        best = self._best_match(src_cidr, dst_cidr)
        return best.target if best is not None else None

    def crosses_nat(self, src_ip_or_cidr: str, dst_ip_or_cidr: str) -> bool:
        """True if any NAT rule matches this (src, dst) pair. The caller
        should mark such a hop conditional (the post-NAT identity is runtime
        state this model can't pin down)."""
        if any(r.matches(src_ip_or_cidr, dst_ip_or_cidr) for r in self.nat_rules):
            return True
        # A route whose next hop is a NAT gateway/instance translates too.
        target = self.route_target(src_ip_or_cidr, dst_ip_or_cidr)
        return bool(target) and target.startswith("nat-")

    def translate(self, src: str, dst: str) -> tuple[str, str]:
        """Apply the first matching NAT rule's translation to ``(src, dst)``.
        An empty translated field leaves that side unchanged; no match leaves
        both unchanged. Never mutates the rule or the fabric."""
        for r in self.nat_rules:
            if r.matches(src, dst):
                return (r.translated_src or src, r.translated_dst or dst)
        return (src, dst)

    def assumptions(self) -> list[str]:
        """Human-readable notes about where the model fell back to a
        conservative assumption (e.g. an unmodelled source assumed reachable).
        Deduplicated and sorted for determinism."""
        return sorted(set(self._assumptions))

    # -- internal ----------------------------------------------------------
    def _record_assumption(self, note: str) -> None:
        if note not in self._assumptions:
            self._assumptions.append(note)


# ---------------------------------------------------------------------------
# AWS loader
# ---------------------------------------------------------------------------

def _aws_route_target(route: dict) -> str:
    """Pick the next-hop target from a boto ``Routes[]`` entry.

    A ``State="blackhole"`` route is dropped regardless of its gateway, so it
    maps to :data:`BLACKHOLE`. Otherwise the first populated target field wins,
    in the order AWS would resolve them.
    """
    if str(route.get("State", "")).lower() == BLACKHOLE:
        return BLACKHOLE
    for key in (
        "GatewayId",            # "local" or igw-…
        "NatGatewayId",         # nat-…
        "TransitGatewayId",     # tgw-…
        "VpcPeeringConnectionId",  # pcx-…
        "NetworkInterfaceId",   # eni-…
        "InstanceId",
        "CarrierGatewayId",
        "EgressOnlyInternetGatewayId",
        "LocalGatewayId",
        "CoreNetworkArn",
    ):
        val = route.get(key)
        if val:
            return str(val)
    return "unknown"


def from_aws(
    describe_route_tables_json: "dict | str",
    *,
    nat_rules: "tuple[NatRule, ...] | list[NatRule]" = (),
    subnet_cidrs: Optional[dict[str, str]] = None,
) -> RoutingFabric:
    """Build a :class:`RoutingFabric` from ``aws ec2 describe-route-tables``
    output (boto3 shape), a dict or a JSON string.

    Shape consumed: ``RouteTables[]`` each with ``Routes[]``
    (``DestinationCidrBlock`` / ``DestinationIpv6CidrBlock``, a gateway/next-hop
    field, and ``State``) and ``Associations[]`` (``SubnetId``, ``Main``).

    * **VPC CIDRs** are derived from the ``local`` routes (an AWS route table
      always has a ``local`` route whose destination *is* the VPC CIDR), and
      injected as implicit local routes everywhere.
    * **Associated subnet CIDRs**: when ``subnet_cidrs`` (``{SubnetId: cidr}``)
      is supplied, each table's ``associated_cidrs`` is filled from its
      associations. When it is **not** supplied we cannot know a subnet's CIDR
      from this export alone, so we associate the table broadly with its VPC
      CIDR(s) — the Main table included — which is conservative (it never
      *narrows* what a source can reach). A table with neither is associated
      with ``0.0.0.0/0`` so it still participates rather than silently
      vanishing.
    * **Blackhole** routes (``State="blackhole"``) map to :data:`BLACKHOLE`
      and are not reachable.

    Never raises on missing/odd keys — a malformed table or route is skipped.
    Deterministic for a fixed input (tables sorted by id, routes in order).
    """
    raw = describe_route_tables_json
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (ValueError, TypeError):
            return RoutingFabric((), nat_rules=nat_rules)
    if not isinstance(raw, dict):
        return RoutingFabric((), nat_rules=nat_rules)

    rts = raw.get("RouteTables")
    if not isinstance(rts, list):
        return RoutingFabric((), nat_rules=nat_rules)

    # First pass: collect VPC CIDRs from local routes across all tables.
    vpc_cidrs: list[str] = []
    for rt in rts:
        if not isinstance(rt, dict):
            continue
        for route in rt.get("Routes", []) or []:
            if not isinstance(route, dict):
                continue
            if str(route.get("GatewayId", "")).lower() == "local":
                dest = route.get("DestinationCidrBlock") or route.get(
                    "DestinationIpv6CidrBlock"
                )
                if dest and dest not in vpc_cidrs:
                    vpc_cidrs.append(str(dest))

    tables: list[RouteTableModel] = []
    unknown_dests: list[str] = []
    for rt in rts:
        if not isinstance(rt, dict):
            continue
        table_id = str(rt.get("RouteTableId", "")) or f"rtb-{len(tables)}"

        entries: list[RouteEntry] = []
        local_cidrs: list[str] = []
        for route in rt.get("Routes", []) or []:
            if not isinstance(route, dict):
                continue
            dest = route.get("DestinationCidrBlock") or route.get(
                "DestinationIpv6CidrBlock"
            )
            target = _aws_route_target(route)
            if not dest or _as_network(str(dest)) is None:
                # A prefix-list (pl-…) or otherwise unreadable destination is
                # not a CIDR we can match on. Dropping it would hide a real
                # route (a false "unreachable"), so a live route over-
                # approximates to "everything", and a blackhole is ignored
                # (ignoring a drop can only make the model more reachable).
                if target != BLACKHOLE:
                    unknown_dests.append(
                        f"{table_id}: route via {target} with destination "
                        f"{route.get('DestinationPrefixListId') or dest or '?'} is "
                        "not a CIDR; assumed to reach any destination"
                    )
                    entries.append(RouteEntry(dest_cidr="0.0.0.0/0", target=target))
                    entries.append(RouteEntry(dest_cidr="::/0", target=target))
                continue
            entries.append(RouteEntry(dest_cidr=str(dest), target=target))
            if target == "local":
                local_cidrs.append(str(dest))

        # Associated subnet CIDRs.
        assoc: list[str] = []
        if subnet_cidrs:
            for a in rt.get("Associations", []) or []:
                if not isinstance(a, dict):
                    continue
                sid = a.get("SubnetId")
                if sid and sid in subnet_cidrs:
                    assoc.append(str(subnet_cidrs[sid]))
        if not assoc:
            # No per-subnet CIDRs: associate broadly with the VPC (Main table
            # or otherwise), falling back to the whole VPC CIDR set, then to
            # 0.0.0.0/0 so the table still participates.
            assoc = local_cidrs or list(vpc_cidrs) or ["0.0.0.0/0"]

        tables.append(
            RouteTableModel(
                id=table_id,
                entries=tuple(entries),
                associated_cidrs=tuple(dict.fromkeys(assoc)),
            )
        )

    fabric = RoutingFabric(
        tables,
        vpc_cidrs=tuple(vpc_cidrs),
        nat_rules=nat_rules,
    )
    for note in unknown_dests:
        fabric._record_assumption(note)
    return fabric
