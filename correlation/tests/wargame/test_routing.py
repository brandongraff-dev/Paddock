"""Tests for the route-table + NAT reachability model (:mod:`.routing`).

These exercise the things that decide correctness for a *defensive* routing
model: longest-prefix match (a specific route beats the default), blackhole
drops, the conservative fallback when routing is unmodelled, NAT detection
(which makes a hop conditional rather than blocking it), and that the oracle
has the ``RouteReachable`` shape the topology layer feeds it.
"""
from __future__ import annotations

import json
import os

from app.engine.wargame.routing import (
    BLACKHOLE,
    NatRule,
    RouteEntry,
    RouteTableModel,
    RoutingFabric,
    from_aws,
)

_FIX = os.path.join(os.path.dirname(__file__), "parsers", "fixtures")


def _load(name: str) -> dict:
    with open(os.path.join(_FIX, name)) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# intra-VPC / local reachability
# ---------------------------------------------------------------------------

def test_intra_vpc_local_reachability():
    fab = RoutingFabric(
        [
            RouteTableModel(
                id="rtb-a",
                entries=(RouteEntry("10.0.0.0/16", "local"),),
                associated_cidrs=("10.0.1.0/24",),
            )
        ],
        vpc_cidrs=("10.0.0.0/16",),
    )
    assert fab.reachable("10.0.1.0/24", "10.0.5.0/24") is True
    assert fab.route_target("10.0.1.0/24", "10.0.5.0/24") == "local"
    # No fallback assumption was needed: routing was modelled.
    assert fab.assumptions() == []


def test_local_route_injected_from_vpc_cidr_even_if_table_omits_it():
    # Table has only a default route; the VPC-CIDR local route is injected.
    fab = RoutingFabric(
        [
            RouteTableModel(
                id="rtb-a",
                entries=(RouteEntry("0.0.0.0/0", "igw-1"),),
                associated_cidrs=("10.0.1.0/24",),
            )
        ],
        vpc_cidrs=("10.0.0.0/16",),
    )
    # Intra-VPC destination routes via the injected local, not the default.
    assert fab.route_target("10.0.1.0/24", "10.0.9.9/32") == "local"


# ---------------------------------------------------------------------------
# peering, igw default, blackhole
# ---------------------------------------------------------------------------

def test_reaches_peered_cidr_via_pcx():
    fab = RoutingFabric(
        [
            RouteTableModel(
                id="rtb-a",
                entries=(
                    RouteEntry("10.0.0.0/16", "local"),
                    RouteEntry("10.50.0.0/16", "pcx-123"),
                    RouteEntry("0.0.0.0/0", "nat-1"),
                ),
                associated_cidrs=("10.0.1.0/24",),
            )
        ],
    )
    assert fab.reachable("10.0.1.0/24", "10.50.1.0/24") is True
    assert fab.route_target("10.0.1.0/24", "10.50.1.0/24") == "pcx-123"


def test_default_route_via_igw_reaches_public_dst():
    fab = RoutingFabric(
        [
            RouteTableModel(
                id="rtb-pub",
                entries=(
                    RouteEntry("10.0.0.0/16", "local"),
                    RouteEntry("0.0.0.0/0", "igw-1"),
                ),
                associated_cidrs=("10.0.2.0/24",),
            )
        ],
    )
    assert fab.reachable("10.0.2.0/24", "203.0.113.10/32") is True
    assert fab.route_target("10.0.2.0/24", "203.0.113.10/32") == "igw-1"


def test_blackhole_dest_not_reachable():
    fab = RoutingFabric(
        [
            RouteTableModel(
                id="rtb-a",
                entries=(
                    RouteEntry("10.0.0.0/16", "local"),
                    RouteEntry("0.0.0.0/0", "nat-1"),
                    RouteEntry("10.0.200.0/24", BLACKHOLE),
                ),
                associated_cidrs=("10.0.1.0/24",),
            )
        ],
    )
    # The /24 blackhole is a longer-prefix match than the 0.0.0.0/0 default,
    # so it wins and the destination is unreachable.
    assert fab.reachable("10.0.1.0/24", "10.0.200.5/32") is False
    assert fab.route_target("10.0.1.0/24", "10.0.200.5/32") == BLACKHOLE
    # A different in-range dst still routes via the default.
    assert fab.reachable("10.0.1.0/24", "198.51.100.1/32") is True


# ---------------------------------------------------------------------------
# unmodelled routing: conservative True + assumption
# ---------------------------------------------------------------------------

def test_unmodelled_source_is_reachable_and_records_assumption():
    fab = RoutingFabric(
        [
            RouteTableModel(
                id="rtb-a",
                entries=(RouteEntry("10.0.0.0/16", "local"),),
                associated_cidrs=("10.0.1.0/24",),
            )
        ],
    )
    # 10.9.0.0/24 has no associated table -> don't block, record assumption.
    assert fab.reachable("10.9.0.0/24", "10.0.1.5/32") is True
    notes = fab.assumptions()
    assert len(notes) == 1
    assert "10.9.0.0/24" in notes[0]
    assert "assumed reachable" in notes[0]
    # Calling again must not duplicate the assumption.
    assert fab.reachable("10.9.0.0/24", "10.0.1.5/32") is True
    assert fab.assumptions() == notes


def test_empty_fabric_is_fully_conservative():
    fab = RoutingFabric()
    assert fab.reachable("10.0.0.0/24", "10.0.1.0/24") is True
    assert len(fab.assumptions()) == 1


# ---------------------------------------------------------------------------
# longest-prefix selection between overlapping routes
# ---------------------------------------------------------------------------

def test_longest_prefix_wins_between_overlapping_routes():
    fab = RoutingFabric(
        [
            RouteTableModel(
                id="rtb-a",
                entries=(
                    RouteEntry("10.0.0.0/8", "tgw-broad"),
                    RouteEntry("10.0.0.0/16", "local"),
                    RouteEntry("10.0.5.0/24", "pcx-specific"),
                ),
                associated_cidrs=("192.168.1.0/24",),
            )
        ],
    )
    # /24 beats /16 beats /8.
    assert fab.route_target("192.168.1.0/24", "10.0.5.7/32") == "pcx-specific"
    assert fab.route_target("192.168.1.0/24", "10.0.9.9/32") == "local"
    assert fab.route_target("192.168.1.0/24", "10.9.9.9/32") == "tgw-broad"


def test_no_covering_route_modelled_source_is_unreachable():
    fab = RoutingFabric(
        [
            RouteTableModel(
                id="rtb-a",
                entries=(RouteEntry("10.0.0.0/16", "local"),),
                associated_cidrs=("10.0.1.0/24",),
            )
        ],
    )
    # Routing IS modelled for this source, but nothing covers a public dst
    # (no default route) -> no route exists.
    assert fab.reachable("10.0.1.0/24", "8.8.8.8/32") is False
    assert fab.route_target("10.0.1.0/24", "8.8.8.8/32") is None


# ---------------------------------------------------------------------------
# NAT: match + translate + crosses_nat
# ---------------------------------------------------------------------------

def test_nat_match_translate_and_crosses_nat():
    nat = NatRule(
        match_src_cidr="10.0.1.0/24",
        match_dst_cidr="203.0.113.0/24",
        translated_src="198.51.100.10/32",
    )
    fab = RoutingFabric([], nat_rules=(nat,))

    assert fab.crosses_nat("10.0.1.5", "203.0.113.9") is True
    assert fab.crosses_nat("10.0.2.5", "203.0.113.9") is False  # src outside
    assert fab.crosses_nat("10.0.1.5", "8.8.8.8") is False      # dst outside

    # translate rewrites the source, leaves the (empty) dst unchanged.
    assert fab.translate("10.0.1.5", "203.0.113.9") == ("198.51.100.10/32", "203.0.113.9")
    # no match -> unchanged.
    assert fab.translate("10.0.2.5", "8.8.8.8") == ("10.0.2.5", "8.8.8.8")


def test_nat_dst_translation():
    nat = NatRule(
        match_src_cidr="0.0.0.0/0",
        match_dst_cidr="198.51.100.5/32",
        translated_dst="10.0.3.9/32",
    )
    fab = RoutingFabric([], nat_rules=(nat,))
    assert fab.crosses_nat("8.8.8.8", "198.51.100.5") is True
    assert fab.translate("8.8.8.8", "198.51.100.5") == ("8.8.8.8", "10.0.3.9/32")


# ---------------------------------------------------------------------------
# from_aws: parse the fixture
# ---------------------------------------------------------------------------

def test_from_aws_parses_fixture():
    data = _load("aws_route_tables.json")
    subnet_cidrs = {
        "subnet-0private0a": "10.0.1.0/24",
        "subnet-0private0b": "10.0.2.0/24",
        "subnet-0public0a": "10.0.100.0/24",
    }
    fab = from_aws(data, subnet_cidrs=subnet_cidrs)

    # VPC CIDR derived from the local routes.
    assert "10.0.0.0/16" in fab.vpc_cidrs

    # Private subnet: intra-VPC local, peered via pcx, public via nat.
    assert fab.reachable("10.0.1.0/24", "10.0.9.9/32") is True
    assert fab.route_target("10.0.1.0/24", "10.0.9.9/32") == "local"
    assert fab.route_target("10.0.1.0/24", "10.50.4.4/32") == "pcx-0abc123def4567890"
    assert fab.route_target("10.0.1.0/24", "1.1.1.1/32") == "nat-0a1b2c3d4e5f6a7b8"

    # The blackhole route in the private table drops its /24.
    assert fab.route_target("10.0.1.0/24", "10.0.200.5/32") == BLACKHOLE
    assert fab.reachable("10.0.1.0/24", "10.0.200.5/32") is False

    # Public subnet reaches the internet via the igw default route.
    assert fab.route_target("10.0.100.0/24", "203.0.113.1/32") == "igw-0f1e2d3c4b5a69780"
    assert fab.reachable("10.0.100.0/24", "203.0.113.1/32") is True


def test_from_aws_accepts_json_string():
    data = _load("aws_route_tables.json")
    fab = from_aws(json.dumps(data), subnet_cidrs={"subnet-0public0a": "10.0.100.0/24"})
    assert fab.reachable("10.0.100.0/24", "203.0.113.1/32") is True


def test_from_aws_without_subnet_map_associates_broadly():
    data = _load("aws_route_tables.json")
    fab = from_aws(data)  # no subnet_cidrs
    # Tables are associated broadly with the VPC CIDR, so an intra-VPC source
    # still routes rather than vanishing.
    assert fab.reachable("10.0.1.0/24", "10.0.9.9/32") is True


def test_from_aws_tolerates_garbage():
    assert isinstance(from_aws("not json at all"), RoutingFabric)
    assert isinstance(from_aws({"Nope": []}), RoutingFabric)
    assert isinstance(from_aws(12345), RoutingFabric)  # type: ignore[arg-type]
    # A garbage input yields an empty, fully-conservative fabric.
    assert from_aws({"Nope": []}).reachable("10.0.0.0/24", "10.0.1.0/24") is True


# ---------------------------------------------------------------------------
# determinism and the RouteReachable contract
# ---------------------------------------------------------------------------

def test_determinism():
    data = _load("aws_route_tables.json")
    subnet_cidrs = {"subnet-0private0a": "10.0.1.0/24"}
    a = from_aws(data, subnet_cidrs=subnet_cidrs)
    b = from_aws(data, subnet_cidrs=subnet_cidrs)
    pairs = [
        ("10.0.1.0/24", "10.0.9.9/32"),
        ("10.0.1.0/24", "10.50.4.4/32"),
        ("10.0.1.0/24", "10.0.200.5/32"),
        ("10.0.1.0/24", "1.1.1.1/32"),
    ]
    for s, d in pairs:
        assert a.reachable(s, d) == b.reachable(s, d)
        assert a.route_target(s, d) == b.route_target(s, d)


def test_reachable_matches_route_reachable_callable_shape():
    # fabric.RouteReachable = Callable[[str, str], bool]. topology passes
    # fabric.reachable straight in, so it must be callable with two str args
    # and return a bool.
    fab = RoutingFabric(
        [
            RouteTableModel(
                id="rtb-a",
                entries=(RouteEntry("10.0.0.0/16", "local"),),
                associated_cidrs=("10.0.1.0/24",),
            )
        ],
    )
    route_reachable = fab.reachable  # the callable the topology layer stores
    assert callable(route_reachable)
    result = route_reachable("10.0.1.0/24", "10.0.5.0/24")
    assert isinstance(result, bool)

    # It is drop-in compatible with the default oracle's signature.
    from app.engine.wargame.fabric import always_reachable

    assert always_reachable.__call__ is not None
    assert isinstance(always_reachable("a", "b"), bool)
