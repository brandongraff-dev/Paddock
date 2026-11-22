"""End-to-end Wargame pipeline test.

Ties the six modules together over the canonical demo environment:

    guest wifi --observed--> smart fridge --fw--> POS --fw--> payments DB

and a *closed* boundary (clinic wifi -> payments DB) that yields a
certificate and, when a flow crosses it anyway, an impossible-traffic
alert.

It exercises the public seams exactly as ``docs/WARGAME.md`` describes
them, so a change that breaks the contract between modules fails here.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.engine.wargame.model import (
    Action,
    Assumption,
    Corroboration,
    Edge,
    EvidenceLabel,
    FixCandidate,
    Flow,
    Node,
    NodeRole,
    PortRange,
    Precondition,
    PreconditionKind,
    Proto,
    ReplicaPlan,
    Rule,
    RuleSet,
)

# These modules are built by the parallel agents; skip cleanly until they
# land so this file can be committed alongside the foundation.
reachability = pytest.importorskip("app.engine.wargame.reachability")
mincut = pytest.importorskip("app.engine.wargame.mincut")
certificate = pytest.importorskip("app.engine.wargame.certificate")
impossible = pytest.importorskip("app.engine.wargame.impossible")
replica = pytest.importorskip("app.engine.wargame.replica")


# ---------------------------------------------------------------------------
# The demo environment
# ---------------------------------------------------------------------------

def _demo():
    nodes = {
        "guest_wifi": Node("guest_wifi", NodeRole.ENTRY, ("10.9.0.0/24",),
                           reason="guest wireless"),
        "fridge": Node("fridge", NodeRole.INTERMEDIATE, ("10.9.0.50/32",)),
        "pos": Node("pos", NodeRole.INTERMEDIATE, ("10.5.0.0/24",)),
        "payments_db": Node("payments_db", NodeRole.CROWN_JEWEL, ("10.1.0.0/24",),
                            reason="cardholder data", jewel_kind="cardholder_data"),
        "clinic_wifi": Node("clinic_wifi", NodeRole.ENTRY, ("10.8.0.0/24",),
                            reason="clinic wireless"),
    }
    rulesets = {
        "fw_pos": RuleSet("fw_pos", [
            Rule("allow_fridge_pos", Action.ALLOW, 10,
                 ("10.9.0.0/24",), ("10.5.0.0/24",),
                 (PortRange.single(Proto.TCP, 8080),)),
        ], default_action=Action.DENY),
        "fw_db": RuleSet("fw_db", [
            Rule("allow_pos_db", Action.ALLOW, 10,
                 ("10.5.0.0/24",), ("10.1.0.0/24",),
                 (PortRange.single(Proto.TCP, 5432),)),
        ], default_action=Action.DENY),
        "fw_clinic": RuleSet("fw_clinic", [
            # Clinic wifi is explicitly denied to the payments DB.
            Rule("deny_clinic_db", Action.DENY, 10,
                 ("10.8.0.0/24",), ("10.1.0.0/24",),
                 (PortRange.any(),)),
        ], default_action=Action.DENY),
    }
    edges = [
        Edge("guest_wifi", "fridge", rule_set_id=None,
             base_labels=frozenset({EvidenceLabel.OBSERVED})),
        Edge("fridge", "pos", rule_set_id="fw_pos",
             port=PortRange.single(Proto.TCP, 8080),
             fix_candidate_id="close_pos_8080"),
        Edge("pos", "payments_db", rule_set_id="fw_db",
             port=PortRange.single(Proto.TCP, 5432),
             fix_candidate_id="close_db_5432"),
        Edge("clinic_wifi", "payments_db", rule_set_id="fw_clinic",
             port=PortRange.any()),
    ]
    return nodes, edges, rulesets


# ---------------------------------------------------------------------------
# Part 1 + 3: backward search finds the open route; the closed pair is closed
# ---------------------------------------------------------------------------

def test_backward_search_finds_the_open_route_and_the_closed_pair():
    nodes, edges, rulesets = _demo()
    result = reachability.backward_reachability(nodes, edges, rulesets)

    assert ("guest_wifi", "payments_db") in result.open_pairs
    # Clinic wifi is denied at the firewall, so no open route to the DB.
    assert ("clinic_wifi", "payments_db") not in result.open_pairs

    routes = result.routes_for(("guest_wifi", "payments_db"))
    assert routes, "expected at least one open route"
    r = routes[0]
    assert [h.src for h in r.hops] + [r.hops[-1].dst] == [
        "guest_wifi", "fridge", "pos", "payments_db"
    ]
    # Weakest hop is the observed guest->fridge hop; the governed hops are
    # proved by config.
    assert r.weakest_label == EvidenceLabel.OBSERVED
    assert EvidenceLabel.PROVED_CONFIG in r.hops[1].labels


def test_determinism():
    nodes, edges, rulesets = _demo()
    a = reachability.backward_reachability(nodes, edges, rulesets)
    b = reachability.backward_reachability(nodes, edges, rulesets)
    assert [r.pair for r in a.routes] == [r.pair for r in b.routes]
    assert a.open_pairs == b.open_pairs


# ---------------------------------------------------------------------------
# Part 1: the minimum-cost fix set cuts every open route
# ---------------------------------------------------------------------------

def test_fix_set_cuts_the_open_route():
    nodes, edges, rulesets = _demo()
    result = reachability.backward_reachability(nodes, edges, rulesets)

    candidates = {
        "close_pos_8080": FixCandidate(
            "close_pos_8080", "rule", "network_rule",
            "Remove fridge→POS 8080 allow", cost=1.0),
        "close_db_5432": FixCandidate(
            "close_db_5432", "rule", "network_rule",
            "Remove POS→payments 5432 allow", cost=1.0),
    }
    fs = mincut.fix_set_for(result, candidates)

    assert fs.cuts_all is True
    # One rule change on the single route suffices; it must be one of the two.
    assert len(fs.selected) == 1
    assert fs.selected[0] in candidates
    assert fs.total_cost == 1.0


# ---------------------------------------------------------------------------
# Part 3: a closed boundary yields a signed, current, verifiable certificate
# ---------------------------------------------------------------------------

def test_closed_boundary_certificate_signs_verifies_and_expires():
    issued = datetime(2026, 11, 22, 12, 0, tzinfo=timezone.utc)
    cert = certificate.build_certificate(
        boundary_src="clinic_wifi",
        boundary_dst="payments_db",
        port=PortRange.single(Proto.TCP, 5432),
        config_hashes=(certificate.hash_snapshot("fw_clinic: deny 10.8/24 -> 10.1/24"),),
        assumptions=[Assumption("no_unmodelled_links",
                                "No links outside the modelled topology.")],
        corroboration=Corroboration(observed_flows=0, window_days=30,
                                     sensor_on_protected_side=True),
        issued_at=issued,
        ttl_hours=24,
    )
    key = b"test-key"
    cert = certificate.sign(cert, key)
    assert certificate.verify(cert, key) is True
    assert certificate.is_current(cert, issued + timedelta(hours=1)) is True
    assert certificate.is_current(cert, issued + timedelta(hours=48)) is False

    # Tampering after signing must fail verification.
    cert.claim = cert.claim + " (edited)"
    assert certificate.verify(cert, key) is False


# ---------------------------------------------------------------------------
# Part 3 cross-check: a flow across the closed boundary raises an alert
# ---------------------------------------------------------------------------

def test_impossible_traffic_alert_on_closed_boundary():
    boundary = impossible.ClosedBoundary(
        src_cidrs=("10.8.0.0/24",),
        dst_cidrs=("10.1.0.0/24",),
        port=PortRange.single(Proto.TCP, 5432),
        certificate_fingerprint="abc123",
        boundary_src="clinic_wifi",
        boundary_dst="payments_db",
    )
    # A completed handshake across a boundary we proved closed → alert.
    real = Flow("10.8.0.5", "10.1.0.9", Proto.TCP, 5432, handshake_completed=True)
    alert = impossible.classify_flow(real, [boundary])
    assert alert is not None
    assert alert.contradicts_certificate == "abc123"

    # A dropped SYN proves the boundary works → no alert.
    dropped = Flow("10.8.0.5", "10.1.0.9", Proto.TCP, 5432)
    assert impossible.classify_flow(dropped, [boundary]) is None


# ---------------------------------------------------------------------------
# Part 2: replica verification confirms preconditions, then a fix closes the
# hop without breaking the service — no exploit is ever run.
# ---------------------------------------------------------------------------

def test_replica_verification_and_fix_proof():
    plan = ReplicaPlan(
        component_id="pos-app",
        image_digest="sha256:deadbeef",
        scope_asset_id="asset-123",
        rebuildable=True,
        health_checks=("pos_boots", "pos_serves_catalog"),
    )
    pres = [
        Precondition(PreconditionKind.VERSION_IN_RANGE,
                     "pos-app in vulnerable range",
                     spec={"component": "pos-app", "range": "<2.1.0"}),
        Precondition(PreconditionKind.ENDPOINT_EXPOSED,
                     "admin 8080 listening",
                     spec={"proto": "tcp", "port": 8080}),
    ]
    facts_before = {
        "versions": {"pos-app": "2.0.5"},
        "listening": ["tcp/8080"],
    }
    v = replica.verify_preconditions(plan, pres, facts_before)
    assert v.preconditions_met is True
    assert v.label == EvidenceLabel.PROVED_REPLICA

    # Apply the fix on the replica: upgrade past the vulnerable range; the
    # service still boots and serves.
    facts_after = {"versions": {"pos-app": "2.1.3"}, "listening": ["tcp/8080"]}
    health = {"pos_boots": True, "pos_serves_catalog": True}
    vf = replica.verify_fix(plan, pres, facts_before, facts_after, health)
    assert vf.fix_closes_hop is True
    assert vf.fix_breaks_service is False
