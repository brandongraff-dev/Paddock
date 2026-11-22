"""Tests for the impossible-traffic detector."""
from __future__ import annotations

import copy

import pytest

from app.engine.wargame.impossible import (
    SUPPRESSED_KINDS,
    ClosedBoundary,
    classify_flow,
    flow_crosses,
    flow_is_real,
    resolve,
)
from app.engine.wargame.model import Flow, ImpossibleResolution, PortRange, Proto


def boundary(fp="fp-b", port=PortRange.single(Proto.TCP, 5432), **kw):
    base = dict(
        src_cidrs=("10.1.0.0/16",), dst_cidrs=("10.9.0.0/24",), port=port,
        certificate_fingerprint=fp, boundary_src="guest", boundary_dst="db",
    )
    base.update(kw)
    return ClosedBoundary(**base)


def flow(**kw):
    base = dict(src_ip="10.1.2.3", dst_ip="10.9.0.5", proto=Proto.TCP, dst_port=5432)
    base.update(kw)
    return Flow(**base)


def test_suppressed_kinds_contents():
    assert SUPPRESSED_KINDS == frozenset(
        {"arp", "mdns", "dhcp", "lb_health", "vpn_encap", "nat", "mgmt", "icmp"})


def test_dropped_syn_is_not_real_and_no_alert():
    f = flow()
    assert flow_is_real(f) is False
    assert classify_flow(f, [boundary()]) is None


@pytest.mark.parametrize("field", ["handshake_completed", "dst_side_observed", "firewall_allow_logged"])
def test_each_evidence_makes_flow_real(field):
    f = flow(**{field: True})
    assert flow_is_real(f) is True
    alert = classify_flow(f, [boundary()])
    assert alert is not None
    assert alert.severity == "critical"
    assert alert.contradicts_certificate == "fp-b"
    assert (alert.boundary_src, alert.boundary_dst) == ("guest", "db")
    assert alert.flow is f
    for word in ("missing", "rule", "bypass"):
        assert word in alert.note


@pytest.mark.parametrize("kind", sorted(SUPPRESSED_KINDS))
def test_suppressed_kinds(kind):
    f = flow(handshake_completed=True, kind=kind)
    assert flow_is_real(f) is False
    assert classify_flow(f, [boundary()]) is None


def test_broadcast_suppressed():
    f = flow(handshake_completed=True, is_broadcast=True)
    assert flow_is_real(f) is False
    assert classify_flow(f, [boundary()]) is None


def test_non_crossing_real_flow_returns_none():
    assert classify_flow(flow(src_ip="192.168.0.1", handshake_completed=True), [boundary()]) is None
    assert classify_flow(flow(dst_ip="8.8.8.8", handshake_completed=True), [boundary()]) is None
    assert classify_flow(flow(dst_port=443, handshake_completed=True), [boundary()]) is None
    assert classify_flow(flow(proto=Proto.UDP, handshake_completed=True), [boundary()]) is None
    assert classify_flow(flow(handshake_completed=True), []) is None


def test_port_none_matches_any_port():
    b = boundary(port=None)
    assert flow_crosses(flow(dst_port=1), b)
    assert flow_crosses(flow(proto=Proto.UDP, dst_port=9999), b)


def test_multiple_boundaries_pick_smallest_fingerprint():
    f = flow(handshake_completed=True)
    bs = [boundary(fp="zzz"), boundary(fp="aaa", boundary_src="x"), boundary(fp="mmm")]
    a1 = classify_flow(f, bs)
    a2 = classify_flow(f, list(reversed(bs)))
    assert a1.contradicts_certificate == a2.contradicts_certificate == "aaa"
    assert a1.boundary_src == "x"


def test_inputs_unchanged_by_classify_and_resolve():
    bs = [boundary(fp="b"), boundary(fp="a")]
    snapshot = copy.deepcopy(bs)
    f = flow(handshake_completed=True)
    fsnap = copy.deepcopy(f)
    alert = classify_flow(f, bs)
    asnap = copy.deepcopy(alert)
    rec = resolve(alert, ImpossibleResolution.ESCALATED_INCIDENT, "  tunnel found  ", "alice")
    assert bs == snapshot and f == fsnap and alert == asnap
    assert rec == {
        "alert": alert,
        "resolution": ImpossibleResolution.ESCALATED_INCIDENT,
        "reason": "tunnel found",
        "resolved_by": "alice",
    }


@pytest.mark.parametrize("reason,by", [("", "a"), ("   ", "a"), ("why", ""), ("why", "  ")])
def test_resolve_requires_reason_and_by(reason, by):
    alert = classify_flow(flow(handshake_completed=True), [boundary()])
    with pytest.raises(ValueError):
        resolve(alert, ImpossibleResolution.RULE_DEFECT_CONFIRMED, reason, by)


def test_unparsable_boundary_cidr_fails_loud():
    # A boundary CIDR that does not parse used to match nothing, so real
    # traffic could cross a "closed" boundary silently. It now covers any
    # address on that side (a human resolves every alert).
    b = boundary(src_cidrs=("guest-zone-object",))
    assert flow_crosses(flow(src_ip="192.168.7.7"), b)
    assert classify_flow(flow(src_ip="192.168.7.7", handshake_completed=True), [b]) is not None
    # The parsable side and the port still have to match.
    assert not flow_crosses(flow(src_ip="192.168.7.7", dst_ip="8.8.8.8"), b)
    assert not flow_crosses(flow(src_ip="192.168.7.7", dst_port=443), b)


def test_ipv4_mapped_ipv6_flow_address_still_crosses():
    f = flow(src_ip="::ffff:10.1.2.3", dst_ip="::ffff:10.9.0.5", handshake_completed=True)
    assert flow_crosses(f, boundary())
    assert classify_flow(f, [boundary()]) is not None
    assert not flow_crosses(flow(src_ip="::ffff:192.168.0.1"), boundary())


def test_exact_per_address_not_representative_host():
    # A flow from the last host of the source block crosses, too.
    assert flow_crosses(flow(src_ip="10.1.255.254"), boundary())
    assert flow_crosses(flow(dst_ip="10.9.0.255"), boundary())


@pytest.mark.parametrize("bad", ["false_positive", "explained", "", None, 3])
def test_resolve_refuses_a_resolution_outside_the_taxonomy(bad):
    alert = classify_flow(flow(handshake_completed=True), [boundary()])
    with pytest.raises(ValueError):
        resolve(alert, bad, "looked fine", "alice")


def test_resolve_accepts_the_enum_value_string_and_record_is_read_only():
    alert = classify_flow(flow(handshake_completed=True), [boundary()])
    rec = resolve(alert, "escalated_incident", "tunnel found", "alice")
    assert rec["resolution"] is ImpossibleResolution.ESCALATED_INCIDENT
    with pytest.raises(TypeError):
        rec["reason"] = "rewritten"  # type: ignore[index]
