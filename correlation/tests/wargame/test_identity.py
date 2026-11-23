"""Tests for identity/credential path modelling."""
from __future__ import annotations

import pytest

from app.engine.wargame.identity import (
    IdentityPrincipal,
    PrincipalKind,
    _assert_identity_label,
    assumption_edge,
    build_identity_layer,
    iam_assume_edges,
    principal_node,
    shared_credential_edges,
)
from app.engine.wargame.model import Edge, EvidenceLabel, Node, NodeRole

FORBIDDEN = {
    EvidenceLabel.TESTED_PROBE,
    EvidenceLabel.OBSERVED,
    EvidenceLabel.PROVED_CONFIG,
    EvidenceLabel.PROVED_LIVE_SAFE_CHECK,
    EvidenceLabel.PROVED_REPLICA,
    EvidenceLabel.IMPORTED,
}


@pytest.mark.parametrize("kind,role", [
    (PrincipalKind.VENDOR_VPN, NodeRole.ENTRY),
    (PrincipalKind.REMOTE_SUPPORT, NodeRole.ENTRY),
    (PrincipalKind.THIRD_PARTY, NodeRole.ENTRY),
    (PrincipalKind.SHARED_ADMIN, NodeRole.ENTRY),
    (PrincipalKind.IAM_ROLE, NodeRole.INTERMEDIATE),
    (PrincipalKind.SERVICE_ACCOUNT, NodeRole.INTERMEDIATE),
])
def test_principal_node_roles(kind, role):
    n = principal_node(IdentityPrincipal("p", kind, reason="why"))
    assert isinstance(n, Node)
    assert n.role is role
    assert n.cidrs == ()
    assert n.reason == "why"
    assert n.metadata["principal_kind"] == kind.value
    assert n.metadata["detected_only"] is True


def test_shared_admin_always_detected_only():
    p = IdentityPrincipal("adm", PrincipalKind.SHARED_ADMIN, detected_only=False)
    assert p.detected_only is True
    assert principal_node(p).metadata["detected_only"] is True


def test_assumption_edge_detected_only_is_inferred():
    e = assumption_edge("adm", "db")
    assert e.base_labels == frozenset({EvidenceLabel.INFERRED})
    assert e.rule_set_id is None
    assert e.metadata == {"hop": "identity", "via": ""}


def test_assumption_edge_declared_is_conditional():
    e = assumption_edge("r", "s3", detected_only=False, via="x")
    assert e.base_labels == frozenset({EvidenceLabel.CONDITIONAL})
    assert e.metadata["via"] == "x"


def test_iam_assume_edges_conditional():
    edges = iam_assume_edges({"role-b": ["s3", "kms"], "role-a": ["db"]})
    assert [(e.src, e.dst) for e in edges] == [
        ("role-a", "db"), ("role-b", "kms"), ("role-b", "s3")]
    assert all(e.base_labels == frozenset({EvidenceLabel.CONDITIONAL}) for e in edges)


def test_shared_credential_edges_fan_out_inferred():
    edges = shared_credential_edges("adm", ["web", "db", "app"])
    assert sorted(e.dst for e in edges) == ["app", "db", "web"]
    assert all(e.src == "adm" for e in edges)
    assert all(e.base_labels == frozenset({EvidenceLabel.INFERRED}) for e in edges)


def test_fix_candidate_id_present():
    for e in shared_credential_edges("adm", ["db"]) + iam_assume_edges({"r": ["x"]}):
        assert e.fix_candidate_id == f"identity:{e.src}->{e.dst}"


def _layer():
    principals = [
        IdentityPrincipal("vpn", PrincipalKind.VENDOR_VPN),
        IdentityPrincipal("adm", PrincipalKind.SHARED_ADMIN),
        IdentityPrincipal("role", PrincipalKind.IAM_ROLE),
    ]
    return build_identity_layer(
        principals,
        assume_map={"role": ["s3", "db"]},
        shared_cred_map={"adm": ["web", "db"], "vpn": ["db"]},
    )


def test_build_identity_layer_deterministic_and_shaped():
    nodes, edges = _layer()
    nodes2, edges2 = _layer()
    assert [n.id for n in nodes] == ["adm", "role", "vpn"]
    assert [(e.src, e.dst) for e in edges] == sorted((e.src, e.dst) for e in edges)
    assert [(e.src, e.dst, e.base_labels) for e in edges] == \
        [(e.src, e.dst, e.base_labels) for e in edges2]
    assert [n.id for n in nodes] == [n.id for n in nodes2]
    assert all(isinstance(n, Node) for n in nodes)
    assert all(isinstance(e, Edge) for e in edges)
    assert len(edges) == 5


def test_build_identity_layer_empty():
    assert build_identity_layer([]) == ([], [])


def test_duplicate_edges_merge_to_weakest_still_allowed():
    _, edges = build_identity_layer(
        [], assume_map={"x": ["y"]}, shared_cred_map={"x": ["y"]})
    assert len(edges) == 1
    assert edges[0].base_labels == frozenset(
        {EvidenceLabel.INFERRED, EvidenceLabel.CONDITIONAL})


@pytest.mark.parametrize("edge", _layer()[1], ids=lambda e: f"{e.src}->{e.dst}")
def test_hard_invariant_no_tested_or_proved_labels(edge):
    assert edge.base_labels
    assert edge.base_labels <= {EvidenceLabel.INFERRED, EvidenceLabel.CONDITIONAL}
    assert not (edge.base_labels & FORBIDDEN)
    _assert_identity_label(edge)


@pytest.mark.parametrize("label", sorted(FORBIDDEN, key=lambda lb: lb.value))
def test_assert_helper_rejects_forbidden(label):
    bad = Edge("a", "b", base_labels=frozenset({EvidenceLabel.INFERRED, label}))
    with pytest.raises(AssertionError):
        _assert_identity_label(bad)


def test_assert_helper_rejects_empty():
    with pytest.raises(AssertionError):
        _assert_identity_label(Edge("a", "b"))
