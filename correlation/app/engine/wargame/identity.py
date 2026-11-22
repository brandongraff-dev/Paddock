"""Identity / credential path modelling for the Wargame engine.

Models identities and third parties as graph nodes and the "can assume /
can use" relationships between them as edges, ready to pass to
``build_topology`` as ``extra_nodes`` / ``extra_edges``.

DEFENSIVE INVARIANT. Credentials are NEVER tested or submitted. A shared
credential is only ever *detected by fingerprint* (mirroring SECURITY.md:
default-credential risk is detected by fingerprinting, never by submitting
passwords), so a credential hop is **inferred**, never tested or proved.
Identity edges therefore carry only ``INFERRED`` (detected, unverified) or
``CONDITIONAL`` (config-declared, but use depends on runtime identity
state). They never carry TESTED_PROBE, OBSERVED, PROVED_*, or IMPORTED;
``_assert_identity_label`` enforces this on every edge built here.

Pure, deterministic, stdlib only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from .model import Edge, EvidenceLabel, Node, NodeRole


class PrincipalKind(str, Enum):
    VENDOR_VPN = "vendor_vpn"
    REMOTE_SUPPORT = "remote_support"
    SHARED_ADMIN = "shared_admin"
    IAM_ROLE = "iam_role"
    SERVICE_ACCOUNT = "service_account"
    THIRD_PARTY = "third_party"


_ENTRY_KINDS = frozenset({
    PrincipalKind.VENDOR_VPN,
    PrincipalKind.REMOTE_SUPPORT,
    PrincipalKind.THIRD_PARTY,
    PrincipalKind.SHARED_ADMIN,
})

#: The only labels a credential/identity edge may carry.
_ALLOWED_IDENTITY_LABELS = frozenset({EvidenceLabel.INFERRED, EvidenceLabel.CONDITIONAL})


@dataclass
class IdentityPrincipal:
    """An identity or third party that can act as a path source.

    ``detected_only`` means we only fingerprinted it and never verified we
    can use it. Always true for SHARED_ADMIN.
    """

    id: str
    kind: PrincipalKind
    reason: str = ""
    detected_only: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.kind is PrincipalKind.SHARED_ADMIN:
            self.detected_only = True


def _assert_identity_label(edge: Edge) -> None:
    """Hard invariant: identity edges are INFERRED/CONDITIONAL only."""
    labels = frozenset(edge.base_labels)
    if not labels or not labels <= _ALLOWED_IDENTITY_LABELS:
        raise AssertionError(
            f"identity edge {edge.src}->{edge.dst} has forbidden labels "
            f"{sorted(lb.value for lb in labels)}; only INFERRED/CONDITIONAL allowed"
        )


def principal_node(p: IdentityPrincipal) -> Node:
    """Graph node for a principal (ENTRY if externally originating)."""
    role = NodeRole.ENTRY if p.kind in _ENTRY_KINDS else NodeRole.INTERMEDIATE
    return Node(
        id=p.id,
        role=role,
        cidrs=(),
        reason=p.reason,
        metadata={
            **p.metadata,
            "principal_kind": p.kind.value,
            "detected_only": p.detected_only,
        },
    )


def assumption_edge(src_id: str, dst_id: str, *, detected_only: bool = True,
                    via: str = "") -> Edge:
    """An identity hop. INFERRED when only detected; else CONDITIONAL."""
    label = EvidenceLabel.INFERRED if detected_only else EvidenceLabel.CONDITIONAL
    edge = Edge(
        src=src_id,
        dst=dst_id,
        rule_set_id=None,
        base_labels=frozenset({label}),
        fix_candidate_id=f"identity:{src_id}->{dst_id}",
        metadata={"hop": "identity", "via": via},
    )
    _assert_identity_label(edge)
    return edge


def shared_credential_edges(principal_id: str, reachable_node_ids: list[str]) -> list[Edge]:
    """A detected shared admin credential grants reach to each listed node.

    The credential is only fingerprinted; it is never submitted or tested,
    so every edge is INFERRED.
    """
    return [
        assumption_edge(principal_id, dst, detected_only=True, via="shared_credential")
        for dst in sorted(set(reachable_node_ids))
    ]


def iam_assume_edges(assume_map: dict[str, list[str]]) -> list[Edge]:
    """Role -> resource edges from a config-declared grant (CONDITIONAL:
    use still depends on who holds the role)."""
    edges: list[Edge] = []
    for role in sorted(assume_map):
        for dst in sorted(set(assume_map[role])):
            edges.append(assumption_edge(role, dst, detected_only=False, via="iam_assume"))
    return edges


def build_identity_layer(
    principals: list[IdentityPrincipal],
    assume_map: Optional[dict[str, list[str]]] = None,
    shared_cred_map: Optional[dict[str, list[str]]] = None,
) -> tuple[list[Node], list[Edge]]:
    """Nodes + edges for ``build_topology(extra_nodes=, extra_edges=)``.

    Output is sorted (nodes by id, edges by (src, dst)). Duplicate
    (src, dst) edges are merged, keeping the union of labels and fix id.
    """
    nodes = [principal_node(p) for p in sorted(principals, key=lambda p: p.id)]

    raw: list[Edge] = list(iam_assume_edges(assume_map or {}))
    for pid in sorted(shared_cred_map or {}):
        raw.extend(shared_credential_edges(pid, shared_cred_map[pid]))

    merged: dict[tuple[str, str], Edge] = {}
    for e in raw:
        key = (e.src, e.dst)
        if key in merged:
            prev = merged[key]
            prev.base_labels = frozenset(prev.base_labels | e.base_labels)
        else:
            merged[key] = e
    edges = [merged[k] for k in sorted(merged)]
    for e in edges:
        _assert_identity_label(e)
    return nodes, edges
