"""Build a Wargame :class:`Environment` from the legacy asset graph.

This adapter bridges the correlation service's existing asset graph (the
dict :meth:`AttackPathEngine._load_graph` returns) into the rule-aware
Wargame twin, so a Wargame assessment can run today over inventory the
platform already has — before any firewall-rule parser is wired in.

HONEST LABELLING. The legacy asset graph carries **no** firewall / security
group / NACL rules: it is a structural adjacency inferred from inventory and
scan data, not config proof. So every edge this adapter produces is an
*ungoverned* adjacency (``rule_set_id=None``) carrying exactly one evidence
label, :attr:`EvidenceLabel.INFERRED`, and the environment has **no** rule
sets at all. Every route found over such a model is therefore limited to the
``inferred`` strength — the adapter never fabricates ``PROVED_CONFIG`` or any
stronger label. Routes stay honestly labelled "inferred" until rule-aware
parsers feed the twin real boundary rules.

Pure and deterministic: no database, no I/O. The same graph always yields an
equal :class:`Environment` (nodes keyed by sorted id, edges in a fixed order).

DEFENSIVE: pure model reasoning over inventory. Nothing here executes,
emits, or represents an exploit, payload, or command.
"""
from __future__ import annotations

from typing import Any

from ..attackpath import classify_source, classify_target
from .environment import Environment
from .model import Edge, EvidenceLabel, Node, NodeRole


# Asset kinds whose value is a single host address; modelled as a host CIDR so
# address-referencing rules could evaluate against the node (there are none in
# the all-inferred model, but the node is correctly addressed for when there
# are).
_ADDRESS_KINDS: dict[str, int] = {"ipv4": 32, "ipv6": 128}


def _node_cidrs(asset: dict[str, Any]) -> tuple[str, ...]:
    """A host CIDR for an ipv4/ipv6 asset (``/32`` or ``/128``); else none."""
    prefix = _ADDRESS_KINDS.get(asset.get("kind"))
    if prefix is None:
        return ()
    value = (asset.get("value") or "").strip()
    if not value:
        return ()
    return (f"{value}/{prefix}",)


def environment_from_graph(graph: dict[str, Any]) -> Environment:
    """Assemble a Wargame :class:`Environment` from a legacy asset graph.

    ``graph`` is exactly what :meth:`AttackPathEngine._load_graph` returns:
    ``{assets, adj, edge_kind, findings_by_asset, public_nets}``.

    Node roles reuse the attack-path classifiers so Wargame picks the same
    entries and crown jewels the attack-path engine would:

    * ``CROWN_JEWEL`` when :func:`classify_target` says so;
    * else ``ENTRY`` when :func:`classify_source` says so;
    * else ``INTERMEDIATE``.

    NOTE on port parentage: :func:`classify_source` can promote a ``port``
    asset to a source only when it can see the parent IP and that IP sits in a
    public scope CIDR. The legacy graph does not reconstruct port→IP parentage
    here, so we pass ``parent_ip=None``. A ``port`` asset therefore simply may
    not classify as a source in this adapter — acceptable for v1; the richer
    classification stays in the attack-path engine, which walks the parentage.

    Every edge is an ungoverned, ``INFERRED`` adjacency (see module docstring).
    """
    assets: dict[str, dict[str, Any]] = graph["assets"]
    adj: dict[str, list[str]] = graph["adj"]
    public_nets: tuple[Any, ...] = graph.get("public_nets", ())

    # -- nodes (deterministic: keyed by sorted asset id) -------------------
    nodes: dict[str, Node] = {}
    for aid in sorted(assets):
        asset = assets[aid]
        is_target, target_reason = classify_target(asset)
        # parent_ip=None: port parentage is not reconstructed here (see above).
        is_source, source_reason = classify_source(
            asset, parent_ip=None, public_nets=public_nets
        )

        if is_target:
            role = NodeRole.CROWN_JEWEL
            reason = target_reason or ""
        elif is_source:
            role = NodeRole.ENTRY
            reason = source_reason or ""
        else:
            role = NodeRole.INTERMEDIATE
            reason = ""

        nodes[aid] = Node(
            id=aid,
            role=role,
            cidrs=_node_cidrs(asset),
            reason=reason,
            jewel_kind=(target_reason or "") if is_target else "",
        )

    # -- edges: each undirected adjacency becomes two directed INFERRED edges
    # Collect each unordered pair once, deterministically, then emit a->b and
    # b->a sharing one fix candidate id (cutting the link cuts both ways).
    pairs: set[tuple[str, str]] = set()
    for src in adj:
        if src not in nodes:
            continue
        for dst in adj[src]:
            if dst not in nodes or dst == src:
                continue
            lo, hi = (src, dst) if src < dst else (dst, src)
            pairs.add((lo, hi))

    edges: list[Edge] = []
    for lo, hi in sorted(pairs):
        fix_id = f"edge:{lo}->{hi}"
        for a, b in ((lo, hi), (hi, lo)):
            edges.append(
                Edge(
                    src=a,
                    dst=b,
                    rule_set_id=None,
                    base_labels=frozenset({EvidenceLabel.INFERRED}),
                    fix_candidate_id=fix_id,
                )
            )

    # No rule sets: the legacy graph carries no boundary rules, so the twin is
    # all-inferred until rule-aware parsers supply them.
    return Environment(nodes=nodes, edges=edges, rulesets={})
