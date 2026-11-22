"""The modelled environment, and changes to it.

An :class:`Environment` is the thing Wargame reasons over: the nodes
(segments, hosts, identities, crown jewels), the directed edges between
them, and the :class:`~app.engine.wargame.model.RuleSet` enforced on each
governed edge. The parsers produce rule sets; a topology — declared by the
customer or assembled from connector inventory — says which rule set gates
which edge. This module is where those meet and where the solver is run.

A :class:`ProposedChange` is a would-be edit to that environment: add or
remove a rule, swap a rule set, add or cut an edge. :func:`apply_change`
returns a *new* environment with the edit applied, leaving the original
untouched, so the change gate (``changegate``) can compare before and
after without mutating anything. Nothing here touches a real network.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Optional

from . import reachability, rules
from .model import (
    Decision,
    Edge,
    Node,
    PortRange,
    Proto,
    ReachabilityResult,
    Rule,
    RuleSet,
)


# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------

@dataclass
class Environment:
    """A model of everything Wargame searches over."""

    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    rulesets: dict[str, RuleSet] = field(default_factory=dict)

    # -- construction helpers ----------------------------------------------
    def add_node(self, node: Node) -> "Environment":
        self.nodes[node.id] = node
        return self

    def add_ruleset(self, ruleset: RuleSet) -> "Environment":
        self.rulesets[ruleset.id] = ruleset
        return self

    def add_edge(self, edge: Edge) -> "Environment":
        self.edges.append(edge)
        return self

    # -- analysis ----------------------------------------------------------
    def reachability(self, **opts) -> ReachabilityResult:
        """Run the backward search over this environment."""
        return reachability.backward_reachability(
            self.nodes, self.edges, self.rulesets, **opts
        )

    def boundary_decision(
        self, src_id: str, dst_id: str, port: Optional[PortRange] = None
    ) -> Decision:
        """Decide whether the governed edge ``src_id -> dst_id`` permits a
        flow, using the two nodes' CIDRs and the edge's rule set. An
        ungoverned or missing edge is permitted by default (no control)."""
        edge = self.find_edge(src_id, dst_id)
        if edge is None:
            return Decision(allowed=False, matched_rule=None)
        if edge.rule_set_id is None:
            return Decision(allowed=True, matched_rule=None)
        rs = self.rulesets.get(edge.rule_set_id)
        if rs is None:
            return Decision(allowed=False, matched_rule=None)
        src = self.nodes.get(src_id)
        dst = self.nodes.get(dst_id)
        return rules.boundary_permits(
            rs,
            src.cidrs if src else (),
            dst.cidrs if dst else (),
            port if port is not None else edge.port,
        )

    def find_edge(
        self, src_id: str, dst_id: str, rule_set_id: Optional[str] = None
    ) -> Optional[Edge]:
        for e in self.edges:
            if e.src == src_id and e.dst == dst_id and (
                rule_set_id is None or e.rule_set_id == rule_set_id
            ):
                return e
        return None

    def copy(self) -> "Environment":
        """A structural copy safe to mutate. Nodes are shared (immutable in
        practice); rule sets and edges are rebuilt so edits don't leak back
        to the original. Rules are frozen, so the rule lists are copied by
        reference to each (immutable) rule."""
        return Environment(
            nodes=dict(self.nodes),
            edges=[replace(e) for e in self.edges],
            rulesets={
                rid: RuleSet(
                    id=rs.id,
                    rules=list(rs.rules),
                    default_action=rs.default_action,
                    vendor=rs.vendor,
                )
                for rid, rs in self.rulesets.items()
            },
        )


# ---------------------------------------------------------------------------
# Proposed changes
# ---------------------------------------------------------------------------

class ChangeKind(str, Enum):
    ADD_RULE = "add_rule"
    REMOVE_RULE = "remove_rule"
    MODIFY_RULE = "modify_rule"
    ADD_RULESET = "add_ruleset"
    REMOVE_RULESET = "remove_ruleset"
    ADD_EDGE = "add_edge"
    REMOVE_EDGE = "remove_edge"


@dataclass
class ChangeOp:
    """One edit. Which fields matter depends on ``kind`` (validated in
    :func:`apply_change`):

    * ADD_RULE / MODIFY_RULE — ``ruleset_id`` + ``rule`` (MODIFY matches the
      existing rule by ``rule.id``).
    * REMOVE_RULE — ``ruleset_id`` + ``rule_id``.
    * ADD_RULESET / REMOVE_RULESET — ``ruleset`` / ``ruleset_id``.
    * ADD_EDGE / REMOVE_EDGE — ``edge`` (REMOVE matches by src/dst/
      rule_set_id).
    """

    kind: ChangeKind
    ruleset_id: str = ""
    rule: Optional[Rule] = None
    rule_id: str = ""
    ruleset: Optional[RuleSet] = None
    edge: Optional[Edge] = None
    description: str = ""


@dataclass
class ProposedChange:
    """A set of edits applied atomically, as one change ticket / IaC plan."""

    ops: list[ChangeOp]
    title: str = ""
    source: str = ""          # "servicenow:CHG0012345" | "terraform-plan" | ...

    def affected_ruleset_ids(self) -> set[str]:
        out: set[str] = set()
        for op in self.ops:
            if op.ruleset_id:
                out.add(op.ruleset_id)
            if op.ruleset is not None:
                out.add(op.ruleset.id)
            if op.edge is not None and op.edge.rule_set_id:
                out.add(op.edge.rule_set_id)
        return out


class ChangeError(ValueError):
    """A proposed change that cannot be applied to this environment."""


def apply_change(env: Environment, change: ProposedChange) -> Environment:
    """Return a new environment with ``change`` applied. Never mutates
    ``env``. Raises :class:`ChangeError` if an op targets something that
    isn't there (e.g. a rule on an unknown rule set), so a malformed change
    fails loudly rather than silently doing nothing."""
    new = env.copy()
    for op in change.ops:
        _apply_op(new, op)
    return new


def _apply_op(env: Environment, op: ChangeOp) -> None:
    k = op.kind
    if k == ChangeKind.ADD_RULESET:
        if op.ruleset is None:
            raise ChangeError("add_ruleset requires a ruleset")
        env.rulesets[op.ruleset.id] = RuleSet(
            id=op.ruleset.id,
            rules=list(op.ruleset.rules),
            default_action=op.ruleset.default_action,
            vendor=op.ruleset.vendor,
        )
        return
    if k == ChangeKind.REMOVE_RULESET:
        if op.ruleset_id not in env.rulesets:
            raise ChangeError(f"remove_ruleset: unknown rule set {op.ruleset_id!r}")
        del env.rulesets[op.ruleset_id]
        return
    if k == ChangeKind.ADD_EDGE:
        if op.edge is None:
            raise ChangeError("add_edge requires an edge")
        env.edges.append(replace(op.edge))
        return
    if k == ChangeKind.REMOVE_EDGE:
        if op.edge is None:
            raise ChangeError("remove_edge requires an edge")
        before = len(env.edges)
        env.edges = [
            e for e in env.edges
            if not (e.src == op.edge.src and e.dst == op.edge.dst
                    and e.rule_set_id == op.edge.rule_set_id)
        ]
        if len(env.edges) == before:
            raise ChangeError(
                f"remove_edge: no edge {op.edge.src}->{op.edge.dst} "
                f"(rule set {op.edge.rule_set_id!r})"
            )
        return

    # rule-level ops need an existing rule set
    rs = env.rulesets.get(op.ruleset_id)
    if rs is None:
        raise ChangeError(f"{k.value}: unknown rule set {op.ruleset_id!r}")

    if k == ChangeKind.ADD_RULE:
        if op.rule is None:
            raise ChangeError("add_rule requires a rule")
        rs.rules.append(op.rule)
        rs.rules.sort(key=lambda r: (r.order, r.id))
        return
    if k == ChangeKind.REMOVE_RULE:
        target = op.rule_id or (op.rule.id if op.rule else "")
        kept = [r for r in rs.rules if r.id != target]
        if len(kept) == len(rs.rules):
            raise ChangeError(
                f"remove_rule: no rule {target!r} in {op.ruleset_id!r}"
            )
        rs.rules = kept
        return
    if k == ChangeKind.MODIFY_RULE:
        if op.rule is None:
            raise ChangeError("modify_rule requires the replacement rule")
        target = op.rule_id or op.rule.id
        idx = next((i for i, r in enumerate(rs.rules) if r.id == target), None)
        if idx is None:
            raise ChangeError(
                f"modify_rule: no rule {target!r} in {op.ruleset_id!r}"
            )
        rs.rules[idx] = op.rule
        rs.rules.sort(key=lambda r: (r.order, r.id))
        return
    raise ChangeError(f"unknown change kind {k!r}")


# ---------------------------------------------------------------------------
# convenience builders for a change ticket / IaC diff
# ---------------------------------------------------------------------------

def open_rule(
    ruleset_id: str, rule: Rule, *, description: str = ""
) -> ChangeOp:
    """A change that adds an allow (or any) rule to a rule set."""
    return ChangeOp(ChangeKind.ADD_RULE, ruleset_id=ruleset_id, rule=rule,
                    description=description)


def remove_rule(ruleset_id: str, rule_id: str, *, description: str = "") -> ChangeOp:
    return ChangeOp(ChangeKind.REMOVE_RULE, ruleset_id=ruleset_id,
                    rule_id=rule_id, description=description)
