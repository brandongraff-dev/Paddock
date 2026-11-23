"""Wargame: Paddock's defensive attacker.

Works backward from the crown jewels over a model of the owner's
environment, labels every hop with the evidence behind it, computes the
cheapest set of changes that cuts every route, and certifies routes it
proves closed. It never executes an exploit — against production or
against its own replicas. See ``docs/WARGAME.md``.

Public surface is re-exported here so callers do ``from app.engine.wargame
import ...`` without reaching into submodules.
"""
from __future__ import annotations

from .model import (
    Action,
    Assumption,
    Certificate,
    Corroboration,
    Decision,
    Edge,
    EvidenceLabel,
    FixCandidate,
    FixSet,
    Flow,
    Hop,
    ImpossibleTrafficAlert,
    LABEL_STRENGTH,
    Node,
    NodeRole,
    PortRange,
    Precondition,
    PreconditionKind,
    Proto,
    ReachabilityResult,
    ReplicaPlan,
    ReplicaVerdict,
    Route,
    Rule,
    RuleSet,
    strongest_label,
    weakest_label,
)
from .environment import (
    ChangeError,
    ChangeKind,
    ChangeOp,
    Environment,
    ProposedChange,
    apply_change,
)
from .safety import (
    UnsafeWargameAction,
    assert_precondition_allowed,
    assert_preconditions_allowed,
    assert_safe_text,
    safe_text,
)

__all__ = [
    "Action",
    "Assumption",
    "Certificate",
    "ChangeError",
    "ChangeKind",
    "ChangeOp",
    "Corroboration",
    "Decision",
    "Edge",
    "Environment",
    "ProposedChange",
    "apply_change",
    "EvidenceLabel",
    "FixCandidate",
    "FixSet",
    "Flow",
    "Hop",
    "ImpossibleTrafficAlert",
    "LABEL_STRENGTH",
    "Node",
    "NodeRole",
    "PortRange",
    "Precondition",
    "PreconditionKind",
    "Proto",
    "ReachabilityResult",
    "ReplicaPlan",
    "ReplicaVerdict",
    "Route",
    "Rule",
    "RuleSet",
    "UnsafeWargameAction",
    "assert_precondition_allowed",
    "assert_preconditions_allowed",
    "assert_safe_text",
    "safe_text",
    "strongest_label",
    "weakest_label",
]
