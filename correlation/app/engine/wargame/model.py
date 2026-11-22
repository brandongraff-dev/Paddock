"""Shared data model for the Wargame engine.

Wargame is Paddock's defensive attacker: it works *backward* from the
crown jewels over a model of the owner's environment, labels every hop
with the evidence behind it, computes the cheapest set of changes that
cuts every route, and certifies the routes it proves closed. See
``docs/WARGAME.md``.

This module is **pure data** — dataclasses and enums only, no I/O and no
algorithms. The three logic modules build on it:

* ``rules`` + ``reachability`` — the rule-aware "solver" and the backward
  search that produces :class:`Route` objects.
* ``mincut`` — the minimum-cost fix set over routes.
* ``certificate`` — a signed, expiring proof that a boundary is closed.
* ``replica`` — precondition verification on rebuilt copies (never an
  exploit).
* ``impossible`` — the "a flow crossed a boundary we proved closed"
  detector.

Keeping every shared type here lets those modules be built and tested
independently without colliding on definitions.

DEFENSIVE INVARIANT. Nothing in this package executes, emits, or
represents an exploit, payload, or command. Routes carry impact and
evidence only. The :mod:`.safety` guard enforces this on any free text
that flows into a narrative, reusing the correlation reject filter.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Evidence ladder
# ---------------------------------------------------------------------------

class EvidenceLabel(str, Enum):
    """Why we believe a hop (or a boundary verdict) is what we say it is.

    A hop may carry *several* labels at once (it can be Observed *and*
    Proved-config). Strength ordering lives in :data:`LABEL_STRENGTH`; a
    route is only as strong as its weakest hop.
    """

    #: The rule solver shows the config permits this hop. No packets sent.
    PROVED_CONFIG = "proved_config"
    #: A safe-check TCP connect crossed the boundary in operation.
    TESTED_PROBE = "tested_probe"
    #: Traffic was seen on this hop (completed handshake / dst-side view).
    OBSERVED = "observed"
    #: Exploit *preconditions* confirmed on the in-scope asset (Assessor).
    PROVED_LIVE_SAFE_CHECK = "proved_live_safe_check"
    #: Preconditions confirmed on a rebuilt copy. Never an exploit run.
    PROVED_REPLICA = "proved_replica"
    #: A third party demonstrated exploitation; recorded, never run here.
    IMPORTED = "imported"
    #: Permitted only subject to runtime state the config can't prove
    #: (App-ID, FQDN objects, dynamic groups, service mesh, ...).
    CONDITIONAL = "conditional"
    #: The graph suggests this hop; nothing has proved it.
    INFERRED = "inferred"
    #: Outside the model; the sensors/config don't cover it.
    UNKNOWN = "unknown"


# Higher = stronger evidence that a hop is *real and usable*. A route's
# strength is the minimum over its hops. CONDITIONAL / INFERRED / UNKNOWN
# are explicitly weak so they never let a route read as "closed-proof".
LABEL_STRENGTH: dict[EvidenceLabel, int] = {
    EvidenceLabel.UNKNOWN: 0,
    EvidenceLabel.INFERRED: 1,
    EvidenceLabel.CONDITIONAL: 2,
    EvidenceLabel.PROVED_CONFIG: 3,
    EvidenceLabel.TESTED_PROBE: 4,
    EvidenceLabel.OBSERVED: 5,
    EvidenceLabel.PROVED_LIVE_SAFE_CHECK: 6,
    EvidenceLabel.PROVED_REPLICA: 7,
    EvidenceLabel.IMPORTED: 8,
}


def weakest_label(labels: "set[EvidenceLabel] | frozenset[EvidenceLabel]") -> EvidenceLabel:
    """The least-strong label in a set (what the hop/route is limited by).

    Empty set → :attr:`EvidenceLabel.UNKNOWN`.
    """
    if not labels:
        return EvidenceLabel.UNKNOWN
    return min(labels, key=lambda lb: LABEL_STRENGTH[lb])


def strongest_label(labels: "set[EvidenceLabel] | frozenset[EvidenceLabel]") -> EvidenceLabel:
    """The most-strong label in a set."""
    if not labels:
        return EvidenceLabel.UNKNOWN
    return max(labels, key=lambda lb: LABEL_STRENGTH[lb])


# ---------------------------------------------------------------------------
# Rule model (the solver's input) — vendor-neutral
# ---------------------------------------------------------------------------

class Action(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class Proto(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ANY = "any"

    def matches(self, other: "Proto") -> bool:
        return self is Proto.ANY or other is Proto.ANY or self is other


@dataclass(frozen=True)
class PortRange:
    """An inclusive L4 port range for a protocol. ``proto=ANY`` or the
    full 0-65535 range model "any port"."""

    proto: Proto = Proto.ANY
    low: int = 0
    high: int = 65535

    def __post_init__(self) -> None:
        if not (0 <= self.low <= self.high <= 65535):
            raise ValueError(f"bad port range {self.low}-{self.high}")

    def contains(self, proto: Proto, port: int) -> bool:
        return self.proto.matches(proto) and self.low <= port <= self.high

    @classmethod
    def single(cls, proto: Proto, port: int) -> "PortRange":
        return cls(proto, port, port)

    @classmethod
    def any(cls) -> "PortRange":
        return cls(Proto.ANY, 0, 65535)


@dataclass(frozen=True)
class Rule:
    """One vendor-neutral firewall / security-group / NACL rule.

    ``order`` is the evaluation position; lower is evaluated first and,
    under first-match semantics, wins. ``conditional`` marks a rule whose
    real effect depends on runtime state the config can't prove (App-ID,
    FQDN objects, dynamic address groups, EDLs, SD-WAN, NetworkPolicy,
    mesh); such a rule can never contribute a *closed* proof — only a
    CONDITIONAL label.
    """

    id: str
    action: Action
    order: int
    src_cidrs: tuple[str, ...]
    dst_cidrs: tuple[str, ...]
    ports: tuple[PortRange, ...] = (PortRange.any(),)
    vendor: str = ""
    conditional: bool = False
    #: A reference back to the source config line/object, for certificates.
    raw_ref: str = ""
    #: Which fix-cost class this rule falls into if a fix touches it.
    cost_class: str = "network_rule"

    def matches(self, src_ip: str, dst_ip: str, proto: Proto, port: int) -> bool:
        if not any(_ip_in_cidr(src_ip, c) for c in self.src_cidrs):
            return False
        if not any(_ip_in_cidr(dst_ip, c) for c in self.dst_cidrs):
            return False
        return any(pr.contains(proto, port) for pr in self.ports)


@dataclass(frozen=True)
class Decision:
    """The result of evaluating a :class:`RuleSet` for one flow."""

    allowed: bool
    #: The rule id that decided it (``None`` → fell through to default).
    matched_rule: Optional[str] = None
    #: True when the deciding rule's effect depends on unprovable runtime
    #: state, so the verdict should be labelled CONDITIONAL, not proved.
    conditional: bool = False


@dataclass
class RuleSet:
    """The rules enforced at one boundary (a firewall, SG set, NACL).

    Evaluation is first-match over ``rules`` sorted by ``order``; if no
    rule matches, ``default_action`` applies. The evaluator lives in
    :mod:`.rules`.
    """

    id: str
    rules: list[Rule]
    default_action: Action = Action.DENY
    vendor: str = ""


# ---------------------------------------------------------------------------
# Topology (the solver + backward-search input)
# ---------------------------------------------------------------------------

class NodeRole(str, Enum):
    ENTRY = "entry"          # internet, guest/IoT segment, vendor VPN, ...
    CROWN_JEWEL = "crown_jewel"
    INTERMEDIATE = "intermediate"


@dataclass
class Node:
    """A segment, host, identity, or third party in the reachability graph.

    ``cidrs`` is used to evaluate rules that reference this node by
    address. Identity/third-party nodes may carry none.
    """

    id: str
    role: NodeRole = NodeRole.INTERMEDIATE
    cidrs: tuple[str, ...] = ()
    #: Why this node is an entry or a jewel (free text, for the report).
    reason: str = ""
    #: Set on crown jewels: the asset the jewel protects (for pricing /
    #: closure counting). Free text.
    jewel_kind: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Edge:
    """A directed adjacency from ``src`` to ``dst``, optionally gated by a
    boundary :class:`RuleSet`.

    ``rule_set_id`` ``None`` means an *ungoverned* adjacency (same segment,
    an identity that can assume a role, an observed flow with no modelled
    control) — those edges are permitted by default and labelled by how we
    learned of them (``base_labels``).
    """

    src: str
    dst: str
    rule_set_id: Optional[str] = None
    #: Port class this edge concerns, for rule evaluation and reporting.
    port: Optional[PortRange] = None
    #: Evidence we already hold for the edge independent of the solver
    #: (e.g. OBSERVED from Sentry/flows, IMPORTED from a pentest).
    base_labels: frozenset[EvidenceLabel] = frozenset()
    #: If cutting this edge is a candidate fix, the candidate id.
    fix_candidate_id: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Routes (the backward search's output)
# ---------------------------------------------------------------------------

@dataclass
class Hop:
    """One step of a route, from ``src`` to ``dst``, with its evidence."""

    src: str
    dst: str
    labels: frozenset[EvidenceLabel]
    port: Optional[PortRange] = None
    rule_ref: str = ""
    #: Candidate fixes that would remove this hop (rule ids / edge ids).
    fix_candidate_ids: frozenset[str] = frozenset()

    @property
    def weakest(self) -> EvidenceLabel:
        return weakest_label(self.labels)


@dataclass
class Route:
    """An ordered path from an entry node to a crown jewel.

    ``hops[0].src`` is the entry; ``hops[-1].dst`` is the jewel.
    """

    entry: str
    jewel: str
    hops: list[Hop]

    @property
    def weakest_label(self) -> EvidenceLabel:
        """A route is only as strong as its weakest hop."""
        if not self.hops:
            return EvidenceLabel.UNKNOWN
        return weakest_label({h.weakest for h in self.hops})

    @property
    def length(self) -> int:
        return len(self.hops)

    @property
    def fix_elements(self) -> frozenset[str]:
        """The union of cuttable elements along the route — the set a fix
        must intersect to break this route (see :mod:`.mincut`)."""
        out: set[str] = set()
        for h in self.hops:
            out |= h.fix_candidate_ids
        return frozenset(out)

    @property
    def pair(self) -> tuple[str, str]:
        return (self.entry, self.jewel)


@dataclass
class ReachabilityResult:
    """Everything the backward search found, ready for mincut + reporting."""

    routes: list[Route]
    #: (entry, jewel) pairs with at least one open route.
    open_pairs: set[tuple[str, str]]
    #: (entry, jewel) pairs considered that have no open route.
    closed_pairs: set[tuple[str, str]]
    #: Pairs where every route depends on a CONDITIONAL hop (needs probe /
    #: observation to settle). Reported separately from open/closed.
    conditional_pairs: set[tuple[str, str]] = field(default_factory=set)
    #: Open pairs (decided exactly, by graph reachability) for which no
    #: example route fits inside the enumeration limits (``max_hops``, the
    #: per-pair cap, the visit budget). Still OPEN — never closed. A shortest
    #: witness for each is in ``witness_routes``.
    truncated_pairs: set[tuple[str, str]] = field(default_factory=set)
    #: Open pairs whose listed ``routes`` may not be *all* of their routes
    #: (cap hit, hop limit bit, budget exhausted; includes
    #: ``truncated_pairs``). A fix set solved over the listing alone is not
    #: proven to cut these — see ``mincut.verified_fix_set``.
    incomplete_pairs: set[tuple[str, str]] = field(default_factory=set)
    #: Open pairs where every route leans on a hop whose weakest evidence is
    #: INFERRED/UNKNOWN (the model merely infers it). Still open; reported
    #: so corroboration can be requested. May overlap ``conditional_pairs``.
    inferred_pairs: set[tuple[str, str]] = field(default_factory=set)
    #: One deterministic shortest route per ``truncated_pairs`` entry, with
    #: no hop limit (so possibly longer than ``max_hops``). Not in ``routes``.
    witness_routes: list[Route] = field(default_factory=list)
    #: True when route enumeration hit a per-jewel visit budget (the listing
    #: for that jewel is partial; open/closed is unaffected).
    budget_exhausted: bool = False

    def routes_for(self, pair: tuple[str, str]) -> list[Route]:
        return [r for r in self.routes if r.pair == pair]


# ---------------------------------------------------------------------------
# Fix set (mincut's input/output)
# ---------------------------------------------------------------------------

#: Cost weight per cost class. Customers override these; a fix set never
#: invents risk weights beyond the class a change falls into. "impossible"
#: marks changes that cannot be made (unpatchable device) so the optimiser
#: avoids them and prefers a compensating control.
DEFAULT_COST_CLASSES: dict[str, float] = {
    "network_rule": 1.0,       # change an ACL / SG / firewall rule
    "cloud_policy": 1.0,       # change a bucket / IAM / SG policy
    "segment_move": 3.0,       # move a host to another VLAN/subnet
    "credential": 2.0,         # rotate / scope a shared credential
    "dependency_bump": 2.0,    # patch an in-house / OSS component
    "compensating": 2.5,       # add a conduit allowlist / monitor
    "vendor_patch": 8.0,       # needs a vendor firmware patch
    "device_patch": 50.0,      # patch a clinical/OT device (rarely allowed)
}


@dataclass(frozen=True)
class FixCandidate:
    """A single change that would remove one or more hops.

    ``cost`` is derived from ``cost_class`` via the (overridable) cost
    table, so the optimiser minimises a customer-set cost, never an
    invented risk weight. ``blocks`` is informational: which (entry,jewel)
    pairs this candidate appears on.
    """

    id: str
    kind: str                      # "rule" | "edge" | "credential" | ...
    cost_class: str
    description: str
    cost: float
    blocks: frozenset[tuple[str, str]] = frozenset()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class FixSet:
    """The optimiser's output: the cheapest set of changes that cuts every
    route it was given."""

    selected: list[str]                     # FixCandidate ids
    total_cost: float
    #: True when every input route is intersected by ``selected``.
    cuts_all: bool
    #: Routes (by index into the input list) left uncut — non-empty only
    #: when some route had no cuttable element (e.g. an inferred hop with
    #: no modelled control to change).
    uncut_routes: list[int] = field(default_factory=list)
    #: Optimality: "exact" (branch & bound closed) or "greedy" (fell back
    #: for a large instance). Reported so no one oversells "minimal".
    optimality: str = "exact"


# ---------------------------------------------------------------------------
# Certificate (closed-boundary proof)
# ---------------------------------------------------------------------------

@dataclass
class Assumption:
    """One stated limit of a closed proof. The honesty of the whole product
    rests on these being explicit and shipped with the certificate."""

    key: str
    text: str


@dataclass
class Corroboration:
    """What independent evidence agrees the boundary is closed."""

    observed_flows: int           # flows seen crossing it in the window
    window_days: int
    sensor_on_protected_side: bool  # False ⇒ "absence of evidence" only
    probe_tested: bool = False


@dataclass
class Certificate:
    """A signed, expiring claim that no route exists across a boundary.

    Carries the exact config it was proved against (by hash), the stated
    assumptions, the corroboration window, and an expiry. A lapsed or
    contradicted certificate is never presented as current.
    """

    claim: str                            # "no route from <A> to <B> on <ports>"
    boundary_src: str
    boundary_dst: str
    port: Optional[PortRange]
    config_hashes: tuple[str, ...]        # snapshot hashes it was proved on
    assumptions: list[Assumption]
    corroboration: Corroboration
    issued_at: str                        # ISO-8601 UTC
    expires_at: str                       # ISO-8601 UTC
    status: str = "valid"                 # valid | expired | contradicted
    fingerprint: str = ""                 # set by certificate.sign()
    #: Which key signed it (see ``signing.py``): a ``wg1-…`` id for a real
    #: per-tenant key, ``"unsigned-dev"`` for the public development key, or
    #: ``""`` for a legacy certificate signed before key ids existed.
    key_id: str = ""


# ---------------------------------------------------------------------------
# Replica verification (preconditions only — NEVER an exploit)
# ---------------------------------------------------------------------------

class PreconditionKind(str, Enum):
    """The safe checks that decide whether an exploit's *conditions* hold.

    This list is a hard allowlist. Anything not here is refused by
    :mod:`.safety`. None of these runs a payload or a command.
    """

    VERSION_IN_RANGE = "version_in_range"   # package/app version vuln range
    FLAG_ENABLED = "flag_enabled"           # a vulnerable feature is on
    ENDPOINT_EXPOSED = "endpoint_exposed"   # the interface is listening
    CODE_REACHABLE = "code_reachable"       # vuln function reachable (callgraph)
    FILE_PRESENT = "file_present"           # a telltale file exists
    CONFIG_VALUE = "config_value"           # a config key has a vuln value


@dataclass
class Precondition:
    """One condition an exploit would need, and how to check it safely."""

    kind: PreconditionKind
    description: str
    #: Opaque spec consumed by the checker (e.g. {"range": "<1.2.3"}).
    spec: dict[str, Any] = field(default_factory=dict)


@dataclass
class ReplicaPlan:
    """How to stand up an isolated copy of a component. Enforced by the
    runner: no network egress, synthetic secrets, no production data."""

    component_id: str
    image_digest: str = ""
    #: In-scope asset this replica stands in for (scope-checked like a
    #: target before any build).
    scope_asset_id: str = ""
    rebuildable: bool = True
    #: Health/smoke checks (customer-supplied) that must still pass after a
    #: fix is applied. Opaque specs; the runner executes them, not payloads.
    health_checks: tuple[str, ...] = ()


@dataclass
class ReplicaVerdict:
    """Outcome of checking preconditions on a replica, and (optionally) of
    verifying a fix on it."""

    component_id: str
    preconditions_met: bool           # all preconditions present ⇒ hop viable
    details: dict[str, bool] = field(default_factory=dict)
    #: Only set by verify_fix: preconditions gone AND health checks pass.
    fix_closes_hop: Optional[bool] = None
    fix_breaks_service: Optional[bool] = None
    label: EvidenceLabel = EvidenceLabel.PROVED_REPLICA
    note: str = ""


# ---------------------------------------------------------------------------
# Impossible traffic (reality vs the proof)
# ---------------------------------------------------------------------------

@dataclass
class Flow:
    """An observed network flow, as ingested from firewall logs / NetFlow /
    Zeek / Sentry / an OT tool."""

    src_ip: str
    dst_ip: str
    proto: Proto
    dst_port: int
    #: Did the TCP handshake complete (not just a dropped SYN)?
    handshake_completed: bool = False
    #: Seen by a sensor on the *destination* side of the boundary?
    dst_side_observed: bool = False
    #: Present in a firewall *allow* log?
    firewall_allow_logged: bool = False
    #: True for broadcast/multicast management chatter we suppress.
    is_broadcast: bool = False
    kind: str = ""                    # "arp"|"mdns"|"dhcp"|"lb_health"|...
    ts: str = ""


class ImpossibleResolution(str, Enum):
    MISSING_ASSET_ADDED = "missing_asset_added"
    RULE_DEFECT_CONFIRMED = "rule_defect_confirmed"
    ESCALATED_INCIDENT = "escalated_incident"


@dataclass
class ImpossibleTrafficAlert:
    """Raised when a flow crosses a boundary a certificate proved closed.

    Resolution always requires a human and a cited reason; the model is
    never auto-amended to explain the flow away (that could legitimise an
    attacker's tunnel)."""

    flow: Flow
    contradicts_certificate: str      # certificate fingerprint
    boundary_src: str
    boundary_dst: str
    severity: str = "critical"
    note: str = ""


# ---------------------------------------------------------------------------
# small shared helper
# ---------------------------------------------------------------------------

def _ip_in_cidr(ip: str, cidr: str) -> bool:
    """True if ``ip`` is inside ``cidr``. A bare ip in ``cidr`` is treated
    as a /32 (or /128). Invalid input is a non-match, never an exception."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        try:
            return addr == ipaddress.ip_address(cidr)
        except ValueError:
            return False
    return addr in net
