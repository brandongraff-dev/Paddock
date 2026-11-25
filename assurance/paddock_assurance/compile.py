"""Lower a validated ``Invariant`` to a ``Plan``: the small, closed IR the evaluator runs."""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from . import hostexpr as X
from . import hostfields as HF
from . import ports as P
from .model import Invariant, Tier, parse_duration
from .parse import digest, parse_invariant


class CompileError(ValueError):
    pass


class PlanKind(str, Enum):
    REACH = "REACH"                  # assert: unreachable
    EXPOSURE_SET = "EXPOSURE_SET"    # assert: exposes-only
    COVERED = "COVERED"              # assert: covered
    HOSTCONFIG = "HOSTCONFIG"        # assert: <predicate> | {all|any|not: ...} over host facts


@dataclass(frozen=True)
class Plan:
    invariant: Invariant
    digest: str
    kind: PlanKind
    max_age: dt.timedelta
    min_tier: Tier
    protocols: frozenset[str]
    via_ports: P.Intervals | None
    allowed_ports: P.Intervals
    max_hops: int
    coverage_required: float
    # HOSTCONFIG only: the canonical tree and the collectors whose facts it reads.
    expr: Optional[X.Node] = None
    collectors: tuple[str, ...] = ()

    @property
    def id(self) -> str:
        return self.invariant.id


def _compile_host(inv: Invariant) -> Plan:
    tree = inv.expr
    assert tree is not None
    leaves = X.leaves(tree)
    for lf in leaves:
        spec = HF.REGISTRY[lf.field]
        if inv.evidence.min_tier.rank > spec.max_tier.rank:
            raise CompileError(
                f"evidence.min_tier {inv.evidence.min_tier.value} is above the strongest evidence "
                f"{spec.name} can ever have ({spec.max_tier.value}: an agent-signed fact is never "
                "lifted), so this invariant could never hold")
    return Plan(
        invariant=inv, digest=digest(inv), kind=PlanKind.HOSTCONFIG,
        max_age=parse_duration(inv.evidence.max_age), min_tier=inv.evidence.min_tier,
        protocols=frozenset(), via_ports=None, allowed_ports=(), max_hops=1,
        coverage_required=inv.coverage.require, expr=tree,
        # every collector a leaf reads, secondary ones included (``installed == false`` also rests on
        # the listener table): a stale or unsigned fact of any of them changes the verdict
        collectors=tuple(sorted({c for lf in leaves for c in (
            HF.REGISTRY[lf.field].collector, *HF.REGISTRY[lf.field].also_collectors)})))


def compile_invariant(inv: Invariant) -> Plan:
    if inv.assert_ == "host-config":
        return _compile_host(inv)
    kind = {"unreachable": PlanKind.REACH, "exposes-only": PlanKind.EXPOSURE_SET,
            "covered": PlanKind.COVERED}[inv.assert_]
    if kind is PlanKind.EXPOSURE_SET and set(inv.via.protocols) == {"icmp"}:
        raise CompileError("'exposes-only' reasons about tcp/udp ports; via.protocols is icmp only")
    return Plan(
        invariant=inv,
        digest=digest(inv),
        kind=kind,
        max_age=parse_duration(inv.evidence.max_age),
        min_tier=inv.evidence.min_tier,
        protocols=frozenset(inv.via.protocols),
        via_ports=P.parse_ports(inv.via.ports) if inv.via.ports else None,
        allowed_ports=P.parse_ports(inv.ports) if inv.ports else (),
        max_hops=inv.via.max_hops if kind is PlanKind.REACH else 1,
        # 'covered' *is* the coverage statement; a floor on the whole graph (which always holds
        # nodes nobody can instrument, like the internet) would only make it unsatisfiable.
        coverage_required=0.0 if kind is PlanKind.COVERED else inv.coverage.require,
    )


def compile_text(text: str) -> Plan:
    return compile_invariant(parse_invariant(text))
