"""Lower a validated ``Invariant`` to a ``Plan``: the small, closed IR the evaluator runs."""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from enum import Enum

from . import ports as P
from .model import Invariant, Tier, parse_duration
from .parse import digest, parse_invariant


class CompileError(ValueError):
    pass


class PlanKind(str, Enum):
    REACH = "REACH"                  # assert: unreachable
    EXPOSURE_SET = "EXPOSURE_SET"    # assert: exposes-only
    COVERED = "COVERED"              # assert: covered


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

    @property
    def id(self) -> str:
        return self.invariant.id


def compile_invariant(inv: Invariant) -> Plan:
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
