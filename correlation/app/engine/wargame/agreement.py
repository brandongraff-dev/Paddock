"""Three-way boundary agreement report (docs/WARGAME.md sections 2.2 and 3).

For one boundary, three independent sources each give a verdict:

* **config**   - the rule solver's reading of the firewall configuration;
* **probe**    - a safe-check connect attempt (did it cross?);
* **observed** - real flows seen crossing the boundary.

This module combines them into an auditor-facing verdict. It is pure and
deterministic, sends nothing and executes nothing.

Asymmetry that drives the logic ("no false closed"): observation can only
ever show OPEN or be absent. Absence of traffic never proves a boundary
closed, so ``observed`` is never CLOSED when derived from flows. Any source
saying OPEN is a finding, because the boundary is meant to be closed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Sequence

from . import safety
from .environment import Environment
from .impossible import ClosedBoundary, flow_crosses, flow_is_real
from .model import Flow, PortRange


class SourceVerdict(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    UNKNOWN = "unknown"


@dataclass
class BoundaryEvidence:
    boundary_src: str
    boundary_dst: str
    port: Optional[PortRange]
    config: SourceVerdict
    probe: SourceVerdict
    observed: SourceVerdict
    #: True when the config verdict rests on a conditional/runtime rule.
    conditional: bool = False


@dataclass
class AgreementReport:
    boundary_src: str
    boundary_dst: str
    port: Optional[PortRange]
    #: "pass" | "fail_open" | "conditional" | "insufficient"
    verdict: str
    agree: bool
    disagreements: list[str] = field(default_factory=list)
    note: str = ""


def _safe(text: str) -> str:
    return safety.safe_text(text, "Boundary agreement note withheld by safety filter.")


def assess_boundary(ev: BoundaryEvidence) -> AgreementReport:
    """Combine the three source verdicts into one report."""
    sources = (
        ("config", ev.config),
        ("probe", ev.probe),
        ("observed", ev.observed),
    )
    label = f"{ev.boundary_src} -> {ev.boundary_dst}"

    def report(verdict: str, agree: bool, disagreements: list[str], note: str):
        return AgreementReport(
            boundary_src=ev.boundary_src,
            boundary_dst=ev.boundary_dst,
            port=ev.port,
            verdict=verdict,
            agree=agree,
            disagreements=disagreements,
            note=_safe(note),
        )

    opens = [n for n, v in sources if v is SourceVerdict.OPEN]
    closeds = [n for n, v in sources if v is SourceVerdict.CLOSED]

    if opens:
        dis: list[str] = []
        for o in opens:
            if closeds:
                for c in closeds:
                    dis.append(f"{o} says open but {c} says closed")
            else:
                dis.append(f"{o} says open")
        return report(
            "fail_open", False, dis,
            f"{label} is meant to be closed but {', '.join(opens)} "
            "shows it open. Investigate before relying on any closed claim.",
        )

    if ev.conditional:
        return report(
            "conditional", False, [],
            f"{label}: the configuration rests on a conditional runtime rule "
            "and cannot prove the boundary closed. A probe or observation "
            "is needed to settle it.",
        )

    if (
        ev.config is SourceVerdict.CLOSED
        and ev.probe is SourceVerdict.CLOSED
        and ev.observed in (SourceVerdict.CLOSED, SourceVerdict.UNKNOWN)
    ):
        return report(
            "pass", True, [],
            f"{label}: configuration and an active probe agree the boundary "
            "is closed, and no real crossing was observed. Observation alone "
            "cannot prove closure.",
        )

    missing: list[str] = []
    if ev.config is SourceVerdict.UNKNOWN:
        missing.append("a configuration verdict")
    if ev.probe is SourceVerdict.UNKNOWN:
        missing.append("an active probe result")
    if ev.config is SourceVerdict.CLOSED and ev.probe is SourceVerdict.CLOSED:
        pass
    elif not missing:
        missing.append("agreement between sources")
    return report(
        "insufficient", False, [],
        f"{label}: insufficient evidence, missing {' and '.join(missing)}.",
    )


def from_environment(
    env: Environment,
    boundary_src: str,
    boundary_dst: str,
    port: Optional[PortRange] = None,
    *,
    probe: Optional[bool] = None,
    observed_flows: Sequence[Flow] = (),
) -> AgreementReport:
    """Build the evidence for one boundary from the model and assess it.

    ``probe`` is "did the safe-check connect succeed":
    ``True`` = the probe crossed the boundary (OPEN), ``False`` = the probe
    was blocked / failed to connect (CLOSED), ``None`` = not run (UNKNOWN).

    ``observed`` is OPEN iff some flow crosses this boundary (source and
    destination CIDRs and port) and is a real flow
    (:func:`impossible.flow_is_real`); otherwise UNKNOWN, never CLOSED.
    """
    decision = env.boundary_decision(boundary_src, boundary_dst, port)
    conditional = bool(decision.conditional)
    if conditional:
        config = SourceVerdict.UNKNOWN
    elif decision.allowed:
        config = SourceVerdict.OPEN
    else:
        config = SourceVerdict.CLOSED

    if probe is None:
        probe_v = SourceVerdict.UNKNOWN
    else:
        probe_v = SourceVerdict.OPEN if probe else SourceVerdict.CLOSED

    src = env.nodes.get(boundary_src)
    dst = env.nodes.get(boundary_dst)
    edge = env.find_edge(boundary_src, boundary_dst)
    eff_port = port if port is not None else (edge.port if edge else None)
    cb = ClosedBoundary(
        src_cidrs=tuple(src.cidrs) if src else (),
        dst_cidrs=tuple(dst.cidrs) if dst else (),
        port=eff_port,
        certificate_fingerprint="",
        boundary_src=boundary_src,
        boundary_dst=boundary_dst,
    )
    seen_open = any(flow_is_real(f) and flow_crosses(f, cb) for f in observed_flows)
    observed = SourceVerdict.OPEN if seen_open else SourceVerdict.UNKNOWN

    return assess_boundary(
        BoundaryEvidence(
            boundary_src=boundary_src,
            boundary_dst=boundary_dst,
            port=port,
            config=config,
            probe=probe_v,
            observed=observed,
            conditional=conditional,
        )
    )
