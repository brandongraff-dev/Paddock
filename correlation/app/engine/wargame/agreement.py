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

Verdict vocabulary (:data:`VERDICTS`), strongest claim first:

* ``"pass"`` — config proves the boundary closed **and a real active probe**
  was blocked, and no real crossing was observed. The only verdict that
  carries probe evidence.
* ``"proved_config"`` — config proves the boundary closed, but no probe has
  tested it (and nothing was observed crossing). A no-packet proof: worth a
  certificate that says so, but not a segmentation *test*.
* ``"conditional"`` — the config verdict rests on runtime state it can't
  prove (App-ID, FQDN, dynamic groups …). Never certified closed.
* ``"insufficient"`` — not enough evidence either way (e.g. no config verdict,
  or the search was truncated).
* ``"fail_open"`` — some source shows the boundary open.

The probe source is ONLY ever a real probe result supplied by the caller.
Never feed the model's own reachability back in as a "probe": that would be
circular evidence (:func:`from_reachability` takes the config verdict from the
model and leaves the probe UNKNOWN unless a real one is given).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Optional, Sequence

from . import safety
from .environment import Environment
from .impossible import ClosedBoundary, flow_crosses, flow_is_real
from .model import Flow, PortRange


#: Every verdict :func:`assess_boundary` can return (schema 041 CHECK).
VERDICTS: tuple[str, ...] = (
    "pass", "proved_config", "conditional", "insufficient", "fail_open",
)

#: Verdicts for which config proves the boundary closed (a certificate may be
#: issued, stating its basis). ``conditional`` is never among them.
CERTIFIABLE_VERDICTS: frozenset[str] = frozenset({"pass", "proved_config"})


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
    #: one of :data:`VERDICTS`
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

    if (
        ev.config is SourceVerdict.CLOSED
        and ev.probe is SourceVerdict.UNKNOWN
        and ev.observed in (SourceVerdict.CLOSED, SourceVerdict.UNKNOWN)
    ):
        return report(
            "proved_config", False, [],
            f"{label}: the configuration proves the boundary closed (no "
            "packets sent), but no active probe has tested it yet and no real "
            "crossing was observed. Observation alone cannot prove closure.",
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

    This is a check of ONE direct boundary (the rule set on the
    ``boundary_src -> boundary_dst`` edge). It says nothing about multi-hop
    routes: for an (entry, crown jewel) pair use :func:`from_reachability`.

    ``probe`` is "did a real safe-check connect succeed":
    ``True`` = the probe crossed the boundary (OPEN), ``False`` = the probe
    was blocked / failed to connect (CLOSED), ``None`` = not run (UNKNOWN).
    Pass only a result a probe actually produced — never a model output.

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

    probe_v = _probe_verdict(probe)

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


def _probe_verdict(probe: Optional[bool]) -> SourceVerdict:
    if probe is None:
        return SourceVerdict.UNKNOWN
    return SourceVerdict.OPEN if probe else SourceVerdict.CLOSED


def from_reachability(
    result: Any,
    entry: str,
    jewel: str,
    *,
    env: Optional[Environment] = None,
    probe: Optional[bool] = None,
    observed_flows: Iterable[Flow] = (),
) -> AgreementReport:
    """Pair-level agreement for ``(entry, jewel)`` from a
    :class:`~.model.ReachabilityResult` (the end-to-end backward search).

    The **config** verdict comes from the search, not from a direct edge (a
    multi-hop pair usually has no direct edge, so a direct-edge reading would
    say CLOSED whatever the route):

    * a conditional pair (every route rests on a conditional hop) ->
      ``conditional``;
    * an open pair -> OPEN (this includes ``truncated_pairs``, which the
      solver reports as open with no route that fits the enumeration limits);
    * a pair listed as truncated but NOT open, or a pair the search did not
      consider -> UNKNOWN (defensive: an unfinished search is never closure);
    * a closed pair (no route in the model) -> CLOSED.

    ``probe`` is a REAL probe result (``True`` crossed, ``False`` blocked,
    ``None`` not run). Default ``None``: the verdict for a closed pair is then
    ``"proved_config"``, never ``"pass"``.

    ``observed`` is OPEN iff a real flow went from ``entry``'s CIDRs to
    ``jewel``'s CIDRs (any port); needs ``env`` for the CIDRs. Else UNKNOWN.
    """
    pair = (entry, jewel)
    truncated = set(getattr(result, "truncated_pairs", None) or ())
    conditional = pair in set(getattr(result, "conditional_pairs", None) or ())
    if conditional:
        config = SourceVerdict.UNKNOWN
    elif pair in set(result.open_pairs):
        config = SourceVerdict.OPEN
    elif pair in truncated:
        config = SourceVerdict.UNKNOWN
    elif pair in set(result.closed_pairs):
        config = SourceVerdict.CLOSED
    else:
        config = SourceVerdict.UNKNOWN

    observed = SourceVerdict.UNKNOWN
    if env is not None:
        src = env.nodes.get(entry)
        dst = env.nodes.get(jewel)
        if src is not None and dst is not None:
            cb = ClosedBoundary(
                src_cidrs=tuple(src.cidrs),
                dst_cidrs=tuple(dst.cidrs),
                port=None,
                certificate_fingerprint="",
                boundary_src=entry,
                boundary_dst=jewel,
            )
            if any(flow_is_real(f) and flow_crosses(f, cb) for f in observed_flows):
                observed = SourceVerdict.OPEN

    rep = assess_boundary(
        BoundaryEvidence(
            boundary_src=entry,
            boundary_dst=jewel,
            port=None,
            config=config,
            probe=_probe_verdict(probe),
            observed=observed,
            conditional=conditional,
        )
    )
    if rep.verdict == "insufficient" and pair in truncated:
        rep.note = _safe(
            f"{entry} -> {jewel}: insufficient evidence; the route search hit "
            "its budget before finishing, so finding no route is not a proof "
            "of closure."
        )
    return rep
