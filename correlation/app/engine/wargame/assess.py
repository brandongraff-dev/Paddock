"""Turn a rule-aware :class:`Environment` into a full assessment bundle.

This is the pure, deterministic core of ``/compute-wargame`` over the
persisted twin: given an :class:`~app.engine.wargame.environment.Environment`
(assembled from parsed config + declared topology), it runs the backward
search, the three-way boundary agreement, the minimum-cost fix set, and the
signed closed-boundary certificates, and serialises them with
:func:`store.assemble_bundle`. ``main.py`` just loads the twin, calls this,
and persists the result.

No I/O and no database: ``issued_at`` is passed in, so the same environment
always yields an equal bundle. DEFENSIVE: pure model reasoning only — nothing
here executes, probes, or emits an exploit, payload or command.

The "probe" source of the boundary agreement here is the backward-reachability
safe-check over the model itself (no packets are sent): a pair the search
proved has no open route did not cross (CLOSED); an open pair crossed (OPEN).
That lets a config-closed boundary reach a ``"pass"`` verdict without
fabricating sensor evidence — the certificate's corroboration still states, in
so many words, that with no protected-side sensor this is absence of evidence,
not an observed closure.

Certificates are built and signed **only** for a CLOSED boundary whose
agreement verdict is ``"pass"`` (or ``"conditional"``); an open / ``fail_open``
boundary is never certified. For a closed pair the direct boundary is
necessarily config-closed (a config-open direct edge would itself be an open
route), so this resolves to proved-config closure.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from . import agreement, certificate, mincut, report, store
from .environment import Environment
from .model import Assumption, Corroboration, Edge, FixCandidate

#: Demo HMAC signing key for the twin's certificates. It is intentionally a
#: fixed, public value so the twin's certificates are self-consistent in dev
#: without a secret; wiring a real per-tenant signing key is a follow-up (see
#: docs/READINESS.md). The certificate's assumptions and expiry carry the
#: honesty; the signature only binds the semantic fields against tampering.
DEMO_SIGNING_KEY = b"twin"


def _gating_cost_class(env: Environment, edge: Edge) -> str:
    """The cost class a fix on ``edge`` falls into: the gating rule's
    ``cost_class`` when the edge is governed by a known rule set, else the
    default ``"network_rule"``. The gating rule is the first-evaluated one
    (lowest ``(order, id)``) for a deterministic choice."""
    if edge.rule_set_id:
        rs = env.rulesets.get(edge.rule_set_id)
        if rs is not None and rs.rules:
            gating = min(rs.rules, key=lambda r: (r.order, r.id))
            return gating.cost_class
    return "network_rule"


def _fix_candidates(env: Environment) -> dict[str, FixCandidate]:
    """One :class:`FixCandidate` per distinct ``fix_candidate_id`` carried by
    the environment's edges (two directed edges sharing a candidate id — e.g.
    an adjacency cut both ways — collapse to one). Priced from the gating
    rule's cost class via :func:`mincut.cost_for`."""
    cands: dict[str, FixCandidate] = {}
    for edge in env.edges:
        fcid = edge.fix_candidate_id
        if not fcid or fcid in cands:
            continue
        cost_class = _gating_cost_class(env, edge)
        cands[fcid] = FixCandidate(
            id=fcid,
            kind="edge",
            cost_class=cost_class,
            description=f"cut {edge.src}->{edge.dst}",
            cost=mincut.cost_for(cost_class),
        )
    return cands


def assess_environment(
    env: Environment,
    *,
    label: str,
    config_hashes: list[str],
    issued_at: datetime,
    coverage_pct: Optional[float] = None,
) -> store.AssessmentBundle:
    """Run a full Wargame assessment over ``env`` and assemble the bundle.

    Deterministic and pure (see the module docstring). Pairs, reports and
    certificates are all produced in sorted order.
    """
    rr = env.reachability()

    open_pairs = set(rr.open_pairs)
    closed_pairs = set(rr.closed_pairs)

    # Boundary agreement for every (entry, jewel) pair the search considered.
    reports = []
    reports_by_pair: dict[tuple[str, str], agreement.AgreementReport] = {}
    for pair in sorted(open_pairs | closed_pairs):
        entry, jewel = pair
        probe = pair in open_pairs  # model-derived safe-check; see module docstring
        ag = agreement.from_environment(env, entry, jewel, port=None, probe=probe)
        reports.append(ag)
        reports_by_pair[pair] = ag

    # Certificates: only a CLOSED boundary that the agreement passes (or that
    # is conditional) is certified — never an open / fail_open one.
    certificates_out = []
    for pair in sorted(closed_pairs):
        ag = reports_by_pair[pair]
        if ag.verdict not in ("pass", "conditional"):
            continue
        entry, jewel = pair
        cert = certificate.build_certificate(
            boundary_src=entry,
            boundary_dst=jewel,
            port=None,
            config_hashes=tuple(config_hashes),
            assumptions=[
                Assumption(
                    "no_unmodelled_links",
                    "No links outside the modelled topology.",
                )
            ],
            corroboration=Corroboration(0, 30, sensor_on_protected_side=False),
            issued_at=issued_at,
            ttl_hours=24,
        )
        certificate.sign(cert, key=DEMO_SIGNING_KEY)
        certificates_out.append(cert)

    candidates = _fix_candidates(env)
    fs = mincut.fix_set_for(rr, candidates)

    scorecard = report.build_scorecard(
        rr, agreement_reports=reports, coverage_pct=coverage_pct
    )

    return store.assemble_bundle(
        reachability=rr,
        scorecard=scorecard,
        agreement_reports=reports,
        certificates=certificates_out,
        fix_set=fs,
        fix_candidates=candidates,
        evidence_packs=(),
        label=label,
    )
