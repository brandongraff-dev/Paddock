"""Auditor evidence pack: Wargame proof mapped onto PCI DSS 4.0 and NERC CIP-005.

Pure and deterministic (stdlib only). It *reports* proof that already
exists; it produces no new traffic and performs no testing. Rules:

* Nothing is MET without supporting evidence.
* A closure statement always carries coverage (``docs/WARGAME.md`` §3):
  "closed" with unknown coverage is absence of evidence, and says so.
* 11.4.5 / 11.4.6 are *tests*. A no-packet proof is not a test on its own,
  so they are MET only when an active probe backed a passing boundary.
* Items form a hash chain, so editing any item changes the pack fingerprint.

Inputs are duck-typed (no imports of agreement/certificate modules):
reports expose ``boundary_src, boundary_dst, port, verdict, agree,
disagreements, note``; certificates expose ``claim, boundary_src,
boundary_dst, assumptions, issued_at, expires_at, status, fingerprint``.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Sequence

from .safety import safe_text

_FALLBACK = "Statement withheld: text did not pass the safety filter."
_COVERAGE_MIN = 0.9


class EvidenceStatus(str, Enum):
    MET = "met"
    EXCEPTION = "exception"
    NOT_ASSESSED = "not_assessed"


@dataclass
class EvidenceItem:
    control_id: str
    title: str
    status: EvidenceStatus
    statement: str
    evidence: dict = field(default_factory=dict)
    refs: tuple[str, ...] = ()
    prev_hash: str = ""
    item_hash: str = ""


@dataclass
class EvidencePack:
    framework: str
    items: list[EvidenceItem]
    generated_at: str
    summary: str
    fingerprint: str = ""


# ---------------------------------------------------------------------------
# Hash chain
# ---------------------------------------------------------------------------

def _canonical(item: EvidenceItem) -> str:
    return json.dumps(
        {
            "control_id": item.control_id,
            "status": item.status.value,
            "statement": item.statement,
            "evidence": item.evidence,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
        ensure_ascii=True,
    )


def chain(items: Sequence[EvidenceItem]) -> str:
    """Link ``items`` in order; return the final hash ('' when empty)."""
    prev = ""
    for item in items:
        item.prev_hash = prev
        item.item_hash = hashlib.sha256(
            (prev + _canonical(item)).encode("utf-8")
        ).hexdigest()
        prev = item.item_hash
    return prev


def verify_chain(pack: EvidencePack) -> bool:
    """Recompute the chain on a copy; True if every hash and the fingerprint match."""
    prev = ""
    for item in pack.items:
        expect = hashlib.sha256((prev + _canonical(item)).encode("utf-8")).hexdigest()
        if item.prev_hash != prev or item.item_hash != expect:
            return False
        prev = item.item_hash
    return pack.fingerprint == prev


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _bname(r: Any) -> str:
    return f"{r.boundary_src}->{r.boundary_dst}"


def _port(r: Any) -> str:
    p = getattr(r, "port", None)
    return "any" if p is None else str(p)


def _sorted(reports: Iterable[Any]) -> list[Any]:
    return sorted(reports, key=lambda r: (_bname(r), _port(r)))


def _coverage_text(coverage_pct: float | None) -> str:
    if coverage_pct is None:
        return "sensor coverage unknown (absence of evidence is not proof of closure)"
    return f"sensor coverage {coverage_pct * 100:.0f}%"


def _entry(r: Any) -> dict:
    return {
        "boundary": _bname(r),
        "port": _port(r),
        "verdict": r.verdict,
        "agree": bool(getattr(r, "agree", False)),
        "disagreements": sorted(str(d) for d in (getattr(r, "disagreements", None) or [])),
        "note": str(getattr(r, "note", "") or ""),
    }


def _item(control_id, title, status, statement, evidence, refs=()) -> EvidenceItem:
    return EvidenceItem(
        control_id=control_id,
        title=title,
        status=status,
        statement=safe_text(statement, _FALLBACK),
        evidence=evidence,
        refs=tuple(refs),
    )


def _verdict_roll(
    reports: list[Any], coverage_pct: float | None, what: str
) -> tuple[EvidenceStatus, str, dict]:
    """Aggregate boundary verdicts into one status + statement + evidence."""
    cov = _coverage_text(coverage_pct)
    entries = [_entry(r) for r in reports]
    if not reports:
        return (
            EvidenceStatus.NOT_ASSESSED,
            f"No boundaries were supplied, so {what} is not assessed; {cov}.",
            {"boundaries": entries, "coverage_pct": coverage_pct},
        )
    fails = [r for r in reports if r.verdict == "fail_open"]
    unassessed = [r for r in reports if r.verdict not in ("pass", "fail_open")]
    passes = [r for r in reports if r.verdict == "pass"]
    ev = {"boundaries": entries, "coverage_pct": coverage_pct}
    if fails:
        parts = []
        for r in fails:
            why = "; ".join(sorted(str(d) for d in (r.disagreements or []))) or (
                str(r.note) or "open route reported"
            )
            parts.append(f"{_bname(r)} port {_port(r)} ({why})")
        return (
            EvidenceStatus.EXCEPTION,
            f"{what}: {len(fails)} boundary route(s) open: "
            + " | ".join(parts)
            + f". {len(passes)} of {len(reports)} boundaries pass; {cov}.",
            ev,
        )
    if unassessed:
        parts = [
            f"{_bname(r)} is {r.verdict}"
            + (f" ({r.note})" if getattr(r, "note", "") else "")
            for r in unassessed
        ]
        return (
            EvidenceStatus.NOT_ASSESSED,
            f"{what} not fully assessed: "
            + "; ".join(parts)
            + f". {len(passes)} of {len(reports)} boundaries pass; {cov}.",
            ev,
        )
    return (
        EvidenceStatus.MET,
        f"{what}: all {len(reports)} boundaries pass (config, probe and "
        f"observation agree); {cov}.",
        ev,
    )


def _finish(framework: str, items: list[EvidenceItem], generated_at: str) -> EvidencePack:
    items = sorted(items, key=lambda i: i.control_id)
    fp = chain(items)
    counts = {s: sum(1 for i in items if i.status is s) for s in EvidenceStatus}
    summary = (
        f"{framework}: {counts[EvidenceStatus.MET]} met, "
        f"{counts[EvidenceStatus.EXCEPTION]} exception, "
        f"{counts[EvidenceStatus.NOT_ASSESSED]} not assessed "
        f"of {len(items)} controls."
    )
    return EvidencePack(
        framework=framework,
        items=items,
        generated_at=generated_at,
        summary=safe_text(summary, _FALLBACK),
        fingerprint=fp,
    )


# ---------------------------------------------------------------------------
# PCI DSS 4.0
# ---------------------------------------------------------------------------

def pci_segmentation_pack(
    *,
    boundary_reports: Sequence[Any],
    certificates: Sequence[Any] = (),
    generated_at: str,
    coverage_pct: float | None = None,
    has_probe: bool = False,
) -> EvidencePack:
    reports = _sorted(boundary_reports)
    certs = sorted(certificates, key=lambda c: (c.boundary_src, c.boundary_dst, c.claim))
    items: list[EvidenceItem] = []

    # 1.3.1 / 1.3.2
    for cid, title, what in (
        ("1.3.1", "Inbound traffic to the CDE is restricted", "Inbound CDE traffic restriction"),
        ("1.3.2", "Outbound traffic from the CDE is restricted", "Outbound CDE traffic restriction"),
    ):
        status, stmt, ev = _verdict_roll(reports, coverage_pct, what)
        items.append(_item(cid, title, status, stmt, ev, ("PCI DSS 4.0 " + cid,)))

    # 1.2.7 config review
    cert_ev = [
        {
            "claim": c.claim,
            "boundary": f"{c.boundary_src}->{c.boundary_dst}",
            "status": c.status,
            "issued_at": c.issued_at,
            "expires_at": c.expires_at,
            "fingerprint": c.fingerprint,
            "assumptions": sorted(a.key for a in (c.assumptions or [])),
        }
        for c in certs
    ]
    valid = [c for c in certs if c.status == "valid"]
    if certs and len(valid) == len(certs):
        s127 = EvidenceStatus.MET
        t127 = (
            f"Configuration proof reviewed: {len(valid)} certificate(s) valid, "
            "each tied to a config snapshot fingerprint and stated assumptions."
        )
    elif certs:
        bad = sorted(f"{c.boundary_src}->{c.boundary_dst} is {c.status}" for c in certs if c.status != "valid")
        s127 = EvidenceStatus.NOT_ASSESSED
        t127 = "Configuration review incomplete: " + "; ".join(bad) + "."
    else:
        s127 = EvidenceStatus.NOT_ASSESSED
        t127 = "No configuration-proof certificates supplied; review not evidenced."
    items.append(_item("1.2.7", "NSC configurations reviewed", s127, t127,
                       {"certificates": cert_ev}, ("PCI DSS 4.0 1.2.7",)))

    # 1.2.5 allowed services (summary level)
    services = [
        {"boundary": _bname(r), "port": _port(r), "verdict": r.verdict}
        for r in reports
    ]
    assessed = bool(reports) and all(r.verdict in ("pass", "fail_open") for r in reports)
    if assessed:
        s125 = EvidenceStatus.MET
        t125 = (
            f"Allowed services identified for {len(reports)} boundary entries "
            "(owner justification still to be attached per service); "
            f"{_coverage_text(coverage_pct)}."
        )
    else:
        s125 = EvidenceStatus.NOT_ASSESSED
        t125 = (
            "Allowed services not fully identified: at least one boundary is "
            f"conditional or insufficient, or none supplied; {_coverage_text(coverage_pct)}."
        )
    items.append(_item("1.2.5", "Allowed services, protocols and ports identified and justified",
                       s125, t125, {"allowed_services": services}, ("PCI DSS 4.0 1.2.5",)))

    # 11.4.5 / 11.4.6 segmentation testing: never MET without a probe
    all_pass = bool(reports) and all(r.verdict == "pass" for r in reports)
    for cid, title in (
        ("11.4.5", "Segmentation controls tested (entity)"),
        ("11.4.6", "Segmentation controls tested every 6 months (service provider)"),
    ):
        ev = {"has_probe": has_probe, "boundaries": [_entry(r) for r in reports]}
        if has_probe and all_pass:
            st = EvidenceStatus.MET
            t = (
                f"Active probe backed passing verdicts on all {len(reports)} boundaries; "
                "partner tester to review and sign; "
                f"{_coverage_text(coverage_pct)}."
            )
        elif not has_probe:
            st = EvidenceStatus.NOT_ASSESSED
            t = (
                "No active probe supplied. A no-packet proof is not a segmentation "
                "test on its own, so this test requirement is not assessed."
            )
        else:
            st = EvidenceStatus.NOT_ASSESSED
            t = (
                "A probe was supplied but not every boundary passes, so the "
                "segmentation test is not established."
            )
        items.append(_item(cid, title, st, t, ev, ("PCI DSS 4.0 " + cid,)))

    # 12.5.2 scope
    cev = {"coverage_pct": coverage_pct, "threshold": _COVERAGE_MIN}
    if coverage_pct is not None and coverage_pct >= _COVERAGE_MIN:
        s125b = EvidenceStatus.MET
        t125b = f"PCI scope confirmed against observed flows; {_coverage_text(coverage_pct)}."
    else:
        s125b = EvidenceStatus.NOT_ASSESSED
        state = "unknown" if coverage_pct is None else f"low ({coverage_pct * 100:.0f}%)"
        t125b = (
            f"Scope not confirmed: coverage is {state}, below the "
            f"{_COVERAGE_MIN * 100:.0f}% needed."
        )
    items.append(_item("12.5.2", "PCI DSS scope documented and confirmed", s125b, t125b,
                       cev, ("PCI DSS 4.0 12.5.2",)))

    return _finish("PCI DSS 4.0 segmentation", items, generated_at)


# ---------------------------------------------------------------------------
# NERC CIP-005
# ---------------------------------------------------------------------------

def cip_005_pack(*, boundary_reports: Sequence[Any], generated_at: str) -> EvidencePack:
    reports = _sorted(boundary_reports)
    items: list[EvidenceItem] = []
    for r in reports:
        status, stmt, ev = _verdict_roll([r], None, f"ESP access point {_bname(r)}")
        items.append(_item(f"CIP-005-R1.{_bname(r)}:{_port(r)}",
                           "Electronic Security Perimeter access point permissions",
                           status, stmt, ev, ("NERC CIP-005 R1",)))
    status, stmt, ev = _verdict_roll(reports, None, "CIP-005 R1 Electronic Security Perimeter")
    items.append(_item("CIP-005-R1", "Electronic Security Perimeter (summary)",
                       status, stmt, ev, ("NERC CIP-005 R1",)))
    return _finish("NERC CIP-005 R1", items, generated_at)


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def render(pack: EvidencePack) -> list[str]:
    lines = [
        f"{pack.framework} evidence pack",
        f"generated: {pack.generated_at}",
        pack.summary,
        f"fingerprint: {pack.fingerprint}",
        "",
    ]
    for i in pack.items:
        lines.append(f"[{i.status.value.upper()}] {i.control_id}  {i.title}")
        lines.append(f"    {i.statement}")
        if i.refs:
            lines.append(f"    refs: {', '.join(i.refs)}")
        lines.append(f"    hash: {i.item_hash}")
    return lines
