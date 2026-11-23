"""Auditor evidence pack: Wargame proof mapped onto PCI DSS 4.0 and NERC CIP-005.

Pure and deterministic (stdlib only). It *reports* proof that already
exists; it produces no new traffic and performs no testing. Rules:

* Nothing is MET without supporting evidence.
* A closure statement always carries coverage (``docs/WARGAME.md`` §3):
  "closed" with unknown coverage is absence of evidence, and says so.
* 11.4.5 / 11.4.6 are *tests*. A no-packet proof is not a test on its own,
  so they are MET only when an active probe backed a passing boundary
  (verdict ``pass``); ``proved_config`` never satisfies them.
* ``proved_config`` (config proves the boundary closed, no probe yet) for the
  *configuration* controls (1.3.1 / 1.3.2, CIP-005 R1): the testing procedure
  for these is an examination of NSC configuration, so a config proof is the
  right kind of evidence — but with no probe, the model's completeness is the
  only thing standing behind it. So, conservatively, ``proved_config`` counts
  toward MET only when coverage is measured and at least 90%; otherwise the
  control is NOT_ASSESSED with that reason. The statement always says how
  many boundaries are config-only vs probe-backed. 1.2.5 (services
  identified) accepts ``proved_config`` as assessed.
* 1.2.7 is not MET on certificates fingerprinted with the public development
  key (``key_id`` ``unsigned-dev`` / legacy ``""``): they are not signed.
* ``coverage_pct`` here is a FRACTION in [0, 1] (0.97 = 97%); a value outside
  that range raises, so a percentage (97.0) can't silently read as 9700%.
* Items form a hash chain, so editing any item changes the pack fingerprint.
  The chain binds every displayed field of every item (control id, title,
  status, statement, evidence, refs) and is seeded with the pack header
  (framework, generated_at), so reordering, deleting, inserting or editing an
  item, or relabelling the pack, is detected by :func:`verify_chain`. The
  chain is unkeyed: it proves integrity against the recorded fingerprint.

Inputs are duck-typed (no imports of agreement/certificate modules):
reports expose ``boundary_src, boundary_dst, port, verdict, agree,
disagreements, note``; certificates expose ``claim, boundary_src,
boundary_dst, assumptions, issued_at, expires_at, status, fingerprint``.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable, Sequence

from .safety import safe_text

_FALLBACK = "Statement withheld: text did not pass the safety filter."
_COVERAGE_MIN = 0.9
_CHAIN_VERSION = "wargame-evidence/v2"

#: Verdicts that are decided (one way or the other) by the evidence.
_DECIDED = ("pass", "proved_config", "fail_open")
#: Key ids whose fingerprint is not a real signature (see signing.py).
_UNSIGNED_KIDS = ("unsigned-dev", "")


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
            "title": item.title,
            "status": item.status.value,
            "statement": item.statement,
            "evidence": item.evidence,
            "refs": list(item.refs),
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
        ensure_ascii=True,
    )


def _seed(framework: str, generated_at: str) -> str:
    """The chain's genesis hash: binds the pack header, so an item can't be
    moved to another pack and the pack can't be relabelled or redated."""
    header = json.dumps(
        {"v": _CHAIN_VERSION, "framework": framework, "generated_at": generated_at},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(header.encode("utf-8")).hexdigest()


def chain(
    items: Sequence[EvidenceItem], *, framework: str = "", generated_at: str = ""
) -> str:
    """Link ``items`` in order from the header seed; return the final hash
    (the seed itself when there are no items)."""
    prev = _seed(framework, generated_at)
    for item in items:
        item.prev_hash = prev
        item.item_hash = hashlib.sha256(
            (prev + _canonical(item)).encode("utf-8")
        ).hexdigest()
        prev = item.item_hash
    return prev


def verify_chain(pack: EvidencePack) -> bool:
    """Recompute the chain (without mutating the pack); True iff every link,
    every item hash, the summary and the fingerprint all match. Detects an
    edited, reordered, inserted or deleted item and a relabelled header."""
    prev = _seed(pack.framework, pack.generated_at)
    for item in pack.items:
        if not isinstance(item.status, EvidenceStatus):
            return False
        expect = hashlib.sha256((prev + _canonical(item)).encode("utf-8")).hexdigest()
        if item.prev_hash != prev or item.item_hash != expect:
            return False
        prev = item.item_hash
    if pack.summary != _summary(pack.framework, pack.items):
        return False
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


def _check_coverage(coverage_pct: float | None) -> float | None:
    if coverage_pct is None:
        return None
    c = float(coverage_pct)
    if not (0.0 <= c <= 1.0):
        raise ValueError(
            f"coverage_pct must be a fraction in [0, 1] (0.97 = 97%), got {coverage_pct!r}"
        )
    return c


def _coverage_ok(coverage_pct: float | None) -> bool:
    return coverage_pct is not None and coverage_pct >= _COVERAGE_MIN


def _coverage_text(coverage_pct: float | None) -> str:
    if coverage_pct is None:
        return "sensor coverage unknown (absence of evidence is not proof of closure)"
    return f"sensor coverage {coverage_pct * 100:.0f}%"


def _ts(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _cert_status(c: Any, generated_at: str) -> str:
    """The certificate's status as of the pack date: a ``valid`` certificate
    whose expiry is at or before ``generated_at`` is ``expired`` (a lapsed
    proof is never evidence), and one with no readable expiry is not valid."""
    status = str(getattr(c, "status", "") or "")
    if status != "valid":
        return status
    exp = _ts(getattr(c, "expires_at", None))
    now = _ts(generated_at)
    if exp is None:
        return "expired"
    if now is not None and exp <= now:
        return "expired"
    return status


def _kid(c: Any) -> str:
    return str(getattr(c, "key_id", "") or "")


def _is_unsigned(c: Any) -> bool:
    """A certificate whose fingerprint is not a real signature."""
    if _kid(c) in _UNSIGNED_KIDS:
        return True
    return any(getattr(a, "key", "") == "unsigned_dev_signature" for a in (c.assumptions or []))


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
    """Aggregate boundary verdicts into one status + statement + evidence.

    ``pass`` (config + a real probe agree) supports MET. ``proved_config``
    (config only, no probe) supports MET only with measured coverage of at
    least 90%; otherwise it leaves the control NOT_ASSESSED (see module doc).
    """
    cov = _coverage_text(coverage_pct)
    entries = [_entry(r) for r in reports]
    if not reports:
        return (
            EvidenceStatus.NOT_ASSESSED,
            f"No boundaries were supplied, so {what} is not assessed; {cov}.",
            {"boundaries": entries, "coverage_pct": coverage_pct},
        )
    fails = [r for r in reports if r.verdict == "fail_open"]
    unassessed = [r for r in reports if r.verdict not in _DECIDED]
    passes = [r for r in reports if r.verdict == "pass"]
    config_only = [r for r in reports if r.verdict == "proved_config"]
    basis = (
        f"{len(passes)} of {len(reports)} boundaries pass with an active probe, "
        f"{len(config_only)} are proved closed by configuration only"
    )
    ev = {
        "boundaries": entries,
        "coverage_pct": coverage_pct,
        "probe_backed": len(passes),
        "config_only": len(config_only),
    }
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
            + f". {basis}; {cov}.",
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
            + f". {basis}; {cov}.",
            ev,
        )
    if config_only and not _coverage_ok(coverage_pct):
        names = ", ".join(_bname(r) for r in config_only)
        return (
            EvidenceStatus.NOT_ASSESSED,
            f"{what} not established: {names} proved closed by configuration "
            "only, with no active probe, and model coverage is not measured at "
            f"{_COVERAGE_MIN * 100:.0f}% or more, so a path outside the model "
            f"can't be ruled out. {basis}; {cov}.",
            ev,
        )
    if config_only:
        return (
            EvidenceStatus.MET,
            f"{what}: all {len(reports)} boundaries proved closed ({basis}; no "
            "real crossing observed). Configuration-only proofs rest on the "
            f"model's coverage; {cov}.",
            ev,
        )
    return (
        EvidenceStatus.MET,
        f"{what}: all {len(reports)} boundaries pass (configuration and an "
        f"active probe agree, no real crossing observed); {cov}.",
        ev,
    )


def _summary(framework: str, items: Sequence[EvidenceItem]) -> str:
    counts = {s: sum(1 for i in items if i.status is s) for s in EvidenceStatus}
    summary = (
        f"{framework}: {counts[EvidenceStatus.MET]} met, "
        f"{counts[EvidenceStatus.EXCEPTION]} exception, "
        f"{counts[EvidenceStatus.NOT_ASSESSED]} not assessed "
        f"of {len(items)} controls."
    )
    return safe_text(summary, _FALLBACK)


def _finish(framework: str, items: list[EvidenceItem], generated_at: str) -> EvidencePack:
    items = sorted(items, key=lambda i: i.control_id)
    fp = chain(items, framework=framework, generated_at=generated_at)
    return EvidencePack(
        framework=framework,
        items=items,
        generated_at=generated_at,
        summary=_summary(framework, items),
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
    coverage_pct = _check_coverage(coverage_pct)
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
            "status": _cert_status(c, generated_at),
            "issued_at": c.issued_at,
            "expires_at": c.expires_at,
            "fingerprint": c.fingerprint,
            "key_id": _kid(c),
            "assumptions": sorted(a.key for a in (c.assumptions or [])),
        }
        for c in certs
    ]
    valid = [c for c in certs if _cert_status(c, generated_at) == "valid"]
    unsigned = [c for c in certs if _is_unsigned(c)]
    if certs and unsigned:
        s127 = EvidenceStatus.NOT_ASSESSED
        t127 = (
            f"Configuration review not evidenced: {len(unsigned)} of {len(certs)} "
            "certificate(s) carry no real signature (fingerprinted with the "
            "public development key; configure WARGAME_SIGNING_KEY)."
        )
    elif certs and len(valid) == len(certs):
        s127 = EvidenceStatus.MET
        t127 = (
            f"Configuration proof reviewed: {len(valid)} certificate(s) valid, "
            "each tied to a config snapshot fingerprint and stated assumptions."
        )
    elif certs:
        bad = sorted(
            f"{c.boundary_src}->{c.boundary_dst} is {_cert_status(c, generated_at)}"
            for c in certs
            if _cert_status(c, generated_at) != "valid"
        )
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
    assessed = bool(reports) and all(r.verdict in _DECIDED for r in reports)
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
            n_cfg = sum(1 for r in reports if r.verdict == "proved_config")
            st = EvidenceStatus.NOT_ASSESSED
            t = (
                "A probe was supplied but not every boundary passes a probe-backed "
                f"check ({n_cfg} proved by configuration only, which is not a "
                "test), so the segmentation test is not established."
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

def cip_005_pack(
    *,
    boundary_reports: Sequence[Any],
    generated_at: str,
    coverage_pct: float | None = None,
) -> EvidencePack:
    """NERC CIP-005 R1. ``coverage_pct`` (a fraction) only matters for
    config-only (``proved_config``) boundaries; see the module doc."""
    coverage_pct = _check_coverage(coverage_pct)
    reports = _sorted(boundary_reports)
    items: list[EvidenceItem] = []
    for r in reports:
        status, stmt, ev = _verdict_roll([r], coverage_pct, f"ESP access point {_bname(r)}")
        items.append(_item(f"CIP-005-R1.{_bname(r)}:{_port(r)}",
                           "Electronic Security Perimeter access point permissions",
                           status, stmt, ev, ("NERC CIP-005 R1",)))
    status, stmt, ev = _verdict_roll(reports, coverage_pct, "CIP-005 R1 Electronic Security Perimeter")
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
