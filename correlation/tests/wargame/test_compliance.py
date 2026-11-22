"""Tests for the auditor evidence pack (duck-typed stand-ins, no engine imports)."""
from __future__ import annotations

from dataclasses import dataclass, field

from app.engine.wargame.compliance import (
    EvidenceStatus,
    cip_005_pack,
    pci_segmentation_pack,
    render,
    verify_chain,
)
from app.engine.wargame.safety import contains_unsafe_token

NOW = "2026-11-22T00:00:00Z"


@dataclass
class R:
    boundary_src: str = "corp"
    boundary_dst: str = "cde"
    port: str = "443"
    verdict: str = "pass"
    agree: bool = True
    disagreements: list = field(default_factory=list)
    note: str = ""


@dataclass
class A:
    key: str
    text: str


@dataclass
class C:
    claim: str = "no route from corp to cde"
    boundary_src: str = "corp"
    boundary_dst: str = "cde"
    assumptions: list = field(default_factory=lambda: [A("k", "t")])
    issued_at: str = "2026-11-01T00:00:00Z"
    expires_at: str = "2027-02-01T00:00:00Z"
    status: str = "valid"
    fingerprint: str = "abc"


def _pack(reports=None, certs=None, cov=0.97, probe=True):
    return pci_segmentation_pack(
        boundary_reports=reports if reports is not None else [R(), R(boundary_src="dmz")],
        certificates=certs if certs is not None else [C()],
        generated_at=NOW,
        coverage_pct=cov,
        has_probe=probe,
    )


def _by(pack):
    return {i.control_id: i for i in pack.items}


def test_all_pass_everything_met():
    b = _by(_pack())
    for cid in ("1.3.1", "1.3.2", "1.2.7", "1.2.5", "11.4.5", "11.4.6", "12.5.2"):
        assert b[cid].status is EvidenceStatus.MET, cid
    assert "97%" in b["1.3.1"].statement
    assert [i.control_id for i in _pack().items] == sorted(b)


def test_fail_open_is_exception_and_named():
    p = _pack(reports=[R(), R(boundary_src="vpn", verdict="fail_open",
                             agree=False, disagreements=["route vpn to cde on 3389"])])
    b = _by(p)
    for cid in ("1.3.1", "1.3.2"):
        assert b[cid].status is EvidenceStatus.EXCEPTION
        assert "vpn->cde" in b[cid].statement
        assert "3389" in b[cid].statement
    assert b["11.4.5"].status is EvidenceStatus.NOT_ASSESSED


def test_conditional_and_insufficient_not_assessed():
    for v in ("conditional", "insufficient"):
        b = _by(_pack(reports=[R(verdict=v, note="no observer")]))
        assert b["1.3.1"].status is EvidenceStatus.NOT_ASSESSED
        assert "no observer" in b["1.3.1"].statement
        assert b["1.2.5"].status is EvidenceStatus.NOT_ASSESSED


def test_no_probe_never_meets_11_4():
    b = _by(_pack(probe=False))
    assert b["1.3.1"].status is EvidenceStatus.MET
    for cid in ("11.4.5", "11.4.6"):
        assert b[cid].status is EvidenceStatus.NOT_ASSESSED
        assert "not a segmentation test" in b[cid].statement


def test_no_reports_nothing_met_from_proof():
    b = _by(_pack(reports=[]))
    for cid in ("1.3.1", "1.3.2", "1.2.5", "11.4.5"):
        assert b[cid].status is EvidenceStatus.NOT_ASSESSED


def test_coverage_none_or_low():
    b = _by(_pack(cov=None))
    assert b["12.5.2"].status is EvidenceStatus.NOT_ASSESSED
    assert "unknown" in b["12.5.2"].statement
    assert "unknown" in b["1.3.1"].statement  # closure always states coverage
    assert _by(_pack(cov=0.5))["12.5.2"].status is EvidenceStatus.NOT_ASSESSED


def test_certificates():
    assert _by(_pack(certs=[]))["1.2.7"].status is EvidenceStatus.NOT_ASSESSED
    b = _by(_pack(certs=[C(), C(boundary_dst="x", status="expired")]))
    assert b["1.2.7"].status is EvidenceStatus.NOT_ASSESSED


def test_chain_deterministic_and_tamper_evident():
    p1, p2 = _pack(), _pack()
    assert p1.fingerprint == p2.fingerprint != ""
    assert p1.fingerprint == p1.items[-1].item_hash
    assert p1.items[0].prev_hash == ""
    assert p1.items[1].prev_hash == p1.items[0].item_hash
    assert verify_chain(p1)
    p1.items[2].statement += " edited"
    assert not verify_chain(p1)
    # recomputing via a differently-worded input changes the fingerprint
    assert _pack(cov=0.95).fingerprint != p2.fingerprint


def test_statements_pass_safety_and_unsafe_is_replaced():
    p = _pack()
    assert all(not contains_unsafe_token(i.statement) for i in p.items)
    bad = _pack(reports=[R(boundary_src="exploit shell", verdict="fail_open",
                           disagreements=["x"])])
    assert all(not contains_unsafe_token(i.statement) for i in bad.items)


def test_cip_005():
    p = cip_005_pack(
        boundary_reports=[R(), R(boundary_src="vpn", verdict="fail_open", disagreements=["open"])],
        generated_at=NOW,
    )
    b = _by(p)
    assert b["CIP-005-R1"].status is EvidenceStatus.EXCEPTION
    assert b["CIP-005-R1.vpn->cde:443"].status is EvidenceStatus.EXCEPTION
    assert b["CIP-005-R1.corp->cde:443"].status is EvidenceStatus.MET
    ok = cip_005_pack(boundary_reports=[R()], generated_at=NOW)
    assert _by(ok)["CIP-005-R1"].status is EvidenceStatus.MET
    assert p.fingerprint == cip_005_pack(
        boundary_reports=[R(), R(boundary_src="vpn", verdict="fail_open", disagreements=["open"])],
        generated_at=NOW,
    ).fingerprint


def test_render_deterministic():
    assert render(_pack()) == render(_pack())
    assert any("11.4.5" in ln for ln in render(_pack()))
