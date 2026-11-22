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
    key_id: str = "wg1-0123456789abcdef"


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
    assert p1.items[0].prev_hash != ""          # seeded with the pack header
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


# ---------------------------------------------------------------------------
# proved_config (config-only, no probe), signing, coverage units, chain
# ---------------------------------------------------------------------------

import copy  # noqa: E402

import pytest  # noqa: E402

from app.engine.wargame.compliance import EvidenceItem  # noqa: E402


def test_proved_config_never_meets_segmentation_testing():
    b = _by(_pack(reports=[R(verdict="proved_config")], probe=True))
    for cid in ("11.4.5", "11.4.6"):
        assert b[cid].status is EvidenceStatus.NOT_ASSESSED
        assert "configuration only" in b[cid].statement


def test_proved_config_meets_1_3_only_with_measured_coverage():
    good = _by(_pack(reports=[R(verdict="proved_config")], cov=0.97))
    assert good["1.3.1"].status is EvidenceStatus.MET
    assert "configuration only" in good["1.3.1"].statement
    assert "probe agree" not in good["1.3.1"].statement
    assert good["1.3.1"].evidence["config_only"] == 1
    assert good["1.3.1"].evidence["probe_backed"] == 0
    for cov in (None, 0.5):
        b = _by(_pack(reports=[R(verdict="proved_config")], cov=cov))
        assert b["1.3.1"].status is EvidenceStatus.NOT_ASSESSED, cov
        assert "no active probe" in b["1.3.1"].statement
    # 1.2.5 (services identified) counts a config proof as assessed.
    assert good["1.2.5"].status is EvidenceStatus.MET


def test_mixed_pass_and_proved_config_states_both():
    b = _by(_pack(reports=[R(), R(boundary_src="dmz", verdict="proved_config")], cov=0.97))
    assert b["1.3.1"].status is EvidenceStatus.MET
    assert "1 of 2 boundaries pass with an active probe" in b["1.3.1"].statement
    assert b["11.4.5"].status is EvidenceStatus.NOT_ASSESSED


def test_cip_005_proved_config_needs_coverage():
    rep = [R(verdict="proved_config")]
    assert _by(cip_005_pack(boundary_reports=rep, generated_at=NOW))[
        "CIP-005-R1"].status is EvidenceStatus.NOT_ASSESSED
    assert _by(cip_005_pack(boundary_reports=rep, generated_at=NOW, coverage_pct=0.95))[
        "CIP-005-R1"].status is EvidenceStatus.MET


@pytest.mark.parametrize("kid", ["unsigned-dev", ""])
def test_unsigned_certificates_do_not_meet_1_2_7(kid):
    b = _by(_pack(certs=[C(key_id=kid)]))
    assert b["1.2.7"].status is EvidenceStatus.NOT_ASSESSED
    assert "development key" in b["1.2.7"].statement


def test_certificate_expired_by_date_does_not_meet_1_2_7():
    lapsed = C(expires_at="2026-11-21T23:59:59Z")       # before NOW, status still "valid"
    b = _by(_pack(certs=[lapsed]))
    assert b["1.2.7"].status is EvidenceStatus.NOT_ASSESSED
    assert "expired" in b["1.2.7"].statement
    assert b["1.2.7"].evidence["certificates"][0]["status"] == "expired"


@pytest.mark.parametrize("cov", [97.0, 1.5, -0.1])
def test_coverage_must_be_a_fraction(cov):
    with pytest.raises(ValueError):
        _pack(cov=cov)
    with pytest.raises(ValueError):
        cip_005_pack(boundary_reports=[R()], generated_at=NOW, coverage_pct=cov)


def _tampered(mutate):
    p = _pack()
    assert verify_chain(p)
    mutate(p)
    return verify_chain(p)


def test_verify_chain_detects_reorder_delete_insert_and_edits():
    assert not _tampered(lambda p: p.items.reverse())
    assert not _tampered(lambda p: p.items.__setitem__(slice(0, 2), [p.items[1], p.items[0]]))
    assert not _tampered(lambda p: p.items.pop(0))
    assert not _tampered(lambda p: p.items.pop(3))
    assert not _tampered(lambda p: p.items.pop())
    assert not _tampered(lambda p: p.items.insert(1, copy.deepcopy(p.items[1])))
    assert not _tampered(lambda p: setattr(p.items[0], "title", "edited"))
    assert not _tampered(lambda p: setattr(p.items[0], "refs", ("other",)))
    assert not _tampered(lambda p: setattr(p.items[0], "status", EvidenceStatus.EXCEPTION))
    assert not _tampered(lambda p: p.items[0].evidence.update({"x": 1}))
    assert not _tampered(lambda p: setattr(p, "framework", "other"))
    assert not _tampered(lambda p: setattr(p, "generated_at", "2020-01-01T00:00:00Z"))
    assert not _tampered(lambda p: setattr(p, "summary", "all met"))
    assert not _tampered(lambda p: setattr(p, "fingerprint", "0" * 64))


def test_verify_chain_detects_a_fully_recomputed_reordered_chain_against_the_fingerprint():
    # Re-chaining a reordered item list yields a different fingerprint, so a
    # recorded fingerprint still exposes it.
    from app.engine.wargame.compliance import chain

    p = _pack()
    recorded = p.fingerprint
    items = [copy.deepcopy(i) for i in reversed(p.items)]
    assert chain(items, framework=p.framework, generated_at=p.generated_at) != recorded


def test_verify_chain_rejects_non_enum_status():
    p = _pack()
    p.items[0] = EvidenceItem(**{**p.items[0].__dict__, "status": "met"})
    assert not verify_chain(p)
