"""Tests for OT/ICS conduit modelling."""
from __future__ import annotations

from app.engine.wargame.model import EvidenceLabel, Hop, PortRange, Proto, Route
from app.engine.wargame.ot import (
    FUNCTION_CLASSES,
    INDUSTRIAL_SERVICES,
    Access,
    annotate_route,
    assess_conduit,
    is_industrial,
)


def test_is_industrial_recognises_protocols():
    assert is_industrial(Proto.TCP, 502) == "modbus"
    assert is_industrial(Proto.TCP, 102) == "s7comm"
    assert is_industrial(Proto.TCP, 20000) == "dnp3"
    assert is_industrial(Proto.UDP, 47808) == "bacnet"
    assert is_industrial(Proto.UDP, 34963) == "profinet"
    assert set(INDUSTRIAL_SERVICES) >= {"modbus", "opc_ua", "iec104"}


def test_is_industrial_rejects_others():
    assert is_industrial(Proto.TCP, 443) is None
    assert is_industrial(Proto.UDP, 502) is None


def test_modbus_write_codes():
    w = FUNCTION_CLASSES["modbus"][Access.WRITE]
    assert {5, 6, 15, 16} <= set(w)
    assert FUNCTION_CLASSES["modbus"][Access.READ] == (1, 2, 3, 4)
    assert FUNCTION_CLASSES["modbus"][Access.CONFIG] == (8, 43)
    assert 3 in FUNCTION_CLASSES["dnp3"][Access.WRITE]
    assert Access.WRITE in FUNCTION_CLASSES["s7comm"]


def test_l3l4_only_cannot_prove_read_only():
    v = assess_conduit(proto=Proto.TCP, port=502, dpi_capable=False,
                       allowed_function_access={Access.READ})
    assert v.write_possible is True
    assert v.conditional is True
    assert v.enforced_read_only is False
    assert "L3/L4" in v.note and "function codes" in v.note


def test_dpi_read_only_holds():
    v = assess_conduit(proto=Proto.TCP, port=502, dpi_capable=True,
                       allowed_function_access={Access.READ})
    assert v.enforced_read_only is True
    assert v.write_possible is False
    assert v.conditional is False


def test_dpi_with_write():
    v = assess_conduit(proto=Proto.TCP, port=102, dpi_capable=True,
                       allowed_function_access={Access.READ, Access.WRITE})
    assert v.write_possible is True
    assert v.enforced_read_only is False


def test_dpi_with_config_only_is_not_read_only():
    v = assess_conduit(proto=Proto.TCP, port=502, dpi_capable=True,
                       allowed_function_access={Access.CONFIG})
    assert v.write_possible is True


def test_dpi_unknown_access_conditional():
    v = assess_conduit(proto=Proto.TCP, port=20000, dpi_capable=True)
    assert v.conditional is True
    assert v.enforced_read_only is False


def test_non_industrial_none():
    assert assess_conduit(proto=Proto.TCP, port=443, dpi_capable=True) is None


def _route():
    hops = [
        Hop("corp", "dmz", frozenset({EvidenceLabel.PROVED_CONFIG}),
            port=PortRange.single(Proto.TCP, 443), rule_ref="fw-it:r1"),
        Hop("dmz", "plc", frozenset({EvidenceLabel.PROVED_CONFIG}),
            port=PortRange.single(Proto.TCP, 502), rule_ref="fw-ot:r7"),
    ]
    return Route("corp", "plc", hops)


def test_annotate_route_flags_industrial_hop_without_dpi():
    notes = annotate_route(_route())
    assert len(notes) == 1
    assert "modbus" in notes[0]
    assert "write to the OT device is possible" in notes[0]


def test_annotate_route_dpi_ruleset_is_conditional_not_closed():
    notes = annotate_route(_route(), dpi_capable_rulesets={"fw-ot"})
    assert len(notes) == 1
    assert "DPI-capable but the permitted function access is unknown" in notes[0]


def test_annotate_route_skips_wide_ranges():
    r = Route("a", "b", [Hop("a", "b", frozenset(), port=PortRange.any())])
    assert annotate_route(r) == []


def test_determinism():
    a = assess_conduit(proto=Proto.TCP, port=502, dpi_capable=False)
    b = assess_conduit(proto=Proto.TCP, port=502, dpi_capable=False)
    assert a == b
    assert annotate_route(_route()) == annotate_route(_route())
