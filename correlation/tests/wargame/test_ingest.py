"""Tests for observed-flow and pentest-result ingest (defensive; reads only)."""
from __future__ import annotations

import json
from pathlib import Path

from app.engine.wargame.impossible import flow_is_real
from app.engine.wargame.ingest import (
    ImportedFinding,
    imported_edges,
    parse_flows,
    parse_flows_detailed,
    parse_sarif,
)
from app.engine.wargame.model import EvidenceLabel, Proto

FIX = Path(__file__).parent / "parsers" / "fixtures"


def _zeek(state: str, **extra) -> str:
    rec = {"id.orig_h": "10.9.0.5", "id.resp_h": "10.1.0.9", "id.resp_p": 5432,
           "proto": "tcp", "conn_state": state}
    rec.update(extra)
    return json.dumps(rec)


# -- generic ---------------------------------------------------------------

def test_generic_list_and_aliases():
    rows = [
        {"src": "1.1.1.1", "dst": "2.2.2.2", "proto": "tcp", "dport": 443,
         "state": "established"},
        {"src_ip": "1.1.1.2", "dst_ip": "2.2.2.3", "proto": "udp", "dst_port": "53",
         "action": "Accept"},
    ]
    flows = parse_flows(rows, fmt="generic")
    assert [f.dst_port for f in flows] == [443, 53]
    assert flows[0].proto is Proto.TCP and flows[0].handshake_completed
    assert not flows[0].firewall_allow_logged
    assert flows[1].proto is Proto.UDP and flows[1].firewall_allow_logged
    assert not flows[1].handshake_completed


def test_generic_from_json_string_and_sf_state():
    raw = json.dumps([{"src": "a", "dst": "b", "proto": "tcp", "dport": 22, "state": "SF"}])
    (f,) = parse_flows(raw, fmt="generic")
    assert f.handshake_completed


# -- zeek ------------------------------------------------------------------

def test_zeek_conn_state_mapping():
    for state in ("SF", "S1", "RSTO", "RSTR"):
        (f,) = parse_flows(_zeek(state), fmt="zeek")
        assert f.handshake_completed and f.dst_side_observed, state
        assert flow_is_real(f)
    for state in ("S0", "REJ"):
        (f,) = parse_flows(_zeek(state), fmt="zeek")
        assert not f.handshake_completed, state
        assert not f.dst_side_observed and not f.firewall_allow_logged
        assert not flow_is_real(f)  # a dropped attempt is not a crossing


def test_zeek_fixture_from_disk():
    flows, stats = parse_flows_detailed((FIX / "zeek_conn.jsonl").read_text(), "zeek")
    assert stats.parsed == 4 and stats.skipped == 0
    pg = flows[0]
    assert (pg.src_ip, pg.dst_ip, pg.dst_port, pg.proto) == (
        "10.9.0.5", "10.1.0.9", 5432, Proto.TCP)
    assert pg.handshake_completed and pg.kind == "postgresql"
    assert not flows[1].handshake_completed   # S0
    assert not flows[2].handshake_completed   # REJ
    assert flows[3].proto is Proto.UDP


# -- firewall --------------------------------------------------------------

def test_firewall_allow_and_deny():
    rows = [
        {"src": "10.0.0.1", "dst": "10.0.1.1", "proto": "tcp", "dport": 80, "action": "allow"},
        {"src": "10.0.0.1", "dst": "10.0.1.1", "proto": "tcp", "dport": 81, "action": "permit"},
        {"src": "10.0.0.1", "dst": "10.0.1.1", "proto": "tcp", "dport": 82, "action": "accept"},
        {"src": "10.0.0.2", "dst": "10.0.1.1", "proto": "tcp", "dport": 80, "action": "deny"},
        {"src": "10.0.0.2", "dst": "10.0.1.1", "proto": "tcp", "dport": 81, "action": "drop"},
    ]
    flows = parse_flows(rows, fmt="firewall")
    assert [f.firewall_allow_logged for f in flows] == [True, True, True, False, False]
    for f in flows[3:]:
        assert not (f.handshake_completed or f.dst_side_observed or f.firewall_allow_logged)
        assert not flow_is_real(f)
    assert flow_is_real(flows[0])


# -- auto ------------------------------------------------------------------

def test_auto_sniffing():
    z = parse_flows(_zeek("SF"))
    assert z[0].handshake_completed and z[0].dst_side_observed

    z_list = parse_flows([{"src": "a", "dst": "b", "proto": "tcp", "dport": 1,
                           "conn_state": "SF"}])
    assert z_list[0].dst_side_observed  # conn_state list -> zeek path

    fw = parse_flows([{"src": "a", "dst": "b", "proto": "tcp", "dport": 1, "action": "allow"}])
    assert fw[0].firewall_allow_logged

    gen = parse_flows([{"src": "a", "dst": "b", "proto": "tcp", "dport": 1}])
    assert len(gen) == 1 and not flow_is_real(gen[0])


# -- bad rows --------------------------------------------------------------

def test_bad_rows_skipped_and_counted():
    raw = "\n".join([
        _zeek("SF"),
        "{not json",
        json.dumps({"id.orig_h": "10.0.0.1", "conn_state": "SF"}),  # no resp
        json.dumps([1, 2]),
        _zeek("S0"),
    ])
    flows, stats = parse_flows_detailed(raw, "zeek")
    assert len(flows) == 2
    assert stats.parsed == 2 and stats.skipped == 3
    assert len(stats.reasons) == 3


def test_bad_generic_rows_and_garbage_input():
    rows = [
        {"src": "a", "dst": "b", "proto": "tcp", "dport": 99999},
        "nope",
        {"src": "a", "proto": "tcp", "dport": 1},
        {"src": "a", "dst": "b", "proto": "tcp", "dport": 1},
    ]
    flows, stats = parse_flows_detailed(rows, "generic")
    assert len(flows) == 1 and stats.skipped == 3
    for junk in (None, 42, "", "[1,", b"\xff\xfe"):
        assert parse_flows(junk) == [] or isinstance(parse_flows(junk), list)
    _, st = parse_flows_detailed([], "bogus")
    assert st.skipped == 1


# -- SARIF -----------------------------------------------------------------

def test_sarif_fixture_from_disk():
    findings = parse_sarif((FIX / "pentest.sarif.json").read_text())
    assert len(findings) == 2
    f = findings[0]
    assert f.rule_id == "PT-001" and f.level == "error"
    assert "lateral movement" in f.message
    assert f.src_hint == "guest-wifi" and f.dst_hint == "billing-db"
    assert findings[1].dst_hint == ""


def test_sarif_never_raises():
    for junk in (None, "", "{", "[]", 5, {"runs": "x"}, {"runs": [None, {"results": [3]}]},
                 {"runs": [{"results": [{"message": {"text": "no id"}}]}]}):
        assert parse_sarif(junk) == []


def test_sarif_uri_pair_hint():
    doc = {"runs": [{"results": [{
        "ruleId": "R", "message": {"text": "m"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a"}}},
                      {"physicalLocation": {"artifactLocation": {"uri": "b"}}}],
    }]}]}
    (f,) = parse_sarif(doc)
    assert (f.src_hint, f.dst_hint) == ("a", "b")


# -- imported edges --------------------------------------------------------

def test_imported_edges_only_when_both_hints_map():
    findings = parse_sarif((FIX / "pentest.sarif.json").read_text())
    mapping = {"guest-wifi": "seg:guest", "billing-db": "db:billing"}
    edges = imported_edges(findings, mapping)
    assert len(edges) == 1
    e = edges[0]
    assert (e.src, e.dst) == ("seg:guest", "db:billing")
    assert e.base_labels == frozenset({EvidenceLabel.IMPORTED})
    assert e.metadata == {"rule_id": "PT-001", "source": "pentest"}
    assert e.rule_set_id is None

    assert imported_edges(findings, {"guest-wifi": "seg:guest"}) == []
    assert imported_edges(findings, {}) == []
    assert imported_edges([ImportedFinding("X", "m", "a", "")], {"a": "n1"}) == []


def test_imported_edges_dedup_and_self_loop():
    fs = [ImportedFinding("R", "m", "a", "b"), ImportedFinding("R", "m", "a", "b"),
          ImportedFinding("S", "m", "a", "a")]
    edges = imported_edges(fs, {"a": "n1", "b": "n2"})
    assert [(e.src, e.dst) for e in edges] == [("n1", "n2")]


# -- determinism -----------------------------------------------------------

def test_determinism():
    zraw = (FIX / "zeek_conn.jsonl").read_text()
    assert parse_flows(zraw) == parse_flows(zraw)
    assert [f.dst_port for f in parse_flows(zraw)] == [5432, 5432, 3389, 53]  # input order
    sraw = (FIX / "pentest.sarif.json").read_text()
    m = {"guest-wifi": "a", "billing-db": "b"}
    assert imported_edges(parse_sarif(sraw), m) == imported_edges(parse_sarif(sraw), m)
