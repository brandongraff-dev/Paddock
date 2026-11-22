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


# -- audit regressions ---------------------------------------------------------

import pytest  # noqa: E402


@pytest.mark.parametrize("state,real", [
    ("SF", True), ("S1", True), ("S2", True), ("S3", True),
    ("RSTO", True), ("RSTR", True),
    ("RSTRH", True), ("SHR", True),            # responder demonstrably answered
    ("S0", False), ("REJ", False), ("RSTOS0", False), ("SH", False),
    ("OTH", False), ("-", False), ("WEIRD", False),
])
def test_zeek_conn_state_real_only_when_completed_or_dst_answered(state, real):
    (f,) = parse_flows(_zeek(state), fmt="zeek") if state != "-" else \
        parse_flows(_zeek(state, conn_state="S0"), fmt="zeek")
    if state == "-":                           # unset state is skipped, not real
        flows, stats = parse_flows_detailed(_zeek("-"), fmt="zeek")
        assert flows == [] and stats.skipped == 1
        return
    assert flow_is_real(f) is real


def test_zeek_rstrh_and_shr_are_dst_side_only_not_a_completed_handshake():
    (f,) = parse_flows(_zeek("RSTRH"), fmt="zeek")
    assert f.dst_side_observed and not f.handshake_completed


def test_zeek_lowercase_state_and_ipv6_endpoints():
    rec = {"id.orig_h": "2001:db8::5", "id.resp_h": "fe80::1%eth0",
           "id.resp_p": 443, "proto": "tcp", "conn_state": "sf"}
    (f,) = parse_flows(json.dumps(rec), fmt="zeek")
    assert f.src_ip == "2001:db8::5" and f.dst_ip == "fe80::1%eth0"
    assert flow_is_real(f)


def test_zeek_unset_fields_are_skipped_not_values():
    rows = "\n".join([
        _zeek("SF", **{"id.orig_h": "-"}),
        _zeek("SF", **{"id.resp_p": "-"}),
        _zeek("SF", **{"id.resp_h": ""}),
        _zeek("SF"),
    ])
    flows, stats = parse_flows_detailed(rows, fmt="zeek")
    assert len(flows) == 1 and stats.skipped == 3


def test_zeek_icmp_with_unset_port_is_accepted():
    rec = {"id.orig_h": "10.0.0.1", "id.resp_h": "10.0.0.2", "id.resp_p": "-",
           "proto": "icmp", "conn_state": "SF"}
    (f,) = parse_flows(json.dumps(rec), fmt="zeek")
    assert f.proto is Proto.ICMP and f.dst_port == 0


def test_zeek_native_tsv_with_unset_fields_and_ipv6():
    tsv = "\n".join([
        "#separator \\x09",
        "#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tconn_state",
        "#types\ttime\taddr\tport\taddr\tport\tenum\tstring",
        "1.0\t10.0.0.1\t5555\t10.0.0.2\t22\ttcp\tSF",
        "2.0\t2001:db8::1\t5556\t2001:db8::2\t22\ttcp\tS0",
        "3.0\t-\t-\t10.0.0.2\t22\ttcp\tSF",
        "short\trow",
        "",
        "#close\t2024-01-01",
    ])
    flows, stats = parse_flows_detailed(tsv)
    assert [f.dst_ip for f in flows] == ["10.0.0.2", "2001:db8::2"]
    assert [flow_is_real(f) for f in flows] == [True, False]
    assert stats.skipped == 2


def test_blank_lines_bom_and_malformed_rows_never_crash():
    good = _zeek("SF")
    raw = "﻿\n\n" + good + "\n   \n{not json\n[1,2]\n" + good + "\n"
    flows, stats = parse_flows_detailed(raw, fmt="zeek")
    assert len(flows) == 2 and stats.skipped == 2
    for junk in (None, 42, b"\xff\xfe", "", "[", "{}", [None, 1, "x"], {"a": 1}):
        flows, stats = parse_flows_detailed(junk)
        assert flows == [] or isinstance(flows, list)


def test_firewall_deny_rows_are_not_real_and_allow_rows_are():
    rows = [{"src": "10.0.0.1", "dst": "10.0.0.2", "proto": "tcp", "dport": 22,
             "action": "deny"},
            {"src": "10.0.0.1", "dst": "10.0.0.2", "proto": "tcp", "dport": 22,
             "action": "allow"}]
    deny, allow = parse_flows(rows, fmt="firewall")
    assert not flow_is_real(deny) and flow_is_real(allow)


def test_sarif_bad_result_does_not_lose_the_others_and_rule_fallbacks():
    doc = {"runs": [
        "junk",
        {"tool": {"driver": {"rules": [{"id": "R-idx"}]}},
         "results": [
             None,
             {"ruleId": "A", "locations": "not-a-list", "message": "m"},
             {"ruleIndex": 0, "message": {"text": "by index"},
              "locations": [{"physicalLocation": {"artifactLocation": {"uri": "u1"}}}]},
             {"rule": {"id": "R-nested"}},
             {"message": "no id at all"},
         ]},
        {"results": {"not": "a list"}},
    ]}
    got = parse_sarif(json.dumps(doc))
    assert [f.rule_id for f in got] == ["A", "R-idx", "R-nested"]
    assert got[1].src_hint == "u1" and got[1].message == "by index"
    assert parse_sarif(b"\xef\xbb\xbf" + json.dumps(doc).encode()) == got
    for junk in (None, 5, "{bad", [], {"runs": 7}, b"\xff"):
        assert parse_sarif(junk) == []
