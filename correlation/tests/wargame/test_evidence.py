"""Stored boundary evidence (``evidence.py``): the probe -> pair mapping, the
stale-probe rule, flow ser/de and timestamps, and impossible traffic against
standing certificates, through ``assess_environment``. Pure, no DB."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.engine.wargame import evidence as ev
from app.engine.wargame.assess import CERT_TTL_HOURS, assess_environment
from app.engine.wargame.environment import Environment
from app.engine.wargame.model import (
    Action, Edge, Flow, Node, NodeRole, PortRange, Proto, RuleSet,
)

NOW = datetime(2026, 11, 22, 12, 0, tzinfo=timezone.utc)


def _p(src="guest", dst="db", result="blocked", port=5432, age_h=1.0, proto="tcp"):
    return ev.ProbeResult(src=src, dst=dst, proto=proto, port=port, result=result,
                          observed_at=NOW - timedelta(hours=age_h), source="scanner-1")


# -- pair mapping -------------------------------------------------------------

def test_probe_counts_only_from_entry_to_jewel():
    res = [
        _p("guest", "dmz", "blocked"),        # hop probe: entry -> intermediate
        _p("dmz", "db", "blocked"),           # hop probe: intermediate -> jewel
        _p("internet", "db", "blocked"),      # a different pair
    ]
    out = ev.pair_probes(res, now=NOW, entries={"guest", "internet"}, jewels={"db"})
    # Hop probes never compose into a pair verdict.
    assert out == {("internet", "db"): False}
    assert ("guest", "db") not in out


def test_without_role_filter_keys_are_exact_src_dst():
    out = ev.pair_probes([_p("dmz", "db")], now=NOW)
    assert out == {("dmz", "db"): False}


def test_any_port_crossed_beats_blocked_and_newest_wins_per_port():
    res = [
        _p(port=5432, result="blocked", age_h=1),
        _p(port=443, result="crossed", age_h=2),
    ]
    assert ev.pair_probes(res, now=NOW) == {("guest", "db"): True}
    # Same port: a newer blocked result supersedes an older crossed one.
    res = [_p(port=5432, result="crossed", age_h=3), _p(port=5432, result="blocked", age_h=1)]
    assert ev.pair_probes(res, now=NOW) == {("guest", "db"): False}
    # ... and a newer crossed one supersedes an older blocked one.
    res = [_p(port=5432, result="blocked", age_h=3), _p(port=5432, result="crossed", age_h=1)]
    assert ev.pair_probes(res, now=NOW) == {("guest", "db"): True}
    # Exact tie on time: crossed wins (fail loud).
    res = [_p(result="blocked", age_h=1), _p(result="crossed", age_h=1)]
    assert ev.pair_probes(res, now=NOW) == {("guest", "db"): True}


def test_error_results_are_no_probe():
    assert ev.pair_probes([_p(result="error")], now=NOW) == {}
    # An error never masks a real result either.
    assert ev.pair_probes([_p(result="blocked", age_h=2), _p(result="error", age_h=1)],
                          now=NOW) == {("guest", "db"): False}


# -- staleness ----------------------------------------------------------------

def test_stale_probe_does_not_count():
    assert ev.PROBE_MAX_AGE_HOURS == CERT_TTL_HOURS == 24
    assert ev.pair_probes([_p(age_h=24.01)], now=NOW) == {}
    assert ev.pair_probes([_p(age_h=23.99)], now=NOW) == {("guest", "db"): False}
    # A stale "crossed" does not count either (the boundary may be fixed since).
    assert ev.pair_probes([_p(result="crossed", age_h=30)], now=NOW) == {}
    # A fresh blocked one does not inherit anything from an old crossed one.
    assert ev.pair_probes([_p(result="crossed", age_h=30), _p(age_h=1)],
                          now=NOW) == {("guest", "db"): False}


def test_future_dated_probe_does_not_count():
    assert ev.pair_probes([_p(age_h=-1)], now=NOW) == {}
    assert ev.pair_probes([_p(age_h=-0.05)], now=NOW) == {("guest", "db"): False}  # 3 min skew


def test_naive_timestamps_are_utc():
    p = ev.ProbeResult("guest", "db", "tcp", 1, "blocked", NOW.replace(tzinfo=None))
    assert ev.probe_counts(p, now=NOW)


# -- flows ----------------------------------------------------------------------

def test_flow_row_round_trip_exact():
    f = Flow("10.9.0.5", "10.1.0.9", Proto.TCP, 5432, handshake_completed=True,
             dst_side_observed=True, firewall_allow_logged=False, is_broadcast=False,
             kind="postgres", ts="1700000000.5")
    row = ev.flow_to_row(f, observed_at=NOW, source="zeek-1")
    assert row["source"] == "zeek-1" and row["observed_at"] == NOW
    assert ev.row_to_flow(row) == f


@pytest.mark.parametrize("ts,expect", [
    ("1763805600", datetime(2025, 11, 22, 10, 0, tzinfo=timezone.utc)),
    ("2026-11-20T08:00:00Z", datetime(2026, 11, 20, 8, 0, tzinfo=timezone.utc)),
    ("2026-11-20T08:00:00", datetime(2026, 11, 20, 8, 0, tzinfo=timezone.utc)),
    ("", NOW), ("yesterday", NOW), ("nan", NOW), ("1e400", NOW),
    ("2030-01-01T00:00:00Z", NOW),            # future: the ingest time instead
])
def test_flow_observed_at(ts, expect):
    assert ev.flow_observed_at(ts, ingested_at=NOW) == expect


def test_observation_window_days():
    assert ev.observation_window_days(None, now=NOW) == 0
    assert ev.observation_window_days(NOW - timedelta(hours=1), now=NOW) == 1
    assert ev.observation_window_days(NOW - timedelta(days=3, hours=1), now=NOW) == 4
    assert ev.observation_window_days(NOW - timedelta(days=90), now=NOW) == ev.FLOW_WINDOW_DAYS


# -- assess_environment with evidence --------------------------------------------

PG = PortRange.single(Proto.TCP, 5432)


def _env() -> Environment:
    """guest (10.9.0.0/24) -> db (10.1.0.0/24) across sg-db, which allows nothing."""
    env = Environment()
    env.add_node(Node("guest", NodeRole.ENTRY, ("10.9.0.0/24",)))
    env.add_node(Node("dmz", NodeRole.INTERMEDIATE, ("10.2.0.0/24",)))
    env.add_node(Node("db", NodeRole.CROWN_JEWEL, ("10.1.0.0/24",)))
    env.add_ruleset(RuleSet("sg-db", [], default_action=Action.DENY))
    env.add_edge(Edge("guest", "db", rule_set_id="sg-db", port=PG))
    return env


def _run(**kw):
    return assess_environment(_env(), label="twin", config_hashes=["h"], issued_at=NOW, **kw)


def _verdict(bundle):
    (b,) = bundle.boundaries
    return b["verdict"]


def _real_flow(src="10.9.0.5", dst="10.1.0.9", **kw):
    return Flow(src, dst, Proto.TCP, 5432, handshake_completed=True, ts=NOW.isoformat(), **kw)


def test_no_evidence_is_proved_config():
    b = _run()
    assert _verdict(b) == "proved_config"
    assert b.certificates[0]["corroboration"]["probe_tested"] is False
    assert b.assessment["metadata"]["impossible_traffic_alerts"] == 0


def test_mapped_blocked_probe_is_pass_and_hop_probe_is_not():
    entries, jewels = ev.env_entries_and_jewels(_env())
    assert (entries, jewels) == ({"guest"}, {"db"})
    hop = ev.pair_probes([_p("guest", "dmz"), _p("dmz", "db")], now=NOW,
                         entries=entries, jewels=jewels)
    assert _verdict(_run(probes=hop)) == "proved_config"
    pair = ev.pair_probes([_p()], now=NOW, entries=entries, jewels=jewels)
    b = _run(probes=pair)
    assert _verdict(b) == "pass"
    assert b.certificates[0]["corroboration"]["probe_tested"] is True
    assert b.assessment["metadata"]["pass_pairs"] == 1
    stale = ev.pair_probes([_p(age_h=25)], now=NOW, entries=entries, jewels=jewels)
    assert _verdict(_run(probes=stale)) == "proved_config"


def test_real_crossing_flow_is_fail_open_and_noise_is_not():
    b = _run(observed_flows=[_real_flow()], observation_window_days=1)
    assert _verdict(b) == "fail_open" and b.certificates == []
    # A dropped SYN, broadcast or management chatter proves nothing.
    dropped = Flow("10.9.0.5", "10.1.0.9", Proto.TCP, 5432)
    mgmt = _real_flow(kind="mgmt")
    assert _verdict(_run(observed_flows=[dropped, mgmt])) == "proved_config"


def test_impossible_traffic_against_a_standing_certificate():
    first = _run()
    cert = first.certificates[0]
    standing = [{**cert}]
    b = _run(observed_flows=[_real_flow(), _real_flow(src="10.2.0.1")],
             observation_window_days=1, standing_certificates=standing)
    md = b.assessment["metadata"]
    assert _verdict(b) == "fail_open"
    assert md["impossible_traffic_alerts"] == 1           # the dmz-sourced flow is not guest
    (a,) = md["impossible_traffic_sample"]
    assert a["contradicts_certificate"] == cert["fingerprint"]
    assert (a["boundary_src"], a["boundary_dst"]) == ("guest", "db")
    assert a["severity"] == "critical" and a["src_ip"] == "10.9.0.5"
    assert md["observation_window_days"] == 1


def test_expired_or_contradicted_certificate_raises_nothing():
    cert = _run().certificates[0]
    expired = {**cert, "expires_at": (NOW - timedelta(minutes=1)).isoformat()}
    gone = {**cert, "status": "contradicted"}
    unknown = {**cert, "boundary_src": "not-modelled"}
    for c in (expired, gone, unknown):
        b = _run(observed_flows=[_real_flow()], standing_certificates=[c])
        assert b.assessment["metadata"]["impossible_traffic_alerts"] == 0


def test_alert_sample_is_capped():
    cert = _run().certificates[0]
    flows = [_real_flow(src=f"10.9.0.{i}") for i in range(1, 12)]
    md = _run(observed_flows=flows, standing_certificates=[cert]).assessment["metadata"]
    assert md["impossible_traffic_alerts"] == 11
    assert len(md["impossible_traffic_sample"]) == ev.ALERT_SAMPLE
