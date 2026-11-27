# SPDX-License-Identifier: AGPL-3.0-or-later
"""Ledger (contract 3.10, D30): local, append-only by convention, no contents recorded."""
from __future__ import annotations

import json
import os
import stat

import pytest

from paddock_cli.guard import GUARD_VERSION, ledger


@pytest.fixture
def st(tmp_path):
    d = tmp_path / "state"
    d.mkdir(mode=0o700)
    return str(d)


def _fixed_clock():
    return 1_800_000_000.0


def test_append_writes_one_json_line_with_standard_fields(st):
    lg = ledger.Ledger(st, session="s1", clock=_fixed_clock)
    assert lg.append("check", blocking=2, open=3, tier="high", checks=["PG-SEC-001", "PG-WEB-005"]) is True
    path = os.path.join(st, "ledger.jsonl")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    (line,) = open(path).read().splitlines()
    rec = json.loads(line)
    assert rec["event"] == "check" and rec["session"] == "s1" and rec["tool_version"] == GUARD_VERSION
    assert rec["ts"] == "2027-01-15T08:00:00Z" and rec["blocking"] == 2 and rec["checks"] == ["PG-SEC-001", "PG-WEB-005"]


def test_events_are_a_closed_list(st):
    lg = ledger.Ledger(st)
    for ev in ("check", "hook_block", "hook_allow", "hook_ignored_by_agent", "hook_error", "fix", "verify", "pkg",
               "deps", "url", "net_call", "suppression_added", "init"):
        assert lg.append(ev) is True
    with pytest.raises(ValueError):
        lg.append("telemetry")


def test_contents_evidence_and_secrets_are_never_recorded(st):
    lg = ledger.Ledger(st)
    secret = "sk" + "_live_" + "A" * 24
    lg.append("check", evidence=secret, content="file text", contents="x", secret=secret, text="free text",
              fingerprints=["0123456789abcdef"], count=3, status="open", reason_code=secret + " with spaces")
    rec = json.loads(open(os.path.join(st, "ledger.jsonl")).read())
    blob = json.dumps(rec)
    assert secret not in blob and "file text" not in blob and "free text" not in blob
    assert "evidence" not in rec and "content" not in rec and "secret" not in rec and "text" not in rec
    assert rec["fingerprints"] == ["0123456789abcdef"] and rec["count"] == 3 and rec["status"] == "open"
    assert "reason_code" not in rec  # a string that is not a plain code is dropped


def test_values_are_cleaned_and_lines_stay_under_4kb(st):
    lg = ledger.Ledger(st)
    lg.append("check", checks=["PG-SEC-%03d" % i for i in range(2000)], host="ex‮ample.com")
    line = open(os.path.join(st, "ledger.jsonl")).read().splitlines()[0]
    assert len(line.encode()) <= 4096
    rec = json.loads(line)
    assert "‮" not in rec.get("host", "")
    assert rec.get("truncated") is True


def test_rotation_at_five_megabytes_keeps_one_generation(st):
    path = os.path.join(st, "ledger.jsonl")
    with open(path, "w") as fh:
        fh.write("x" * (5 * 1024 * 1024 + 1))
    os.chmod(path, 0o600)
    lg = ledger.Ledger(st)
    lg.append("check", count=1)
    assert os.path.getsize(path + ".1") > 5 * 1024 * 1024
    assert len(open(path).read().splitlines()) == 1
    # a second rotation replaces the single old generation
    with open(path, "a") as fh:
        fh.write("y" * (5 * 1024 * 1024))
    lg.append("check", count=2)
    assert open(path + ".1").read(1) in ("{", "y")
    assert sorted(f for f in os.listdir(st)) == ["ledger.jsonl", "ledger.jsonl.1"]
    assert stat.S_IMODE(os.stat(path + ".1").st_mode) == 0o600


def test_read_returns_records_and_skips_malformed_lines(st):
    lg = ledger.Ledger(st)
    lg.append("check", count=1)
    with open(os.path.join(st, "ledger.jsonl"), "a") as fh:
        fh.write("not json\n[1,2]\n")
    lg.append("fix", count=2)
    recs = lg.read()
    assert [r["event"] for r in recs] == ["check", "fix"]
    assert [r["event"] for r in lg.read(limit=1)] == ["fix"]


def test_clear_removes_both_generations(st):
    lg = ledger.Ledger(st)
    lg.append("check")
    open(os.path.join(st, "ledger.jsonl.1"), "w").write("old\n")
    assert lg.clear() == 2
    assert os.listdir(st) == [] and lg.read() == []
    assert lg.clear() == 0


def test_no_state_means_no_ledger_and_no_error():
    lg = ledger.Ledger(None)
    assert lg.append("check", count=1) is False
    assert lg.read() == [] and lg.clear() == 0


def test_symlinked_ledger_is_refused_and_does_not_raise(st, tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("keep\n")
    os.symlink(victim, os.path.join(st, "ledger.jsonl"))
    lg = ledger.Ledger(st)
    assert lg.append("check", count=1) is False
    assert victim.read_text() == "keep\n"
    assert lg.read() == []


def test_session_id_is_cleaned(st):
    lg = ledger.Ledger(st, session="abc‮/../../x " + "z" * 200)
    lg.append("check")
    rec = json.loads(open(os.path.join(st, "ledger.jsonl")).read())
    assert rec["session"].isascii() and len(rec["session"]) <= 64 and "‮" not in rec["session"]
