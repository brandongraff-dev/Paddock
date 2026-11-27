# SPDX-License-Identifier: AGPL-3.0-or-later
"""Inline suppressions and the baseline file (contract 3.10, D13)."""
from __future__ import annotations

import json
import os

import pytest

from paddock_cli.guard import errors, files, model, suppress
from paddock_cli.guard.files import FileView
from support import gitenv


def _fv(text, path="a.py"):
    return FileView(path=path, text=text, size=len(text))


@pytest.mark.parametrize("line", [
    "x = 1  # paddock:ignore PG-WEB-005 local development server only",
    "x = 1  // paddock:ignore PG-WEB-005 local development server only",
    "x = 1  -- paddock:ignore PG-WEB-005 local development server only",
    "x = 1  /* paddock:ignore PG-WEB-005 local development server only */",
    "<div></div> <!-- paddock:ignore PG-WEB-005 local development server only -->",
    "# paddock:ignore PG-WEB-005 local development server only",
])
def test_valid_inline_suppression_in_every_comment_style(line):
    sups, notes = suppress.scan_suppressions(_fv(line + "\n"))
    assert notes == []
    assert len(sups) == 1 and sups[0].check_id == "PG-WEB-005" and sups[0].scope == "line" and sups[0].line == 1
    assert sups[0].reason == "local development server only"


def test_reason_is_required_and_at_least_eight_characters():
    for text in ("# paddock:ignore PG-WEB-005\n", "# paddock:ignore PG-WEB-005 short\n", "# paddock:ignore PG-WEB-005 1234567\n"):
        sups, notes = suppress.scan_suppressions(_fv(text))
        assert sups == [] and len(notes) == 1 and notes[0].startswith("PG-META-001")
    sups, notes = suppress.scan_suppressions(_fv("# paddock:ignore PG-WEB-005 12345678\n"))
    assert len(sups) == 1 and notes == []


def test_bad_check_id_is_malformed():
    sups, notes = suppress.scan_suppressions(_fv("# paddock:ignore not-an-id this is a long enough reason\n"))
    assert sups == [] and notes and notes[0].startswith("PG-META-001")


def test_marker_outside_a_comment_is_not_a_suppression():
    sups, notes = suppress.scan_suppressions(_fv('s = "paddock:ignore PG-WEB-005 inside a string literal"\n'))
    assert sups == [] and notes == []


def test_ignore_file_only_in_the_first_ten_lines():
    body = ["x = 1"] * 9
    sups, notes = suppress.scan_suppressions(_fv("\n".join(body + ["# paddock:ignore-file PG-WEB-005 generated file here"]) + "\n"))
    assert len(sups) == 1 and sups[0].scope == "file"
    sups, notes = suppress.scan_suppressions(_fv("\n".join(body + ["x", "# paddock:ignore-file PG-WEB-005 generated file here"]) + "\n"))
    assert sups == [] and notes and "first 10 lines" in notes[0]


def test_matching_line_and_line_above_and_file_scope():
    text = ("a = 1\n# paddock:ignore PG-WEB-005 reason is long enough\nb = 2\nc = 3  # paddock:ignore PG-WEB-007 on the same line ok\n"
            "# paddock:ignore-file PG-SEC-001 whole file is a fixture\n")
    sups, _ = suppress.scan_suppressions(_fv(text))
    assert suppress.match(sups, "PG-WEB-005", 3) is not None       # comment directly above
    assert suppress.match(sups, "PG-WEB-005", 2) is not None       # comment on the line itself
    assert suppress.match(sups, "PG-WEB-005", 4) is None
    assert suppress.match(sups, "PG-WEB-007", 4) is not None
    assert suppress.match(sups, "PG-WEB-007", 5) is not None  # directly below the comment's line
    assert suppress.match(sups, "PG-SEC-001", 100) is not None and suppress.match(sups, "PG-SEC-001", None) is not None
    assert suppress.match(sups, "PG-WEB-005", None) is None
    assert suppress.match(sups, "PG-WEB-999", 3) is None


def test_reason_text_is_cleaned_and_capped_in_the_record():
    sups, _ = suppress.scan_suppressions(_fv("# paddock:ignore PG-WEB-005 " + "‮ reason \x1b[31m" + "x" * 500 + "\n"))
    assert len(sups) == 1 and "‮" not in sups[0].reason and "\x1b" not in sups[0].reason and len(sups[0].reason) <= 200


def test_scan_is_bounded_on_a_long_line():
    sups, notes = suppress.scan_suppressions(_fv("# paddock:ignore PG-WEB-005 " + "x" * 100000 + "\n" + "y" * 5000000))
    assert len(sups) <= 1


# ---- baseline ---------------------------------------------------------------------------------
def _finding(fp="0123456789abcdef", check="PG-WEB-005", file="a.py"):
    return model.GuardFinding(
        fingerprint=fp, check_id=check, title="t", severity="high", confidence="high", blocking=True, file=file,
        line=1, end_line=1, evidence="", message="t", fix_hint="", agent_prompt="", fixer=None, cwe=None,
        tier_evidence="unmeasured")


def test_baseline_create_serialise_and_load(tmp_path):
    b = suppress.create_baseline([_finding(), _finding("fedcba9876543210", "PG-SEC-001", "b.js")], today="2026-11-27")
    doc = json.loads(suppress.baseline_json(b))
    assert doc["schema"] == "paddock-guard/baseline/v1" and doc["created"] == "2026-11-27"
    assert [e["fingerprint"] for e in doc["entries"]] == ["0123456789abcdef", "fedcba9876543210"]
    assert set(doc["entries"][0]) == {"fingerprint", "check_id", "file", "reason"}
    suppress.write_baseline(str(tmp_path), b)
    got, notes = suppress.load_baseline(str(tmp_path))
    assert notes == [] and got.fingerprints == {"0123456789abcdef", "fedcba9876543210"}


def test_baseline_update_removes_entries_that_no_longer_match():
    b = suppress.create_baseline([_finding(), _finding("fedcba9876543210")], today="2026-11-27")
    u = suppress.update_baseline(b, [_finding("fedcba9876543210")])
    assert u.fingerprints == {"fedcba9876543210"} and u.created == "2026-11-27"
    u = suppress.update_baseline(b, [_finding("fedcba9876543210"), _finding("1111111111111111")])
    assert "1111111111111111" not in u.fingerprints  # update never adds


def test_baseline_missing_is_none_and_malformed_is_noted_not_trusted(tmp_path):
    assert suppress.load_baseline(str(tmp_path)) == (None, [])
    (tmp_path / ".paddock").mkdir()
    for text in ("{not json", json.dumps({"schema": "other", "entries": []}),
                 json.dumps({"schema": "paddock-guard/baseline/v1", "entries": [{"fingerprint": "xyz", "check_id": "a", "file": "b", "reason": "c"}]}),
                 json.dumps({"schema": "paddock-guard/baseline/v1", "entries": "no"}), "[" * 200000):
        (tmp_path / ".paddock" / "baseline.json").write_text(text)
        got, notes = suppress.load_baseline(str(tmp_path))
        assert got is None and notes and "baseline" in notes[0].lower()


def test_baseline_symlink_is_not_read(tmp_path):
    outside = tmp_path / "o.json"
    outside.write_text(json.dumps({"schema": "paddock-guard/baseline/v1", "entries": []}))
    (tmp_path / "p" / ".paddock").mkdir(parents=True)
    os.symlink(outside, tmp_path / "p" / ".paddock" / "baseline.json")
    got, notes = suppress.load_baseline(str(tmp_path / "p"))
    assert got is None and notes


def test_baseline_from_a_git_ref(repo):
    (repo / ".paddock").mkdir()
    b = suppress.create_baseline([_finding()], today="2026-11-27")
    suppress.write_baseline(str(repo), b)
    sha = gitenv.commit_all(repo)
    (repo / ".paddock" / "baseline.json").write_text(suppress.baseline_json(suppress.create_baseline([], today="2026-11-27")))
    got, notes = suppress.load_baseline(str(repo), ref=sha)
    assert got.fingerprints == {"0123456789abcdef"}
    got, notes = suppress.load_baseline(str(repo))
    assert got.fingerprints == set()


def test_write_baseline_creates_paddock_gitignore_first_and_refuses_symlinked_dir(tmp_path):
    root = tmp_path / "r"
    root.mkdir()
    suppress.write_baseline(str(root), suppress.create_baseline([_finding()], today="2026-11-27"))
    gi = (root / ".paddock" / ".gitignore").read_text()
    assert "cache/" in gi and "ledger.jsonl*" in gi and "backups/" in gi
    outside = tmp_path / "outside"
    outside.mkdir()
    other = tmp_path / "o"
    other.mkdir()
    os.symlink(outside, other / ".paddock")
    with pytest.raises(errors.GuardError):
        suppress.write_baseline(str(other), suppress.create_baseline([], today="2026-11-27"))
    assert list(outside.iterdir()) == []


def test_baseline_entry_text_is_cleaned():
    b = suppress.create_baseline([_finding(file="a‮b.py")], today="2026-11-27", reason="legacy \x1b[31m finding")
    e = b.entries[0]
    assert "‮" not in e.file and "\x1b" not in e.reason


def test_baseline_with_too_many_entries_is_rejected(tmp_path):
    (tmp_path / ".paddock").mkdir()
    entries = [{"fingerprint": "%016x" % i, "check_id": "PG-A-001", "file": "f", "reason": "r"} for i in range(10001)]
    (tmp_path / ".paddock" / "baseline.json").write_text(json.dumps({"schema": "paddock-guard/baseline/v1", "created": "2026-01-01", "entries": entries}))
    got, notes = suppress.load_baseline(str(tmp_path))
    assert got is None and notes


def test_files_module_still_reads_through_the_safe_reader():
    assert hasattr(files, "read_file")
