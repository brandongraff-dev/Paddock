"""scripts/export_changelog.py: CHANGELOG.md -> the data the dashboard's About page shows.

Run from the repo root:  pytest -q scripts/tests/test_changelog.py
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("export_changelog", ROOT / "scripts" / "export_changelog.py")
ec = importlib.util.module_from_spec(spec)
sys.modules["export_changelog"] = ec
spec.loader.exec_module(ec)

GOOD = """# Changelog

## State of the app

| Area | State | Notes |
|---|---|---|
| Install on **Windows** | unverified | Never run on a real PC. See [the docs](docs/x.md). |
| Detection | working | `207` cases. |

## [Unreleased]

### Added

- One thing, with **bold** and a [link](https://example.com).
- A second thing
  that wraps onto a continuation line.

### Known issues

- A caveat.

## [1.2.3] - 2026-02-01

### Fixed

- Something.

## Earlier work

- Old news.
"""


def test_the_real_changelog_parses_and_the_generated_file_is_current():
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "export_changelog.py"), "--check"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr + r.stdout


def test_the_real_changelog_is_honest_about_the_unproven_parts():
    data = ec.parse((ROOT / "CHANGELOG.md").read_text())
    by = {r["area"]: r["state"] for r in data["state"]}
    assert by["Install on Windows (Paddock Setup)"] == "unverified"
    assert by["Prebuilt images and release downloads"] == "not released"
    assert data["releases"][0]["version"] == "Unreleased"
    assert {r["state"] for r in data["state"]} <= set(ec.STATES)
    kinds = {s["kind"] for s in data["releases"][0]["sections"]}
    assert {"Added", "Security", "Known issues"} <= kinds


def test_parses_state_releases_and_history_and_strips_markdown():
    d = ec.parse(GOOD)
    assert d["state"] == [
        {"area": "Install on Windows", "state": "unverified", "notes": "Never run on a real PC. See the docs."},
        {"area": "Detection", "state": "working", "notes": "207 cases."},
    ]
    assert [r["version"] for r in d["releases"]] == ["Unreleased", "1.2.3"]
    assert d["releases"][1]["date"] == "2026-02-01" and d["releases"][0]["date"] is None
    added = d["releases"][0]["sections"][0]
    assert added["kind"] == "Added"
    assert added["items"] == ["One thing, with bold and a link.", "A second thing that wraps onto a continuation line."]
    assert d["other"] == [{"title": "Earlier work", "items": ["Old news."]}]


@pytest.mark.parametrize("mutate,msg", [
    (lambda t: t.replace("| unverified |", "| mostly fine |"), "not one of"),
    (lambda t: t.replace("## [1.2.3] - 2026-02-01", "## [1.2.3]"), "needs a date"),
    (lambda t: t.replace("### Fixed", "### Fixes"), "unknown section"),
    (lambda t: t.replace("## [1.2.3] - 2026-02-01", "## [v1.2]"), "unrecognised release heading"),
    (lambda t: t.replace("| Detection | working | `207` cases. |", "| Detection | working |"), "3 cells"),
    (lambda t: t.replace("## State of the app", "## Status"), "no 'State of the app'"),
    (lambda t: t.replace("## [Unreleased]\n\n### Added\n\n- One thing", "## [Unreleased]\n\n- Orphan bullet\n\n### Added\n\n- One thing"), "under a ### section"),
])
def test_rejects_malformed_changelogs_with_a_clear_message(mutate, msg):
    with pytest.raises(ec.ChangelogError, match=msg):
        ec.parse(mutate(GOOD))


def test_requires_at_least_one_release_section():
    with pytest.raises(ec.ChangelogError, match="no release section"):
        ec.parse("## State of the app\n\n| Area | State | Notes |\n|---|---|---|\n| A | working | n |\n")


def test_check_fails_when_the_generated_file_is_stale(tmp_path, monkeypatch):
    out = tmp_path / "changelog.generated.ts"
    monkeypatch.setattr(ec, "OUT", out)
    monkeypatch.setattr(ec, "ROOT", tmp_path)
    src = tmp_path / "CHANGELOG.md"
    src.write_text(GOOD)
    monkeypatch.setattr(ec, "SRC", src)
    assert ec.main(["--check"]) == 1                    # nothing generated yet
    assert ec.main([]) == 0 and out.exists()
    assert ec.main(["--check"]) == 0
    src.write_text(GOOD.replace("Old news.", "Older news."))
    assert ec.main(["--check"]) == 1                    # the source changed: regenerate


def test_generated_ts_is_deterministic_and_marked_generated():
    text = ec.render(ec.parse(GOOD))
    assert text == ec.render(ec.parse(GOOD))
    assert text.startswith("// GENERATED from CHANGELOG.md") and "export const CHANGELOG: Changelog" in text
