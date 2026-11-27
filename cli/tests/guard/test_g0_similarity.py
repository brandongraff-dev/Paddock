# SPDX-License-Identifier: AGPL-3.0-or-later
"""support/similarity.py (contract D6): skips silently without rule files, flags coincident patterns."""
from __future__ import annotations

import re
from dataclasses import dataclass

from support import similarity


def test_no_rule_files_is_silent_and_empty(tmp_path):
    env = {"PADDOCK_GUARD_SIMILARITY_DIRS": str(tmp_path / "nothing"), "HOME": str(tmp_path)}
    matches, n_rules, n_files = similarity.run({"gh": r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"}, env)
    assert matches == []
    out = similarity.report([], 0, 0)
    assert "nothing was compared" in out


def test_gitleaks_toml_and_detect_secrets_source_are_read_and_compared(tmp_path):
    (tmp_path / "gitleaks.toml").write_text(
        '[[rules]]\nid = "github-pat"\nregex = \'\'\'ghp_[0-9a-zA-Z]{36}\'\'\'\n'
        '[[rules]]\nid = "other"\nregex = \'\'\'completely-different-[a-z]+\'\'\'\n')
    (tmp_path / "plugin.py").write_text("import re\nRX = re.compile(r'AKIA[0-9A-Z]{16}')\n")
    rules = similarity.load_rules([tmp_path / "gitleaks.toml", tmp_path / "plugin.py"])
    assert {r.rule_id for r in rules} == {"github-pat", "other", "compile@2"}
    fams = {"github": r"\bghp_[0-9a-zA-Z]{36}\b", "aws": r"\bAKIA[0-9A-Z]{16}\b", "unrelated": r"zzz-[0-9]{3}-qqq"}
    got = {(m.family, m.other.rule_id) for m in similarity.compare(fams, rules)}
    assert got == {("github", "github-pat"), ("aws", "compile@2")}
    text = similarity.report(similarity.compare(fams, rules), len(rules), 2)
    assert "github is" in text and "similar" in text


def test_discovery_honours_the_environment_directory(tmp_path):
    d = tmp_path / "rules"
    d.mkdir()
    (d / "gitleaks.toml").write_text("[[rules]]\nid='x'\nregex='abc'\n")
    files = similarity.discover_rule_files({"PADDOCK_GUARD_SIMILARITY_DIRS": str(d), "HOME": str(tmp_path)})
    assert (d / "gitleaks.toml") in files


def test_families_from_objects_accepts_compiled_patterns():
    @dataclass
    class Fam:
        name: str
        regex: re.Pattern

    assert similarity.families_from_objects([Fam("a", re.compile("x+y"))]) == {"a": "x+y"}


def test_hostile_rule_files_are_skipped(tmp_path):
    (tmp_path / "gitleaks.toml").write_text("not toml [[[")
    (tmp_path / "bad.py").write_text("def broken(:\n")
    assert similarity.load_rules([tmp_path / "gitleaks.toml", tmp_path / "bad.py"]) == []
