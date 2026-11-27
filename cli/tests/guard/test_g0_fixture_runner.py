# SPDX-License-Identifier: AGPL-3.0-or-later
"""The generic fixture runner (contract 4.0.3, 3.12): 3 TP and 3 NEG per check, variants, known misses."""
from __future__ import annotations

import json
from pathlib import Path


from paddock_cli.guard import registry
from support import fixture_runner, testchecks

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "checks"


def _mk(root: Path, name: str, files: dict[str, str], expect: dict | None = None, note: str | None = None):
    d = root / name
    for rel, text in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    if expect is not None:
        (d / "expect.json").write_text(json.dumps(expect))
    if note is not None:
        (d / "NOTE.md").write_text(note)
    return d


def _good_tree(tmp_path, cid="PG-TST-001"):
    root = tmp_path / "fx" / cid
    for i in range(1, 4):
        _mk(root, "tp-%d" % i, {"src/a.txt": "    FORBIDDEN_ONE%d\n" % i}, {"check": cid, "files": ["src/a.txt"], "fingerprint_stable_under_line_shift": True})
        _mk(root, "neg-%d" % i, {"src/a.txt": "harmless %d\n" % i}, note="Plain text with no forbidden word.")
    _mk(root, "fn-1", {"a.txt": "FORBIDDEN_AB\n"}, note="Known miss: the suffix is two letters, below the pattern minimum.")
    return root.parent


def test_discovery_and_counts(tmp_path):
    root = _good_tree(tmp_path)
    found = fixture_runner.discover(root)
    kinds = found["PG-TST-001"]
    assert len(kinds["tp"]) == 3 and len(kinds["neg"]) == 3 and len(kinds["fn"]) == 1
    assert fixture_runner.count_problems("PG-TST-001", kinds) == []
    kinds["tp"].pop()
    assert fixture_runner.count_problems("PG-TST-001", kinds)


def test_runner_passes_a_correct_check_through_every_variant(tmp_path, registry_sandbox, dev_tiers):
    testchecks.register_all()
    root = _good_tree(tmp_path)
    kinds = fixture_runner.discover(root)["PG-TST-001"]
    for kind in ("tp", "neg", "fn"):
        for case in kinds[kind]:
            assert fixture_runner.run_case(case, "PG-TST-001", kind, tmp_path / "work") == [], (kind, case.name)


def test_runner_rejects_a_tp_that_does_not_fire_and_a_neg_that_does(tmp_path, registry_sandbox, dev_tiers):
    testchecks.register_all()
    root = tmp_path / "fx" / "PG-TST-001"
    tp = _mk(root, "tp-1", {"a.txt": "nothing to see\n"}, {"check": "PG-TST-001", "files": ["a.txt"]})
    neg = _mk(root, "neg-1", {"a.txt": "FORBIDDEN_ONE\n"}, note="This one fires, so it is not a negative.")
    nonote = _mk(root, "neg-2", {"a.txt": "fine\n"})
    assert "did not fire" in " ".join(fixture_runner.run_case(tp, "PG-TST-001", "tp", tmp_path / "w"))
    assert "fired on a neg" in " ".join(fixture_runner.run_case(neg, "PG-TST-001", "neg", tmp_path / "w"))
    assert "NOTE.md" in " ".join(fixture_runner.run_case(nonote, "PG-TST-001", "neg", tmp_path / "w"))


def test_runner_requires_expect_json_and_wrong_files_or_check_are_problems(tmp_path, registry_sandbox, dev_tiers):
    testchecks.register_all()
    root = tmp_path / "fx" / "PG-TST-001"
    no_expect = _mk(root, "tp-1", {"a.txt": "FORBIDDEN_ONE\n"})
    wrong_files = _mk(root, "tp-2", {"a.txt": "FORBIDDEN_ONE\n"}, {"check": "PG-TST-001", "files": ["other.txt"]})
    wrong_check = _mk(root, "tp-3", {"a.txt": "FORBIDDEN_ONE\n"}, {"check": "PG-TST-002", "files": ["a.txt"]})
    assert "expect.json" in " ".join(fixture_runner.run_case(no_expect, "PG-TST-001", "tp", tmp_path / "w"))
    assert "expect.json wants" in " ".join(fixture_runner.run_case(wrong_files, "PG-TST-001", "tp", tmp_path / "w"))
    assert "expect.json check" in " ".join(fixture_runner.run_case(wrong_check, "PG-TST-001", "tp", tmp_path / "w"))


def test_runner_detects_a_check_that_breaks_on_a_variant(tmp_path, registry_sandbox, dev_tiers):
    from paddock_cli.guard import model
    from paddock_cli.guard.registry import Check

    def only_first_line(ctx, fv):
        return [model.Hit(file=fv.path, line=1, anchor="first")] if fv.lines and fv.lines[0].startswith("FORBIDDEN") else []

    registry.register(Check(id="PG-TST-030", title="Fragile", severity="high", proposed_tier="high", scope="file",
                            globs=("*.txt",), agent_prompt="x", run=only_first_line))
    root = tmp_path / "fx" / "PG-TST-030"
    tp = _mk(root, "tp-1", {"a.txt": "FORBIDDEN\n"}, {"check": "PG-TST-030", "files": ["a.txt"]})
    probs = fixture_runner.run_case(tp, "PG-TST-030", "tp", tmp_path / "w")
    assert any("leading-blank-line variant" in p for p in probs) and not any("crlf" in p or "bom variant" in p for p in probs)


def test_runner_checks_fingerprint_stability_when_pinned(tmp_path, registry_sandbox, dev_tiers):
    from paddock_cli.guard import model
    from paddock_cli.guard.registry import Check

    def by_line_anchor(ctx, fv):
        return [model.Hit(file=fv.path, line=i, anchor="line-%d" % i) for i, ln in enumerate(fv.lines, 1) if "FORBIDDEN" in ln]

    registry.register(Check(id="PG-TST-031", title="Line anchored", severity="high", proposed_tier="high", scope="file",
                            globs=("*.txt",), agent_prompt="x", run=by_line_anchor))
    root = tmp_path / "fx" / "PG-TST-031"
    tp = _mk(root, "tp-1", {"a.txt": "FORBIDDEN\n"}, {"check": "PG-TST-031", "files": ["a.txt"], "fingerprint_stable_under_line_shift": True})
    probs = fixture_runner.run_case(tp, "PG-TST-031", "tp", tmp_path / "w")
    assert any("fingerprints changed" in p for p in probs)


def test_git_stanza_fixtures_work_through_the_runner(tmp_path, registry_sandbox, dev_tiers):
    from paddock_cli.guard import model
    from paddock_cli.guard.registry import Check

    def untracked_env(ctx, fv):
        return [model.Hit(file=fv.path, line=1, anchor="tracked-env")] if ctx.tracked(fv.path) else []

    registry.register(Check(id="PG-TST-032", title="Tracked dotenv", severity="high", proposed_tier="high", scope="file",
                            globs=("**/.env*",), agent_prompt="x", run=untracked_env))
    root = tmp_path / "fx" / "PG-TST-032"
    tp = _mk(root, "tp-1", {"dot-env": "X=1\n"}, {"check": "PG-TST-032", "files": [".env"], "git": {"init": True, "tracked": [".env"], "ignored": []}})
    neg = _mk(root, "neg-1", {"dot-env": "X=1\n", "dot-gitignore": ".env\n"}, {"git": {"init": True, "tracked": [".gitignore"], "ignored": [".env"]}},
              note="Not tracked and ignored.")
    assert fixture_runner.run_case(tp, "PG-TST-032", "tp", tmp_path / "w") == []
    assert fixture_runner.run_case(neg, "PG-TST-032", "neg", tmp_path / "w") == []


def test_variants_transform_text_as_named():
    v = fixture_runner.variants()
    assert v["crlf"]("a\nb\n") == "a\r\nb\r\n" and v["bom"]("x").startswith("﻿") and v["leading-blank-line"]("x") == "\nx"
    assert v["tabs"]("a\n    b\n        c\n  d\n") == "a\n\tb\n\t\tc\n\td\n"


def test_every_registered_builtin_check_has_three_tp_and_three_neg_fixtures():
    registry.discover()
    found = fixture_runner.discover(FIXTURES)
    problems = []
    for c in registry.all_checks():
        if c.origin != "builtin" or c.id.startswith("PG-TST"):
            continue
        problems += fixture_runner.count_problems(c.id, found.get(c.id, {"tp": [], "neg": [], "fn": []}))
    assert problems == []


def test_real_fixtures_behave_through_the_runner(tmp_path, dev_tiers):
    """Runs every committed tp, neg and fn fixture for registered checks (vacuous until checks exist)."""
    registry.discover()
    found = fixture_runner.discover(FIXTURES)
    problems = []
    for c in registry.all_checks():
        kinds = found.get(c.id)
        if not kinds or c.origin != "builtin":
            continue
        for kind in ("tp", "neg", "fn"):
            for case in kinds[kind]:
                problems += fixture_runner.run_case(case, c.id, kind, tmp_path / "w")
    assert problems == []


def test_committed_fixtures_never_store_token_shaped_literals():
    assert fixture_runner.literal_token_problems(Path(__file__).resolve().parent / "fixtures") == []


def test_the_literal_token_scan_flags_a_planted_token(tmp_path):
    (tmp_path / "a.txt").write_text("key = " + "gh" + "p_" + "A1b2C3d4" * 5 + "\n")
    (tmp_path / "ok.txt").write_text("AKIA" + "IOSFODNN7EXAMPLE\n")
    probs = fixture_runner.literal_token_problems(tmp_path)
    assert len(probs) == 1 and "a.txt" in probs[0]
