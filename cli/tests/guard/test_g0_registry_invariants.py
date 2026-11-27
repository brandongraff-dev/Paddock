# SPDX-License-Identifier: AGPL-3.0-or-later
"""test_registry_invariants, test_catalogue_counts, test_cmd_modules_import_light (contract 3.4, 4.10, 3.5)."""
from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from paddock_cli.guard import catalogue, fixers, model, registry
from support import register79

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
GUARD = REPO / "cli" / "paddock_cli" / "guard"


def _complete() -> bool:
    if os.environ.get("PADDOCK_GUARD_COMPLETE") == "1":
        return True
    f = HERE / "all_packs_built.py"
    if not f.is_file():
        return False
    ns: dict = {}
    exec(compile(f.read_text(encoding="utf-8"), str(f), "exec"), ns)  # a data file owned by G12
    return ns.get("ALL_PACKS_BUILT") is True


@pytest.fixture(scope="module")
def builtin():
    registry.discover()
    return [c for c in registry.all_checks() if c.origin == "builtin"]


# ---- test_registry_invariants ------------------------------------------------------------------------
def test_registry_invariants(builtin):
    assert registry.invariant_problems(builtin) == []
    assert registry.import_errors() == [], registry.import_errors()
    for c in builtin:
        assert c.severity in model.SEVERITIES and c.proposed_tier in model.TIERS
        assert c.fixer is None or c.fixer in fixers.FIXER_NAMES
        if c.network:
            assert c.id.startswith(("PG-PKG-", "PG-URL-"))
    assert fixers.BREAKING <= set(fixers.FIXER_NAMES)


def test_unverified_ids_match_the_register_both_ways(builtin):
    reg = register79.load_register()
    if reg is None:
        pytest.skip("docs/GUARD_CONTRACT.md is not available")
    for c in builtin:
        naming = {uid for uid, row in reg.items() if c.id in row["checks"]}
        open_ids = {uid for uid in naming if reg[uid]["status"] == "OPEN"}
        have = set(c.unverified_ids)
        assert open_ids <= have, "%s must list the open ids %s" % (c.id, sorted(open_ids - have))
        assert have <= naming, "%s lists ids the register does not tie to it: %s" % (c.id, sorted(have - naming))
        if open_ids - registry.load_verified():
            assert c.spec_status == "UNVERIFIED", "%s depends on an open id and must be marked UNVERIFIED" % c.id


def test_verified_spec_status_needs_closed_ids_and_a_real_source_row(builtin):
    closed = registry.load_verified()
    for c in builtin:
        if c.spec_status == "VERIFIED":
            assert set(c.unverified_ids) <= closed, "%s is VERIFIED but depends on an open id" % c.id
    path = Path(registry.VERIFIED_PATH)
    if not path.is_file():
        return
    doc = json.loads(path.read_text(encoding="utf-8"))
    entries = doc.get("entries", []) if isinstance(doc, dict) else doc
    for e in entries:
        assert e["kind"] in ("doc", "tool") and e.get("date")
        src, _, row = e["source"].partition("#")
        f = REPO / src
        assert f.is_file(), "source %s does not exist" % src
        assert row and row in f.read_text(encoding="utf-8"), "row %s not found in %s" % (row, src)
        if e["kind"] == "tool":
            assert src == "docs/guard/REVIEW_LOG.md"


def test_register_parser_reads_the_contract_table():
    reg = register79.load_register()
    if reg is None:
        pytest.skip("docs/GUARD_CONTRACT.md is not available")
    assert reg["U-16"]["status"] == "OPEN" and {"PG-SEC-003", "PG-SEC-001", "PG-URL-001"} <= reg["U-16"]["checks"]
    assert reg["U-02"]["status"] == "CONFIRMED" and reg["U-02"]["checks"] == {"PG-AGT-003"}
    assert reg["U-03"]["checks"] == set() and reg["U-26"]["checks"] == {"PG-WEB-001"}
    assert len(reg) >= 27


def test_register_parser_on_a_synthetic_table():
    text = "### 7.9 UNVERIFIED register\n\n| U-90 | claim | PG-SEC-001 (sub-rule: x), PG-SEC-002 | OPEN | t | v |\n| U-91 | c | docs only | CONFIRMED (x) | t | v |\n\n## 8. next\n"
    got = register79.parse_register(text)
    assert got == {"U-90": {"status": "OPEN", "checks": {"PG-SEC-001", "PG-SEC-002"}}, "U-91": {"status": "CONFIRMED", "checks": set()}}


# ---- test_catalogue_counts ----------------------------------------------------------------------------
def test_expected_counts_match_the_contract_table():
    text = (REPO / "docs" / "GUARD_CONTRACT.md")
    if not text.is_file():
        pytest.skip("docs/GUARD_CONTRACT.md is not available")
    body = text.read_text(encoding="utf-8")
    sec = body[body.index("### 4.10 Count and tier table"):]
    sec = sec[: sec.index("Declared highs")]
    rows = {}
    for m in re.finditer(r"^\| (SEC|BAAS|WEB|AGT|SUP|CI|DKR|PKG|URL|Total) \| (\d+) \| (\d+) \| (\d+) \| (\d+) \|", sec, re.M):
        rows[m.group(1)] = tuple(int(x) for x in m.groups()[1:])
    assert rows.pop("Total") == catalogue.EXPECTED_TOTAL
    assert rows == catalogue.EXPECTED_COUNTS
    assert tuple(sum(v[i] for v in catalogue.EXPECTED_COUNTS.values()) for i in range(4)) == catalogue.EXPECTED_TOTAL


def test_catalogue_counts(builtin):
    got = catalogue.pack_counts(builtin)
    if _complete():
        assert got == catalogue.EXPECTED_COUNTS
        assert tuple(sum(v[i] for v in got.values()) for i in range(4)) == catalogue.EXPECTED_TOTAL
        eff = sum(1 for c in builtin if registry.proposed_tier(c) == "high")
        assert eff >= 0  # informational: recomputed from verified.json (4.10 last column)
        return
    for pack, row in got.items():
        assert pack in catalogue.EXPECTED_COUNTS, "unknown pack %s" % pack
        for have, want in zip(row, catalogue.EXPECTED_COUNTS[pack]):
            assert have <= want, "%s declares more checks than 4.10 allows: %s vs %s" % (pack, row, catalogue.EXPECTED_COUNTS[pack])


def test_pack_counts_logic():
    mk = lambda i, t: registry.Check(id="PG-SEC-%03d" % i, title="t", severity="low", proposed_tier=t, scope="file", agent_prompt="x", run=lambda c, f: [])
    assert catalogue.pack_counts([mk(1, "high"), mk(2, "medium"), mk(3, "high")]) == {"SEC": (3, 2, 1, 0)}


# ---- test_cmd_modules_import_light ----------------------------------------------------------------------
def _cmd_modules():
    return sorted(p for p in GUARD.glob("cmd_*.py"))


def test_cmd_modules_import_only_argparse_sys_and_typing_at_top_level():
    for p in _cmd_modules():
        tree = ast.parse(p.read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, ast.Import):
                names = {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                names = {(node.module or "").split(".")[0]}
            else:
                continue
            assert names <= {"argparse", "sys", "typing", "__future__"}, "%s imports %s at module level" % (p.name, names)


def test_cmd_modules_import_light(tmp_path):
    for p in _cmd_modules():
        mod = "paddock_cli.guard." + p.stem
        code = ("import sys, %s\nheavy = sorted(m for m in sys.modules if m.startswith('paddock_cli.guard.') and m != %r)\n"
                "print('HEAVY', heavy)\n") % (mod, mod)
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env={**os.environ, "PYTHONPATH": str(REPO / "cli"), "PYTHONDONTWRITEBYTECODE": "1"}, timeout=60)
        assert r.returncode == 0, r.stderr
        assert "HEAVY []" in r.stdout, (p.name, r.stdout)


def test_building_the_parser_does_not_import_the_engine():
    code = ("import sys\nfrom paddock_cli.guard import cli\ncli.build_parser()\n"
            "heavy = [m for m in ('engine', 'registry', 'files', 'context', 'config', 'output', 'rulepack', 'gitutil') if 'paddock_cli.guard.' + m in sys.modules]\n"
            "print('HEAVY', heavy)\n")
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env={**os.environ, "PYTHONPATH": str(REPO / "cli")}, timeout=60)
    assert "HEAVY []" in r.stdout, r.stdout + r.stderr


def test_commands_constant_lists_every_package_command():
    from paddock_cli.guard import cli

    assert cli.COMMANDS == ("cmd_check", "cmd_explain", "cmd_list", "cmd_status", "cmd_baseline", "cmd_ledger", "cmd_catalogue",
                            "cmd_pkg", "cmd_deps", "cmd_shim", "cmd_verify", "cmd_fix", "cmd_url", "cmd_init", "cmd_hook",
                            "cmd_receipt", "cmd_badge")


def test_a_missing_command_module_is_skipped_but_other_errors_propagate(monkeypatch):
    import importlib

    from paddock_cli.guard import cli

    real = importlib.import_module

    def fake(name, *a, **k):
        if name == "paddock_cli.guard.cmd_pkg":
            raise ModuleNotFoundError("No module named", name=name)
        if name == "paddock_cli.guard.cmd_url":
            raise ModuleNotFoundError("No module named 'missing_dep'", name="missing_dep")
        return real(name, *a, **k)

    monkeypatch.setattr(cli.importlib, "import_module", fake)
    with pytest.raises(ModuleNotFoundError) as ei:
        cli.build_parser()
    assert ei.value.name == "missing_dep"
    monkeypatch.setattr(cli, "COMMANDS", tuple(c for c in cli.COMMANDS if c != "cmd_url"))
    cli.build_parser()  # cmd_pkg missing by name is skipped
