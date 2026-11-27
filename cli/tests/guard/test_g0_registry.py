# SPDX-License-Identifier: AGPL-3.0-or-later
"""Registry (contract 3.3, 3.4, 4.0.8, D8): checks, tiers, discovery, invariants."""
from __future__ import annotations

import json
import sys
import types

import pytest

from paddock_cli.guard import GUARD_VERSION, errors, model, registry
from paddock_cli.guard.registry import Check, register


def _check(cid="PG-TST-001", **kw):
    base = dict(
        id=cid, title="Test check", severity="high", proposed_tier="high", scope="file",
        globs=("**/*.py",), why="why", fix_hint="fix", agent_prompt="Remove it from {file}.",
        run=lambda ctx, fv: [],
    )
    base.update(kw)
    return Check(**base)


def test_check_is_frozen_keyword_only_and_derives_pack(registry_sandbox):
    c = _check()
    assert c.pack == "TST" and c.inline_suppressible is True and c.network is False
    assert c.spec_status == "VERIFIED" and c.unverified_ids == () and c.fixer is None
    with pytest.raises(Exception):
        c.title = "x"  # type: ignore[misc]
    with pytest.raises(TypeError):
        Check("PG-TST-001", "t")  # type: ignore[misc]


@pytest.mark.parametrize("kw", [{"severity": "urgent"}, {"proposed_tier": "huge"}, {"scope": "galaxy"}])
def test_check_validates_enums(kw):
    with pytest.raises(ValueError):
        _check(**kw)


def test_register_function_and_decorator_forms(registry_sandbox):
    c = register(_check())
    assert registry.get("PG-TST-001") is c

    @register(id="PG-TST-002", title="Decorated", severity="medium", proposed_tier="medium",
              scope="file", globs=("*.txt",), why="w", fix_hint="f", agent_prompt="Fix {file}.")
    def run(ctx, fv):
        return []

    assert registry.get("PG-TST-002").run is run
    assert [c.id for c in registry.all_checks()] == ["PG-TST-001", "PG-TST-002"]


def test_duplicate_id_is_an_error_and_unknown_get_is_a_usage_error(registry_sandbox):
    register(_check())
    with pytest.raises(ValueError):
        register(_check())
    with pytest.raises(errors.UsageError):
        registry.get("PG-NOPE-999")


def test_sandbox_restores_previous_contents():
    before = [c.id for c in registry.all_checks()]
    with registry.sandbox():
        register(_check("PG-TST-009"))
        assert [c.id for c in registry.all_checks()] == ["PG-TST-009"]
    assert [c.id for c in registry.all_checks()] == before


def _write_tiers(tmp_path, monkeypatch, entries):
    p = tmp_path / "tiers.json"
    p.write_text(json.dumps(entries))
    monkeypatch.setattr(registry, "TIERS_PATH", str(p))
    registry.reset_caches()


def test_release_build_without_tiers_json_is_medium_and_unmeasured(registry_sandbox, tmp_path, monkeypatch):
    monkeypatch.setattr(registry, "TIERS_PATH", str(tmp_path / "absent.json"))
    registry.reset_caches()
    assert model.REQUIRE_TIERS is True
    c = register(_check())
    assert registry.effective_tier(c) == ("medium", "unmeasured")


def test_dev_tree_uses_the_proposal_and_labels_it_unmeasured(registry_sandbox, dev_tiers, tmp_path, monkeypatch):
    monkeypatch.setattr(registry, "TIERS_PATH", str(tmp_path / "absent.json"))
    registry.reset_caches()
    c = register(_check())
    assert registry.effective_tier(c) == ("high", "unmeasured")
    d = register(_check("PG-TST-002", proposed_tier="low"))
    assert registry.effective_tier(d) == ("low", "unmeasured")


def test_tiers_json_entry_decides_the_effective_tier(registry_sandbox, tmp_path, monkeypatch):
    c = register(_check())
    _write_tiers(tmp_path, monkeypatch, [{"check_id": "PG-TST-001", "tier": "high", "status": "measured"}])
    assert registry.effective_tier(c) == ("high", "measured")
    _write_tiers(tmp_path, monkeypatch, {"entries": [{"check_id": "PG-TST-001", "tier": "high", "status": "ai-estimated"}]})
    assert registry.effective_tier(c) == ("high", "ai-estimated")
    _write_tiers(tmp_path, monkeypatch, {"PG-TST-001": {"tier": "medium", "status": "insufficient-n"}})
    assert registry.effective_tier(c) == ("medium", "insufficient-n")


def test_high_entry_without_a_bar_status_is_demoted(registry_sandbox, tmp_path, monkeypatch):
    c = register(_check())
    for status in ("insufficient-n", "not-labellable", "bogus"):
        _write_tiers(tmp_path, monkeypatch, [{"check_id": "PG-TST-001", "tier": "high", "status": status}])
        assert registry.effective_tier(c)[0] == "medium"


def test_release_build_check_missing_from_present_tiers_json_is_medium(registry_sandbox, tmp_path, monkeypatch):
    c = register(_check("PG-TST-003"))
    _write_tiers(tmp_path, monkeypatch, [{"check_id": "PG-TST-001", "tier": "high", "status": "measured"}])
    assert registry.effective_tier(c) == ("medium", "unmeasured")


def test_unverified_ids_cap_the_tier_until_closed(registry_sandbox, dev_tiers, tmp_path, monkeypatch):
    vf = tmp_path / "verified.json"
    monkeypatch.setattr(registry, "VERIFIED_PATH", str(vf))
    registry.reset_caches()
    c = register(_check(unverified_ids=("U-16",), spec_status="UNVERIFIED"))
    assert registry.proposed_tier(c) == "medium"
    assert registry.effective_tier(c)[0] == "medium"
    vf.write_text(json.dumps([{"id": "U-16", "kind": "doc", "source": "docs/guard/sources/secrets.md#u16",
                               "date": "2026-11-27"}]))
    registry.reset_caches()
    assert registry.proposed_tier(c) == "high"
    # a measured high entry is still capped while an id is open
    vf.unlink()
    registry.reset_caches()
    _write_tiers(tmp_path, monkeypatch, [{"check_id": "PG-TST-001", "tier": "high", "status": "measured"}])
    assert registry.effective_tier(c)[0] == "medium"


def test_missing_data_files_mean_empty_sets(tmp_path, monkeypatch):
    monkeypatch.setattr(registry, "TIERS_PATH", str(tmp_path / "x.json"))
    monkeypatch.setattr(registry, "VERIFIED_PATH", str(tmp_path / "y.json"))
    registry.reset_caches()
    assert registry.load_tiers() == {} and registry.load_verified() == set()


def test_malformed_data_files_are_ignored_not_fatal(tmp_path, monkeypatch):
    for name, content in (("t.json", "{not json"), ("v.json", "[1,2,3]")):
        (tmp_path / name).write_text(content)
    monkeypatch.setattr(registry, "TIERS_PATH", str(tmp_path / "t.json"))
    monkeypatch.setattr(registry, "VERIFIED_PATH", str(tmp_path / "v.json"))
    registry.reset_caches()
    assert registry.load_tiers() == {} and registry.load_verified() == set()


def test_why_text_marks_anecdotal_rationale():
    assert registry.why_text(_check(why="Agents do X.")).endswith("(anecdotal, unmeasured)")
    assert not registry.why_text(_check(why="Agents do X. source: https://example.invalid/a")).endswith("(anecdotal, unmeasured)")


def test_glob_matching_semantics():
    from paddock_cli.guard.files import match_glob as m

    assert m("**/*.py", "a.py") and m("**/*.py", "a/b/c.py") and not m("**/*.py", "a.pyc")
    assert m("*.json", "package.json") and m("*.json", "sub/package.json")  # no slash: any depth
    assert m("src/*.js", "src/a.js") and not m("src/*.js", "src/x/a.js") and not m("src/*.js", "lib/src/a.js")
    assert m("src/**", "src/a/b.js") and not m("src/**", "other/a.js")
    assert m(".github/workflows/*.yml", ".github/workflows/ci.yml")
    assert m("**/.env*", ".env.production") and m("**/.env*", "a/.env")
    assert not m("**/fixtures/**", "src/a.py") and m("**/fixtures/**", "tests/fixtures/x/a.py")
    assert m("a?c", "abc") and not m("a?c", "a/c")
    assert m("**", "x/y/z")


def test_discover_loads_checks_modules_and_reports_import_errors(registry_sandbox, tmp_path, monkeypatch):
    import paddock_cli.guard.checks as checks_pkg

    d = tmp_path / "extra_checks"
    d.mkdir()
    (d / "good_mod.py").write_text(
        "from paddock_cli.guard.registry import register\n"
        "register(id='PG-TST-010', title='t', severity='low', proposed_tier='low', scope='file', globs=('*',),"
        " why='w', fix_hint='f', agent_prompt='p', run=lambda c, f: [])\n")
    (d / "broken_mod.py").write_text("raise RuntimeError('boom')\n")
    (d / "missing_dep_mod.py").write_text("import not_a_real_module_xyz\n")
    monkeypatch.setattr(checks_pkg, "__path__", list(checks_pkg.__path__) + [str(d)])
    for name in ("good_mod", "broken_mod", "missing_dep_mod"):
        sys.modules.pop("paddock_cli.guard.checks." + name, None)
    registry.discover(force=True)
    assert "PG-TST-010" in [c.id for c in registry.all_checks()]
    errs = {m: cls for m, cls in registry.import_errors()}
    assert errs["paddock_cli.guard.checks.broken_mod"] == "RuntimeError"
    assert errs["paddock_cli.guard.checks.missing_dep_mod"] == "ModuleNotFoundError"
    for name in ("good_mod", "broken_mod", "missing_dep_mod"):
        sys.modules.pop("paddock_cli.guard.checks." + name, None)


def test_discover_tolerates_absent_pkg_and_urlcheck_and_finds_them_when_present(registry_sandbox, monkeypatch):
    registry.discover(force=True)
    assert not [m for m, _ in registry.import_errors() if m.endswith((".pkg.checks", ".urlcheck.checks", ".pkg", ".urlcheck"))]
    for pkgname in ("pkg", "urlcheck"):
        parent = types.ModuleType("paddock_cli.guard." + pkgname)
        parent.__path__ = []  # type: ignore[attr-defined]
        mod = types.ModuleType("paddock_cli.guard.%s.checks" % pkgname)
        cid = "PG-PKG-001" if pkgname == "pkg" else "PG-URL-001"

        def reg(cid=cid):
            register(id=cid, title="t", severity="high", proposed_tier="high", scope="project", why="w",
                     fix_hint="f", agent_prompt="p", network=True, run=lambda c, f: [])

        reg()
        monkeypatch.setitem(sys.modules, "paddock_cli.guard." + pkgname, parent)
        monkeypatch.setitem(sys.modules, "paddock_cli.guard.%s.checks" % pkgname, mod)
        registry._CHECKS.pop(cid, None)
    registry.discover(force=True)
    # modules were already executed by our fake; discovery must import them without error
    assert not [m for m, _ in registry.import_errors()]


def test_invariant_problems_flags_each_rule(registry_sandbox):
    good = _check()
    assert registry.invariant_problems([good]) == []
    probs = registry.invariant_problems([_check("PG-TST-1")])
    assert any("id" in p for p in probs)
    probs = registry.invariant_problems([_check(agent_prompt="Fix {file.__class__} and {0}")])
    assert any("template" in p for p in probs)
    probs = registry.invariant_problems([_check(fixer="rm_rf")])
    assert any("fixer" in p for p in probs)
    probs = registry.invariant_problems([_check(network=True)])
    assert any("network" in p for p in probs)
    assert registry.invariant_problems([_check("PG-PKG-001", network=True)]) == []
    assert registry.invariant_problems([_check("PG-URL-001", network=True)]) == []
    assert registry.invariant_problems([_check(fixer="gitignore_env")]) == []
    probs = registry.invariant_problems([_check(), _check(title="again")])
    assert any("duplicate" in p for p in probs)


def test_fixer_names_constants_exist_without_imports():
    from paddock_cli.guard import fixers

    assert set(fixers.FIXER_NAMES) == {
        "gitignore_env", "strip_hidden_unicode", "workflow_permissions", "pin_from_lockfile", "secret_to_env"}
    assert fixers.BREAKING == frozenset({"pin_from_lockfile", "secret_to_env"})
    assert fixers.BREAKING <= set(fixers.FIXER_NAMES)


def test_require_tiers_agrees_with_guard_version():
    assert model.REQUIRE_TIERS == (".dev" not in GUARD_VERSION)
