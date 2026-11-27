# SPDX-License-Identifier: AGPL-3.0-or-later
"""CLI wiring, exit codes (D12), commands (contract 3.5, acceptance 1, 2, 4)."""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys

import pytest

from paddock_cli import main as paddock_main
from paddock_cli.guard import GUARD_VERSION, cli, files
from support import expand_fixture, gitenv, testchecks


def _w(root, rel, text="x\n"):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(text if isinstance(text, bytes) else text.encode())
    return p


@pytest.fixture
def tc(registry_sandbox, dev_tiers):
    testchecks.register_all()


def _main(argv, capsys):
    code = cli.main(argv)
    out = capsys.readouterr()
    return code, out.out, out.err


# ---- help, version, list, explain (also offline in a subprocess) ----------------------------------
def test_module_entry_runs_offline_help_version_list_explain_check(guard_env, tmp_path, clean_app):
    app = tmp_path / "app"
    expand_fixture(clean_app, app)

    def run(*args):
        return subprocess.run([sys.executable, "-m", "paddock_cli.guard", *args], env=guard_env, cwd=str(tmp_path),
                              capture_output=True, text=True, timeout=120)

    r = run("--help")
    assert r.returncode == 0 and "check" in r.stdout and "explain" in r.stdout and "baseline" in r.stdout
    r = run("--version")
    assert r.returncode == 0 and r.stdout.strip() == "paddock-guard " + GUARD_VERSION
    assert run("list").returncode == 0
    assert run("explain", "PG-NOPE-001").returncode == 2
    r = run("check", str(app), "--offline", "--no-cache")
    assert r.returncode == 0, r.stderr
    assert "checks ran at tier" in r.stdout and "no findings is not a safety result" in r.stdout
    r = run(str(app), "--offline", "--no-cache")  # no subcommand means check
    assert r.returncode == 0 and "Paddock Guard" in r.stdout
    assert run("check", str(app), "--base", "--output=/tmp/x").returncode == 2


def test_launcher_script_runs_paddock_guard(guard_env):
    r = subprocess.run(["paddock-guard", "--version"], env=guard_env, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0 and GUARD_VERSION in r.stdout


def test_help_lists_commands_and_hides_nothing_promotional(capsys):
    code, out, err = _main(["--help"], capsys)
    assert code == 0
    for word in ("check", "explain", "list", "status", "baseline", "ledger", "catalogue"):
        assert word in out


def test_unknown_option_and_mutually_exclusive_flags_exit_two(capsys, tmp_path):
    assert _main(["check", str(tmp_path), "--nope"], capsys)[0] == 2
    assert _main(["check", str(tmp_path), "--changed", "--staged"], capsys)[0] == 2
    assert _main(["check", str(tmp_path), "--base", "HEAD", "--staged"], capsys)[0] == 2
    assert _main(["check", str(tmp_path), "--tier", "ultra"], capsys)[0] == 2
    assert _main(["check", str(tmp_path), "--format", "xml"], capsys)[0] == 2


# ---- check ----------------------------------------------------------------------------------------
def test_check_exit_codes_blocking_and_not(tc, tmp_path, capsys):
    proj = tmp_path / "proj"
    _w(proj, "a.txt", "FORBIDDEN_ONE\n")
    code, out, _ = _main(["check", str(proj), "--no-cache"], capsys)
    assert code == 1 and "1 blocking" in out and "PG-TST-001" in out
    assert _main(["check", str(proj), "--no-cache", "--fail-on", "critical"], capsys)[0] == 0
    clean = tmp_path / "clean"
    _w(clean, "a.txt", "nothing here\n")
    assert _main(["check", str(clean), "--no-cache"], capsys)[0] == 0


def test_check_runtime_errors_exit_two(tc, tmp_path, capsys):
    assert _main(["check", str(tmp_path / "missing"), "--no-cache"], capsys)[0] == 2
    assert _main(["check", os.environ["HOME"], "--no-cache"], capsys)[0] == 2
    code, out, err = _main(["check", str(tmp_path), "--base", "--output=/tmp/pwn", "--no-cache"], capsys)
    assert code == 2
    proj = tmp_path / "p"
    _w(proj, ".paddock/guard.toml", "[guard]\nbogus = 1\n")
    code, out, err = _main(["check", str(proj), "--no-cache"], capsys)
    assert code == 2 and "bogus" in err


def test_formats_to_stdout_and_to_a_file(tc, tmp_path, capsys):
    proj = tmp_path / "proj"
    _w(proj, "a.txt", "FORBIDDEN_ONE\n")
    for fmt, probe in (("json", lambda t: json.loads(t)["schema"]), ("sarif", lambda t: json.loads(t)["version"]),
                       ("markdown", lambda t: t.startswith("### Paddock Guard") or None), ("text", lambda t: "Paddock Guard" in t or None)):
        code, out, err = _main(["check", str(proj), "--no-cache", "--format", fmt], capsys)
        assert code == 1 and probe(out)
    dest = tmp_path / "out" / "report.sarif"
    code, out, err = _main(["check", str(proj), "--no-cache", "--format", "sarif", "-o", str(dest)], capsys)
    assert code == 1 and json.loads(dest.read_text())["version"] == "2.1.0"
    assert stat.S_IMODE(os.stat(dest).st_mode) == 0o600 and "SARIF" not in out
    link = tmp_path / "link.json"
    os.symlink(tmp_path / "victim", link)
    code, out, err = _main(["check", str(proj), "--no-cache", "--format", "json", "-o", str(link)], capsys)
    assert code == 2 and not (tmp_path / "victim").exists()


def test_check_writes_state_outside_the_tree_and_nothing_with_no_cache(tc, repo, tmp_path, monkeypatch, capsys):
    cache = tmp_path / "cache"
    monkeypatch.setenv("PADDOCK_CACHE_DIR", str(cache))
    _w(repo, "a.txt", "FORBIDDEN_ONE\n")
    gitenv.commit_all(repo)
    assert _main(["check", str(repo), "--no-cache"], capsys)[0] == 1
    assert not cache.exists()
    assert gitenv.git(repo, "status", "--porcelain").stdout == ""
    assert _main(["check", str(repo)], capsys)[0] == 1
    (state,) = list((cache / "guard" / "projects").iterdir())
    rep = state / "last-report.json"
    assert json.loads(rep.read_text())["schema"] == "paddock-guard/report/v1"
    assert stat.S_IMODE(os.stat(rep).st_mode) == 0o600 and stat.S_IMODE(os.stat(state / "ledger.jsonl").st_mode) == 0o600
    assert gitenv.git(repo, "status", "--porcelain").stdout == ""
    lines = (state / "ledger.jsonl").read_text().splitlines()
    ev = json.loads(lines[-1])
    assert ev["event"] == "check" and ev["blocking"] == 1 and "FORBIDDEN" not in lines[-1]
    gitenv.git(repo, "add", "-A")
    assert gitenv.git(repo, "diff", "--cached", "--name-only").stdout == ""


def test_no_state_environment_variable_writes_nothing(tc, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("PADDOCK_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("PADDOCK_GUARD_NO_STATE", "1")
    proj = tmp_path / "proj"
    _w(proj, "a.txt", "FORBIDDEN_ONE\n")
    _main(["check", str(proj)], capsys)
    assert not (tmp_path / "cache").exists()


def test_default_command_is_check_for_the_standalone_entry(tc, tmp_path, capsys, monkeypatch):
    proj = tmp_path / "proj"
    _w(proj, "a.txt", "FORBIDDEN_ONE\n")
    monkeypatch.chdir(proj)
    code, out, _ = _main(["--no-cache"], capsys)
    assert code == 1 and "PG-TST-001" in out
    code, out, _ = _main([], capsys)
    assert code == 1


def test_check_changed_and_only_and_tier(tc, repo, capsys):
    _w(repo, "a.txt", "FORBIDDEN_ONE\n")
    _w(repo, "b.txt", "FORBIDDEN_TWO MEDIUMWORD\n")
    gitenv.commit_all(repo)
    _w(repo, "b.txt", "FORBIDDEN_TWO MEDIUMWORD\n# edit\n")
    code, out, _ = _main(["check", str(repo), "--no-cache", "--changed", "--format", "json"], capsys)
    doc = json.loads(out)
    assert doc["mode"]["scope"] == "changed" and [f["file"] for f in doc["findings"]] == ["b.txt"]
    code, out, _ = _main(["check", str(repo), "--no-cache", "--tier", "medium", "--format", "json"], capsys)
    assert {f["check_id"] for f in json.loads(out)["findings"]} == {"PG-TST-001", "PG-TST-002"}
    code, out, _ = _main(["check", str(repo), "--no-cache", "--only", "PG-TST-002", "--tier", "medium", "--format", "json"], capsys)
    assert {f["check_id"] for f in json.loads(out)["findings"]} == {"PG-TST-002"}
    assert _main(["check", str(repo), "--no-cache", "--only", "PG-NOPE-001"], capsys)[0] == 2


def test_check_base_delta_and_staged(tc, repo, capsys):
    _w(repo, "a.txt", "FORBIDDEN_OLD\n")
    base = gitenv.commit_all(repo)
    _w(repo, "a.txt", "FORBIDDEN_OLD\nFORBIDDEN_NEW\n")
    code, out, _ = _main(["check", str(repo), "--no-cache", "--base", base, "--format", "json"], capsys)
    names = [f["data"]["name"] for f in json.loads(out)["findings"]]
    assert code == 1 and names == ["forbidden_new"]
    gitenv.git(repo, "add", "a.txt")
    _w(repo, "a.txt", "clean\n")
    code, out, _ = _main(["check", str(repo), "--no-cache", "--staged", "--format", "json"], capsys)
    assert json.loads(out)["mode"]["scope"] == "staged" and code == 1


def test_config_ref_and_baseline_ref_are_validated(tc, repo, capsys):
    _w(repo, "a.txt", "x\n")
    gitenv.commit_all(repo)
    for flag in ("--config-ref", "--baseline-ref"):
        assert _main(["check", str(repo), "--no-cache", flag, "--upload-pack=x"], capsys)[0] == 2
        assert _main(["check", str(repo), "--no-cache", flag, "HEAD"], capsys)[0] == 0


def test_new_suppression_versus_base_fails_unless_approved(tc, repo, tmp_path, monkeypatch, capsys):
    _w(repo, "a.txt", "plain\n")
    base = gitenv.commit_all(repo)
    _w(repo, "a.txt", "FORBIDDEN_ONE  # paddock:ignore PG-TST-001 deliberate and reviewed\n")
    code, out, _ = _main(["check", str(repo), "--no-cache", "--base", base, "--format", "json"], capsys)
    doc = json.loads(out)
    assert doc["summary"]["suppressed"] == 1 and doc["summary"]["blocking"] == 0
    assert code == 1 and doc["suppressions_added"] and "suppression" in " ".join(doc["notes"]).lower()
    fp = doc["suppressions_added"][0]["fingerprint"]
    cfgdir = tmp_path / "userconf"
    cfgdir.mkdir()
    (cfgdir / "guard.toml").write_text('[ci]\napproved_suppressions = ["%s"]\n' % fp)
    (cfgdir / "guard.toml").chmod(0o600)
    monkeypatch.setenv("PADDOCK_CONFIG_DIR", str(cfgdir))
    code, out, _ = _main(["check", str(repo), "--no-cache", "--base", base], capsys)
    assert code == 0
    (cfgdir / "guard.toml").write_text("[ci]\nfail_on_new_suppression = false\n")
    code, out, _ = _main(["check", str(repo), "--no-cache", "--base", base], capsys)
    assert code == 0


def test_hook_exhausted_reminders_block_until_a_person_approves(tc, repo, tmp_path, monkeypatch, capsys):
    from paddock_cli.guard import ledger as ledger_mod

    cache = tmp_path / "cache"
    monkeypatch.setenv("PADDOCK_CACHE_DIR", str(cache))
    _w(repo, "a.txt", "FORBIDDEN_ONE\n")
    gitenv.commit_all(repo)
    code, out, _ = _main(["check", str(repo), "--fail-on", "critical", "--format", "json"], capsys)
    assert code == 0
    fp = json.loads(out)["findings"][0]["fingerprint"]
    (state,) = list((cache / "guard" / "projects").iterdir())
    ledger_mod.Ledger(str(state)).append("hook_ignored_by_agent", fingerprints=[fp], check_ids=["PG-TST-001"])
    code, out, _ = _main(["check", str(repo), "--fail-on", "critical", "--format", "json"], capsys)
    doc = json.loads(out)
    assert code == 1 and any(n.startswith("PG-META-004") for n in doc["notes"])
    _w(repo, "a.txt", "fixed\n")
    assert _main(["check", str(repo), "--fail-on", "critical"], capsys)[0] == 0


def test_check_makes_no_network_connection(tc, tmp_path, monkeypatch, capsys):
    import socket

    def refuse(*a, **k):
        raise AssertionError("network used")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    proj = tmp_path / "proj"
    _w(proj, "a.txt", "FORBIDDEN_ONE\n")
    assert _main(["check", str(proj), "--no-cache", "--offline"], capsys)[0] == 1


# ---- explain, list, status --------------------------------------------------------------------------
def test_explain_text_and_json(tc, capsys):
    code, out, _ = _main(["explain", "PG-TST-001"], capsys)
    assert code == 0 and "Forbidden word" in out and "(anecdotal, unmeasured)" in out and "severity" in out.lower()
    code, out, _ = _main(["explain", "PG-TST-001", "--format", "json"], capsys)
    d = json.loads(out)
    assert d["id"] == "PG-TST-001" and d["effective_tier"] == "high" and d["tier_evidence"] == "unmeasured"
    assert d["declared_tier"] == "high" and d["inline_suppressible"] is True and d["agent_prompt_template"]
    assert _main(["explain", "PG-NOPE-001"], capsys)[0] == 2


def test_list_filters_by_effective_tier(tc, capsys):
    code, out, _ = _main(["list", "--format", "json"], capsys)
    ids = [c["id"] for c in json.loads(out)]
    assert "PG-TST-001" in ids and "PG-TST-003" in ids and ids == sorted(ids)
    code, out, _ = _main(["list", "--tier", "high", "--format", "json"], capsys)
    hi = [c["id"] for c in json.loads(out)]
    assert "PG-TST-001" in hi and "PG-TST-002" not in hi and "PG-TST-003" not in hi
    code, out, _ = _main(["list"], capsys)
    assert "PG-TST-002" in out and code == 0


def test_status_reports_version_counts_and_state(tc, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("PADDOCK_CACHE_DIR", str(tmp_path / "cache"))
    proj = tmp_path / "proj"
    _w(proj, "a.txt", "FORBIDDEN_ONE\n")
    _main(["check", str(proj)], capsys)
    code, out, _ = _main(["status", str(proj), "--format", "json"], capsys)
    d = json.loads(out)
    assert code == 0 and d["version"] == GUARD_VERSION and d["checks"]["total"] == 9 and d["ledger_events"] >= 1
    assert d["tiers_json_present"] in (True, False) and "user_config" in d
    code, out, _ = _main(["status", str(proj)], capsys)
    assert GUARD_VERSION in out


# ---- baseline ---------------------------------------------------------------------------------------
def test_baseline_create_update_show(tc, repo, capsys):
    _w(repo, "a.txt", "FORBIDDEN_ONE\nFORBIDDEN_TWO\n")
    gitenv.commit_all(repo)
    assert _main(["baseline", "show", str(repo)], capsys)[0] == 2  # no baseline yet
    code, out, _ = _main(["baseline", "create", str(repo), "--no-cache"], capsys)
    assert code == 0 and "2 finding" in out
    doc = json.loads((repo / ".paddock" / "baseline.json").read_text())
    assert doc["schema"] == "paddock-guard/baseline/v1" and len(doc["entries"]) == 2
    assert (repo / ".paddock" / ".gitignore").is_file()
    assert _main(["baseline", "create", str(repo), "--no-cache"], capsys)[0] == 2  # refuses to overwrite
    assert _main(["baseline", "create", str(repo), "--no-cache", "--force"], capsys)[0] == 0
    code, out, _ = _main(["check", str(repo), "--no-cache"], capsys)
    assert code == 0 and "2 baselined" in out
    gitenv.git(repo, "add", "-A")
    staged = gitenv.git(repo, "diff", "--cached", "--name-only").stdout.split()
    assert sorted(staged) == [".paddock/.gitignore", ".paddock/baseline.json"]
    _w(repo, "a.txt", "FORBIDDEN_ONE\n")
    code, out, _ = _main(["baseline", "update", str(repo), "--no-cache"], capsys)
    assert code == 0 and "1 entr" in out
    assert len(json.loads((repo / ".paddock" / "baseline.json").read_text())["entries"]) == 1
    code, out, _ = _main(["baseline", "show", str(repo)], capsys)
    assert code == 0 and "FORBIDDEN" not in out and "1 baseline entr" in out


def test_baseline_refuses_a_symlinked_paddock_dir(tc, tmp_path, capsys):
    outside = tmp_path / "outside"
    outside.mkdir()
    proj = tmp_path / "proj"
    _w(proj, "a.txt", "FORBIDDEN_ONE\n")
    os.symlink(outside, proj / ".paddock")
    assert _main(["baseline", "create", str(proj), "--no-cache"], capsys)[0] == 2
    assert list(outside.iterdir()) == []


# ---- ledger -----------------------------------------------------------------------------------------
def test_ledger_show_and_clear(tc, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("PADDOCK_CACHE_DIR", str(tmp_path / "cache"))
    proj = tmp_path / "proj"
    _w(proj, "a.txt", "FORBIDDEN_ONE\n")
    _main(["check", str(proj)], capsys)
    code, out, _ = _main(["ledger", "show", str(proj)], capsys)
    assert code == 0 and "check" in out and "FORBIDDEN" not in out
    code, out, _ = _main(["ledger", "show", str(proj), "--format", "json"], capsys)
    assert json.loads(out)[0]["event"] == "check"
    code, out, _ = _main(["ledger", "clear", str(proj)], capsys)
    assert code == 0 and "removed 1" in out
    assert json.loads(_main(["ledger", "show", str(proj), "--format", "json"], capsys)[1]) == []


# ---- catalogue --------------------------------------------------------------------------------------
def test_catalogue_generates_and_checks(tc, tmp_path, capsys):
    docs = tmp_path / "docs" / "guard"
    docs.mkdir(parents=True)
    assert _main(["catalogue", "--check", "--docs-dir", str(docs)], capsys)[0] == 1  # missing files
    assert _main(["catalogue", "--docs-dir", str(docs)], capsys)[0] == 0
    assert (docs / "CHECKS.md").is_file() and (docs / "TIERS.md").is_file()
    assert "PG-TST-001" in (docs / "CHECKS.md").read_text() and "effective" in (docs / "TIERS.md").read_text().lower()
    assert _main(["catalogue", "--check", "--docs-dir", str(docs)], capsys)[0] == 0
    (docs / "CHECKS.md").write_text("stale\n")
    code, out, err = _main(["catalogue", "--check", "--docs-dir", str(docs)], capsys)
    assert code == 1 and "CHECKS.md" in out + err
    assert _main(["catalogue", "--check", "--docs-dir", str(tmp_path / "nope")], capsys)[0] == 2


def test_checks_md_has_static_columns_only(tc):
    from paddock_cli.guard import catalogue, registry

    md = catalogue.render_checks_md(registry.all_checks())
    assert "| ID |" in md and "PG-TST-001" in md
    header = [ln for ln in md.splitlines() if ln.startswith("| ID |")][0].lower()
    assert "effective" not in header and "evidence" not in header and "declared tier" in header
    tiers = catalogue.render_tiers_md(registry.all_checks())
    assert "unmeasured" in tiers


# ---- paddock guard through main.py ----------------------------------------------------------------------
def test_paddock_guard_subcommand_is_registered_in_main(tc, tmp_path, capsys, monkeypatch):
    proj = tmp_path / "proj"
    _w(proj, "a.txt", "FORBIDDEN_ONE\n")
    assert paddock_main.main(["guard", "list"]) == 0
    assert "PG-TST-001" in capsys.readouterr().out
    assert paddock_main.main(["guard", "check", str(proj), "--no-cache"]) == 1
    capsys.readouterr()
    assert paddock_main.main(["guard", str(proj), "--no-cache"]) == 1  # no subcommand: check
    capsys.readouterr()
    monkeypatch.chdir(proj)
    assert paddock_main.main(["guard", "--no-cache"]) == 1
    capsys.readouterr()
    with pytest.raises(SystemExit) as ei:
        paddock_main.main(["guard", "-h"])
    assert ei.value.code == 0 and "explain" in capsys.readouterr().out
    assert paddock_main.main(["guard", "explain", "PG-NOPE-001"]) == 2
    capsys.readouterr()


def test_main_py_hunk_is_one_small_block():
    out = subprocess.run(["git", "diff", "--no-color", "-U0", "--", "cli/paddock_cli/main.py"], capture_output=True, text=True,
                         cwd=os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
    added = [ln for ln in out.stdout.splitlines() if ln.startswith("+") and not ln.startswith("+++")]
    removed = [ln for ln in out.stdout.splitlines() if ln.startswith("-") and not ln.startswith("---")]
    hunks = [ln for ln in out.stdout.splitlines() if ln.startswith("@@")]
    if out.stdout.strip():  # once committed the diff is empty; the shape is asserted while it is a diff
        assert len(hunks) == 1 and len(added) <= 8 and removed == []
        assert any("_register_guard" in ln for ln in added)
    text = (files.__file__ and open(os.path.join(os.path.dirname(paddock_main.__file__), "main.py")).read())
    assert "from .guard.cli import register as _register_guard" in text
    assert text.index("_register_guard(sub)") < text.index("    return ap")
