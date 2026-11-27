# SPDX-License-Identifier: AGPL-3.0-or-later
"""Test support of contract 3.12: fixtures, fake tokens, git isolation, launcher, collection."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import fakes
import support
from support import gitenv

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]


def _write(root: Path, rel: str, text: str = "x\n") -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8", newline="")


def test_fakes_families_cover_the_contract_list():
    want = {
        "aws_akia", "aws_secret", "gh_pat", "gitlab_pat", "slack", "stripe_live", "stripe_whsec",
        "anthropic", "openai", "sendgrid", "supabase_service_jwt", "supabase_anon_jwt", "pem_rsa",
        "db_url_pw",
    }
    assert want <= set(fakes.FAMILIES)


def test_fakes_shapes_match_provider_formats():
    f = fakes.fake
    assert re.fullmatch(r"AKIA[0-9A-Z]{16}", f("aws_akia"))
    sec = f("aws_secret")
    assert re.fullmatch(r"[A-Za-z0-9/+=]{40}", sec) and not re.fullmatch(r"[0-9a-f]{40}", sec) and sec != sec.lower()
    assert re.fullmatch(r"gh[p]_[A-Za-z0-9]{36}", f("gh_pat"))
    assert re.fullmatch(r"glpat-[0-9A-Za-z_-]{20}", f("gitlab_pat"))
    assert re.fullmatch(r"xoxb-\d{12}-\d{12}-[A-Za-z0-9]{24}", f("slack"))
    assert re.fullmatch(r"sk_live_[0-9a-zA-Z]{24}", f("stripe_live"))
    assert re.fullmatch(r"whsec_[A-Za-z0-9]{32}", f("stripe_whsec"))
    assert re.fullmatch(r"sk-ant-api03-[A-Za-z0-9_-]{90}", f("anthropic"))
    assert re.fullmatch(r"sk-proj-[A-Za-z0-9_-]{48}", f("openai"))
    assert re.fullmatch(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}", f("sendgrid"))
    assert re.fullmatch(r"postgres://app:[A-Za-z0-9]{20}@db\.[a-z0-9]{10}\.supabase\.co:5432/postgres", f("db_url_pw"))
    pem = f("pem_rsa")
    assert pem.startswith("-----BEGIN RSA PRIVATE KEY-----\n") and pem.rstrip().endswith("-----END RSA PRIVATE KEY-----")
    assert len([ln for ln in pem.splitlines() if re.fullmatch(r"[A-Za-z0-9+/=]{64}", ln)]) >= 2


def test_fakes_jwt_roles_and_demo_issuer():
    import base64

    def payload(tok):
        b = tok.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(b + "=" * (-len(b) % 4)))

    assert payload(fakes.fake("supabase_service_jwt"))["role"] == "service_role"
    assert payload(fakes.fake("supabase_anon_jwt"))["role"] == "anon"
    demo = payload(fakes.fake("supabase_demo_service_jwt"))
    assert demo["iss"] == "supabase-demo" and demo["role"] == "service_role"


def test_fakes_are_deterministic_and_variants_differ():
    assert fakes.fake("gh_pat") == fakes.fake("gh_pat")
    assert fakes.fake("gh_pat", 2) != fakes.fake("gh_pat")


def test_fakes_source_holds_no_literal_token():
    src = (HERE / "fakes.py").read_text(encoding="utf-8")
    for pat in (r"AKIA[0-9A-Z]{16}", r"ghp_[A-Za-z0-9]{36}", r"sk_live_[0-9a-zA-Z]{20}",
                r"-----BEGIN [A-Z ]*PRIVATE KEY-----", r"xox[bp]-\d", r"eyJ[A-Za-z0-9_-]{10,}\.eyJ"):
        assert not re.search(pat, src), pat


def test_expand_text_replaces_markers_and_rejects_unknown():
    out = fakes.expand_text("a={{fake:gh_pat}} b={{fake:gh_pat:2}}")
    assert "{{" not in out and out.count("gh") >= 2
    with pytest.raises(KeyError):
        fakes.expand_text("{{fake:nope}}")


def test_expand_fixture_renames_expands_and_materialises_git(tmp_path):
    src = tmp_path / "src"
    _write(src, "dot-env", "TOKEN={{fake:gh_pat}}\n")
    _write(src, "dot-env.production", "X=1\n")
    _write(src, "dot-gitignore", ".env\n_unrelated\n")
    _write(src, "_dist/app.js", "var a;\n")
    _write(src, "_node_modules/x/index.js", "1;\n")
    _write(src, "_next/server.js", "2;\n")
    _write(src, "dot-github/workflows/ci.yml", "on: push\n")
    _write(src, "plain/_notmapped.txt", "keep\n")
    _write(src, "expect.json", json.dumps({"check": "PG-X-001", "files": ["dot-env"],
                                           "git": {"init": True, "tracked": [".env.production", "dist/app.js"], "ignored": [".env"]}}))
    _write(src, "NOTE.md", "note\n")
    dst = tmp_path / "dst"
    support.expand_fixture(src, dst)
    assert (dst / ".env").is_file() and (dst / ".env.production").is_file()
    assert (dst / ".gitignore").is_file()
    assert (dst / "dist" / "app.js").is_file()
    assert (dst / "node_modules" / "x" / "index.js").is_file()
    assert (dst / ".next" / "server.js").is_file()
    assert (dst / ".github" / "workflows" / "ci.yml").is_file()
    assert (dst / "plain" / "_notmapped.txt").is_file()
    assert not (dst / "expect.json").exists() and not (dst / "NOTE.md").exists()
    text = (dst / ".env").read_text()
    assert "{{" not in text and re.fullmatch(r"TOKEN=gh[p]_[A-Za-z0-9]{36}\n", text)
    # git stanza
    assert (dst / ".git").is_dir()
    tracked = gitenv.git(dst, "ls-files").stdout.split()
    assert sorted(tracked) == [".env.production", "dist/app.js"]
    assert gitenv.git(dst, "check-ignore", "-q", ".env", check=False).returncode == 0


def test_expand_fixture_refuses_missing_ignored_contract(tmp_path):
    src = tmp_path / "src"
    _write(src, "a.txt", "1\n")
    _write(src, "expect.json", json.dumps({"git": {"init": True, "tracked": ["a.txt"], "ignored": ["a.txt"]}}))
    with pytest.raises(AssertionError):
        support.expand_fixture(src, tmp_path / "dst")


def test_rename_map_is_data_file():
    data = json.loads((HERE / "support" / "rename_map.json").read_text())
    assert data["dot_prefix"] == "dot-"
    assert data["underscore_names"]["_dist"] == "dist"
    assert data["underscore_names"]["_next"] == ".next"


def test_expand_app_cli_runs_as_script(tmp_path):
    src = tmp_path / "app"
    _write(src, "dot-env", "A={{fake:aws_akia}}\n")
    out = tmp_path / "out"
    r = subprocess.run([sys.executable, str(HERE / "support" / "expand_app.py"), str(src), str(out)],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert (out / ".env").is_file() and "{{" not in (out / ".env").read_text()


def test_git_helper_survives_ambient_gpgsign(tmp_path, monkeypatch):
    amb = tmp_path / "ambient.gitconfig"
    amb.write_text("[commit]\n\tgpgsign = true\n[gpg]\n\tprogram = /nonexistent/signer\n[user]\n\tname = Amb\n\temail = a@b\n")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(amb))
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "commit.gpgsign")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "true")
    repo = tmp_path / "r"
    repo.mkdir()
    gitenv.init_repo(repo)
    (repo / "f.txt").write_text("1\n")
    gitenv.git(repo, "add", "f.txt")
    gitenv.git(repo, "commit", "-q", "-m", "one")
    assert gitenv.git(repo, "rev-parse", "HEAD").stdout.strip()
    assert gitenv.git(repo, "log", "-1", "--format=%an <%ae>").stdout.strip() == "Test <test@example.invalid>"


def test_launcher_writes_executables_and_runs_python_module(tmp_path):
    bindir = support.launcher.make_bin(tmp_path / "bin")
    exe = Path(bindir) / "paddock-guard"
    stub = Path(bindir) / "paddock-guard-mcp"
    assert os.access(exe, os.X_OK) and os.access(stub, os.X_OK)
    text = exe.read_text()
    assert "PYTHONPATH" in text and "paddock_cli.guard" in text and sys.executable in text
    assert str(REPO / "cli") in text


def test_guard_env_fixture_points_everything_into_tmp(guard_env, tmp_path):
    for key in ("HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "PADDOCK_CONFIG_DIR", "PADDOCK_CACHE_DIR"):
        assert str(tmp_path) in guard_env[key], key
    assert guard_env["GIT_CONFIG_GLOBAL"] == "/dev/null" or str(tmp_path) in guard_env["GIT_CONFIG_GLOBAL"]
    assert guard_env["PATH"].split(os.pathsep)[0].endswith("bin")
    assert str(REPO / "cli") in guard_env["PYTHONPATH"]


def test_fixtures_are_not_collected_by_pytest():
    conf = (HERE / "conftest.py").read_text()
    assert "collect_ignore_glob" in conf and "fixtures/*" in conf
    r = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider",
         str(HERE / "test_g0_support.py"), str(HERE / "fixtures")],
        capture_output=True, text=True, cwd=str(REPO / "cli"), timeout=120,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert "fixtures/apps/clean-app/tests/test_x.py" not in r.stdout
    assert (HERE / "fixtures" / "apps" / "clean-app" / "tests" / "test_x.py").is_file()
    assert (HERE / "fixtures" / "apps" / "clean-app" / "tests" / "conftest.py").is_file()


@pytest.mark.skipif(shutil.which("ruff") is None, reason="ruff not installed")
def test_ruff_check_dot_is_clean_with_fixtures_present():
    r = subprocess.run(["ruff", "check", "--no-cache", "."], capture_output=True, text=True,
                       cwd=str(REPO), timeout=300)
    assert r.returncode == 0, r.stdout[-2000:]


def test_ruff_toml_excludes_fixture_directories():
    text = (REPO / "ruff.toml").read_text()
    assert "cli/tests/guard/fixtures" in text and "bench/**/fixtures" in text


def test_unique_test_basenames_across_guard_and_bench():
    seen: dict[str, str] = {}
    dup: list[str] = []
    for base in (HERE, REPO / "bench" / "tests", REPO / "bench" / "precision" / "tests"):
        if not base.is_dir():
            continue
        for p in base.rglob("test_*.py"):
            if "fixtures" in p.relative_to(base).parts:
                continue
            if p.name in seen:
                dup.append("%s and %s" % (seen[p.name], p))
            seen[p.name] = str(p)
    assert dup == []


def test_clean_app_fixture_is_neutral_and_secret_free():
    root = HERE / "fixtures" / "apps" / "clean-app"
    names = [p.name for p in root.rglob("*")]
    assert "dot-gitignore" in names
    assert ".env" not in names and ".gitignore" not in names and "node_modules" not in names
    blob = "\n".join(p.read_text(errors="replace") for p in root.rglob("*") if p.is_file())
    assert not re.search(r"AKIA[0-9A-Z]{16}|gh[ps]_[A-Za-z0-9]{36}|sk_live_|BEGIN [A-Z ]*PRIVATE KEY", blob)


def test_perf_helper_skips_absolute_timings_when_switched_off():
    from support import perf

    perf.within(1.0, 2.0, enabled=True)
    with pytest.raises(AssertionError):
        perf.within(3.0, 2.0, enabled=True)
    perf.within(3.0, 2.0, enabled=False)  # PADDOCK_GUARD_PERF=0 on a loaded machine
    assert perf.PERF_ENABLED in (True, False)
