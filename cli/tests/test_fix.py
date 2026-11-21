import ast
import json
import shutil
import subprocess
import sys

import pytest

import fake_osv
from conftest import FIXTURE, run
from paddock_cli import engines, fixplan, scanner
from paddock_cli.applyfix import ApplyError, apply_plans
from paddock_cli.osvclient import OsvClient


def fix_json(capsys, repo, *extra):
    code, out, err = run(capsys, "fix", repo, "--no-git", "--json", *extra)
    return code, json.loads(out), err


def test_fix_yes_applies_everything_and_verifies(capsys, repo, patch_osv):
    code, out, err = run(capsys, "fix", repo, "--no-git", "--yes")
    assert code == 0, out + err
    assert "verified: 8 of 8 fixed" in out
    assert '"version": "4.17.21"' in (repo / "package-lock.json").read_text()
    assert "lodash-4.17.21.tgz" in (repo / "package-lock.json").read_text()
    assert "integrity" not in (repo / "package-lock.json").read_text()
    json.loads((repo / "package-lock.json").read_text())                 # still valid JSON
    assert "requests==2.31.0" in (repo / "requirements.txt").read_text()
    assert "<version>2.16.0</version>" in (repo / "java/pom.xml").read_text()
    assert "gin v1.7.7" in (repo / "svc-go/go.mod").read_text()          # two hops: 1.6.3 -> 1.7.0 -> 1.7.7
    cfg = (repo / "app/config.py").read_text()
    assert 'DB_PASSWORD = os.environ["DB_PASSWORD"]' in cfg and "Zx9Kp2Lm8Qr4Vt7Wb3Nd" not in cfg
    ast.parse(cfg)
    assert "process.env.API_TOKEN" in (repo / "web/app.js").read_text()
    assert (repo / ".env.example").read_text().splitlines()[1:] == ["DB_PASSWORD=", "API_TOKEN="]
    assert (repo / ".gitignore").read_text() == ".env\n"
    ng = (repo / "deploy/nginx.conf").read_text()
    assert "ssl_protocols TLSv1.2 TLSv1.3;" in ng and "Strict-Transport-Security" in ng
    assert not list(repo.rglob(".*paddock-*")), "no temp files left behind"


def test_after_fixing_a_rescan_is_clean_and_fix_is_idempotent(capsys, repo, patch_osv):
    run(capsys, "fix", repo, "--no-git", "--yes")
    code, out, _ = run(capsys, "scan", repo, "--no-git", "--json")
    left = [(f["kind"], f["title"]) for f in json.loads(out)["findings"]]
    assert {k for k, _ in left} == {"code"}, left                          # only the taint bugs remain
    code, out, _ = run(capsys, "fix", repo, "--no-git", "--yes")
    assert code == 0 and "Nothing can be fixed automatically" in out


def test_fix_without_a_terminal_or_yes_changes_nothing(capsys, repo, patch_osv, monkeypatch):
    before = {p: p.read_bytes() for p in repo.rglob("*") if p.is_file()}
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    code, out, err = run(capsys, "fix", repo, "--no-git")
    assert code == 2 and "--yes" in err and "+++ b/" in out
    assert before == {p: p.read_bytes() for p in repo.rglob("*") if p.is_file()}


def test_interactive_confirmation(capsys, repo, patch_osv, monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _="": "n")
    code, out, err = run(capsys, "fix", repo, "--no-git")
    assert code == 0 and "Nothing changed" in err
    assert "4.17.20" in (repo / "package-lock.json").read_text()
    monkeypatch.setattr("builtins.input", lambda _="": "y")
    code, out, _ = run(capsys, "fix", repo, "--no-git")
    assert code == 0 and "verified: 8 of 8" in out


def test_patch_file_is_written_and_nothing_is_applied(capsys, repo, patch_osv, tmp_path):
    patch = tmp_path / "out.diff"
    code, out, err = run(capsys, "fix", repo, "--no-git", "--patch", patch)
    assert code == 0 and patch.exists()
    assert "4.17.20" in (repo / "package-lock.json").read_text(), "--patch alone must not apply"
    assert patch.read_text().count("\n+++ b/") >= 8


def test_patch_applies_cleanly_with_git_and_equals_yes(capsys, git_repo, patch_osv, tmp_path):
    patch = tmp_path / "out.diff"
    run(capsys, "fix", git_repo, "--patch", patch)
    twin = tmp_path / "twin"
    shutil.copytree(FIXTURE, twin)
    run(capsys, "fix", twin, "--no-git", "--yes")
    subprocess.run(["git", "-C", str(git_repo), "apply", "--check", str(patch)], check=True)
    subprocess.run(["git", "-C", str(git_repo), "apply", str(patch)], check=True)
    for rel in ("package-lock.json", "requirements.txt", "java/pom.xml", "svc-go/go.mod", "app/config.py",
                "web/app.js", "deploy/nginx.conf", ".env.example", ".gitignore"):
        assert (git_repo / rel).read_text() == (twin / rel).read_text(), rel


def test_json_output_lists_fixes_gate_and_skips(capsys, repo, patch_osv):
    code, rep, _ = fix_json(capsys, repo)
    assert len(rep["fixes"]) == 8 and all(f["gate"]["ok"] for f in rep["fixes"])
    engines_used = {f["gate"]["engine"] for f in rep["fixes"]}
    assert engines_used == {"remediation.gate", "cli secret gate"}
    assert all(f["resolves"] for f in rep["fixes"])


def _scan_plans(repo, osv, **kw):
    client = OsvClient(transport=osv, cache=repo.parent / "c2")
    res = scanner.scan(repo, osv=client, use_git=False)
    return fixplan.plan_fixes(res, repo, client, **kw)


def test_major_upgrades_are_skipped_unless_allowed(repo):
    adv = [{**a, "ranges": [("0", "5.0.0")]} if a["id"] == "GHSA-35jh-r3h4-6jhm" else a
           for a in fake_osv.ADVISORIES if a["id"] != "GHSA-p6mc-m468-83gw"]
    osv = fake_osv.FakeOsv(adv)
    plans, skipped = _scan_plans(repo, osv)
    assert not any("lodash" in p.title for p in plans)
    why = next(s.reason for s in skipped if "lodash" in s.finding.title)
    assert "major upgrade" in why and "--allow-major" in why
    plans, skipped = _scan_plans(repo, osv, allow_major=True)
    # package.json still says ^4.17.19, which excludes 5.0.0, so even --allow-major leaves it to the human
    assert "package.json" in next(s.reason for s in skipped if "lodash" in s.finding.title)
    (repo / "package.json").write_text('{"dependencies": {"lodash": "*"}}')
    plans, _ = _scan_plans(repo, osv, allow_major=True)
    p = next(p for p in plans if "lodash" in p.title)
    assert p.breaking and p.gate_ok and "major version change" in " ".join(p.notes)


def test_npm_range_that_excludes_the_fix_is_not_edited(repo, osv):
    (repo / "package.json").write_text('{"dependencies": {"lodash": "~4.16.0"}}')
    plans, skipped = _scan_plans(repo, osv)
    s = next(s for s in skipped if "lodash" in s.finding.title)
    assert "package.json" in s.reason and "excludes 4.17.21" in s.reason


def test_unsupported_manifests_get_a_clear_reason(tmp_path, osv):
    d = tmp_path / "p"
    d.mkdir()
    (d / "poetry.lock").write_text('[[package]]\nname = "requests"\nversion = "2.19.0"\n')
    plans, skipped = _scan_plans(d, osv)
    assert not plans and "not supported yet" in skipped[0].reason and "2.31.0" in skipped[0].reason


def test_requirements_with_extras_markers_comments_and_crlf(tmp_path, osv):
    d = tmp_path / "p"
    d.mkdir()
    (d / "requirements.txt").write_bytes(
        b"# deps\r\nRequests[security]==2.19.0 ; python_version >= '3.8'  # pinned\r\nflask>=2\r\n")
    plans, _ = _scan_plans(d, osv)
    assert len(plans) == 1 and plans[0].gate_ok
    apply_plans(plans, d)
    assert (d / "requirements.txt").read_bytes() == (
        b"# deps\r\nRequests[security]==2.31.0 ; python_version >= '3.8'  # pinned\r\nflask>=2\r\n")


def test_requirements_fix_matches_the_remediation_generator(tmp_path):
    gen = engines.generators()
    base = "requests==2.19.0\nflask==2.0.0\n"
    g = gen.generate_dependency_bump({"ecosystem": "PyPI", "package": "requests",
                                      "current_version": "2.19.0", "fixed_version": "2.31.0",
                                      "lockfile_path": "requirements.txt", "base_content": base})
    assert fixplan.unified_diff("requirements.txt", base,
                                fixplan.bump_requirements(base, "requests", "2.19.0", "2.31.0")) == g.unified


def test_pom_property_versions(tmp_path):
    pom = ("<project><properties><log4j.version>2.14.1</log4j.version></properties><dependencies>"
           "<dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId>"
           "<version>${log4j.version}</version></dependency></dependencies></project>")
    out, why = fixplan.bump_pom(pom, "org.apache.logging.log4j:log4j-core", "2.14.1", "2.17.1")
    assert "<log4j.version>2.17.1</log4j.version>" in out and "${log4j.version}" in out
    shared = pom.replace("</dependencies>", "<dependency><groupId>g</groupId><artifactId>a</artifactId>"
                         "<version>${log4j.version}</version></dependency></dependencies>")
    out, why = fixplan.bump_pom(shared, "org.apache.logging.log4j:log4j-core", "2.14.1", "2.17.1")
    assert out is None and "shared" in why


def test_npm_lock_edit_variants():
    pretty = ('{\n  "packages": {\n    "node_modules/a/node_modules/lodash": {\n'
              '      "version": "4.17.20",\n      "resolved": "https://r/lodash-4.17.20.tgz",\n'
              '      "integrity": "sha512-x",\n      "dev": true\n    },\n'
              '    "node_modules/lodash": {\n      "version": "4.17.20",\n'
              '      "integrity": "sha512-y"\n    }\n  }\n}\n')
    core, full = fixplan.bump_npm_lock(pretty, "lodash", "4.17.20", "4.17.21")
    assert core.count("4.17.21") == 2 and "sha512" in core, "core only touches versions"
    doc = json.loads(full)
    for entry in doc["packages"].values():
        assert entry["version"] == "4.17.21" and "integrity" not in entry
    assert doc["packages"]["node_modules/a/node_modules/lodash"]["dev"] is True
    assert fixplan.bump_npm_lock(pretty, "lodash", "9.9.9", "10.0.0") == (None, None)
    assert fixplan.bump_npm_lock(pretty, "lodash-es", "4.17.20", "4.17.21") == (None, None)
    v1 = '{"dependencies":{"lodash":{"version":"4.17.20","resolved":"https://r/lodash-4.17.20.tgz","integrity":"sha512-z"}}}'
    _, full = fixplan.bump_npm_lock(v1, "lodash", "4.17.20", "4.17.21")
    assert json.loads(full)["dependencies"]["lodash"] == {
        "version": "4.17.21", "resolved": "https://r/lodash-4.17.21.tgz"}


# --- secrets ---------------------------------------------------------------- #

def _secret_plans(tmp_path, name, text, osv=None):
    d = tmp_path / "s"
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(text)
    client = OsvClient(transport=osv or fake_osv.FakeOsv(), cache=tmp_path / "c")
    res = scanner.scan(d, osv=client, use_git=False, only={"secrets", "code"})
    return d, *fixplan.plan_fixes(res, d, client)


def test_python_secret_import_placement(tmp_path):
    src = '"""Doc."""\nfrom __future__ import annotations\n\nimport sys\n\nclass C:\n    dbPassword = "Zx9Kp2Lm8Qr4Vt7Wb3Nd"  # prod\n'
    d, plans, skipped = _secret_plans(tmp_path, "m.py", src)
    assert len(plans) == 1 and plans[0].gate_ok, skipped
    apply_plans(plans, d)
    out = (d / "m.py").read_text()
    ast.parse(out)
    assert out.index("from __future__") < out.index("import os") < out.index("import sys")
    assert '    dbPassword = os.environ["DB_PASSWORD"]  # prod' in out


def test_existing_import_os_is_not_duplicated(tmp_path):
    src = 'import os\n\nAPI_KEY = "Zx9Kp2Lm8Qr4Vt7Wb3Nd"\nOTHER = os.getcwd()\n'
    d, plans, _ = _secret_plans(tmp_path, "m.py", src)
    apply_plans(plans, d)
    assert (d / "m.py").read_text().count("import os") == 1


def test_two_secrets_in_one_file(tmp_path):
    src = 'DB_PASSWORD = "Zx9Kp2Lm8Qr4Vt7Wb3Nd"\nAPI_SECRET = "Qw8Er7Ty6Ui5Op4As3Df"\n'
    d, plans, _ = _secret_plans(tmp_path, "m.py", src)
    assert len(plans) == 2
    apply_plans(plans, d)
    out = (d / "m.py").read_text()
    ast.parse(out)
    assert out.count('os.environ["') == 2 and out.count("import os") == 1
    assert (d / ".env.example").read_text().count("=\n") == 2


def test_typescript_secret(tmp_path):
    d, plans, _ = _secret_plans(tmp_path, "a.ts", 'export const apiKey = "Zx9Kp2Lm8Qr4Vt7Wb3Nd"; // prod\n')
    apply_plans(plans, d)
    assert (d / "a.ts").read_text() == "export const apiKey = process.env.API_KEY; // prod\n"
    from paddock_cli.secrets_scan import JS_ASSIGN
    assert JS_ASSIGN.match('const apiKey: string = "Zx9Kp2Lm8Qr4Vt7Wb3Nd";')


def test_unsupported_secret_locations_are_left_for_the_human(tmp_path):
    d, plans, skipped = _secret_plans(tmp_path, "main.go", 'package main\nvar apiKey = "Zx9Kp2Lm8Qr4Vt7Wb3Nd"\n')
    assert not plans and "not supported" in skipped[0].reason
    token = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"      # token-shaped, built at runtime
    d2, plans, skipped = _secret_plans(tmp_path / "y", "m.py", f'c = connect(token="{token}")\n')
    assert not plans and "simple" in skipped[0].reason


def test_secret_gate_blocks_a_rewrite_that_keeps_the_secret(tmp_path):
    d, plans, _ = _secret_plans(tmp_path, "m.py", 'DB_PASSWORD = "Zx9Kp2Lm8Qr4Vt7Wb3Nd"\n')
    p = plans[0]
    assert fixplan.secret_gate(p, "Zx9Kp2Lm8Qr4Vt7Wb3Nd") == []
    p.edits[0].after += '# Zx9Kp2Lm8Qr4Vt7Wb3Nd\n'
    assert any("still appear" in r for r in fixplan.secret_gate(p, "Zx9Kp2Lm8Qr4Vt7Wb3Nd"))
    p.edits[1].after += "DB_PASSWORD=Zx9Kp2Lm8Qr4Vt7Wb3Nd\n"
    assert any(".env.example may only" in r for r in fixplan.secret_gate(p, "Zx9Kp2Lm8Qr4Vt7Wb3Nd"))


def test_the_remediation_gate_denies_source_edits_so_secrets_need_their_own_gate(tmp_path):
    d, plans, _ = _secret_plans(tmp_path, "m.py", 'DB_PASSWORD = "Zx9Kp2Lm8Qr4Vt7Wb3Nd"\n')
    res = engines.gate().check(plans[0].unified, "dependency_bump",
                               {"package": "x", "current_version": "1", "fixed_version": "2"})
    assert not res.ok and any("source-code" in r for r in res.reasons)


# --- safety ------------------------------------------------------------------ #

def test_apply_refuses_when_a_file_changed_since_the_plan(repo, osv):
    plans, _ = _scan_plans(repo, osv)
    (repo / "requirements.txt").write_text("requests==2.19.0\n# edited meanwhile\n")
    with pytest.raises(ApplyError, match="changed since"):
        apply_plans(plans, repo)
    assert "2.19.0" in (repo / "requirements.txt").read_text()
    assert "4.17.20" in (repo / "package-lock.json").read_text(), "nothing is written on refusal"


def test_apply_never_writes_outside_the_repo(tmp_path):
    from paddock_cli.fixplan import Edit, FixPlan
    d = tmp_path / "r"
    d.mkdir()
    p = FixPlan(id="x", kind="config", title="t", resolves=[], edits=[Edit("../evil.txt", None, "x\n")])
    with pytest.raises(ApplyError, match="outside"):
        apply_plans([p], d)
    assert not (tmp_path / "evil.txt").exists()


def test_offline_fix_cannot_verify_new_versions_and_says_so(capsys, repo, patch_osv):
    run(capsys, "scan", repo, "--no-git", "--json")            # warm the cache for current versions
    code, out, _ = run(capsys, "fix", repo, "--no-git", "--yes", "--offline", "--only", "deps")
    assert code == 1
    assert "unverified" in out and "could not be checked against OSV" in out
    assert "verified: 0 of 4 fixed" in out


def test_fix_does_not_touch_files_it_has_no_fix_for(capsys, repo, patch_osv):
    before = (repo / "app/server.py").read_bytes()
    run(capsys, "fix", repo, "--no-git", "--yes")
    assert (repo / "app/server.py").read_bytes() == before     # taint bugs need a human
