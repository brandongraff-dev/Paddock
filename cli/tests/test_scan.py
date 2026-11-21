import json

from conftest import run

FAKE_PASSWORD = "Zx9Kp2Lm8Qr4Vt7Wb3Nd"          # planted in tests/fixtures/vuln-repo/app/config.py


def scan_json(capsys, repo, *extra):
    code, out, _ = run(capsys, "scan", repo, "--json", "--no-git", *extra)
    return code, json.loads(out)


def titles(report, kind):
    return [f["title"] for f in report["findings"] if f["kind"] == kind]


def test_finds_vulnerable_dependencies_in_every_supported_ecosystem(capsys, repo, patch_osv):
    _, rep = scan_json(capsys, repo)
    deps = {f["data"]["ecosystem"]: f for f in rep["findings"] if f["kind"] == "dependency"}
    assert set(deps) == {"npm", "PyPI", "Go", "Maven"}
    assert deps["npm"]["data"]["package"] == "lodash" and deps["npm"]["file"] == "package-lock.json"
    assert deps["PyPI"]["data"]["fixed_version"] == "2.31.0"          # one bump clears both advisories
    assert deps["Maven"]["severity"] == "critical"
    assert deps["Go"]["data"]["package"] == "github.com/gin-gonic/gin"
    assert deps["npm"]["line"] == 16 and deps["PyPI"]["line"] == 2    # annotated at the manifest line
    assert "CVE-2021-23337" in deps["npm"]["data"]["cve_ids"]


def test_finds_the_planted_secret_the_taint_bug_and_the_misconfig(capsys, repo, patch_osv):
    _, rep = scan_json(capsys, repo)
    secrets = {f["file"] for f in rep["findings"] if f["kind"] == "secret"}
    assert secrets == {"app/config.py", "web/app.js"}
    code = {f["data"]["rule_class"] for f in rep["findings"] if f["kind"] == "code"}
    assert {"sql_injection", "command_injection"} <= code
    sqli = next(f for f in rep["findings"] if f["data"].get("rule_class") == "sql_injection")
    assert sqli["file"] == "app/server.py" and sqli["cwe"] == "CWE-89"
    assert sqli["data"]["dataflow"], "source -> sink steps are kept"
    cfg = {f["rule_id"] for f in rep["findings"] if f["kind"] == "config"}
    assert cfg == {"config:nginx-weak-tls", "config:nginx-no-hsts"}


def test_every_finding_explains_why_it_matters(capsys, repo, patch_osv):
    _, rep = scan_json(capsys, repo)
    assert rep["findings"]
    for f in rep["findings"]:
        assert len(f["why"]) > 30 and f["fix"], f["title"]


def test_the_secret_value_never_appears_in_any_output(capsys, repo, patch_osv, tmp_path):
    sarif = tmp_path / "out.sarif"
    code, out, err = run(capsys, "scan", repo, "--no-git", "--sarif", sarif)
    code2, jout, _ = run(capsys, "scan", repo, "--no-git", "--json")
    blob = out + err + jout + sarif.read_text()
    assert FAKE_PASSWORD not in blob and "a1B2c3D4e5F6g7H8" not in blob


def test_pretty_report_is_grouped_and_mentions_fix(capsys, repo, patch_osv):
    code, out, _ = run(capsys, "scan", repo, "--no-git")
    assert code == 0                                   # no --fail-on: informational by default
    for heading in ("VULNERABLE DEPENDENCIES", "SECRETS", "CODE", "CONFIGURATION"):
        assert heading in out
    assert "why" in out and "paddock fix" in out
    assert "\x1b[" not in out, "no colour when stdout is not a terminal"


def test_exit_codes_for_ci(capsys, repo, patch_osv):
    assert run(capsys, "scan", repo, "--no-git", "--fail-on", "critical")[0] == 1
    assert run(capsys, "scan", repo, "--no-git", "--fail-on", "high")[0] == 1
    assert run(capsys, "scan", repo, "--no-git", "--only", "config", "--fail-on", "high")[0] == 0
    assert run(capsys, "scan", repo, "--no-git", "--only", "config", "--fail-on", "low")[0] == 1
    assert run(capsys, "scan", "/definitely/not/here")[0] == 2


def test_clean_repo_is_clean(capsys, tmp_path, patch_osv):
    (tmp_path / "ok").mkdir()
    (tmp_path / "ok" / "main.py").write_text("print('hi')\n")
    code, out, _ = run(capsys, "scan", tmp_path / "ok", "--no-git", "--fail-on", "low")
    assert code == 0 and "Nothing found" in out


def test_json_shape(capsys, repo, patch_osv):
    code, rep = scan_json(capsys, repo)
    assert rep["tool"]["name"] == "paddock-cli"
    assert rep["summary"]["total"] == len(rep["findings"]) == 10
    assert rep["summary"]["critical"] == 2
    assert {"id", "kind", "severity", "title", "why", "file", "line", "fix"} <= rep["findings"][0].keys()
    assert any(f["auto_fixable"] for f in rep["findings"])


def test_only_selects_scanners(capsys, repo, patch_osv, osv):
    _, rep = scan_json(capsys, repo, "--only", "secrets")
    assert {f["kind"] for f in rep["findings"]} == {"secret"}
    assert not osv.calls, "--only secrets must not query OSV"


def test_exclude_globs(capsys, repo, patch_osv):
    _, rep = scan_json(capsys, repo, "--exclude", "app/*", "--exclude", "web")
    assert not [f for f in rep["findings"] if f["kind"] in ("secret", "code")]


def test_malicious_and_typosquat_packages(capsys, tmp_path, patch_osv):
    d = tmp_path / "r"
    d.mkdir()
    (d / "requirements.txt").write_text("reqeusts==1.0.0\n")
    (d / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"evil-demo-pkg": "1.0.0"}},
        "node_modules/evil-demo-pkg": {"version": "1.0.0"}}}))
    _, rep = scan_json(capsys, d)
    mal = [f for f in rep["findings"] if f["kind"] == "malicious"]
    assert mal and mal[0]["severity"] == "critical" and "MAL-2024-0001" in mal[0]["message"]
    squat = [f for f in rep["findings"] if f["kind"] == "typosquat"]
    assert squat and squat[0]["data"]["resembles"] == "requests"


def test_offline_with_cold_cache_says_so_and_reports_no_vulns(capsys, repo, patch_osv, osv):
    code, rep = scan_json(capsys, repo, "--offline")
    assert not osv.calls
    assert not [f for f in rep["findings"] if f["kind"] == "dependency"]
    assert rep["stats"]["osv_unchecked"] == 4
    assert any("offline cache" in n for n in rep["notes"])


def test_offline_with_warm_cache_matches_online(capsys, repo, patch_osv, osv):
    _, online = scan_json(capsys, repo)
    calls = len(osv.calls)
    _, offline = scan_json(capsys, repo, "--offline")
    assert len(osv.calls) == calls
    key = lambda r: sorted(f["id"] for f in r["findings"])  # noqa: E731
    assert key(online) == key(offline)


def test_go_sum_is_filtered_through_go_mod(capsys, tmp_path, patch_osv):
    d = tmp_path / "g"
    d.mkdir()
    (d / "go.mod").write_text("module m\n\ngo 1.21\n\nrequire github.com/gin-gonic/gin v1.7.7\n")
    (d / "go.sum").write_text(
        "github.com/gin-gonic/gin v1.6.3 h1:aaa=\ngithub.com/gin-gonic/gin v1.7.7 h1:bbb=\n")
    _, rep = scan_json(capsys, d)
    assert not rep["findings"], "the old go.sum entry is not what gets built"
