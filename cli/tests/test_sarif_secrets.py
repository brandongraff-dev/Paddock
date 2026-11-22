import json

from conftest import run
from paddock_cli import secrets_scan as S


def test_sarif_is_valid_2_1_0_and_matches_the_orchestrator_shape(capsys, repo, patch_osv, tmp_path):
    out = tmp_path / "r.sarif"
    code, _, _ = run(capsys, "scan", repo, "--no-git", "--sarif", out)
    doc = json.loads(out.read_text())
    assert doc["version"] == "2.1.0" and doc["$schema"].endswith("sarif-2.1.0.json")
    run_ = doc["runs"][0]
    driver = run_["tool"]["driver"]
    assert driver["name"] == "Paddock"
    rules = {r["id"]: r for r in driver["rules"]}
    results = run_["results"]
    assert len(results) >= 10
    for r in results:
        assert r["ruleId"] in rules and r["level"] in ("error", "warning", "note")
        loc = r["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] and not loc["artifactLocation"]["uri"].startswith("/")
        assert "paddock/v1" in r["partialFingerprints"]
    # each dependency advisory is its own rule with a security-severity (GitHub sorts on it)
    assert "GHSA-35jh-r3h4-6jhm" in rules
    assert float(rules["GHSA-35jh-r3h4-6jhm"]["properties"]["security-severity"]) > 0
    sqli = next(r for r in results if "sql" in r["ruleId"].lower())
    assert sqli["locations"][0]["physicalLocation"]["region"]["startLine"] == 14
    assert sqli.get("codeFlows"), "taint dataflow is carried into SARIF"
    assert run_["automationDetails"]["id"].startswith("paddock-cli/")


def test_sarif_to_stdout_suppresses_the_pretty_report(capsys, repo, patch_osv):
    code, out, _ = run(capsys, "scan", repo, "--no-git", "--sarif", "-")
    assert json.loads(out)["version"] == "2.1.0"
    assert run(capsys, "scan", repo, "--json", "--sarif", "-")[0] == 2


def fake(prefix, body):
    return prefix + body      # built at runtime so no token-shaped literal sits in the repo


def test_token_formats_are_detected_in_any_text_file(tmp_path):
    cases = {
        "aws-access-key-id": fake("AKIA", "QWERTYUIOP123456"),
        "github-token": fake("ghp_", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"),
        "slack-token": fake("xoxb-", "1234567890-abcdefghijkl"),
        "stripe-live-key": fake("sk_live_", "abcdEFGH1234ijklMNOP5678"),
        "google-api-key": fake("AIza", "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"),
        "private-key": fake("-----BEGIN RSA ", "PRIVATE KEY-----"),
    }
    for rule, value in cases.items():
        hits = list(S.scan_text("notes/readme.txt", f"some text\nvalue: {value}\n"))
        assert [h.rule for h in hits] == [rule], rule
        assert hits[0].line == 2
        assert value not in hits[0].preview, "previews are redacted"


def test_placeholders_examples_and_lockfiles_are_not_flagged():
    assert not list(S.scan_text("a.txt", "key = " + fake("AKIAIOSFODNN7", "EXAMPLE")))
    assert not list(S.scan_text("config.yml", 'password: "changeme123"'))
    assert not list(S.scan_text("config.yml", 'password: "${DB_PASSWORD}"'))
    assert not list(S.scan_text("config.yml", 'api_key: "your_api_key_here1"'))
    assert not list(S.scan_text(".env.example", 'API_TOKEN="Zx9Kp2Lm8Qr4Vt7Wb3Nd"'))
    assert not list(S.scan_text("package-lock.json", '"integrity": "sha512-Zx9Kp2Lm8Qr4Vt7Wb3Nd=="'))
    assert not list(S.scan_text("config.yml", 'name: "plainwordsonly"'))


def test_generic_assignments_only_in_config_style_files():
    line = 'db_password: "Zx9Kp2Lm8Qr4Vt7Wb3Nd"\n'
    hit, = S.scan_text("deploy/values.yaml", line)
    assert hit.rule == "generic-credential" and hit.var_name == "db_password"
    assert not list(S.scan_text("src/notes.md", line)), "prose is left alone"


def test_secret_in_an_env_file_and_a_yaml_is_reported(capsys, tmp_path, patch_osv):
    d = tmp_path / "r"
    d.mkdir()
    (d / "deploy.yml").write_text(f'token: "{fake("ghp_", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8")}"\n')
    code, out, _ = run(capsys, "scan", d, "--no-git", "--json", "--only", "secrets")
    findings = json.loads(out)["findings"]
    assert len(findings) == 1 and findings[0]["rule_id"] == "secret:github-token"


def test_env_name():
    assert S.env_name("dbPassword") == "DB_PASSWORD"
    assert S.env_name("DB_PASSWORD") == "DB_PASSWORD"
    assert S.env_name("api-key") == "API_KEY"
    assert S.env_name("9lives") == "SECRET_9LIVES"
