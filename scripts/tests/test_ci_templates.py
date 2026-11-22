"""integrations/ci: the shared script (against a fake curl) and the templates.

Run from the repo root:  pytest -q scripts/tests/test_ci_templates.py
"""
from __future__ import annotations

import json
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CI = ROOT / "integrations" / "ci"
SCRIPT = CI / "paddock-ci.sh"

# A curl stand-in: records argv (one arg per line) and writes FAKE_CURL_BODY to -o FILE.
FAKE_CURL = r"""#!/bin/bash
printf '%s\n' "$@" > "$FAKE_CURL_ARGS"
out=""
prev=""
for a in "$@"; do
  [ "$prev" = "-o" ] && out="$a"
  prev="$a"
done
[ -n "${FAKE_CURL_STDIN_COPY:-}" ] && for a in "$@"; do case "$a" in @*) cp "${a#@}" "$FAKE_CURL_STDIN_COPY";; esac; done
[ -n "$out" ] && printf '%s' "$FAKE_CURL_BODY" > "$out"
exit "${FAKE_CURL_RC:-0}"
"""

SARIF = {"runs": [{"tool": {"driver": {"rules": [
    {"properties": {"security-severity": "8.8"}}, {"properties": {"security-severity": "3.0"}}]}},
    "results": [{"ruleIndex": 0}, {"ruleIndex": 1}, {"ruleIndex": 0, "suppressions": [{"kind": "external"}]}]}]}


@pytest.fixture
def box(tmp_path):
    b = tmp_path / "bin"
    b.mkdir()
    c = b / "curl"
    c.write_text(FAKE_CURL)
    c.chmod(c.stat().st_mode | stat.S_IEXEC)
    w = tmp_path / "work"
    w.mkdir()
    return {"bin": b, "work": w, "args": tmp_path / "args.txt", "copy": tmp_path / "body.json", "tmp": tmp_path}


def run(box, *args, env=None, body="{}", rc=0):
    e = {"PATH": f"{box['bin']}:/usr/bin:/bin", "HOME": str(box["tmp"]), "FAKE_CURL_ARGS": str(box["args"]),
         "FAKE_CURL_BODY": body, "FAKE_CURL_RC": str(rc), "FAKE_CURL_STDIN_COPY": str(box["copy"])}
    e.update(env or {})
    return subprocess.run(["bash", str(SCRIPT), *args], env=e, cwd=box["work"], capture_output=True, text=True, timeout=60)


def argv(box) -> list[str]:
    return box["args"].read_text().splitlines()


GOOD = {"PADDOCK_URL": "https://paddock.example.com", "PADDOCK_INGEST_TOKEN": "pdi_tok"}


def test_shellcheck():
    sc = shutil.which("shellcheck")
    if not sc:
        pytest.skip("shellcheck not installed")
    assert subprocess.run([sc, str(SCRIPT)], capture_output=True, text=True).returncode == 0


def test_ingest_sends_token_url_and_params(box):
    (box["work"] / "trivy.json").write_text('{"SchemaVersion": 2}')
    body = json.dumps({"source": "ci", "format": "trivy", "status": "ok", "findings_new": 3, "errors": []})
    r = run(box, "ingest", "trivy.json", "--format", "trivy", "--asset", "web 1/x", "--strict", env={**GOOD, "PADDOCK_PROJECT": "acme/web"}, body=body)
    assert r.returncode == 0, r.stderr
    a = argv(box)
    url = next(x for x in a if x.startswith("https://"))
    assert url.startswith("https://paddock.example.com/v1/ingest?")
    for part in ("format=trivy", "project=acme%2Fweb", "asset=web%201%2Fx", "strict=true"):
        assert part in url, url
    assert "X-Paddock-Ingest-Token: pdi_tok" in a and "--data-binary" in a
    assert any(x.startswith("@") and x.endswith("trivy.json") for x in a)
    assert '"findings_new":3' in r.stdout
    assert "pdi_tok" not in r.stdout + r.stderr                                     # never echoed


def test_ingest_with_api_key_and_project_detection(box):
    (box["work"] / "r.sarif").write_text("{}")
    r = run(box, "ingest", "r.sarif", env={"PADDOCK_URL": "https://p.example.com/", "PADDOCK_API_KEY": "pak_x",
                                           "CI_PROJECT_PATH": "grp/proj"})
    assert r.returncode == 0
    a = argv(box)
    assert "X-API-Key: pak_x" in a and not any("Ingest-Token" in x for x in a)
    assert any("project=grp%2Fproj" in x for x in a)
    assert any(x.startswith("https://p.example.com/v1/ingest?") for x in a)         # trailing slash trimmed


@pytest.mark.parametrize("env,msg", [
    ({"PADDOCK_URL": "http://paddock.example.com", "PADDOCK_INGEST_TOKEN": "t"}, "plain http"),
    ({"PADDOCK_URL": "ftp://x", "PADDOCK_INGEST_TOKEN": "t"}, "https://"),
    ({"PADDOCK_INGEST_TOKEN": "t"}, "PADDOCK_URL"),
    ({"PADDOCK_URL": "https://p.example.com"}, "PADDOCK_INGEST_TOKEN"),
])
def test_ingest_refuses_bad_config(box, env, msg):
    (box["work"] / "f.json").write_text("{}")
    r = run(box, "ingest", "f.json", env=env)
    assert r.returncode == 2 and msg in r.stderr and not box["args"].exists()


def test_http_allowed_for_localhost_or_override(box):
    (box["work"] / "f.json").write_text("{}")
    assert run(box, "ingest", "f.json", env={"PADDOCK_URL": "http://localhost:8080", "PADDOCK_INGEST_TOKEN": "t"}).returncode == 0
    assert run(box, "ingest", "f.json", env={"PADDOCK_URL": "http://paddock.lan", "PADDOCK_INGEST_TOKEN": "t",
                                             "PADDOCK_ALLOW_HTTP": "1"}).returncode == 0


def test_ingest_missing_file_and_server_error(box):
    assert run(box, "ingest", "nope.json", env=GOOD).returncode == 2
    (box["work"] / "f.json").write_text("{}")
    r = run(box, "ingest", "f.json", env=GOOD, rc=22, body='{"detail":"invalid ingest token"}')
    assert r.returncode == 22                                                       # build fails on a rejected upload


def test_soft_fail_only_for_unreachable(box):
    (box["work"] / "f.json").write_text("{}")
    env = {**GOOD, "PADDOCK_SOFT_FAIL": "1"}
    assert run(box, "ingest", "f.json", env=env, rc=7).returncode == 0              # connection refused
    assert "unreachable" in run(box, "ingest", "f.json", env=env, rc=28).stderr
    assert run(box, "ingest", "f.json", env=env, rc=22).returncode == 22            # HTTP 4xx is still a failure


def test_lockfiles_payload_is_safe_and_filtered(box):
    w = box["work"]
    (w / "package-lock.json").write_text('{"lockfileVersion": 3}')
    (w / "sub").mkdir()
    (w / "sub" / "requirements.txt").write_text("flask==2.3.0\n")
    (w / "node_modules").mkdir()
    (w / "node_modules" / "package-lock.json").write_text("{}")
    (w / "notes.txt").write_text("not a lockfile")
    r = run(box, "lockfiles", env={"PADDOCK_URL": "https://p.example.com", "PADDOCK_API_KEY": "pak_k",
                                   "PADDOCK_PROJECT": "acme/web"}, body='{"project":"acme/web","components":5}')
    assert r.returncode == 0, r.stderr
    payload = json.loads(box["copy"].read_text())
    assert payload["project"] == "acme/web" and sorted(payload["files"]) == ["package-lock.json", "sub/requirements.txt"]
    assert any(x == "https://p.example.com/v1/import/lockfiles" for x in argv(box))
    assert "X-API-Key: pak_k" in argv(box)


def test_gate_fails_on_unsuppressed_high_only(box):
    env = {"PADDOCK_URL": "https://p.example.com", "PADDOCK_API_KEY": "k", "PADDOCK_PROJECT": "p"}
    r = run(box, "gate", "--fail-on", "high", env=env, body=json.dumps(SARIF))
    assert r.returncode == 1 and "1 unsuppressed" in r.stderr                       # 8.8 counts, 3.0 and the suppressed one do not
    assert run(box, "gate", "--fail-on", "critical", env=env, body=json.dumps(SARIF)).returncode == 0
    assert run(box, "gate", "--fail-on", "nonsense", env=env).returncode == 2
    clean = {"runs": [{"tool": {"driver": {"rules": []}}, "results": []}]}
    assert run(box, "gate", "--fail-on", "low", env=env, body=json.dumps(clean)).returncode == 0


def test_hook_modes_never_block_when_unconfigured_or_offline(box):
    assert run(box, "gate", "--fail-on", "high", "--soft", env={}).returncode == 0
    r = run(box, "precommit", "package-lock.json", env={})
    assert r.returncode == 0 and "skipping" in r.stderr
    (box["work"] / "go.mod").write_text("module x\n")
    env = {"PADDOCK_URL": "https://p.example.com", "PADDOCK_API_KEY": "k"}
    assert run(box, "precommit", "go.mod", "README.md", env=env, rc=7).returncode == 0
    assert run(box, "gate", "--fail-on", "high", "--soft", env=env, rc=7).returncode == 0


def test_unknown_command_and_help(box):
    assert run(box, "frobnicate").returncode == 2
    h = run(box, "--help")
    assert h.returncode == 0 and "paddock-ci.sh ingest" in h.stdout


# --------------------------------------------------------------------------- #
# templates
# --------------------------------------------------------------------------- #

YAMLS = ["gitlab-ci.yml", "bitbucket-pipelines.yml", "azure-pipelines.yml", "circleci-config.yml",
         "pre-commit-config.yaml"]


@pytest.mark.parametrize("name", YAMLS)
def test_yaml_templates_parse(name):
    assert isinstance(yaml.safe_load((CI / name).read_text()), (dict, list))


@pytest.mark.parametrize("name", YAMLS + ["Jenkinsfile"])
def test_templates_use_secrets_not_literals_and_call_the_script(name):
    text = (CI / name).read_text()
    assert "pdi_" not in text and "pak_" not in text                               # no embedded credentials
    if name != "pre-commit-config.yaml":
        assert "paddock-ci" in text and "PADDOCK_INGEST_TOKEN" in text and "/v1/ingest" not in text.replace("paddock-ci", "")
    assert "set -x" not in text and "curl -k" not in text and "--insecure" not in text


def test_jenkinsfile_uses_credentials_binding_and_single_quotes():
    t = (CI / "Jenkinsfile").read_text()
    assert "credentials('paddock-ingest-token')" in t and "sh '''" in t and 'sh """' not in t


def test_precommit_hooks_manifest():
    hooks = {h["id"]: h for h in yaml.safe_load((ROOT / ".pre-commit-hooks.yaml").read_text())}
    assert set(hooks) == {"paddock-lockfiles", "paddock-gate"}
    for h in hooks.values():
        assert h["language"] == "script" and (ROOT / h["entry"].split()[0]).is_file()
    assert hooks["paddock-gate"]["stages"] == ["pre-push"] and "--soft" in hooks["paddock-gate"]["entry"]
