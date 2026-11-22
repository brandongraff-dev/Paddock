import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from conftest import run
from paddock_cli import initcmd, upload

ALLOWED_RULE_SOURCES = {"nuclei", "cve_match", "policy", "chain", "secret_scan", "tls_check",
                        "header_check", "exposed_file", "manual", "takeover", "tls_grade", "sca",
                        "sast", "threat_intel"}   # orchestrator/app/constants.py RULE_SOURCES
SECRET = "Zx9Kp2Lm8Qr4Vt7Wb3Nd"


class Server:
    """A throwaway stand-in for the Paddock orchestrator."""

    def __init__(self):
        self.requests = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _reply(self, obj, code=200):
                data = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                outer.requests.append(("GET", self.path, self.headers.get("X-API-Key"), None))
                if self.path == "/healthz":
                    return self._reply({"status": "ok"})
                if self.path == "/v1/auth/me":
                    ok = self.headers.get("X-API-Key") == "pak_test"
                    return self._reply({"username": "ci-bot"} if ok else {"detail": "no"},
                                       200 if ok else 401)
                self._reply({}, 404)

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.requests.append(("POST", self.path, self.headers.get("X-API-Key"), body))
                self._reply({"inserted": len(body["items"]), "updated": 0, "items": []})

        self.srv = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_port}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()


@pytest.fixture
def server():
    s = Server()
    yield s
    s.close()


def test_upload_posts_findings_to_the_bulk_api(capsys, repo, patch_osv, server, monkeypatch):
    monkeypatch.setenv("PADDOCK_API_KEY", "pak_test")
    code, out, err = run(capsys, "upload", repo, "--no-git", "--server", server.url, "--project", "demo")
    assert code == 0 and "uploaded 10 findings" in out
    posts = [r for r in server.requests if r[0] == "POST"]
    assert len(posts) == 1 and posts[0][1] == "/v1/findings/bulk" and posts[0][2] == "pak_test"
    items = posts[0][3]["items"]
    assert len(items) == 10
    assert {i["rule_source"] for i in items} == {"sca", "sast", "secret_scan", "policy"}
    assert {i["rule_source"] for i in items} <= ALLOWED_RULE_SOURCES
    for i in items:           # the shape orchestrator/app/models.py FindingIn requires
        assert i["rule_id"] and i["title"] and i["description"] is not None
        assert i["severity"] in ("info", "low", "medium", "high", "critical")
        assert i.get("asset_value") == "demo" and i.get("asset_kind") == "repository"
    assert SECRET not in json.dumps(items) and "a1B2c3D4e5F6g7H8" not in json.dumps(items)
    lodash = next(i for i in items if i["rule_id"] == "sca:npm:lodash")
    assert lodash["evidence"]["fixed_version"] == "4.17.21" and lodash["evidence"]["manifest"]


def test_scan_and_fix_never_talk_to_a_server(capsys, repo, patch_osv, server, monkeypatch):
    monkeypatch.setenv("PADDOCK_API_KEY", "pak_test")
    monkeypatch.setenv("PADDOCK_SERVER", server.url)
    run(capsys, "scan", repo, "--no-git")
    run(capsys, "fix", repo, "--no-git", "--yes")
    assert server.requests == [], "uploading is opt-in: only `paddock upload` may call a server"


def test_upload_needs_a_key_and_a_safe_server(capsys, repo, patch_osv, server, monkeypatch):
    code, _, err = run(capsys, "upload", repo, "--no-git", "--server", server.url)
    assert code == 2 and "PADDOCK_API_KEY" in err and not server.requests
    monkeypatch.setenv("PADDOCK_API_KEY", "pak_test")
    code, _, err = run(capsys, "upload", repo, "--no-git", "--server", "http://paddock.example.com")
    assert code == 2 and "plain http" in err
    code, _, err = run(capsys, "upload", repo, "--no-git")
    assert code == 2 and "no server" in err


def test_login_saves_the_server_but_never_the_key(capsys, server, monkeypatch):
    monkeypatch.setenv("PADDOCK_API_KEY", "pak_test")
    code, out, _ = run(capsys, "login", "--server", server.url)
    assert code == 0 and "ci-bot" in out
    saved = json.loads(upload.config_path().read_text())
    assert saved == {"server": server.url}
    assert "pak_test" not in upload.config_path().read_text()
    assert oct(upload.config_path().stat().st_mode & 0o777) == "0o600"
    monkeypatch.setenv("PADDOCK_API_KEY", "wrong")
    assert run(capsys, "login", "--server", server.url)[0] == 2


def test_upload_uses_the_login_server(capsys, repo, patch_osv, server, monkeypatch):
    monkeypatch.setenv("PADDOCK_API_KEY", "pak_test")
    run(capsys, "login", "--server", server.url)
    code, out, _ = run(capsys, "upload", repo, "--no-git")
    assert code == 0 and any(r[1] == "/v1/findings/bulk" for r in server.requests)


# --- init ------------------------------------------------------------------- #

def test_init_writes_workflow_and_precommit(capsys, tmp_path):
    code, out, _ = run(capsys, "init", tmp_path)
    assert code == 0
    wf = (tmp_path / ".github/workflows/paddock.yml").read_text()
    for needle in ("paddock scan --sarif paddock.sarif --fail-on high", "security-events: write",
                   "github/codeql-action/upload-sarif@v3", "if: always()", "pull_request"):
        assert needle in wf
    pc = (tmp_path / ".pre-commit-config.yaml").read_text()
    assert "entry: paddock scan --only secrets,code" in pc
    yaml = pytest.importorskip("yaml")
    assert yaml.safe_load(wf)["jobs"]["scan"]["steps"]
    assert yaml.safe_load(pc)["repos"][0]["hooks"][0]["id"] == "paddock"


def test_init_does_not_overwrite_or_rewrite_existing_files(capsys, tmp_path):
    wf = tmp_path / ".github/workflows/paddock.yml"
    wf.parent.mkdir(parents=True)
    wf.write_text("custom: true\n")
    (tmp_path / ".pre-commit-config.yaml").write_text("repos:\n  - repo: x\n")
    code, out, _ = run(capsys, "init", tmp_path)
    assert wf.read_text() == "custom: true\n"
    assert (tmp_path / ".pre-commit-config.yaml").read_text() == "repos:\n  - repo: x\n"
    assert "add this hook yourself" in out
    run(capsys, "init", tmp_path, "--force")
    assert "paddock scan" in wf.read_text()
    assert "id: paddock" in out and "- repo: local" in initcmd.PRECOMMIT_HOOK


# --- terminal behaviour ----------------------------------------------------- #

def test_no_color_and_force_color(capsys, repo, patch_osv, monkeypatch):
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert "\x1b[" in run(capsys, "scan", repo, "--no-git")[1]
    monkeypatch.setenv("NO_COLOR", "1")
    assert "\x1b[" not in run(capsys, "scan", repo, "--no-git")[1], "NO_COLOR wins over FORCE_COLOR"
    monkeypatch.delenv("NO_COLOR")
    assert "\x1b[" not in run(capsys, "scan", repo, "--no-git", "--no-color")[1]


def test_help_and_version(capsys):
    with pytest.raises(SystemExit) as e:
        run(capsys, "--version")
    assert e.value.code == 0
    assert "paddock-cli" in capsys.readouterr().out
    for cmd in ("scan", "fix", "login", "upload", "init"):
        with pytest.raises(SystemExit):
            run(capsys, cmd, "--help")
        assert "usage: paddock" in capsys.readouterr().out


def test_zero_third_party_imports():
    """The CLI must run on a bare interpreter: no aiohttp/asyncpg/yaml pulled in by the engines."""
    root = Path(__file__).resolve().parent.parent
    code = (f"import sys; sys.path.insert(0, {str(root)!r})\n"
            "import paddock_cli.main as m, paddock_cli.engines as e\n"
            "e.sca_osv(); e.sca_parsers(); e.sca_risk(); e.sast(); e.gate(); e.verify(); e.standards()\n"
            "bad = [n for n in ('aiohttp','asyncpg','yaml','redis','orjson','uvloop') if n in sys.modules]\n"
            "print(bad)")
    p = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True)
    assert p.stdout.strip() == "[]", p.stderr + p.stdout
