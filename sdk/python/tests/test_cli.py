from __future__ import annotations

import json
import os
import stat

import httpx
import pytest

from paddock_sdk import NO_RETRY, PaddockClient
from paddock_sdk.cli import EXIT_API, EXIT_OK, EXIT_UNSUPPORTED, main, render_table
from paddock_sdk.config import Config, Profile


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    for var in ("PADDOCK_URL", "PADDOCK_API_KEY", "PADDOCK_TOKEN", "PADDOCK_PROFILE"):
        monkeypatch.delenv(var, raising=False)
    path = tmp_path / "paddockctl.json"
    monkeypatch.setenv("PADDOCK_CONFIG", str(path))
    return Config.load(path)


@pytest.fixture
def run(api, cfg, capsys):
    client = PaddockClient("http://paddock.test", api_key="pak_x", transport=httpx.MockTransport(api), retry=NO_RETRY)

    def _run(*argv, use_client=True):
        code = main(list(argv), config=cfg, client=client if use_client else None,
                    transport=httpx.MockTransport(api))
        out, err = capsys.readouterr()
        return code, out, err

    return _run


def test_login_with_api_key_writes_private_config(run, api, cfg):
    api.on("GET", "/v1/auth/me", {"actor": "alice", "role": "admin", "clearance": "restricted",
                                   "kind": "apikey", "capabilities": []})
    code, out, _ = run("login", "--url", "http://paddock.test/", "--api-key", "pak_abc_123", "--profile", "prod",
                       use_client=False)
    assert code == EXIT_OK, out
    assert "alice" in out
    assert api.calls[0].headers["authorization"] == "Bearer pak_abc_123"
    saved = json.loads(cfg.path.read_text())
    assert saved["current"] == "prod"
    assert saved["profiles"]["prod"] == {"url": "http://paddock.test", "api_key": "pak_abc_123", "verify_tls": True}
    assert stat.S_IMODE(os.stat(cfg.path).st_mode) == 0o600


def test_profiles_and_env_override(cfg, monkeypatch):
    cfg.set_profile(Profile(name="lab", url="http://lab:8080", token="eyJabcdefghijklmnop"))
    cfg.save()
    again = Config.load(cfg.path)
    assert again.profile().url == "http://lab:8080"
    assert again.profile().redacted()["token"].endswith("...")
    monkeypatch.setenv("PADDOCK_API_KEY", "pak_env")
    p = again.profile()
    assert p.api_key == "pak_env" and p.token is None


def test_scope_list_table_and_json(run, api):
    rows = [{"id": 1, "kind": "domain", "value": "example.com", "active": True, "added_by": "a",
             "auth_doc_ref": "SOW-1", "expires_at": None}]
    api.on("GET", "/v1/scope", rows)
    code, out, _ = run("scope", "list")
    assert code == EXIT_OK
    assert out.splitlines()[0].split()[:3] == ["ID", "KIND", "VALUE"]
    assert "example.com" in out
    code, out, _ = run("scope", "list", "-o", "json")
    assert json.loads(out) == rows


def test_scope_add_uses_actor(run, api):
    api.on("GET", "/v1/auth/me", {"actor": "alice"})
    api.on("POST", "/v1/scope", httpx.Response(201, json={"id": 2, "kind": "domain", "value": "ex.com"}))
    code, _, _ = run("scope", "add", "domain", "ex.com", "--auth-doc-ref", "SOW-9")
    assert code == EXIT_OK
    assert api.body() == {"kind": "domain", "value": "ex.com", "added_by": "alice", "auth_doc_ref": "SOW-9"}


def test_scope_check_exit_code(run, api):
    api.on("POST", "/v1/scope/check", {"allow": False, "normalized": "evil.test", "reason": "no match"})
    code, out, _ = run("scope", "check", "evil.test")
    assert code == EXIT_API and "no match" in out


def test_scope_verify_unsupported(run):
    code, _, err = run("scope", "verify", "3")
    assert code == EXIT_UNSUPPORTED
    assert "does not provide scope verification" in err


def test_scan_run_wait(run, api, monkeypatch):
    monkeypatch.setattr("paddock_sdk.cli.time.sleep", lambda s: None)
    api.on("POST", "/v1/scans", httpx.Response(201, json={"id": "s1", "status": "queued"}))
    api.on("GET", "/v1/scans/s1", [httpx.Response(200, json={"id": "s1", "status": "running"}),
                                   httpx.Response(200, json={"id": "s1", "status": "completed"})])
    code, out, _ = run("scan", "run", "passive", "example.com", "--wait", "-o", "json")
    assert code == EXIT_OK
    assert json.loads(out)["status"] == "completed"
    assert api.body(0) == {"kind": "passive", "target": "example.com", "priority": 5}


def test_findings_list_and_accept(run, api):
    api.on("GET", "/v1/findings", {"items": [{"id": "f1", "severity": "critical", "title": "Exposed .git"}],
                                   "total": 1, "limit": 100, "offset": 0})
    code, out, _ = run("findings", "list", "--severity", "critical")
    assert code == EXIT_OK and "Exposed .git" in out
    assert api.calls[-1].url.params["severity"] == "critical"
    api.on("PATCH", "/v1/findings/f1", {"id": "f1", "status": "accepted_risk"})
    code, _, _ = run("findings", "accept", "f1", "--reason", "WAF rule")
    assert code == EXIT_OK
    assert api.body() == {"status": "accepted_risk", "notes": "WAF rule"}
    run("findings", "accept", "f1", "--reason", "scanner FP", "--false-positive")
    assert api.body()["status"] == "false_positive"


def test_export_missing_endpoint_and_success(run, api, tmp_path):
    code, _, err = run("export", "sarif")
    assert code == EXIT_UNSUPPORTED
    assert "does not provide sarif export" in err
    api.on("GET", "/v1/export/sarif", {"version": "2.1.0", "runs": []})
    target = tmp_path / "out.sarif"
    code, _, _ = run("export", "sarif", "--out", str(target), "--param", "severity=high")
    assert code == EXIT_OK
    assert json.loads(target.read_text())["version"] == "2.1.0"
    assert api.calls[-1].url.params["severity"] == "high"


def test_integrations_list(run, api):
    code, _, err = run("integrations", "list")
    assert code == EXIT_UNSUPPORTED and "integrations" in err
    api.on("GET", "/v1/integrations", [{"id": "i1", "kind": "slack", "name": "sec", "enabled": True}])
    code, out, _ = run("integrations", "list")
    assert code == EXIT_OK and "slack" in out


def test_license_and_usage(run, api):
    api.on("GET", "/v1/license", {"edition": "community", "status": "community", "features": [],
                                   "limits": {"seats": None}})
    code, out, _ = run("license", "show")
    assert code == EXIT_OK and "community" in out
    api.on("GET", "/v1/usage", {"edition": "team", "monitored_assets": 12, "limits": {
        "assets": {"used": 12, "limit": 10, "over": True}}, "notes": ["n"]})
    code, out, err = run("usage")
    assert code == EXIT_OK and "12 / 10 OVER" in out and "note: n" in err


def test_api_errors_are_reported(run, api):
    api.on("GET", "/v1/scope", httpx.Response(403, json={"detail": "requires capability 'read'"}))
    code, _, err = run("scope", "list")
    assert code == EXIT_API and "HTTP 403" in err


def test_render_table_truncates():
    t = render_table([{"a": "x" * 100, "b": None}], ["a", "b"])
    assert "…" in t and t.splitlines()[2].rstrip().endswith("-")
