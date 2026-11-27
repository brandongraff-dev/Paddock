"""`paddock assurance scopes list|suggest|set|clear` (docs/ASSURANCE_P2_1.md 6.5 item 4, D37).

The CLI is a thin, stdlib-only client of the sensor-scope API. What is pinned here: the key comes from the environment
only (never argv, never printed, never saved); a server that would send it over plain http is refused; a wide scope is
refused locally unless `--allow-wide` AND a 20 character reason are given (the server enforces the same rule, this just
saves the round trip and a mistaken keystroke); `suggest` only prints, it never changes a scope; errors say what the
server said.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from conftest import run
from paddock_cli import main as cli_main

S1 = "5e5e5e5e-0000-0000-0000-000000000001"
S2 = "5e5e5e5e-0000-0000-0000-000000000002"
S3 = "5e5e5e5e-0000-0000-0000-000000000003"
KEY = "pak_test_secret_key_value"


def listing(**over):
    base = {
        "items": [
            {"sensor_id": S1, "name": "span-hq", "site": "hq", "status": "active", "online": True,
             "cidrs": ["10.20.0.0/24"], "scope_declared": True, "set_by": "alice", "justification": "core span",
             "set_at": "2026-11-01T10:00:00Z",
             "observed": {"prefixes": [{"prefix": "10.20.0.0/24", "flows": 40, "last_seen": "2026-11-26T10:00:00Z",
                                        "private": True},
                                       {"prefix": "10.30.0.0/24", "flows": 7, "last_seen": "2026-11-26T09:00:00Z",
                                        "private": True}],
                          "truncated": False, "window_days": 7},
             "declared_but_unobserved": [], "observed_outside_scope": ["10.30.0.0/24"],
             "suggested_cidrs": ["10.20.0.0/24", "10.30.0.0/24"], "advisory_notes": []}],
        "unscoped_sensors": [
            {"sensor_id": S2, "name": "span-dc", "site": "dc", "status": "active", "online": True, "cidrs": [],
             "scope_declared": False, "set_by": None, "justification": "", "set_at": None,
             "observed": {"prefixes": [{"prefix": "10.50.0.0/24", "flows": 3, "last_seen": None, "private": True}],
                          "truncated": False, "window_days": 7},
             "declared_but_unobserved": [], "observed_outside_scope": [], "suggested_cidrs": ["10.50.0.0/24"],
             "advisory_notes": []},
            {"sensor_id": S3, "name": "span-hq", "site": "branch", "status": "active", "online": False, "cidrs": [],
             "scope_declared": False, "set_by": None, "justification": "", "set_at": None,
             "observed": {"prefixes": [], "truncated": False, "window_days": 7},
             "declared_but_unobserved": [], "observed_outside_scope": [], "suggested_cidrs": [],
             "advisory_notes": []}],
        "total": 1,
    }
    base.update(over)
    return base


class Server:
    """A throwaway stand-in for the orchestrator's sensor-scope routes."""

    def __init__(self, data=None):
        self.data = data or listing()
        self.requests = []
        self.replies = {}                    # (method) -> (code, obj) overrides
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, obj):
                data = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _body(self):
                n = int(self.headers.get("Content-Length") or 0)
                return json.loads(self.rfile.read(n)) if n else None

            def _handle(self, method):
                body = self._body()
                outer.requests.append((method, self.path, self.headers.get("X-API-Key"), body))
                if method in outer.replies:
                    return self._send(*outer.replies[method])
                if method == "GET" and self.path == "/v1/assurance/sensor-scopes":
                    return self._send(200, outer.data)
                if method == "PUT" and self.path.startswith("/v1/assurance/sensor-scopes/"):
                    return self._send(200, {"scope": {"sensor_id": self.path.rsplit("/", 1)[1], "cidrs": body["cidrs"]},
                                            "changed": True, "previous": None, "graph_version": 5,
                                            "warnings": ["10.99.0.0/24: this sensor saw no flows in it"]})
                if method == "DELETE" and self.path.startswith("/v1/assurance/sensor-scopes/"):
                    return self._send(200, {"deleted": True, "sensor_id": self.path.split("?")[0].rsplit("/", 1)[1],
                                            "previous": ["10.20.0.0/24"], "graph_version": 6})
                self._send(404, {"detail": "no"})

            def do_GET(self):
                self._handle("GET")

            def do_PUT(self):
                self._handle("PUT")

            def do_DELETE(self):
                self._handle("DELETE")

        self.srv = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_port}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()

    def calls(self, method):
        return [r for r in self.requests if r[0] == method]


@pytest.fixture
def server(monkeypatch):
    s = Server()
    monkeypatch.setenv("PADDOCK_API_KEY", KEY)
    monkeypatch.setenv("PADDOCK_SERVER", s.url)
    yield s
    s.close()


def scopes(capsys, *argv):
    return run(capsys, "assurance", "scopes", *argv)


# --------------------------------------------------------------------------- #
# list
# --------------------------------------------------------------------------- #

def test_list_shows_declared_and_undeclared_sensors_and_what_they_saw(capsys, server):
    code, out, err = scopes(capsys, "list", "--no-color")
    assert code == 0, err
    assert [r[:3] for r in server.requests] == [("GET", "/v1/assurance/sensor-scopes", KEY)]
    assert "span-hq" in out and S1 in out and "10.20.0.0/24" in out and "core span" in out
    assert "span-dc" in out and "no declared scope" in out and "covers nothing" in out
    assert "10.30.0.0/24" in out                                   # observed outside the declared scope is surfaced
    assert KEY not in out and KEY not in err


def test_list_json_is_the_servers_answer(capsys, server):
    code, out, _ = scopes(capsys, "list", "--json")
    assert code == 0 and json.loads(out) == server.data


def test_list_with_nothing_says_so(capsys, server):
    server.data = {"items": [], "unscoped_sensors": [], "total": 0}
    code, out, _ = scopes(capsys, "list", "--no-color")
    assert code == 0 and "no sensors" in out.lower()


# --------------------------------------------------------------------------- #
# suggest: prints, never changes
# --------------------------------------------------------------------------- #

def test_suggest_prints_the_evidence_and_a_command_to_review_and_changes_nothing(capsys, server):
    code, out, err = scopes(capsys, "suggest", "span-dc", "--no-color")
    assert code == 0, err
    assert "10.50.0.0/24" in out
    assert f"paddock assurance scopes set {S2} --cidr 10.50.0.0/24 --why" in out
    assert [m for m, *_ in server.requests] == ["GET"]             # nothing was written
    code, out, _ = scopes(capsys, "suggest", S1, "--no-color")    # by id; also shows the gaps
    assert code == 0 and "10.30.0.0/24" in out and "outside" in out.lower()


def test_suggest_without_evidence_says_there_is_nothing_to_suggest(capsys, server):
    code, out, _ = scopes(capsys, "suggest", S3, "--no-color")
    assert code == 0 and "no flows" in out.lower() and "--cidr" not in out


def test_an_unknown_or_ambiguous_sensor_is_an_error_that_names_the_choices(capsys, server):
    code, _, err = scopes(capsys, "suggest", "nope")
    assert code == 2 and "no sensor" in err
    code, _, err = scopes(capsys, "suggest", "span-hq")
    assert code == 2 and "ambiguous" in err and S1 in err and S3 in err


# --------------------------------------------------------------------------- #
# set / clear
# --------------------------------------------------------------------------- #

def test_set_sends_the_declaration_and_prints_the_warnings(capsys, server):
    code, out, err = scopes(capsys, "set", S1, "--cidr", "10.20.0.0/24", "--cidr", "10.30.0.0/24,10.99.0.0/24",
                            "--why", "core switch mirror, checked with netops", "--no-color")
    assert code == 0, err
    (put,) = server.calls("PUT")
    assert put[1] == f"/v1/assurance/sensor-scopes/{S1}" and put[2] == KEY
    assert put[3] == {"cidrs": ["10.20.0.0/24", "10.30.0.0/24", "10.99.0.0/24"],
                      "justification": "core switch mirror, checked with netops"}
    assert "allow_wide" not in put[3]
    assert "saw no flows" in out                                   # the server's warnings reach the operator


def test_set_resolves_a_sensor_name_through_the_listing(capsys, server):
    code, _, _ = scopes(capsys, "set", "span-dc", "--cidr", "10.50.0.0/24", "--why", "dc span port")
    assert code == 0
    assert server.calls("PUT")[0][1] == f"/v1/assurance/sensor-scopes/{S2}"


@pytest.mark.parametrize("cidr", ["10.0.0.0/8", "10.0.0.0/15", "fd00::/47", "2001:db8::/32", "::ffff:0.0.0.0/97",
                                  "::ffff:10.0.0.0/104", "::ffff:172.16.0.0/108", "::ffff:0:0/96"])
def test_a_wide_scope_is_refused_locally_without_allow_wide(capsys, server, cidr):
    code, _, err = scopes(capsys, "set", S1, "--cidr", cidr, "--why", "x" * 40)
    assert code == 2 and "--allow-wide" in err and server.requests == []


def test_allow_wide_needs_a_real_reason_and_then_goes_through(capsys, server):
    code, _, err = scopes(capsys, "set", S1, "--cidr", "10.0.0.0/8", "--allow-wide", "--why", "too short")
    assert code == 2 and "20" in err and server.requests == []
    why = "the whole campus is mirrored on the core"
    code, _, err = scopes(capsys, "set", S1, "--cidr", "10.0.0.0/8", "--allow-wide", "--why", why)
    assert code == 0, err
    assert server.calls("PUT")[0][3] == {"cidrs": ["10.0.0.0/8"], "justification": why, "allow_wide": True}


@pytest.mark.parametrize("argv", [["set", S1, "--why", "no cidr"], ["set", S1, "--cidr", "10.0.0.0/24"],
                                  ["set", S1, "--cidr", "not-a-cidr", "--why", "bad one"],
                                  ["set", S1, "--cidr", "10.0.0.0/24", "--why", "   "],
                                  ["clear", S1], ["clear", S1, "--why", "  "]])
def test_missing_or_malformed_input_never_reaches_the_server(capsys, server, argv):
    try:
        code, _, _ = scopes(capsys, *argv)
    except SystemExit as exc:                  # argparse's own usage error
        code = exc.code
    assert code == 2 and server.requests == []


def test_a_server_refusal_is_reported_with_its_own_words(capsys, server):
    server.replies["PUT"] = (422, {"detail": {"error": "scope_too_wide", "cidrs": ["10.0.0.0/15"],
                                             "message": "10.0.0.0/15: shorter than /16"}})
    code, _, err = scopes(capsys, "set", S1, "--cidr", "10.0.0.0/16", "--why", "span")
    assert code == 2 and "scope_too_wide" in err and "shorter than /16" in err


def test_clear_deletes_with_a_justification(capsys, server):
    code, out, err = scopes(capsys, "clear", S1, "--why", "span port was removed", "--no-color")
    assert code == 0, err
    (d,) = server.calls("DELETE")
    path = urlparse(d[1])
    assert path.path == f"/v1/assurance/sensor-scopes/{S1}"
    assert parse_qs(path.query) == {"justification": ["span port was removed"]}
    assert d[2] == KEY and "10.20.0.0/24" in out and "covers nothing" in out


# --------------------------------------------------------------------------- #
# the key and the server
# --------------------------------------------------------------------------- #

def test_the_key_is_never_taken_from_argv():
    p = cli_main.build_parser()
    for flag in ("--api-key", "--key", "--token"):
        with pytest.raises(SystemExit):
            p.parse_args(["assurance", "scopes", "list", flag, "x"])


def test_no_key_no_request(capsys, server, monkeypatch):
    monkeypatch.delenv("PADDOCK_API_KEY")
    code, _, err = scopes(capsys, "list")
    assert code == 2 and "PADDOCK_API_KEY" in err and server.requests == []


def test_a_plain_http_remote_server_is_refused(capsys, monkeypatch):
    monkeypatch.setenv("PADDOCK_API_KEY", KEY)
    monkeypatch.setenv("PADDOCK_SERVER", "http://paddock.example.com")
    code, _, err = scopes(capsys, "list")
    assert code == 2 and "plain http" in err and KEY not in err


def test_a_flag_server_beats_the_environment(capsys, server, monkeypatch):
    monkeypatch.setenv("PADDOCK_SERVER", "http://127.0.0.1:1")
    code, _, err = scopes(capsys, "list", "--server", server.url)
    assert code == 0, err


def test_an_unreachable_server_is_an_error_not_a_traceback(capsys, monkeypatch):
    monkeypatch.setenv("PADDOCK_API_KEY", KEY)
    monkeypatch.setenv("PADDOCK_SERVER", "http://127.0.0.1:9")
    code, _, err = scopes(capsys, "list")
    assert code == 2 and "cannot reach" in err and KEY not in err


def test_scan_and_fix_still_never_talk_to_a_server(capsys, repo, patch_osv, server):
    run(capsys, "scan", repo, "--no-git")
    assert server.requests == []


def test_the_module_uses_only_the_standard_library():
    import ast
    import sys
    from pathlib import Path

    import paddock_cli
    src = (Path(paddock_cli.__file__).parent / "scopes.py").read_text()
    top = {n.names[0].name.split(".")[0] for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Import)}
    top |= {n.module.split(".")[0] for n in ast.walk(ast.parse(src))
            if isinstance(n, ast.ImportFrom) and n.module and n.level == 0}
    assert top <= set(sys.stdlib_module_names) | {"__future__"}


def test_a_narrow_v4_mapped_scope_is_not_called_wide(capsys, server):
    code, _, err = scopes(capsys, "set", S1, "--cidr", "::ffff:10.20.0.0/120", "--why", "span port")
    assert code == 0, err


def test_the_api_key_is_never_sent_to_a_redirect_target(capsys, monkeypatch):
    """urllib copies the headers (X-API-Key included) onto a redirected GET, to whatever host the answer names. The
    CLI refuses to follow redirects at all and says where the server pointed."""
    elsewhere = Server()

    class Redirect(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", elsewhere.url + "/v1/assurance/sensor-scopes")
            self.send_header("Content-Length", "0")
            self.end_headers()

    srv = HTTPServer(("127.0.0.1", 0), Redirect)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setenv("PADDOCK_API_KEY", KEY)
    monkeypatch.setenv("PADDOCK_SERVER", f"http://127.0.0.1:{srv.server_port}")
    try:
        code, out, err = scopes(capsys, "list")
    finally:
        srv.shutdown()
        elsewhere.close()
    assert code != 0 and "redirect" in (out + err).lower()
    assert elsewhere.requests == []                                # the key never left for the other host
    assert KEY not in out + err
