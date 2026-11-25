"""The `paddock` CLI: tokens never on argv, exit codes, and the commands against a live fake orchestrator."""
from __future__ import annotations

import io
import json
import os
import sys

import pytest

from paddock_agent import cli
from paddock_agent.agent import EXIT_RE_ENROLL
from tests.fake_fleet import FakeFleet


@pytest.fixture
def env(tmp_path, monkeypatch):
    for k in list(os.environ):
        if k.startswith("PADDOCK_"):
            monkeypatch.delenv(k)
    fleet = FakeFleet()
    httpd, url = fleet.serve()
    monkeypatch.setenv("PADDOCK_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("PADDOCK_SERVER", url)
    monkeypatch.setenv("PADDOCK_QUARANTINE_DIR", str(tmp_path / "q"))
    monkeypatch.setenv("PADDOCK_INVENTORY_SEC", "0")
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    yield fleet, tmp_path
    httpd.shutdown()
    httpd.server_close()


def run(capsys, *argv):
    code = cli.main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def enroll(env, monkeypatch, capsys, **kw):
    fleet, _ = env
    monkeypatch.setenv(cli.TOKEN_ENV, fleet.token)
    return run(capsys, "enroll", "--hostname", "web-01.example")


def test_token_argument_is_refused_everywhere(env, capsys):
    fleet, _ = env
    code, out, err = run(capsys, "enroll", "--token", fleet.token)
    assert code == 2 and "never accepted on the command line" in err
    assert fleet.requests == []
    assert fleet.token not in out + err


def test_enroll_reads_the_token_from_the_environment_and_removes_it(env, monkeypatch, capsys):
    fleet, tmp = env
    code, out, err = enroll(env, monkeypatch, capsys)
    assert code == 0, err
    doc = json.loads(out)
    assert doc["enrolled"] is True and doc["agent_id"] == fleet.agent_id and doc["tenant_id"] == fleet.tenant_id
    assert fleet.token not in out + err
    assert cli.TOKEN_ENV not in os.environ                                # not left for child processes
    assert os.stat(tmp / "state" / "credentials.json").st_mode & 0o777 == 0o600
    assert os.stat(tmp / "state" / "keys" / "ed25519.key").st_mode & 0o777 == 0o600


def test_enroll_reads_the_token_from_stdin(env, monkeypatch, capsys):
    fleet, _ = env
    monkeypatch.setattr(sys, "stdin", io.StringIO(fleet.token + "\n"))
    code, out, err = run(capsys, "enroll", "--token-stdin", "--hostname", "web-01.example")
    assert code == 0, err and fleet.token not in out + err


def test_enroll_without_any_token_is_a_usage_error(env, capsys):
    fleet, _ = env
    code, _out, err = run(capsys, "enroll", "--hostname", "web-01")
    assert code == 2 and cli.TOKEN_ENV in err and fleet.requests == []


def test_a_terminal_prompts_without_echo(env, monkeypatch, capsys):
    fleet, _ = env
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: fleet.token)
    stdin = io.StringIO("")
    stdin.isatty = lambda: True
    monkeypatch.setattr(sys, "stdin", stdin)
    assert cli.read_enroll_token(from_stdin=False, environ={}, stdin=stdin) == fleet.token


def test_second_enroll_needs_force(env, monkeypatch, capsys):
    fleet, _ = env
    assert enroll(env, monkeypatch, capsys)[0] == 0
    monkeypatch.setenv(cli.TOKEN_ENV, fleet.new_token())
    code, _out, err = run(capsys, "enroll", "--hostname", "web-01.example")
    assert code == 2 and "already enrolled" in err
    monkeypatch.setenv(cli.TOKEN_ENV, fleet.token)
    code, out, err = run(capsys, "enroll", "--hostname", "web-01.example", "--force")
    assert code == 0, err


def test_bad_token_shapes_and_server_refusals_have_distinct_exit_codes(env, monkeypatch, capsys):
    fleet, _ = env
    monkeypatch.setenv(cli.TOKEN_ENV, "nonsense")
    assert run(capsys, "enroll", "--hostname", "w")[0] == 2
    monkeypatch.setenv(cli.TOKEN_ENV, "fet_ffffffffffff_" + "x" * 30)           # well formed, but unknown
    code, _o, err = run(capsys, "enroll", "--hostname", "w")
    assert code == 5 and "401" in err


def test_status_before_and_after_enrollment_never_prints_secrets(env, monkeypatch, capsys):
    fleet, tmp = env
    code, out, _e = run(capsys, "status")
    assert code == 0 and json.loads(out)["enrolled"] is False
    enroll(env, monkeypatch, capsys)
    code, out, _e = run(capsys, "status")
    doc = json.loads(out)
    assert code == 0 and doc["enrolled"] is True and doc["key_id"] and doc["ed25519_backend"] in ("pure", "cryptography")
    assert fleet.agent_token not in out and fleet.token not in out


def test_loose_credentials_file_is_exit_6(env, monkeypatch, capsys):
    _fleet, tmp = env
    enroll(env, monkeypatch, capsys)
    os.chmod(tmp / "state" / "credentials.json", 0o644)
    code, _o, err = run(capsys, "status")
    assert code == 6 and "accessible by other users" in err


def test_run_sends_signed_heartbeat_and_posture_then_stops(env, monkeypatch, capsys):
    fleet, _ = env
    enroll(env, monkeypatch, capsys)
    monkeypatch.setenv("PADDOCK_HEARTBEAT_SEC", "5")
    code, _o, err = run(capsys, "run", "--iterations", "1")
    assert code == 0, err
    assert [k for k, _ in fleet.accepted][:2] == ["heartbeat", "posture"]
    assert fleet.rejected == []


def test_run_exits_7_when_the_server_demands_re_enrollment(env, monkeypatch, capsys):
    fleet, _ = env
    enroll(env, monkeypatch, capsys)
    fleet.require_reenroll = True
    code, _o, _e = run(capsys, "run", "--iterations", "3")
    assert code == EXIT_RE_ENROLL == 7


def test_run_without_enrollment_is_exit_2(env, capsys):
    code, _o, err = run(capsys, "run", "--iterations", "1")
    assert code == 2 and "not enrolled" in err


def test_rotate_key_command(env, monkeypatch, capsys):
    fleet, _ = env
    enroll(env, monkeypatch, capsys)
    old = fleet.active_key()
    code, out, err = run(capsys, "rotate-key")
    assert code == 0, err
    assert json.loads(out)["key_id"] == fleet.active_key() != old


def test_posture_command_sends_one_envelope(env, monkeypatch, capsys):
    fleet, _ = env
    enroll(env, monkeypatch, capsys)
    code, out, err = run(capsys, "posture")
    assert code == 0, err
    assert [k for k, _ in fleet.accepted] == ["posture"] and json.loads(out)["sent"] is True


def test_collect_prints_the_canonical_payload_without_any_network_call(env, capsys):
    fleet, _ = env
    code, out, err = run(capsys, "collect", "--raw")
    assert code == 0, err
    payload = json.loads(out)
    assert payload["schema"] == 2 and "self" in payload["sections"]
    assert fleet.requests == []


def test_simulate_previews_and_refuses_ipv6_and_bad_targets(env, capsys):
    code, out, _e = run(capsys, "simulate", "block_ip", "203.0.113.10")
    assert code == 0 and json.loads(out)["dry_run"] is True
    code, _o, err = run(capsys, "simulate", "block_ip", "2001:db8::1")
    assert code == 2 and "IPv6" in err
    code, _o, err = run(capsys, "simulate", "firewall_rule", "in:tcp:99999")
    assert code == 2 and "refused" in err
    code, _o, err = run(capsys, "simulate", "quarantine_file", "scp://x/y")
    assert code == 2


def test_simulate_needs_neither_a_server_nor_valid_state(env, monkeypatch, capsys):
    _fleet, tmp = env
    os.makedirs(tmp / "state")
    (tmp / "state" / "credentials.json").write_text("garbage")
    os.chmod(tmp / "state" / "credentials.json", 0o644)
    monkeypatch.delenv("PADDOCK_SERVER")
    assert run(capsys, "simulate", "block_domain", "evil.example")[0] == 0


def test_inventory_prints_the_v1_shape_offline(env, capsys):
    code, out, _e = run(capsys, "inventory", "--no-packages")
    assert code == 0 and set(json.loads(out)) == {"os_info", "packages", "listeners", "posture"}


def test_posture_command_reports_when_no_posture_could_be_built(env, monkeypatch, capsys):
    fleet, _ = env
    enroll(env, monkeypatch, capsys)
    from paddock_agent.agent import Agent
    monkeypatch.setattr(Agent, "collect_payload", lambda self, seq=0, ctx=None: (_ for _ in ()).throw(RuntimeError("x")))
    code, out, err = run(capsys, "posture")
    assert code == 1 and "Nothing was sent" in err and "sent" not in out
    assert fleet.accepted == []
