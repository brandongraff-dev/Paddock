# SPDX-License-Identifier: Apache-2.0
"""The command line: exit codes 0, 1, 2 and 64, their precedence, and what a bad invocation can never become.

Exit 2 means only "unverifiable": a usage error is always 64, an unexpected failure is 2 (never 0).
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import sys
from pathlib import Path

import pytest

from paddock_verify import SPEC_VERSION, __version__, checks, cli, codes, fetch

SPEC = Path(__file__).resolve().parents[2] / "docs" / "spec" / "containment-attestation-v1"
CASES = SPEC / "vectors" / "cases"
ROOTS = str(SPEC / "vectors" / "test-roots.json")
GOOD_DNS = {"resolver": "r1", "answers": {"_paddock-attest.example.com": {"status": "ok", "txt": [
    "v=1; kid=2ceb61e24df5fde7c0ab24b2a2774fa4; fp=sha256:2ceb61e24df5fde7c0ab24b2a2774fa4cccecbb50a4b7f487b874c4baf7807a8"]}}}


def call(argv, monkeypatch=None):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        status = cli.main(list(argv))
    return status, out.getvalue(), err.getvalue()


@pytest.fixture
def env(tmp_path):
    dns = tmp_path / "dns.json"
    dns.write_text(json.dumps(GOOD_DNS))
    shutil.copytree(str(CASES / "valid-minimal-holds" / "bundle"), str(tmp_path / "ok"))
    base = ["--offline", "--now", "2026-12-01T12:00:00Z", "--roots", ROOTS, "--dns-resolver", "file:%s" % dns, "--no-state"]
    return dict(tmp=tmp_path, dns=dns, target=str(tmp_path / "ok" / ".well-known" / "paddock"), base=base)


def verify(env, *extra, target=None, json_out=True):
    argv = env["base"] + (["--json"] if json_out else []) + list(extra) + [target or env["target"]]
    return call(argv)


# ----------------------------------------------------------------------------------------- 0, 1, 2
def test_exit_zero_for_an_accepted_bundle_in_both_output_forms(env):
    status, out, err = verify(env)
    assert (status, err) == (0, "") and json.loads(out)["decision"] == "accepted"
    status, out, err = verify(env, json_out=False)
    assert status == 0 and out.splitlines()[:2] == ["profile: baseline (no acceptance policy given; nothing requires specific invariants)",
                                                     "VALID under baseline profile"]


def test_exit_one_for_a_reject_and_two_for_unverifiable_and_the_json_agrees(env):
    late = list(env["base"])
    late[late.index("--now") + 1] = "2026-12-02T10:00:00Z"
    status, out, _ = call(late + ["--json", env["target"]])
    assert status == 1 and json.loads(out)["exit"] == 1
    status, out, _ = call(["--offline", "--now", "2026-12-01T12:00:00Z", "--roots", ROOTS, "--no-state", "--json", env["target"]])
    assert status == 2 and json.loads(out)["primary"] == "dns.skipped_offline"


def test_reject_wins_over_unverifiable(env):
    # the DNS is unreachable (unverifiable) and the statement has expired (reject)
    status, out, _ = call(["--offline", "--now", "2026-12-02T10:00:00Z", "--roots", ROOTS, "--no-state", "--json", env["target"]])
    d = json.loads(out)
    assert status == 1 and [r["code"] for r in d["reasons"]] == ["dns.skipped_offline", "time.expired"] and d["primary"] == "time.expired"


def test_a_source_build_without_roots_is_unverifiable_not_accepted(env):
    status, out, _ = call(["--offline", "--now", "2026-12-01T12:00:00Z", "--dns-resolver", "file:%s" % env["dns"], "--no-state", "--json", env["target"]])
    d = json.loads(out)
    assert status == 2 and d["primary"] == "config.no_trust_roots" and d["decision"] == "unverifiable"


def test_custom_roots_are_announced(env):
    status, out, _ = verify(env, json_out=False)
    assert "custom trust roots in use" in out.splitlines()
    status, out, _ = call(["--print-roots", "--roots", ROOTS])
    assert status == 0 and "root" in out and out.splitlines()[-1] == "custom trust roots in use"
    status, out, _ = call(["--print-roots"])
    assert status == 0 and "no trust roots are built into this verifier" in out


def test_quiet_prints_only_the_headline(env):
    status, out, _ = verify(env, "--quiet", json_out=False)
    assert status == 0 and len(out.strip().splitlines()) == 2 and "No counterexample" not in out
    status, out, _ = verify(env, "--quiet")
    assert json.loads(out)["decision"] == "accepted"                    # --json is unaffected by --quiet


def test_not_found_and_unsafe_targets_are_unverifiable(env):
    status, out, _ = verify(env, target=str(env["tmp"] / "nowhere"))
    assert status == 2 and json.loads(out)["primary"] == "input.not_found"
    status, out, _ = verify(env, target="http://example.com/")
    assert status == 2 and json.loads(out)["primary"] == "input.insecure_transport"
    status, out, _ = verify(env, target="not a domain")
    assert status == 2 and json.loads(out)["primary"] == "input.not_found"


def test_keys_and_revoked_overrides(env):
    k = env["tmp"] / "keys.json"
    shutil.copy(str(Path(env["target"]) / "keys.json"), str(k))
    os.remove(str(Path(env["target"]) / "keys.json"))
    assert verify(env)[0] == 2                                           # keys.missing
    assert verify(env, "--keys", str(k))[0] == 0
    r = env["tmp"] / "rev.json"
    shutil.copy(str(Path(env["target"]) / "revoked.json"), str(r))
    os.remove(str(Path(env["target"]) / "revoked.json"))
    assert verify(env, "--keys", str(k))[0] == 2                         # revocation.missing
    assert verify(env, "--keys", str(k), "--revoked", str(r))[0] == 0
    assert call(env["base"] + ["--keys", str(env["tmp"] / "nope.json"), env["target"]]) [0] == 2


def test_policy_flags_change_the_profile_and_the_outcome(env):
    status, out, _ = verify(env, "--require", "std:public-ports-allowlist")
    d = json.loads(out)
    assert status == 1 and d["profile"] == "policy" and d["primary"] == "invariant.missing" and d["policy_sha256"]
    status, out, _ = verify(env, "--require", "std:no-internet-to-datastore:configured", "--min-coverage", "0.9", "--max-age", "72h")
    assert status == 0 and json.loads(out)["profile"] == "policy"
    p = env["tmp"] / "p.yaml"
    p.write_text("policy_version: 1\nrequire:\n  - { invariant: std:no-internet-to-datastore, verdict: HOLDS }\n")
    status, out, _ = verify(env, "--policy", str(p))
    assert status == 0 and "ACCEPTED under policy p.yaml" in call(env["base"] + ["--policy", str(p), env["target"]])[1]


def test_history_flag_and_depth(env):
    status, out, _ = verify(env, "--history", "required", "--history-depth", "3")
    assert status == 0 and json.loads(out)["profile"] == "policy"


# ----------------------------------------------------------------------------------------------- 64
@pytest.mark.parametrize("argv", [
    ["--no-such-flag", "x"], ["--now"], [], ["--now", "yesterday", "x"], ["--roots", "/nonexistent/r.json", "x"], ["--std-registry", "/nonexistent", "x"],
    ["--policy", "/nonexistent/p.json", "x"], ["--dns-resolver", "bogus", "x"], ["--dns-resolver", "udp:not-an-ip", "x"], ["--history", "sometimes", "x"],
    ["--history-depth", "0", "x"], ["--history-depth", "many", "x"], ["--timeout", "0", "x"], ["--max-anchor-age", "soon", "x"],
    ["--dns-min-resolvers", "0", "x"], ["--anchor-file", "/nonexistent", "x"], ["--explain", "no.such_code"], ["--max-age", "forever", "x"],
    ["--min-coverage", "7", "x"], ["--require", "std", "x"], ["--require", "std:a:b:c", "x"], ["--offline", "https://example.com/"],
    ["--offline", "example.com"], ["--state-file"], ["--dns-resolver", "file:/nonexistent/fx.json", "x"],
])
def test_usage_and_configuration_errors_are_exit_64_never_2(argv):
    status, out, err = call(argv)
    assert status == 64 and out == "" and err != "", argv


def test_argparse_help_exits_zero_and_abbreviations_are_not_accepted(env):
    status, out, err = call(["--jso", env["target"]])
    assert status == 64                                              # no abbreviation: 2 could otherwise sneak in from a typo


def test_invalid_policy_reports_the_line(env, tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("policy_version: 1\nmax_age: 48h\nbogus line\n")
    status, out, err = call(["--policy", str(p), "x"])
    assert status == 64 and "config.policy_invalid" in err and "line 3" in err
    p.write_text('{"policy_version": 1, "surprise": true}')
    status, out, err = call(["--policy", str(p), "x"])
    assert status == 64 and "surprise" in err


def test_version_explain_and_print_roots_exit_zero():
    status, out, _ = call(["--version"])
    assert status == 0 and out == "paddock-verify %s (containment attestation spec %s)\n" % (__version__, SPEC_VERSION)
    for code in codes.CODES:
        status, out, _ = call(["--explain", code])
        assert status == 0 and out.startswith(code + ": ") and "defined in: spec/" in out
    assert call(["--help"])[0] == 0


# --------------------------------------------------------------------------------- unexpected failures
def test_an_unexpected_failure_in_the_pipeline_is_two_never_zero(env, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("bug")
    monkeypatch.setattr("paddock_verify.schema.validate_statement", boom)
    status, out, _ = verify(env)
    d = json.loads(out)
    assert status == 2 and d["primary"] == "internal.error" and d["decision"] == "unverifiable"


def test_an_unexpected_failure_in_the_command_line_is_two_with_no_traceback(env, monkeypatch):
    monkeypatch.setattr(checks, "verify", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("bug")))
    status, out, err = verify(env)
    assert status == 2 and out == "" and "internal.error" in err and "Traceback" not in err


def test_keyboard_interrupt_is_not_swallowed_as_a_decision(env, monkeypatch):
    monkeypatch.setattr(checks, "verify", lambda *a, **k: (_ for _ in ()).throw(KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):
        verify(env)


def test_the_module_entry_point_runs():
    import subprocess
    root = Path(__file__).resolve().parents[1]
    p = subprocess.run([sys.executable, "-m", "paddock_verify", "--version"], cwd=str(root), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert p.returncode == 0 and p.stdout.decode().startswith("paddock-verify ")
    p = subprocess.run([sys.executable, "-m", "paddock_verify"], cwd=str(root), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert p.returncode == 64


# ----------------------------------------------------------------------------------------------- state
def test_state_file_records_and_catches_a_rollback(env, tmp_path):
    state = tmp_path / "state.json"
    chain = tmp_path / "chain"
    shutil.copytree(str(CASES / "valid-chain-seq2-with-history" / "bundle"), str(chain))
    base = [a for a in env["base"] if a != "--no-state"]
    assert call(base + ["--state-file", str(state), "--json", str(chain / ".well-known" / "paddock")])[0] == 0
    saved = json.loads(state.read_text())
    assert saved["subjects"]["dns:example.com"]["seq"] == 2 and saved["revocation"][next(iter(saved["revocation"]))]["seq"] == 42
    status, out, _ = call(base + ["--state-file", str(state), "--json", env["target"]])           # seq 1 after seq 2
    assert status == 1 and json.loads(out)["primary"] == "chain.seq_rollback"
    assert json.loads(state.read_text()) == saved                                                  # a rejected run changes nothing it must not
    assert call(base + ["--no-state", "--json", env["target"]])[0] == 0                            # --no-state ignores it


def test_no_state_never_creates_a_file_and_the_default_comes_from_the_environment(env, tmp_path, monkeypatch):
    base = [a for a in env["base"] if a != "--no-state"]
    p = tmp_path / "dflt" / "s.json"
    p.parent.mkdir()
    monkeypatch.setenv("PADDOCK_VERIFY_STATE", str(p))
    assert call(env["base"] + [env["target"]])[0] == 0 and not p.exists()
    assert call(base + [env["target"]])[0] == 0 and p.exists()


def test_the_default_state_file_is_created_with_its_directory_on_the_first_run(env, tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("PADDOCK_VERIFY_STATE", raising=False)
    base = [a for a in env["base"] if a != "--no-state"]
    status, out, err = call(base + ["--json", env["target"]])
    saved = home / ".paddock" / "verify-state.json"
    assert status == 0 and err == "" and saved.is_file(), (err, list(home.iterdir()))
    assert json.loads(saved.read_text())["subjects"]["dns:example.com"]["seq"] == 1
    assert (home / ".paddock").stat().st_mode & 0o077 == 0                                  # private to the user
    chain = tmp_path / "chain"
    shutil.copytree(str(CASES / "valid-chain-seq2-with-history" / "bundle"), str(chain))
    assert call(base + ["--json", str(chain / ".well-known" / "paddock")])[0] == 0
    assert call(base + ["--json", env["target"]])[0] == 1                                    # the rollback protection is in force


def test_a_state_file_that_cannot_be_written_is_always_said_so_and_never_changes_the_decision(env, tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("PADDOCK_VERIFY_STATE", raising=False)
    from paddock_verify import state as state_mod

    def refuse(self, path=None, make_dir=False):
        raise state_mod.StateError("cannot write the state file")

    monkeypatch.setattr(state_mod.State, "save", refuse)
    base = [a for a in env["base"] if a != "--no-state"]
    status, out, err = call(base + ["--json", env["target"]])                               # the default path, no --state-file
    assert status == 0 and "state file could not be written" in err


def test_unreadable_state_is_unverifiable_and_an_unwritable_one_does_not_change_the_decision(env, tmp_path):
    base = [a for a in env["base"] if a != "--no-state"]
    s = tmp_path / "s.json"
    s.write_text("{not json")
    status, out, _ = call(base + ["--state-file", str(s), "--json", env["target"]])
    assert status == 2 and json.loads(out)["primary"] == "chain.state_unreadable" and s.read_text() == "{not json"
    status, out, err = call(base + ["--state-file", str(tmp_path / "no-such-dir" / "s.json"), "--json", env["target"]])
    assert status == 0 and "state file could not be written" in err


# ----------------------------------------------------------------------------------- domain and URL targets
def test_domain_target_uses_the_keys_hint_and_the_default_location(env, monkeypatch):
    seen = {}
    real = fetch.locate

    def fake_locate(target, keys=None, revoked=None, **kw):
        seen["target"], seen["kw"] = target, kw
        return real(env["target"], keys, revoked)

    monkeypatch.setattr(cli.fetch, "locate", fake_locate)
    base = [a for a in env["base"] if a != "--offline"]
    status, out, err = call(base + ["--json", "example.com"])
    assert seen["target"] == "https://example.com/.well-known/paddock/" and status == 0, err         # no keys= hint in the fixture
    fx = json.loads(json.dumps(GOOD_DNS))
    fx["answers"]["_paddock-attest.example.com"]["txt"][0] += "; keys=https://hosted.test/v1/public/attest/example.com/keys.json"
    env["dns"].write_text(json.dumps(fx))
    status, out, err = call(base + ["--json", "--allow-private", "--timeout", "3", "Example.COM"])
    assert seen["target"] == "https://hosted.test/v1/public/attest/example.com/" and status == 0
    assert seen["kw"] == {"timeout": 3.0, "allow_private": True}
    status, out, err = call(base + ["--json", "https://x.test/b/"])
    assert seen["target"] == "https://x.test/b/" and status == 0                                        # the expected domain then comes from bundle.json


def test_a_domain_target_checks_the_subject_against_the_domain(env, monkeypatch):
    real = fetch.locate
    monkeypatch.setattr(cli.fetch, "locate", lambda target, keys=None, revoked=None, **kw: real(env["target"], keys, revoked))
    fx = {"resolver": "r1", "answers": {"_paddock-attest.example.org": {"status": "nxdomain"}}}
    env["dns"].write_text(json.dumps(fx))
    base = [a for a in env["base"] if a != "--offline"]
    status, out, _ = call(base + ["--json", "example.org"])
    assert status == 1 and json.loads(out)["primary"] == "dns.domain_mismatch"
