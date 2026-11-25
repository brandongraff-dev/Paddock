"""Regression tests for the P2 adversarial-review findings pkg-1 .. pkg-13 (installer, unit, release, docs).

Python 3.8 compatible. The installer is exercised exactly like test_install_agent_sh.py does (a ``file://`` mirror
and ``--root``); the service-management steps use a recording fake ``systemctl`` through the installer's
test-only knob ``PADDOCK_INSTALL_TEST_SYSTEMCTL`` (honoured only together with ``--root``).
What is NOT covered: a real systemd, a real GitHub release, a real cosign.
"""
import hashlib
import os
import re
import shutil
import signal
import subprocess
import sys
import time

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import build_zipapp as bz  # noqa: E402,F401  (agent/packaging is put on sys.path by test_install_agent_sh)
from test_install_agent_sh import (  # noqa: E402
    FAKE_AGENT, REPO, SCRIPT, SERVER, TOKEN, UNIT, clean_env, make_mirror, out, run, staged, system_tool,
    tool_path,
)

pytestmark = pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX sh")

AGENT_V2 = os.path.join(REPO, "docs", "AGENT_V2.md")
FLEET_WIRING = os.path.join(REPO, "docs", "FLEET_WIRING.md")
READINESS = os.path.join(REPO, "docs", "READINESS.md")
RELEASE_YML = os.path.join(REPO, ".github", "workflows", "release.yml")

NO_NEWLINE_TOKEN = TOKEN.encode()


@pytest.fixture(scope="module")
def real_pyz_path(tmp_path_factory):
    p = tmp_path_factory.mktemp("real") / "paddock-agent.pyz"
    bz.build(str(p))
    return p


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def seed_credentials(root):
    (root / "var/lib/paddock-agent").mkdir(parents=True, exist_ok=True)
    (root / "var/lib/paddock-agent/credentials.json").write_text("{}")


def fake_systemctl(tmp_path, *, active_rc=0):
    log = tmp_path / "systemctl.log"
    p = tmp_path / "fake-systemctl"
    p.write_text(
        "#!/bin/sh\n"
        "printf '%%s\\n' \"$*\" >> %s\n"
        "if [ \"$1\" = is-active ]; then\n"
        "  if [ %d -eq 0 ]; then echo active; else echo failed; fi\n"
        "  exit %d\n"
        "fi\n"
        "exit 0\n" % (log, active_rc, active_rc))
    os.chmod(str(p), 0o755)
    return p, log


def systemd_env(tmp_path, ctl, **extra):
    return clean_env(tool_path(tmp_path), PADDOCK_INSTALL_TEST_SYSTEMCTL=str(ctl),
                     PADDOCK_INSTALL_SETTLE_SECS="0", **extra)


# =========================================================== pkg-1: a token without a trailing newline
def test_pkg1_a_token_piped_without_a_newline_is_accepted(tmp_path):
    mirror, _ = make_mirror(tmp_path, FAKE_AGENT.encode())
    record = tmp_path / "record.json"
    env = clean_env(tool_path(tmp_path), FAKE_AGENT_RECORD=str(record), FAKE_AGENT_RC="0")
    res, root = staged(tmp_path, mirror, env=env, stdin=NO_NEWLINE_TOKEN)      # what `printf %s "$TOKEN" |` sends
    assert res.returncode == 0, out(res)
    import json
    assert json.loads(record.read_text())["stdin"].strip() == TOKEN
    assert TOKEN.encode() not in res.stdout + res.stderr


def test_pkg1_the_token_is_read_before_any_file_is_installed(tmp_path):
    for stdin, msg in ((b"", "no enrollment token"), (b"nonsense-Sup3rS3cret", "does not look like")):
        sub = tmp_path / ("c%d" % len(msg))
        sub.mkdir()
        mirror, _ = make_mirror(sub, FAKE_AGENT.encode())
        res, root = staged(sub, mirror, env=clean_env(tool_path(sub)), stdin=stdin)
        assert res.returncode != 0 and msg in out(res), out(res)
        assert not (root / "usr").exists() and not (root / "etc").exists() and not (root / "var").exists()
        assert "Sup3rS3cret" not in out(res)


# =========================================================== pkg-13: token hygiene
def _env_recording_shims(tmp_path, tools):
    path = tool_path(tmp_path)
    log = tmp_path / "children-env.log"
    for t in tools:
        real = system_tool(t)
        dst = os.path.join(path, t)
        if os.path.lexists(dst):
            os.unlink(dst)
        with open(dst, "w") as fh:
            fh.write("#!/bin/sh\nenv >> %s\nexec %s \"$@\"\n" % (log, real))
        os.chmod(dst, 0o755)
    return path, log


def test_pkg13_no_child_process_inherits_the_token_from_the_environment(tmp_path):
    mirror, _ = make_mirror(tmp_path, FAKE_AGENT.encode())
    path, log = _env_recording_shims(tmp_path, ("sha256sum", "cp", "mkdir", "awk", "chmod", "mv", "mktemp", "head"))
    pyw = tmp_path / "python-wrapper"
    pyw.write_text("#!/bin/sh\nenv >> %s\nexec %s \"$@\"\n" % (log, sys.executable))
    os.chmod(str(pyw), 0o755)
    record = tmp_path / "record.json"
    env = clean_env(path, PADDOCK_ENROLL_TOKEN=TOKEN, TOKEN="fet_aaaaaaaaaaaa_LeakViaTOKENvariable",
                    FAKE_AGENT_RECORD=str(record), FAKE_AGENT_RC="0")
    root = tmp_path / "root"
    res = run(["--server", SERVER, "--root", str(root), "--base-url", "file://" + str(mirror), "--python", str(pyw)],
              env=env, stdin=b"")
    assert res.returncode == 0, out(res)
    seen = log.read_text()
    assert seen.count("PATH=") >= 8                                          # the shims really ran
    assert "Sup3rS3cret" not in seen and "LeakViaTOKENvariable" not in seen
    assert "PADDOCK_ENROLL_TOKEN" not in seen


def test_pkg13_sigterm_stops_the_installer_instead_of_carrying_on(tmp_path, real_pyz_path):
    mirror, _ = make_mirror(tmp_path, real_pyz_path.read_bytes())
    path = tool_path(tmp_path)
    shim = os.path.join(path, "sha256sum")
    os.unlink(shim)
    with open(shim, "w") as fh:
        fh.write("#!/bin/sh\nsleep 3\nexec %s \"$@\"\n" % system_tool("sha256sum"))
    os.chmod(shim, 0o755)
    root = tmp_path / "root"
    proc = subprocess.Popen(["sh", SCRIPT, "--server", SERVER, "--root", str(root), "--base-url",
                             "file://" + str(mirror), "--python", sys.executable, "--no-enroll"],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=clean_env(path))
    time.sleep(1.2)
    proc.send_signal(signal.SIGTERM)
    so, se = proc.communicate(timeout=60)
    text = (so + se).decode("utf-8", "replace")
    assert proc.returncode == 143, (proc.returncode, text)                   # 128 + SIGTERM, not a later failure
    assert "checksum mismatch" not in text and "done." not in text
    assert not (root / "usr").exists()


def test_pkg13_the_piped_installer_error_does_not_steer_towards_sudo_var_assignments(tmp_path):
    mirror, _ = make_mirror(tmp_path, FAKE_AGENT.encode())
    with open(SCRIPT, "rb") as script:
        res = subprocess.run(["sh", "-s", "--", "--server", SERVER, "--root", str(tmp_path / "r"), "--base-url",
                              "file://" + str(mirror), "--python", sys.executable],
                             stdin=script, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             env=clean_env(tool_path(tmp_path)), timeout=60)
    text = out(res)
    assert res.returncode != 0 and "piped into sh" in text
    assert "give the token in PADDOCK_ENROLL_TOKEN" not in text
    assert "download the script and run" in text and "sh ./install-agent.sh" in text and "stdin" in text
    assert "argv" in text                                                    # and says why a VAR=value is wrong


def test_pkg13_a_group_or_world_writable_install_dir_is_refused(tmp_path, real_pyz_path):
    mirror, _ = make_mirror(tmp_path, real_pyz_path.read_bytes())
    root = tmp_path / "root"
    lib = root / "usr/local/lib/paddock-agent"
    lib.mkdir(parents=True)
    os.chmod(str(lib), 0o777)
    res, _ = staged(tmp_path, mirror, "--no-enroll")
    assert res.returncode != 0 and "writable" in out(res), out(res)
    assert not (lib / "paddock-agent.pyz").exists()


def test_pkg13_an_install_dir_that_is_a_symlink_is_refused(tmp_path, real_pyz_path):
    mirror, _ = make_mirror(tmp_path, real_pyz_path.read_bytes())
    root = tmp_path / "root"
    (root / "usr/local/lib").mkdir(parents=True)
    elsewhere = tmp_path / "attacker-dir"
    elsewhere.mkdir()
    os.symlink(str(elsewhere), str(root / "usr/local/lib/paddock-agent"))
    res, _ = staged(tmp_path, mirror, "--no-enroll")
    assert res.returncode != 0 and "symlink" in out(res), out(res)
    assert list(elsewhere.iterdir()) == []


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() != 0, reason="needs root to chown")
def test_pkg13_an_install_dir_owned_by_someone_else_is_refused(tmp_path, real_pyz_path):
    mirror, _ = make_mirror(tmp_path, real_pyz_path.read_bytes())
    root = tmp_path / "root"
    lib = root / "usr/local/lib/paddock-agent"
    lib.mkdir(parents=True)
    os.chown(str(lib), 65534, 65534)
    res, _ = staged(tmp_path, mirror, "--no-enroll")
    assert res.returncode != 0 and "not owned by" in out(res), out(res)
    assert not (lib / "paddock-agent.pyz").exists()


# =========================================================== pkg-4: restart and check the service
def test_pkg4_the_service_is_restarted_after_the_archive_is_replaced_and_checked(tmp_path):
    mirror, _ = make_mirror(tmp_path, FAKE_AGENT.encode())
    ctl, log = fake_systemctl(tmp_path)
    root = tmp_path / "root"
    seed_credentials(root)
    res, _ = staged(tmp_path, mirror, env=systemd_env(tmp_path, ctl), stdin=b"")
    assert res.returncode == 0, out(res)
    calls = log.read_text().splitlines()
    assert "daemon-reload" in calls
    assert any(c.startswith("restart ") or c.startswith("try-restart ") for c in calls), calls
    assert "enable paddock-agent" in calls or "enable --now paddock-agent" in calls
    assert calls.index("daemon-reload") < max(i for i, c in enumerate(calls) if "restart" in c)
    assert any(c.startswith("is-active") for c in calls)
    assert "is running" in out(res)


def test_pkg4_a_service_that_is_not_active_after_the_wait_fails_the_install(tmp_path):
    mirror, _ = make_mirror(tmp_path, FAKE_AGENT.encode())
    ctl, log = fake_systemctl(tmp_path, active_rc=3)
    root = tmp_path / "root"
    seed_credentials(root)
    res, _ = staged(tmp_path, mirror, env=systemd_env(tmp_path, ctl), stdin=b"")
    assert res.returncode != 0
    assert "is running" not in out(res) and "not running" in out(res) and "journalctl" in out(res)


def test_pkg4_no_start_with_an_active_service_warns_that_the_old_code_still_runs(tmp_path):
    mirror, _ = make_mirror(tmp_path, FAKE_AGENT.encode())
    ctl, log = fake_systemctl(tmp_path)
    root = tmp_path / "root"
    seed_credentials(root)
    res, _ = staged(tmp_path, mirror, "--no-start", env=systemd_env(tmp_path, ctl), stdin=b"")
    assert res.returncode == 0, out(res)
    assert "still running the previous" in out(res) and "systemctl restart" in out(res)
    assert not any(c.startswith("restart") or "--now" in c for c in log.read_text().splitlines())


# =========================================================== pkg-5: agent.env is merged, not overwritten
def test_pkg5_operator_settings_in_agent_env_survive_a_rerun(tmp_path, real_pyz_path):
    mirror, _ = make_mirror(tmp_path, real_pyz_path.read_bytes())
    root = tmp_path / "root"
    conf = root / "etc/paddock-agent"
    conf.mkdir(parents=True)
    (conf / "agent.env").write_text(
        "# mine\nPADDOCK_SERVER=https://old.example\nPADDOCK_CA_FILE=/etc/ca.pem\nPADDOCK_ENABLE_IMDS=true\n"
        "PADDOCK_SERVER=https://older.example\nPADDOCK_POSTURE_INTERVAL=60")          # no trailing newline
    res, _ = staged(tmp_path, mirror, "--no-enroll")
    assert res.returncode == 0, out(res)
    lines = (conf / "agent.env").read_text().splitlines()
    assert lines.count("PADDOCK_SERVER=" + SERVER) == 1
    assert not any(ln.startswith("PADDOCK_SERVER=") and ln != "PADDOCK_SERVER=" + SERVER for ln in lines)
    for keep in ("PADDOCK_CA_FILE=/etc/ca.pem", "PADDOCK_ENABLE_IMDS=true", "PADDOCK_POSTURE_INTERVAL=60", "# mine"):
        assert keep in lines, lines
    assert (conf / "agent.env").stat().st_mode & 0o777 == 0o600


def test_pkg5_a_fresh_install_still_writes_only_the_server(tmp_path, real_pyz_path):
    mirror, _ = make_mirror(tmp_path, real_pyz_path.read_bytes())
    res, root = staged(tmp_path, mirror, "--no-enroll")
    assert res.returncode == 0, out(res)
    lines = (root / "etc/paddock-agent/agent.env").read_text().splitlines()
    assert [ln for ln in lines if not ln.startswith("#")] == ["PADDOCK_SERVER=" + SERVER]


# =========================================================== pkg-6: no release-notes digest that does not exist
def test_pkg6_the_release_body_carries_the_archive_and_installer_digests():
    yml = read(RELEASE_YML)
    m = re.search(r"^\s*body_path:\s*(\S+)", yml, re.M)
    assert m, "the release step has no body_path"
    notes_step = yml.split("Release notes", 1)[1].split("Create release", 1)[0]       # the step that writes it
    assert m.group(1) in notes_step and "out/SHA256SUMS" in notes_step


def test_pkg6_docs_and_help_do_not_point_at_a_digest_source_that_is_not_independent():
    doc = read(AGENT_V2)
    assert "compare the digest with the release notes" not in doc
    assert "--require-cosign" in doc.split("## 2.")[0]                                # the quick start uses it
    sh = read(SCRIPT)
    assert "pin it from the release notes" not in sh
    assert "independent" in sh.split("set -eu")[0]


# =========================================================== pkg-7: the documented commands must run
@pytest.mark.parametrize("path", [AGENT_V2, FLEET_WIRING, SCRIPT])
def test_pkg7_documented_installer_commands_do_not_need_the_exec_bit(path):
    bad = []
    for n, line in enumerate(read(path).splitlines(), 1):
        for m in re.finditer(r"(?<![\w./-])\./install-agent\.sh", line):
            if not re.search(r"\bsh $", line[:m.start()]):
                bad.append((n, line.strip()))
    assert not bad, bad


# =========================================================== pkg-8: the paddock command
def test_pkg8_a_foreign_paddock_command_is_not_overwritten_and_survives_uninstall(tmp_path, real_pyz_path):
    mirror, _ = make_mirror(tmp_path, real_pyz_path.read_bytes())
    root = tmp_path / "root"
    link = root / "usr/local/bin/paddock"
    link.parent.mkdir(parents=True)
    link.write_text("#!/bin/sh\necho REAL-PADDOCK-CLI\n")
    os.chmod(str(link), 0o755)
    res, _ = staged(tmp_path, mirror, "--no-enroll")
    assert res.returncode == 0, out(res)
    assert "REAL-PADDOCK-CLI" in link.read_text() and not os.path.islink(str(link))
    assert "not overwriting" in out(res)
    res = run(["--root", str(root), "--uninstall"], env=clean_env(tool_path(tmp_path)), stdin=b"")
    assert res.returncode == 0, out(res)
    assert "REAL-PADDOCK-CLI" in link.read_text()                                    # not ours: kept
    assert not (root / "usr/local/lib/paddock-agent").exists()


def test_pkg8_a_foreign_symlink_is_kept_too(tmp_path, real_pyz_path):
    mirror, _ = make_mirror(tmp_path, real_pyz_path.read_bytes())
    root = tmp_path / "root"
    link = root / "usr/local/bin/paddock"
    link.parent.mkdir(parents=True)
    os.symlink("/usr/bin/true", str(link))
    res, _ = staged(tmp_path, mirror, "--no-enroll")
    assert res.returncode == 0, out(res)
    assert os.readlink(str(link)) == "/usr/bin/true"
    res = run(["--root", str(root), "--uninstall"], env=clean_env(tool_path(tmp_path)), stdin=b"")
    assert os.path.islink(str(link)) and os.readlink(str(link)) == "/usr/bin/true"


def test_pkg8_the_command_is_a_wrapper_that_runs_the_verified_interpreter(tmp_path, real_pyz_path):
    mirror, _ = make_mirror(tmp_path, real_pyz_path.read_bytes())
    res, root = staged(tmp_path, mirror, "--no-enroll")
    assert res.returncode == 0, out(res)
    link = root / "usr/local/bin/paddock"
    assert not os.path.islink(str(link)) and link.stat().st_mode & 0o777 == 0o755
    text = link.read_text()
    assert text.startswith("#!/bin/sh\n")
    assert ("exec '%s' '/usr/local/lib/paddock-agent/paddock-agent.pyz' \"$@\"" % sys.executable) in text
    # re-running replaces our own wrapper silently, and uninstall removes it
    res, _ = staged(tmp_path, mirror, "--no-enroll")
    assert res.returncode == 0 and "not overwriting" not in out(res)
    res = run(["--root", str(root), "--uninstall"], env=clean_env(tool_path(tmp_path)), stdin=b"")
    assert not os.path.lexists(str(link))


def test_pkg8_a_symlink_left_by_the_old_installer_is_upgraded_and_removed(tmp_path, real_pyz_path):
    mirror, _ = make_mirror(tmp_path, real_pyz_path.read_bytes())
    root = tmp_path / "root"
    link = root / "usr/local/bin/paddock"
    link.parent.mkdir(parents=True)
    os.symlink("/usr/local/lib/paddock-agent/paddock-agent.pyz", str(link))
    res, _ = staged(tmp_path, mirror, "--no-enroll")
    assert res.returncode == 0, out(res)
    assert not os.path.islink(str(link)) and "exec '" in link.read_text()
    os.unlink(str(link))
    os.symlink("/usr/local/lib/paddock-agent/paddock-agent.pyz", str(link))
    res = run(["--root", str(root), "--uninstall"], env=clean_env(tool_path(tmp_path)), stdin=b"")
    assert not os.path.lexists(str(link))


# =========================================================== pkg-9: the documented build is the release build
def _build_env_assignment(text):
    m = re.search(r"((?:SOURCE_DATE_EPOCH=\S+\s+)?)python3? \S*agent/packaging/build_zipapp\.py", text)
    return m.group(1).strip() if m else None


def test_pkg9_the_documented_build_command_is_the_one_the_release_runs():
    doc, yml = _build_env_assignment(read(AGENT_V2)), _build_env_assignment(read(RELEASE_YML))
    assert yml is not None and doc is not None
    assert doc == yml, "docs say %r, the release workflow runs %r" % (doc, yml)
    assert not [ln for ln in read(RELEASE_YML).splitlines() if "build_zipapp.py" in ln and "git log" in ln]
    # the installer is pinned the same way in both
    sed = 's/^PINNED_TAG=.*/PINNED_TAG='
    assert sed in read(AGENT_V2) and sed in read(RELEASE_YML)


def test_pkg9_building_twice_with_the_documented_recipe_is_byte_identical(tmp_path):
    recipe = _build_env_assignment(read(AGENT_V2))
    assert recipe and recipe.startswith("SOURCE_DATE_EPOCH=")
    epoch = recipe.split("=", 1)[1]
    digests = set()
    for i, (tz, umask) in enumerate((("UTC", 0o022), ("Pacific/Auckland", 0o077))):
        outp = tmp_path / ("b%d" % i) / "paddock-agent.pyz"
        old = os.umask(umask)
        try:
            res = subprocess.run([sys.executable, os.path.join(REPO, "agent", "packaging", "build_zipapp.py"),
                                  "--out", str(outp)],
                                 env=dict(os.environ, TZ=tz, SOURCE_DATE_EPOCH=epoch), stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, timeout=120, cwd=str(tmp_path))
        finally:
            os.umask(old)
        assert res.returncode == 0, res.stderr
        digests.add(hashlib.sha256(outp.read_bytes()).hexdigest())
    assert len(digests) == 1
    assert bz.source_date_epoch(epoch) == int(epoch)


# =========================================================== pkg-10: stale READINESS clause
def test_pkg10_readiness_does_not_claim_the_agent_events_are_unregistered():
    text = read(READINESS)
    assert "audit rows only until" not in text
    base = read(os.path.join(REPO, "orchestrator", "app", "integrations", "base.py"))
    assert '"agent.offline"' in base and '"agent.online"' in base                 # the claim it replaces is false


# =========================================================== pkg-12: release trust root
def test_pkg12_every_action_is_pinned_by_commit_sha():
    uses = [ln.strip() for ln in read(RELEASE_YML).splitlines() if re.match(r"\s*(-\s+)?uses:", ln)]
    assert uses
    unpinned = [u for u in uses if not re.search(r"@[0-9a-f]{40}(\s|$)", u)]
    assert not unpinned, unpinned


def test_pkg12_cosign_is_pinned_to_a_version_wherever_it_is_installed():
    lines = read(RELEASE_YML).splitlines()
    at = [i for i, ln in enumerate(lines) if "sigstore/cosign-installer@" in ln]
    assert len(at) == 3, at
    for i in at:
        assert any(re.search(r"cosign-release:\s*'?v\d+\.\d+\.\d+'?\s*$", ln) for ln in lines[i + 1:i + 4]), lines[i]


def test_pkg12_a_protected_environment_and_a_main_ancestry_gate_precede_every_job():
    yml = read(RELEASE_YML)
    assert re.search(r"^\s+environment:\s*release\s*$", yml, re.M)
    assert "merge-base --is-ancestor" in yml
    for job in ("images", "agent"):
        body = yml.split("\n  %s:\n" % job, 1)[1]
        assert re.search(r"^    needs:\s*\[?\s*gate", body, re.M), job
    rel = yml.split("\n  release:\n", 1)[1]
    assert re.search(r"needs:\s*\[[^\]]*gate", rel)


def test_pkg12_the_minimum_cosign_version_is_documented():
    assert re.search(r"cosign\D{0,40}2\.\d", read(AGENT_V2))
    assert re.search(r"cosign\D{0,60}2\.\d", read(SCRIPT).split("set -eu")[0])


# =========================================================== pkg-2: what the unit permits, said exactly
def test_pkg2_the_docs_state_the_legacy_iptables_limit_and_do_not_claim_netlink_for_everything():
    doc = read(AGENT_V2)
    assert "Firewall actions use netlink." not in doc
    assert "CAP_NET_RAW" in doc and "legacy" in doc and "UNKNOWN" in doc.split("CAP_NET_RAW")[1][:900]
    wiring = read(FLEET_WIRING)
    assert "CAP_NET_RAW" in wiring and "legacy" in wiring


def test_pkg2_the_unit_does_not_silently_widen_the_bounding_set():
    unit = read(UNIT)
    assert "CAP_NET_RAW" not in [t for ln in unit.splitlines() if ln.startswith("CapabilityBoundingSet=")
                                 for t in ln.split("=", 1)[1].split()]
    assert "legacy" in unit and "CAP_NET_RAW" in unit        # but the unit says why, where an operator reads it


# =========================================================== rework round: verifier follow-ups
def test_pkg12_the_gate_comment_does_not_claim_more_than_a_gate_can_do():
    head = read(RELEASE_YML).split("\non:\n", 1)[0]
    assert "gets no release and no signature" not in head
    flat = " ".join(head.split())
    # the real control is repository settings; the workflow itself says so, and says what it cannot stop
    assert "tag ruleset" in flat and "same commit" in flat and "cannot" in flat


def test_pkg12_agent_v2_states_the_limit_of_the_release_gate():
    flat = " ".join(read(AGENT_V2).split())
    assert "tag ruleset" in flat and "does not prove" in flat


def test_pkg13_the_parent_of_the_archive_dir_is_checked_too(tmp_path, real_pyz_path):
    mirror, _ = make_mirror(tmp_path, real_pyz_path.read_bytes())
    root = tmp_path / "root"
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (root / "opt/x").mkdir(parents=True)
    os.symlink(str(elsewhere), str(root / "opt/x/lib"))                      # <prefix>/lib is somebody's symlink
    res, _ = staged(tmp_path, mirror, "--no-enroll", "--prefix", "/opt/x")
    assert res.returncode != 0 and "symlink" in out(res), out(res)
    assert list(elsewhere.iterdir()) == []


def test_pkg13_a_symlinked_state_dir_is_refused_and_the_docs_say_so(tmp_path, real_pyz_path):
    mirror, _ = make_mirror(tmp_path, real_pyz_path.read_bytes())
    root = tmp_path / "root"
    (root / "var/lib").mkdir(parents=True)
    moved = tmp_path / "moved-state"
    moved.mkdir()
    os.symlink(str(moved), str(root / "var/lib/paddock-agent"))
    res, _ = staged(tmp_path, mirror, "--no-enroll")
    assert res.returncode != 0 and "symlink" in out(res)
    flat = " ".join(read(AGENT_V2).split())
    assert "symlink" in flat and "bind mount" in flat                       # the relocation advice


def test_pkg2_the_drop_in_recipe_mentions_the_lock_file_and_the_clean_checkout_is_stated():
    flat = " ".join(read(AGENT_V2).split())
    assert "ReadWritePaths=/run/xtables.lock" in flat
    assert "clean checkout" in flat
