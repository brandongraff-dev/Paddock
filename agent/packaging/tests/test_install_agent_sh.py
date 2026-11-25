"""scripts/install-agent.sh, everything that can be checked offline (Python 3.8 compatible).

Real installs run against a ``file://`` mirror with ``--root`` (a staging directory), so no network, root or
systemd is involved; ``cosign`` is a recording fake. What is NOT covered here: a real GitHub release download,
a real cosign/sigstore verification, and the unit under a real systemd.
"""
import hashlib
import os
import shutil
import stat
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
PACKAGING = os.path.dirname(HERE)
AGENT = os.path.dirname(PACKAGING)
REPO = os.path.dirname(AGENT)
SCRIPT = os.path.join(REPO, "scripts", "install-agent.sh")
UNIT = os.path.join(AGENT, "systemd", "paddock-agent.service")
sys.path.insert(0, PACKAGING)

import build_zipapp as bz  # noqa: E402

pytestmark = pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX sh")

TOKEN = "fet_0123456789ab_Sup3rS3cretTokenValue_0123456789"
SERVER = "https://paddock.example.com"
TOOLS = ("sh", "dash", "awk", "sed", "head", "tr", "cat", "cp", "mv", "rm", "mkdir", "chmod", "ln", "id", "uname",
         "mktemp", "sha256sum", "dirname", "basename", "stty", "grep", "env", "sleep", "readlink", "find")


def clean_env(path=None, **extra):
    env = {"PATH": path or os.environ.get("PATH", ""), "HOME": "/nonexistent", "LC_ALL": "C", "TMPDIR": "/tmp"}
    env.update(extra)
    return env


def run(args, *, env=None, stdin=None, path=None, timeout=60):
    kw = {"input": stdin} if isinstance(stdin, bytes) else {"stdin": stdin if stdin is not None else subprocess.DEVNULL}
    return subprocess.run(["sh", SCRIPT] + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          env=env if env is not None else clean_env(path), timeout=timeout, **kw)


def out(res):
    return (res.stdout + res.stderr).decode("utf-8", "replace")


@pytest.fixture(scope="module")
def real_pyz(tmp_path_factory):
    d = tmp_path_factory.mktemp("real")
    p = d / "paddock-agent.pyz"
    bz.build(str(p))
    return p


def make_mirror(tmp_path, pyz_bytes, *, sums=None, name="mirror"):
    m = tmp_path / name
    m.mkdir()
    (m / "paddock-agent.pyz").write_bytes(pyz_bytes)
    digest = hashlib.sha256(pyz_bytes).hexdigest()
    (m / "SHA256SUMS").write_text(sums if sums is not None else "%s  paddock-agent.pyz\n" % digest)
    (m / "SHA256SUMS.sigstore.json").write_text("{}")
    return m, digest


def system_tool(name):
    """The real binary, looked up in the system directories (a sandbox may shadow PATH entries such as rm)."""
    for d in ("/usr/bin", "/bin", "/usr/local/bin"):
        p = os.path.join(d, name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return shutil.which(name)


def tool_path(tmp_path, with_cosign=None):
    """A PATH holding only the tools the installer needs (plus a fake cosign when asked): no curl, no wget."""
    d = tmp_path / "bin"
    d.mkdir(exist_ok=True)
    for t in TOOLS:
        real = system_tool(t)
        if real and not (d / t).exists():
            os.symlink(real, str(d / t))
    if with_cosign is not None:
        log = tmp_path / "cosign.log"
        (d / "cosign").write_text("#!/bin/sh\nprintf '%%s\\n' \"$*\" >> %s\nexit %d\n" % (log, with_cosign))
        os.chmod(str(d / "cosign"), 0o755)
    return str(d)


def staged(tmp_path, mirror, *extra, env=None, stdin=b"", path=None):
    root = tmp_path / "root"
    args = ["--server", SERVER, "--root", str(root), "--base-url", "file://" + str(mirror),
            "--python", sys.executable] + list(extra)
    return run(args, env=env if env is not None else clean_env(path or tool_path(tmp_path)), stdin=stdin), root


# ---------------------------------------------------------------- the script itself
def test_script_is_executable_posix_and_shellcheck_clean_when_available():
    assert os.stat(SCRIPT).st_mode & stat.S_IXUSR
    first = open(SCRIPT).readline()
    assert first.strip() == "#!/bin/sh"
    assert subprocess.run(["sh", "-n", SCRIPT]).returncode == 0
    if shutil.which("dash"):
        assert subprocess.run(["dash", "-n", SCRIPT]).returncode == 0
    if shutil.which("shellcheck"):
        res = subprocess.run(["shellcheck", "-s", "sh", SCRIPT], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert res.returncode == 0, res.stdout.decode()


def test_help_lists_the_documented_options():
    res = run(["--help"])
    assert res.returncode == 0
    text = out(res)
    for opt in ("--server", "--version", "--sha256", "--require-cosign", "--dry-run", "--uninstall", "--purge",
                "--no-enroll", "--reenroll"):
        assert opt in text, opt
    assert "never accepted" in text or "NEVER an argument" in text


def test_the_pin_is_a_tag_never_latest():
    src = open(SCRIPT).read()
    pin = [ln for ln in src.splitlines() if ln.startswith("PINNED_TAG=")]
    assert len(pin) == 1 and pin[0].startswith('PINNED_TAG="v')
    assert "/latest/" not in src and "releases/latest" not in src


# ---------------------------------------------------------------- argument handling
@pytest.mark.parametrize("bad", [
    ["--token", TOKEN], ["--token=" + TOKEN], ["--enroll-token", TOKEN], [TOKEN],
])
def test_a_token_on_the_command_line_is_refused_and_never_echoed(bad):
    res = run(["--server", SERVER, "--dry-run"] + bad)
    assert res.returncode != 0
    assert "0123456789ab" not in out(res) and "Sup3rS3cret" not in out(res)
    assert "argument" in out(res)


@pytest.mark.parametrize("args,msg", [
    (["--dry-run"], "--server is required"),
    (["--server", "http://paddock.example.com", "--dry-run"], "https://"),
    (["--server", "http://127.evil.example.com", "--dry-run"], "https://"),
    (["--server", "http://localhost.evil.example", "--dry-run"], "https://"),
    (["--server", "ftp://x", "--dry-run"], "https://"),
    (["--server", "https://user:pw@paddock.example.com", "--dry-run"], "unexpected characters"),
    (["--server", "https://paddock.example.com/?a=b", "--dry-run"], "unexpected characters"),
    (["--server", SERVER, "--version", "latest", "--dry-run"], "release tag"),
    (["--server", SERVER, "--version", "v1.0.0;rm", "--dry-run"], "unexpected characters"),
    (["--server", SERVER, "--repo", "../etc", "--dry-run"], "unexpected characters"),
    (["--server", SERVER, "--repo", "noslash", "--dry-run"], "OWNER/NAME"),
    (["--server", SERVER, "--base-url", "http://mirror.example", "--dry-run"], "https://"),
    (["--server", SERVER, "--base-url", "https://u:p@mirror.example", "--dry-run"], "unexpected characters"),
    (["--server", SERVER, "--sha256", "abc", "--dry-run"], "64 hex"),
    (["--server", SERVER, "--prefix", "relative", "--dry-run"], "absolute"),
    (["--server", SERVER, "--root", "/tmp/a b", "--dry-run"], "unexpected characters"),
    (["--server", SERVER, "--hostname", "a b", "--dry-run"], "hostname"),
    (["--purge"], "--purge only makes sense"),
    (["--server"], "needs a value"),
    (["--frobnicate"], "unknown option"),
])
def test_bad_arguments_fail_closed(args, msg):
    res = run(args)
    assert res.returncode != 0, out(res)
    assert msg in out(res), out(res)


@pytest.mark.parametrize("server", ["http://127.0.0.1:8080", "http://localhost:8080", "https://paddock.example.com:8443/"])
def test_acceptable_servers_pass_validation(server):
    assert run(["--server", server, "--dry-run"]).returncode == 0


# ---------------------------------------------------------------- dry run
def test_dry_run_changes_nothing_uses_no_network_and_reads_no_token(tmp_path):
    marker = tmp_path / "network-was-used"
    path = tool_path(tmp_path)
    for tool in ("curl", "wget", "systemctl"):
        p = os.path.join(path, tool)
        with open(p, "w") as fh:
            fh.write("#!/bin/sh\necho %s >> %s\nexit 99\n" % (tool, marker))
        os.chmod(p, 0o755)
    root = tmp_path / "root"
    res = run(["--server", SERVER, "--root", str(root), "--dry-run"],
              env=clean_env(path, PADDOCK_ENROLL_TOKEN=TOKEN), stdin=subprocess.DEVNULL)
    assert res.returncode == 0, out(res)
    assert not marker.exists() and not root.exists()
    text = out(res)
    assert "Sup3rS3cret" not in text and TOKEN not in text and "0123456789ab" not in text
    assert "not shown" in text
    assert "no changes made" in text
    assert text.count("[dry-run]") > 10


def test_dry_run_shows_the_pinned_release_the_checks_and_the_unit():
    res = run(["--server", SERVER, "--dry-run", "--python", "/usr/bin/python3"])
    text = out(res)
    assert res.returncode == 0
    assert "https://github.com/brandongraff-dev/paddock/releases/download/v0.2.0/paddock-agent.pyz" in text
    assert "SHA256SUMS" in text and "abort on any mismatch" in text
    assert "latest'" in text and "there is no 'latest'" in text
    assert "ExecStart=/usr/bin/python3 /usr/local/lib/paddock-agent/paddock-agent.pyz run" in text


def test_dry_run_with_cosign_names_the_workflow_identity(tmp_path):
    path = tool_path(tmp_path, with_cosign=0)
    res = run(["--server", SERVER, "--dry-run", "--version", "v9.9.9", "--repo", "acme/paddock"],
              env=clean_env(path))
    text = out(res)
    assert "cosign verify-blob" in text
    assert "https://github.com/acme/paddock/.github/workflows/release.yml@refs/tags/v9.9.9" in text
    assert "https://token.actions.githubusercontent.com" in text


def test_dry_run_says_when_require_cosign_would_stop(tmp_path):
    res = run(["--server", SERVER, "--dry-run", "--require-cosign"], env=clean_env(tool_path(tmp_path)))
    assert res.returncode == 0 and "would stop here" in out(res)


def _unit_from_dry_run(text):
    lines = [ln[len("[dry-run]     | "):] if ln.startswith("[dry-run]     | ") else
             ("" if ln == "[dry-run]     |" else None) for ln in text.splitlines()]
    return "\n".join(ln for ln in lines if ln is not None) + "\n"


def test_unit_written_by_the_installer_equals_the_unit_file_in_the_repo():
    res = run(["--server", SERVER, "--dry-run", "--python", "/usr/bin/python3"])
    emitted = _unit_from_dry_run(out(res))
    assert emitted == open(UNIT).read()


def parse_unit(text):
    sections, cur = {}, None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            cur = sections.setdefault(line.strip("[]"), [])
        else:
            k, _, v = line.partition("=")
            cur.append((k, v))
    return sections


def test_unit_has_exactly_the_contract_sandbox_and_one_root_process():
    unit = parse_unit(open(UNIT).read())
    svc = dict(unit["Service"])
    assert svc["User"] == "root"                        # one root process (owner decision O2)
    required = {
        "NoNewPrivileges": "yes", "ProtectSystem": "strict", "ProtectHome": "yes", "PrivateTmp": "yes",
        "ReadWritePaths": "/var/lib/paddock-agent",
        "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6 AF_NETLINK",
        "ProtectKernelTunables": "yes", "SystemCallFilter": "@system-service",
        "CapabilityBoundingSet": "CAP_DAC_READ_SEARCH CAP_SYS_PTRACE CAP_NET_ADMIN",
        "RestartPreventExitStatus": "7", "Restart": "on-failure",
    }
    for k, v in required.items():
        assert svc.get(k) == v, k
    keys = [k for k, _ in unit["Service"]]
    assert len(keys) == len(set(keys))                 # no directive is set twice (a later one would win)
    text = open(UNIT).read()
    for secret_ish in ("TOKEN", "fet_", "Environment=PADDOCK_ENROLL"):
        assert secret_ish not in text
    assert "ExecStart=" in text and "paddock-agent.pyz run" in text
    # no capability beyond the three read-mostly ones, no way back to full root
    assert "CAP_SYS_ADMIN" not in text and "AmbientCapabilities" not in text


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="needs systemd-analyze")
def test_unit_passes_systemd_analyze_verify(tmp_path):
    unit = tmp_path / "paddock-agent.service"
    unit.write_text(open(UNIT).read())
    res = subprocess.run(["systemd-analyze", "verify", str(unit)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         timeout=30)
    text = out(res)
    # a missing ExecStart binary is expected in a CI sandbox; any syntax/unknown-directive complaint is not
    complaints = [ln for ln in text.splitlines() if "Unknown key" in ln or "Failed to parse" in ln
                  or "Invalid" in ln or "Unknown section" in ln]
    assert not complaints, text


# ---------------------------------------------------------------- real staged installs
def test_staged_install_writes_the_right_files_with_the_right_modes(tmp_path, real_pyz):
    mirror, digest = make_mirror(tmp_path, real_pyz.read_bytes())
    res, root = staged(tmp_path, mirror, "--no-enroll")
    assert res.returncode == 0, out(res)
    pyz = root / "usr/local/lib/paddock-agent/paddock-agent.pyz"
    assert pyz.read_bytes() == real_pyz.read_bytes() and pyz.stat().st_mode & 0o777 == 0o755
    # was: a symlink to the archive, run through its `#!/usr/bin/env python3` line (P2 review pkg-8: that is not the
    # interpreter the installer verified). Now a wrapper that execs the verified interpreter; see test_installer_p2x.py.
    link = root / "usr/local/bin/paddock"
    assert not os.path.islink(str(link)) and link.stat().st_mode & 0o777 == 0o755
    assert "exec '%s' '/usr/local/lib/paddock-agent/paddock-agent.pyz' \"$@\"" % sys.executable in link.read_text()
    env_file = root / "etc/paddock-agent/agent.env"
    assert env_file.stat().st_mode & 0o777 == 0o600
    assert env_file.read_text().splitlines()[-1] == "PADDOCK_SERVER=" + SERVER
    assert (root / "etc/paddock-agent").stat().st_mode & 0o777 == 0o700
    assert (root / "var/lib/paddock-agent").stat().st_mode & 0o777 == 0o700
    unit = (root / "etc/systemd/system/paddock-agent.service").read_text()
    assert ("ExecStart=%s /usr/local/lib/paddock-agent/paddock-agent.pyz run" % sys.executable) in unit
    assert "systemd was not touched" in out(res) and digest in out(res)
    assert not any(n.endswith(".new") for _d, _s, files in os.walk(str(root)) for n in files)
    # and the installed archive really runs
    ok = subprocess.run([sys.executable, str(pyz), "--version"], stdout=subprocess.PIPE)
    assert ok.returncode == 0 and ok.stdout.startswith(b"paddock ")


def test_a_tampered_archive_is_refused_and_nothing_is_installed(tmp_path, real_pyz):
    good = real_pyz.read_bytes()
    mirror, _ = make_mirror(tmp_path, good)
    (mirror / "paddock-agent.pyz").write_bytes(good + b"# backdoor\n")
    res, root = staged(tmp_path, mirror, "--no-enroll")
    assert res.returncode != 0 and "checksum mismatch" in out(res)
    assert not (root / "usr").exists() and not (root / "etc").exists()


@pytest.mark.parametrize("sums,msg", [
    ("", "no entry"),
    ("%s  other.pyz\n" % ("a" * 64), "no entry"),
    ("nothex  paddock-agent.pyz\n", "malformed"),
    ("%s  paddock-agent.pyz\n" % ("a" * 63), "malformed"),
    ("%s  paddock-agent.pyz\n" % ("0" * 64), "checksum mismatch"),
])
def test_bad_checksum_manifests_fail_closed(tmp_path, real_pyz, sums, msg):
    mirror, _ = make_mirror(tmp_path, real_pyz.read_bytes(), sums=sums)
    res, root = staged(tmp_path, mirror, "--no-enroll")
    assert res.returncode != 0 and msg in out(res), out(res)
    assert not (root / "usr").exists()


def test_a_missing_download_fails_closed(tmp_path):
    res, root = staged(tmp_path, tmp_path / "nowhere", "--no-enroll")
    assert res.returncode != 0 and "could not download" in out(res)
    assert not root.exists() or not (root / "usr").exists()


def test_the_pinned_sha256_must_match_even_when_the_manifest_does(tmp_path, real_pyz):
    mirror, digest = make_mirror(tmp_path, real_pyz.read_bytes())
    res, root = staged(tmp_path, mirror, "--no-enroll", "--sha256", "b" * 64)
    assert res.returncode != 0 and "pinned" in out(res) and not (root / "usr").exists()
    res, root2 = staged(tmp_path, mirror, "--no-enroll", "--sha256", digest.upper())
    assert res.returncode == 0, out(res)


def test_an_archive_that_does_not_run_is_not_installed(tmp_path):
    mirror, _ = make_mirror(tmp_path, b"#!/bin/sh\nexit 3\n")
    res, root = staged(tmp_path, mirror, "--no-enroll")
    assert res.returncode != 0 and "does not run" in out(res)
    assert not (root / "usr").exists()


def test_an_interpreter_older_than_38_is_refused(tmp_path, real_pyz):
    mirror, _ = make_mirror(tmp_path, real_pyz.read_bytes())
    old = tmp_path / "python-old"
    old.write_text("#!/bin/sh\nexit 1\n")
    os.chmod(str(old), 0o755)
    root = tmp_path / "root"
    res = run(["--server", SERVER, "--root", str(root), "--base-url", "file://" + str(mirror), "--python", str(old),
               "--no-enroll"], env=clean_env(tool_path(tmp_path)), stdin=b"")
    assert res.returncode != 0 and "older than Python 3.8" in out(res)
    assert not (root / "usr").exists()


# ---- cosign
def test_cosign_is_invoked_with_the_release_workflow_identity_and_gates_the_install(tmp_path, real_pyz):
    mirror, _ = make_mirror(tmp_path, real_pyz.read_bytes())
    path = tool_path(tmp_path, with_cosign=0)
    res, root = staged(tmp_path, mirror, "--no-enroll", "--version", "v0.2.0", "--repo", "acme/paddock", path=path)
    assert res.returncode == 0, out(res)
    log = (tmp_path / "cosign.log").read_text()
    assert log.startswith("verify-blob ")
    assert "--certificate-identity https://github.com/acme/paddock/.github/workflows/release.yml@refs/tags/v0.2.0" in log
    assert "--certificate-oidc-issuer https://token.actions.githubusercontent.com" in log
    assert "--bundle" in log and log.strip().endswith("SHA256SUMS")
    assert "signature OK" in out(res)


def test_a_failing_cosign_check_blocks_the_install(tmp_path, real_pyz):
    mirror, _ = make_mirror(tmp_path, real_pyz.read_bytes())
    path = tool_path(tmp_path, with_cosign=1)
    res, root = staged(tmp_path, mirror, "--no-enroll", path=path)
    assert res.returncode != 0 and "did not verify" in out(res)
    assert not (root / "usr").exists()


def test_a_missing_signature_bundle_blocks_the_install_when_cosign_is_present(tmp_path, real_pyz):
    mirror, _ = make_mirror(tmp_path, real_pyz.read_bytes())
    os.unlink(str(mirror / "SHA256SUMS.sigstore.json"))
    res, root = staged(tmp_path, mirror, "--no-enroll", path=tool_path(tmp_path, with_cosign=0))
    assert res.returncode != 0 and "signature bundle" in out(res)
    assert not (root / "usr").exists()


def test_require_cosign_without_cosign_is_an_error_and_without_it_a_loud_warning(tmp_path, real_pyz):
    mirror, _ = make_mirror(tmp_path, real_pyz.read_bytes())
    res, root = staged(tmp_path, mirror, "--no-enroll", "--require-cosign")
    assert res.returncode != 0 and "cosign is not installed" in out(res) and not (root / "usr").exists()
    res, root = staged(tmp_path, mirror, "--no-enroll")
    assert res.returncode == 0 and "signature was NOT checked" in out(res)


# ---- the token
FAKE_AGENT = r'''#!/usr/bin/env python3
import json, os, sys
rec = {"argv": sys.argv[1:], "env_has_token": "PADDOCK_ENROLL_TOKEN" in os.environ,
       "env_state": os.environ.get("PADDOCK_STATE_DIR"), "env_server": os.environ.get("PADDOCK_SERVER")}
if len(sys.argv) > 1 and sys.argv[1] == "--version":
    print("paddock fake")
    sys.exit(0)
if len(sys.argv) > 1 and sys.argv[1] == "enroll":
    data = sys.stdin.read()
    rec["stdin"] = data
    secret = data.strip()
    leaks = []
    for pid in os.listdir("/proc"):
        if pid.isdigit():
            try:
                cmd = open("/proc/%s/cmdline" % pid, "rb").read().decode("utf-8", "replace")
            except OSError:
                continue
            if secret and secret in cmd:
                leaks.append(pid)
    rec["cmdline_leaks"] = leaks
    with open(os.environ["FAKE_AGENT_RECORD"], "w") as fh:
        json.dump(rec, fh)
    sys.exit(int(os.environ.get("FAKE_AGENT_RC", "0")))
sys.exit(0)
'''


def token_install(tmp_path, *, stdin=b"", env_token=None, rc=0, extra=()):
    mirror, _ = make_mirror(tmp_path, FAKE_AGENT.encode())
    record = tmp_path / "record.json"
    env = clean_env(tool_path(tmp_path), FAKE_AGENT_RECORD=str(record), FAKE_AGENT_RC=str(rc))
    if env_token is not None:
        env["PADDOCK_ENROLL_TOKEN"] = env_token
    res, root = staged(tmp_path, mirror, *extra, env=env, stdin=stdin)
    return res, root, record


def tree_text(root):
    blobs = []
    for d, _s, files in os.walk(str(root)):
        for n in files:
            p = os.path.join(d, n)
            if not os.path.islink(p):
                blobs.append(open(p, "rb").read())
    return b"\n".join(blobs)


@pytest.mark.skipif(not os.path.isdir("/proc/self"), reason="needs /proc")
@pytest.mark.parametrize("via", ["stdin", "env"])
def test_the_token_reaches_the_agent_on_stdin_and_is_in_no_argv_no_file_no_output(tmp_path, via):
    kw = {"stdin": (TOKEN + "\n").encode()} if via == "stdin" else {"env_token": TOKEN}
    res, root, record = token_install(tmp_path, **kw)
    assert res.returncode == 0, out(res)
    import json
    rec = json.loads(record.read_text())
    assert rec["argv"] == ["enroll", "--token-stdin"]                       # nothing secret in argv
    assert rec["stdin"].strip() == TOKEN
    assert rec["cmdline_leaks"] == []                                       # no process on the box had it in its argv
    assert rec["env_has_token"] is False                                    # not even in the child's environment
    assert rec["env_server"] == SERVER and rec["env_state"] == str(root / "var/lib/paddock-agent")
    assert TOKEN.encode() not in res.stdout + res.stderr
    assert b"Sup3rS3cret" not in tree_text(root)
    assert b"Sup3rS3cret" not in (res.stdout + res.stderr)


def test_a_malformed_token_is_rejected_without_being_shown(tmp_path):
    res, root, record = token_install(tmp_path, stdin=b"not-a-token-Sup3rS3cret\n")
    assert res.returncode != 0 and "does not look like" in out(res)
    assert "Sup3rS3cret" not in out(res) and not record.exists()


def test_no_token_at_all_is_an_error(tmp_path):
    res, root, record = token_install(tmp_path, stdin=b"")
    assert res.returncode != 0 and "no enrollment token" in out(res) and not record.exists()


def test_a_failed_enrollment_fails_the_install_and_does_not_start_anything(tmp_path):
    res, root, record = token_install(tmp_path, stdin=(TOKEN + "\n").encode(), rc=5)
    assert res.returncode != 0 and "enrollment failed" in out(res)
    assert TOKEN.encode() not in res.stdout + res.stderr and b"Sup3rS3cret" not in tree_text(root)


def test_an_already_enrolled_host_keeps_its_credentials_and_needs_no_token(tmp_path):
    mirror, _ = make_mirror(tmp_path, FAKE_AGENT.encode())
    root = tmp_path / "root"
    (root / "var/lib/paddock-agent").mkdir(parents=True)
    (root / "var/lib/paddock-agent/credentials.json").write_text("{}")
    res, _ = staged(tmp_path, mirror, env=clean_env(tool_path(tmp_path), FAKE_AGENT_RECORD=str(tmp_path / "r")),
                    stdin=b"")
    assert res.returncode == 0 and "already enrolled" in out(res) and not (tmp_path / "r").exists()


def test_reenroll_passes_force_and_hostname(tmp_path):
    res, root, record = token_install(tmp_path, stdin=(TOKEN + "\n").encode(),
                                      extra=("--reenroll", "--hostname", "web-1.internal"))
    assert res.returncode == 0, out(res)
    import json
    assert json.loads(record.read_text())["argv"] == ["enroll", "--token-stdin", "--force", "--hostname",
                                                      "web-1.internal"]


def test_a_piped_installer_cannot_also_read_the_token_from_stdin(tmp_path):
    mirror, _ = make_mirror(tmp_path, FAKE_AGENT.encode())
    root = tmp_path / "root"
    with open(SCRIPT, "rb") as script:
        res = subprocess.run(["sh", "-s", "--", "--server", SERVER, "--root", str(root), "--base-url",
                              "file://" + str(mirror), "--python", sys.executable],
                             stdin=script, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             env=clean_env(tool_path(tmp_path)), timeout=60)
    assert res.returncode != 0 and "piped into sh" in out(res)


# ---------------------------------------------------------------- uninstall
def test_uninstall_removes_the_program_but_keeps_the_key_unless_purged(tmp_path, real_pyz):
    mirror, _ = make_mirror(tmp_path, real_pyz.read_bytes())
    res, root = staged(tmp_path, mirror, "--no-enroll")
    assert res.returncode == 0, out(res)
    (root / "var/lib/paddock-agent/keys").mkdir()
    (root / "var/lib/paddock-agent/keys/ed25519.key").write_text("seed")
    base = ["--root", str(root), "--uninstall"]
    res = run(base, env=clean_env(tool_path(tmp_path)), stdin=b"")
    assert res.returncode == 0, out(res)
    assert not (root / "usr/local/lib/paddock-agent").exists()
    assert not (root / "etc/systemd/system/paddock-agent.service").exists()
    assert not os.path.lexists(str(root / "usr/local/bin/paddock"))
    assert (root / "var/lib/paddock-agent/keys/ed25519.key").exists()          # the key survives
    assert "revoke it in Paddock" in out(res)
    # a purge without a terminal and without --yes refuses, and removes nothing
    res = run(base + ["--purge"], env=clean_env(tool_path(tmp_path)), stdin=b"")
    assert res.returncode != 0 and "--yes" in out(res)
    assert (root / "var/lib/paddock-agent/keys/ed25519.key").exists()
    res = run(base + ["--purge", "--yes"], env=clean_env(tool_path(tmp_path)), stdin=b"")
    assert res.returncode == 0
    assert not (root / "var/lib/paddock-agent").exists() and not (root / "etc/paddock-agent").exists()


def test_uninstall_dry_run_touches_nothing(tmp_path):
    root = tmp_path / "root"
    (root / "var/lib/paddock-agent").mkdir(parents=True)
    res = run(["--root", str(root), "--uninstall", "--purge", "--dry-run"], env=clean_env(tool_path(tmp_path)),
              stdin=b"")
    assert res.returncode == 0 and "PURGE" in out(res)
    assert (root / "var/lib/paddock-agent").exists()
