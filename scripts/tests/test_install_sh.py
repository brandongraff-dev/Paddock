"""scripts/install.sh: shellcheck, dry-run, and a full run against a fake Docker.

Run from the repo root:  pytest -q scripts/tests/test_install_sh.py
"""
from __future__ import annotations

import hashlib
import http.server
import shutil
import stat
import subprocess
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "install.sh"

FAKE_DOCKER = r"""#!/bin/sh
# records every call; behaviour switches via FAKE_DOCKER_MODE
echo "$@" >> "$FAKE_DOCKER_LOG"
case "$FAKE_DOCKER_MODE" in
  no-compose) [ "$1 $2" = "compose version" ] && exit 1 ;;
  no-daemon)  [ "$1" = "info" ] && { echo "permission denied" >&2; exit 1; } ;;
esac
case "$1" in
  version) echo "26.1.0" ;;
  volume)  [ -n "${FAKE_DOCKER_VOLUME:-}" ] && echo "$FAKE_DOCKER_VOLUME" ;;
esac
exit 0
"""


@pytest.fixture
def sandbox(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    d = bindir / "docker"
    d.write_text(FAKE_DOCKER)
    d.chmod(d.stat().st_mode | stat.S_IEXEC)
    src = tmp_path / "src"
    (src / "schema").mkdir(parents=True)
    (src / "docker-compose.lite.yml").write_text("name: paddock-lite\nservices: {}\n")
    shutil.copy(ROOT / ".env.example", src / ".env.example")
    (src / "schema" / "001.sql").write_text("-- x\n")
    return {"bin": bindir, "src": src, "home": tmp_path / "home", "log": tmp_path / "docker.log", "tmp": tmp_path}


class _Health(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):  # noqa: D401
        pass


@pytest.fixture
def health():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Health)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _path_without_docker(sb) -> str:
    """A PATH with the system tools but no docker at all. Using /usr/bin:/bin
    directly isn't enough: on CI runners (and most dev machines) the real
    docker lives in /usr/bin."""
    d = sb["home"].parent / "nodocker-bin"
    if not d.exists():
        d.mkdir()
        for sysdir in ("/usr/bin", "/bin"):
            for f in Path(sysdir).iterdir():
                link = d / f.name
                if f.name.startswith("docker") or link.exists():
                    continue
                try:
                    link.symlink_to(f)
                except OSError:
                    pass
    return str(d)


def run(sb, *args, mode="", volume="", health_url=None, extra_env=None, path_extra=True):
    env = {
        "PATH": f"{sb['bin']}:/usr/bin:/bin" if path_extra else _path_without_docker(sb),
        "HOME": str(sb["home"]),
        "FAKE_DOCKER_LOG": str(sb["log"]),
        "FAKE_DOCKER_MODE": mode,
        "FAKE_DOCKER_VOLUME": volume,
        "PADDOCK_SRC_DIR": str(sb["src"]),
    }
    if health_url:
        env["PADDOCK_API_URL"] = health_url
        env["PADDOCK_UI_URL"] = health_url
    env.update(extra_env or {})
    return subprocess.run(["sh", str(SCRIPT), *args], env=env, capture_output=True, text=True, timeout=60,
                          stdin=subprocess.DEVNULL, start_new_session=True)


def env_file(sb) -> dict[str, str]:
    out = {}
    for line in (sb["home"] / "paddock" / ".env").read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            out[k] = v
    return out


def calls(sb) -> list[str]:
    return sb["log"].read_text().splitlines() if sb["log"].exists() else []


# --------------------------------------------------------------------------- #

def test_shell_syntax_and_shellcheck():
    assert subprocess.run(["sh", "-n", str(SCRIPT)]).returncode == 0
    sc = shutil.which("shellcheck")
    if not sc:
        pytest.skip("shellcheck not installed")
    r = subprocess.run([sc, "-s", "sh", str(SCRIPT)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout


def test_help_and_bad_args(sandbox):
    r = run(sandbox, "--help")
    assert r.returncode == 0 and "--uninstall" in r.stdout and "--dry-run" in r.stdout
    for bad in (["--nope"], ["--dir"], ["--wait", "x"], ["--repo", "noslash"], ["--ref", "a;b"], ["--purge"]):
        r = run(sandbox, *bad)
        assert r.returncode != 0, bad


def test_dry_run_changes_nothing_and_needs_no_docker(sandbox):
    r = run(sandbox, "--dry-run", "--active", path_extra=False)          # no docker on PATH at all
    assert r.returncode == 0, r.stderr
    assert "[dry-run]" in r.stdout and "--profile active" in r.stdout and "JWT_SECRET" in r.stdout
    assert not (sandbox["home"] / "paddock").exists() and not sandbox["log"].exists()
    r = run(sandbox, "--dry-run", "--uninstall", "--purge", "--dir", str(sandbox["tmp"] / "x"))
    assert r.returncode == 0 and "down -v" in r.stdout


def test_full_install_secrets_start_health_and_output(sandbox, health):
    r = run(sandbox, health_url=health, extra_env={"PADDOCK_SRC_DIR": str(sandbox["src"])})
    assert r.returncode == 0, r.stdout + r.stderr
    e = env_file(sandbox)
    for k in ("POSTGRES_PASSWORD", "PADDOCK_APP_DB_PASSWORD", "ADMIN_BOOTSTRAP_PASSWORD"):
        assert len(e[k]) == 24 and e[k].isalnum() and not e[k].startswith("change-me"), k
    for k in ("SERVICE_API_KEY", "JWT_SECRET", "PADDOCK_SECRET_KEY", "AUDIT_HMAC_KEY"):
        assert len(e[k]) >= 40 and "/" not in e[k] and "+" not in e[k], k
    assert len({e[k] for k in ("POSTGRES_PASSWORD", "ADMIN_BOOTSTRAP_PASSWORD", "JWT_SECRET", "PADDOCK_SECRET_KEY")}) == 4
    import base64
    assert len(base64.urlsafe_b64decode(e["PADDOCK_SECRET_KEY"])) == 32        # valid Fernet-style key
    envp = sandbox["home"] / "paddock" / ".env"
    assert stat.S_IMODE(envp.stat().st_mode) == 0o600
    assert (sandbox["home"] / "paddock" / "docker-compose.install.yml").read_text().count("${") == 3
    up = [c for c in calls(sandbox) if " up " in f" {c} "]
    assert len(up) == 1 and "-p paddock-lite" in up[0] and "-d --build" in up[0] and "--profile" not in up[0]
    assert "docker-compose.install.yml" in up[0]
    assert "Username:  admin" in r.stdout and f"Password:  {e['ADMIN_BOOTSTRAP_PASSWORD']}" in r.stdout
    assert "http://localhost:3000" in r.stdout or health in r.stdout
    for k in ("JWT_SECRET", "PADDOCK_SECRET_KEY", "AUDIT_HMAC_KEY", "SERVICE_API_KEY", "POSTGRES_PASSWORD"):
        assert e[k] not in r.stdout + r.stderr                                      # only the admin password is printed


def test_rerun_is_idempotent_and_keeps_secrets(sandbox, health):
    assert run(sandbox, health_url=health).returncode == 0
    envp = sandbox["home"] / "paddock" / ".env"
    before = hashlib.sha256(envp.read_bytes()).hexdigest()
    r = run(sandbox, health_url=health)
    assert r.returncode == 0 and "kept existing POSTGRES_PASSWORD" in r.stdout and "sources already present" in r.stdout
    assert hashlib.sha256(envp.read_bytes()).hexdigest() == before
    assert len([c for c in calls(sandbox) if " up " in f" {c} "]) == 2          # compose up is itself idempotent


def test_user_values_are_never_overwritten(sandbox, health):
    d = sandbox["home"] / "paddock"
    d.mkdir(parents=True)
    (d / ".env").write_text("POSTGRES_PASSWORD=my-own-pw\nADMIN_BOOTSTRAP_PASSWORD=\nCUSTOM=1\n")
    assert run(sandbox, health_url=health).returncode == 0
    e = env_file(sandbox)
    assert e["POSTGRES_PASSWORD"] == "my-own-pw" and e["CUSTOM"] == "1"
    assert len(e["ADMIN_BOOTSTRAP_PASSWORD"]) == 24                              # empty value was filled


def test_active_and_no_start_and_upgrade(sandbox, health):
    r = run(sandbox, "--no-start")
    assert r.returncode == 0 and not [c for c in calls(sandbox) if " up " in f" {c} "]
    assert run(sandbox, "--active", "--upgrade", health_url=health).returncode == 0
    assert any("--profile active" in c and " up " in f" {c} " for c in calls(sandbox))


def test_prerequisite_failures_are_clear(sandbox):
    r = run(sandbox, mode="no-compose")
    assert r.returncode != 0 and "compose" in r.stderr and not (sandbox["home"] / "paddock" / ".env").exists()
    r = run(sandbox, mode="no-daemon")
    assert r.returncode != 0 and "Docker daemon" in r.stderr
    r = run(sandbox, path_extra=False)
    assert r.returncode != 0 and "Docker is not installed" in r.stderr


def test_refuses_orphaned_database_volume(sandbox):
    r = run(sandbox, volume="paddock-lite_pg_data")
    assert r.returncode != 0 and "passwords are unknown" in r.stderr
    assert not (sandbox["home"] / "paddock" / ".env").exists()


def test_unhealthy_exits_nonzero_but_prints_credentials_hint(sandbox):
    r = run(sandbox, "--wait", "3", health_url="http://127.0.0.1:9")
    assert r.returncode == 1 and "not healthy" in r.stderr
    assert "Password:" in r.stdout


def test_uninstall_keeps_data_purge_removes(sandbox, health):
    assert run(sandbox, health_url=health).returncode == 0
    d = sandbox["home"] / "paddock"
    r = run(sandbox, "--uninstall")
    assert r.returncode == 0 and d.exists() and (d / ".env").exists()
    down = [c for c in calls(sandbox) if " down" in f" {c}"]
    assert down and "-v" not in down[-1].split()
    r = run(sandbox, "--uninstall", "--purge")                                   # no tty, no --yes -> refuses
    assert r.returncode != 0 and "--yes" in r.stderr and d.exists()
    r = run(sandbox, "--uninstall", "--purge", "--yes")
    assert r.returncode == 0 and not d.exists()
    assert "-v" in [c for c in calls(sandbox) if " down" in f" {c}"][-1].split()
    r = run(sandbox, "--uninstall")
    assert r.returncode != 0 and "does not look like a Paddock install" in r.stderr


def test_purge_never_deletes_home_or_root(sandbox):
    sandbox["home"].mkdir()
    (sandbox["home"] / "docker-compose.lite.yml").write_text("services: {}\n")
    r = run(sandbox, "--uninstall", "--purge", "--yes", "--dir", str(sandbox["home"]))
    assert r.returncode != 0 and "refusing" in r.stderr and sandbox["home"].exists()


def test_download_path_is_pinned_to_https_codeload(sandbox):
    # no PADDOCK_SRC_DIR: the dry run must name the exact URL it would fetch
    r = run(sandbox, "--dry-run", "--ref", "v1.2.3", "--repo", "acme/paddock",
            extra_env={"PADDOCK_SRC_DIR": ""})
    assert "https://codeload.github.com/acme/paddock/tar.gz/v1.2.3" in r.stdout
