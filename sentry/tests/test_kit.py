"""The plug-in kit: installer, cloud-init renderer, bundle, unit files, pi-gen stage.

The installer is run for real (bash) against a throw-away root directory and the
fake Paddock server from test_enrollment, so the enroll step exercises the actual
CLI end to end. Nothing here touches the host's /etc or systemd."""
from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
import tarfile
from pathlib import Path

import pytest

from .test_enrollment import CRED, GOOD_TOKEN, FakePaddock

KIT = Path(__file__).resolve().parents[2] / "deploy" / "sentry-kit"
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(BASH is None or shutil.which("python3") is None, reason="needs bash + python3")


@pytest.fixture
def paddock():
    s = FakePaddock()
    yield s
    s.close()


def _install(tmp_path: Path, env_text: str | None, extra_env: dict | None = None, args: list[str] | None = None):
    root = tmp_path / "root"
    boot = root / "boot" / "firmware"
    boot.mkdir(parents=True, exist_ok=True)
    (root / "etc" / "NetworkManager").mkdir(parents=True, exist_ok=True)
    if env_text is not None:
        (boot / "paddock-sentry.env").write_text(env_text)
    env = {**os.environ, "PADDOCK_ROOT": str(root), "PADDOCK_SKIP_APT": "1", "PADDOCK_SKIP_SYSTEMD": "1",
           "PADDOCK_SKIP_USER": "1", **(extra_env or {})}
    p = subprocess.run([BASH, str(KIT / "install.sh"), *(args or [])], env=env, capture_output=True, text=True,
                       timeout=60)
    return p, root, boot


def _envfile(server: str, token: str = GOOD_TOKEN, extra: str = "") -> str:
    return f"# first boot\nPADDOCK_SERVER={server}\nPADDOCK_ENROLL_TOKEN={token}\nPADDOCK_SENTRY_IFACE=eth1\n{extra}"


def test_installer_enrolls_for_real_and_leaves_no_token_behind(paddock, tmp_path):
    p, root, boot = _install(tmp_path, _envfile(paddock.url, extra="PADDOCK_SENTRY_NAME=lobby-1\n"))
    assert p.returncode == 0, p.stdout + p.stderr
    cred = root / "var/lib/paddock-sentry/credentials.json"
    assert cred.is_file() and stat.S_IMODE(cred.stat().st_mode) == 0o600
    assert CRED in cred.read_text() and CRED not in p.stdout + p.stderr
    assert paddock.enroll_body["name"] == "lobby-1"
    env_after = (boot / "paddock-sentry.env").read_text()
    assert GOOD_TOKEN not in env_after and "<used" in env_after       # the spent token is scrubbed from the SD card
    assert (boot / "paddock-sentry.status").read_text().split()[1] == "OK:"
    conf = (root / "etc/paddock-sentry/sentry.env").read_text()
    assert "PADDOCK_SENTRY_IFACE=eth1" in conf and f"PADDOCK_SERVER={paddock.url}" in conf
    assert "interface-name:eth1" in (root / "etc/NetworkManager/conf.d/90-paddock-sentry.conf").read_text()
    assert os.access(root / "usr/local/bin/paddock-sentry", os.X_OK)
    assert (root / "usr/local/lib/paddock-sentry/prepare-iface").exists()
    assert (root / "opt/paddock-sentry/lib/paddock_sentry/cli.py").exists()
    assert not list((root / "opt/paddock-sentry/lib").rglob("__pycache__"))
    assert (root / "var/lib/paddock-sentry/.installed").exists()


def test_installer_is_idempotent_and_keeps_the_credential(paddock, tmp_path):
    p, root, boot = _install(tmp_path, _envfile(paddock.url))
    assert p.returncode == 0
    first = (root / "var/lib/paddock-sentry/credentials.json").read_text()
    # second run: the token line is spent, the credential must be kept and no new enrollment made
    p2 = subprocess.run([BASH, str(KIT / "install.sh")], capture_output=True, text=True, timeout=60,
                        env={**os.environ, "PADDOCK_ROOT": str(root), "PADDOCK_SKIP_APT": "1",
                             "PADDOCK_SKIP_SYSTEMD": "1", "PADDOCK_SKIP_USER": "1"})
    assert p2.returncode == 0, p2.stdout + p2.stderr
    assert (root / "var/lib/paddock-sentry/credentials.json").read_text() == first
    assert paddock.requests.count("/enroll") == 1


def test_a_spent_or_wrong_token_fails_with_advice_on_the_card(paddock, tmp_path):
    p, root, boot = _install(tmp_path, _envfile(paddock.url, token="pet_deadbeef_" + "x" * 30))
    assert p.returncode != 0
    status = (boot / "paddock-sentry.status").read_text()
    assert "FAILED" in status and "Sensors > Add sensor" in status
    assert not (root / "var/lib/paddock-sentry/credentials.json").exists()
    assert not (root / "var/lib/paddock-sentry/.installed").exists()   # so the first-boot unit retries


@pytest.mark.parametrize("bad", [
    "PADDOCK_SERVER=$(touch {pwn})\nPADDOCK_ENROLL_TOKEN=" + GOOD_TOKEN + "\n",
    "PADDOCK_SERVER=ftp://x\nPADDOCK_ENROLL_TOKEN=" + GOOD_TOKEN + "\n",
    "PADDOCK_SERVER=https://ok.example\nPADDOCK_ENROLL_TOKEN=pet_zz;touch {pwn}\n",
    "PADDOCK_SERVER=https://ok.example\nPADDOCK_ENROLL_TOKEN=" + GOOD_TOKEN + "\nPADDOCK_SENTRY_NAME=a;touch {pwn}\n",
    "PADDOCK_SERVER=https://ok.example\nPADDOCK_ENROLL_TOKEN=" + GOOD_TOKEN + "\nPADDOCK_SENTRY_IFACE=eth1;touch {pwn}\n",
    "PADDOCK_ENROLL_TOKEN=" + GOOD_TOKEN + "\n",
])
def test_the_env_file_is_data_never_code(tmp_path, bad):
    pwn = tmp_path / "pwned"
    p, root, boot = _install(tmp_path, bad.format(pwn=pwn))
    assert p.returncode != 0 and not pwn.exists()
    assert "FAILED" in (boot / "paddock-sentry.status").read_text()


def test_missing_env_file_is_explained(tmp_path):
    p, *_ = _install(tmp_path, None)
    assert p.returncode != 0 and "paddock-sentry.env" in p.stdout + p.stderr


def test_quoted_values_and_crlf_from_windows_editors_are_handled(paddock, tmp_path):
    text = f'PADDOCK_SERVER="{paddock.url}"\r\nPADDOCK_ENROLL_TOKEN={GOOD_TOKEN}\r\nPADDOCK_SENTRY_IFACE=eth1\r\n'
    p, root, _ = _install(tmp_path, text)
    assert p.returncode == 0, p.stdout + p.stderr


def test_render_user_data_fills_every_placeholder_and_validates(tmp_path):
    script = KIT / "cloud-init" / "render-user-data.sh"
    args = ["--server", "https://paddock.example.com:8101", "--token", GOOD_TOKEN,
            "--bundle-url", "https://files.example.com/kit.tar.gz", "--bundle-sha256", "a" * 64, "--name", "lobby"]
    ok = subprocess.run([BASH, str(script), *args], capture_output=True, text=True)
    assert ok.returncode == 0, ok.stderr
    assert "@" not in ok.stdout.replace("user@", "") or "@PADDOCK" not in ok.stdout
    assert ok.stdout.startswith("#cloud-config") and GOOD_TOKEN in ok.stdout and "a" * 64 in ok.stdout
    assert 'permissions: "0600"' in ok.stdout          # the token file is not world-readable
    for bad in (["--server", "http://insecure.example"], ["--token", "nope"],
                ["--bundle-url", "http://x"], ["--bundle-sha256", "short"], ["--name", "a b;c"]):
        swapped = list(args)
        i = swapped.index(bad[0])
        swapped[i + 1] = bad[1]
        r = subprocess.run([BASH, str(script), *swapped], capture_output=True, text=True)
        assert r.returncode == 2, bad


def test_bundle_is_reproducible_and_self_contained(tmp_path):
    outs = []
    for n in (1, 2):
        out = tmp_path / f"out{n}"
        r = subprocess.run([BASH, str(KIT / "make-bundle.sh"), str(out)], capture_output=True, text=True, timeout=60)
        assert r.returncode == 0, r.stderr
        (tb,) = out.glob("*.tar.gz")
        outs.append(tb)
        sha = [ln.split()[1] for ln in r.stdout.splitlines() if ln.startswith("sha256:")][0]
        assert sha == hashlib.sha256(tb.read_bytes()).hexdigest()
    assert outs[0].read_bytes() == outs[1].read_bytes()
    with tarfile.open(outs[0]) as tf:
        names = tf.getnames()
        assert any(n.endswith("/install.sh") for n in names) and any(n.endswith("paddock_sentry/cli.py") for n in names)
        assert not any("__pycache__" in n or "/tests/" in n for n in names)
        assert all(m.uid == 0 and m.gid == 0 for m in tf.getmembers())


def test_bundle_installs_from_its_own_directory(paddock, tmp_path):
    r = subprocess.run([BASH, str(KIT / "make-bundle.sh"), str(tmp_path / "out")], capture_output=True, text=True)
    assert r.returncode == 0
    (tb,) = (tmp_path / "out").glob("*.tar.gz")
    ex = tmp_path / "ex"
    ex.mkdir()
    with tarfile.open(tb) as tf:
        tf.extractall(ex)  # noqa: S202 - our own bundle
    kit = next(ex.iterdir())
    root = tmp_path / "root"
    (root / "boot/firmware").mkdir(parents=True)
    (root / "boot/firmware/paddock-sentry.env").write_text(_envfile(paddock.url))
    env = {**os.environ, "PADDOCK_ROOT": str(root), "PADDOCK_SKIP_APT": "1", "PADDOCK_SKIP_SYSTEMD": "1",
           "PADDOCK_SKIP_USER": "1"}
    p = subprocess.run([BASH, str(kit / "install.sh")], env=env, capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stdout + p.stderr


def test_units_are_least_privilege_and_consistent():
    svc = (KIT / "paddock-sentry.service").read_text()
    assert "DynamicUser" not in svc and "User=paddock-sentry" in svc
    assert "ConditionPathExists=/var/lib/paddock-sentry/credentials.json" in svc
    assert "ExecStartPre=+/usr/local/lib/paddock-sentry/prepare-iface" in svc
    assert "CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN" in svc and "NoNewPrivileges=yes" in svc
    assert "PADDOCK_SENTRY_TOKEN" not in svc
    legacy = (KIT.parents[1] / "sentry" / "deploy" / "paddock-sentry.service").read_text()
    assert "PADDOCK_SENTRY_TOKEN" in legacy  # the manual / shared-token unit is unchanged for existing installs
    fb = (KIT / "paddock-sentry-firstboot.service").read_text()
    assert "install.sh --firstboot" in fb and "ConditionPathExists=!/var/lib/paddock-sentry/.installed" in fb


def test_prepare_iface_rejects_odd_names_and_never_sends():
    r = subprocess.run(["sh", str(KIT / "prepare-iface.sh"), "eth0;reboot"], capture_output=True, text=True)
    assert r.returncode == 2
    text = (KIT / "prepare-iface.sh").read_text()
    assert "disable_ipv6=1" in text and "promisc on" in text and "arp off" in text


def test_pi_gen_stage_follows_the_documented_layout():
    stage = KIT / "pi-gen" / "stage-paddock"
    assert (stage / "EXPORT_IMAGE").exists() and (stage / "prerun.sh").read_text().startswith("#!/bin/bash -e")
    assert "tcpdump" in (stage / "00-packages" / "00-packages").read_text()
    run = (stage / "01-sentry" / "01-run.sh").read_text()
    assert "${ROOTFS_DIR}" in run and "on_chroot" in run and "paddock-sentry-firstboot.service" in run
    assert os.access(stage / "01-sentry" / "01-run.sh", os.X_OK) and os.access(stage / "prerun.sh", os.X_OK)
    cfg = (KIT / "pi-gen" / "config.example").read_text()
    assert 'STAGE_LIST="stage0 stage1 stage2 stage-paddock"' in cfg and "PUBKEY_ONLY_SSH=1" in cfg
    assert "@SSH_PUBLIC_KEY@" in cfg


def test_pi_gen_build_script_refuses_without_a_key_or_with_a_hostile_one(tmp_path):
    env = {k: v for k, v in os.environ.items() if k != "SSH_PUBLIC_KEY"}
    r = subprocess.run([BASH, str(KIT / "pi-gen" / "build.sh")], env={**env, "WORK_DIR": str(tmp_path / "w")},
                       capture_output=True, text=True)
    assert r.returncode != 0 and "SSH_PUBLIC_KEY" in r.stderr
    r = subprocess.run([BASH, str(KIT / "pi-gen" / "build.sh")],
                       env={**env, "SSH_PUBLIC_KEY": 'ssh-ed25519 AAAA"; rm -rf /', "WORK_DIR": str(tmp_path / "w")},
                       capture_output=True, text=True)
    assert r.returncode == 2 and not (tmp_path / "w").exists()


@pytest.mark.parametrize("script", [
    "install.sh", "prepare-iface.sh", "make-bundle.sh", "cloud-init/render-user-data.sh", "pi-gen/build.sh",
    "pi-gen/stage-paddock/prerun.sh", "pi-gen/stage-paddock/01-sentry/01-run.sh"])
def test_scripts_parse(script):
    assert subprocess.run([BASH, "-n", str(KIT / script)], capture_output=True).returncode == 0
    sc = shutil.which("shellcheck")
    if sc:
        r = subprocess.run([sc, "-S", "warning", "-e", "SC2086,SC2154", str(KIT / script)], capture_output=True, text=True)
        assert r.returncode == 0, r.stdout
