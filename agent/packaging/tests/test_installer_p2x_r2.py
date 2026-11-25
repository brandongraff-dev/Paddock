"""Round-2 regression tests for the installer (findings K-8, K-9: token prompt and token scrub).

Python 3.8 compatible. Exercised like test_installer_p2x.py: a ``file://`` mirror and ``--root`` staging.
"""
import os
import re
import select
import shutil
import signal
import sys
import time

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from test_install_agent_sh import (  # noqa: E402
    FAKE_AGENT, SCRIPT, SERVER, TOKEN, clean_env, make_mirror, out, run, system_tool, tool_path,
)

pty = pytest.importorskip("pty")
termios = pytest.importorskip("termios")

SHELLS = [s for s in ("sh", "dash", "bash") if shutil.which(s)]


def _read_until(fd, needle, timeout=15.0):
    buf = b""
    end = time.time() + timeout
    while time.time() < end and needle not in buf:
        if select.select([fd], [], [], 0.2)[0]:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
    return buf


def _echo_on(fd):
    return bool(termios.tcgetattr(fd)[3] & termios.ECHO)


def _wait_exit(pid, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        done, status = os.waitpid(pid, os.WNOHANG)
        if done:
            return status
        time.sleep(0.05)
    os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)
    raise AssertionError("the installer did not exit")


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("how", ["ctrl-c", "sigterm"])
def test_k8_an_interrupted_hidden_token_prompt_restores_terminal_echo(tmp_path, shell, how):
    """K-8: on a pty, ^C at 'Enrollment token (input hidden):' left the terminal with echo OFF (the traps were
    installed only after the token had been read)."""
    mirror, _ = make_mirror(tmp_path, FAKE_AGENT.encode())
    path = tool_path(tmp_path)
    pid, fd = pty.fork()
    if pid == 0:                                              # child: becomes the installer on the pty
        try:
            os.execve(system_tool(shell) or shell,
                      [shell, SCRIPT, "--server", SERVER, "--root", str(tmp_path / "root"), "--base-url",
                       "file://" + str(mirror), "--python", sys.executable],
                      clean_env(path))
        finally:
            os._exit(127)
    try:
        seen = _read_until(fd, b"input hidden")
        assert b"input hidden" in seen, seen
        time.sleep(0.2)
        assert not _echo_on(fd)                               # the prompt really turned echo off
        if how == "ctrl-c":
            os.write(fd, b"\x03")                             # the line discipline raises SIGINT
        else:
            os.kill(pid, signal.SIGTERM)
        status = _wait_exit(pid)
        assert _echo_on(fd), "the terminal was left with echo off"
        assert not (os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0), status        # it did not carry on
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def test_k8_a_token_typed_at_the_prompt_still_works_and_restores_echo(tmp_path):
    mirror, _ = make_mirror(tmp_path, FAKE_AGENT.encode())
    path = tool_path(tmp_path)
    record = tmp_path / "record.json"
    pid, fd = pty.fork()
    if pid == 0:
        try:
            env = clean_env(path, FAKE_AGENT_RECORD=str(record), FAKE_AGENT_RC="0")
            os.execve(system_tool("sh") or "sh",
                      ["sh", SCRIPT, "--server", SERVER, "--root", str(tmp_path / "root"), "--base-url",
                       "file://" + str(mirror), "--python", sys.executable], env)
        finally:
            os._exit(127)
    try:
        assert b"input hidden" in _read_until(fd, b"input hidden")
        time.sleep(0.2)
        os.write(fd, TOKEN.encode() + b"\n")
        rest = _read_until(fd, b"\x00", timeout=8.0)             # drain until the installer exits
        status = _wait_exit(pid, 20.0)
        assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, (status, rest)
        assert TOKEN.encode() not in rest                        # never echoed
        assert _echo_on(fd)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def test_k9_an_exported_ENV_TOKEN_does_not_keep_the_token_exported(tmp_path):
    """K-9: ENV_TOKEN=x in the caller's environment stayed exported, so the installer's own assignment of the
    token to it put the token in the environment of every child."""
    mirror, _ = make_mirror(tmp_path, FAKE_AGENT.encode())
    path = tool_path(tmp_path)
    log = tmp_path / "children-env.log"
    for t in ("sha256sum", "cp", "mkdir", "awk", "chmod", "mv", "mktemp", "head"):
        dst = os.path.join(path, t)
        if os.path.lexists(dst):
            os.unlink(dst)
        with open(dst, "w") as fh:
            fh.write("#!/bin/sh\nenv >> %s\nexec %s \"$@\"\n" % (log, system_tool(t)))
        os.chmod(dst, 0o755)
    pyw = tmp_path / "python-wrapper"
    pyw.write_text("#!/bin/sh\nenv >> %s\nexec %s \"$@\"\n" % (log, sys.executable))
    os.chmod(str(pyw), 0o755)
    record = tmp_path / "record.json"
    env = clean_env(path, PADDOCK_ENROLL_TOKEN=TOKEN, ENV_TOKEN="decoy", TOKEN="decoy2",
                    FAKE_AGENT_RECORD=str(record), FAKE_AGENT_RC="0")
    res = run(["--server", SERVER, "--root", str(tmp_path / "root"), "--base-url", "file://" + str(mirror),
               "--python", str(pyw)], env=env, stdin=b"")
    assert res.returncode == 0, out(res)
    seen = log.read_text()
    assert seen.count("PATH=") >= 8                                          # the wrappers really ran
    assert "Sup3rS3cret" not in seen
    for name in ("ENV_TOKEN", "TOKEN", "PADDOCK_ENROLL_TOKEN"):
        assert not re.search(r"^%s=" % name, seen, re.M), name                   # not even the caller's decoy
