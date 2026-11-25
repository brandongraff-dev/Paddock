"""Round-3 regression test for the installer (finding K2-1: SIGQUIT at the hidden token prompt).

Python 3.8 compatible. Same pty harness as test_installer_p2x_r2.py.
"""
import os
import shutil
import signal
import sys
import time

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from test_install_agent_sh import (  # noqa: E402
    FAKE_AGENT, SCRIPT, SERVER, clean_env, make_mirror, system_tool, tool_path,
)
from test_installer_p2x_r2 import _echo_on, _read_until, _wait_exit  # noqa: E402

pty = pytest.importorskip("pty")
termios = pytest.importorskip("termios")

SHELLS = [s for s in ("sh", "dash", "bash") if shutil.which(s)]


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("how", ["ctrl-backslash", "sighup", "sigquit"])
def test_k2_1_quit_or_hangup_at_the_hidden_token_prompt_restores_terminal_echo(tmp_path, shell, how):
    """K2-1: ^\\ (SIGQUIT) at 'Enrollment token (input hidden):' killed an sh/dash installer (status 3) with the
    pty's ECHO flag still off, because only EXIT, INT and TERM were trapped. HUP is the same class."""
    mirror, _ = make_mirror(tmp_path, FAKE_AGENT.encode())
    path = tool_path(tmp_path)
    pid, fd = pty.fork()
    if pid == 0:
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
        assert not _echo_on(fd)
        if how == "ctrl-backslash":
            os.write(fd, b"\x1c")                             # the line discipline raises SIGQUIT
        elif how == "sigquit":
            os.kill(pid, signal.SIGQUIT)
        else:
            os.kill(pid, signal.SIGHUP)
        status = _wait_exit(pid)
        assert _echo_on(fd), "the terminal was left with echo off (status %r)" % (status,)
        assert not (os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0), status
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
