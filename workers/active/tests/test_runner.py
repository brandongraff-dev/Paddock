"""Subprocess runner: timeout, missing binary, banned args."""
from __future__ import annotations

import pytest

from app.util import runner
from tests.conftest import FakeProcess


pytestmark = pytest.mark.asyncio


async def test_missing_binary_raises(fake_subprocess):
    # No factory registered -> resolve_binary returns None.
    with pytest.raises(runner.ToolUnavailable):
        await runner.run("naabu", ["-h"], timeout=1.0)


async def test_run_captures_stdout(fake_subprocess):
    fake_subprocess.register("naabu", lambda args: FakeProcess(stdout_bytes=b'{"port": 22}\n'))
    r = await runner.run("naabu", ["-host", "1.2.3.4"], timeout=5.0)
    assert r.returncode == 0
    assert r.lines == ['{"port": 22}']


async def test_banned_arg_refused(fake_subprocess):
    fake_subprocess.register("naabu", lambda args: FakeProcess())
    with pytest.raises(ValueError):
        await runner.run("naabu", ["-host", "x", "--stealth"], timeout=1.0)


async def test_timeout_terminates(fake_subprocess):
    fake_subprocess.register("naabu", lambda args: FakeProcess(raise_timeout=True))
    with pytest.raises(runner.ToolTimeout):
        await runner.run("naabu", ["-host", "x"], timeout=0.2)


async def test_nonzero_exit_raises_toolfailed(fake_subprocess):
    fake_subprocess.register("naabu",
                             lambda args: FakeProcess(stderr_bytes=b"boom", returncode=2))
    with pytest.raises(runner.ToolFailed):
        await runner.run("naabu", ["-host", "x"], timeout=5.0)
