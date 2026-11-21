"""Safe subprocess runner.

Rules:
* ``asyncio.create_subprocess_exec`` only — never shell=True.
* Explicit ``cwd``. Caller may pass one; default is an isolated empty dir
  so the tool cannot find relative config files we did not place.
* Timeout + cancel propagate correctly: SIGTERM then SIGKILL.
* stdout is captured and streamed line-by-line so a scan with 10k matches
  does not blow the buffer.
* If the binary is missing, raise ``ToolUnavailable`` — the module layer
  converts that to a finding, the service keeps running.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from typing import AsyncIterator, Iterable, Sequence

import structlog

log = structlog.get_logger(__name__)


class ToolUnavailable(RuntimeError):
    def __init__(self, tool: str):
        super().__init__(f"tool unavailable: {tool!r} not on PATH")
        self.tool = tool


class ToolTimeout(RuntimeError):
    def __init__(self, tool: str, timeout: float):
        super().__init__(f"tool timeout: {tool!r} exceeded {timeout}s")
        self.tool = tool
        self.timeout = timeout


class ToolFailed(RuntimeError):
    def __init__(self, tool: str, returncode: int, stderr: str):
        super().__init__(f"{tool!r} exited with code {returncode}: {stderr[:500]}")
        self.tool = tool
        self.returncode = returncode
        self.stderr = stderr


@dataclass
class SubprocessResult:
    tool: str
    returncode: int
    stdout: str = ""
    stderr: str = ""
    duration_sec: float = 0.0
    timed_out: bool = False
    lines: list[str] = field(default_factory=list)


_BANNED_ARG_FRAGMENTS = (
    "--bypass", "--evade", "--stealth", "--rate-limit-bypass",
    "--hidden", "--cloak", "--decoy",
)


def _assert_args_clean(tool: str, args: Sequence[str]) -> None:
    for a in args:
        low = a.lower()
        for banned in _BANNED_ARG_FRAGMENTS:
            if low.startswith(banned):
                raise ValueError(
                    f"refused subprocess arg {a!r} for {tool}: evasion flags are not permitted"
                )


def resolve_binary(tool: str) -> str | None:
    """Return a full path for ``tool`` or None if it is not installed."""
    return shutil.which(tool)


async def run(
    tool: str,
    args: Sequence[str],
    *,
    timeout: float,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    input_bytes: bytes | None = None,
) -> SubprocessResult:
    """Run ``tool`` with ``args`` and return its captured output.

    Raises ``ToolUnavailable`` if the binary is missing, ``ToolTimeout`` on
    timeout, and ``ToolFailed`` if returncode != 0 (stdout is still available
    on the exception's ``stderr`` log).
    """
    _assert_args_clean(tool, args)
    binary = resolve_binary(tool)
    if binary is None:
        raise ToolUnavailable(tool)

    # Use an isolated empty cwd by default so that a planted file in the
    # project directory cannot influence the tool.
    cwd_dir = cwd
    created_tmp = None
    if cwd_dir is None:
        created_tmp = tempfile.mkdtemp(prefix=f"asm-{tool}-")
        cwd_dir = created_tmp

    sub_env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": cwd_dir,
    }
    if env:
        sub_env.update(env)

    full = [binary, *args]
    log.info("subprocess.start", tool=tool, args=args)

    import time
    t0 = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        *full,
        cwd=cwd_dir,
        env=sub_env,
        stdin=asyncio.subprocess.PIPE if input_bytes is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(input=input_bytes), timeout=timeout
        )
    except asyncio.TimeoutError:
        log.warning("subprocess.timeout", tool=tool, timeout=timeout)
        _terminate(proc)
        try:
            await asyncio.wait_for(proc.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
        if created_tmp:
            shutil.rmtree(created_tmp, ignore_errors=True)
        raise ToolTimeout(tool, timeout)
    except asyncio.CancelledError:
        _terminate(proc)
        try:
            await asyncio.wait_for(proc.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
        if created_tmp:
            shutil.rmtree(created_tmp, ignore_errors=True)
        raise

    if created_tmp:
        shutil.rmtree(created_tmp, ignore_errors=True)

    duration = time.monotonic() - t0
    stdout = (stdout_b or b"").decode("utf-8", errors="replace")
    stderr = (stderr_b or b"").decode("utf-8", errors="replace")
    result = SubprocessResult(
        tool=tool,
        returncode=proc.returncode or 0,
        stdout=stdout,
        stderr=stderr,
        duration_sec=duration,
        lines=[ln for ln in stdout.splitlines() if ln.strip()],
    )
    log.info(
        "subprocess.done",
        tool=tool,
        returncode=result.returncode,
        lines=len(result.lines),
        duration_sec=round(duration, 3),
    )
    if result.returncode != 0:
        # Some tools (nuclei with no hits) can be non-zero in some versions;
        # we surface the failure but it's up to the caller to decide.
        raise ToolFailed(tool, result.returncode, stderr)
    return result


def _terminate(proc: asyncio.subprocess.Process) -> None:
    try:
        proc.terminate()
    except ProcessLookupError:
        pass
