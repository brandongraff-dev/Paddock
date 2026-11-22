"""GuardedRunner: the only ScenarioRunner a scenario ever sees.

Every method goes through the IsolationGuard, so a scenario can reach nothing
but the verified replica it was handed, inside the internal-only sandbox
network. A scenario cannot obtain the backend or a raw socket; it can only ask
the runner to run a command, make an HTTP request, or test a TCP port against
*this replica*.

HTTP and TCP probes are implemented by running a client INSIDE the sandbox
(``guard.exec_in``) against the replica's own internal alias -- the request
never originates outside the sealed network. The real (docker) path assumes the
replica image (or, later, a dedicated probe sidecar) carries ``curl``; the
version-identity signal most scenarios lead with needs only ``exec_in`` and is
unaffected. Against the in-memory ``FakeBackend`` these calls return scripted
output, which is how the prover is tested deterministically with no containers.
"""
from __future__ import annotations

from typing import Optional

from ..sandbox.guard import IsolationGuard
from ..sandbox.types import ExecResult, Replica
from ..scenarios.base import HttpProbe, ScenarioRunner

# A probe's target is always the replica's own alias; the guard re-checks it.
_MAX_BODY_EXCERPT = 400


class GuardedRunner(ScenarioRunner):
    def __init__(self, guard: IsolationGuard) -> None:
        self._guard = guard

    async def exec_in(
        self, replica: Replica, argv: tuple[str, ...], *, timeout_sec: int = 30
    ) -> ExecResult:
        return await self._guard.exec_in(replica, tuple(argv), timeout_sec=timeout_sec)

    def _replica_url(self, replica: Replica, path: str) -> str:
        # Defense in depth: prove the host we are about to target is a replica
        # alias, not a live/routable address, before forming a URL from it.
        self._guard.assert_replica_target(replica.internal_host)
        port = replica.internal_port or 80
        p = path if path.startswith("/") else "/" + path
        return f"http://{replica.internal_host}:{port}{p}"

    async def http(
        self,
        replica: Replica,
        path: str = "/",
        *,
        method: str = "GET",
        timeout_sec: int = 15,
        headers: Optional[dict[str, str]] = None,
    ) -> HttpProbe:
        url = self._replica_url(replica, path)
        method = (method or "GET").upper()
        argv = ["curl", "-sS", "-m", str(max(1, timeout_sec)), "-D", "-"]
        if method == "HEAD":
            argv.append("-I")
        else:
            argv += ["-X", method, "-o", "-"]
        for k, v in (headers or {}).items():
            # Header names/values are scenario-supplied constants, never a target
            # address; argv (no shell) keeps them inert.
            argv += ["-H", f"{k}: {v}"]
        argv.append(url)
        res = await self.exec_in(replica, tuple(argv), timeout_sec=timeout_sec)
        if res.timed_out:
            return HttpProbe(error="timeout")
        if res.exit_code != 0 and not res.stdout:
            return HttpProbe(error=f"curl exit {res.exit_code}: {res.stderr[:160]}")
        return _parse_http(res.stdout)

    async def tcp_open(self, replica: Replica, *, timeout_sec: int = 5) -> bool:
        self._guard.assert_replica_target(replica.internal_host)
        port = replica.internal_port
        if not port:
            return False
        # Portable, dependency-light TCP connect from inside the replica.
        script = (
            "import socket,sys;"
            f"s=socket.socket();s.settimeout({max(1, timeout_sec)});"
            f"sys.exit(0 if s.connect_ex(('{replica.internal_host}',{int(port)}))==0 else 1)"
        )
        res = await self.exec_in(
            replica, ("python3", "-c", script), timeout_sec=timeout_sec
        )
        return res.ok


def _parse_http(raw: str) -> HttpProbe:
    """Parse a ``curl -D -`` dump (status line + headers, blank line, body).

    Tolerant of multiple header blocks (redirect chains): the LAST status line
    and its header block win, matching how curl prints them in order.
    """
    if not raw:
        return HttpProbe(error="empty response")
    # Normalise newlines; split header block(s) from body on the first blank line
    # AFTER the final status line.
    text = raw.replace("\r\n", "\n")
    blocks = text.split("\n\n")
    # Find the last block that starts with an HTTP status line.
    status = 0
    headers: dict[str, str] = {}
    header_block_idx = -1
    for i, block in enumerate(blocks):
        first = block.lstrip().split("\n", 1)[0]
        if first.upper().startswith("HTTP/"):
            parts = first.split()
            if len(parts) >= 2 and parts[1].isdigit():
                status = int(parts[1])
                header_block_idx = i
                headers = {}
                for line in block.split("\n")[1:]:
                    if ":" in line:
                        k, _, v = line.partition(":")
                        headers[k.strip()] = v.strip()
    body = ""
    if header_block_idx >= 0 and header_block_idx + 1 < len(blocks):
        body = "\n\n".join(blocks[header_block_idx + 1 :])
    if status == 0:
        return HttpProbe(error="no HTTP status line in response")
    return HttpProbe(status=status, headers=headers, body_excerpt=body[:_MAX_BODY_EXCERPT])
