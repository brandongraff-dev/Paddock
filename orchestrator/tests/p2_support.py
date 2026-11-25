"""Shared support for the P2 end-to-end and wire-vector tests (docs/ASSURANCE_P2.md section 10).

Nothing in here re-implements the code under test:

* ``FixtureHost`` is a pretend Linux server whose files and command output come from the REAL captured fixtures
  shipped with the agent (``agent/tests/fixtures``: an Ubuntu 24.04 ``/etc/os-release``, ``/proc/net/tcp``, the full
  ``dpkg-query`` and ``apt-get -s`` output, a real ``nft -j list ruleset`` capture). The REAL collectors run over it.
* ``AgentRuntime`` runs the REAL ``paddock_agent.agent.Agent`` (real keys, real envelope signing, real client) and
  carries its HTTP calls to the in-process ASGI app, so the server sees exactly what a network agent would send.

The agent package is imported from the installed distribution when there is one (CI installs ``agent/``), else
from the checkout; either way it is the code under ``agent/paddock_agent``.
"""
from __future__ import annotations

import asyncio
import copy
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Callable

REPO = Path(__file__).resolve().parents[2]
AGENT_DIR = REPO / "agent"
FIXTURES = AGENT_DIR / "tests" / "fixtures"

try:  # installed (CI: ``pip install -e agent``)
    import paddock_agent
except ImportError:  # a plain checkout
    sys.path.insert(0, str(AGENT_DIR))
    import paddock_agent

from paddock_agent import envelope as agent_envelope  # noqa: E402
from paddock_agent import signing as agent_signing  # noqa: E402
from paddock_agent.agent import Agent  # noqa: E402
from paddock_agent.client import FleetClient  # noqa: E402
from paddock_agent.config import AgentConfig  # noqa: E402
from paddock_agent.runner import Ctx  # noqa: E402
from paddock_agent.state import State  # noqa: E402

AGENT_VERSION = paddock_agent.__version__


def fixture(*parts: str) -> str:
    return (FIXTURES.joinpath(*parts)).read_text(encoding="utf-8")


def _res(out: str = "", rc: int = 0, err: str = "", missing: bool = False) -> dict:
    return {"rc": None if missing else rc, "out": out, "err_tail": err, "timed_out": False, "missing": missing,
            "truncated": False}


PUBLIC_IP = "93.184.216.34"
PUBLIC_PORT = 9000


def hardened_nft() -> dict:
    """The real ``nft -j list ruleset`` capture (policy-drop input chain), minus the one rule the model cannot
    read (``meta mark``): everything left is a matcher the firewall model supports, so the model is ``exact``."""
    doc = json.loads(fixture("ubuntu2404", "nft_json_unshare.json"))
    kept = []
    for obj in doc["nftables"]:
        rule = obj.get("rule")
        if rule and any("meta" in (e.get("match", {}).get("left", {})) and
                        e["match"]["left"]["meta"].get("key") == "mark" for e in rule["expr"] if "match" in e):
            continue
        kept.append(obj)
    return {"nftables": kept}


def open_nft() -> dict:
    """The same capture with the input chain's policy turned to accept and every rule removed: a host whose
    firewall lets everything in."""
    doc = hardened_nft()
    out = []
    for obj in doc["nftables"]:
        if "rule" in obj:
            continue
        obj = copy.deepcopy(obj)
        if obj.get("chain", {}).get("hook") == "input":
            obj["chain"]["policy"] = "accept"
        out.append(obj)
    return {"nftables": out}


class FixtureHost:
    """A pretend server. Mutate ``password_auth`` / ``nft`` between collections to change what the host says."""

    def __init__(self, root: Path, *, hostname: str = "web-1", password_auth: str = "no",
                 nft: dict | None = None, lo_only_listeners: bool = False) -> None:
        self.root = Path(root)
        self.hostname = hostname
        self.password_auth = password_auth
        self.nft = nft if nft is not None else hardened_nft()
        self.calls: list[list[str]] = []
        self._build_tree(lo_only_listeners)

    # ---- the file tree the collectors read ----------------------------------------------------------------
    def _put(self, base: Path, path: str, content: str | bytes, mode: int | None = None) -> None:
        full = base / path.lstrip("/")
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_bytes(content.encode() if isinstance(content, str) else content)
        if mode is not None:
            full.chmod(mode)

    def _build_tree(self, lo_only: bool) -> None:
        host, proc = self.root / "root", self.root / "proc"
        host.mkdir(parents=True, exist_ok=True)
        proc.mkdir(parents=True, exist_ok=True)
        files = {
            "/etc/os-release": fixture("ubuntu2404", "os-release.ubuntu2404.txt"),
            "/etc/machine-id": "0123456789abcdef0123456789abcdef\n",
            "/etc/ssh/sshd_config": "PasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM yes\n",
            "/etc/passwd": fixture("synthetic", "sshd", "passwd.sample"),
        }
        for path, content in files.items():
            self._put(host, path, content)
        for b in ("/usr/sbin/sshd", "/usr/bin/ssh", "/usr/sbin/nft", "/usr/bin/dpkg-query", "/usr/bin/apt-get"):
            self._put(host, b, "#!/bin/sh\n", mode=0o755)
        tcp = fixture("ubuntu2404", "proc_net_tcp.container.txt")
        if lo_only:
            tcp = "\n".join(ln for ln in tcp.splitlines() if "00000000:07E8" not in ln) + "\n"
        # a service bound to the host's own public address (93.184.216.34 = 22D8B85D little-endian) on tcp/9000:
        # the firewall capture does not accept 9000, so the agent models it as closed
        tcp += ("  40: 22D8B85D:2328 00000000:0000 0A 00000000:00000000 00:00000000 00000000"
                "     0        0 77777 1 0000000000000000 100 0 0 10 0\n")
        pfiles = {
            "/proc/sys/kernel/random/boot_id": "11111111-2222-3333-4444-555555555555\n",
            "/proc/uptime": "12345.67 9999.99\n",
            "/proc/self/status": "Name:\tpaddock\nCapEff:\t0000000000081004\n",
            "/proc/net/tcp": tcp,
            "/proc/net/udp": fixture("ubuntu2404", "proc_net_udp.container.txt"),
            "/proc/net/if_inet6": "00000000000000000000000000000001 01 80 10 80 lo\n",
        }
        for path, content in pfiles.items():
            self._put(proc, path[len("/proc"):], content)

    # ---- the fake commands ------------------------------------------------------------------------------------
    def sshd_T(self) -> str:
        text = fixture("synthetic", "sshd", "sshd_T.hardened.txt").splitlines()
        return "\n".join(f"passwordauthentication {self.password_auth}" if ln.startswith("passwordauthentication ")
                         else ln for ln in text) + "\n"

    def runner(self, argv: list[str], timeout: float, max_bytes: int) -> dict:
        self.calls.append(list(argv))
        name = os.path.basename(argv[0]) if argv else ""
        if name == "sshd":
            return _res(self.sshd_T())
        if name == "ssh":
            return _res("", err="OpenSSH_9.6p1 Ubuntu-3ubuntu13.5, OpenSSL 3.0.13 30 Jan 2024")
        if name == "nft":
            return _res(json.dumps(self.nft))
        if name == "dpkg-query":
            return _res(fixture("ubuntu2404", "dpkg_query_sample.ubuntu2404.tsv"))
        if name == "apt-get":
            return _res(fixture("synthetic", "patch", "apt_sim_empty.txt"))
        return _res(missing=True)

    def make_ctx(self, state_dir: str, *, seq: int, key_id: str, machine_salt: bytes,
                 clock: Callable[[], float] = time.time) -> Ctx:
        ctx = Ctx(state_dir, AGENT_VERSION, seq=seq, key_id=key_id, machine_salt=machine_salt,
                  now=lambda: int(clock()), proc_root=str(self.root / "proc"), host_root=str(self.root / "root"),
                  runner=self.runner, is_root=True, containerised=False, platform="linux")
        ctx.cache["machine"] = "x86_64"
        return ctx


# --------------------------------------------------------------------------- #
# the real agent, talking to the in-process app
# --------------------------------------------------------------------------- #

class AsgiBridge:
    """A ``FleetClient`` transport that runs each request against an ``httpx.AsyncClient`` bound to the ASGI app.

    The agent is synchronous, so it runs in a worker thread (``asyncio.to_thread``); each call hops back onto the
    test's event loop. Everything the server sees (headers, body bytes, gzip) is exactly what the client built.
    """

    def __init__(self, http, loop: asyncio.AbstractEventLoop) -> None:
        self.http, self.loop = http, loop
        self.log: list[tuple[str, str, int]] = []
        self.interceptor: Callable[[str, str, dict, bytes], Any] | None = None

    def __call__(self, method: str, url: str, headers: dict, body: bytes | None, timeout: float):
        path = "/" + url.split("://", 1)[1].split("/", 1)[1]
        if self.interceptor is not None:
            body = self.interceptor(method, path, headers, body) or body
        fut = asyncio.run_coroutine_threadsafe(
            self.http.request(method, path, headers=headers, content=body), self.loop)
        resp = fut.result(timeout=60)
        self.log.append((method, path, resp.status_code))
        return resp.status_code, {k.lower(): v for k, v in resp.headers.items()}, resp.content


class AgentRuntime:
    """One real agent on one fixture host. All blocking methods are run with ``await rt.call(...)``."""

    def __init__(self, tmp: Path, http, loop, *, hostname: str = "web-1", host: FixtureHost | None = None,
                 clock: Callable[[], float] = time.time) -> None:
        self.tmp = Path(tmp)
        self.host = host or FixtureHost(self.tmp / f"host-{hostname}", hostname=hostname)
        self.state_dir = str(self.tmp / f"state-{hostname}")
        self.bridge = AsgiBridge(http, loop)
        self.clock = clock
        self.cfg = AgentConfig(server="http://localhost", state_dir=self.state_dir,
                               quarantine_dir=str(self.tmp / f"quarantine-{hostname}"), dry_run=True,
                               inventory_interval_s=0)
        self.client = FleetClient("http://localhost", transport=self.bridge)
        self.agent = Agent(self.cfg, client=self.client, state=State(self.state_dir), clock=self.clock,
                           ctx_factory=self._ctx)

    def _ctx(self, *, seq: int, key_id: str) -> Ctx:
        salt = ("paddock-machine/v1:%s" % self.agent.creds.tenant_id).encode()
        return self.host.make_ctx(self.state_dir, seq=seq, key_id=key_id, machine_salt=salt, clock=self.clock)

    async def call(self, fn, *a, **kw):
        return await asyncio.to_thread(fn, *a, **kw)

    async def enroll(self, token: str, hostname: str | None = None, **kw):
        return await self.call(self.agent.enroll, token, hostname=hostname or self.host.hostname, **kw)

    async def posture(self):
        return await self.call(self.agent.send_posture)

    async def heartbeat(self):
        return await self.call(self.agent.heartbeat)

    @property
    def creds(self):
        return self.agent.creds

    @property
    def seed(self) -> bytes:
        return self.agent.state.load_key()

    @property
    def public_key(self) -> bytes:
        return agent_signing.public_key(self.seed)

    @property
    def key_id(self) -> str:
        return agent_signing.key_id(self.public_key)


# --------------------------------------------------------------------------- #
# orchestrator-side helpers
# --------------------------------------------------------------------------- #

async def seed_key(db_pool, tenant_id: str, username: str, role: str = "admin") -> str:
    """A user + API key for ``tenant_id`` (an operator credential for enforce-mode HTTP calls)."""
    from app import auth as auth_svc

    full, prefix, key_hash = auth_svc.generate_api_key()
    async with db_pool.acquire() as con:
        uid = await con.fetchval(
            "INSERT INTO app_users (username, role, clearance, pw_hash, tenant_id) "
            "VALUES ($1, $2, 'restricted', $3, $4) RETURNING id",
            username, role, auth_svc.hash_password("pw-" + username), tenant_id)
        await con.execute(
            "INSERT INTO api_keys (user_id, name, prefix, key_hash, scopes, tenant_id) "
            "VALUES ($1, 'k', $2, $3, $4::text[], $5)",
            uid, prefix, key_hash, sorted(auth_svc.ROLE_CAPABILITIES[role]), tenant_id)
    return full


def agent_client_error():
    from paddock_agent.client import FleetClientError

    return FleetClientError


def make_credentials(agent_id, token: str, tenant_id: str, server: str = "http://localhost"):
    """Credentials as an old (v1) agent would have left them: the state file the real ``State`` reads."""
    from paddock_agent.state import Credentials

    return Credentials(agent_id=str(agent_id), agent_token=token, tenant_id=tenant_id, server=server,
                       hostname="old-host", key_id="0" * 32, enrolled_at="2026-01-01T00:00:00Z")


def hdr(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


__all__ = ["seed_key", "hdr", "agent_client_error", "make_credentials", "AGENT_VERSION", "AgentRuntime", "AsgiBridge", "FixtureHost", "agent_envelope", "agent_signing",
           "fixture", "hardened_nft", "open_nft", "REPO", "PUBLIC_IP", "PUBLIC_PORT"]
