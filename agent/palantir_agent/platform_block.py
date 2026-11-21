"""Platform abstraction for HOST-LOCAL defensive enforcement.

An ``Enforcer`` knows how to, on the LOCAL host only:
  * ``simulate(action_type, target)`` -> return the plan (commands/steps) it
    WOULD run, touching nothing. Always safe, always side-effect free.
  * ``apply(action_type, target)``    -> actually make the change and return
    ``{"output": {...}, "revert": {...}}`` where ``revert`` is everything
    needed to undo it. Every apply is reversible.
  * ``revert(plan)`` / ``simulate_revert(plan)`` -> undo / preview the undo.

Only the Linux enforcer actually executes (iptables/nft for IP + port rules,
/etc/hosts sinkhole for domains, a move-to-quarantine dir for files -- never a
delete). Windows / macOS are explicit NotImplemented stubs that are ALWAYS
dry-run: they can simulate (describe the plan) but refuse to apply.

Nothing here reaches off the box. There is no remote transport, no SSH, no
scan -- the enforcer's whole vocabulary is "change a setting on this machine".
"""
from __future__ import annotations

import platform as _platform
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Callable


class EnforcerError(RuntimeError):
    pass


class NotSupportedError(EnforcerError):
    """The running platform cannot apply this action (dry-run only)."""


# A command runner is injectable so tests never shell out.
Runner = Callable[[list[str]], "CompletedLike"]


class CompletedLike:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _real_runner(cmd: list[str]) -> CompletedLike:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)  # noqa: S603
    return CompletedLike(proc.returncode, proc.stdout, proc.stderr)


class BaseEnforcer:
    name = "base"
    can_apply = False

    def __init__(self, *, quarantine_dir: str = "/var/lib/palantir-agent/quarantine",
                 runner: Runner | None = None) -> None:
        self.quarantine_dir = quarantine_dir
        self._run = runner or _real_runner

    # -- plan builders (pure; used by both simulate and apply) --------------- #
    def _plan(self, action_type: str, target: str) -> dict[str, Any]:  # pragma: no cover
        raise NotImplementedError

    def simulate(self, action_type: str, target: str) -> dict[str, Any]:
        plan = self._plan(action_type, target)
        return {"would": plan, "dry_run": True, "platform": self.name, "target": target}

    def simulate_revert(self, plan: dict[str, Any]) -> dict[str, Any]:
        return {"would_revert": plan, "dry_run": True, "platform": self.name}

    def apply(self, action_type: str, target: str) -> dict[str, Any]:  # pragma: no cover
        raise NotImplementedError

    def revert(self, plan: dict[str, Any]) -> dict[str, Any]:  # pragma: no cover
        raise NotImplementedError


class LinuxEnforcer(BaseEnforcer):
    name = "linux"
    can_apply = True

    def _plan(self, action_type: str, target: str) -> dict[str, Any]:
        if action_type == "block_ip":
            return {
                "mechanism": "iptables",
                "add": ["iptables", "-I", "INPUT", "-s", target, "-j", "DROP"],
                "add_out": ["iptables", "-I", "OUTPUT", "-d", target, "-j", "DROP"],
                "remove": ["iptables", "-D", "INPUT", "-s", target, "-j", "DROP"],
                "remove_out": ["iptables", "-D", "OUTPUT", "-d", target, "-j", "DROP"],
            }
        if action_type == "block_domain":
            return {
                "mechanism": "hosts-sinkhole",
                "file": "/etc/hosts",
                "line": f"127.0.0.1 {target}  # palantir-agent block",
            }
        if action_type == "firewall_rule":
            direction, proto, port = self._parse_portspec(target)
            chain = "INPUT" if direction != "out" else "OUTPUT"
            return {
                "mechanism": "iptables",
                "add": ["iptables", "-I", chain, "-p", proto, "--dport", port, "-j", "DROP"],
                "remove": ["iptables", "-D", chain, "-p", proto, "--dport", port, "-j", "DROP"],
            }
        if action_type == "quarantine_file":
            dest = str(Path(self.quarantine_dir) / f"{int(time.time())}_{Path(target).name}")
            return {"mechanism": "move-to-quarantine", "src": target, "dest": dest}
        raise NotSupportedError(f"unknown action_type {action_type!r}")

    @staticmethod
    def _parse_portspec(spec: str) -> tuple[str, str, str]:
        parts = spec.replace(":", " ").split()
        if len(parts) == 3:
            direction, proto, port = parts
        else:
            direction, proto, port = "in", parts[0], parts[1]
        return direction.lower(), proto.lower(), port

    def apply(self, action_type: str, target: str) -> dict[str, Any]:
        plan = self._plan(action_type, target)
        if action_type in ("block_ip", "firewall_rule"):
            self._exec(plan["add"])
            if "add_out" in plan:
                self._exec(plan["add_out"])
            revert = {"commands": [plan["remove"]] + ([plan["remove_out"]] if "remove_out" in plan else []),
                      "mechanism": plan["mechanism"]}
            return {"output": {"plan": plan}, "revert": revert}
        if action_type == "block_domain":
            line = plan["line"]
            with open(plan["file"], "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            return {"output": {"appended": line},
                    "revert": {"mechanism": "hosts-sinkhole", "file": plan["file"], "line": line}}
        if action_type == "quarantine_file":
            src, dest = plan["src"], plan["dest"]
            Path(self.quarantine_dir).mkdir(parents=True, exist_ok=True)
            shutil.move(src, dest)  # never a delete -- reversible
            return {"output": {"moved": {"src": src, "dest": dest}},
                    "revert": {"mechanism": "move-to-quarantine", "src": src, "dest": dest}}
        raise NotSupportedError(action_type)

    def revert(self, plan: dict[str, Any]) -> dict[str, Any]:
        mech = plan.get("mechanism")
        if mech == "iptables":
            for cmd in plan.get("commands", []):
                self._exec(cmd)
            return {"reverted": plan.get("commands", [])}
        if mech == "hosts-sinkhole":
            self._remove_hosts_line(plan["file"], plan["line"])
            return {"reverted_line": plan["line"]}
        if mech == "move-to-quarantine":
            src, dest = plan["src"], plan["dest"]
            if Path(dest).exists():
                shutil.move(dest, src)  # restore it exactly
            return {"restored": {"src": src, "dest": dest}}
        raise NotSupportedError(f"cannot revert mechanism {mech!r}")

    def _exec(self, cmd: list[str]) -> None:
        res = self._run(cmd)
        if res.returncode != 0:
            raise EnforcerError(f"command failed ({res.returncode}): {' '.join(cmd)} :: {res.stderr}")

    @staticmethod
    def _remove_hosts_line(path: str, line: str) -> None:
        p = Path(path)
        if not p.exists():
            return
        kept = [ln for ln in p.read_text().splitlines() if ln.strip() != line.strip()]
        p.write_text("\n".join(kept) + ("\n" if kept else ""))


class _StubEnforcer(BaseEnforcer):
    """Windows / macOS: can describe a plan, can NEVER apply (always dry-run)."""
    can_apply = False

    def _plan(self, action_type: str, target: str) -> dict[str, Any]:
        return {"mechanism": f"{self.name}-not-implemented", "action_type": action_type,
                "target": target, "note": f"host-local enforcement on {self.name} is not implemented"}

    def apply(self, action_type: str, target: str) -> dict[str, Any]:
        raise NotSupportedError(
            f"{self.name} enforcement is not implemented; this platform is dry-run only"
        )

    def revert(self, plan: dict[str, Any]) -> dict[str, Any]:
        raise NotSupportedError(
            f"{self.name} enforcement is not implemented; nothing was ever applied"
        )


class WindowsEnforcer(_StubEnforcer):
    name = "windows"


class MacEnforcer(_StubEnforcer):
    name = "macos"


_ENFORCERS: dict[str, type[BaseEnforcer]] = {
    "linux": LinuxEnforcer,
    "windows": WindowsEnforcer,
    "macos": MacEnforcer,
    "darwin": MacEnforcer,
}


def detect_platform(override: str | None = None) -> str:
    sysname = (override or _platform.system()).lower()
    if sysname == "darwin":
        return "macos"
    return sysname  # 'linux' | 'windows' | 'macos'


def get_enforcer(platform_name: str | None = None, *, quarantine_dir: str | None = None,
                 runner: Runner | None = None) -> BaseEnforcer:
    name = detect_platform(platform_name)
    cls = _ENFORCERS.get(name, WindowsEnforcer)  # unknown -> never-apply stub
    kwargs: dict[str, Any] = {"runner": runner}
    if quarantine_dir:
        kwargs["quarantine_dir"] = quarantine_dir
    return cls(**{k: v for k, v in kwargs.items() if v is not None})
