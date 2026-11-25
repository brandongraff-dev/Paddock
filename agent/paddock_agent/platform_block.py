"""Platform abstraction for HOST-LOCAL defensive enforcement.

An ``Enforcer`` knows how to, on the LOCAL host only:
  * ``simulate(action_type, target)`` -> return the plan (commands/steps) it
    WOULD run, touching nothing. Always safe, always side-effect free.
  * ``apply(action_type, target)``    -> actually make the change and return
    ``{"output": {...}, "revert": {...}}`` where ``revert`` describes how to undo it.
  * ``validate_revert(plan)`` -> the TRUSTED revert plan re-derived locally from a
    server-supplied (untrusted) one, or :class:`RevertRefused`.
  * ``revert(plan)`` / ``simulate_revert(plan)`` -> undo / preview the undo.

SAFETY (audit 7.4): a revert plan comes back from the server, so it is DATA, never a program. The
Linux enforcer never executes an argv, path or file name taken from it. It recovers the original
*typed* action (action type + target) from the plan, re-validates that with the host-local guard, and
rebuilds the one fixed command/line/move this agent would have created. A plan that does not match
exactly what the agent could have produced is refused (``rm -rf`` included). A quarantine restore
additionally needs this host's own manifest entry, so the server cannot choose where a file lands.

Only the Linux enforcer actually executes (iptables for IPv4 IP + port rules, /etc/hosts sinkhole for
domains, a move-to-quarantine dir for files -- never a delete). IPv6 ``block_ip`` is refused loudly (the
iptables back end is IPv4-only). Windows / macOS are explicit NotImplemented stubs that are ALWAYS
dry-run. Nothing here reaches off the box: no remote transport, no SSH, no scan.
"""
from __future__ import annotations

import ipaddress
import json
import os
import platform as _platform
import re
import shutil
import subprocess
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Type

from .actions import (  # noqa: F401 -- the exception types are re-exported from here
    EnforcerError,
    HostLocalError,
    NotSupportedError,
    RevertRefused,
    assert_host_local,
)
from .state import atomic_write


class CompletedLike:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


# A command runner is injectable so tests never shell out.
Runner = Callable[[List[str]], Any]


def _real_runner(cmd: List[str]) -> CompletedLike:
    env = dict(os.environ)
    env["LC_ALL"] = "C"
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30,  # noqa: S603
                          stdin=subprocess.DEVNULL, env=env)
    return CompletedLike(proc.returncode, proc.stdout, proc.stderr)


_HOSTS_LINE_RE = re.compile(r"^127\.0\.0\.1 (\S{1,253})  # paddock-agent block$")
_QUARANTINE_NAME_RE = re.compile(r"^\d{1,12}_[^/\x00]{1,200}$")
_MANIFEST_NAME = ".paddock-manifest.json"


class BaseEnforcer:
    name = "base"
    can_apply = False

    def __init__(self, *, quarantine_dir: str = "/var/lib/paddock-agent/quarantine",
                 runner: Optional[Runner] = None) -> None:
        self.quarantine_dir = quarantine_dir
        self._run = runner or _real_runner

    # -- plan builders (pure; used by both simulate and apply) --------------- #
    def _plan(self, action_type: str, target: str) -> Dict[str, Any]:  # pragma: no cover
        raise NotImplementedError

    def simulate(self, action_type: str, target: str) -> Dict[str, Any]:
        plan = self._plan(action_type, target)
        return {"would": plan, "dry_run": True, "platform": self.name, "target": target}

    def validate_revert(self, plan: Any) -> Dict[str, Any]:
        """The trusted revert plan derived from an untrusted one. Base: nothing can be reverted."""
        raise NotSupportedError("%s enforcement cannot revert anything" % self.name)

    def simulate_revert(self, plan: Any) -> Dict[str, Any]:
        return {"would_revert": self.validate_revert(plan), "dry_run": True, "platform": self.name}

    def apply(self, action_type: str, target: str) -> Dict[str, Any]:  # pragma: no cover
        raise NotImplementedError

    def revert(self, plan: Any) -> Dict[str, Any]:  # pragma: no cover
        raise NotImplementedError


class LinuxEnforcer(BaseEnforcer):
    name = "linux"
    can_apply = True

    def __init__(self, *, quarantine_dir: str = "/var/lib/paddock-agent/quarantine",
                 runner: Optional[Runner] = None, hosts_path: str = "/etc/hosts") -> None:
        super().__init__(quarantine_dir=quarantine_dir, runner=runner)
        self.hosts_path = hosts_path

    # ------------------------------------------------------------------ #
    # plans (built only from guard-validated typed input)
    # ------------------------------------------------------------------ #
    def _plan(self, action_type: str, target: str) -> Dict[str, Any]:
        try:
            target = assert_host_local(action_type, target)
        except HostLocalError as exc:
            raise NotSupportedError("refused: %s" % exc)
        if action_type == "block_ip":
            if ipaddress.ip_address(target).version != 4:
                raise NotSupportedError(
                    "block_ip for an IPv6 address is not supported: the Linux enforcer drives iptables "
                    "(IPv4 only), so the block would never take effect. Refused, nothing applied.")
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
                "file": self.hosts_path,
                "line": "127.0.0.1 %s  # paddock-agent block" % target,
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
            dest = self._quarantine_dest(target)
            return {"mechanism": "move-to-quarantine", "src": target, "dest": dest}
        raise NotSupportedError("unknown action_type %r" % (action_type,))

    @staticmethod
    def _parse_portspec(spec: str) -> Tuple[str, str, str]:
        parts = spec.replace(":", " ").split()
        if len(parts) == 3:
            direction, proto, port = parts
        else:
            direction, proto, port = "in", parts[0], parts[1]
        return direction.lower(), proto.lower(), port

    def _quarantine_dest(self, src: str) -> str:
        name = os.path.basename(src) or "file"
        base = "%d_%s" % (int(time.time()), name)
        dest = os.path.join(self.quarantine_dir, base)
        n = 0
        while os.path.lexists(dest):          # never overwrite an earlier quarantined file
            n += 1
            dest = os.path.join(self.quarantine_dir, "%s.%d" % (base, n))
        return dest

    # ------------------------------------------------------------------ #
    # apply
    # ------------------------------------------------------------------ #
    def apply(self, action_type: str, target: str) -> Dict[str, Any]:
        target = self._canonical(action_type, target)
        plan = self._plan(action_type, target)
        if action_type in ("block_ip", "firewall_rule"):
            self._exec(plan["add"])
            if "add_out" in plan:
                self._exec(plan["add_out"])
            commands = [plan["remove"]] + ([plan["remove_out"]] if "remove_out" in plan else [])
            revert = {"mechanism": "iptables", "action_type": action_type, "target": target,
                      "commands": commands}
            return {"output": {"plan": plan}, "revert": revert}
        if action_type == "block_domain":
            line = plan["line"]
            with open(plan["file"], "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            return {"output": {"appended": line},
                    "revert": {"mechanism": "hosts-sinkhole", "action_type": "block_domain",
                               "target": target, "file": plan["file"], "line": line}}
        if action_type == "quarantine_file":
            src, dest = plan["src"], plan["dest"]
            os.makedirs(self.quarantine_dir, mode=0o700, exist_ok=True)
            self._manifest_put(os.path.basename(dest), src)      # write-ahead: a quarantined file always has a record
            try:
                shutil.move(src, dest)  # never a delete -- reversible
            except BaseException:
                self._manifest_drop(os.path.basename(dest))
                raise
            return {"output": {"moved": {"src": src, "dest": dest}},
                    "revert": {"mechanism": "move-to-quarantine", "action_type": "quarantine_file",
                               "target": src, "src": src, "dest": dest}}
        raise NotSupportedError(action_type)

    @staticmethod
    def _canonical(action_type: str, target: str) -> str:
        try:
            return assert_host_local(action_type, target)
        except HostLocalError as exc:
            raise NotSupportedError("refused: %s" % exc)

    def _exec(self, cmd: List[str]) -> None:
        res = self._run(cmd)
        if res.returncode != 0:
            raise EnforcerError("command failed (%s): %s :: %s" % (res.returncode, " ".join(cmd), res.stderr))

    # ------------------------------------------------------------------ #
    # revert: the server's plan is untrusted data
    # ------------------------------------------------------------------ #
    def validate_revert(self, plan: Any) -> Dict[str, Any]:
        if not isinstance(plan, dict):
            raise RevertRefused("revert plan is not an object")
        mech = plan.get("mechanism")
        if mech == "iptables":
            return self._validate_iptables(plan)
        if mech == "hosts-sinkhole":
            return self._validate_hosts(plan)
        if mech == "move-to-quarantine":
            return self._validate_quarantine(plan)
        raise RevertRefused("unknown revert mechanism %r" % (mech if isinstance(mech, str) else None))

    def _typed_from_commands(self, commands: Any) -> Tuple[str, str]:
        """The typed action a removal command list could have come from, or :class:`RevertRefused`."""
        if (not isinstance(commands, list) or not 1 <= len(commands) <= 2
                or not all(isinstance(c, list) and all(isinstance(a, str) for a in c) for c in commands)):
            raise RevertRefused("revert commands must be one or two argument lists")
        first = commands[0]
        if len(first) == 7 and first[:4] == ["iptables", "-D", "INPUT", "-s"] and first[5:] == ["-j", "DROP"]:
            return "block_ip", first[4]
        if (len(first) == 9 and first[:2] == ["iptables", "-D"] and first[2] in ("INPUT", "OUTPUT")
                and first[3] == "-p" and first[5] == "--dport" and first[7:] == ["-j", "DROP"]):
            direction = "in" if first[2] == "INPUT" else "out"
            return "firewall_rule", "%s:%s:%s" % (direction, first[4], first[6])
        raise RevertRefused("revert commands are not a removal this agent could have created")

    def _validate_iptables(self, plan: Dict[str, Any]) -> Dict[str, Any]:
        at, tgt = plan.get("action_type"), plan.get("target")
        if isinstance(at, str) and isinstance(tgt, str):
            if at not in ("block_ip", "firewall_rule"):
                raise RevertRefused("an iptables revert must come from block_ip or firewall_rule")
        else:
            at, tgt = self._typed_from_commands(plan.get("commands"))
        try:
            canon_target = assert_host_local(at, tgt)
            derived = self._plan(at, canon_target)
        except (HostLocalError, NotSupportedError) as exc:
            raise RevertRefused("revert target refused: %s" % exc)
        commands = [derived["remove"]] + ([derived["remove_out"]] if "remove_out" in derived else [])
        if "commands" in plan and plan["commands"] != commands:
            raise RevertRefused("revert commands differ from the plan this agent would have created")
        return {"mechanism": "iptables", "action_type": at, "target": canon_target, "commands": commands}

    def _validate_hosts(self, plan: Dict[str, Any]) -> Dict[str, Any]:
        tgt = plan.get("target")
        if not isinstance(tgt, str):
            line = plan.get("line")
            m = _HOSTS_LINE_RE.match(line) if isinstance(line, str) else None
            if not m:
                raise RevertRefused("revert line is not a sinkhole line this agent could have written")
            tgt = m.group(1)
        try:
            domain = assert_host_local("block_domain", tgt)
        except HostLocalError as exc:
            raise RevertRefused("revert target refused: %s" % exc)
        derived = self._plan("block_domain", domain)
        if "line" in plan and plan["line"] != derived["line"]:
            raise RevertRefused("revert line differs from the line this agent would have written")
        if "file" in plan and plan["file"] != self.hosts_path:
            raise RevertRefused("revert names a file other than %s" % self.hosts_path)
        return {"mechanism": "hosts-sinkhole", "action_type": "block_domain", "target": domain,
                "file": self.hosts_path, "line": derived["line"]}

    def _validate_quarantine(self, plan: Dict[str, Any]) -> Dict[str, Any]:
        dest = plan.get("dest")
        if not isinstance(dest, str):
            raise RevertRefused("quarantine revert needs the quarantined file")
        qdir = os.path.normpath(self.quarantine_dir)
        if os.path.dirname(os.path.normpath(dest)) != qdir or ".." in dest.split("/"):
            raise RevertRefused("quarantine revert names a file outside the quarantine directory")
        name = os.path.basename(dest)
        if not _QUARANTINE_NAME_RE.match(name):
            raise RevertRefused("quarantine revert names a file this agent could not have created")
        src = self._manifest().get(name)
        if not isinstance(src, str):
            raise RevertRefused("no local record of quarantining %s; restore it by hand" % name)
        if "src" in plan and plan["src"] != src:
            raise RevertRefused("quarantine revert names a restore path that differs from this host's record")
        try:
            assert_host_local("quarantine_file", src)
        except HostLocalError as exc:
            raise RevertRefused("recorded restore path refused: %s" % exc)
        return {"mechanism": "move-to-quarantine", "action_type": "quarantine_file", "target": src,
                "src": src, "dest": os.path.join(qdir, name)}

    def revert(self, plan: Any) -> Dict[str, Any]:
        safe = self.validate_revert(plan)         # raises RevertRefused: nothing below runs on a bad plan
        mech = safe["mechanism"]
        if mech == "iptables":
            for cmd in safe["commands"]:
                self._exec(cmd)
            return {"reverted": safe["commands"]}
        if mech == "hosts-sinkhole":
            self._remove_hosts_line(safe["file"], safe["line"])
            return {"reverted_line": safe["line"]}
        if mech == "move-to-quarantine":
            src, dest = safe["src"], safe["dest"]
            if os.path.islink(dest) or not os.path.isfile(dest):
                raise RevertRefused("the quarantined file is missing or not a regular file")
            if os.path.lexists(src):
                raise RevertRefused("refusing to overwrite %s while restoring it" % src)
            if not os.path.isdir(os.path.dirname(src)):
                raise RevertRefused("the original directory of %s no longer exists" % src)
            shutil.move(dest, src)  # restore it exactly
            self._manifest_drop(os.path.basename(dest))
            return {"restored": {"src": src, "dest": dest}}
        raise NotSupportedError("cannot revert mechanism %r" % mech)  # pragma: no cover

    @staticmethod
    def _remove_hosts_line(path: str, line: str) -> None:
        if not os.path.exists(path):
            return
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        kept = [ln for ln in lines if ln.strip() != line.strip()]
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(kept) + ("\n" if kept else ""))

    # -- the host's own record of what it quarantined ------------------------ #
    def _manifest_path(self) -> str:
        return os.path.join(self.quarantine_dir, _MANIFEST_NAME)

    def _manifest(self) -> Dict[str, str]:
        try:
            with open(self._manifest_path(), "r", encoding="utf-8") as fh:
                data = json.load(fh)
            items = data.get("items", {})
            return dict((k, v) for k, v in items.items() if isinstance(k, str) and isinstance(v, str))
        except (OSError, ValueError, AttributeError):
            return {}

    def _manifest_put(self, name: str, src: str) -> None:
        items = self._manifest()
        items[name] = src
        atomic_write(self._manifest_path(), json.dumps({"v": 1, "items": items}, sort_keys=True).encode("utf-8"))

    def _manifest_drop(self, name: str) -> None:
        items = self._manifest()
        if name in items:
            del items[name]
            atomic_write(self._manifest_path(),
                         json.dumps({"v": 1, "items": items}, sort_keys=True).encode("utf-8"))


class _StubEnforcer(BaseEnforcer):
    """Windows / macOS: can describe a plan, can NEVER apply (always dry-run)."""
    can_apply = False

    def _plan(self, action_type: str, target: str) -> Dict[str, Any]:
        return {"mechanism": "%s-not-implemented" % self.name, "action_type": action_type,
                "target": target, "note": "host-local enforcement on %s is not implemented" % self.name}

    def validate_revert(self, plan: Any) -> Dict[str, Any]:
        return {"mechanism": "%s-not-implemented" % self.name,
                "note": "nothing was ever applied on this platform"}

    def apply(self, action_type: str, target: str) -> Dict[str, Any]:
        raise NotSupportedError(
            "%s enforcement is not implemented; this platform is dry-run only" % self.name)

    def revert(self, plan: Any) -> Dict[str, Any]:
        raise NotSupportedError(
            "%s enforcement is not implemented; nothing was ever applied" % self.name)


class WindowsEnforcer(_StubEnforcer):
    name = "windows"


class MacEnforcer(_StubEnforcer):
    name = "macos"


_ENFORCERS = {
    "linux": LinuxEnforcer,
    "windows": WindowsEnforcer,
    "macos": MacEnforcer,
    "darwin": MacEnforcer,
}  # type: Dict[str, Type[BaseEnforcer]]


def detect_platform(override: Optional[str] = None) -> str:
    sysname = (override or _platform.system()).lower()
    if sysname == "darwin":
        return "macos"
    return sysname  # 'linux' | 'windows' | 'macos'


def get_enforcer(platform_name: Optional[str] = None, *, quarantine_dir: Optional[str] = None,
                 runner: Optional[Runner] = None) -> BaseEnforcer:
    name = detect_platform(platform_name)
    cls = _ENFORCERS.get(name, WindowsEnforcer)  # unknown -> never-apply stub
    kwargs = {"runner": runner}  # type: Dict[str, Any]
    if quarantine_dir:
        kwargs["quarantine_dir"] = quarantine_dir
    return cls(**dict((k, v) for k, v in kwargs.items() if v is not None))
