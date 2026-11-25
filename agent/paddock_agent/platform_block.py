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

The agent only ever undoes its own work: iptables rules carry ``-m comment --comment paddock:<action id>``
(removed only after ``iptables -C`` proves they exist), and ``validate_revert`` takes the agent's ledger of
what it applied (see ``agent.py``): no unreverted local record, no revert. Quarantine never follows a
symlink (every path component is opened ``O_NOFOLLOW`` and the move is ``dir_fd``-relative).

Only the Linux enforcer actually executes (iptables for IPv4 IP + port rules, /etc/hosts sinkhole for
domains, a move-to-quarantine dir for files -- never a delete). IPv6 ``block_ip`` is refused loudly (the
iptables back end is IPv4-only). Windows / macOS are explicit NotImplemented stubs that are ALWAYS
dry-run. Nothing here reaches off the box: no remote transport, no SSH, no scan.
"""
from __future__ import annotations

import errno
import ipaddress
import json
import logging
import os
import platform as _platform
import re
import stat
import subprocess
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Type

from .actions import (  # noqa: F401 -- the exception types are re-exported from here
    EnforcerError,
    HostLocalError,
    NotSupportedError,
    RevertRefused,
    assert_host_local,
)
from .state import atomic_write

log = logging.getLogger("paddock-agent.enforce")


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
_TAG_RE = re.compile(r"^paddock:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
SIMULATED_TAG = "paddock:<action-id>"
# never quarantined: the agent's own install, config and state (a quarantine of its key would brick it)
DEFAULT_PROTECTED = ("/var/lib/paddock-agent", "/etc/paddock-agent", "/usr/local/lib/paddock-agent")

# the ledger an agent passes to validate_revert: (action_type, canonical target) -> the unreverted local rule
# record ({"tag": ...}) or None
# ``ledger(action_type, target[, tag])``: this host's own record of an unreverted rule the agent applied. With a
# ``tag`` the lookup is for exactly that action's rule (reverts work in any order); without one, the newest.
Ledger = Callable[..., Optional[Dict[str, Any]]]


class BaseEnforcer:
    name = "base"
    can_apply = False
    tags_rules = False       # True when apply()/simulate() take the action id and tag what they change

    def __init__(self, *, quarantine_dir: str = "/var/lib/paddock-agent/quarantine",
                 runner: Optional[Runner] = None, protected_paths: Sequence[str] = ()) -> None:
        self.quarantine_dir = quarantine_dir
        self._run = runner or _real_runner
        self.protected_paths = tuple(p for p in protected_paths if p)

    # -- plan builders (pure; used by both simulate and apply) --------------- #
    def _plan(self, action_type: str, target: str) -> Dict[str, Any]:  # pragma: no cover
        raise NotImplementedError

    def simulate(self, action_type: str, target: str) -> Dict[str, Any]:
        plan = self._plan(action_type, target)
        return {"would": plan, "dry_run": True, "platform": self.name, "target": target}

    def validate_revert(self, plan: Any, ledger: Optional[Ledger] = None) -> Dict[str, Any]:
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
    tags_rules = True

    def __init__(self, *, quarantine_dir: str = "/var/lib/paddock-agent/quarantine",
                 runner: Optional[Runner] = None, hosts_path: str = "/etc/hosts",
                 protected_paths: Sequence[str] = ()) -> None:
        super().__init__(quarantine_dir=quarantine_dir, runner=runner, protected_paths=protected_paths)
        self.hosts_path = hosts_path

    # ------------------------------------------------------------------ #
    # plans (built only from guard-validated typed input)
    # ------------------------------------------------------------------ #
    @staticmethod
    def _rule(chain: str, match: List[str], tag: Optional[str]) -> Dict[str, List[str]]:
        """The insert / check / delete argument lists of one DROP rule. The comment tag is what lets the agent
        remove only its own rule and nobody else's."""
        body = list(match) + (["-m", "comment", "--comment", tag] if tag else []) + ["-j", "DROP"]
        return {"add": ["iptables", "-I", chain] + body, "check": ["iptables", "-C", chain] + body,
                "remove": ["iptables", "-D", chain] + body}

    def _plan(self, action_type: str, target: str, tag: Optional[str] = None) -> Dict[str, Any]:
        try:
            target = assert_host_local(action_type, target)
        except HostLocalError as exc:
            raise NotSupportedError("refused: %s" % exc)
        if action_type == "block_ip":
            if ipaddress.ip_address(target).version != 4:
                raise NotSupportedError(
                    "block_ip for an IPv6 address is not supported: the Linux enforcer drives iptables "
                    "(IPv4 only), so the block would never take effect. Refused, nothing applied.")
            inp = self._rule("INPUT", ["-s", target], tag)
            out = self._rule("OUTPUT", ["-d", target], tag)
            return {
                "mechanism": "iptables",
                "add": inp["add"], "add_out": out["add"],
                "check": inp["check"], "check_out": out["check"],
                "remove": inp["remove"], "remove_out": out["remove"],
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
            rule = self._rule(chain, ["-p", proto, "--dport", port], tag)
            return {"mechanism": "iptables", "add": rule["add"], "check": rule["check"],
                    "remove": rule["remove"]}
        if action_type == "quarantine_file":
            dest = self._quarantine_dest(target)
            return {"mechanism": "move-to-quarantine", "src": target, "dest": dest}
        raise NotSupportedError("unknown action_type %r" % (action_type,))

    def simulate(self, action_type: str, target: str, action_id: Optional[str] = None) -> Dict[str, Any]:
        tag = ("paddock:%s" % action_id) if action_id else SIMULATED_TAG
        plan = self._plan(action_type, target, tag=tag if action_type in ("block_ip", "firewall_rule") else None)
        return {"would": plan, "dry_run": True, "platform": self.name, "target": target}

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
    def apply(self, action_type: str, target: str, action_id: Optional[str] = None) -> Dict[str, Any]:
        """Make the change. Idempotent for one ``action_id`` (a crash can re-run it): iptables rules are checked
        with ``-C`` before ``-I``, the hosts line is not appended twice, an already-quarantined file is
        recognised."""
        target = self._canonical(action_type, target)
        tag = None
        if action_type in ("block_ip", "firewall_rule"):
            if action_id is not None:
                tag = "paddock:%s" % action_id
                if not _TAG_RE.match(tag):
                    raise NotSupportedError("the action id is not a UUID; refusing to tag a rule with it")
        plan = self._plan(action_type, target, tag=tag)
        if action_type in ("block_ip", "firewall_rule"):
            self._apply_iptables(plan, action_type, target, tag)
            commands = [plan["remove"]] + ([plan["remove_out"]] if "remove_out" in plan else [])
            revert = {"mechanism": "iptables", "action_type": action_type, "target": target,
                      "commands": commands}
            if tag:
                revert["tag"] = tag
            return {"output": {"plan": plan}, "revert": revert}
        if action_type == "block_domain":
            line = plan["line"]
            appended = self._append_hosts_line(plan["file"], line)
            return {"output": {"appended": line, "already_present": not appended},
                    "revert": {"mechanism": "hosts-sinkhole", "action_type": "block_domain",
                               "target": target, "file": plan["file"], "line": line}}
        if action_type == "quarantine_file":
            return self._apply_quarantine(plan, target)
        raise NotSupportedError(action_type)

    def _apply_iptables(self, plan: Dict[str, Any], action_type: str, target: str, tag: Optional[str]) -> None:
        inserted = []  # type: List[List[str]]
        try:
            for add_key, check_key in (("add", "check"), ("add_out", "check_out")):
                if add_key not in plan:
                    continue
                if self._present(plan[check_key]):
                    continue                              # already in place (a re-run): never a duplicate
                self._exec(plan[add_key])
                inserted.append(plan[add_key])
        except Exception as exc:  # noqa: BLE001 -- undo the half that went in, then report
            failed = []
            for cmd in reversed(inserted):
                try:
                    self._exec(["iptables", "-D"] + cmd[2:])
                except Exception as back:  # noqa: BLE001
                    failed.append(str(back))
            if failed:
                err = EnforcerError("%s; ROLLBACK FAILED, a rule may remain on this host: %s"
                                    % (exc, "; ".join(failed)))
                commands = [plan["remove"]] + ([plan["remove_out"]] if "remove_out" in plan else [])
                err.revert = {"mechanism": "iptables", "action_type": action_type, "target": target,  # type: ignore[attr-defined]
                              "commands": commands, **({"tag": tag} if tag else {})}
                raise err
            raise EnforcerError("%s; the part that was applied was rolled back" % exc)

    def _present(self, check_cmd: List[str]) -> bool:
        """``iptables -C``: True when the rule exists, False when it does not, an error for anything else."""
        res = self._run(check_cmd)
        if res.returncode == 0:
            return True
        if res.returncode == 1:
            return False
        raise EnforcerError("command failed (%s): %s :: %s" % (res.returncode, " ".join(check_cmd), res.stderr))

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

    # -- /etc/hosts --------------------------------------------------------- #
    def _hosts_target(self, path: str) -> str:
        """The file the sinkhole line really goes into. A plain file is itself. A SYMLINKED hosts file is written
        through (the link is never replaced by a regular file) but only when the final target is an existing
        regular file inside the directory that holds the configured hosts path (``/etc``); anything else is
        refused with a clear error and nothing is touched."""
        if not os.path.islink(path):
            return path
        real = os.path.realpath(path)
        root = os.path.realpath(os.path.dirname(os.path.abspath(path)))
        if os.path.dirname(real) != root and not real.startswith(root.rstrip("/") + "/"):
            raise EnforcerError("%s is a symlink to %s, outside %s; refusing to write through it (point it at a "
                                "file in that directory, or manage the sinkhole by hand)" % (path, real, root))
        try:
            st = os.stat(real)
        except OSError:
            raise EnforcerError("%s is a symlink to %s, which does not exist; refusing to create it" % (path, real))
        if not stat.S_ISREG(st.st_mode):
            raise EnforcerError("%s is a symlink to %s, which is not a regular file; refusing" % (path, real))
        return real

    def _append_hosts_line(self, path: str, line: str) -> bool:
        """Append ``line`` on a line of its own (never glued onto an unterminated last line), atomically and
        keeping the file's mode and owner (a symlinked file is written through, see :meth:`_hosts_target`).
        False when the exact line is already there."""
        path = self._hosts_target(path)
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except FileNotFoundError:
            data = b""
        want = line.encode("utf-8")
        if any(ln.strip() == want for ln in data.split(b"\n")):
            return False
        if data and not data.endswith(b"\n"):
            data += b"\n"
        _write_preserving(path, data + want + b"\n")
        return True

    def _remove_hosts_line(self, path: str, line: str) -> int:
        """Remove every line equal to ``line``; EnforcerError when there was none (nothing was reverted)."""
        path = self._hosts_target(path)
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except FileNotFoundError:
            raise EnforcerError("%s does not exist; there is no sinkhole line to remove" % path)
        want = line.encode("utf-8")
        parts = data.split(b"\n")            # split on \n ONLY: splitlines() also splits on \x0b \x0c U+2028 ...
        kept = [p for p in parts if p.strip() != want]
        removed = len(parts) - len(kept)
        if not removed:
            raise EnforcerError("the sinkhole line was not found in %s; nothing was removed" % path)
        _write_preserving(path, b"\n".join(kept))
        return removed

    # -- quarantine --------------------------------------------------------- #
    def _protected_roots(self) -> List[str]:
        roots = set()
        for p in tuple(DEFAULT_PROTECTED) + self.protected_paths + (self.quarantine_dir,):
            if not p:
                continue
            p = os.path.normpath(p)
            roots.add(p)
            roots.add(os.path.realpath(p))
        return sorted(roots)

    def _refuse_protected(self, path: str) -> None:
        for root in self._protected_roots():
            if path == root or path.startswith(root.rstrip("/") + "/"):
                raise EnforcerError("%s is inside %s, which the agent never quarantines" % (path, root))

    def _apply_quarantine(self, plan: Dict[str, Any], target: str) -> Dict[str, Any]:
        src, dest = plan["src"], plan["dest"]
        if os.path.normpath(src) != src:
            raise EnforcerError("quarantine_file needs a normalised path (no '//', '/./' or trailing '/'): %r" % src)
        self._refuse_protected(src)
        parent, name = os.path.split(src)
        try:
            pfd = _open_dir_nofollow(parent)
        except OSError as exc:
            raise EnforcerError("refusing %s: its directory is missing or reached through a symlink (%s); give "
                                "the real path" % (src, exc.strerror or exc))
        try:
            try:
                st = os.stat(name, dir_fd=pfd, follow_symlinks=False)
            except FileNotFoundError:
                done = self._already_quarantined(src)
                if done is not None:                 # a re-run after a crash: it was moved the first time
                    return done
                raise EnforcerError("cannot quarantine %s: it does not exist" % src)
            except OSError as exc:
                raise EnforcerError("cannot quarantine %s: %s" % (src, exc.strerror or exc))
            if not stat.S_ISREG(st.st_mode):
                raise EnforcerError("refusing %s: not a regular file (symlinks and directories are never "
                                    "quarantined)" % src)
            os.makedirs(self.quarantine_dir, mode=0o700, exist_ok=True)
            qfd = os.open(os.path.realpath(self.quarantine_dir), _DIR_FLAGS)
            try:
                dname = os.path.basename(dest)
                # write-ahead: a quarantined file always has a record (and what to check at restore)
                self._manifest_put(dname, src, {"uid": st.st_uid, "mode": stat.S_IMODE(st.st_mode)})
                try:
                    _move_nofollow(pfd, name, qfd, dname)
                except BaseException:
                    self._manifest_drop(dname)
                    raise
            finally:
                os.close(qfd)
        finally:
            os.close(pfd)
        return {"output": {"moved": {"src": src, "dest": dest}},
                "revert": {"mechanism": "move-to-quarantine", "action_type": "quarantine_file",
                           "target": src, "src": src, "dest": dest}}

    def _already_quarantined(self, src: str) -> Optional[Dict[str, Any]]:
        """The result of an earlier quarantine of ``src`` (this host's own manifest says it is in quarantine)."""
        found = [n for n, s0 in self._manifest().items()
                 if s0 == src and os.path.lexists(os.path.join(self.quarantine_dir, n))]
        if not found:
            return None
        dest = os.path.join(self.quarantine_dir, sorted(found)[-1])
        return {"output": {"moved": {"src": src, "dest": dest}, "already_quarantined": True},
                "revert": {"mechanism": "move-to-quarantine", "action_type": "quarantine_file",
                           "target": src, "src": src, "dest": dest}}

    # ------------------------------------------------------------------ #
    # revert: the server's plan is untrusted data
    # ------------------------------------------------------------------ #
    def validate_revert(self, plan: Any, ledger: Optional[Ledger] = None) -> Dict[str, Any]:
        if not isinstance(plan, dict):
            raise RevertRefused("revert plan is not an object")
        mech = plan.get("mechanism")
        if mech == "iptables":
            return self._validate_iptables(plan, ledger)
        if mech == "hosts-sinkhole":
            return self._validate_hosts(plan, ledger)
        if mech == "move-to-quarantine":
            return self._validate_quarantine(plan, ledger)
        raise RevertRefused("unknown revert mechanism %r" % (mech if isinstance(mech, str) else None))

    @staticmethod
    def _split_tag(cmd: List[str]) -> Tuple[List[str], Optional[str]]:
        """``cmd`` without its ``-m comment --comment <tag>`` triple, and the tag (shape-checked)."""
        if "-m" not in cmd and "--comment" not in cmd:
            return cmd, None
        i = len(cmd) - 6
        if i >= 0 and cmd[i:i + 3] == ["-m", "comment", "--comment"] and cmd[i + 4:] == ["-j", "DROP"] \
                and _TAG_RE.match(cmd[i + 3]):
            return cmd[:i] + cmd[i + 4:], cmd[i + 3]
        raise RevertRefused("revert commands are not a removal this agent could have created")

    def _typed_from_commands(self, commands: Any) -> Tuple[str, str, Optional[str]]:
        """The typed action (and tag) a removal command list could have come from, or :class:`RevertRefused`."""
        if (not isinstance(commands, list) or not 1 <= len(commands) <= 2
                or not all(isinstance(c, list) and all(isinstance(a, str) for a in c) for c in commands)):
            raise RevertRefused("revert commands must be one or two argument lists")
        first, tag = self._split_tag(commands[0])
        if len(first) == 7 and first[:4] == ["iptables", "-D", "INPUT", "-s"] and first[5:] == ["-j", "DROP"]:
            return "block_ip", first[4], tag
        if (len(first) == 9 and first[:2] == ["iptables", "-D"] and first[2] in ("INPUT", "OUTPUT")
                and first[3] == "-p" and first[5] == "--dport" and first[7:] == ["-j", "DROP"]):
            direction = "in" if first[2] == "INPUT" else "out"
            return "firewall_rule", "%s:%s:%s" % (direction, first[4], first[6]), tag
        raise RevertRefused("revert commands are not a removal this agent could have created")

    def _validate_iptables(self, plan: Dict[str, Any], ledger: Optional[Ledger] = None) -> Dict[str, Any]:
        at, tgt = plan.get("action_type"), plan.get("target")
        plan_tag = plan.get("tag") if isinstance(plan.get("tag"), str) else None
        if isinstance(at, str) and isinstance(tgt, str):
            if at not in ("block_ip", "firewall_rule"):
                raise RevertRefused("an iptables revert must come from block_ip or firewall_rule")
            if plan_tag is None and "commands" in plan:
                try:
                    _a, _t, plan_tag = self._typed_from_commands(plan.get("commands"))
                except RevertRefused:
                    pass                                   # the typed fields rule; the echo check below refuses
        else:
            at, tgt, cmd_tag = self._typed_from_commands(plan.get("commands"))
            if plan_tag is not None and cmd_tag is not None and plan_tag != cmd_tag:
                raise RevertRefused("revert tag differs from the tag in its commands")
            plan_tag = plan_tag or cmd_tag
        if plan_tag is not None and not _TAG_RE.match(plan_tag):
            raise RevertRefused("revert tag is not one this agent could have written")
        try:
            canon_target = assert_host_local(at, tgt)
            self._plan(at, canon_target)                   # typed validation (IPv4 only, port range, ...)
        except (HostLocalError, NotSupportedError) as exc:
            raise RevertRefused("revert target refused: %s" % exc)
        tag = plan_tag
        if ledger is not None:
            # a revert names the rule by the tag the agent wrote (paddock:<action id>): look THAT record up, so an
            # older block can be reverted while a newer one of the same target stays in force
            rule = ledger(at, canon_target, plan_tag) if plan_tag is not None else ledger(at, canon_target)
            if not isinstance(rule, dict):
                raise RevertRefused("no unreverted local record that this agent applied %s %s; refusing to "
                                    "remove a rule it did not create" % (at, canon_target))
            local_tag = rule.get("tag") if isinstance(rule.get("tag"), str) else None
            if plan_tag is not None and plan_tag != local_tag:
                raise RevertRefused("revert tag differs from this host's own record")
            tag = local_tag                                # the host's record, not the server's word
        derived = self._plan(at, canon_target, tag=tag)
        commands = [derived["remove"]] + ([derived["remove_out"]] if "remove_out" in derived else [])
        if "commands" in plan and plan["commands"] != commands:
            raise RevertRefused("revert commands differ from the plan this agent would have created")
        out = {"mechanism": "iptables", "action_type": at, "target": canon_target, "commands": commands}
        if tag:
            out["tag"] = tag
        return out

    def _validate_hosts(self, plan: Dict[str, Any], ledger: Optional[Ledger] = None) -> Dict[str, Any]:
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
        if ledger is not None and not isinstance(ledger("block_domain", domain), dict):
            raise RevertRefused("no unreverted local record that this agent blocked %s; refusing to edit "
                                "%s for it" % (domain, self.hosts_path))
        return {"mechanism": "hosts-sinkhole", "action_type": "block_domain", "target": domain,
                "file": self.hosts_path, "line": derived["line"]}

    def _validate_quarantine(self, plan: Dict[str, Any], ledger: Optional[Ledger] = None) -> Dict[str, Any]:
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
        if ledger is not None and not isinstance(ledger("quarantine_file", src), dict):
            raise RevertRefused("no unreverted local record that this agent quarantined %s" % src)
        return {"mechanism": "move-to-quarantine", "action_type": "quarantine_file", "target": src,
                "src": src, "dest": os.path.join(qdir, name)}

    def revert(self, plan: Any, ledger: Optional[Ledger] = None) -> Dict[str, Any]:
        safe = self.validate_revert(plan, ledger)         # raises RevertRefused: nothing below runs on a bad plan
        mech = safe["mechanism"]
        if mech == "iptables":
            removed, absent = [], []
            for cmd in safe["commands"]:
                if self._present(["iptables", "-C"] + cmd[2:]):   # only a rule that exists (tag included)
                    self._exec(cmd)
                    removed.append(cmd)
                else:
                    absent.append(cmd)
            if not removed:
                raise EnforcerError("no matching rule is present on this host; nothing was removed")
            out = {"reverted": removed}  # type: Dict[str, Any]
            if absent:
                out["absent"] = absent
            return out
        if mech == "hosts-sinkhole":
            self._remove_hosts_line(safe["file"], safe["line"])
            return {"reverted_line": safe["line"]}
        if mech == "move-to-quarantine":
            return self._restore_quarantine(safe)
        raise NotSupportedError("cannot revert mechanism %r" % mech)  # pragma: no cover

    def _restore_quarantine(self, safe: Dict[str, Any]) -> Dict[str, Any]:
        src, dest = safe["src"], safe["dest"]
        name = os.path.basename(dest)
        if os.path.normpath(src) != src:
            raise RevertRefused("the recorded restore path is not normalised")
        try:
            self._refuse_protected(src)
        except EnforcerError as exc:
            raise RevertRefused(str(exc))
        try:
            qfd = os.open(os.path.realpath(self.quarantine_dir), _DIR_FLAGS)
        except OSError:
            raise RevertRefused("the quarantine directory is missing")
        try:
            try:
                st = os.stat(name, dir_fd=qfd, follow_symlinks=False)
            except OSError:
                raise RevertRefused("the quarantined file is missing or not a regular file")
            if not stat.S_ISREG(st.st_mode):
                raise RevertRefused("the quarantined file is missing or not a regular file")
            meta = self._manifest_meta().get(name)
            if (not isinstance(meta, dict) or meta.get("uid") != st.st_uid
                    or meta.get("mode") != stat.S_IMODE(st.st_mode)):
                raise RevertRefused("the quarantined file's owner or mode differs from what this host recorded "
                                    "when it quarantined it; restore it by hand after inspecting it")
            parent, sname = os.path.split(src)
            try:
                pfd = _open_dir_nofollow(parent)
            except OSError:
                raise RevertRefused("the original directory of %s no longer exists (or is now reached through "
                                    "a symlink)" % src)
            try:
                try:
                    os.stat(sname, dir_fd=pfd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise RevertRefused("refusing to overwrite %s while restoring it" % src)
                _move_nofollow(qfd, name, pfd, sname)     # restore it exactly
            finally:
                os.close(pfd)
        finally:
            os.close(qfd)
        self._manifest_drop(name)
        return {"restored": {"src": src, "dest": dest}}

    # -- the host's own record of what it quarantined ------------------------ #
    def _manifest_path(self) -> str:
        return os.path.join(self.quarantine_dir, _MANIFEST_NAME)

    def _manifest_doc(self) -> Dict[str, Any]:
        try:
            with open(self._manifest_path(), "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError, AttributeError):
            return {}

    def _manifest(self) -> Dict[str, str]:
        items = self._manifest_doc().get("items", {})
        if not isinstance(items, dict):
            return {}
        return dict((k, v) for k, v in items.items() if isinstance(k, str) and isinstance(v, str))

    def _manifest_meta(self) -> Dict[str, Any]:
        meta = self._manifest_doc().get("meta", {})
        return meta if isinstance(meta, dict) else {}

    def _manifest_write(self, items: Dict[str, str], meta: Dict[str, Any]) -> None:
        atomic_write(self._manifest_path(),
                     json.dumps({"v": 1, "items": items, "meta": meta}, sort_keys=True).encode("utf-8"))

    def _manifest_put(self, name: str, src: str, meta: Optional[Dict[str, Any]] = None) -> None:
        items, metas = self._manifest(), dict(self._manifest_meta())
        items[name] = src
        if meta is not None:
            metas[name] = meta
        self._manifest_write(items, metas)

    def _manifest_drop(self, name: str) -> None:
        items, metas = self._manifest(), dict(self._manifest_meta())
        if name in items or name in metas:
            items.pop(name, None)
            metas.pop(name, None)
            self._manifest_write(items, metas)


# --------------------------------------------------------------------------- #
# low-level file helpers (symlink-safe moves, order-preserving /etc/hosts writes)
# --------------------------------------------------------------------------- #

_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)


def _open_dir_nofollow(path: str) -> int:
    """An fd for the absolute directory ``path``, opened one component at a time with ``O_NOFOLLOW`` so no
    component can be a symlink (OSError ELOOP / ENOTDIR otherwise)."""
    if not path.startswith("/"):
        raise OSError(errno.EINVAL, "not an absolute path")
    fd = os.open("/", _DIR_FLAGS)
    try:
        for comp in [c for c in path.split("/") if c]:
            nfd = os.open(comp, _DIR_FLAGS | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
            os.close(fd)
            fd = nfd
        return fd
    except BaseException:
        os.close(fd)
        raise


def _move_nofollow(sfd: int, sname: str, dfd: int, dname: str) -> None:
    """Move ``sname`` (in directory ``sfd``) to ``dname`` (in ``dfd``) without following a symlink anywhere:
    a ``dir_fd``-relative rename, or (across filesystems) a copy that preserves mode (setuid/setgid
    included), owner and times followed by an unlink of the source, or an :class:`EnforcerError` when it cannot."""
    try:
        os.rename(sname, dname, src_dir_fd=sfd, dst_dir_fd=dfd)
        return
    except OSError as exc:
        if exc.errno != errno.EXDEV:
            raise
    rflags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    rfd = os.open(sname, rflags, dir_fd=sfd)
    try:
        st = os.fstat(rfd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(errno.EINVAL, "not a regular file")
        wfd = os.open(dname, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                      | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=dfd)
        try:
            while True:
                chunk = os.read(rfd, 1 << 20)
                if not chunk:
                    break
                view = memoryview(chunk)
                while view:
                    view = view[os.write(wfd, view):]
            # owner FIRST, mode second: chown clears setuid / setgid, so the other order loses the bits
            want = stat.S_IMODE(st.st_mode)
            try:
                os.fchown(wfd, st.st_uid, st.st_gid)
            except OSError:
                pass                                       # not root: the restore check will notice a change
            got = os.fstat(wfd)
            if want & (stat.S_ISUID | stat.S_ISGID) and (got.st_uid, got.st_gid) != (st.st_uid, st.st_gid):
                # never leave a setuid / setgid copy that belongs to somebody else, and never drop the bits
                # silently: refuse (the source is untouched and the copy is removed below)
                raise EnforcerError(
                    "cannot move %s across filesystems: its owner (%d:%d) cannot be preserved, so its "
                    "setuid/setgid bits (mode %04o) would be lost or end up on another owner. Quarantine it "
                    "from a mount that allows a rename, or by hand" % (sname, st.st_uid, st.st_gid, want))
            os.fchmod(wfd, want)
            if stat.S_IMODE(os.fstat(wfd).st_mode) != want:
                raise EnforcerError("cannot move %s across filesystems: its mode %04o could not be preserved"
                                    % (sname, want))
            os.fsync(wfd)
        except BaseException:
            os.close(wfd)
            try:
                os.unlink(dname, dir_fd=dfd)
            except OSError:
                pass
            raise
        os.close(wfd)
    finally:
        os.close(rfd)
    try:
        os.utime(dname, ns=(st.st_atime_ns, st.st_mtime_ns), dir_fd=dfd, follow_symlinks=False)
    except (OSError, NotImplementedError):
        pass
    os.unlink(sname, dir_fd=sfd)


def _write_preserving(path: str, data: bytes) -> None:
    """Replace ``path`` atomically (temp file in the same directory + ``os.replace``) keeping its mode and
    owner. A bind-mounted file (a container's /etc/hosts) cannot be replaced: that one case writes in place."""
    try:
        st = os.stat(path)
        mode, uid, gid = stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid
    except FileNotFoundError:
        mode, uid, gid = 0o644, None, None
    parent = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=parent, prefix=".paddock-")
    try:
        os.fchmod(fd, mode)
        if uid is not None:
            try:
                os.fchown(fd, uid, gid)
            except OSError:
                pass
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except OSError as exc:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        if exc.errno != errno.EBUSY:
            raise
        log.warning("%s cannot be replaced (bind mount); writing it in place", path)
        with open(path, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class _StubEnforcer(BaseEnforcer):
    """Windows / macOS: can describe a plan, can NEVER apply (always dry-run)."""
    can_apply = False

    def _plan(self, action_type: str, target: str) -> Dict[str, Any]:
        return {"mechanism": "%s-not-implemented" % self.name, "action_type": action_type,
                "target": target, "note": "host-local enforcement on %s is not implemented" % self.name}

    def validate_revert(self, plan: Any, ledger: Optional[Ledger] = None) -> Dict[str, Any]:
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
                 runner: Optional[Runner] = None,
                 protected_paths: Optional[Sequence[str]] = None) -> BaseEnforcer:
    name = detect_platform(platform_name)
    cls = _ENFORCERS.get(name, WindowsEnforcer)  # unknown -> never-apply stub
    kwargs = {"runner": runner}  # type: Dict[str, Any]
    if quarantine_dir:
        kwargs["quarantine_dir"] = quarantine_dir
    if protected_paths:
        kwargs["protected_paths"] = tuple(protected_paths)
    return cls(**dict((k, v) for k, v in kwargs.items() if v is not None))
