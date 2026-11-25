"""Probe runner and collection context for the v2 collectors (Python 3.8 syntax only).

Two things live here:

* ``run_command``: the only way a collector executes a program. It returns
  ``{rc, out, err_tail, timed_out, missing, truncated}``; it never raises. The
  child gets a fixed PATH, ``LC_ALL=C``, no shell, stdin on /dev/null, an output
  cap, and is killed as a process group on timeout or overflow. The v1
  ``inventory._safe_run`` (which collapses "missing", "failed" and "empty" into
  ``""``) is not used by v2.
* ``Ctx``: everything a collector may depend on (clock, filesystem roots, the
  runner, privilege, caches). Collectors never touch the OS except through it, so
  tests inject a fake runner and a temporary root.

No floats are ever put into a payload; floats here are local timeouts only.
"""
import errno
import hashlib
import os
import selectors
import signal
import stat
import subprocess
import sys
import time

FIXED_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
DEFAULT_MAX_BYTES = 4 * 1024 * 1024
DEFAULT_TIMEOUT_S = 15.0
ERR_TAIL_CHARS = 512
_CHUNK = 65536

_CAP_DAC_READ_SEARCH = 2
_CAP_NET_ADMIN = 12
_CAP_SYS_PTRACE = 19


class CollectorTimeout(Exception):
    """Raised by ``Ctx.check()`` when a collector exhausted its time budget."""


def _clean_tail(raw):
    text = raw.decode("utf-8", "replace")
    text = "".join(c if (c >= " " and c != "\x7f") or c in "\n\t" else "?" for c in text)
    text = " ".join(text.split())
    return text[-ERR_TAIL_CHARS:]


def _kill_group(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except OSError:
            pass


def run_command(argv, timeout=DEFAULT_TIMEOUT_S, max_bytes=DEFAULT_MAX_BYTES, env=None):
    """Run ``argv`` and return ``{rc, out, err_tail, timed_out, missing, truncated}``.

    ``rc`` is None when the program never ran (``missing``) or did not exit
    normally. ``out`` is decoded UTF-8 (errors replaced) and capped at
    ``max_bytes``; hitting the cap kills the child and sets ``truncated``.
    ``env`` may add harmless variables; PATH and LC_ALL are always fixed.
    """
    res = {"rc": None, "out": "", "err_tail": "", "timed_out": False,
           "missing": False, "truncated": False}
    if not argv:
        res["missing"] = True
        return res
    exe = str(argv[0])
    if "/" not in exe:
        found = None
        for d in FIXED_PATH.split(":"):
            cand = os.path.join(d, exe)
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                found = cand
                break
        if found is None:
            res["missing"] = True
            return res
        exe = found
    environment = {"PATH": FIXED_PATH, "LC_ALL": "C", "LANG": "C", "TZ": "UTC"}
    for k, v in (env or {}).items():
        if k not in ("PATH", "LC_ALL", "LANG"):
            environment[str(k)] = str(v)
    try:
        proc = subprocess.Popen(  # noqa: S603 - argv list, shell=False, fixed env
            [exe] + [str(a) for a in argv[1:]],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=environment, shell=False, close_fds=True, start_new_session=True)
    except FileNotFoundError:
        res["missing"] = True
        return res
    except PermissionError:
        res["rc"] = 126
        res["err_tail"] = "permission denied"
        return res
    except OSError as exc:
        res["rc"] = 127
        res["err_tail"] = _clean_tail((exc.strerror or "os error").encode("utf-8", "replace"))
        return res

    deadline = time.monotonic() + max(0.05, float(timeout))
    out = bytearray()
    err = bytearray()
    sel = selectors.DefaultSelector()
    try:
        sel.register(proc.stdout, selectors.EVENT_READ, "out")
        sel.register(proc.stderr, selectors.EVENT_READ, "err")
        while sel.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                res["timed_out"] = True
                break
            for key, _ in sel.select(min(remaining, 0.25)):
                try:
                    chunk = os.read(key.fd, _CHUNK)
                except OSError as exc:
                    if exc.errno in (errno.EINTR, errno.EAGAIN):
                        continue
                    chunk = b""
                if not chunk:
                    sel.unregister(key.fileobj)
                    continue
                if key.data == "out":
                    room = max_bytes - len(out)
                    if len(chunk) > room:
                        out.extend(chunk[:max(room, 0)])
                        res["truncated"] = True
                    else:
                        out.extend(chunk)
                else:
                    err.extend(chunk)
                    if len(err) > 8192:
                        del err[:-4096]
            if res["truncated"]:
                break
        if not res["timed_out"] and not res["truncated"]:
            try:
                proc.wait(timeout=max(0.05, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                res["timed_out"] = True
    finally:
        sel.close()
        if res["timed_out"] or res["truncated"] or proc.poll() is None:
            _kill_group(proc)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        for stream in (proc.stdout, proc.stderr):
            try:
                stream.close()
            except OSError:
                pass
    res["rc"] = proc.returncode
    res["out"] = bytes(out).decode("utf-8", "replace")
    res["err_tail"] = _clean_tail(bytes(err[-2048:]))
    return res


class Ctx(object):
    """Collection context. The first eight arguments are the pinned interface."""

    def __init__(self, state_dir, agent_version, seq=0, key_id="", machine_salt=b"",
                 clock_skew_ms=None, enable_imds=False, now=None,
                 proc_root="/proc", host_root="/", runner=None, is_root=None,
                 containerised=None, collector_budget_s=90, total_budget_s=240, platform=None):
        self.state_dir = state_dir
        self.agent_version = str(agent_version)
        self.seq = int(seq)
        self.key_id = str(key_id)
        if isinstance(machine_salt, str):
            machine_salt = machine_salt.encode("utf-8")
        self.machine_salt = bytes(machine_salt or b"")
        self.clock_skew_ms = None if clock_skew_ms is None else int(clock_skew_ms)
        self.enable_imds = bool(enable_imds)
        self._now = now
        self.proc_root = proc_root
        self.host_root = host_root
        self._runner = runner or run_command
        self._is_root = is_root
        self._containerised = containerised
        self.collector_budget_s = int(collector_budget_s)
        self.total_budget_s = int(total_budget_s)
        # Set by the agent after the server acknowledged a manifest digest; None means
        # "the server has nothing", so the full package list is sent.
        self.known_manifest_sha = None
        self.force_full_manifest = False
        self.cache = {}
        self.stats = {}
        self.platform = platform or sys.platform
        self._deadline = None
        self._started = time.monotonic()
        self._cap_eff = "unset"

    # ------------------------------------------------------------------ clock
    def now_s(self):
        n = self._now
        if callable(n):
            n = n()
        if n is None:
            return int(time.time())
        if hasattr(n, "timestamp"):  # a datetime
            return int(n.timestamp())
        return int(n)

    def now_iso(self):
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.now_s()))

    # ----------------------------------------------------------------- budget
    def set_deadline(self, seconds):
        self._deadline = time.monotonic() + max(1, int(seconds))

    def clear_deadline(self):
        self._deadline = None

    def time_left(self):
        if self._deadline is None:
            return 3600.0
        return self._deadline - time.monotonic()

    def check(self):
        if self._deadline is not None and time.monotonic() >= self._deadline:
            raise CollectorTimeout("collector time budget exhausted")

    # ------------------------------------------------------------- execution
    def run(self, argv, timeout=DEFAULT_TIMEOUT_S, max_bytes=DEFAULT_MAX_BYTES):
        left = self.time_left()
        if left <= 0:
            return {"rc": None, "out": "", "err_tail": "", "timed_out": True,
                    "missing": False, "truncated": False}
        res = self._runner(list(argv), min(float(timeout), max(0.1, left)), int(max_bytes))
        out = {"rc": None, "out": "", "err_tail": "", "timed_out": False,
               "missing": False, "truncated": False}
        out.update(res or {})
        return out

    # ------------------------------------------------------------ filesystem
    def fs_path(self, path):
        if path == "/proc" or path.startswith("/proc/"):
            return self.proc_root + path[len("/proc"):]
        if self.host_root in ("", "/"):
            return path
        return self.host_root.rstrip("/") + "/" + path.lstrip("/")

    def read_bytes(self, path, max_bytes=1 << 20):
        """Return ``(status, data)``; status is ok|missing|denied|truncated|error."""
        try:
            with open(self.fs_path(path), "rb") as fh:
                data = fh.read(max_bytes + 1)
        except FileNotFoundError:
            return "missing", b""
        except NotADirectoryError:
            return "missing", b""
        except PermissionError:
            return "denied", b""
        except OSError:
            return "error", b""
        if len(data) > max_bytes:
            return "truncated", data[:max_bytes]
        return "ok", data

    def read_text(self, path, max_bytes=1 << 20):
        status, data = self.read_bytes(path, max_bytes)
        return status, data.decode("utf-8", "replace")

    def exists(self, path):
        return os.path.lexists(self.fs_path(path))

    def isfile(self, path):
        return os.path.isfile(self.fs_path(path))

    def isdir(self, path):
        return os.path.isdir(self.fs_path(path))

    def listdir(self, path):
        """Return ``(status, sorted names)``."""
        try:
            return "ok", sorted(os.listdir(self.fs_path(path)))
        except FileNotFoundError:
            return "missing", []
        except NotADirectoryError:
            return "missing", []
        except PermissionError:
            return "denied", []
        except OSError:
            return "error", []

    def readlink(self, path):
        """Return ``(status, target)``; status is ok|missing|denied|error."""
        try:
            return "ok", os.readlink(self.fs_path(path))
        except FileNotFoundError:
            return "missing", ""
        except PermissionError:
            return "denied", ""
        except OSError:
            return "error", ""

    def stat_key(self, path):
        """``(st_dev, st_ino, st_mtime_ns, st_size)`` following symlinks, else None."""
        try:
            st = os.stat(self.fs_path(path))
        except OSError:
            return None
        return (st.st_dev, st.st_ino, st.st_mtime_ns, st.st_size)

    def change_ns(self, path):
        """Newest of mtime and ctime in ns (following symlinks), else None. ctime cannot be set
        back by ``cp -p``, ``rsync -a``, ``tar`` or ``touch -d``: it shows a change they hide."""
        try:
            st = os.stat(self.fs_path(path))
        except OSError:
            return None
        return max(st.st_mtime_ns, st.st_ctime_ns)

    def link_change_ns(self, path):
        """``(ns, doubt)``: the newest change time (mtime or ctime of ``lstat``) of every symbolic link
        met while resolving ``path`` component by component, and whether the resolution cannot be
        trusted (a loop, more than 40 links, a link that cannot be read). ``change_ns`` follows links
        and so sees only the target: repointing a link (``ln -sf``) leaves the target untouched but
        creates a link whose own ctime is "now". ``ns`` is None when no link is on the path."""
        best = None
        doubt = False
        links = 0
        pending = [c for c in path.split("/") if c]
        cur = ""
        while pending:
            comp = pending.pop(0)
            if comp == ".":
                continue
            if comp == "..":
                cur = cur.rpartition("/")[0]
                continue
            nxt = cur + "/" + comp
            try:
                st = os.lstat(self.fs_path(nxt))
            except (FileNotFoundError, NotADirectoryError):
                break                                    # nothing below a missing component
            except OSError:
                doubt = True
                break
            if not stat.S_ISLNK(st.st_mode):
                cur = nxt
                continue
            t = max(st.st_mtime_ns, st.st_ctime_ns)
            best = t if best is None else max(best, t)
            links += 1
            lst, target = self.readlink(nxt)
            if links > 40 or lst != "ok" or not target:
                doubt = True
                break
            if target.startswith("/"):
                cur = ""
            pending = [c for c in target.split("/") if c] + pending
        return best, doubt

    def mtime_s(self, path):
        try:
            return int(os.stat(self.fs_path(path)).st_mtime)
        except OSError:
            return None

    def which(self, name, extra_dirs=()):
        """Absolute virtual path of an executable in the fixed PATH, else None."""
        dirs = list(extra_dirs) + FIXED_PATH.split(":")
        for d in dirs:
            cand = d.rstrip("/") + "/" + name
            real = self.fs_path(cand)
            if os.path.isfile(real) and os.access(real, os.X_OK):
                return cand
        return None

    def sha256_file(self, path, max_bytes=128 * 1024 * 1024):
        """Hex sha256 of a file, or None when it is missing/unreadable/over the cap."""
        h = hashlib.sha256()
        total = 0
        try:
            with open(self.fs_path(path), "rb") as fh:
                while True:
                    chunk = fh.read(1 << 20)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        return None
                    h.update(chunk)
        except OSError:
            return None
        return h.hexdigest()

    # -------------------------------------------------------------- privilege
    @property
    def is_root(self):
        if self._is_root is not None:
            return bool(self._is_root)
        try:
            return os.geteuid() == 0
        except AttributeError:
            return False

    def cap_eff(self):
        """Effective capability mask as an int, or None when unreadable."""
        if self._cap_eff == "unset":
            val = None
            status, text = self.read_text("/proc/self/status", 1 << 16)
            if status == "ok":
                for line in text.splitlines():
                    if line.startswith("CapEff:"):
                        try:
                            val = int(line.split(":", 1)[1].strip(), 16)
                        except ValueError:
                            val = None
                        break
            self._cap_eff = val
        return self._cap_eff

    def has_cap(self, bit):
        mask = self.cap_eff()
        if mask is None:
            return self.is_root
        return bool(mask >> bit & 1)

    @property
    def can_read_net_admin(self):
        return self.has_cap(_CAP_NET_ADMIN)

    @property
    def can_ptrace(self):
        return self.has_cap(_CAP_SYS_PTRACE) or self.has_cap(_CAP_DAC_READ_SEARCH)

    @property
    def containerised(self):
        if self._containerised is None:
            self._containerised = self._detect_container()
        return self._containerised

    def _detect_container(self):
        if self.exists("/.dockerenv") or self.exists("/run/.containerenv"):
            return True
        status, text = self.read_text("/proc/1/cgroup", 1 << 16)
        if status == "ok":
            low = text.lower()
            for token in ("docker", "kubepods", "containerd", "/lxc/", "libpod", "crio-"):
                if token in low:
                    return True
        status, data = self.read_bytes("/proc/1/environ", 1 << 16)
        if status == "ok":
            for item in data.split(b"\0"):
                if item.startswith(b"container="):
                    return True
        return False
