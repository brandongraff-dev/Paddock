"""On-disk agent state: key, credentials, write-ahead sequence counter, outbox, handled actions.

Layout under the state directory (default ``/var/lib/paddock-agent``, mode 0700, owned by the user
the agent runs as)::

    keys/ed25519.key       the active Ed25519 seed + key id (0600)
    keys/ed25519.pending   a key that is being enrolled/rotated to (0600), see agent.py
    credentials.json       agent id, tenant id, server, ``fat_`` token (0600)
    seq                    the last sequence number handed out (write-ahead, fsynced)
    outbox/                gzip envelopes/results that could not be delivered yet
    handled.json           ids + results of server actions already carried out (and the rule each applied)
    .state.lock            flock around every read-modify-write of seq / handled.json / the key files
    .instance.lock         held for the daemon's whole life (one daemon per state dir); holds its pid

Every secret is written with ``mkstemp`` + ``fchmod 0600`` + ``fsync`` + ``os.replace`` + directory
fsync, so there is never a world-readable window and a crash leaves either the old or the new file.
Every secret is **refused on read** when it is group/world accessible, not owned by the running user,
or lives in a state directory other users can write to. Python 3.8 compatible, stdlib only.
"""
import contextlib
import errno
import gzip
import json
import logging
import os
import stat
import tempfile
import threading
import time

from . import envelope, signing

try:                       # POSIX only; on other platforms the locks degrade to no-ops
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None

log = logging.getLogger("paddock-agent.state")

DEFAULT_STATE_DIR = "/var/lib/paddock-agent"
MAX_SEQ = envelope.MAX_SEQ  # 2**53-1: the largest integer RFC 8785 (IEEE doubles) prints exactly
LOCK_WAIT_S = 30.0          # how long a state mutation waits for another process before giving up


class StateError(RuntimeError):
    """The state directory or a file in it is unusable. Never retried silently."""


class InstanceBusy(StateError):
    """Another agent process holds this state directory. ``pid`` is its pid when it recorded one."""

    def __init__(self, message, pid=None):
        super(InstanceBusy, self).__init__(message)
        self.pid = pid


# --------------------------------------------------------------------------- #
# low level
# --------------------------------------------------------------------------- #

def _fsync_dir(path):
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def atomic_write(path, data, mode=0o600):
    """Write ``data`` (bytes) to ``path`` atomically with ``mode`` from the first byte."""
    path = str(path)
    parent = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=parent, prefix=".tmp-")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    _fsync_dir(parent)


def check_secret_file(path):
    """Raise :class:`StateError` unless ``path`` is a regular file only its owner can touch."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise StateError("cannot stat %s: %s" % (path, exc))
    if not stat.S_ISREG(st.st_mode):
        raise StateError("%s is not a regular file" % path)
    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o077:
        raise StateError("%s is accessible by other users (mode %04o); run: chmod 600 %s"
                         % (path, mode, path))
    if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
        raise StateError("%s is owned by uid %d, not by the agent user (uid %d)"
                         % (path, st.st_uid, os.geteuid()))


def read_secret(path):
    """Bytes of a secret file, or ``None`` when it does not exist; refuses loose permissions."""
    try:
        check_secret_file(path)
    except FileNotFoundError:
        return None
    try:
        with open(path, "rb") as fh:
            return fh.read(1024 * 1024)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise StateError("cannot read %s: %s" % (path, exc))


def _loads(data, what):
    try:
        out = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeError):
        raise StateError("%s is not valid JSON; re-enroll this host" % what)
    if not isinstance(out, dict):
        raise StateError("%s is not a JSON object; re-enroll this host" % what)
    return out


# --------------------------------------------------------------------------- #
# credentials
# --------------------------------------------------------------------------- #

class Credentials(object):
    def __init__(self, agent_id, agent_token, tenant_id, server, hostname, key_id="", enrolled_at=""):
        self.agent_id = agent_id
        self.agent_token = agent_token
        self.tenant_id = tenant_id
        self.server = server
        self.hostname = hostname
        self.key_id = key_id
        self.enrolled_at = enrolled_at

    def to_json(self):
        return {"v": 2, "agent_id": self.agent_id, "agent_token": self.agent_token,
                "tenant_id": self.tenant_id, "server": self.server, "hostname": self.hostname,
                "key_id": self.key_id, "enrolled_at": self.enrolled_at}

    def __repr__(self):  # never print the token
        return "Credentials(agent_id=%r, tenant_id=%r, server=%r, hostname=%r)" % (
            self.agent_id, self.tenant_id, self.server, self.hostname)


# --------------------------------------------------------------------------- #
# outbox (port of sentry/paddock_sentry/buffer.py)
# --------------------------------------------------------------------------- #

class Outbox(object):
    """Bounded on-disk queue of items waiting for delivery (gzip JSON, one file each).

    When the byte cap would be exceeded the **oldest** items are evicted first (newest data is the most
    useful, and a host offline for weeks must not fill its disk). Evictions are counted in ``dropped``.
    """

    def __init__(self, path, max_bytes=64 * 1024 * 1024):
        self.path = str(path)
        self.max_bytes = int(max_bytes)
        self.dropped = 0
        self._last_ns = 0
        self._ready = False

    def _ensure(self):
        if self._ready:
            return
        os.makedirs(self.path, mode=0o700, exist_ok=True)
        for name in os.listdir(self.path):
            if name.endswith(".tmp"):          # a crash mid-write
                _unlink(os.path.join(self.path, name))
        self._ready = True

    def files(self):
        try:
            names = sorted(n for n in os.listdir(self.path) if n.endswith(".json.gz"))
        except FileNotFoundError:
            return []
        return [os.path.join(self.path, n) for n in names]

    def __len__(self):
        return len(self.files())

    def size(self):
        total = 0
        for f in self.files():
            try:
                total += os.stat(f).st_size
            except OSError:
                pass
        return total

    def put(self, item):
        """Store a JSON-able dict; returns how many older items were evicted to fit."""
        self._ensure()
        ns = max(time.time_ns(), self._last_ns + 1)   # strictly increasing: oldest-first order
        self._last_ns = ns
        final = os.path.join(self.path, "%020d.json.gz" % ns)
        raw = gzip.compress(json.dumps(item, separators=(",", ":"), sort_keys=True).encode("utf-8"),
                            6, mtime=0)
        fd, tmp = tempfile.mkstemp(dir=self.path, prefix=".tmp-", suffix=".tmp")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(raw)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, final)
        except BaseException:
            _unlink(tmp)
            raise
        return self._enforce_cap()

    def _enforce_cap(self):
        files = self.files()
        sizes = {}
        for f in files:
            try:
                sizes[f] = os.stat(f).st_size
            except OSError:
                sizes[f] = 0
        total = sum(sizes.values())
        evicted = 0
        while files and total > self.max_bytes:
            victim = files.pop(0)               # oldest first
            total -= sizes[victim]
            _unlink(victim)
            evicted += 1
        self.dropped += evicted
        if evicted:
            log.warning("outbox full (cap %d bytes): dropped %d oldest item(s)", self.max_bytes, evicted)
        return evicted

    def read(self, path):
        """One buffered item; a corrupt file is removed and skipped (returns ``None``)."""
        try:
            with gzip.open(path, "rb") as fh:
                data = fh.read(MAX_OUTBOX_ITEM)
            item = json.loads(data.decode("utf-8"))
            if not isinstance(item, dict):
                raise ValueError("not an object")
            return item
        except FileNotFoundError:
            return None
        except (OSError, EOFError, ValueError):
            log.warning("discarding unreadable outbox item %s", os.path.basename(path))
            _unlink(path)
            return None

    def delete(self, path):
        _unlink(path)


MAX_OUTBOX_ITEM = 16 * 1024 * 1024


def _unlink(path):
    try:
        os.unlink(path)
    except OSError:
        pass


def _release(fd):
    try:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_UN)
    except (IOError, OSError):
        pass
    try:
        os.close(fd)
    except OSError:
        pass


def _read_pid(fd):
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        raw = os.read(fd, 32).decode("ascii", "replace").strip()
        pid = int(raw)
        return pid if pid > 1 else None
    except (OSError, ValueError):
        return None


# --------------------------------------------------------------------------- #
# the state directory
# --------------------------------------------------------------------------- #

class State(object):
    def __init__(self, state_dir=None, outbox_max_bytes=64 * 1024 * 1024):
        self.dir = str(state_dir or DEFAULT_STATE_DIR)
        self.keys_dir = os.path.join(self.dir, "keys")
        self.key_path = os.path.join(self.keys_dir, "ed25519.key")
        self.pending_key_path = os.path.join(self.keys_dir, "ed25519.pending")
        self.cred_path = os.path.join(self.dir, "credentials.json")
        self.seq_path = os.path.join(self.dir, "seq")
        self.handled_path = os.path.join(self.dir, "handled.json")
        self.lock_path = os.path.join(self.dir, ".state.lock")
        self.instance_path = os.path.join(self.dir, ".instance.lock")
        self.outbox = Outbox(os.path.join(self.dir, "outbox"), outbox_max_bytes)
        self._rlock = threading.RLock()
        self._lock_fd = None
        self._instance_fd = None

    # -- directory ---------------------------------------------------------- #
    def ensure_dir(self):
        """Create the state directory (0700) and refuse one other users can write to."""
        try:
            os.makedirs(self.dir, mode=0o700, exist_ok=True)
            os.makedirs(self.keys_dir, mode=0o700, exist_ok=True)
            st = os.stat(self.dir)
        except OSError as exc:
            raise StateError("cannot use state directory %s: %s" % (self.dir, exc))
        if not stat.S_ISDIR(st.st_mode):
            raise StateError("%s is not a directory" % self.dir)
        if stat.S_IMODE(st.st_mode) & 0o022:
            raise StateError("state directory %s is writable by other users (mode %04o); run: "
                             "chmod 700 %s" % (self.dir, stat.S_IMODE(st.st_mode), self.dir))
        if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
            raise StateError("state directory %s is not owned by the agent user" % self.dir)

    # -- locks -------------------------------------------------------------- #
    @contextlib.contextmanager
    def exclusive(self):
        """Exclusive, re-entrant lock on the state directory (``flock``), for every read-modify-write.

        Two processes (the daemon and `paddock rotate-key`, say) can never reserve the same sequence number or
        interleave a key change. Waits up to ``LOCK_WAIT_S`` and then raises :class:`StateError` (the run
        loop treats that as a retry), so a stuck process cannot freeze the daemon for good."""
        with self._rlock:
            outer = self._lock_fd is None
            if outer:
                self._lock_fd = self._acquire(self.lock_path, wait=True)
            try:
                yield
            finally:
                if outer:
                    fd, self._lock_fd = self._lock_fd, None
                    if fd is not None:
                        _release(fd)

    def _acquire(self, path, wait):
        if fcntl is None:                                  # pragma: no cover
            return None
        self.ensure_dir()
        try:
            fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0), 0o600)
        except OSError as exc:
            raise StateError("cannot open the lock file %s: %s" % (path, exc))
        deadline = time.monotonic() + LOCK_WAIT_S
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return fd
            except (IOError, OSError) as exc:
                if exc.errno not in (errno.EAGAIN, errno.EACCES, errno.EWOULDBLOCK):
                    os.close(fd)
                    raise StateError("cannot lock %s: %s" % (path, exc))
                if not wait or time.monotonic() >= deadline:
                    os.close(fd)
                    raise StateError("the state directory %s is locked by another process" % self.dir)
            time.sleep(0.002)

    def acquire_instance(self):
        """Claim the state directory for a daemon (non-blocking); records this pid. :class:`InstanceBusy` if taken."""
        if fcntl is None:                                  # pragma: no cover
            return
        self.ensure_dir()
        fd = os.open(self.instance_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0), 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (IOError, OSError) as exc:
            pid = _read_pid(fd)
            os.close(fd)
            if exc.errno in (errno.EAGAIN, errno.EACCES, errno.EWOULDBLOCK):
                raise InstanceBusy("another paddock agent is already running on %s%s"
                                   % (self.dir, " (pid %d)" % pid if pid else ""), pid=pid)
            raise StateError("cannot lock %s: %s" % (self.instance_path, exc))
        os.ftruncate(fd, 0)
        os.write(fd, ("%d\n" % os.getpid()).encode("ascii"))
        self._instance_fd = fd

    def release_instance(self):
        fd, self._instance_fd = self._instance_fd, None
        if fd is not None:
            _release(fd)

    def daemon_pid(self):
        """The pid of the daemon holding this state directory right now, or ``None``."""
        if fcntl is None:                                  # pragma: no cover
            return None
        try:
            fd = os.open(self.instance_path, os.O_RDWR | getattr(os, "O_CLOEXEC", 0))
        except OSError:
            return None
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except (IOError, OSError):
                return _read_pid(fd)                       # held by someone: that is the daemon
            fcntl.flock(fd, fcntl.LOCK_UN)
            return None
        finally:
            os.close(fd)

    # -- credentials -------------------------------------------------------- #
    def load_credentials(self):
        data = read_secret(self.cred_path)
        if data is None:
            return None
        d = _loads(data, self.cred_path)
        try:
            return Credentials(
                agent_id=str(d["agent_id"]), agent_token=str(d["agent_token"]),
                tenant_id=str(d["tenant_id"]), server=str(d.get("server", "")),
                hostname=str(d.get("hostname", "")), key_id=str(d.get("key_id", "")),
                enrolled_at=str(d.get("enrolled_at", "")))
        except KeyError as exc:
            raise StateError("%s lacks %s; re-enroll this host (v1 credentials are not valid)"
                             % (self.cred_path, exc))

    def save_credentials(self, creds):
        self.ensure_dir()
        atomic_write(self.cred_path, json.dumps(creds.to_json(), indent=2).encode("utf-8"))

    # -- keys --------------------------------------------------------------- #
    @staticmethod
    def _encode_key(seed):
        pub = signing.public_key(seed)
        return json.dumps({"v": 1, "alg": "ed25519", "seed_b64": envelope.b64u(seed),
                           "key_id": signing.key_id(pub)}).encode("utf-8")

    def _load_key_file(self, path):
        data = read_secret(path)
        if data is None:
            return None
        d = _loads(data, path)
        try:
            seed = envelope.b64u_decode(str(d["seed_b64"]))
            if len(seed) != 32 or d.get("alg") != "ed25519":
                raise ValueError("bad key")
            kid = signing.key_id(signing.public_key(seed))
            if d.get("key_id") != kid:
                raise ValueError("key id mismatch")
        except (KeyError, ValueError, envelope.EnvelopeError):
            raise StateError("%s is corrupt; re-enroll this host" % path)
        return seed

    def load_key(self):
        """The active 32-byte seed, or ``None``."""
        return self._load_key_file(self.key_path)

    def load_pending_key(self):
        return self._load_key_file(self.pending_key_path)

    def save_key(self, seed):
        self.ensure_dir()
        atomic_write(self.key_path, self._encode_key(seed))

    def save_pending_key(self, seed):
        self.ensure_dir()
        atomic_write(self.pending_key_path, self._encode_key(seed))

    def promote_pending_key(self):
        """Make the pending key the active one (atomic rename)."""
        if self.load_pending_key() is None:
            raise StateError("there is no pending key to promote")
        os.replace(self.pending_key_path, self.key_path)
        _fsync_dir(self.keys_dir)

    def discard_pending_key(self):
        _unlink(self.pending_key_path)
        _fsync_dir(self.keys_dir)

    # -- write-ahead sequence ---------------------------------------------- #
    def current_seq(self):
        data = read_secret(self.seq_path)
        if data is None:
            return 0
        try:
            val = json.loads(data.decode("utf-8"))["seq"]
        except (ValueError, KeyError, TypeError, UnicodeError):
            raise StateError("%s is corrupt; the sequence counter cannot be trusted, re-enroll this host"
                             % self.seq_path)
        if isinstance(val, bool) or not isinstance(val, int) or val < 0 or val > MAX_SEQ:
            raise StateError("%s holds an invalid counter; re-enroll this host" % self.seq_path)
        return val

    def _write_seq(self, value):
        self.ensure_dir()
        atomic_write(self.seq_path, json.dumps({"seq": int(value)}).encode("utf-8"))

    def next_seq(self):
        """Reserve the next sequence number. The incremented value is fsynced BEFORE this returns, so a
        crash after the send can only skip a number, never reuse one (write-ahead)."""
        with self.exclusive():
            value = self.current_seq() + 1
            if value > MAX_SEQ:
                raise StateError("sequence counter exhausted; re-enroll this host")
            self._write_seq(value)
            return value

    def fast_forward(self, next_value):
        """Make the NEXT reserved number at least ``next_value`` (used after a 409 ``expected_min``).

        It can only raise the counter, never lower it, so it can never cause a reuse."""
        if isinstance(next_value, bool) or not isinstance(next_value, int):
            return False
        if next_value < 1 or next_value > MAX_SEQ:
            return False
        with self.exclusive():
            if next_value - 1 > self.current_seq():
                self._write_seq(next_value - 1)
                return True
            return False

    # -- handled actions ---------------------------------------------------- #
    def load_handled(self):
        data = read_secret(self.handled_path)
        if data is None:
            return {}
        try:
            d = _loads(data, self.handled_path)
        except StateError:
            return {}
        items = d.get("items")
        return items if isinstance(items, dict) else {}

    def save_handled(self, items, keep=256):
        """Persist ``items``. The newest ``keep`` stay, and so does every record whose rule is still applied on
        the host (unreverted): trimming one would make a live block impossible to revert (agent-4)."""
        order = sorted(items, key=lambda k: items[k].get("at", 0))
        trimmed = dict((k, items[k]) for k in order[-keep:])
        for k in order[:-keep] if keep else order:
            rule = items[k].get("rule")
            if isinstance(rule, dict) and not rule.get("reverted") and not items[k].get("reverted"):
                trimmed[k] = items[k]
        self.ensure_dir()
        atomic_write(self.handled_path,
                     json.dumps({"v": 1, "items": trimmed}, sort_keys=True).encode("utf-8"))
