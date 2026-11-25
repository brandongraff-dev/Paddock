"""self-health collector: the agent describing itself (sent even when every collector fails).

Never contains the raw machine id (only a salted hash), never any file contents. The
server uses it to tell a collector error (field-level UNKNOWN) from agent silence
(everything UNKNOWN). Python 3.8 syntax only.
"""
import hashlib
import platform as _platform
import re

from . import base
from .base import clean_str

_UUID_RE = re.compile(r"^[0-9a-fA-F-]{8,40}$")


def machine_id_hash(salt, machine_id):
    """Hex sha256 over ``salt + b"\\n" + machine_id`` (never the raw id)."""
    h = hashlib.sha256()
    h.update(bytes(salt))
    h.update(b"\n")
    h.update(machine_id.strip().encode("utf-8", "replace"))
    return h.hexdigest()


def collect(ctx):
    boot_id = None
    st, text = ctx.read_text("/proc/sys/kernel/random/boot_id", 64)
    if st == "ok" and _UUID_RE.match(text.strip()):
        boot_id = text.strip().lower()
    mid_hash = None
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        st, text = ctx.read_text(path, 256)
        if st == "ok" and text.strip():
            mid_hash = machine_id_hash(ctx.machine_salt, text)
            break
    uptime = None
    st, text = ctx.read_text("/proc/uptime", 128)
    if st == "ok":
        head = text.split()[0] if text.split() else ""
        m = re.match(r"^(\d+)", head)
        if m:
            uptime = int(m.group(1))
    mask = ctx.cap_eff()
    caps = {
        "cap_eff": None if mask is None else "%016x" % mask,
        "net_admin": ctx.has_cap(12),
        "sys_ptrace": ctx.has_cap(19),
        "dac_read_search": ctx.has_cap(2),
    }
    collectors = {}
    for name in sorted(ctx.stats):
        s = ctx.stats[name]
        collectors[name] = {"status": s["status"], "ms": int(s["ms"]),
                            "reason": s.get("reason")}
    v = {
        "agent_version": clean_str(ctx.agent_version, 32),
        "python": _platform.python_version(),
        "platform": clean_str(ctx.platform, 16),
        "collectors": collectors,
        "caps": caps,
        "is_root": bool(ctx.is_root),
        "containerised": bool(ctx.containerised),
        "boot_id": boot_id,
        "machine_id_hash": mid_hash,
        "uptime_s": uptime,
        "seq": int(ctx.seq),
        "key_id": clean_str(ctx.key_id, 64),
        "payload_bytes": int(ctx.cache.get("data_bytes", 0)),
        "clock_skew_ms": ctx.clock_skew_ms,
        "imds_enabled": bool(ctx.enable_imds),
    }
    return base.ok(v, conf="exact", partial=False)
