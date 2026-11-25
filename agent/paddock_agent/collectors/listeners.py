"""listeners collector: listening TCP and bound UDP sockets from ``/proc`` (stdlib only).

Existence needs no privilege (``/proc/net/*`` is world readable); attribution
(pid, exe, sha256, unit) needs root or CAP_SYS_PTRACE and is reported per field as
``null`` plus an ``attribution`` summary, never as a missing listener. Command lines,
environments and arguments are never read. Python 3.8 syntax only.
"""
import ipaddress
import re
import sys

from . import base
from .base import clean_str

MAX_LISTENERS = 2000
ATTRIB_RESERVE_S = 5      # stop attributing sockets to pids when this little collector time is left
EXE_HASH_CAP = 128 * 1024 * 1024
_HASH_CACHE = {}
_HASH_CACHE_MAX = 512
_CONTAINER_RE = re.compile(r"(?<![0-9a-f])([0-9a-f]{64})(?![0-9a-f])")
_UNIT_OK = re.compile(r"^[A-Za-z0-9:_.\\@-]{1,96}$")
_TCP_LISTEN = "0A"
_UDP_BOUND = "07"


def decode_addr(hexaddr):
    """Decode a ``/proc/net`` hex address. Returns ``(ip_string, family)`` (family 4 or 6).

    The kernel prints each 32-bit word of the address in HOST byte order: reversed on a
    little-endian host, already in network order on a big-endian one (s390x, ppc64 BE). IPv4 is one
    word, IPv6 is four. An IPv4-mapped IPv6 address is returned as the plain IPv4 string.
    """
    raw = bytes.fromhex(hexaddr)
    little = sys.byteorder == "little"
    if len(raw) == 4:
        return str(ipaddress.IPv4Address(raw[::-1] if little else raw)), 4
    if len(raw) == 16:
        packed = b"".join(raw[i:i + 4][::-1] if little else raw[i:i + 4] for i in range(0, 16, 4))
        a6 = ipaddress.IPv6Address(packed)
        if a6.ipv4_mapped is not None:
            return str(a6.ipv4_mapped), 4
        return str(a6), 6
    raise ValueError("bad address length")


def bind_class(ip, fam):
    if fam == 4:
        if ip == "0.0.0.0":
            return "wildcard4"
        if ip.startswith("127."):
            return "loopback"
        return "specific"
    if ip == "::":
        return "wildcard6"
    if ip == "::1":
        return "loopback"
    return "specific"


def parse_proc_net(text, proto, family):
    """Parse a ``/proc/net/{tcp,tcp6,udp,udp6}`` body.

    Returns ``(rows, bad_lines)``. ``rows`` are listening TCP (state 0A) or bound,
    unconnected UDP (state 07, zero remote) sockets:
    ``{proto, ip, port, fam, bind_class, uid, inode}``. ``bad_lines`` counts data lines
    that could not be parsed (so a caller can mark the table partial).
    """
    rows = []
    bad = 0
    for n, line in enumerate(text.splitlines()):
        parts = line.split()
        if not parts or (n == 0 and parts[0] == "sl"):
            continue
        if len(parts) < 10 or not parts[0].endswith(":"):
            bad += 1
            continue
        try:
            lhex, lport = parts[1].split(":")
            rhex, rport = parts[2].split(":")
            state = parts[3].upper()
            if proto == "tcp":
                if state != _TCP_LISTEN:
                    continue
            else:
                if state != _UDP_BOUND:
                    continue
                if int(rport, 16) != 0 or int(rhex, 16) != 0:
                    continue
            ip, fam = decode_addr(lhex)
            row = {"proto": proto, "ip": ip, "port": int(lport, 16), "fam": fam,
                   "bind_class": bind_class(ip, fam), "uid": int(parts[7]),
                   "inode": int(parts[9])}
        except (ValueError, IndexError):
            bad += 1
            continue
        if not 0 < row["port"] < 65536:
            if row["port"] != 0:
                bad += 1
            continue
        rows.append(row)
    return rows, bad


def _priority(row):
    """Sample rank when the table is over the cap: 0 wildcard or privileged non-loopback binds,
    1 other non-loopback binds, 2 loopback."""
    if row["bind_class"] == "loopback":
        return 2
    if row["bind_class"] in ("wildcard4", "wildcard6") or row["port"] < 1024:
        return 0
    return 1


def parse_cgroup(text):
    """``(unit, container_short_id)`` from a ``/proc/PID/cgroup`` body (either may be None)."""
    paths = []
    for line in text.splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3:
            paths.append((parts[1], parts[2]))
    chosen = None
    for ctrl, path in paths:
        if ctrl == "":
            chosen = path
            break
    if chosen is None:
        for ctrl, path in paths:
            if "name=systemd" in ctrl.split(","):
                chosen = path
                break
    if chosen is None and paths:
        chosen = paths[0][1]
    container = None
    for _ctrl, path in paths:
        m = _CONTAINER_RE.search(path)
        if m:
            container = m.group(1)[:12]
            break
    unit = None
    if chosen:
        comps = [c for c in chosen.split("/") if c]
        for kind in (".service", ".scope"):
            for comp in reversed(comps):
                if comp.endswith(kind):
                    if kind == ".scope" and _CONTAINER_RE.search(comp):
                        continue
                    if _UNIT_OK.match(comp):
                        unit = comp
                    break
            if unit:
                break
    return unit, container


def _exe_hash(ctx, pid):
    key = ctx.stat_key("/proc/%d/exe" % pid)
    if key is None:
        return None
    if key[3] > EXE_HASH_CAP:
        return None
    hit = _HASH_CACHE.get(key)
    if hit is not None:
        return hit
    digest = ctx.sha256_file("/proc/%d/exe" % pid, EXE_HASH_CAP)
    if digest is not None:
        if len(_HASH_CACHE) >= _HASH_CACHE_MAX:
            _HASH_CACHE.clear()
        _HASH_CACHE[key] = digest
    return digest


def _map_inodes(ctx, wanted):
    """``(inode -> sorted pids, unreadable_pid_count, complete)``. ``complete`` is False when the
    scan stopped early because the collector's time budget was nearly spent."""
    found = {}
    unreadable = 0
    status, names = ctx.listdir("/proc")
    if status != "ok":
        return found, -1, True
    pids = sorted(int(n) for n in names if n.isdigit())
    for i, pid in enumerate(pids):
        if i % 50 == 0:
            if ctx.time_left() < ATTRIB_RESERVE_S:
                return found, unreadable, False
            ctx.check()
        st, fds = ctx.listdir("/proc/%d/fd" % pid)
        if st == "denied":
            unreadable += 1
            continue
        if st != "ok":
            continue
        for fd in fds:
            ls, target = ctx.readlink("/proc/%d/fd/%s" % (pid, fd))
            if ls != "ok" or not target.startswith("socket:["):
                continue
            try:
                inode = int(target[8:-1])
            except ValueError:
                continue
            if inode in wanted:
                lst = found.setdefault(inode, [])
                if pid not in lst:
                    lst.append(pid)
    return found, unreadable, True


def map_inodes(ctx, wanted):
    """Map socket inodes to pids. Returns ``(inode -> sorted pids, unreadable_pid_count)``."""
    found, unreadable, _complete = _map_inodes(ctx, wanted)
    return found, unreadable


def _proc_facts(ctx, pid):
    comm = None
    st, text = ctx.read_text("/proc/%d/comm" % pid, 64)
    if st == "ok":
        comm = clean_str(text.strip(), 16) or None
    exe, deleted = None, False
    st, target = ctx.readlink("/proc/%d/exe" % pid)
    if st == "ok":
        if target.endswith(" (deleted)"):
            deleted = True
            target = target[:-len(" (deleted)")]
        exe = clean_str(target, 256)
    sha = _exe_hash(ctx, pid) if exe is not None else None
    unit = container = None
    st, text = ctx.read_text("/proc/%d/cgroup" % pid, 1 << 15)
    if st == "ok":
        unit, container = parse_cgroup(text)
    return {"comm": comm, "exe": exe, "exe_deleted": deleted, "exe_sha256": sha,
            "unit": unit, "container": container}


def collect(ctx):
    if not ctx.platform.startswith("linux"):
        return base.unavailable("unsupported_platform")
    if ctx.containerised:
        return base.unavailable("containerised_agent")
    rows = []
    bad = 0
    partial = False
    ipv6 = False
    for fname, proto, fam in (("tcp", "tcp", 4), ("tcp6", "tcp", 6),
                              ("udp", "udp", 4), ("udp6", "udp", 6)):
        st, text = ctx.read_text("/proc/net/" + fname, 1 << 23)
        if st == "missing":
            if fname == "tcp":
                return base.unavailable("unsupported_platform")
            if fname == "udp":
                partial = True
            continue
        if st == "denied":
            return base.unavailable("permission_denied")
        if st == "truncated":
            return base.error("truncated", "/proc/net/%s too large" % fname)
        if st != "ok":
            return base.error("exception", "cannot read /proc/net/%s" % fname)
        if fam == 6:
            ipv6 = True
        r, b = parse_proc_net(text, proto, fam)
        rows.extend(r)
        bad += b
    if bad:
        partial = True

    by_key = {}
    for r in rows:
        k = (r["proto"], r["ip"], r["port"])
        if k not in by_key:
            by_key[k] = {"row": r, "inodes": [r["inode"]]}
        else:
            by_key[k]["inodes"].append(r["inode"])
    dropped = 0
    if len(by_key) > MAX_LISTENERS:
        # keep a bounded, prioritised sample (wildcard and privileged-port listeners first, loopback
        # last: a local user can flood loopback ports at will) and keep the table partial
        keys = sorted(by_key, key=lambda k: (_priority(by_key[k]["row"]), k[2], k[0], k[1]))
        keep = set(keys[:MAX_LISTENERS])
        dropped = len(by_key) - MAX_LISTENERS
        by_key = dict((k, v) for k, v in by_key.items() if k in keep)
        rows = [r for r in rows if (r["proto"], r["ip"], r["port"]) in by_key]
        partial = True

    wanted = set(r["inode"] for r in rows)
    pid_map, unreadable, scan_complete = ({}, 0, True)
    if wanted:
        pid_map, unreadable, scan_complete = _map_inodes(ctx, wanted)
    if not scan_complete:
        partial = True
    if unreadable < 0:
        unreadable = 0
        attrib = "denied"
    else:
        attrib = None

    facts_cache = {}
    out = []
    unattributed = 0
    for k in sorted(by_key, key=lambda x: (x[2], x[0], x[1])):
        ent = by_key[k]
        r = ent["row"]
        pids = sorted(set(p for ino in ent["inodes"] for p in pid_map.get(ino, [])))
        item = {"proto": r["proto"], "ip": r["ip"], "port": r["port"],
                "bind_class": r["bind_class"], "uid": r["uid"], "pid": None, "comm": None,
                "exe": None, "exe_deleted": False, "exe_sha256": None, "unit": None,
                "container": None, "n_pids": len(pids)}
        if pids:
            pid = pids[0]
            if pid not in facts_cache:
                facts_cache[pid] = _proc_facts(ctx, pid)
            item["pid"] = pid
            item.update(facts_cache[pid])
        else:
            unattributed += 1
        out.append(item)

    if attrib is None:
        if not out:
            attrib = "ok"
        elif not scan_complete:
            attrib = "denied" if unattributed == len(out) else "partial"
        elif unattributed == 0 and unreadable == 0:
            attrib = "ok"
        elif unattributed == len(out):
            attrib = "denied"
        else:
            attrib = "partial"
    bv6 = None
    st, text = ctx.read_text("/proc/sys/net/ipv6/bindv6only", 16)
    if st == "ok" and text.strip() in ("0", "1"):
        bv6 = int(text.strip())
    v = {"count": len(out), "listeners": out, "ipv6": ipv6, "bindv6only": bv6,
         "attribution": {"status": attrib, "unreadable_pids": unreadable,
                         "unattributed": unattributed}}
    if dropped:
        v["dropped"] = dropped
    return base.ok(v, conf="exact", partial=partial)
